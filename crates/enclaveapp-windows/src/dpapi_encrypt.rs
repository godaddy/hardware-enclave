// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Windows DPAPI-backed software ECIES encryption backend.
//!
//! This is intentionally not the normal Windows backend. It exists only
//! for VM hosts where TPM 2.0 is unavailable. The private P-256 key
//! is stored on disk encrypted by per-user DPAPI, and the public ECIES
//! wire format matches the software/keyring backend.
//!
//! ## Application-layer key
//!
//! When an application key (`app_key`) is configured via
//! [`DpapiEncryptor::with_app_key`], the P-256 private key bytes are
//! further wrapped in AES-256-GCM before being handed to DPAPI. This
//! adds an application-specific secret that is embedded in the calling
//! binary, defeating generic per-user DPAPI oracle tools (e.g., tools
//! that call `CryptUnprotectData` on every `.key` file they find) that
//! do not carry knowledge of the embedding binary.
//!
//! The on-disk format after the app key layer is applied (prior to DPAPI):
//!
//! ```text
//! [ GDA1 magic (4 B) ][ nonce (12 B) ][ AES-256-GCM ciphertext+tag (48 B) ]
//! ```
//!
//! Legacy blobs (32 raw bytes, no magic prefix) are accepted transparently
//! on first load. If an app key is configured, the legacy blob is silently
//! re-wrapped in the new format on the same load — subsequent decryptions
//! use the stronger on-disk protection without user action.
//!
//! See `THREAT_MODEL.md` ("Windows Secure Storage: TPM vs DPAPI") for the
//! full threat-model posture and what this protection does and does not
//! provide.

use elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use enclaveapp_core::metadata::{self, KeyMeta};
use enclaveapp_core::traits::{EnclaveEncryptor, EnclaveKeyManager};
use enclaveapp_core::types::{validate_label, AccessPolicy, KeyType};
use enclaveapp_core::{Error, Result};
use p256::SecretKey;
use zeroize::Zeroizing;

const ECIES_VERSION: u8 = 0x01;
const GCM_NONCE_SIZE: usize = 12;
const GCM_TAG_SIZE: usize = 16;
const UNCOMPRESSED_POINT_SIZE: usize = 65;
const RAW_KEY_SIZE: usize = 32;
const MIN_CIPHERTEXT_LEN: usize = 1 + UNCOMPRESSED_POINT_SIZE + GCM_NONCE_SIZE + GCM_TAG_SIZE;

/// Magic prefix for app-key-wrapped DPAPI blobs. ASCII "GDA1".
const APP_KEY_MAGIC: [u8; 4] = [b'G', b'D', b'A', b'1'];
/// Size of the DPAPI plaintext when the app key layer is present:
/// 4 (magic) + 12 (nonce) + 32 (ciphertext) + 16 (tag) = 64 bytes.
const WRAPPED_KEY_SIZE: usize = APP_KEY_MAGIC.len() + GCM_NONCE_SIZE + RAW_KEY_SIZE + GCM_TAG_SIZE;

#[derive(Debug)]
pub struct DpapiEncryptor {
    app_name: String,
    keys_dir_override: Option<std::path::PathBuf>,
    /// Optional application-layer AES-256-GCM key applied around DPAPI.
    /// When present, the on-disk P-256 private key is wrapped in
    /// AES-256-GCM before DPAPI protects it. This key is expected to be
    /// embedded in the calling binary as a compile-time constant, so that
    /// a generic `CryptUnprotectData` oracle cannot extract the P-256 key
    /// without also analysing the binary to recover this key.
    app_key: Option<[u8; 32]>,
}

impl DpapiEncryptor {
    pub fn new(app_name: &str) -> Self {
        Self {
            app_name: app_name.to_string(),
            keys_dir_override: None,
            app_key: None,
        }
    }

    pub fn with_keys_dir(app_name: &str, keys_dir: std::path::PathBuf) -> Self {
        Self {
            app_name: app_name.to_string(),
            keys_dir_override: Some(keys_dir),
            app_key: None,
        }
    }

    /// Apply an application-layer AES-256-GCM key around DPAPI.
    ///
    /// The key should be a compile-time constant embedded in the calling
    /// binary. See the module-level documentation for the on-disk format and
    /// migration behaviour.
    pub fn with_app_key(mut self, key: [u8; 32]) -> Self {
        self.app_key = Some(key);
        self
    }

    fn keys_dir(&self) -> std::path::PathBuf {
        self.keys_dir_override
            .clone()
            .unwrap_or_else(|| metadata::keys_dir(&self.app_name))
    }

    fn key_path(&self, label: &str) -> std::path::PathBuf {
        self.keys_dir().join(format!("{label}.key"))
    }

    fn load_secret_key(&self, key_path: &std::path::Path, label: &str) -> Result<SecretKey> {
        let protected = match metadata::read_no_follow(key_path) {
            Ok(bytes) => bytes,
            Err(Error::Io(ref e)) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::KeyNotFound {
                    label: label.to_string(),
                });
            }
            Err(err) => return Err(err),
        };
        let plaintext = Zeroizing::new(crate::dpapi::unprotect(&protected, "dpapi_decrypt_key")?);

        let raw_key: Zeroizing<Vec<u8>> = match plaintext.len() {
            RAW_KEY_SIZE => {
                // Legacy format: the P-256 key was stored as raw bytes under
                // DPAPI with no application-layer wrapping. If an app key is
                // now configured, re-wrap silently so subsequent loads use the
                // stronger on-disk format. Best-effort: a write failure is
                // logged but does not prevent the current decrypt from
                // proceeding — the migration will be retried next time.
                if let Some(ak) = &self.app_key {
                    match app_key_wrap(plaintext.as_slice(), ak) {
                        Ok(wrapped) => match crate::dpapi::protect(&wrapped, "dpapi_encrypt_key") {
                            Ok(new_protected) => {
                                if let Err(e) = metadata::atomic_write(key_path, &new_protected) {
                                    tracing::warn!(
                                        label = %label,
                                        error = %e,
                                        "DPAPI app-key migration write failed; \
                                         will retry on next load"
                                    );
                                }
                            }
                            Err(e) => {
                                tracing::warn!(
                                    label = %label,
                                    error = %e,
                                    "DPAPI app-key migration re-protect failed"
                                );
                            }
                        },
                        Err(e) => {
                            tracing::warn!(
                                label = %label,
                                error = %e,
                                "DPAPI app-key migration wrap failed"
                            );
                        }
                    }
                }
                Zeroizing::new(plaintext.to_vec())
            }
            WRAPPED_KEY_SIZE if plaintext.starts_with(&APP_KEY_MAGIC) => {
                // New format: strip the magic and AES-GCM unwrap.
                let Some(ak) = &self.app_key else {
                    return Err(Error::KeyOperation {
                        operation: "load_secret_key".into(),
                        detail: "app-key-wrapped DPAPI blob present but no app key configured \
                                 — the key cannot be decrypted without the binary that wrote it"
                            .into(),
                    });
                };
                app_key_unwrap(&plaintext[APP_KEY_MAGIC.len()..], ak)?
            }
            n => {
                return Err(Error::KeyOperation {
                    operation: "dpapi_decrypt_key".into(),
                    detail: format!(
                        "unexpected decrypted key length {n}: \
                         expected {RAW_KEY_SIZE} (legacy) or {WRAPPED_KEY_SIZE} (app-key-wrapped)"
                    ),
                });
            }
        };

        SecretKey::from_slice(&raw_key).map_err(|e| Error::KeyOperation {
            operation: "load_secret_key".into(),
            detail: e.to_string(),
        })
    }
}

impl EnclaveKeyManager for DpapiEncryptor {
    fn generate(&self, label: &str, key_type: KeyType, policy: AccessPolicy) -> Result<Vec<u8>> {
        validate_label(label)?;
        if key_type != KeyType::Encryption {
            return Err(Error::KeyOperation {
                operation: "generate".into(),
                detail: "DpapiEncryptor only supports encryption keys".into(),
            });
        }
        let dir = self.keys_dir();
        metadata::ensure_dir(&dir)?;
        let _lock = metadata::DirLock::acquire(&dir)?;
        let key_path = self.key_path(label);
        if key_path.exists() || metadata::key_files_exist(&dir, label)? {
            return Err(Error::DuplicateLabel {
                label: label.to_string(),
            });
        }

        let secret_key = SecretKey::random(&mut elliptic_curve::rand_core::OsRng);
        let public_key = secret_key.public_key();
        let pub_bytes = public_key.to_encoded_point(false).as_bytes().to_vec();
        let secret_bytes = Zeroizing::new(secret_key.to_bytes().to_vec());

        // If an app key is configured, wrap the P-256 private key in
        // AES-256-GCM before handing it to DPAPI. This means a
        // `CryptUnprotectData` oracle alone cannot recover the key.
        let protected = if let Some(ak) = &self.app_key {
            let wrapped = app_key_wrap(&secret_bytes, ak)?;
            crate::dpapi::protect(&wrapped, "dpapi_encrypt_key")?
        } else {
            crate::dpapi::protect(&secret_bytes, "dpapi_encrypt_key")?
        };

        metadata::atomic_write(&key_path, &protected)?;
        metadata::restrict_file_permissions(&key_path)?;
        metadata::save_pub_key(&dir, label, &pub_bytes)?;

        let meta = KeyMeta::new(label, key_type, policy);
        match crate::meta_hmac::load_or_create(&self.app_name)? {
            Some(hmac_key) => {
                metadata::save_meta_with_hmac(&dir, label, &meta, hmac_key.as_slice())?;
            }
            None => metadata::save_meta(&dir, label, &meta)?,
        }

        Ok(pub_bytes)
    }

    fn public_key(&self, label: &str) -> Result<Vec<u8>> {
        validate_label(label)?;
        let dir = self.keys_dir();
        match metadata::load_pub_key(&dir, label) {
            Ok(pub_key) => Ok(pub_key),
            Err(_) => {
                let secret = self.load_secret_key(&self.key_path(label), label)?;
                Ok(secret
                    .public_key()
                    .to_encoded_point(false)
                    .as_bytes()
                    .to_vec())
            }
        }
    }

    fn list_keys(&self) -> Result<Vec<String>> {
        metadata::list_labels(&self.keys_dir())
    }

    fn delete_key(&self, label: &str) -> Result<()> {
        validate_label(label)?;
        let dir = self.keys_dir();
        let key_path = self.key_path(label);
        let key_exists = key_path.exists() || metadata::key_files_exist(&dir, label)?;
        if !key_exists {
            return Err(Error::KeyNotFound {
                label: label.to_string(),
            });
        }
        let _lock = metadata::DirLock::acquire(&dir)?;
        if key_path.exists() {
            std::fs::remove_file(&key_path)?;
        }
        match metadata::delete_key_files(&dir, label) {
            Ok(()) | Err(Error::KeyNotFound { .. }) => Ok(()),
            Err(err) => Err(err),
        }
    }

    fn is_available(&self) -> bool {
        true
    }
}

impl EnclaveEncryptor for DpapiEncryptor {
    fn encrypt(&self, label: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
        use p256::ecdh::diffie_hellman;
        use rand::RngCore;

        validate_label(label)?;
        let pub_bytes = self.public_key(label)?;
        let stored_point =
            p256::EncodedPoint::from_bytes(&pub_bytes).map_err(|e| Error::EncryptFailed {
                detail: format!("invalid public key: {e}"),
            })?;
        let stored_pub = p256::PublicKey::from_encoded_point(&stored_point)
            .into_option()
            .ok_or_else(|| Error::EncryptFailed {
                detail: "invalid public key point".into(),
            })?;

        let eph_secret = SecretKey::random(&mut elliptic_curve::rand_core::OsRng);
        let eph_pub = eph_secret.public_key();
        let eph_pub_bytes = eph_pub.to_encoded_point(false).as_bytes().to_vec();
        let shared_secret = diffie_hellman(eph_secret.to_nonzero_scalar(), stored_pub.as_affine());
        let derived_key = derive_key(&shared_secret, &eph_pub_bytes);
        let cipher = Aes256Gcm::new_from_slice(derived_key.as_slice()).map_err(|e| {
            Error::EncryptFailed {
                detail: format!("AES init: {e}"),
            }
        })?;
        let mut nonce_bytes = [0_u8; GCM_NONCE_SIZE];
        rand::rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);
        let encrypted = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| Error::EncryptFailed {
                detail: format!("AES-GCM: {e}"),
            })?;

        let mut output =
            Vec::with_capacity(1 + UNCOMPRESSED_POINT_SIZE + GCM_NONCE_SIZE + encrypted.len());
        output.push(ECIES_VERSION);
        output.extend_from_slice(&eph_pub_bytes);
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&encrypted);
        Ok(output)
    }

    fn decrypt(&self, label: &str, ciphertext: &[u8]) -> Result<Vec<u8>> {
        use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
        use p256::ecdh::diffie_hellman;

        validate_label(label)?;
        if ciphertext.len() < MIN_CIPHERTEXT_LEN {
            return Err(Error::DecryptFailed {
                detail: "ciphertext too short".into(),
            });
        }
        if ciphertext[0] != ECIES_VERSION {
            return Err(Error::DecryptFailed {
                detail: format!("unsupported version: 0x{:02x}", ciphertext[0]),
            });
        }
        let eph_pub_bytes = &ciphertext[1..66];
        let nonce_bytes = &ciphertext[66..78];
        let encrypted = &ciphertext[78..];
        let secret = self.load_secret_key(&self.key_path(label), label)?;
        let eph_point =
            p256::EncodedPoint::from_bytes(eph_pub_bytes).map_err(|e| Error::DecryptFailed {
                detail: format!("invalid ephemeral key: {e}"),
            })?;
        let eph_pub = p256::PublicKey::from_encoded_point(&eph_point)
            .into_option()
            .ok_or_else(|| Error::DecryptFailed {
                detail: "invalid ephemeral key point".into(),
            })?;
        let shared_secret = diffie_hellman(secret.to_nonzero_scalar(), eph_pub.as_affine());
        let derived_key = derive_key(&shared_secret, eph_pub_bytes);
        let cipher = Aes256Gcm::new_from_slice(derived_key.as_slice()).map_err(|e| {
            Error::DecryptFailed {
                detail: format!("AES init: {e}"),
            }
        })?;
        let nonce_array: [u8; GCM_NONCE_SIZE] =
            nonce_bytes.try_into().map_err(|_| Error::DecryptFailed {
                detail: "invalid nonce length".into(),
            })?;
        let nonce = Nonce::from(nonce_array);
        cipher
            .decrypt(&nonce, encrypted)
            .map_err(|e| Error::DecryptFailed {
                detail: format!("AES-GCM: {e}"),
            })
    }
}

/// Wrap `plaintext` (the raw P-256 key bytes) in AES-256-GCM using `ak`.
///
/// Output format: `APP_KEY_MAGIC (4 B) | nonce (12 B) | ciphertext+tag (48 B)`
fn app_key_wrap(plaintext: &[u8], ak: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>> {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
    use rand::RngCore;

    let cipher = Aes256Gcm::new_from_slice(ak).map_err(|e| Error::EncryptFailed {
        detail: format!("app key AES init: {e}"),
    })?;
    let mut nonce_bytes = [0_u8; GCM_NONCE_SIZE];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let encrypted = cipher
        .encrypt(&Nonce::from(nonce_bytes), plaintext)
        .map_err(|e| Error::EncryptFailed {
            detail: format!("app key AES-GCM encrypt: {e}"),
        })?;
    let mut out = Zeroizing::new(Vec::with_capacity(WRAPPED_KEY_SIZE));
    out.extend_from_slice(&APP_KEY_MAGIC);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&encrypted);
    Ok(out)
}

/// Unwrap the AES-256-GCM layer applied by [`app_key_wrap`].
///
/// `data` is the bytes after the magic prefix: `nonce (12 B) | ciphertext+tag (48 B)`.
/// Returns the raw P-256 key bytes on success.
fn app_key_unwrap(data: &[u8], ak: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>> {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};

    let expected = GCM_NONCE_SIZE + RAW_KEY_SIZE + GCM_TAG_SIZE;
    if data.len() != expected {
        return Err(Error::DecryptFailed {
            detail: format!(
                "app-key wrapped data has unexpected length {} (expected {expected})",
                data.len()
            ),
        });
    }
    let cipher = Aes256Gcm::new_from_slice(ak).map_err(|e| Error::DecryptFailed {
        detail: format!("app key AES init: {e}"),
    })?;
    let nonce_arr: [u8; GCM_NONCE_SIZE] =
        data[..GCM_NONCE_SIZE]
            .try_into()
            .map_err(|_| Error::DecryptFailed {
                detail: "nonce slice length mismatch".into(),
            })?;
    let nonce = Nonce::from(nonce_arr);
    let plaintext = cipher
        .decrypt(nonce, &data[GCM_NONCE_SIZE..])
        .map_err(|e| Error::DecryptFailed {
            detail: format!("app key AES-GCM decrypt: {e}"),
        })?;
    if plaintext.len() != RAW_KEY_SIZE {
        return Err(Error::DecryptFailed {
            detail: format!(
                "app key AES-GCM produced {} bytes, expected {RAW_KEY_SIZE}",
                plaintext.len()
            ),
        });
    }
    Ok(Zeroizing::new(plaintext))
}

fn derive_key(
    shared_secret: &p256::ecdh::SharedSecret,
    eph_pub_bytes: &[u8],
) -> Zeroizing<[u8; 32]> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(shared_secret.raw_secret_bytes());
    hasher.update([0x00, 0x00, 0x00, 0x01]);
    hasher.update(eph_pub_bytes);
    let result = hasher.finalize();
    let mut key = Zeroizing::new([0_u8; 32]);
    key.copy_from_slice(&result);
    key
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn app_key_wrap_unwrap_roundtrip() {
        let raw_key = [42u8; RAW_KEY_SIZE];
        let ak = [0xABu8; 32];
        let wrapped = app_key_wrap(&raw_key, &ak).unwrap();
        assert_eq!(wrapped.len(), WRAPPED_KEY_SIZE);
        assert!(wrapped.starts_with(&APP_KEY_MAGIC));
        let unwrapped = app_key_unwrap(&wrapped[APP_KEY_MAGIC.len()..], &ak).unwrap();
        assert_eq!(unwrapped.as_slice(), &raw_key);
    }

    #[test]
    fn app_key_wrap_produces_different_ciphertexts_each_time() {
        let raw_key = [1u8; RAW_KEY_SIZE];
        let ak = [2u8; 32];
        let w1 = app_key_wrap(&raw_key, &ak).unwrap();
        let w2 = app_key_wrap(&raw_key, &ak).unwrap();
        // Nonces are random — ciphertexts must differ.
        assert_ne!(w1.as_slice(), w2.as_slice());
    }

    #[test]
    fn app_key_unwrap_wrong_key_fails() {
        let raw_key = [42u8; RAW_KEY_SIZE];
        let ak = [0xABu8; 32];
        let wrong_ak = [0xCDu8; 32];
        let wrapped = app_key_wrap(&raw_key, &ak).unwrap();
        assert!(app_key_unwrap(&wrapped[APP_KEY_MAGIC.len()..], &wrong_ak).is_err());
    }

    #[test]
    fn app_key_unwrap_truncated_data_fails() {
        let ak = [0xABu8; 32];
        // Too short: only a nonce, no ciphertext.
        let truncated = [0u8; GCM_NONCE_SIZE];
        assert!(app_key_unwrap(&truncated, &ak).is_err());
    }

    #[test]
    fn wrapped_key_size_constant_is_correct() {
        // Verify the constant matches the layout: magic + nonce + ciphertext + GCM tag.
        assert_eq!(WRAPPED_KEY_SIZE, 4 + 12 + 32 + 16);
    }

    #[test]
    fn app_key_magic_is_ascii_gda1() {
        assert_eq!(&APP_KEY_MAGIC, b"GDA1");
    }
}
