// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! `LinuxTpmEncryptor` -- ECDH P-256 / ECIES encryption backend using Linux TPM 2.0.
//!

#![allow(unused_qualifications, let_underscore_drop)]
//! ## ECIES Wire Format
//!
//! ```text
//! [0x01] [65-byte ephemeral pubkey] [12-byte nonce] [ciphertext] [16-byte GCM tag]
//! ```
//!
//! ## Encryption flow
//!
//! 1. Load the stored public key for the label.
//! 2. Generate an ephemeral ECDH P-256 key pair in software.
//! 3. Perform software ECDH between ephemeral private key and stored public key.
//! 4. Derive a 32-byte AES key via X9.63 KDF (SHA-256).
//! 5. AES-256-GCM encrypt with a random 12-byte nonce.
//!
//! ## Decryption flow
//!
//! 1. Parse the ephemeral public key from the ciphertext.
//! 2. Load the TPM key and call `ecdh_z_gen` to compute the shared secret
//!    (the private key never leaves the TPM).
//! 3. Derive the AES key and decrypt.

use crate::tpm::{self, TpmConfig};
use elliptic_curve::sec1::FromEncodedPoint;
use enclaveapp_core::metadata::{self, DirLock};
use enclaveapp_core::traits::{EnclaveEncryptor, EnclaveKeyManager};
use enclaveapp_core::types::validate_label;
use enclaveapp_core::{AccessPolicy, Error, KeyType, Result};
use tss_esapi::structures::{EccParameter, EccPoint, Public};
use tss_esapi::traits::{Marshall, UnMarshall};

const ECIES_VERSION: u8 = 0x01;
const GCM_NONCE_SIZE: usize = 12;
const GCM_TAG_SIZE: usize = 16;
const UNCOMPRESSED_POINT_SIZE: usize = 65;
const MIN_CIPHERTEXT_LEN: usize = 1 + UNCOMPRESSED_POINT_SIZE + GCM_NONCE_SIZE + GCM_TAG_SIZE;

/// Linux TPM 2.0-backed ECDH P-256 encryptor (ECIES).
#[derive(Debug)]
pub struct LinuxTpmEncryptor {
    config: TpmConfig,
}

impl LinuxTpmEncryptor {
    /// Create a new encryptor for the given application.
    pub fn new(app_name: &str) -> Self {
        Self {
            config: TpmConfig::new(app_name),
        }
    }

    /// Create an encryptor with a custom keys directory path.
    pub fn with_keys_dir(app_name: &str, keys_dir: std::path::PathBuf) -> Self {
        Self {
            config: TpmConfig::with_keys_dir(app_name, keys_dir),
        }
    }

    /// Load a child key into the TPM and return its handle along with the context.
    fn load_key(&self, label: &str) -> Result<(tss_esapi::Context, tss_esapi::handles::KeyHandle)> {
        let dir = self.config.keys_dir();
        let (pub_blob, priv_blob) = tpm::load_key_blobs(&dir, label)?;

        let mut ctx = tpm::open_context()?;
        let primary_handle = tpm::create_primary(&mut ctx)?;

        let private = tss_esapi::structures::Private::try_from(priv_blob).map_err(|e| {
            Error::KeyOperation {
                operation: "load_private".into(),
                detail: e.to_string(),
            }
        })?;
        let public = Public::unmarshall(&pub_blob).map_err(|e| Error::KeyOperation {
            operation: "load_public".into(),
            detail: e.to_string(),
        })?;

        let key_handle =
            ctx.load(primary_handle, private, public)
                .map_err(|e| Error::KeyOperation {
                    operation: "load_key".into(),
                    detail: e.to_string(),
                })?;

        Ok((ctx, key_handle))
    }
}

/// Derive a 32-byte AES key from a raw shared secret using X9.63 KDF (single-pass SHA-256).
///
/// X9.63 KDF: SHA-256(shared_secret_x || counter_be32 || shared_info)
/// where counter = 0x00000001 for the first (and only) block.
/// shared_info = ephemeral public key bytes (65 bytes).
fn derive_key(shared_x: &[u8], eph_pub_bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(shared_x);
    hasher.update([0x00, 0x00, 0x00, 0x01]); // counter = 1 (big-endian)
    hasher.update(eph_pub_bytes);
    let result = hasher.finalize();
    let mut key = [0_u8; 32];
    key.copy_from_slice(&result);
    key
}

/// Convert a 65-byte SEC1 uncompressed point to a TPM EccPoint.
fn sec1_to_ecc_point(sec1: &[u8]) -> Result<EccPoint> {
    if sec1.len() != 65 || sec1[0] != 0x04 {
        return Err(Error::KeyOperation {
            operation: "sec1_to_ecc_point".into(),
            detail: format!(
                "invalid SEC1 point (len={}, prefix=0x{:02x})",
                sec1.len(),
                sec1.first().copied().unwrap_or(0)
            ),
        });
    }
    let x = EccParameter::try_from(&sec1[1..33]).map_err(|e| Error::KeyOperation {
        operation: "ecc_param_x".into(),
        detail: e.to_string(),
    })?;
    let y = EccParameter::try_from(&sec1[33..65]).map_err(|e| Error::KeyOperation {
        operation: "ecc_param_y".into(),
        detail: e.to_string(),
    })?;
    Ok(EccPoint::new(x, y))
}

impl EnclaveKeyManager for LinuxTpmEncryptor {
    fn generate(&self, label: &str, key_type: KeyType, policy: AccessPolicy) -> Result<Vec<u8>> {
        validate_label(label)?;
        if key_type != KeyType::Encryption {
            return Err(Error::KeyOperation {
                operation: "generate".into(),
                detail: "LinuxTpmEncryptor only supports encryption keys".into(),
            });
        }

        let dir = self.config.keys_dir();
        metadata::ensure_dir(&dir)?;
        let _lock = DirLock::acquire(&dir)?;

        tpm::ensure_label_available(&dir, label)?;

        let mut ctx = tpm::open_context()?;
        let primary_handle = tpm::create_primary(&mut ctx)?;
        let template = tpm::encryption_key_template()?;

        let result = ctx
            .create(primary_handle, template, None, None, None, None)
            .map_err(|e| Error::GenerateFailed {
                detail: format!("TPM create: {e}"),
            })?;

        // Extract the public key as SEC1 uncompressed point
        let pub_key = tpm::extract_public_key(&result.out_public)?;

        // Serialize and save TPM blobs
        let pub_blob = result
            .out_public
            .marshall()
            .map_err(|e| Error::KeyOperation {
                operation: "marshall_public".into(),
                detail: e.to_string(),
            })?;
        let priv_blob: Vec<u8> = result.out_private.to_vec();
        tpm::persist_generated_key(
            &dir, label, key_type, policy, &pub_key, &pub_blob, &priv_blob,
        )?;

        Ok(pub_key)
    }

    fn public_key(&self, label: &str) -> Result<Vec<u8>> {
        validate_label(label)?;
        let dir = self.config.keys_dir();
        tpm::load_public_key(&dir, label)
    }

    fn list_keys(&self) -> Result<Vec<String>> {
        tpm::list_labels(&self.config.keys_dir())
    }

    fn delete_key(&self, label: &str) -> Result<()> {
        validate_label(label)?;
        let dir = self.config.keys_dir();
        if !dir.exists() {
            return Err(Error::KeyNotFound {
                label: label.to_string(),
            });
        }
        let _lock = DirLock::acquire(&dir)?;
        let blob_existed = tpm::key_blobs_exist(&dir, label)?;
        let metadata_existed = metadata::key_files_exist(&dir, label)?;
        if !blob_existed && !metadata_existed {
            return Err(Error::KeyNotFound {
                label: label.to_string(),
            });
        }
        match tpm::delete_key_blobs(&dir, label) {
            Ok(()) => {}
            Err(Error::KeyNotFound { .. }) if metadata_existed => {}
            Err(err) => return Err(err),
        }
        match metadata::delete_key_files(&dir, label) {
            Ok(()) => Ok(()),
            Err(Error::KeyNotFound { .. }) if blob_existed => Ok(()),
            Err(err) => Err(err),
        }
    }

    fn is_available(&self) -> bool {
        tpm::is_available()
    }
}

impl EnclaveEncryptor for LinuxTpmEncryptor {
    fn encrypt(&self, label: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
        use elliptic_curve::sec1::ToEncodedPoint;
        use p256::ecdh::diffie_hellman;
        use rand::RngCore;

        validate_label(label)?;

        // Load the stored public key (SEC1 uncompressed)
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

        // Generate ephemeral key pair in software
        let eph_secret = p256::SecretKey::random(&mut elliptic_curve::rand_core::OsRng);
        let eph_pub = eph_secret.public_key();
        let eph_pub_bytes: Vec<u8> = eph_pub.to_encoded_point(false).as_bytes().to_vec();

        // ECDH shared secret (software -- encryption uses public key only)
        let shared_secret = diffie_hellman(eph_secret.to_nonzero_scalar(), stored_pub.as_affine());

        // X9.63 KDF
        let derived_key = derive_key(shared_secret.raw_secret_bytes(), &eph_pub_bytes);

        // AES-256-GCM encrypt
        let cipher = Aes256Gcm::new_from_slice(&derived_key).map_err(|e| Error::EncryptFailed {
            detail: format!("AES init: {e}"),
        })?;

        let mut nonce_bytes = [0_u8; GCM_NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let encrypted = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| Error::EncryptFailed {
                detail: format!("AES-GCM: {e}"),
            })?;

        // Format: [version(1)] [eph_pub(65)] [nonce(12)] [ciphertext+tag]
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

        // AccessPolicy is stored in key metadata but is not enforced here.
        // The TPM key uses empty authorization and `ecdh_z_gen` runs without
        // an HMAC/auth session, so no user prompt occurs regardless of the
        // policy recorded at generation time.
        validate_label(label)?;

        if ciphertext.len() < MIN_CIPHERTEXT_LEN {
            return Err(Error::DecryptFailed {
                detail: format!(
                    "ciphertext too short: {} < {MIN_CIPHERTEXT_LEN}",
                    ciphertext.len()
                ),
            });
        }
        if ciphertext[0] != ECIES_VERSION {
            return Err(Error::DecryptFailed {
                detail: format!("unsupported ECIES version: 0x{:02x}", ciphertext[0]),
            });
        }

        let eph_pub_bytes = &ciphertext[1..66];
        let nonce_bytes = &ciphertext[66..78];
        let encrypted = &ciphertext[78..];

        // Load the TPM key
        let (mut ctx, key_handle) = self.load_key(label)?;

        // Convert ephemeral public key to TPM EccPoint
        let eph_point = sec1_to_ecc_point(eph_pub_bytes)?;

        // ECDH via TPM -- the private key never leaves the hardware
        let shared_point =
            ctx.ecdh_z_gen(key_handle, eph_point)
                .map_err(|e| Error::DecryptFailed {
                    detail: format!("TPM ECDH: {e}"),
                })?;

        // The shared secret is the x-coordinate of the resulting point
        let shared_x = shared_point.x().value();

        // X9.63 KDF (same derivation as encryption)
        let derived_key = derive_key(shared_x, eph_pub_bytes);

        // AES-256-GCM decrypt
        let cipher = Aes256Gcm::new_from_slice(&derived_key).map_err(|e| Error::DecryptFailed {
            detail: format!("AES init: {e}"),
        })?;
        let nonce = Nonce::from_slice(nonce_bytes);

        cipher
            .decrypt(nonce, encrypted)
            .map_err(|e| Error::DecryptFailed {
                detail: format!("AES-GCM: {e}"),
            })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn derive_key_deterministic() {
        let shared_x = [0x42_u8; 32];
        let eph_pub = [0x04_u8; 65];
        let key1 = derive_key(&shared_x, &eph_pub);
        let key2 = derive_key(&shared_x, &eph_pub);
        assert_eq!(key1, key2);
        assert_ne!(key1, [0u8; 32]); // not all zeros
    }

    #[test]
    fn derive_key_different_inputs_different_outputs() {
        let eph_pub = [0x04_u8; 65];
        let key1 = derive_key(&[0x01; 32], &eph_pub);
        let key2 = derive_key(&[0x02; 32], &eph_pub);
        assert_ne!(key1, key2);
    }

    #[test]
    fn sec1_to_ecc_point_valid() {
        let mut sec1 = vec![0x04];
        sec1.extend_from_slice(&[0xAA; 32]); // x
        sec1.extend_from_slice(&[0xBB; 32]); // y
        let point = sec1_to_ecc_point(&sec1).unwrap();
        assert_eq!(point.x().value(), &[0xAA; 32]);
        assert_eq!(point.y().value(), &[0xBB; 32]);
    }

    #[test]
    fn sec1_to_ecc_point_wrong_length() {
        let sec1 = vec![0x04; 33];
        assert!(sec1_to_ecc_point(&sec1).is_err());
    }

    #[test]
    fn sec1_to_ecc_point_wrong_prefix() {
        let mut sec1 = vec![0x02];
        sec1.extend_from_slice(&[0xAA; 64]);
        assert!(sec1_to_ecc_point(&sec1).is_err());
    }

    #[test]
    fn tpm_encryptor_rejects_signing_key_type() {
        let enc = LinuxTpmEncryptor::with_keys_dir(
            "test",
            std::env::temp_dir().join("enclaveapp-tpm-test-enc-reject"),
        );
        let err = enc
            .generate("test", KeyType::Signing, AccessPolicy::None)
            .unwrap_err();
        match err {
            Error::KeyOperation { .. } => {}
            other => panic!("expected KeyOperation, got: {other}"),
        }
    }

    #[test]
    fn generate_rejects_duplicate_private_blob_without_public_blob() {
        let dir = std::env::temp_dir().join(format!(
            "enclaveapp-tpm-test-enc-dup-{}",
            std::process::id()
        ));
        drop(std::fs::remove_dir_all(&dir));
        std::fs::create_dir_all(&dir).unwrap();

        let enc = LinuxTpmEncryptor::with_keys_dir("test", dir.clone());
        metadata::atomic_write(&dir.join("stray-enc.tpm_priv"), b"priv").unwrap();

        let err = enc
            .generate("stray-enc", KeyType::Encryption, AccessPolicy::None)
            .unwrap_err();
        match err {
            Error::DuplicateLabel { label } => assert_eq!(label, "stray-enc"),
            other => panic!("expected DuplicateLabel, got: {other}"),
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }

    // Integration tests that require actual TPM hardware.
    // Run with: ENCLAVEAPP_TEST_TPM=1 cargo test -p enclaveapp-linux-tpm --features encryption
    #[test]
    fn tpm_encrypt_decrypt_roundtrip() {
        if std::env::var("ENCLAVEAPP_TEST_TPM").is_err() {
            eprintln!("skipping TPM test (set ENCLAVEAPP_TEST_TPM=1 to run)");
            return;
        }

        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("enclaveapp-tpm-enc-test-{pid}-{id}"));
        std::fs::create_dir_all(&dir).unwrap();

        let enc = LinuxTpmEncryptor::with_keys_dir("test", dir.clone());

        enc.generate("tpm-enc-test", KeyType::Encryption, AccessPolicy::None)
            .unwrap();

        let plaintext = b"the quick brown fox jumps over the lazy dog";
        let ciphertext = enc.encrypt("tpm-enc-test", plaintext).unwrap();
        let decrypted = enc.decrypt("tpm-enc-test", &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);

        enc.delete_key("tpm-enc-test").unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
