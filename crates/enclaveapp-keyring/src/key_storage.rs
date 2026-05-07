// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Shared key generation and file storage for the software backend.
//!
//! When a system keyring is available, private keys are encrypted at rest
//! using AES-256-GCM with a random key encryption key (KEK) stored in the
//! keyring. When the keyring is unavailable, keys are stored unencrypted
//! with a one-time warning to stderr.

#![cfg_attr(
    not(any(feature = "signing", feature = "encryption")),
    allow(dead_code)
)]

use elliptic_curve::sec1::ToEncodedPoint;
use enclaveapp_core::metadata::{self, KeyMeta};
use enclaveapp_core::types::validate_label;
use enclaveapp_core::{AccessPolicy, Error, KeyType, Result};
use p256::SecretKey;
use std::path::PathBuf;
#[cfg_attr(
    not(all(feature = "keyring-storage", target_env = "gnu")),
    allow(unused_imports)
)]
use zeroize::{Zeroize, Zeroizing};

/// Version byte for encrypted key files.
const ENCRYPTED_KEY_VERSION: u8 = 0x01;

/// AES-256-GCM nonce size in bytes.
const GCM_NONCE_SIZE: usize = 12;

/// AES-256-GCM authentication tag size in bytes.
const GCM_TAG_SIZE: usize = 16;

/// Raw P-256 secret key size in bytes.
const RAW_KEY_SIZE: usize = 32;

/// KEK size in bytes (AES-256).
#[cfg(any(all(feature = "keyring-storage", target_env = "gnu"), test))]
const KEK_SIZE: usize = 32;

/// Minimum encrypted key file size: version(1) + nonce(12) + encrypted_key(32) + tag(16).
const MIN_ENCRYPTED_FILE_SIZE: usize = 1 + GCM_NONCE_SIZE + RAW_KEY_SIZE + GCM_TAG_SIZE;

/// Software keys are always available (but may lack keyring encryption).
pub fn is_available() -> bool {
    true
}

/// Check whether the keyring-storage feature is compiled in.
///
/// When this returns false, keys will be stored as plaintext files.
/// Callers that require at-rest encryption should refuse to proceed.
pub fn has_keyring_feature() -> bool {
    cfg!(feature = "keyring-storage")
}

/// Configuration for the software backend.
#[derive(Debug)]
pub struct SoftwareConfig {
    pub app_name: String,
    pub keys_dir_override: Option<PathBuf>,
    /// Whether to attempt keyring-based encryption. Defaults to `true` when
    /// the `keyring-storage` feature is enabled, `false` otherwise.
    /// Set to `false` for testing or environments where the keyring
    /// is known to be unavailable.
    #[allow(dead_code)]
    pub use_keyring: bool,
}

impl SoftwareConfig {
    #[allow(dead_code)]
    pub fn new(app_name: &str) -> Self {
        Self {
            app_name: app_name.to_string(),
            keys_dir_override: None,
            use_keyring: cfg!(feature = "keyring-storage"),
        }
    }

    pub fn with_keys_dir(app_name: &str, keys_dir: PathBuf) -> Self {
        Self {
            app_name: app_name.to_string(),
            keys_dir_override: Some(keys_dir),
            use_keyring: cfg!(feature = "keyring-storage"),
        }
    }

    pub fn keys_dir(&self) -> PathBuf {
        self.keys_dir_override
            .clone()
            .unwrap_or_else(|| metadata::keys_dir(&self.app_name))
    }
}

/// Probe whether the system keyring is functional.
#[cfg(all(feature = "keyring-storage", target_env = "gnu"))]
fn keyring_available(app_name: &str) -> bool {
    let entry = match keyring::Entry::new(app_name, "__keyring_probe__") {
        Ok(e) => e,
        Err(_) => return false,
    };
    match entry.set_secret(b"probe") {
        Ok(()) => {
            drop(entry.delete_credential());
            true
        }
        Err(_) => false,
    }
}

/// Keyring account name under which the per-app meta-HMAC key is stored.
///
/// The meta-HMAC key is a random 32-byte value, generated on first use
/// and reused across all keys for the app. It authenticates
/// `<label>.meta` JSON contents so a same-UID attacker cannot rewrite
/// `AccessPolicy` (or any other policy-bearing meta field) without
/// also having keyring access.
#[cfg(all(feature = "keyring-storage", target_env = "gnu"))]
const META_HMAC_ACCOUNT: &str = "__meta_hmac_key__";

/// Load or create the per-app meta-HMAC key in the system keyring.
///
/// Returns `Ok(Some(key))` when keyring access succeeds, `Ok(None)`
/// when the keyring is unavailable — callers fall back to writing
/// plain (unauthenticated) meta in that case so the library stays
/// functional on systems without a running Secret Service.
///
/// Exposed publicly so `enclaveapp-app-storage` can pass the key
/// into `metadata::load_meta_with_hmac` at `ensure_key` time without
/// taking its own keyring dependency.
#[cfg(all(feature = "keyring-storage", target_env = "gnu"))]
pub fn meta_hmac_key(app_name: &str) -> Option<Zeroizing<Vec<u8>>> {
    use rand::RngCore;
    let entry = keyring::Entry::new(app_name, META_HMAC_ACCOUNT).ok()?;
    match entry.get_secret() {
        Ok(bytes) if bytes.len() == 32 => Some(Zeroizing::new(bytes)),
        Ok(_) | Err(_) => {
            let mut buf = [0_u8; 32];
            rand::thread_rng().fill_bytes(&mut buf);
            entry.set_secret(&buf).ok()?;
            let out = Zeroizing::new(buf.to_vec());
            // Wipe the local array; Zeroizing only wraps the Vec copy.
            buf.zeroize();
            Some(out)
        }
    }
}

#[cfg(not(all(feature = "keyring-storage", target_env = "gnu")))]
#[allow(dead_code)]
pub fn meta_hmac_key(_app_name: &str) -> Option<Zeroizing<Vec<u8>>> {
    None
}

/// Read-only companion to [`meta_hmac_key`] — never calls
/// `set_secret`, so it is safe from contexts where a Secret Service
/// write could prompt the user to unlock a locked keyring or fail
/// silently in a non-interactive session.
///
/// Returns `Ok(Some(key))` when the entry is present and well-formed;
/// `Ok(None)` when the entry has not been created yet (no `Err`
/// because that's the pre-keygen state and not actionable). Errors
/// only on a confirmed Secret Service failure that the operator
/// should see — corrupt entry, daemon crash. The verify path treats
/// `Err` as fail-open, so consumers should match the macOS / Windows
/// pattern: map `Err` to "skip verification" rather than refusing
/// to proceed.
#[cfg(all(feature = "keyring-storage", target_env = "gnu"))]
pub fn meta_hmac_key_existing(app_name: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let entry =
        keyring::Entry::new(app_name, META_HMAC_ACCOUNT).map_err(|e| Error::KeyOperation {
            operation: "meta_hmac_load".into(),
            detail: format!("keyring::Entry::new: {e}"),
        })?;
    match entry.get_secret() {
        Ok(bytes) if bytes.len() == 32 => Ok(Some(Zeroizing::new(bytes))),
        Ok(_) | Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(Error::KeyOperation {
            operation: "meta_hmac_load".into(),
            detail: format!("get_secret: {e}"),
        }),
    }
}

#[cfg(not(all(feature = "keyring-storage", target_env = "gnu")))]
#[allow(dead_code)]
pub fn meta_hmac_key_existing(_app_name: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
    Ok(None)
}

/// Save the private key bytes to a `.key` file, encrypting with a keyring-stored
/// KEK when `use_keyring` is true. When `use_keyring` is false (testing only),
/// falls back to unencrypted file storage.
///
/// Production callers should always set `use_keyring: true` and the app-storage
/// layer enforces this by checking `has_keyring_feature()` before accepting the
/// software backend.
fn save_private_key(
    config: &SoftwareConfig,
    key_path: &std::path::Path,
    secret_bytes: &[u8],
    label: &str,
) -> Result<()> {
    #[cfg(all(feature = "keyring-storage", target_env = "gnu"))]
    if config.use_keyring && keyring_available(&config.app_name) {
        return save_encrypted(&config.app_name, key_path, secret_bytes, label);
    }

    #[cfg(all(feature = "keyring-storage", target_env = "gnu"))]
    if config.use_keyring {
        return Err(Error::KeyOperation {
            operation: "save_private_key".into(),
            detail: "system keyring is not available; refusing to store key as plaintext".into(),
        });
    }

    // When keyring-storage isn't compiled (e.g. musl builds) but use_keyring
    // is requested, refuse to store keys as plaintext.
    #[cfg(not(all(feature = "keyring-storage", target_env = "gnu")))]
    if config.use_keyring {
        let _ = (key_path, secret_bytes, label);
        return Err(Error::KeyOperation {
            operation: "save_private_key".into(),
            detail: "keyring-storage feature not available in this build; \
                     refusing to store key as plaintext"
                .into(),
        });
    }

    // Unencrypted fallback — only reachable when use_keyring is false (tests).
    #[cfg(not(all(feature = "keyring-storage", target_env = "gnu")))]
    let _ = (config, label);

    metadata::atomic_write(key_path, secret_bytes)?;
    metadata::restrict_file_permissions(key_path)?;
    Ok(())
}

/// Encrypt the secret key with a random KEK, store the KEK in the keyring,
/// and write the encrypted key to disk.
#[cfg(all(feature = "keyring-storage", target_env = "gnu"))]
fn save_encrypted(
    app_name: &str,
    key_path: &std::path::Path,
    secret_bytes: &[u8],
    label: &str,
) -> Result<()> {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
    use rand::RngCore;

    // Generate random KEK. Wrap in Zeroizing so we wipe it after use.
    let mut kek_arr = [0_u8; KEK_SIZE];
    rand::thread_rng().fill_bytes(&mut kek_arr);
    let kek = Zeroizing::new(kek_arr);
    // Local mutable was required for fill_bytes; wipe the intermediate.
    kek_arr.zeroize();

    // Store KEK in keyring
    let entry = keyring::Entry::new(app_name, label).map_err(|e| Error::KeyOperation {
        operation: "keyring_entry".into(),
        detail: e.to_string(),
    })?;
    entry
        .set_secret(kek.as_slice())
        .map_err(|e| Error::KeyOperation {
            operation: "keyring_store".into(),
            detail: e.to_string(),
        })?;

    // Encrypt with AES-256-GCM
    let cipher = Aes256Gcm::new_from_slice(kek.as_slice()).map_err(|e| Error::KeyOperation {
        operation: "aes_init".into(),
        detail: e.to_string(),
    })?;

    let mut nonce_bytes = [0_u8; GCM_NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let encrypted = cipher.encrypt(nonce, secret_bytes).map_err(|e| {
        // Clean up keyring entry on failure
        drop(entry.delete_credential());
        Error::KeyOperation {
            operation: "encrypt_key".into(),
            detail: e.to_string(),
        }
    })?;

    // File format: [version(1)] [nonce(12)] [encrypted_key + tag]
    let mut file_data = Vec::with_capacity(1 + GCM_NONCE_SIZE + encrypted.len());
    file_data.push(ENCRYPTED_KEY_VERSION);
    file_data.extend_from_slice(&nonce_bytes);
    file_data.extend_from_slice(&encrypted);

    metadata::atomic_write(key_path, &file_data)?;
    metadata::restrict_file_permissions(key_path)?;
    Ok(())
}

/// Load the private key bytes from a `.key` file, decrypting if necessary.
///
/// The returned `Zeroizing<Vec<u8>>` wipes the plaintext key material when
/// the caller drops it. This is load-bearing for the threat-model commitment
/// that keyring/software-backend plaintext key bytes do not linger in heap
/// allocations after use.
fn load_private_key_bytes(
    app_name: &str,
    key_path: &std::path::Path,
    label: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let bytes = metadata::read_no_follow(key_path)?;

    // Backward compatibility: raw 32-byte key (unencrypted)
    if bytes.len() == RAW_KEY_SIZE {
        return Ok(Zeroizing::new(bytes));
    }

    // Encrypted format: version(1) + nonce(12) + encrypted_key(32) + tag(16) = 61
    if bytes.len() >= MIN_ENCRYPTED_FILE_SIZE && bytes[0] == ENCRYPTED_KEY_VERSION {
        #[cfg(all(feature = "keyring-storage", target_env = "gnu"))]
        {
            return decrypt_private_key(app_name, &bytes, label);
        }
        #[cfg(not(all(feature = "keyring-storage", target_env = "gnu")))]
        {
            let _ = (app_name, label);
            return Err(Error::KeyOperation {
                operation: "load_private_key".into(),
                detail: "key file is encrypted with keyring but the \
                         keyring-storage feature is not compiled in"
                    .into(),
            });
        }
    }

    // Unknown format
    Err(Error::KeyOperation {
        operation: "load_private_key".into(),
        detail: format!(
            "unrecognized key file format (size={}, version=0x{:02x})",
            bytes.len(),
            bytes.first().copied().unwrap_or(0)
        ),
    })
}

/// Decrypt an encrypted key file using the KEK from the keyring.
///
/// The KEK retrieved from the keyring is zeroized on drop (wrapped in
/// `Zeroizing<Vec<u8>>`). The decrypted plaintext key bytes are also
/// returned as `Zeroizing<Vec<u8>>` so they never linger past the caller.
#[cfg(all(feature = "keyring-storage", target_env = "gnu"))]
fn decrypt_private_key(
    app_name: &str,
    file_data: &[u8],
    label: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};

    let nonce_bytes = &file_data[1..1 + GCM_NONCE_SIZE];
    let encrypted = &file_data[1 + GCM_NONCE_SIZE..];

    // Retrieve KEK from keyring
    let entry = keyring::Entry::new(app_name, label).map_err(|e| Error::KeyOperation {
        operation: "keyring_entry".into(),
        detail: e.to_string(),
    })?;
    let kek = Zeroizing::new(entry.get_secret().map_err(|e| Error::KeyOperation {
        operation: "keyring_retrieve".into(),
        detail: format!("cannot retrieve key encryption key from keyring: {e}"),
    })?);

    if kek.len() != KEK_SIZE {
        return Err(Error::KeyOperation {
            operation: "keyring_retrieve".into(),
            detail: format!(
                "invalid KEK size from keyring: expected {KEK_SIZE}, got {}",
                kek.len()
            ),
        });
    }

    let cipher = Aes256Gcm::new_from_slice(&kek).map_err(|e| Error::KeyOperation {
        operation: "aes_init".into(),
        detail: e.to_string(),
    })?;
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, encrypted)
        .map(Zeroizing::new)
        .map_err(|e| Error::KeyOperation {
            operation: "decrypt_key".into(),
            detail: format!("failed to decrypt private key: {e}"),
        })
}

/// Delete the keyring entry for a key, ignoring errors (the entry may not exist
/// if the key was stored unencrypted).
#[cfg(all(feature = "keyring-storage", target_env = "gnu"))]
fn delete_keyring_entry(app_name: &str, label: &str) {
    if let Ok(entry) = keyring::Entry::new(app_name, label) {
        drop(entry.delete_credential());
    }
}

/// Generate a new P-256 secret key, save it and its public key to disk.
/// Returns the 65-byte uncompressed SEC1 public key.
pub fn generate_and_save(
    config: &SoftwareConfig,
    label: &str,
    key_type: KeyType,
    policy: AccessPolicy,
) -> Result<Vec<u8>> {
    validate_label(label)?;
    let dir = config.keys_dir();
    metadata::ensure_dir(&dir)?;
    let _lock = metadata::DirLock::acquire(&dir)?;

    // Check for duplicates
    let key_path = dir.join(format!("{label}.key"));
    if key_path.exists() || metadata::key_files_exist(&dir, label)? {
        return Err(Error::DuplicateLabel {
            label: label.to_string(),
        });
    }

    // Generate key
    let secret_key = SecretKey::random(&mut elliptic_curve::rand_core::OsRng);
    let public_key = secret_key.public_key();

    // SEC1 uncompressed public key (65 bytes: 0x04 || X || Y)
    let pub_bytes: Vec<u8> = public_key.to_encoded_point(false).as_bytes().to_vec();

    // Save private key (encrypted if keyring is available, plaintext
    // otherwise). Wrap the plaintext byte buffer in Zeroizing so the
    // raw key is wiped as soon as we've written the encrypted form.
    let secret_bytes = Zeroizing::new(secret_key.to_bytes().to_vec());
    save_private_key(config, &key_path, &secret_bytes, label)?;

    // Save cached public key
    metadata::save_pub_key(&dir, label, &pub_bytes)?;

    // Save metadata with an HMAC sidecar so a same-UID attacker cannot
    // rewrite `AccessPolicy` in `.meta` without also having access to
    // the per-app meta-HMAC key in the system keyring. If the keyring
    // is unavailable (no Secret Service) we fall back to the plain
    // save_meta path — the keyring is strictly weaker than hardware
    // anyway and we document the residual risk.
    //
    // `use_keyring=false` (test mode) skips the Secret Service round-
    // trip entirely. The `keyring` crate's `Entry::get_secret()` /
    // `set_secret()` blocks indefinitely when no D-Bus session bus
    // is reachable, which is the default state in non-graphical CI
    // environments. Production never sets this flag false.
    let meta = KeyMeta::new(label, key_type, policy);
    let hmac_key_opt = if config.use_keyring {
        meta_hmac_key(&config.app_name)
    } else {
        None
    };
    match hmac_key_opt {
        Some(hmac_key) => {
            metadata::save_meta_with_hmac(&dir, label, &meta, hmac_key.as_slice())?;
        }
        None => {
            metadata::save_meta(&dir, label, &meta)?;
        }
    }

    Ok(pub_bytes)
}

/// Load a secret key from disk.
pub fn load_secret_key(config: &SoftwareConfig, label: &str) -> Result<SecretKey> {
    validate_label(label)?;
    let key_path = config.keys_dir().join(format!("{label}.key"));
    if !key_path.exists() {
        return Err(Error::KeyNotFound {
            label: label.to_string(),
        });
    }
    let bytes = load_private_key_bytes(&config.app_name, &key_path, label)?;
    SecretKey::from_slice(&bytes).map_err(|e| Error::KeyOperation {
        operation: "load_secret_key".into(),
        detail: e.to_string(),
    })
}

/// Load the cached public key, or derive it from the secret key.
pub fn load_public_key(config: &SoftwareConfig, label: &str) -> Result<Vec<u8>> {
    validate_label(label)?;
    let dir = config.keys_dir();
    match metadata::load_pub_key(&dir, label) {
        Ok(pub_key) => Ok(pub_key),
        Err(_) => {
            let secret = load_secret_key(config, label)?;
            let pub_bytes: Vec<u8> = secret
                .public_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec();
            Ok(pub_bytes)
        }
    }
}

/// List all key labels.
pub fn list_labels(config: &SoftwareConfig) -> Result<Vec<String>> {
    metadata::list_labels(&config.keys_dir())
}

/// Rename a key from `old_label` to `new_label`.
///
/// On the keyring backend, the private key's KEK (when encryption is in
/// effect) is stored in the system keyring keyed by `(app_name, label)`,
/// and the disk blob is named `<label>.key`. Both must be moved together
/// for the new label to decrypt correctly.
///
/// Strategy:
///   1. Load and decrypt the secret under the old label.
///   2. Save the secret under the new label (generates a fresh KEK in
///      the keyring when applicable) at the new file path.
///   3. Rename the `.meta`, `.pub`, `.handle` metadata files.
///   4. Delete the old `.key` and the old keyring entry.
///
/// If step 3 fails after step 2, the new `.key` is removed so the disk
/// state stays consistent with the keyring.
pub fn rename_key(config: &SoftwareConfig, old_label: &str, new_label: &str) -> Result<()> {
    validate_label(old_label)?;
    validate_label(new_label)?;
    if old_label == new_label {
        return Ok(());
    }

    let dir = config.keys_dir();
    let old_key_path = dir.join(format!("{old_label}.key"));
    let new_key_path = dir.join(format!("{new_label}.key"));

    if !old_key_path.exists() && !metadata::key_files_exist(&dir, old_label)? {
        return Err(Error::KeyNotFound {
            label: old_label.to_string(),
        });
    }
    if new_key_path.exists() || metadata::key_files_exist(&dir, new_label)? {
        return Err(Error::DuplicateLabel {
            label: new_label.to_string(),
        });
    }

    let _lock = metadata::DirLock::acquire(&dir)?;

    // Load + decrypt (if encrypted) under the old label.
    let secret_bytes = load_private_key_bytes(&config.app_name, &old_key_path, old_label)?;

    // Save under the new label. For the keyring-encrypted case this
    // creates a fresh KEK in the keyring under `(app_name, new_label)`.
    save_private_key(config, &new_key_path, &secret_bytes, new_label)?;

    // Rename the metadata sibling files. Pass the per-app HMAC key
    // (when keyring is available) so the `.meta.hmac` sidecar is
    // recomputed against the relabeled meta. Otherwise the rename
    // would either leave the old-label sidecar orphaned (now wrong
    // for the new-label meta JSON) or, if rename_key_files refused
    // to proceed without the key, fail outright.
    let hmac_key = meta_hmac_key(&config.app_name);
    let hmac_slice = hmac_key.as_ref().map(|k| k.as_slice());
    if let Err(error) = metadata::rename_key_files(&dir, old_label, new_label, hmac_slice) {
        drop(std::fs::remove_file(&new_key_path));
        #[cfg(all(feature = "keyring-storage", target_env = "gnu"))]
        delete_keyring_entry(&config.app_name, new_label);
        return Err(error);
    }

    // Clean up the old side: delete the old .key file and old keyring
    // entry. Failures here are cosmetic — the new label is fully
    // functional; log via a warning would be nice but we keep the
    // helper dependency-light.
    drop(std::fs::remove_file(&old_key_path));
    #[cfg(all(feature = "keyring-storage", target_env = "gnu"))]
    delete_keyring_entry(&config.app_name, old_label);

    Ok(())
}

/// Delete a key and all associated files.
pub fn delete_key(config: &SoftwareConfig, label: &str) -> Result<()> {
    validate_label(label)?;
    let dir = config.keys_dir();
    let key_path = dir.join(format!("{label}.key"));
    let key_exists = dir.exists() && (key_path.exists() || metadata::key_files_exist(&dir, label)?);
    if !key_exists {
        return Err(Error::KeyNotFound {
            label: label.to_string(),
        });
    }
    let _lock = metadata::DirLock::acquire(&dir)?;

    // Remove the keyring entry (ignore errors -- may not exist)
    #[cfg(all(feature = "keyring-storage", target_env = "gnu"))]
    delete_keyring_entry(&config.app_name, label);

    // Remove the private key file
    if key_path.exists() {
        std::fs::remove_file(&key_path)?;
    }

    match metadata::delete_key_files(&dir, label) {
        Ok(()) | Err(Error::KeyNotFound { .. }) => Ok(()),
        Err(err) => Err(err),
    }
}

/// Encrypt a raw private key with the given KEK using AES-256-GCM.
/// Returns the full encrypted file format bytes.
#[cfg(test)]
fn encrypt_key_bytes(kek: &[u8; KEK_SIZE], secret_bytes: &[u8]) -> Vec<u8> {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
    use rand::RngCore;

    let cipher = Aes256Gcm::new_from_slice(kek).expect("valid key size");
    let mut nonce_bytes = [0_u8; GCM_NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let encrypted = cipher.encrypt(nonce, secret_bytes).expect("encryption");

    let mut file_data = Vec::with_capacity(1 + GCM_NONCE_SIZE + encrypted.len());
    file_data.push(ENCRYPTED_KEY_VERSION);
    file_data.extend_from_slice(&nonce_bytes);
    file_data.extend_from_slice(&encrypted);
    file_data
}

/// Decrypt an encrypted key file using the given KEK.
/// Returns the raw private key bytes.
#[cfg(test)]
fn decrypt_key_bytes(kek: &[u8; KEK_SIZE], file_data: &[u8]) -> Vec<u8> {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};

    assert_eq!(file_data[0], ENCRYPTED_KEY_VERSION);
    let nonce_bytes = &file_data[1..1 + GCM_NONCE_SIZE];
    let encrypted = &file_data[1 + GCM_NONCE_SIZE..];

    let cipher = Aes256Gcm::new_from_slice(kek).expect("valid key size");
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher.decrypt(nonce, encrypted).expect("decryption")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_dir() -> PathBuf {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("enclaveapp-sw-ks-test-{pid}-{id}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Test config with keyring disabled to avoid system keychain prompts.
    fn test_config(dir: &std::path::Path) -> SoftwareConfig {
        SoftwareConfig {
            app_name: "test-app".to_string(),
            keys_dir_override: Some(dir.to_path_buf()),
            use_keyring: false,
        }
    }

    #[test]
    fn is_available_returns_true() {
        assert!(is_available());
    }

    #[test]
    fn generate_creates_key_pub_meta_files() {
        let dir = test_dir();
        let config = test_config(&dir);
        let pub_key =
            generate_and_save(&config, "test-key", KeyType::Signing, AccessPolicy::None).unwrap();

        assert_eq!(pub_key.len(), 65);
        assert_eq!(pub_key[0], 0x04);
        assert!(dir.join("test-key.key").exists());
        assert!(dir.join("test-key.pub").exists());
        assert!(dir.join("test-key.meta").exists());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn generate_rejects_duplicate_labels() {
        let dir = test_dir();
        let config = test_config(&dir);
        generate_and_save(&config, "dup", KeyType::Signing, AccessPolicy::None).unwrap();
        let err =
            generate_and_save(&config, "dup", KeyType::Signing, AccessPolicy::None).unwrap_err();
        match err {
            Error::DuplicateLabel { label } => assert_eq!(label, "dup"),
            other => panic!("expected DuplicateLabel, got: {other}"),
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_secret_key_roundtrips() {
        let dir = test_dir();
        let config = test_config(&dir);
        generate_and_save(&config, "roundtrip", KeyType::Signing, AccessPolicy::None).unwrap();

        let secret = load_secret_key(&config, "roundtrip").unwrap();
        let pub_bytes: Vec<u8> = secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        assert_eq!(pub_bytes.len(), 65);
        assert_eq!(pub_bytes[0], 0x04);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_public_key_returns_65_bytes_starting_with_04() {
        let dir = test_dir();
        let config = test_config(&dir);
        let generated =
            generate_and_save(&config, "pub-test", KeyType::Signing, AccessPolicy::None).unwrap();

        let loaded = load_public_key(&config, "pub-test").unwrap();
        assert_eq!(loaded.len(), 65);
        assert_eq!(loaded[0], 0x04);
        assert_eq!(loaded, generated);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_public_key_falls_back_to_secret_key() {
        let dir = test_dir();
        let config = test_config(&dir);
        let generated =
            generate_and_save(&config, "fallback", KeyType::Signing, AccessPolicy::None).unwrap();

        // Remove the .pub file to force fallback
        std::fs::remove_file(dir.join("fallback.pub")).unwrap();

        let loaded = load_public_key(&config, "fallback").unwrap();
        assert_eq!(loaded, generated);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn generate_and_save_rejects_duplicate_pub_or_meta_without_private_key() {
        let dir = test_dir();
        let config = test_config(&dir);
        metadata::ensure_dir(&dir).unwrap();

        std::fs::write(dir.join("orphan.pub"), b"existing-pub").unwrap();
        let err =
            generate_and_save(&config, "orphan", KeyType::Signing, AccessPolicy::None).unwrap_err();
        assert!(matches!(err, Error::DuplicateLabel { label } if label == "orphan"));

        std::fs::remove_file(dir.join("orphan.pub")).unwrap();
        metadata::save_meta(
            &dir,
            "orphan",
            &KeyMeta::new("orphan", KeyType::Signing, AccessPolicy::None),
        )
        .unwrap();
        let err =
            generate_and_save(&config, "orphan", KeyType::Signing, AccessPolicy::None).unwrap_err();
        assert!(matches!(err, Error::DuplicateLabel { label } if label == "orphan"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn delete_key_removes_all_files() {
        let dir = test_dir();
        let config = test_config(&dir);
        generate_and_save(&config, "del-test", KeyType::Signing, AccessPolicy::None).unwrap();

        delete_key(&config, "del-test").unwrap();
        assert!(!dir.join("del-test.key").exists());
        assert!(!dir.join("del-test.pub").exists());
        assert!(!dir.join("del-test.meta").exists());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn list_labels_returns_sorted_labels() {
        let dir = test_dir();
        let config = test_config(&dir);
        generate_and_save(&config, "charlie", KeyType::Signing, AccessPolicy::None).unwrap();
        generate_and_save(&config, "alpha", KeyType::Encryption, AccessPolicy::None).unwrap();
        generate_and_save(&config, "bravo", KeyType::Signing, AccessPolicy::None).unwrap();

        let labels = list_labels(&config).unwrap();
        assert_eq!(labels, vec!["alpha", "bravo", "charlie"]);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_secret_key_fails_for_nonexistent() {
        let dir = test_dir();
        let config = test_config(&dir);
        let err = load_secret_key(&config, "ghost").unwrap_err();
        match err {
            Error::KeyNotFound { label } => assert_eq!(label, "ghost"),
            other => panic!("expected KeyNotFound, got: {other}"),
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }

    // --- Encrypted key format tests (no keyring needed) ---

    #[test]
    fn encrypt_decrypt_key_bytes_roundtrip() {
        use rand::RngCore;

        let mut kek = [0_u8; KEK_SIZE];
        rand::thread_rng().fill_bytes(&mut kek);

        let mut secret = [0_u8; RAW_KEY_SIZE];
        rand::thread_rng().fill_bytes(&mut secret);

        let encrypted = encrypt_key_bytes(&kek, &secret);
        let decrypted = decrypt_key_bytes(&kek, &encrypted);
        assert_eq!(decrypted, secret);
    }

    #[test]
    fn encrypted_file_format_has_correct_structure() {
        use rand::RngCore;

        let mut kek = [0_u8; KEK_SIZE];
        rand::thread_rng().fill_bytes(&mut kek);

        let secret = [0xAB_u8; RAW_KEY_SIZE];
        let encrypted = encrypt_key_bytes(&kek, &secret);

        // version(1) + nonce(12) + encrypted_key(32) + tag(16) = 61
        assert_eq!(encrypted.len(), MIN_ENCRYPTED_FILE_SIZE);
        assert_eq!(encrypted[0], ENCRYPTED_KEY_VERSION);
    }

    #[test]
    fn decrypt_fails_with_wrong_kek() {
        use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
        use rand::RngCore;

        let mut kek = [0_u8; KEK_SIZE];
        rand::thread_rng().fill_bytes(&mut kek);

        let secret = [0x42_u8; RAW_KEY_SIZE];
        let encrypted = encrypt_key_bytes(&kek, &secret);

        // Try with a different KEK
        let mut wrong_kek = [0_u8; KEK_SIZE];
        rand::thread_rng().fill_bytes(&mut wrong_kek);

        let nonce_bytes = &encrypted[1..1 + GCM_NONCE_SIZE];
        let ciphertext = &encrypted[1 + GCM_NONCE_SIZE..];

        let cipher = Aes256Gcm::new_from_slice(&wrong_kek).unwrap();
        let nonce = Nonce::from_slice(nonce_bytes);
        let result = cipher.decrypt(nonce, ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn backward_compat_raw_key_file_loads() {
        let dir = test_dir();
        let config = test_config(&dir);
        metadata::ensure_dir(&dir).unwrap();

        // Generate a key and manually write it as a raw 32-byte file (old format)
        let secret_key = SecretKey::random(&mut elliptic_curve::rand_core::OsRng);
        let secret_bytes = secret_key.to_bytes();
        let key_path = dir.join("legacy.key");
        std::fs::write(&key_path, &*secret_bytes).unwrap();

        // Also write the metadata so the key is findable
        let meta = KeyMeta::new("legacy", KeyType::Signing, AccessPolicy::None);
        metadata::save_meta(&dir, "legacy", &meta).unwrap();

        // load_secret_key should read the raw bytes directly
        let loaded = load_secret_key(&config, "legacy").unwrap();
        assert_eq!(loaded.to_bytes(), secret_bytes);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn unrecognized_file_format_returns_error() {
        let dir = test_dir();
        let config = test_config(&dir);
        metadata::ensure_dir(&dir).unwrap();

        // Write a file that is neither 32 bytes nor starts with 0x01 + valid length
        let key_path = dir.join("bad.key");
        std::fs::write(&key_path, [0x00; 50]).unwrap();

        let meta = KeyMeta::new("bad", KeyType::Signing, AccessPolicy::None);
        metadata::save_meta(&dir, "bad", &meta).unwrap();

        let err = load_secret_key(&config, "bad").unwrap_err();
        match err {
            Error::KeyOperation { operation, .. } => {
                assert_eq!(operation, "load_private_key");
            }
            other => panic!("expected KeyOperation, got: {other}"),
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn generate_sets_0600_permissions_on_key_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = test_dir();
        let config = test_config(&dir);
        generate_and_save(&config, "perm-test", KeyType::Signing, AccessPolicy::None).unwrap();

        let key_path = dir.join("perm-test.key");
        let mode = std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0600 permissions, got {mode:04o}");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn generate_with_invalid_label_returns_error() {
        let dir = test_dir();
        let config = test_config(&dir);

        let err = generate_and_save(&config, "", KeyType::Signing, AccessPolicy::None).unwrap_err();
        assert!(matches!(err, Error::InvalidLabel { .. }));

        let err = generate_and_save(&config, "bad/label", KeyType::Signing, AccessPolicy::None)
            .unwrap_err();
        assert!(matches!(err, Error::InvalidLabel { .. }));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn list_labels_empty_dir_returns_empty_vec() {
        let dir = test_dir();
        let config = test_config(&dir);
        // Ensure the dir exists but has no key files
        metadata::ensure_dir(&dir).unwrap();

        let labels = list_labels(&config).unwrap();
        assert!(labels.is_empty());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn delete_key_nonexistent_returns_key_not_found() {
        let dir = test_dir();
        let config = test_config(&dir);
        metadata::ensure_dir(&dir).unwrap();

        let err = delete_key(&config, "nonexistent").unwrap_err();
        match err {
            Error::KeyNotFound { label } => assert_eq!(label, "nonexistent"),
            other => panic!("expected KeyNotFound, got: {other}"),
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn delete_key_missing_dir_returns_key_not_found() {
        let dir =
            std::env::temp_dir().join(format!("enclaveapp-sw-missing-{}", std::process::id()));
        drop(std::fs::remove_dir_all(&dir));
        let config = SoftwareConfig::with_keys_dir("test-app", dir);
        let err = delete_key(&config, "ghost").unwrap_err();
        match err {
            Error::KeyNotFound { label } => assert_eq!(label, "ghost"),
            other => panic!("expected KeyNotFound, got: {other}"),
        }
    }

    #[test]
    fn key_storage_operations_reject_invalid_labels() {
        let dir = test_dir();
        let config = test_config(&dir);

        let err = load_secret_key(&config, "../escape").unwrap_err();
        assert!(matches!(err, Error::InvalidLabel { .. }));

        let err = load_public_key(&config, "../escape").unwrap_err();
        assert!(matches!(err, Error::InvalidLabel { .. }));

        let err = delete_key(&config, "../escape").unwrap_err();
        assert!(matches!(err, Error::InvalidLabel { .. }));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn delete_key_then_regenerate_same_label_succeeds() {
        let dir = test_dir();
        let config = test_config(&dir);

        let pub1 =
            generate_and_save(&config, "regen", KeyType::Signing, AccessPolicy::None).unwrap();
        delete_key(&config, "regen").unwrap();
        let pub2 =
            generate_and_save(&config, "regen", KeyType::Signing, AccessPolicy::None).unwrap();

        // New key should be different (different random key)
        assert_ne!(pub1, pub2);
        // But both should be valid 65-byte uncompressed points
        assert_eq!(pub2.len(), 65);
        assert_eq!(pub2[0], 0x04);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn encrypted_key_file_without_keyring_feature_returns_descriptive_error() {
        use rand::RngCore;

        let dir = test_dir();
        let config = test_config(&dir);
        metadata::ensure_dir(&dir).unwrap();

        // Create an encrypted key file manually using encrypt_key_bytes
        let mut kek = [0_u8; KEK_SIZE];
        rand::thread_rng().fill_bytes(&mut kek);
        let mut secret = [0_u8; RAW_KEY_SIZE];
        rand::thread_rng().fill_bytes(&mut secret);
        let encrypted = encrypt_key_bytes(&kek, &secret);

        let key_path = dir.join("enc-no-keyring.key");
        std::fs::write(&key_path, &encrypted).unwrap();

        let meta = KeyMeta::new("enc-no-keyring", KeyType::Signing, AccessPolicy::None);
        metadata::save_meta(&dir, "enc-no-keyring", &meta).unwrap();

        // On non-Linux-gnu targets (including macOS and Windows), the keyring-storage
        // feature is not compiled in, so loading should fail with a descriptive error.
        // On Linux-gnu without the feature, same behavior.
        #[cfg(not(all(feature = "keyring-storage", target_env = "gnu")))]
        {
            let err = load_secret_key(&config, "enc-no-keyring").unwrap_err();
            match err {
                Error::KeyOperation { detail, .. } => {
                    assert!(
                        detail.contains("keyring-storage"),
                        "error should mention keyring-storage feature, got: {detail}"
                    );
                }
                other => panic!("expected KeyOperation, got: {other}"),
            }
        }

        // On Linux-gnu WITH keyring-storage, decryption would fail because
        // the KEK isn't in the keyring, but that's a different error path
        // that we don't test here.
        #[cfg(all(feature = "keyring-storage", target_env = "gnu"))]
        {
            drop(config);
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn encrypted_key_format_version_byte_nonce_ciphertext_tag() {
        use rand::RngCore;

        let mut kek = [0_u8; KEK_SIZE];
        rand::thread_rng().fill_bytes(&mut kek);

        let secret = [0x55_u8; RAW_KEY_SIZE];
        let encrypted = encrypt_key_bytes(&kek, &secret);

        // Verify format: version(1) + nonce(12) + ciphertext(32) + tag(16)
        assert_eq!(encrypted[0], 0x01, "version byte should be 0x01");
        assert_eq!(
            encrypted.len(),
            1 + 12 + 32 + 16,
            "total length should be 61"
        );

        // Nonce is 12 bytes starting at offset 1
        let nonce = &encrypted[1..13];
        assert_eq!(nonce.len(), 12);

        // Ciphertext+tag is the remaining 48 bytes
        let ct_tag = &encrypted[13..];
        assert_eq!(ct_tag.len(), 32 + 16);
    }
}
