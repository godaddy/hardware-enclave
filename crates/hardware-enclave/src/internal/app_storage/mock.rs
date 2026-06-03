// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Mock encryption storage for testing without hardware.
//!
//! Uses AES-256-GCM with a random in-memory key. Provides no hardware
//! backing; suitable only for tests and development.

// aes-gcm 0.10 still uses generic-array 0.14 internally and emits a
// deprecation notice on `Nonce::from_slice` — the 1.x migration is
// upstream work, silence here so `-D warnings` doesn't trip.
#![allow(
    dead_code,
    unused_imports,
    unused_qualifications,
    unreachable_patterns,
    deprecated
)]

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use rand::RngCore;
use sha2::{Digest, Sha256};

use super::encryption::EncryptionStorage;
use super::error::{Result, StorageError};
use super::platform::BackendKind;

/// Nonce size for AES-256-GCM (96 bits).
const NONCE_SIZE: usize = 12;

/// Mock secure storage for testing.
///
/// Uses AES-256-GCM with a random in-memory key.
/// Encrypts/decrypts in a format compatible with test assertions
/// but does not provide hardware-backed security.
pub struct MockEncryptionStorage {
    cipher: Aes256Gcm,
}

impl std::fmt::Debug for MockEncryptionStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockEncryptionStorage")
            .field("cipher", &"<Aes256Gcm>")
            .finish()
    }
}

impl MockEncryptionStorage {
    /// Create a new mock storage with a randomly generated AES-256 key.
    pub fn new() -> Self {
        let mut key_bytes = [0_u8; 32];
        rand::thread_rng().fill_bytes(&mut key_bytes);
        Self::from_key_bytes(key_bytes)
    }

    /// Create a mock storage with a key deterministically derived from
    /// the application name.
    ///
    /// This is how [`create_encryption_storage`](crate::internal::app_storage::create_encryption_storage)
    /// instantiates the mock when [`MOCK_STORAGE_ENV`](crate::internal::app_storage::MOCK_STORAGE_ENV)
    /// is set. The deterministic key makes the mock viable across
    /// process boundaries — parent and child `cargo test` processes
    /// that both construct storage for the same app will land on the
    /// same AES key and can decrypt each other's ciphertexts. A
    /// random-keyed [`new`] would fail cross-process tests with
    /// `aead::Error` because each process would have its own key.
    ///
    /// The derivation is `SHA-256("enclaveapp-app-storage mock v1\0" || app_name)`.
    /// It is explicitly *not* cryptographically secret — anyone with
    /// the app name can recompute it. That is the point: this is a
    /// test-only backend.
    pub fn for_app(app_name: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"enclaveapp-app-storage mock v1\0");
        hasher.update(app_name.as_bytes());
        let key_bytes: [u8; 32] = hasher.finalize().into();
        Self::from_key_bytes(key_bytes)
    }

    fn from_key_bytes(key_bytes: [u8; 32]) -> Self {
        let cipher = Aes256Gcm::new_from_slice(&key_bytes)
            .expect("32-byte key is always valid for AES-256-GCM");
        Self { cipher }
    }
}

impl Default for MockEncryptionStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl EncryptionStorage for MockEncryptionStorage {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce_bytes = [0_u8; NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| StorageError::EncryptionFailed(e.to_string()))?;

        let mut output = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext);
        Ok(output)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < NONCE_SIZE {
            return Err(StorageError::DecryptionFailed(
                "ciphertext too short to contain nonce".into(),
            ));
        }

        let (nonce_bytes, encrypted) = ciphertext.split_at(NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);

        self.cipher
            .decrypt(nonce, encrypted)
            .map_err(|e| StorageError::DecryptionFailed(e.to_string()))
    }

    fn destroy(&self) -> Result<()> {
        Ok(())
    }

    fn is_available(&self) -> bool {
        true
    }

    fn backend_name(&self) -> &'static str {
        "Mock (AES-GCM)"
    }

    fn backend_kind(&self) -> BackendKind {
        BackendKind::Keyring
    }
}

// ── MockSigner ────────────────────────────────────────────────────────────────

use crate::internal::core::{
    traits::{EnclaveKeyManager, EnclaveSigner},
    types::{AccessPolicy, KeyType},
    Error as CoreError, Result as CoreResult,
};
use elliptic_curve::sec1::ToEncodedPoint;
use p256::{
    ecdsa::{signature::Signer, DerSignature, SigningKey},
    SecretKey,
};
use std::collections::BTreeMap;
use std::sync::Mutex;

/// Cross-platform mock signer for testing without hardware.
///
/// Stores P-256 private keys in memory (keyed by label). Implements the same
/// traits as the platform hardware backends so test code can use it via the
/// normal `create_signer()` factory when `ENCLAVEAPP_MOCK_STORAGE` is set.
pub struct MockSigner {
    keys: Mutex<BTreeMap<String, SecretKey>>,
}

impl std::fmt::Debug for MockSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockSigner").finish()
    }
}

impl MockSigner {
    pub fn new() -> Self {
        Self {
            keys: Mutex::new(BTreeMap::new()),
        }
    }
}

impl Default for MockSigner {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(unsafe_code)]
// Safety: MockSigner uses Mutex for all interior mutability.
unsafe impl Send for MockSigner {}
#[allow(unsafe_code)]
unsafe impl Sync for MockSigner {}

fn lock_mock<'mutex>(
    mutex: &'mutex Mutex<BTreeMap<String, SecretKey>>,
) -> std::sync::MutexGuard<'mutex, BTreeMap<String, SecretKey>> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

impl EnclaveKeyManager for MockSigner {
    fn generate(
        &self,
        label: &str,
        _key_type: KeyType,
        _policy: AccessPolicy,
    ) -> CoreResult<Vec<u8>> {
        let secret = SecretKey::random(&mut elliptic_curve::rand_core::OsRng);
        let pub_bytes = secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        lock_mock(&self.keys).insert(label.to_string(), secret);
        Ok(pub_bytes)
    }

    fn public_key(&self, label: &str) -> CoreResult<Vec<u8>> {
        lock_mock(&self.keys)
            .get(label)
            .map(|k| k.public_key().to_encoded_point(false).as_bytes().to_vec())
            .ok_or_else(|| CoreError::KeyNotFound {
                label: label.to_string(),
            })
    }

    fn list_keys(&self) -> CoreResult<Vec<String>> {
        Ok(lock_mock(&self.keys).keys().cloned().collect())
    }

    fn delete_key(&self, label: &str) -> CoreResult<()> {
        lock_mock(&self.keys)
            .remove(label)
            .map(|_| ())
            .ok_or_else(|| CoreError::KeyNotFound {
                label: label.to_string(),
            })
    }

    fn is_available(&self) -> bool {
        true
    }
}

impl EnclaveSigner for MockSigner {
    fn sign(&self, label: &str, data: &[u8]) -> CoreResult<Vec<u8>> {
        let keys = lock_mock(&self.keys);
        let secret = keys.get(label).ok_or_else(|| CoreError::KeyNotFound {
            label: label.to_string(),
        })?;
        let signing_key = SigningKey::from(secret);
        let sig: DerSignature = signing_key.sign(data);
        Ok(sig.to_bytes().to_vec())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let storage = MockEncryptionStorage::new();
        let plaintext = b"hello, secure world!";

        let ciphertext = storage.encrypt(plaintext).unwrap();
        assert_ne!(ciphertext, plaintext);
        assert!(ciphertext.len() > plaintext.len());

        let decrypted = storage.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_produces_different_ciphertexts() {
        let storage = MockEncryptionStorage::new();
        let plaintext = b"same input";

        let ct1 = storage.encrypt(plaintext).unwrap();
        let ct2 = storage.encrypt(plaintext).unwrap();
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn decrypt_empty_input_fails() {
        let storage = MockEncryptionStorage::new();
        assert!(storage.decrypt(&[]).is_err());
    }

    #[test]
    fn decrypt_short_input_fails() {
        let storage = MockEncryptionStorage::new();
        assert!(storage.decrypt(&[0_u8; 5]).is_err());
    }

    #[test]
    fn decrypt_tampered_ciphertext_fails() {
        let storage = MockEncryptionStorage::new();
        let mut ciphertext = storage.encrypt(b"sensitive data").unwrap();
        if let Some(byte) = ciphertext.get_mut(NONCE_SIZE + 1) {
            *byte ^= 0xff;
        }
        assert!(storage.decrypt(&ciphertext).is_err());
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        let s1 = MockEncryptionStorage::new();
        let s2 = MockEncryptionStorage::new();

        let ciphertext = s1.encrypt(b"key-specific").unwrap();
        assert!(s2.decrypt(&ciphertext).is_err());
    }

    #[test]
    fn decrypt_truncated_by_one_byte_fails() {
        // A ciphertext that is longer than the nonce but missing the last
        // byte of the GCM authentication tag must be rejected cleanly.
        let storage = MockEncryptionStorage::new();
        let mut ciphertext = storage.encrypt(b"truncation test").unwrap();
        assert!(
            ciphertext.len() > NONCE_SIZE,
            "ciphertext must exceed nonce"
        );
        ciphertext.pop(); // remove last byte
        let result = storage.decrypt(&ciphertext);
        assert!(
            result.is_err(),
            "truncated ciphertext must return Err, not panic"
        );
    }

    #[test]
    fn encrypt_empty_plaintext() {
        let storage = MockEncryptionStorage::new();
        let ciphertext = storage.encrypt(b"").unwrap();
        let decrypted = storage.decrypt(&ciphertext).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn encrypt_large_plaintext() {
        let storage = MockEncryptionStorage::new();
        let plaintext = vec![0xAB_u8; 100_000];
        let ciphertext = storage.encrypt(&plaintext).unwrap();
        let decrypted = storage.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn trait_methods() {
        let storage = MockEncryptionStorage::new();
        assert!(storage.is_available());
        assert_eq!(storage.backend_name(), "Mock (AES-GCM)");
        assert_eq!(storage.backend_kind(), BackendKind::Keyring);
        assert!(storage.destroy().is_ok());
    }

    #[test]
    fn default_impl_works() {
        let storage = MockEncryptionStorage::default();
        let ciphertext = storage.encrypt(b"default test").unwrap();
        let decrypted = storage.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, b"default test");
    }

    #[test]
    fn encrypt_decrypt_various_sizes() {
        let storage = MockEncryptionStorage::new();
        for size in [0, 1, 100, 10_000] {
            let plaintext = vec![0xAA_u8; size];
            let ciphertext = storage.encrypt(&plaintext).unwrap();
            let decrypted = storage.decrypt(&ciphertext).unwrap();
            assert_eq!(decrypted, plaintext, "roundtrip failed for size {size}");
        }
    }
}
