// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Software ECIES encryption backend (ECDH P-256 + AES-256-GCM).

use crate::key_storage::{self, SoftwareConfig};
use elliptic_curve::sec1::FromEncodedPoint;
use enclaveapp_core::traits::{EnclaveEncryptor, EnclaveKeyManager};
use enclaveapp_core::types::{validate_label, AccessPolicy, KeyType};
use enclaveapp_core::{Error, Result};

const ECIES_VERSION: u8 = 0x01;
const GCM_NONCE_SIZE: usize = 12;
const GCM_TAG_SIZE: usize = 16;
const UNCOMPRESSED_POINT_SIZE: usize = 65;
const MIN_CIPHERTEXT_LEN: usize = 1 + UNCOMPRESSED_POINT_SIZE + GCM_NONCE_SIZE + GCM_TAG_SIZE;

/// Software-based ECIES encryptor using P-256 ECDH + AES-256-GCM.
///
/// Private keys are stored as files on disk (not hardware-backed).
#[derive(Debug)]
pub struct SoftwareEncryptor {
    config: SoftwareConfig,
}

impl SoftwareEncryptor {
    pub fn new(app_name: &str) -> Self {
        Self {
            config: SoftwareConfig::new(app_name),
        }
    }

    pub fn with_keys_dir(app_name: &str, keys_dir: std::path::PathBuf) -> Self {
        Self {
            config: SoftwareConfig::with_keys_dir(app_name, keys_dir),
        }
    }

    /// Disable keyring-based key encryption (for testing or environments
    /// without a keyring daemon).
    ///
    /// When the `keyring-storage` feature is not enabled this is a no-op
    /// because keyring support is already absent.
    pub fn without_keyring(mut self) -> Self {
        self.config.use_keyring = false;
        self
    }
}

impl EnclaveKeyManager for SoftwareEncryptor {
    fn generate(&self, label: &str, key_type: KeyType, policy: AccessPolicy) -> Result<Vec<u8>> {
        validate_label(label)?;
        if key_type != KeyType::Encryption {
            return Err(Error::KeyOperation {
                operation: "generate".into(),
                detail: "SoftwareEncryptor only supports encryption keys".into(),
            });
        }
        key_storage::generate_and_save(&self.config, label, key_type, policy)
    }

    fn public_key(&self, label: &str) -> Result<Vec<u8>> {
        validate_label(label)?;
        key_storage::load_public_key(&self.config, label)
    }

    fn list_keys(&self) -> Result<Vec<String>> {
        key_storage::list_labels(&self.config)
    }

    fn delete_key(&self, label: &str) -> Result<()> {
        validate_label(label)?;
        key_storage::delete_key(&self.config, label)
    }

    fn is_available(&self) -> bool {
        true
    }
}

/// Derive a 32-byte AES key from ECDH shared secret using X9.63 KDF (single-pass SHA-256).
///
/// X9.63 KDF: SHA-256(shared_secret_x || counter_be32 || shared_info)
/// where counter = 0x00000001 for the first (and only) block.
/// shared_info = ephemeral public key bytes (65 bytes).
///
/// The derived AES key is returned as `Zeroizing<[u8; 32]>` so the
/// caller never holds the symmetric key past the AES-GCM op.
fn derive_key(
    shared_secret: &p256::ecdh::SharedSecret,
    eph_pub_bytes: &[u8],
) -> zeroize::Zeroizing<[u8; 32]> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(shared_secret.raw_secret_bytes());
    hasher.update([0x00, 0x00, 0x00, 0x01]); // counter = 1 (big-endian)
    hasher.update(eph_pub_bytes);
    let result = hasher.finalize();
    let mut key = zeroize::Zeroizing::new([0_u8; 32]);
    key.copy_from_slice(&result);
    key
}

impl EnclaveEncryptor for SoftwareEncryptor {
    fn encrypt(&self, label: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
        use elliptic_curve::sec1::ToEncodedPoint;
        use p256::ecdh::diffie_hellman;
        use rand::RngCore;

        validate_label(label)?;
        // Load the stored public key
        let pub_bytes = key_storage::load_public_key(&self.config, label)?;
        let stored_point =
            p256::EncodedPoint::from_bytes(&pub_bytes).map_err(|e| Error::EncryptFailed {
                detail: format!("invalid public key: {e}"),
            })?;
        let stored_pub = p256::PublicKey::from_encoded_point(&stored_point)
            .into_option()
            .ok_or_else(|| Error::EncryptFailed {
                detail: "invalid public key point".into(),
            })?;

        // Generate ephemeral key pair
        let eph_secret = p256::SecretKey::random(&mut elliptic_curve::rand_core::OsRng);
        let eph_pub = eph_secret.public_key();
        let eph_pub_bytes: Vec<u8> = eph_pub.to_encoded_point(false).as_bytes().to_vec();

        // ECDH shared secret
        let shared_secret = diffie_hellman(eph_secret.to_nonzero_scalar(), stored_pub.as_affine());

        // X9.63 KDF
        let derived_key = derive_key(&shared_secret, &eph_pub_bytes);

        // AES-256-GCM encrypt
        let cipher = Aes256Gcm::new_from_slice(derived_key.as_slice()).map_err(|e| {
            Error::EncryptFailed {
                detail: format!("AES init: {e}"),
            }
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
        use p256::ecdh::diffie_hellman;

        // AccessPolicy is stored in key metadata but is not enforced here.
        // The private key is loaded from the keyring and decrypted without any
        // user prompt, regardless of the policy recorded at generation time.
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

        // Parse
        let eph_pub_bytes = &ciphertext[1..66];
        let nonce_bytes = &ciphertext[66..78];
        let encrypted = &ciphertext[78..];

        // Load our secret key
        let secret = key_storage::load_secret_key(&self.config, label)?;

        // Reconstruct ephemeral public key
        let eph_point =
            p256::EncodedPoint::from_bytes(eph_pub_bytes).map_err(|e| Error::DecryptFailed {
                detail: format!("invalid ephemeral key: {e}"),
            })?;
        let eph_pub = p256::PublicKey::from_encoded_point(&eph_point)
            .into_option()
            .ok_or_else(|| Error::DecryptFailed {
                detail: "invalid ephemeral key point".into(),
            })?;

        // ECDH shared secret
        let shared_secret = diffie_hellman(secret.to_nonzero_scalar(), eph_pub.as_affine());

        // Same KDF
        let derived_key = derive_key(&shared_secret, eph_pub_bytes);

        // AES-256-GCM decrypt
        let cipher = Aes256Gcm::new_from_slice(derived_key.as_slice()).map_err(|e| {
            Error::DecryptFailed {
                detail: format!("AES init: {e}"),
            }
        })?;
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = cipher
            .decrypt(nonce, encrypted)
            .map_err(|e| Error::DecryptFailed {
                detail: format!("AES-GCM: {e}"),
            })?;

        Ok(plaintext)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_dir() -> PathBuf {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("enclaveapp-sw-enc-test-{pid}-{id}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let dir = test_dir();
        let enc = SoftwareEncryptor::with_keys_dir("test", dir.clone()).without_keyring();

        enc.generate("roundtrip", KeyType::Encryption, AccessPolicy::None)
            .unwrap();

        let plaintext = b"the quick brown fox jumps over the lazy dog";
        let ciphertext = enc.encrypt("roundtrip", plaintext).unwrap();
        let decrypted = enc.decrypt("roundtrip", &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn encrypt_produces_different_output_each_time() {
        let dir = test_dir();
        let enc = SoftwareEncryptor::with_keys_dir("test", dir.clone()).without_keyring();

        enc.generate("nonce-test", KeyType::Encryption, AccessPolicy::None)
            .unwrap();

        let plaintext = b"same data";
        let ct1 = enc.encrypt("nonce-test", plaintext).unwrap();
        let ct2 = enc.encrypt("nonce-test", plaintext).unwrap();
        assert_ne!(
            ct1, ct2,
            "different ephemeral keys should produce different ciphertext"
        );

        // But both decrypt to the same plaintext
        let pt1 = enc.decrypt("nonce-test", &ct1).unwrap();
        let pt2 = enc.decrypt("nonce-test", &ct2).unwrap();
        assert_eq!(pt1, plaintext.to_vec());
        assert_eq!(pt2, plaintext.to_vec());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn decrypt_fails_with_wrong_key() {
        let dir = test_dir();
        let enc = SoftwareEncryptor::with_keys_dir("test", dir.clone()).without_keyring();

        enc.generate("key-a", KeyType::Encryption, AccessPolicy::None)
            .unwrap();
        enc.generate("key-b", KeyType::Encryption, AccessPolicy::None)
            .unwrap();

        let ciphertext = enc.encrypt("key-a", b"secret").unwrap();
        let err = enc.decrypt("key-b", &ciphertext).unwrap_err();
        match err {
            Error::DecryptFailed { .. } => {}
            other => panic!("expected DecryptFailed, got: {other}"),
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn decrypt_fails_with_truncated_ciphertext() {
        let dir = test_dir();
        let enc = SoftwareEncryptor::with_keys_dir("test", dir.clone()).without_keyring();

        enc.generate("trunc-test", KeyType::Encryption, AccessPolicy::None)
            .unwrap();

        let err = enc.decrypt("trunc-test", &[0x01; 10]).unwrap_err();
        match err {
            Error::DecryptFailed { detail } => assert!(detail.contains("too short")),
            other => panic!("expected DecryptFailed, got: {other}"),
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn decrypt_fails_with_wrong_version_byte() {
        let dir = test_dir();
        let enc = SoftwareEncryptor::with_keys_dir("test", dir.clone()).without_keyring();

        enc.generate("ver-test", KeyType::Encryption, AccessPolicy::None)
            .unwrap();

        let mut ciphertext = enc.encrypt("ver-test", b"data").unwrap();
        ciphertext[0] = 0x02; // wrong version

        let err = enc.decrypt("ver-test", &ciphertext).unwrap_err();
        match err {
            Error::DecryptFailed { detail } => assert!(detail.contains("version")),
            other => panic!("expected DecryptFailed, got: {other}"),
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn empty_plaintext_roundtrip() {
        let dir = test_dir();
        let enc = SoftwareEncryptor::with_keys_dir("test", dir.clone()).without_keyring();

        enc.generate("empty-test", KeyType::Encryption, AccessPolicy::None)
            .unwrap();

        let ciphertext = enc.encrypt("empty-test", b"").unwrap();
        let decrypted = enc.decrypt("empty-test", &ciphertext).unwrap();
        assert!(decrypted.is_empty());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn large_plaintext_roundtrip() {
        let dir = test_dir();
        let enc = SoftwareEncryptor::with_keys_dir("test", dir.clone()).without_keyring();

        enc.generate("large-test", KeyType::Encryption, AccessPolicy::None)
            .unwrap();

        let plaintext: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
        let ciphertext = enc.encrypt("large-test", &plaintext).unwrap();
        let decrypted = enc.decrypt("large-test", &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn generate_rejects_signing_key_type() {
        let dir = test_dir();
        let enc = SoftwareEncryptor::with_keys_dir("test", dir.clone()).without_keyring();

        let err = enc
            .generate("sign-key", KeyType::Signing, AccessPolicy::None)
            .unwrap_err();
        match err {
            Error::KeyOperation { .. } => {}
            other => panic!("expected KeyOperation, got: {other}"),
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn ciphertext_has_correct_format() {
        let dir = test_dir();
        let enc = SoftwareEncryptor::with_keys_dir("test", dir.clone()).without_keyring();

        enc.generate("fmt-test", KeyType::Encryption, AccessPolicy::None)
            .unwrap();

        let ciphertext = enc.encrypt("fmt-test", b"hello").unwrap();

        // version byte
        assert_eq!(ciphertext[0], 0x01);
        // ephemeral public key (uncompressed point starts with 0x04)
        assert_eq!(ciphertext[1], 0x04);
        // Total overhead: 1 + 65 + 12 + 16 = 94 bytes beyond plaintext
        assert_eq!(ciphertext.len(), 1 + 65 + 12 + 5 + 16);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn is_available_returns_true() {
        let dir = test_dir();
        let enc = SoftwareEncryptor::with_keys_dir("test", dir.clone()).without_keyring();
        assert!(enc.is_available());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn encrypt_fails_for_nonexistent_key() {
        let dir = test_dir();
        let enc = SoftwareEncryptor::with_keys_dir("test", dir.clone()).without_keyring();

        let err = enc.encrypt("ghost", b"data").unwrap_err();
        match err {
            Error::KeyNotFound { label } => assert_eq!(label, "ghost"),
            other => panic!("expected KeyNotFound, got: {other}"),
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn decrypt_fails_for_nonexistent_key() {
        let dir = test_dir();
        let enc = SoftwareEncryptor::with_keys_dir("test", dir.clone()).without_keyring();

        // Craft a minimal valid-looking ciphertext
        let fake_ct = vec![0x01; MIN_CIPHERTEXT_LEN + 10];
        let err = enc.decrypt("ghost", &fake_ct).unwrap_err();
        match err {
            Error::KeyNotFound { label } => assert_eq!(label, "ghost"),
            // Also accept DecryptFailed since the fake ciphertext might fail point parsing first
            Error::DecryptFailed { .. } => {}
            other => panic!("expected KeyNotFound or DecryptFailed, got: {other}"),
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn decrypt_fails_with_corrupted_ciphertext() {
        let dir = test_dir();
        let enc = SoftwareEncryptor::with_keys_dir("test", dir.clone()).without_keyring();

        enc.generate("corrupt-test", KeyType::Encryption, AccessPolicy::None)
            .unwrap();

        let mut ciphertext = enc.encrypt("corrupt-test", b"test data").unwrap();
        // Flip a byte in the encrypted portion
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 0xFF;

        let err = enc.decrypt("corrupt-test", &ciphertext).unwrap_err();
        match err {
            Error::DecryptFailed { .. } => {}
            other => panic!("expected DecryptFailed, got: {other}"),
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn generate_returns_valid_65_byte_pubkey() {
        let dir = test_dir();
        let enc = SoftwareEncryptor::with_keys_dir("test", dir.clone()).without_keyring();

        let pub_bytes = enc
            .generate("gen-pubkey", KeyType::Encryption, AccessPolicy::None)
            .unwrap();
        assert_eq!(pub_bytes.len(), 65);
        assert_eq!(pub_bytes[0], 0x04, "SEC1 uncompressed point prefix");

        // Verify it's a valid P-256 point
        let pk = p256::PublicKey::from_sec1_bytes(&pub_bytes);
        assert!(pk.is_ok(), "must be a valid P-256 point");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn encrypt_decrypt_roundtrip_various_sizes() {
        let dir = test_dir();
        let enc = SoftwareEncryptor::with_keys_dir("test", dir.clone()).without_keyring();

        enc.generate("sizes-test", KeyType::Encryption, AccessPolicy::None)
            .unwrap();

        for size in [0, 1, 100, 10_000, 100_000] {
            let plaintext: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            let ciphertext = enc.encrypt("sizes-test", &plaintext).unwrap();
            let decrypted = enc.decrypt("sizes-test", &ciphertext).unwrap();
            assert_eq!(decrypted, plaintext, "roundtrip failed for size {size}");
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn ciphertext_format_detailed_structure() {
        let dir = test_dir();
        let enc = SoftwareEncryptor::with_keys_dir("test", dir.clone()).without_keyring();

        enc.generate("struct-test", KeyType::Encryption, AccessPolicy::None)
            .unwrap();

        let plaintext = b"hello world";
        let ciphertext = enc.encrypt("struct-test", plaintext).unwrap();

        // Version byte
        assert_eq!(ciphertext[0], 0x01);

        // Ephemeral public key: 65 bytes starting with 0x04
        assert_eq!(
            ciphertext[1], 0x04,
            "ephemeral pubkey should start with 0x04"
        );
        let eph_pub = &ciphertext[1..66];
        assert_eq!(eph_pub.len(), 65);

        // Verify ephemeral public key is a valid P-256 point
        let pk = p256::PublicKey::from_sec1_bytes(eph_pub);
        assert!(pk.is_ok());

        // Nonce: 12 bytes at offset 66
        let nonce = &ciphertext[66..78];
        assert_eq!(nonce.len(), 12);

        // Remaining: ciphertext (same length as plaintext) + 16-byte tag
        let encrypted_portion = &ciphertext[78..];
        assert_eq!(
            encrypted_portion.len(),
            plaintext.len() + 16,
            "encrypted portion should be plaintext_len + 16 (GCM tag)"
        );

        // Total: 1 + 65 + 12 + plaintext_len + 16
        assert_eq!(ciphertext.len(), 1 + 65 + 12 + plaintext.len() + 16);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn ciphertext_is_different_each_time_due_to_random_nonce_and_ephemeral_key() {
        let dir = test_dir();
        let enc = SoftwareEncryptor::with_keys_dir("test", dir.clone()).without_keyring();

        enc.generate("nonce-diff", KeyType::Encryption, AccessPolicy::None)
            .unwrap();

        let plaintext = b"same plaintext";
        let ct1 = enc.encrypt("nonce-diff", plaintext).unwrap();
        let ct2 = enc.encrypt("nonce-diff", plaintext).unwrap();

        // Full ciphertexts should differ
        assert_ne!(ct1, ct2);

        // Ephemeral public keys should differ (different random key each time)
        let eph1 = &ct1[1..66];
        let eph2 = &ct2[1..66];
        assert_ne!(eph1, eph2, "ephemeral public keys should be different");

        // Nonces should differ
        let nonce1 = &ct1[66..78];
        let nonce2 = &ct2[66..78];
        assert_ne!(nonce1, nonce2, "nonces should be different");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn decrypt_corrupted_nonce_returns_error() {
        let dir = test_dir();
        let enc = SoftwareEncryptor::with_keys_dir("test", dir.clone()).without_keyring();

        enc.generate("nonce-corrupt", KeyType::Encryption, AccessPolicy::None)
            .unwrap();

        let mut ciphertext = enc.encrypt("nonce-corrupt", b"test").unwrap();
        // Corrupt the nonce (bytes 66..78)
        ciphertext[70] ^= 0xFF;

        let err = enc.decrypt("nonce-corrupt", &ciphertext).unwrap_err();
        match err {
            Error::DecryptFailed { .. } => {}
            other => panic!("expected DecryptFailed, got: {other}"),
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn decrypt_corrupted_ephemeral_key_returns_error() {
        let dir = test_dir();
        let enc = SoftwareEncryptor::with_keys_dir("test", dir.clone()).without_keyring();

        enc.generate("eph-corrupt", KeyType::Encryption, AccessPolicy::None)
            .unwrap();

        let mut ciphertext = enc.encrypt("eph-corrupt", b"test").unwrap();
        // Corrupt a byte in the ephemeral public key (not the 0x04 prefix,
        // as that would fail point parsing, but an interior byte)
        ciphertext[10] ^= 0xFF;

        let err = enc.decrypt("eph-corrupt", &ciphertext).unwrap_err();
        match err {
            Error::DecryptFailed { .. } => {}
            other => panic!("expected DecryptFailed, got: {other}"),
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn generate_with_invalid_label_returns_error() {
        let dir = test_dir();
        let enc = SoftwareEncryptor::with_keys_dir("test", dir.clone()).without_keyring();

        // Empty label
        let err = enc
            .generate("", KeyType::Encryption, AccessPolicy::None)
            .unwrap_err();
        match err {
            Error::InvalidLabel { .. } => {}
            other => panic!("expected InvalidLabel for empty label, got: {other}"),
        }

        // Label with special characters
        let err = enc
            .generate("bad/label", KeyType::Encryption, AccessPolicy::None)
            .unwrap_err();
        match err {
            Error::InvalidLabel { .. } => {}
            other => panic!("expected InvalidLabel for label with slash, got: {other}"),
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn public_key_matches_generated() {
        let dir = test_dir();
        let enc = SoftwareEncryptor::with_keys_dir("test", dir.clone()).without_keyring();

        let generated = enc
            .generate("pk-match", KeyType::Encryption, AccessPolicy::None)
            .unwrap();
        let retrieved = enc.public_key("pk-match").unwrap();
        assert_eq!(generated, retrieved);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn list_keys_after_generate_includes_label() {
        let dir = test_dir();
        let enc = SoftwareEncryptor::with_keys_dir("test", dir.clone()).without_keyring();

        enc.generate("listed-enc-key", KeyType::Encryption, AccessPolicy::None)
            .unwrap();

        let keys = enc.list_keys().unwrap();
        assert!(keys.contains(&"listed-enc-key".to_string()));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn delete_key_then_encrypt_returns_key_not_found() {
        let dir = test_dir();
        let enc = SoftwareEncryptor::with_keys_dir("test", dir.clone()).without_keyring();

        enc.generate("del-enc", KeyType::Encryption, AccessPolicy::None)
            .unwrap();
        enc.delete_key("del-enc").unwrap();

        let err = enc.encrypt("del-enc", b"data").unwrap_err();
        match err {
            Error::KeyNotFound { label } => assert_eq!(label, "del-enc"),
            other => panic!("expected KeyNotFound, got: {other}"),
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn software_encryptor_rejects_invalid_labels_across_operations() {
        let dir = test_dir();
        let enc = SoftwareEncryptor::with_keys_dir("test", dir.clone()).without_keyring();

        let err = enc.public_key("../escape").unwrap_err();
        assert!(matches!(err, Error::InvalidLabel { .. }));

        let err = enc.delete_key("../escape").unwrap_err();
        assert!(matches!(err, Error::InvalidLabel { .. }));

        let err = enc.encrypt("../escape", b"payload").unwrap_err();
        assert!(matches!(err, Error::InvalidLabel { .. }));

        let err = enc.decrypt("../escape", b"ciphertext").unwrap_err();
        assert!(matches!(err, Error::InvalidLabel { .. }));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn one_byte_plaintext_roundtrip() {
        let dir = test_dir();
        let enc = SoftwareEncryptor::with_keys_dir("test", dir.clone()).without_keyring();

        enc.generate("one-byte", KeyType::Encryption, AccessPolicy::None)
            .unwrap();

        let plaintext = &[0x42_u8];
        let ciphertext = enc.encrypt("one-byte", plaintext).unwrap();
        let decrypted = enc.decrypt("one-byte", &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn decrypt_exactly_min_ciphertext_len_with_bad_data() {
        let dir = test_dir();
        let enc = SoftwareEncryptor::with_keys_dir("test", dir.clone()).without_keyring();

        enc.generate("min-len", KeyType::Encryption, AccessPolicy::None)
            .unwrap();

        // Exactly MIN_CIPHERTEXT_LEN bytes with version 0x01 but garbage data
        let mut fake = vec![0x01_u8; MIN_CIPHERTEXT_LEN];
        // Set the "ephemeral public key" first byte to 0x04 to look like a point
        fake[1] = 0x04;

        let err = enc.decrypt("min-len", &fake).unwrap_err();
        match err {
            Error::DecryptFailed { .. } => {}
            other => panic!("expected DecryptFailed, got: {other}"),
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
