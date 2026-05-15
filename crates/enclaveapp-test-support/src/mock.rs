// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Mock implementations of `EnclaveKeyManager`, `EnclaveSigner`, and
//! `EnclaveEncryptor` for testing without hardware.

use enclaveapp_core::*;
use std::collections::HashMap;
use std::sync::Mutex;

/// A stored mock key.
#[derive(Clone, Debug)]
struct MockKey {
    #[allow(dead_code)]
    label: String,
    key_type: KeyType,
    #[allow(dead_code)]
    policy: AccessPolicy,
    public_key: Vec<u8>,   // 65-byte fake SEC1 point
    private_seed: Vec<u8>, // deterministic seed for signing/encryption
}

/// Mock key backend for testing. All operations are in-memory.
/// Keys are deterministic: the same label always produces the same key material.
#[derive(Debug)]
pub struct MockKeyBackend {
    keys: Mutex<HashMap<String, MockKey>>,
}

impl MockKeyBackend {
    /// Create a new empty mock backend.
    pub fn new() -> Self {
        MockKeyBackend {
            keys: Mutex::new(HashMap::new()),
        }
    }

    /// Generate a deterministic fake P-256 public key from a label.
    fn make_public_key(label: &str) -> Vec<u8> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        label.hash(&mut hasher);
        let hash = hasher.finish();
        let hash_bytes = hash.to_le_bytes();

        let mut key = vec![0x04_u8]; // uncompressed prefix
                                     // X coordinate: repeat hash bytes to fill 32 bytes
        for i in 0..32 {
            key.push(hash_bytes[i % 8]);
        }
        // Y coordinate: different pattern
        for i in 0..32 {
            key.push(hash_bytes[(i + 4) % 8] ^ 0xFF);
        }
        key
    }

    /// Generate a deterministic seed from a label for mock crypto.
    fn make_seed(label: &str) -> Vec<u8> {
        label.as_bytes().to_vec()
    }
}

impl Default for MockKeyBackend {
    fn default() -> Self {
        Self::new()
    }
}

/// Lock the mutex, converting a poison error to `Error::KeyOperation`.
fn lock_keys(
    keys: &Mutex<HashMap<String, MockKey>>,
) -> Result<std::sync::MutexGuard<'_, HashMap<String, MockKey>>> {
    keys.lock().map_err(|e| Error::KeyOperation {
        operation: "lock".into(),
        detail: format!("lock poisoned: {e}"),
    })
}

impl EnclaveKeyManager for MockKeyBackend {
    fn generate(&self, label: &str, key_type: KeyType, policy: AccessPolicy) -> Result<Vec<u8>> {
        types::validate_label(label)?;

        let mut keys = lock_keys(&self.keys)?;
        if keys.contains_key(label) {
            return Err(Error::DuplicateLabel {
                label: label.to_string(),
            });
        }

        let public_key = Self::make_public_key(label);
        let private_seed = Self::make_seed(label);

        keys.insert(
            label.to_string(),
            MockKey {
                label: label.to_string(),
                key_type,
                policy,
                public_key: public_key.clone(),
                private_seed,
            },
        );

        Ok(public_key)
    }

    fn public_key(&self, label: &str) -> Result<Vec<u8>> {
        let keys = lock_keys(&self.keys)?;
        keys.get(label)
            .map(|k| k.public_key.clone())
            .ok_or_else(|| Error::KeyNotFound {
                label: label.to_string(),
            })
    }

    fn list_keys(&self) -> Result<Vec<String>> {
        let keys = lock_keys(&self.keys)?;
        let mut labels: Vec<String> = keys.keys().cloned().collect();
        labels.sort();
        Ok(labels)
    }

    fn delete_key(&self, label: &str) -> Result<()> {
        let mut keys = lock_keys(&self.keys)?;
        if keys.remove(label).is_none() {
            return Err(Error::KeyNotFound {
                label: label.to_string(),
            });
        }
        Ok(())
    }

    fn is_available(&self) -> bool {
        true
    }
}

impl EnclaveSigner for MockKeyBackend {
    fn sign(&self, label: &str, data: &[u8]) -> Result<Vec<u8>> {
        let keys = lock_keys(&self.keys)?;
        let key = keys.get(label).ok_or_else(|| Error::KeyNotFound {
            label: label.to_string(),
        })?;

        if key.key_type != KeyType::Signing {
            return Err(Error::SignFailed {
                detail: "key is not a signing key".into(),
            });
        }

        // Deterministic mock signature: XOR data with seed, wrap in fake DER.
        // This is NOT cryptographically valid — it's for testing control flow only.
        let mut sig_data = Vec::with_capacity(data.len().min(32));
        for (i, &b) in data.iter().take(32).enumerate() {
            sig_data.push(b ^ key.private_seed[i % key.private_seed.len()]);
        }
        // Pad to 32 bytes if needed
        while sig_data.len() < 32 {
            sig_data.push(0);
        }

        // Wrap in a minimal DER SEQUENCE { INTEGER r, INTEGER s }
        let r = &sig_data[..16];
        let s = &sig_data[16..32];
        let mut der = Vec::new();
        der.push(0x30); // SEQUENCE tag
                        // Placeholder for length
        let seq_start = der.len();
        der.push(0);

        // INTEGER r
        der.push(0x02);
        if r[0] & 0x80 != 0 {
            der.push((r.len() + 1) as u8);
            der.push(0x00);
        } else {
            der.push(r.len() as u8);
        }
        der.extend_from_slice(r);

        // INTEGER s
        der.push(0x02);
        if s[0] & 0x80 != 0 {
            der.push((s.len() + 1) as u8);
            der.push(0x00);
        } else {
            der.push(s.len() as u8);
        }
        der.extend_from_slice(s);

        der[seq_start] = (der.len() - seq_start - 1) as u8;

        Ok(der)
    }
}

impl EnclaveEncryptor for MockKeyBackend {
    fn encrypt(&self, label: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        let keys = lock_keys(&self.keys)?;
        let key = keys.get(label).ok_or_else(|| Error::KeyNotFound {
            label: label.to_string(),
        })?;

        if key.key_type != KeyType::Encryption {
            return Err(Error::EncryptFailed {
                detail: "key is not an encryption key".into(),
            });
        }

        // Mock ECIES: XOR plaintext with repeating seed.
        // Format: [0x01 version] [plaintext XOR'd with seed]
        let mut ciphertext = vec![0x01_u8];
        for (i, &b) in plaintext.iter().enumerate() {
            ciphertext.push(b ^ key.private_seed[i % key.private_seed.len()]);
        }
        Ok(ciphertext)
    }

    fn decrypt(&self, label: &str, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let keys = lock_keys(&self.keys)?;
        let key = keys.get(label).ok_or_else(|| Error::KeyNotFound {
            label: label.to_string(),
        })?;

        if key.key_type != KeyType::Encryption {
            return Err(Error::DecryptFailed {
                detail: "key is not an encryption key".into(),
            });
        }

        if ciphertext.is_empty() || ciphertext[0] != 0x01 {
            return Err(Error::DecryptFailed {
                detail: "invalid ciphertext format".into(),
            });
        }

        // Reverse XOR
        let encrypted = &ciphertext[1..];
        let mut plaintext = Vec::with_capacity(encrypted.len());
        for (i, &b) in encrypted.iter().enumerate() {
            plaintext.push(b ^ key.private_seed[i % key.private_seed.len()]);
        }
        Ok(plaintext)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    // ── Key generation ──────────────────────────────────────────────────

    #[test]
    fn generate_signing_key_succeeds() {
        let backend = MockKeyBackend::new();
        let result = backend.generate("sign-key", KeyType::Signing, AccessPolicy::None);
        assert!(result.is_ok());
    }

    #[test]
    fn generate_encryption_key_succeeds() {
        let backend = MockKeyBackend::new();
        let result = backend.generate("enc-key", KeyType::Encryption, AccessPolicy::None);
        assert!(result.is_ok());
    }

    #[test]
    fn generate_duplicate_label_fails() {
        let backend = MockKeyBackend::new();
        backend
            .generate("dup", KeyType::Signing, AccessPolicy::None)
            .unwrap();
        let err = backend
            .generate("dup", KeyType::Signing, AccessPolicy::None)
            .unwrap_err();
        match err {
            Error::DuplicateLabel { label } => assert_eq!(label, "dup"),
            other => panic!("expected DuplicateLabel, got: {other}"),
        }
    }

    #[test]
    fn generate_invalid_label_fails() {
        let backend = MockKeyBackend::new();
        let err = backend
            .generate("", KeyType::Signing, AccessPolicy::None)
            .unwrap_err();
        match err {
            Error::InvalidLabel { .. } => {}
            other => panic!("expected InvalidLabel, got: {other}"),
        }

        let err = backend
            .generate("bad label", KeyType::Signing, AccessPolicy::None)
            .unwrap_err();
        match err {
            Error::InvalidLabel { .. } => {}
            other => panic!("expected InvalidLabel, got: {other}"),
        }
    }

    #[test]
    fn generated_public_key_is_65_bytes_uncompressed() {
        let backend = MockKeyBackend::new();
        let pub_key = backend
            .generate("test-key", KeyType::Signing, AccessPolicy::None)
            .unwrap();
        assert_eq!(pub_key.len(), 65);
        assert_eq!(pub_key[0], 0x04);
    }

    #[test]
    fn same_label_produces_same_public_key() {
        // Two separate backends with the same label produce identical keys
        let backend1 = MockKeyBackend::new();
        let backend2 = MockKeyBackend::new();
        let key1 = backend1
            .generate("deterministic", KeyType::Signing, AccessPolicy::None)
            .unwrap();
        let key2 = backend2
            .generate("deterministic", KeyType::Signing, AccessPolicy::None)
            .unwrap();
        assert_eq!(key1, key2);
    }

    // ── Key listing ─────────────────────────────────────────────────────

    #[test]
    fn list_empty_returns_empty() {
        let backend = MockKeyBackend::new();
        let labels = backend.list_keys().unwrap();
        assert!(labels.is_empty());
    }

    #[test]
    fn list_after_generate_returns_label() {
        let backend = MockKeyBackend::new();
        backend
            .generate("my-key", KeyType::Signing, AccessPolicy::None)
            .unwrap();
        let labels = backend.list_keys().unwrap();
        assert_eq!(labels, vec!["my-key"]);
    }

    #[test]
    fn list_returns_sorted_labels() {
        let backend = MockKeyBackend::new();
        backend
            .generate("charlie", KeyType::Signing, AccessPolicy::None)
            .unwrap();
        backend
            .generate("alpha", KeyType::Encryption, AccessPolicy::None)
            .unwrap();
        backend
            .generate("bravo", KeyType::Signing, AccessPolicy::None)
            .unwrap();
        let labels = backend.list_keys().unwrap();
        assert_eq!(labels, vec!["alpha", "bravo", "charlie"]);
    }

    #[test]
    fn list_after_delete_removes_label() {
        let backend = MockKeyBackend::new();
        backend
            .generate("keep", KeyType::Signing, AccessPolicy::None)
            .unwrap();
        backend
            .generate("remove", KeyType::Signing, AccessPolicy::None)
            .unwrap();
        backend.delete_key("remove").unwrap();
        let labels = backend.list_keys().unwrap();
        assert_eq!(labels, vec!["keep"]);
    }

    // ── Key deletion ────────────────────────────────────────────────────

    #[test]
    fn delete_existing_key_succeeds() {
        let backend = MockKeyBackend::new();
        backend
            .generate("to-delete", KeyType::Signing, AccessPolicy::None)
            .unwrap();
        assert!(backend.delete_key("to-delete").is_ok());
    }

    #[test]
    fn delete_nonexistent_key_fails() {
        let backend = MockKeyBackend::new();
        let err = backend.delete_key("ghost").unwrap_err();
        match err {
            Error::KeyNotFound { label } => assert_eq!(label, "ghost"),
            other => panic!("expected KeyNotFound, got: {other}"),
        }
    }

    #[test]
    fn delete_then_regenerate_same_label_succeeds() {
        let backend = MockKeyBackend::new();
        backend
            .generate("reuse", KeyType::Signing, AccessPolicy::None)
            .unwrap();
        backend.delete_key("reuse").unwrap();
        let result = backend.generate("reuse", KeyType::Encryption, AccessPolicy::None);
        assert!(result.is_ok());
    }

    // ── Public key ──────────────────────────────────────────────────────

    #[test]
    fn public_key_for_existing_key_returns_correct_bytes() {
        let backend = MockKeyBackend::new();
        let generated = backend
            .generate("pubkey-test", KeyType::Signing, AccessPolicy::None)
            .unwrap();
        let retrieved = backend.public_key("pubkey-test").unwrap();
        assert_eq!(generated, retrieved);
    }

    #[test]
    fn public_key_for_nonexistent_key_fails() {
        let backend = MockKeyBackend::new();
        let err = backend.public_key("missing").unwrap_err();
        match err {
            Error::KeyNotFound { label } => assert_eq!(label, "missing"),
            other => panic!("expected KeyNotFound, got: {other}"),
        }
    }

    // ── Signing ─────────────────────────────────────────────────────────

    #[test]
    fn sign_with_signing_key_succeeds() {
        let backend = MockKeyBackend::new();
        backend
            .generate("signer", KeyType::Signing, AccessPolicy::None)
            .unwrap();
        let sig = backend.sign("signer", b"hello world");
        assert!(sig.is_ok());
    }

    #[test]
    fn sign_with_encryption_key_fails() {
        let backend = MockKeyBackend::new();
        backend
            .generate("enc-only", KeyType::Encryption, AccessPolicy::None)
            .unwrap();
        let err = backend.sign("enc-only", b"data").unwrap_err();
        match err {
            Error::SignFailed { .. } => {}
            other => panic!("expected SignFailed, got: {other}"),
        }
    }

    #[test]
    fn sign_with_nonexistent_key_fails() {
        let backend = MockKeyBackend::new();
        let err = backend.sign("no-such-key", b"data").unwrap_err();
        match err {
            Error::KeyNotFound { label } => assert_eq!(label, "no-such-key"),
            other => panic!("expected KeyNotFound, got: {other}"),
        }
    }

    #[test]
    fn signature_is_deterministic() {
        let backend = MockKeyBackend::new();
        backend
            .generate("det-sign", KeyType::Signing, AccessPolicy::None)
            .unwrap();
        let sig1 = backend.sign("det-sign", b"same data").unwrap();
        let sig2 = backend.sign("det-sign", b"same data").unwrap();
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn signature_changes_with_different_data() {
        let backend = MockKeyBackend::new();
        backend
            .generate("diff-sign", KeyType::Signing, AccessPolicy::None)
            .unwrap();
        let sig1 = backend.sign("diff-sign", b"data one").unwrap();
        let sig2 = backend.sign("diff-sign", b"data two").unwrap();
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn signature_starts_with_der_sequence_tag() {
        let backend = MockKeyBackend::new();
        backend
            .generate("der-test", KeyType::Signing, AccessPolicy::None)
            .unwrap();
        let sig = backend.sign("der-test", b"test data").unwrap();
        assert_eq!(sig[0], 0x30, "signature should start with DER SEQUENCE tag");
    }

    // ── Encryption ──────────────────────────────────────────────────────

    #[test]
    fn encrypt_with_encryption_key_succeeds() {
        let backend = MockKeyBackend::new();
        backend
            .generate("encryptor", KeyType::Encryption, AccessPolicy::None)
            .unwrap();
        let result = backend.encrypt("encryptor", b"secret data");
        assert!(result.is_ok());
    }

    #[test]
    fn encrypt_with_signing_key_fails() {
        let backend = MockKeyBackend::new();
        backend
            .generate("sign-only", KeyType::Signing, AccessPolicy::None)
            .unwrap();
        let err = backend.encrypt("sign-only", b"data").unwrap_err();
        match err {
            Error::EncryptFailed { .. } => {}
            other => panic!("expected EncryptFailed, got: {other}"),
        }
    }

    #[test]
    fn encrypt_with_nonexistent_key_fails() {
        let backend = MockKeyBackend::new();
        let err = backend.encrypt("nope", b"data").unwrap_err();
        match err {
            Error::KeyNotFound { label } => assert_eq!(label, "nope"),
            other => panic!("expected KeyNotFound, got: {other}"),
        }
    }

    #[test]
    fn decrypt_reverses_encrypt() {
        let backend = MockKeyBackend::new();
        backend
            .generate("roundtrip", KeyType::Encryption, AccessPolicy::None)
            .unwrap();
        let plaintext = b"the quick brown fox jumps over the lazy dog";
        let ciphertext = backend.encrypt("roundtrip", plaintext).unwrap();
        let decrypted = backend.decrypt("roundtrip", &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let backend = MockKeyBackend::new();
        backend
            .generate("key-a", KeyType::Encryption, AccessPolicy::None)
            .unwrap();
        backend
            .generate("key-b", KeyType::Encryption, AccessPolicy::None)
            .unwrap();
        let ciphertext = backend.encrypt("key-a", b"secret").unwrap();
        // Decrypting with key-b should produce wrong plaintext (not the same as original)
        let wrong = backend.decrypt("key-b", &ciphertext).unwrap();
        assert_ne!(wrong, b"secret");
    }

    #[test]
    fn decrypt_invalid_format_fails() {
        let backend = MockKeyBackend::new();
        backend
            .generate("fmt-test", KeyType::Encryption, AccessPolicy::None)
            .unwrap();

        // Empty ciphertext
        let err = backend.decrypt("fmt-test", b"").unwrap_err();
        match err {
            Error::DecryptFailed { .. } => {}
            other => panic!("expected DecryptFailed, got: {other}"),
        }

        // Wrong version byte
        let err = backend.decrypt("fmt-test", &[0x02, 0x00]).unwrap_err();
        match err {
            Error::DecryptFailed { .. } => {}
            other => panic!("expected DecryptFailed, got: {other}"),
        }
    }

    #[test]
    fn empty_plaintext_roundtrip() {
        let backend = MockKeyBackend::new();
        backend
            .generate("empty-test", KeyType::Encryption, AccessPolicy::None)
            .unwrap();
        let ciphertext = backend.encrypt("empty-test", b"").unwrap();
        let decrypted = backend.decrypt("empty-test", &ciphertext).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn large_plaintext_roundtrip() {
        let backend = MockKeyBackend::new();
        backend
            .generate("large-test", KeyType::Encryption, AccessPolicy::None)
            .unwrap();
        let plaintext: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();
        let ciphertext = backend.encrypt("large-test", &plaintext).unwrap();
        let decrypted = backend.decrypt("large-test", &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    // ── Availability ────────────────────────────────────────────────────

    #[test]
    fn is_available_returns_true() {
        let backend = MockKeyBackend::new();
        assert!(backend.is_available());
    }

    // ── Thread safety ───────────────────────────────────────────────────

    #[test]
    fn generate_from_multiple_threads_does_not_panic() {
        use std::sync::Arc;

        let backend = Arc::new(MockKeyBackend::new());
        let mut handles = Vec::new();

        for i in 0..10 {
            let backend = Arc::clone(&backend);
            handles.push(std::thread::spawn(move || {
                let label = format!("thread-key-{i}");
                backend
                    .generate(&label, KeyType::Signing, AccessPolicy::None)
                    .unwrap();
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let labels = backend.list_keys().unwrap();
        assert_eq!(labels.len(), 10);
    }

    // ── Additional tests ───────────────────────────────────────────────

    #[test]
    fn generate_then_list_returns_sorted_labels() {
        let backend = MockKeyBackend::new();
        backend
            .generate("zebra", KeyType::Signing, AccessPolicy::None)
            .unwrap();
        backend
            .generate("alpha", KeyType::Encryption, AccessPolicy::None)
            .unwrap();
        backend
            .generate("mango", KeyType::Signing, AccessPolicy::None)
            .unwrap();
        let labels = backend.list_keys().unwrap();
        assert_eq!(labels, vec!["alpha", "mango", "zebra"]);
    }

    #[test]
    fn delete_all_keys_then_list_returns_empty() {
        let backend = MockKeyBackend::new();
        backend
            .generate("a", KeyType::Signing, AccessPolicy::None)
            .unwrap();
        backend
            .generate("b", KeyType::Encryption, AccessPolicy::None)
            .unwrap();
        backend
            .generate("c", KeyType::Signing, AccessPolicy::None)
            .unwrap();
        backend.delete_key("a").unwrap();
        backend.delete_key("b").unwrap();
        backend.delete_key("c").unwrap();
        let labels = backend.list_keys().unwrap();
        assert!(labels.is_empty());
    }

    #[test]
    fn sign_with_data_larger_than_1mb() {
        let backend = MockKeyBackend::new();
        backend
            .generate("big-sign", KeyType::Signing, AccessPolicy::None)
            .unwrap();
        let data: Vec<u8> = (0..1_100_000).map(|i| (i % 256) as u8).collect();
        let sig = backend.sign("big-sign", &data).unwrap();
        assert_eq!(sig[0], 0x30, "signature should start with DER SEQUENCE tag");
        // Signature should be deterministic
        let sig2 = backend.sign("big-sign", &data).unwrap();
        assert_eq!(sig, sig2);
    }

    #[test]
    fn encrypt_empty_plaintext_returns_valid_ciphertext() {
        let backend = MockKeyBackend::new();
        backend
            .generate("enc-empty", KeyType::Encryption, AccessPolicy::None)
            .unwrap();
        let ciphertext = backend.encrypt("enc-empty", b"").unwrap();
        // Ciphertext should be version byte only (0x01) for empty plaintext
        assert_eq!(ciphertext, vec![0x01]);
        let decrypted = backend.decrypt("enc-empty", &ciphertext).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn encrypt_1mb_plaintext_roundtrips() {
        let backend = MockKeyBackend::new();
        backend
            .generate("enc-1mb", KeyType::Encryption, AccessPolicy::None)
            .unwrap();
        let plaintext: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();
        let ciphertext = backend.encrypt("enc-1mb", &plaintext).unwrap();
        let decrypted = backend.decrypt("enc-1mb", &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn concurrent_generate_from_20_threads() {
        use std::sync::Arc;

        let backend = Arc::new(MockKeyBackend::new());
        let mut handles = Vec::new();

        for i in 0..20 {
            let backend = Arc::clone(&backend);
            handles.push(std::thread::spawn(move || {
                let label = format!("stress-key-{i:02}");
                backend
                    .generate(&label, KeyType::Signing, AccessPolicy::None)
                    .unwrap();
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let labels = backend.list_keys().unwrap();
        assert_eq!(labels.len(), 20);
    }

    #[test]
    fn concurrent_sign_from_10_threads_same_key() {
        use std::sync::Arc;

        let backend = Arc::new(MockKeyBackend::new());
        backend
            .generate("shared-signer", KeyType::Signing, AccessPolicy::None)
            .unwrap();

        let mut handles = Vec::new();
        for i in 0..10 {
            let backend = Arc::clone(&backend);
            handles.push(std::thread::spawn(move || {
                let data = format!("data-from-thread-{i}");
                backend.sign("shared-signer", data.as_bytes()).unwrap()
            }));
        }

        let mut signatures = Vec::new();
        for handle in handles {
            signatures.push(handle.join().unwrap());
        }

        // All signatures should start with DER SEQUENCE tag
        for sig in &signatures {
            assert_eq!(sig[0], 0x30);
        }
    }

    #[test]
    fn mock_key_backend_default_works() {
        let backend = MockKeyBackend::default();
        assert!(backend.is_available());
        assert!(backend.list_keys().unwrap().is_empty());
    }

    #[test]
    fn different_mock_key_backend_instances_are_independent() {
        let backend1 = MockKeyBackend::new();
        let backend2 = MockKeyBackend::new();

        backend1
            .generate("key-in-1", KeyType::Signing, AccessPolicy::None)
            .unwrap();
        backend2
            .generate("key-in-2", KeyType::Encryption, AccessPolicy::None)
            .unwrap();

        let labels1 = backend1.list_keys().unwrap();
        let labels2 = backend2.list_keys().unwrap();

        assert_eq!(labels1, vec!["key-in-1"]);
        assert_eq!(labels2, vec!["key-in-2"]);

        // key-in-1 should not exist in backend2
        assert!(backend2.public_key("key-in-1").is_err());
        // key-in-2 should not exist in backend1
        assert!(backend1.public_key("key-in-2").is_err());
    }

    #[test]
    fn key_exists_returns_true_for_generated_key() {
        let backend = MockKeyBackend::new();
        backend
            .generate("exists-key", KeyType::Signing, AccessPolicy::None)
            .unwrap();
        assert!(backend.key_exists("exists-key").unwrap());
    }

    #[test]
    fn key_exists_returns_false_for_missing_key() {
        let backend = MockKeyBackend::new();
        assert!(!backend.key_exists("ghost-key").unwrap());
    }

    #[test]
    fn key_exists_returns_false_after_delete() {
        let backend = MockKeyBackend::new();
        backend
            .generate("del-key", KeyType::Signing, AccessPolicy::None)
            .unwrap();
        backend.delete_key("del-key").unwrap();
        assert!(!backend.key_exists("del-key").unwrap());
    }

    #[test]
    fn rename_key_default_impl_returns_error() {
        let backend = MockKeyBackend::new();
        backend
            .generate("source", KeyType::Signing, AccessPolicy::None)
            .unwrap();
        let result = backend.rename_key("source", "target");
        assert!(result.is_err(), "default rename_key must return an error");
    }

    #[test]
    fn sign_with_presence_falls_back_to_sign() {
        use enclaveapp_core::PresenceMode;
        let backend = MockKeyBackend::new();
        backend
            .generate("signing-key", KeyType::Signing, AccessPolicy::None)
            .unwrap();
        let data = b"test data";
        let sig_regular = backend.sign("signing-key", data).unwrap();
        let sig_presence = backend
            .sign_with_presence("signing-key", data, PresenceMode::Cached, 30, "reason")
            .unwrap();
        assert_eq!(
            sig_regular, sig_presence,
            "sign_with_presence must delegate to sign"
        );
    }
}
