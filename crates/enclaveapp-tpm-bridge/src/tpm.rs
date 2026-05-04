// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! TPM 2.0 storage operations via libenclaveapp.
//!
//! On Windows, this uses `enclaveapp-windows::TpmEncryptor` to perform
//! hardware-backed ECIES encryption via the Windows CNG/NCrypt APIs.
//!
//! On non-Windows platforms, all operations return an error at runtime.

use enclaveapp_core::metadata;
use enclaveapp_core::traits::{EnclaveEncryptor, EnclaveKeyManager, EnclaveSigner};
use enclaveapp_core::types::{AccessPolicy, KeyType};
use std::path::Path;

#[cfg_attr(not(any(test, target_os = "windows")), allow(dead_code))]
fn existing_policy(keys_dir: &Path, key_label: &str) -> Option<AccessPolicy> {
    let meta_path = keys_dir.join(format!("{key_label}.meta"));
    if !meta_path.exists() {
        return None;
    }
    metadata::load_meta(keys_dir, key_label)
        .ok()
        .map(|meta| meta.access_policy)
}

#[cfg_attr(not(any(test, target_os = "windows")), allow(dead_code))]
pub(crate) fn ensure_key<E>(
    encryptor: &E,
    keys_dir: &Path,
    key_label: &str,
    policy: AccessPolicy,
) -> Result<(), String>
where
    E: EnclaveEncryptor + EnclaveKeyManager,
{
    if encryptor.public_key(key_label).is_ok() {
        match existing_policy(keys_dir, key_label) {
            Some(existing) if existing != policy => {
                encryptor
                    .delete_key(key_label)
                    .map_err(|e| format!("key deletion failed: {e}"))?;
            }
            _ => return Ok(()),
        }
    }

    encryptor
        .generate(key_label, KeyType::Encryption, policy)
        .map_err(|e| format!("key generation failed: {e}"))?;
    Ok(())
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) fn ensure_signing_key<S>(
    signer: &S,
    keys_dir: &Path,
    key_label: &str,
    policy: AccessPolicy,
) -> Result<(), String>
where
    S: EnclaveSigner + EnclaveKeyManager,
{
    if signer.public_key(key_label).is_ok() {
        match existing_policy(keys_dir, key_label) {
            Some(existing) if existing != policy => {
                signer
                    .delete_key(key_label)
                    .map_err(|e| format!("key deletion failed: {e}"))?;
            }
            _ => return Ok(()),
        }
    }

    signer
        .generate(key_label, KeyType::Signing, policy)
        .map_err(|e| format!("key generation failed: {e}"))?;
    Ok(())
}

#[cfg(target_os = "windows")]
mod platform {
    use super::{ensure_key, ensure_signing_key, metadata};
    use enclaveapp_core::traits::{EnclaveEncryptor, EnclaveKeyManager, EnclaveSigner};
    use enclaveapp_core::types::AccessPolicy;
    use enclaveapp_windows::{TpmEncryptor, TpmSigner};

    pub struct TpmStorage {
        encryptor: TpmEncryptor,
        key_label: String,
    }

    impl std::fmt::Debug for TpmStorage {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("TpmStorage")
                .field("key_label", &self.key_label)
                .finish_non_exhaustive()
        }
    }

    impl TpmStorage {
        pub fn new(
            app_name: &str,
            key_label: &str,
            access_policy: AccessPolicy,
        ) -> Result<Self, String> {
            let encryptor = TpmEncryptor::new(app_name);

            if !encryptor.is_available() {
                return Err("TPM not available".to_string());
            }

            ensure_key(
                &encryptor,
                &metadata::keys_dir(app_name),
                key_label,
                access_policy,
            )?;

            Ok(Self {
                encryptor,
                key_label: key_label.to_string(),
            })
        }

        pub fn delete(app_name: &str, key_label: &str) -> Result<(), String> {
            let encryptor = TpmEncryptor::new(app_name);

            if !encryptor.is_available() {
                return Err("TPM not available".to_string());
            }

            encryptor
                .delete_key(key_label)
                .map_err(|e| format!("key delete failed: {e}"))
        }

        pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
            self.encryptor
                .encrypt(&self.key_label, plaintext)
                .map_err(|e| e.to_string())
        }

        pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
            self.encryptor
                .decrypt(&self.key_label, ciphertext)
                .map_err(|e| e.to_string())
        }
    }

    pub struct TpmSigningStorage {
        signer: TpmSigner,
        key_label: String,
    }

    impl std::fmt::Debug for TpmSigningStorage {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("TpmSigningStorage")
                .field("key_label", &self.key_label)
                .finish_non_exhaustive()
        }
    }

    impl TpmSigningStorage {
        pub fn new(
            app_name: &str,
            key_label: &str,
            access_policy: AccessPolicy,
        ) -> Result<Self, String> {
            let signer = TpmSigner::new(app_name);

            if !signer.is_available() {
                return Err("TPM not available".to_string());
            }

            ensure_signing_key(
                &signer,
                &metadata::keys_dir(app_name),
                key_label,
                access_policy,
            )?;

            Ok(Self {
                signer,
                key_label: key_label.to_string(),
            })
        }

        pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, String> {
            self.signer
                .sign(&self.key_label, data)
                .map_err(|e| e.to_string())
        }

        pub fn public_key(&self) -> Result<Vec<u8>, String> {
            self.signer
                .public_key(&self.key_label)
                .map_err(|e| e.to_string())
        }

        pub fn list_keys(&self) -> Result<Vec<String>, String> {
            self.signer.list_keys().map_err(|e| e.to_string())
        }

        /// List signing keys for an app without requiring a per-label
        /// `init_signing`. Unlike the instance method above, this is
        /// the path the bridge server uses for `list_keys` so the
        /// agent's identity-enumeration doesn't create a `default`
        /// key as a side effect of the per-key init_signing prelude.
        pub fn list_keys_for_app(app_name: &str) -> Result<Vec<String>, String> {
            let signer = TpmSigner::new(app_name);
            if !signer.is_available() {
                return Err("TPM not available".to_string());
            }
            signer.list_keys().map_err(|e| e.to_string())
        }

        /// Read the public key for an existing (app_name, key_label)
        /// pair without `init_signing`. Same shape as the
        /// `list_keys_for_app` standalone helper added in libenclaveapp
        /// PR #110: lets the bridge server respond to a `public_key`
        /// request without going through TpmSigningStorage::new (which
        /// has create-if-missing semantics). If the key doesn't exist,
        /// the underlying `TpmSigner::public_key` returns
        /// `Error::KeyNotFound`, which is the right shape for clients
        /// to handle.
        pub fn public_key_for_app(app_name: &str, key_label: &str) -> Result<Vec<u8>, String> {
            let signer = TpmSigner::new(app_name);
            if !signer.is_available() {
                return Err("TPM not available".to_string());
            }
            signer.public_key(key_label).map_err(|e| e.to_string())
        }

        pub fn delete(app_name: &str, key_label: &str) -> Result<(), String> {
            let signer = TpmSigner::new(app_name);

            if !signer.is_available() {
                return Err("TPM not available".to_string());
            }

            signer
                .delete_key(key_label)
                .map_err(|e| format!("key delete failed: {e}"))
        }

        /// Check if a signing key exists without creating it. Unlike `new()`,
        /// this does not call `ensure_signing_key` so it has no side effects.
        pub fn key_exists(app_name: &str, key_label: &str) -> Result<bool, String> {
            let signer = TpmSigner::new(app_name);

            if !signer.is_available() {
                return Err("TPM not available".to_string());
            }

            match signer.public_key(key_label) {
                Ok(_) => Ok(true),
                Err(enclaveapp_core::Error::KeyNotFound { .. }) => Ok(false),
                Err(e) => Err(e.to_string()),
            }
        }
    }
}

#[cfg(not(target_os = "windows"))]
mod platform {
    use enclaveapp_core::types::AccessPolicy;

    #[derive(Debug)]
    pub struct TpmStorage {
        _app_name: String,
        _key_label: String,
        _access_policy: AccessPolicy,
    }

    impl TpmStorage {
        #[allow(clippy::unnecessary_wraps)]
        pub fn new(
            app_name: &str,
            key_label: &str,
            access_policy: AccessPolicy,
        ) -> Result<Self, String> {
            Ok(Self {
                _app_name: app_name.to_string(),
                _key_label: key_label.to_string(),
                _access_policy: access_policy,
            })
        }

        #[allow(clippy::unnecessary_wraps)]
        pub fn delete(_app_name: &str, _key_label: &str) -> Result<(), String> {
            Ok(())
        }

        #[allow(clippy::unused_self)]
        pub fn encrypt(&self, _plaintext: &[u8]) -> Result<Vec<u8>, String> {
            Err("TPM bridge is only supported on Windows".to_string())
        }

        #[allow(clippy::unused_self)]
        pub fn decrypt(&self, _ciphertext: &[u8]) -> Result<Vec<u8>, String> {
            Err("TPM bridge is only supported on Windows".to_string())
        }
    }

    #[derive(Debug)]
    pub struct TpmSigningStorage {
        _app_name: String,
        _key_label: String,
        _access_policy: AccessPolicy,
    }

    impl TpmSigningStorage {
        #[allow(clippy::unnecessary_wraps)]
        pub fn new(
            app_name: &str,
            key_label: &str,
            access_policy: AccessPolicy,
        ) -> Result<Self, String> {
            Ok(Self {
                _app_name: app_name.to_string(),
                _key_label: key_label.to_string(),
                _access_policy: access_policy,
            })
        }

        #[allow(clippy::unused_self)]
        pub fn sign(&self, _data: &[u8]) -> Result<Vec<u8>, String> {
            Err("TPM signing bridge is only supported on Windows".to_string())
        }

        #[allow(clippy::unused_self)]
        pub fn public_key(&self) -> Result<Vec<u8>, String> {
            Err("TPM signing bridge is only supported on Windows".to_string())
        }

        #[allow(clippy::unused_self)]
        pub fn list_keys(&self) -> Result<Vec<String>, String> {
            Err("TPM signing bridge is only supported on Windows".to_string())
        }

        pub fn list_keys_for_app(_app_name: &str) -> Result<Vec<String>, String> {
            Err("TPM signing bridge is only supported on Windows".to_string())
        }

        pub fn public_key_for_app(_app_name: &str, _key_label: &str) -> Result<Vec<u8>, String> {
            Err("TPM signing bridge is only supported on Windows".to_string())
        }

        #[allow(clippy::unnecessary_wraps)]
        pub fn delete(_app_name: &str, _key_label: &str) -> Result<(), String> {
            Ok(())
        }

        pub fn key_exists(_app_name: &str, _key_label: &str) -> Result<bool, String> {
            Err("TPM signing bridge is only supported on Windows".to_string())
        }
    }
}

pub use platform::TpmSigningStorage;
pub use platform::TpmStorage;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use enclaveapp_core::{Error, Result};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_dir() -> std::path::PathBuf {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("enclaveapp-tpm-bridge-test-{pid}-{id}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[derive(Default)]
    struct FakeState {
        has_key: bool,
        deleted: Vec<String>,
        generated: Vec<(String, KeyType, AccessPolicy)>,
    }

    #[derive(Default)]
    struct FakeEncryptor {
        state: Mutex<FakeState>,
    }

    impl FakeEncryptor {
        fn with_existing_key() -> Self {
            Self {
                state: Mutex::new(FakeState {
                    has_key: true,
                    deleted: Vec::new(),
                    generated: Vec::new(),
                }),
            }
        }

        fn deleted_labels(&self) -> Vec<String> {
            self.state.lock().unwrap().deleted.clone()
        }

        fn generated_calls(&self) -> Vec<(String, KeyType, AccessPolicy)> {
            self.state.lock().unwrap().generated.clone()
        }
    }

    impl EnclaveKeyManager for FakeEncryptor {
        fn generate(
            &self,
            label: &str,
            key_type: KeyType,
            policy: AccessPolicy,
        ) -> Result<Vec<u8>> {
            let mut state = self.state.lock().map_err(|e| Error::KeyOperation {
                operation: "lock".to_string(),
                detail: e.to_string(),
            })?;
            state.has_key = true;
            state.generated.push((label.to_string(), key_type, policy));
            Ok(vec![0x04; 65])
        }

        fn public_key(&self, label: &str) -> Result<Vec<u8>> {
            let state = self.state.lock().map_err(|e| Error::KeyOperation {
                operation: "lock".to_string(),
                detail: e.to_string(),
            })?;
            if state.has_key {
                Ok(vec![0x04; 65])
            } else {
                Err(Error::KeyNotFound {
                    label: label.to_string(),
                })
            }
        }

        fn list_keys(&self) -> Result<Vec<String>> {
            Ok(Vec::new())
        }

        fn delete_key(&self, label: &str) -> Result<()> {
            let mut state = self.state.lock().map_err(|e| Error::KeyOperation {
                operation: "lock".to_string(),
                detail: e.to_string(),
            })?;
            state.has_key = false;
            state.deleted.push(label.to_string());
            Ok(())
        }

        fn is_available(&self) -> bool {
            true
        }
    }

    impl EnclaveEncryptor for FakeEncryptor {
        fn encrypt(&self, _label: &str, _plaintext: &[u8]) -> Result<Vec<u8>> {
            Ok(Vec::new())
        }

        fn decrypt(&self, _label: &str, _ciphertext: &[u8]) -> Result<Vec<u8>> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn ensure_key_generates_when_missing() {
        let dir = test_dir();
        let encryptor = FakeEncryptor::default();

        ensure_key(&encryptor, &dir, "cache-key", AccessPolicy::BiometricOnly).unwrap();

        assert!(encryptor.deleted_labels().is_empty());
        assert_eq!(
            encryptor.generated_calls(),
            vec![(
                "cache-key".to_string(),
                KeyType::Encryption,
                AccessPolicy::BiometricOnly
            )]
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn ensure_key_regenerates_when_policy_mismatches() {
        let dir = test_dir();
        metadata::save_meta(
            &dir,
            "cache-key",
            &metadata::KeyMeta::new("cache-key", KeyType::Encryption, AccessPolicy::None),
        )
        .unwrap();
        let encryptor = FakeEncryptor::with_existing_key();

        ensure_key(&encryptor, &dir, "cache-key", AccessPolicy::BiometricOnly).unwrap();

        assert_eq!(encryptor.deleted_labels(), vec!["cache-key".to_string()]);
        assert_eq!(
            encryptor.generated_calls(),
            vec![(
                "cache-key".to_string(),
                KeyType::Encryption,
                AccessPolicy::BiometricOnly
            )]
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn ensure_key_keeps_existing_key_when_policy_matches() {
        let dir = test_dir();
        metadata::save_meta(
            &dir,
            "cache-key",
            &metadata::KeyMeta::new(
                "cache-key",
                KeyType::Encryption,
                AccessPolicy::BiometricOnly,
            ),
        )
        .unwrap();
        let encryptor = FakeEncryptor::with_existing_key();

        ensure_key(&encryptor, &dir, "cache-key", AccessPolicy::BiometricOnly).unwrap();

        assert!(encryptor.deleted_labels().is_empty());
        assert!(encryptor.generated_calls().is_empty());

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
