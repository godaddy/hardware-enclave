// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! High-level encryption storage with automatic platform detection.
//!
//! Replaces the per-app `secure_storage` modules in awsenc and sso-jwt.

#[allow(unused_imports)]
use crate::error::{Result, StorageError};
use crate::platform::BackendKind;
use crate::StorageConfig;
#[allow(unused_imports)]
use enclaveapp_core::metadata;
#[allow(unused_imports)]
use enclaveapp_core::traits::{EnclaveEncryptor, EnclaveKeyManager};
#[allow(unused_imports)]
use enclaveapp_core::types::{AccessPolicy, KeyType};
#[allow(unused_imports)]
use tracing::{debug, warn};

/// High-level encryption storage for consuming applications.
///
/// Handles platform detection, backend initialization, key lifecycle,
/// and encrypt/decrypt operations. This is the primary type consumers use.
///
/// Use via the [`EncryptionStorage`] trait or call methods directly.
pub struct AppEncryptionStorage {
    kind: BackendKind,
    app_name: String,
    key_label: String,
    access_policy: AccessPolicy,
    /// Resolved keys directory (honors `StorageConfig::keys_dir`
    /// override, otherwise `metadata::keys_dir(app_name)`). Stored
    /// here so `decrypt`'s per-op `check_meta_integrity` reaches
    /// the same `.meta` the platform encryptor wrote at keygen.
    keys_dir: std::path::PathBuf,
    inner: StorageInner,
}

// Internal enum dispatch — avoids Box<dyn> for the common case.
enum StorageInner {
    #[cfg(target_os = "macos")]
    SecureEnclave(enclaveapp_apple::SecureEnclaveEncryptor),

    #[cfg(target_os = "windows")]
    Tpm(enclaveapp_windows::TpmEncryptor),

    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    LinuxTpm(enclaveapp_linux_tpm::LinuxTpmEncryptor),

    #[cfg(target_os = "linux")]
    Software(enclaveapp_keyring::SoftwareEncryptor),

    #[cfg(target_os = "linux")]
    WslBridge { bridge_path: std::path::PathBuf },
}

impl std::fmt::Debug for AppEncryptionStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppEncryptionStorage")
            .field("kind", &self.kind)
            .field("app_name", &self.app_name)
            .field("key_label", &self.key_label)
            .field("access_policy", &self.access_policy)
            .finish()
    }
}

impl AppEncryptionStorage {
    /// Initialize encryption storage with automatic platform detection.
    ///
    /// 1. Detects the current platform (macOS/Windows/Linux/WSL)
    /// 2. Initializes the appropriate libenclaveapp backend
    /// 3. Checks if a key with the given label exists
    /// 4. If not, generates a new key with the configured access policy
    /// 5. If yes, checks that the existing key's policy matches;
    ///    on mismatch, re-generates (encryption keys protect temporary cached data)
    #[allow(clippy::needless_return, unreachable_code)]
    pub fn init(config: StorageConfig) -> Result<Self> {
        #[cfg(target_os = "macos")]
        {
            return Self::init_macos(&config);
        }

        #[cfg(target_os = "windows")]
        {
            return Self::init_windows(&config);
        }

        #[cfg(target_os = "linux")]
        {
            if config.force_keyring {
                debug!("--keyring flag: forcing software keyring backend for encryption");
                return Self::init_linux_keyring(&config);
            }
            if enclaveapp_wsl::is_wsl() {
                return Self::init_wsl(&config);
            }
            return Self::init_linux(&config);
        }

        #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
        {
            let _ = config;
            Err(StorageError::NotAvailable)
        }
    }

    fn resolved_keys_dir(config: &StorageConfig) -> std::path::PathBuf {
        config
            .keys_dir
            .clone()
            .unwrap_or_else(|| metadata::keys_dir(&config.app_name))
    }

    #[cfg(target_os = "macos")]
    fn init_macos(config: &StorageConfig) -> Result<Self> {
        let keys_dir = Self::resolved_keys_dir(config);
        let mut keychain_config =
            enclaveapp_apple::KeychainConfig::with_keys_dir(&config.app_name, keys_dir.clone())
                .with_user_presence(config.wrapping_key_user_presence)
                .with_cache_ttl(config.wrapping_key_cache_ttl);
        if let Some(ref group) = config.keychain_access_group {
            keychain_config = keychain_config.with_access_group(group.clone());
        }
        let encryptor = enclaveapp_apple::SecureEnclaveEncryptor::with_config(keychain_config);

        if !encryptor.is_available() {
            return Err(StorageError::NotAvailable);
        }

        Self::ensure_key(&encryptor, config, &keys_dir, config.access_policy)?;
        debug!(
            "Secure Enclave encryption ready (app={}, label={}, policy={:?})",
            config.app_name, config.key_label, config.access_policy
        );

        Ok(Self {
            kind: BackendKind::SecureEnclave,
            app_name: config.app_name.clone(),
            key_label: config.key_label.clone(),
            access_policy: config.access_policy,
            keys_dir,
            inner: StorageInner::SecureEnclave(encryptor),
        })
    }

    #[cfg(target_os = "windows")]
    fn init_windows(config: &StorageConfig) -> Result<Self> {
        let keys_dir = Self::resolved_keys_dir(config);

        // When the app opts into `prefer_windows_hello_ux`, the TPM key
        // is created without `NCRYPT_UI_PROTECT_KEY_FLAG` (no CryptUI
        // password dialog) and the on-disk AccessPolicy is forced to
        // `None`. Application-level Hello verification via
        // `UserConsentVerifier` gates the actual private-key operations.
        // See `enclaveapp_windows::hello_gate` for the documented
        // threat-model trade-off and `StorageConfig::prefer_windows_hello_ux`
        // for the per-app opt-in semantics.
        //
        // If the caller also passed a non-None AccessPolicy, log the
        // downgrade explicitly. The combination is permitted (callers
        // get soft Hello gating, not hardware-enforced biometric) but
        // it should be visible in audit logs so a misconfigured app
        // doesn't believe it's getting more than it asked for.
        let (effective_policy, hello_gate) = if config.prefer_windows_hello_ux {
            let gate = std::sync::Arc::new(enclaveapp_windows::hello_gate::HelloGate::new());
            if config.access_policy != AccessPolicy::None {
                tracing::info!(
                    app = %config.app_name,
                    requested_policy = ?config.access_policy,
                    "prefer_windows_hello_ux: TPM key created without NCRYPT_UI_PROTECT_KEY_FLAG \
                     and on-disk AccessPolicy recorded as None; Hello consent is enforced at the \
                     application level via UserConsentVerifier (soft gate). The caller-requested \
                     AccessPolicy is honored only as a UX intent signal, not as an OS-mediated \
                     hardware policy."
                );
            }
            (AccessPolicy::None, Some(gate))
        } else {
            (config.access_policy, None)
        };

        let mut encryptor =
            enclaveapp_windows::TpmEncryptor::with_keys_dir(&config.app_name, keys_dir.clone());
        if let Some(gate) = hello_gate.clone() {
            encryptor = encryptor.with_hello_gate(gate, config.wrapping_key_cache_ttl);
        }

        if !encryptor.is_available() {
            return Err(StorageError::NotAvailable);
        }

        Self::ensure_key(&encryptor, config, &keys_dir, effective_policy)?;
        debug!(
            "TPM encryption ready (app={}, label={}, requested_policy={:?}, effective_policy={:?}, hello_gate={})",
            config.app_name,
            config.key_label,
            config.access_policy,
            effective_policy,
            hello_gate.is_some(),
        );

        Ok(Self {
            kind: BackendKind::Tpm,
            app_name: config.app_name.clone(),
            key_label: config.key_label.clone(),
            access_policy: effective_policy,
            keys_dir,
            inner: StorageInner::Tpm(encryptor),
        })
    }

    #[cfg(target_os = "linux")]
    fn init_linux(config: &StorageConfig) -> Result<Self> {
        #[cfg(target_env = "gnu")]
        if enclaveapp_linux_tpm::is_available() {
            let keys_dir = Self::resolved_keys_dir(config);
            let encryptor = enclaveapp_linux_tpm::LinuxTpmEncryptor::with_keys_dir(
                &config.app_name,
                keys_dir.clone(),
            );
            Self::ensure_key(&encryptor, config, &keys_dir, config.access_policy)?;
            debug!("Linux TPM encryption ready (app={})", config.app_name);
            return Ok(Self {
                kind: BackendKind::Tpm,
                app_name: config.app_name.clone(),
                key_label: config.key_label.clone(),
                access_policy: config.access_policy,
                keys_dir,
                inner: StorageInner::LinuxTpm(encryptor),
            });
        }

        Self::init_linux_keyring(config)
    }

    #[cfg(target_os = "linux")]
    fn init_linux_keyring(config: &StorageConfig) -> Result<Self> {
        if !enclaveapp_keyring::has_keyring_feature() {
            return Err(StorageError::NotAvailable);
        }

        let keys_dir = Self::resolved_keys_dir(config);

        if config.access_policy != AccessPolicy::None {
            #[allow(clippy::print_stderr)]
            {
                eprintln!(
                    "warning: biometric/user-presence has no effect on Linux \
                     software fallback"
                );
            }
        }

        let encryptor = enclaveapp_keyring::SoftwareEncryptor::with_keys_dir(
            &config.app_name,
            keys_dir.clone(),
        );
        Self::ensure_key(&encryptor, config, &keys_dir, AccessPolicy::None)?;

        debug!(
            "Linux keyring encryption backend ready (app={})",
            config.app_name
        );

        Ok(Self {
            kind: BackendKind::Keyring,
            app_name: config.app_name.clone(),
            key_label: config.key_label.clone(),
            access_policy: config.access_policy,
            keys_dir,
            inner: StorageInner::Software(encryptor),
        })
    }

    #[cfg(target_os = "linux")]
    fn init_wsl(config: &StorageConfig) -> Result<Self> {
        let bridge_path =
            crate::platform::find_bridge_executable(&config.app_name, &config.extra_bridge_paths)
                .ok_or(StorageError::NotAvailable)?;

        debug!(
            "WSL TPM bridge found at {} (app={})",
            bridge_path.display(),
            config.app_name
        );
        enclaveapp_bridge::bridge_init(
            &bridge_path,
            &config.app_name,
            &config.key_label,
            config.access_policy,
        )
        .map_err(|e| StorageError::KeyInitFailed(e.to_string()))?;

        Ok(Self {
            kind: BackendKind::TpmBridge,
            app_name: config.app_name.clone(),
            key_label: config.key_label.clone(),
            access_policy: config.access_policy,
            keys_dir: Self::resolved_keys_dir(config),
            inner: StorageInner::WslBridge { bridge_path },
        })
    }

    /// Ensure a key exists with the correct access policy.
    /// If the key exists but has a different policy, re-generate it
    /// (encryption keys protect temporary cached data, so this is safe).
    fn ensure_key(
        encryptor: &impl EnclaveEncryptor,
        config: &StorageConfig,
        keys_dir: &std::path::Path,
        expected_policy: AccessPolicy,
    ) -> Result<()> {
        if encryptor.public_key(&config.key_label).is_ok() {
            // Don't reach into the platform secure store unless there's
            // actually a `.meta` file to verify. Same rationale as
            // `platform::verify_meta_integrity` — keeps test binaries
            // and synthetic probe paths off the macOS Keychain ACL
            // prompt path.
            let meta_path = keys_dir.join(format!("{}.meta", config.key_label));
            let meta_exists = meta_path.exists();
            // Key exists — verify the `.meta.hmac` sidecar first when a
            // per-app meta-HMAC key is available from the platform's
            // secure store (macOS Keychain, Windows DPAPI, Linux Secret
            // Service). A HMAC mismatch is a hard failure: someone
            // rewrote `.meta` after save, so we don't trust any stored
            // policy and refuse to proceed.
            //
            // A *missing* sidecar in strict mode is also a hard error
            // — that's exactly the threat-model promise the sidecar
            // is making ("attacker without secure-store access is
            // caught"). We allow a one-shot upgrade for caches
            // written by pre-strict-mode versions: if the sidecar is
            // missing, log a warning and migrate it from the current
            // meta so subsequent loads are strict. The migration
            // "blesses" whatever meta is on disk at first load after
            // upgrade — an inherent property of any HMAC migration.
            //
            // The dispatch lives in
            // `enclaveapp_app_storage::platform::meta_hmac_key`
            // which fans out per-platform. `None` returns mean the
            // platform store is unreachable; in that case we skip
            // the verification rather than refusing to proceed,
            // matching the legacy "Linux without Secret Service"
            // behavior.
            #[cfg(test)]
            let _ = meta_exists;
            #[cfg(test)]
            let hmac_key: Option<zeroize::Zeroizing<Vec<u8>>> = None;
            #[cfg(not(test))]
            let hmac_key = meta_exists
                .then(|| crate::platform::meta_hmac_key(&config.app_name))
                .flatten();
            if let Some(hmac_key) = hmac_key {
                let strict = metadata::load_meta_with_hmac(
                    keys_dir,
                    &config.key_label,
                    hmac_key.as_slice(),
                    metadata::MetaIntegrityMode::RequireSidecar,
                );
                if let Err(e) = strict {
                    let msg = e.to_string();
                    if msg.contains(metadata::META_HMAC_VERIFY_OP) {
                        return Err(StorageError::KeyInitFailed(msg));
                    }
                    if msg.contains(metadata::META_HMAC_MISSING_OP) {
                        warn!(
                            label = %config.key_label,
                            "`.meta.hmac` sidecar missing — migrating from existing meta. \
                             If you did not just upgrade, treat this as suspicious and \
                             regenerate the key."
                        );
                        if let Err(migrate_err) = metadata::migrate_meta_to_hmac(
                            keys_dir,
                            &config.key_label,
                            hmac_key.as_slice(),
                        ) {
                            return Err(StorageError::KeyInitFailed(migrate_err.to_string()));
                        }
                    }
                    // Other errors (deserialize failure, IO errors)
                    // fall through to the legacy handling below.
                }
            }
            // Key exists — check policy match.
            if let Ok(meta) = metadata::load_meta(keys_dir, &config.key_label) {
                if meta.access_policy != expected_policy {
                    warn!(
                        "key policy mismatch: existing={:?}, requested={:?}; re-generating key",
                        meta.access_policy, expected_policy
                    );
                    encryptor
                        .delete_key(&config.key_label)
                        .map_err(|e| StorageError::KeyInitFailed(e.to_string()))?;
                    // Fall through to generate below.
                } else {
                    return Ok(());
                }
            } else {
                // Metadata missing but key exists — use as-is. The key was likely
                // created before metadata tracking was introduced.
                warn!(
                    "key exists but metadata missing (label={}); using key with unknown policy",
                    config.key_label
                );
                return Ok(());
            }
        }

        debug!("generating new encryption key (label={})", config.key_label);
        encryptor
            .generate(&config.key_label, KeyType::Encryption, expected_policy)
            .map_err(|e| StorageError::KeyInitFailed(e.to_string()))?;

        // Stamp the per-key trust-anchor tag against the meta the
        // platform encryptor just wrote. The encryption side doesn't
        // run through `SshencBackend`'s re-stamp path (encryption
        // apps don't have a SshencBackend overlay), so the stamp
        // happens once at this layer and covers the apps' single
        // configured key. Best-effort on a meta-HMAC-key load
        // failure; the next ensure_key cycle on app start will
        // re-attempt and the user can recover via `<app> migrate-meta`
        // if it never succeeds.
        Self::stamp_trust_anchor(&config.app_name, &config.key_label, keys_dir);
        Ok(())
    }

    /// Stamp the per-key trust-anchor tag from the on-disk `.meta`.
    /// Platform-dispatching: macOS Keychain, Windows Credential
    /// Manager, Linux Secret Service. No-op on platforms without a
    /// trust-anchor implementation (currently always one of those
    /// three on supported targets).
    #[cfg_attr(
        not(any(target_os = "macos", target_os = "windows", target_os = "linux")),
        allow(unused_variables)
    )]
    fn stamp_trust_anchor(app_name: &str, label: &str, keys_dir: &std::path::Path) {
        #[cfg(all(not(test), target_os = "macos"))]
        {
            if let Ok(Some(hk)) = enclaveapp_apple::meta_hmac::load_existing(app_name) {
                let meta_path = keys_dir.join(format!("{label}.meta"));
                if let Ok(meta_bytes) = std::fs::read(&meta_path) {
                    let tag = metadata::compute_meta_hmac_bytes(hk.as_slice(), &meta_bytes);
                    if let Err(e) = enclaveapp_apple::meta_tag::store(app_name, label, &tag) {
                        warn!(
                            label = %label,
                            error = %e,
                            "encryption keygen meta-tag stamp failed"
                        );
                    }
                }
            }
        }
        #[cfg(all(not(test), target_os = "windows"))]
        {
            if let Ok(Some(hk)) = enclaveapp_windows::meta_hmac::load_or_create(app_name) {
                if let Err(e) = enclaveapp_windows::meta_tag::stamp_from_disk(
                    app_name,
                    label,
                    keys_dir,
                    hk.as_slice(),
                ) {
                    warn!(
                        label = %label,
                        error = %e,
                        "encryption keygen meta-tag stamp failed"
                    );
                }
            }
        }
        #[cfg(all(not(test), target_os = "linux"))]
        {
            if let Ok(Some(hk)) = enclaveapp_keyring::meta_hmac_key_existing(app_name) {
                if let Err(e) = enclaveapp_keyring::meta_tag::stamp_from_disk(
                    app_name,
                    label,
                    keys_dir,
                    hk.as_slice(),
                ) {
                    warn!(
                        label = %label,
                        error = %e,
                        "encryption keygen meta-tag stamp failed"
                    );
                }
            }
        }
        #[cfg(test)]
        let _ = (app_name, label, keys_dir);
    }
}

/// Encryption storage trait for dynamic dispatch (used with mock backend).
pub trait EncryptionStorage: Send + Sync {
    /// Encrypt plaintext. No biometric prompt (uses public key only).
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>>;
    /// Decrypt ciphertext. May trigger biometric if key has access policy.
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;
    /// Delete the key and associated files.
    fn destroy(&self) -> Result<()>;
    /// Whether the backend is available.
    fn is_available(&self) -> bool;
    /// Human-readable backend name.
    fn backend_name(&self) -> &'static str;
    /// Which backend is in use.
    fn backend_kind(&self) -> BackendKind;
}

impl EncryptionStorage for AppEncryptionStorage {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        match &self.inner {
            #[cfg(target_os = "macos")]
            StorageInner::SecureEnclave(enc) => enc
                .encrypt(&self.key_label, plaintext)
                .map_err(|e| StorageError::EncryptionFailed(e.to_string())),

            #[cfg(target_os = "windows")]
            StorageInner::Tpm(enc) => enc
                .encrypt(&self.key_label, plaintext)
                .map_err(|e| StorageError::EncryptionFailed(e.to_string())),

            #[cfg(all(target_os = "linux", target_env = "gnu"))]
            StorageInner::LinuxTpm(enc) => enc
                .encrypt(&self.key_label, plaintext)
                .map_err(|e| StorageError::EncryptionFailed(e.to_string())),

            #[cfg(target_os = "linux")]
            StorageInner::Software(enc) => enc
                .encrypt(&self.key_label, plaintext)
                .map_err(|e| StorageError::EncryptionFailed(e.to_string())),

            #[cfg(target_os = "linux")]
            StorageInner::WslBridge { bridge_path } => enclaveapp_bridge::bridge_encrypt(
                bridge_path,
                &self.app_name,
                &self.key_label,
                plaintext,
                self.access_policy,
            )
            .map_err(|e| StorageError::EncryptionFailed(e.to_string())),
        }
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        // Per-op trust-anchor check before invoking the platform
        // encryptor. Symmetric with the signing side: a same-UID
        // attacker who rewrites `.meta` between `ensure_key`
        // (init-time sidecar verify) and a later `decrypt` is
        // caught here. The init-time sidecar check is necessary
        // (it gates whether the key file is even loaded) but not
        // sufficient because long-lived processes don't re-init.
        // `check_meta_integrity` is platform-dispatching and
        // read-only.
        crate::platform::check_meta_integrity(&self.app_name, &self.key_label, &self.keys_dir)?;

        match &self.inner {
            #[cfg(target_os = "macos")]
            StorageInner::SecureEnclave(enc) => enc
                .decrypt(&self.key_label, ciphertext)
                .map_err(|e| StorageError::DecryptionFailed(e.to_string())),

            #[cfg(target_os = "windows")]
            StorageInner::Tpm(enc) => enc
                .decrypt(&self.key_label, ciphertext)
                .map_err(|e| StorageError::DecryptionFailed(e.to_string())),

            #[cfg(all(target_os = "linux", target_env = "gnu"))]
            StorageInner::LinuxTpm(enc) => enc
                .decrypt(&self.key_label, ciphertext)
                .map_err(|e| StorageError::DecryptionFailed(e.to_string())),

            #[cfg(target_os = "linux")]
            StorageInner::Software(enc) => enc
                .decrypt(&self.key_label, ciphertext)
                .map_err(|e| StorageError::DecryptionFailed(e.to_string())),

            #[cfg(target_os = "linux")]
            StorageInner::WslBridge { bridge_path } => enclaveapp_bridge::bridge_decrypt(
                bridge_path,
                &self.app_name,
                &self.key_label,
                ciphertext,
                self.access_policy,
            )
            .map_err(|e| StorageError::DecryptionFailed(e.to_string())),
        }
    }

    fn destroy(&self) -> Result<()> {
        match &self.inner {
            #[cfg(target_os = "macos")]
            StorageInner::SecureEnclave(enc) => enc
                .delete_key(&self.key_label)
                .map_err(|e| StorageError::KeyNotFound(e.to_string())),

            #[cfg(target_os = "windows")]
            StorageInner::Tpm(enc) => enc
                .delete_key(&self.key_label)
                .map_err(|e| StorageError::KeyNotFound(e.to_string())),

            #[cfg(all(target_os = "linux", target_env = "gnu"))]
            StorageInner::LinuxTpm(enc) => enc
                .delete_key(&self.key_label)
                .map_err(|e| StorageError::KeyNotFound(e.to_string())),

            #[cfg(target_os = "linux")]
            StorageInner::Software(enc) => enc
                .delete_key(&self.key_label)
                .map_err(|e| StorageError::KeyNotFound(e.to_string())),

            #[cfg(target_os = "linux")]
            StorageInner::WslBridge { bridge_path } => {
                enclaveapp_bridge::bridge_destroy(bridge_path, &self.app_name, &self.key_label)
                    .map_err(|e| StorageError::KeyNotFound(e.to_string()))
            }
        }
    }

    fn is_available(&self) -> bool {
        true
    }

    fn backend_name(&self) -> &'static str {
        match self.kind {
            BackendKind::SecureEnclave => "Secure Enclave",
            BackendKind::Tpm => "TPM 2.0",
            BackendKind::TpmBridge => "TPM 2.0 (WSL Bridge)",
            BackendKind::Keyring => "Linux (keyring)",
        }
    }

    fn backend_kind(&self) -> BackendKind {
        self.kind
    }
}

// Send + Sync: all inner types are Send + Sync (encryptors hold file paths and handles).
// The platform crates declare their types as Send + Sync.
#[allow(unsafe_code)]
unsafe impl Send for AppEncryptionStorage {}
#[allow(unsafe_code)]
unsafe impl Sync for AppEncryptionStorage {}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use enclaveapp_test_support::MockKeyBackend;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_dir() -> std::path::PathBuf {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("enclaveapp-enc-test-{pid}-{id}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn make_config(keys_dir: &std::path::Path) -> StorageConfig {
        StorageConfig {
            app_name: "test-app".into(),
            key_label: "test-key".into(),
            access_policy: AccessPolicy::None,
            extra_bridge_paths: vec![],
            keys_dir: Some(keys_dir.to_path_buf()),
            force_keyring: false,
            wrapping_key_user_presence: false,
            wrapping_key_cache_ttl: std::time::Duration::ZERO,
            keychain_access_group: None,
            prefer_windows_hello_ux: false,
        }
    }

    #[test]
    fn ensure_key_generates_new_key_when_none_exists() {
        let dir = test_dir();
        let backend = MockKeyBackend::new();
        let config = make_config(&dir);

        AppEncryptionStorage::ensure_key(&backend, &config, &dir, AccessPolicy::None).unwrap();

        // Key should now exist in the backend
        assert!(backend.public_key("test-key").is_ok());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn ensure_key_with_matching_policy_is_noop() {
        let dir = test_dir();
        let backend = MockKeyBackend::new();
        let config = make_config(&dir);

        // Generate key first
        backend
            .generate("test-key", KeyType::Encryption, AccessPolicy::None)
            .unwrap();
        // Save metadata with matching policy
        let meta = metadata::KeyMeta::new("test-key", KeyType::Encryption, AccessPolicy::None);
        metadata::save_meta(&dir, "test-key", &meta).unwrap();

        // ensure_key should be a no-op (key exists with matching policy)
        AppEncryptionStorage::ensure_key(&backend, &config, &dir, AccessPolicy::None).unwrap();

        // Key should still exist
        assert!(backend.public_key("test-key").is_ok());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn ensure_key_with_mismatched_policy_deletes_and_regenerates() {
        let dir = test_dir();
        let backend = MockKeyBackend::new();
        let mut config = make_config(&dir);
        config.access_policy = AccessPolicy::BiometricOnly;

        // Generate key with BiometricOnly policy
        backend
            .generate("test-key", KeyType::Encryption, AccessPolicy::BiometricOnly)
            .unwrap();
        let original_pub = backend.public_key("test-key").unwrap();

        // Save metadata with BiometricOnly
        let meta =
            metadata::KeyMeta::new("test-key", KeyType::Encryption, AccessPolicy::BiometricOnly);
        metadata::save_meta(&dir, "test-key", &meta).unwrap();

        // ensure_key with None policy should delete and regenerate
        AppEncryptionStorage::ensure_key(&backend, &config, &dir, AccessPolicy::None).unwrap();

        // Key should still exist but was regenerated (MockKeyBackend produces
        // deterministic keys from the label, so the public key will be the same
        // in the mock case — but the important thing is the operation succeeded)
        let new_pub = backend.public_key("test-key").unwrap();
        // Since MockKeyBackend is deterministic by label, the public key is the same
        assert_eq!(original_pub, new_pub);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn ensure_key_with_missing_metadata_but_existing_key_uses_as_is() {
        let dir = test_dir();
        let backend = MockKeyBackend::new();
        let config = make_config(&dir);

        // Generate key but don't save metadata
        backend
            .generate("test-key", KeyType::Encryption, AccessPolicy::None)
            .unwrap();

        // ensure_key should accept the key without metadata (legacy case)
        AppEncryptionStorage::ensure_key(&backend, &config, &dir, AccessPolicy::None).unwrap();

        // Key should still exist (wasn't deleted)
        assert!(backend.public_key("test-key").is_ok());
        // Only one key should exist (wasn't regenerated)
        assert_eq!(backend.list_keys().unwrap().len(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
