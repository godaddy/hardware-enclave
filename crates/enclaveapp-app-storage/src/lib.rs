// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! High-level application storage for hardware-backed key management.
//!
//! This crate provides shared platform detection, key initialization, and
//! encrypt/decrypt/sign wrapping that all consuming applications need.
//! It replaces the per-app `secure_storage` modules in awsenc and sso-jwt,
//! and the platform detection logic in sshenc.
//!
//! # Usage
//!
//! For encryption (awsenc, sso-jwt):
//! ```no_run
//! use enclaveapp_app_storage::{AppEncryptionStorage, StorageConfig, AccessPolicy, EncryptionStorage};
//!
//! let storage = AppEncryptionStorage::init(StorageConfig {
//!     app_name: "myapp".into(),
//!     key_label: "cache-key".into(),
//!     access_policy: AccessPolicy::BiometricOnly,
//!     extra_bridge_paths: vec![],
//!     keys_dir: None,
//!     force_keyring: false,
//!     wrapping_key_user_presence: false,
//!     wrapping_key_cache_ttl: std::time::Duration::ZERO,
//!     keychain_access_group: None,
//!     prefer_windows_hello_ux: false,
//! })?;
//!
//! let ciphertext = storage.encrypt(b"secret")?;
//! let plaintext = storage.decrypt(&ciphertext)?;
//! # Ok::<(), enclaveapp_app_storage::StorageError>(())
//! ```
//!
//! For signing (sshenc):
//! ```no_run
//! use enclaveapp_app_storage::{AppSigningBackend, StorageConfig, AccessPolicy};
//!
//! let backend = AppSigningBackend::init(StorageConfig {
//!     app_name: "sshenc".into(),
//!     key_label: "default".into(),
//!     access_policy: AccessPolicy::None,
//!     extra_bridge_paths: vec![],
//!     keys_dir: None,
//!     force_keyring: false,
//!     wrapping_key_user_presence: false,
//!     wrapping_key_cache_ttl: std::time::Duration::ZERO,
//!     keychain_access_group: None,
//!     prefer_windows_hello_ux: false,
//! })?;
//!
//! // Use the underlying signer/key_manager for operations.
//! let signer = backend.signer();
//! let key_manager = backend.key_manager();
//! # Ok::<(), enclaveapp_app_storage::StorageError>(())
//! ```

#[cfg(target_os = "linux")]
mod backend_marker;
pub mod encryption;
pub mod error;
#[cfg(feature = "mock")]
pub mod mock;
pub mod platform;
pub mod signing;

// Re-export primary types for consumers.
pub use encryption::{AppEncryptionStorage, EncryptionStorage};
pub use error::{Result, StorageError};
#[cfg(feature = "mock")]
pub use mock::MockEncryptionStorage;
pub use platform::BackendKind;
pub use signing::AppSigningBackend;

// Re-export core types so consumers don't need a separate enclaveapp-core dep.
pub use enclaveapp_core::metadata::KeyMeta;
pub use enclaveapp_core::traits::{EnclaveEncryptor, EnclaveKeyManager, EnclaveSigner};
pub use enclaveapp_core::types::{AccessPolicy, KeyType};

/// Configuration for initializing application storage.
#[derive(Debug, Clone)]
pub struct StorageConfig {
    /// Application name (e.g., "awsenc", "sso-jwt", "sshenc").
    /// Used to namespace keys and locate config directories.
    pub app_name: String,
    /// Key label (e.g., "cache-key", "default").
    pub key_label: String,
    /// Access policy for key operations.
    pub access_policy: AccessPolicy,
    /// Extra WSL bridge paths beyond the auto-derived defaults.
    /// The standard discovery and auto-derived trusted paths are tried first.
    /// These must be explicit absolute override paths for app-specific legacy locations.
    pub extra_bridge_paths: Vec<String>,
    /// Override the keys directory (default: `~/.config/<app_name>/keys/`).
    /// sshenc uses `~/.sshenc/keys/` which differs from the standard layout.
    pub keys_dir: Option<std::path::PathBuf>,
    /// Force the software keyring backend, bypassing WSL bridge detection and
    /// libtss2 TPM probing. Linux only — ignored on macOS and Windows.
    /// Useful for testing the keyring path from WSL environments.
    pub force_keyring: bool,
    /// (macOS only) Protect the wrapping-key keychain item with a
    /// `SecAccessControl(.userPresence)` flag so access is gated on
    /// Touch ID / device passcode instead of the legacy code-signature
    /// ACL. Trades a one-time LocalAuthentication prompt per process
    /// (combined with `wrapping_key_cache_ttl`) for the elimination of
    /// the "Always Allow" dialog that otherwise re-appears on every
    /// unsigned-binary rebuild. Default: `false`.
    pub wrapping_key_user_presence: bool,
    /// (macOS only) How long the process may re-use a loaded wrapping
    /// key without another keychain round-trip (and, on user-presence
    /// items, another LocalAuthentication prompt). `Duration::ZERO`
    /// disables the cache. Default: `ZERO`.
    pub wrapping_key_cache_ttl: std::time::Duration,
    /// (macOS only) Data Protection keychain access group, in
    /// `<TEAMID>.<group>` form. When `Some`, wrapping-key items are
    /// stored in the modern Data Protection keychain (which actually
    /// accepts the `.userPresence` ACL — the legacy keychain rejects
    /// it with `errSecParam` -50). The calling binary MUST be
    /// codesigned with a `keychain-access-groups` entitlement listing
    /// the same group, otherwise SecItemAdd returns
    /// `errSecMissingEntitlement` -34018 and the bridge falls back to
    /// the legacy keychain (no userPresence gate).
    ///
    /// When `None` (default), the legacy keychain is used directly,
    /// which accepts unsigned callers but rejects userPresence ACLs.
    /// Default: `None`.
    pub keychain_access_group: Option<String>,
    /// (Windows only) Surface a Windows Hello biometric/PIN prompt at
    /// encrypt/decrypt time instead of the legacy `NCRYPT_UI_PROTECT_KEY_FLAG`
    /// CryptUI password protector dialog. When `true`:
    ///
    /// - The TPM encryption key is created WITHOUT `NCRYPT_UI_PROTECT_KEY_FLAG`,
    ///   so the OS does not surface the legacy password dialog at finalize
    ///   or at sign/decrypt time.
    /// - `NCryptCreatePersistedKey`, `NCryptFinalizeKey`, and `NCryptOpenKey`
    ///   are all invoked with `NCRYPT_SILENT_FLAG` so the KSP cannot
    ///   surface its own UI; if it would need to, the call fails with
    ///   `NTE_SILENT_CONTEXT` rather than showing a surprise dialog.
    /// - Each encrypt and decrypt is gated by
    ///   `Windows.Security.Credentials.UI.UserConsentVerifier.RequestVerificationAsync(...)`,
    ///   which fires the modern Windows Hello biometric/PIN UI.
    /// - The verification is cached for `wrapping_key_cache_ttl` so repeated
    ///   operations within the window do not re-prompt.
    ///
    /// **AccessPolicy override:** When this flag is `true` the
    /// [`StorageConfig::access_policy`] field is **overridden to
    /// `AccessPolicy::None` at the OS-level key creation step**
    /// (the on-disk meta records `None`). The Hello consent prompt is
    /// the application-level access enforcement; the TPM key itself
    /// carries no OS-mediated UI policy. Callers that pass
    /// `BiometricOnly` together with `prefer_windows_hello_ux: true`
    /// are getting **soft Hello gating, not hardware-enforced
    /// biometric**. That trade-off is intentional and is logged at
    /// `tracing::info` level so the override is auditable.
    ///
    /// **Threat-model target:** *same-UID file-on-disk attackers*
    /// (backup tools, AV upload agents, OneDrive sync of the profile
    /// dir, accidental git commits, colleagues `cat`-ing the
    /// credential file, supply-chain dependencies that scan `$HOME`).
    /// The TPM-resident wrapping key makes the on-disk ciphertext
    /// useless without invoking the TPM operation on the original
    /// machine while authenticated as the original user. A stolen
    /// file is just ciphertext. This is a major upgrade over the
    /// `chmod 0600` posture that preceded it.
    ///
    /// **Out of scope:** same-UID active malware (code execution as
    /// the same user). `UserConsentVerifier`'s `Verified` Boolean is
    /// a user-mode result consumed by the calling process; same-UID
    /// code can hook it or call `NCryptSecretAgreement` on the TPM
    /// key directly. That attacker class has higher-leverage paths
    /// regardless (reading process memory after legitimate unlock,
    /// keystroke capture, etc.), so the soft gate is a UX consent
    /// signal, not a hard cryptographic boundary against malware.
    ///
    /// No-op on non-Windows platforms. Default: `false`.
    pub prefer_windows_hello_ux: bool,
}

/// Environment variable that, when the `mock` cargo feature is
/// compiled in **and** this var is set to a non-empty value, forces
/// [`create_encryption_storage`] to return a [`MockEncryptionStorage`]
/// instead of the real platform backend.
///
/// **Security:** the env-var check below is feature-gated to `mock`.
/// Release binaries built without the feature ignore the variable
/// entirely — no runtime path leads to the mock backend, so setting
/// the variable in production does nothing. Only `cargo test` builds
/// (where downstream `[dev-dependencies]` turn the feature on) read
/// this variable.
///
/// This exists for CI environments that cannot satisfy a real
/// hardware-backed backend — typically GitHub Actions macOS runners,
/// which would otherwise block on a login-keychain ACL confirmation
/// prompt.
#[cfg(feature = "mock")]
pub const MOCK_STORAGE_ENV: &str = "ENCLAVEAPP_MOCK_STORAGE";

/// Create encryption storage with automatic platform detection.
///
/// When built with the `mock` feature (test builds only), honours
/// [`MOCK_STORAGE_ENV`]: a non-empty value routes through
/// [`MockEncryptionStorage`]. Release builds have the feature off,
/// so this function unconditionally returns the real backend —
/// there is no runtime switch that could downgrade production
/// security.
pub fn create_encryption_storage(config: StorageConfig) -> Result<Box<dyn EncryptionStorage>> {
    #[cfg(feature = "mock")]
    {
        if let Ok(val) = std::env::var(MOCK_STORAGE_ENV) {
            if !val.is_empty() {
                tracing::warn!(
                    app = %config.app_name,
                    "{MOCK_STORAGE_ENV} is set — returning MockEncryptionStorage (no hardware backing)"
                );
                return Ok(Box::new(MockEncryptionStorage::for_app(&config.app_name)));
            }
        }
    }
    let storage = AppEncryptionStorage::init(config)?;
    Ok(Box::new(storage))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn storage_config_debug() {
        let config = StorageConfig {
            app_name: "test".into(),
            key_label: "key".into(),
            access_policy: AccessPolicy::None,
            extra_bridge_paths: vec![],
            keys_dir: None,
            force_keyring: false,
            wrapping_key_user_presence: false,
            wrapping_key_cache_ttl: std::time::Duration::ZERO,
            keychain_access_group: None,
            prefer_windows_hello_ux: false,
        };
        let debug = format!("{config:?}");
        assert!(debug.contains("test"));
        assert!(debug.contains("key"));
    }

    #[test]
    fn storage_config_clone() {
        let config = StorageConfig {
            app_name: "test".into(),
            key_label: "key".into(),
            access_policy: AccessPolicy::BiometricOnly,
            extra_bridge_paths: vec!["/custom/path".into()],
            keys_dir: Some(std::path::PathBuf::from("/custom/keys")),
            force_keyring: false,
            wrapping_key_user_presence: false,
            wrapping_key_cache_ttl: std::time::Duration::ZERO,
            keychain_access_group: None,
            prefer_windows_hello_ux: false,
        };
        let cloned = config.clone();
        assert_eq!(cloned.app_name, "test");
        assert_eq!(cloned.key_label, "key");
        assert_eq!(cloned.access_policy, AccessPolicy::BiometricOnly);
        assert_eq!(cloned.extra_bridge_paths.len(), 1);
    }

    #[test]
    fn storage_error_display() {
        let err = StorageError::NotAvailable;
        assert_eq!(err.to_string(), "hardware security module not available");

        let err = StorageError::EncryptionFailed("bad key".into());
        assert_eq!(err.to_string(), "encryption failed: bad key");

        let err = StorageError::DecryptionFailed("corrupt".into());
        assert_eq!(err.to_string(), "decryption failed: corrupt");

        let err = StorageError::SigningFailed("timeout".into());
        assert_eq!(err.to_string(), "signing failed: timeout");

        let err = StorageError::KeyInitFailed("no hardware".into());
        assert_eq!(err.to_string(), "key initialization failed: no hardware");

        let err = StorageError::KeyNotFound("missing".into());
        assert_eq!(err.to_string(), "key not found: missing");

        let err = StorageError::PolicyMismatch("None vs BiometricOnly".into());
        assert_eq!(
            err.to_string(),
            "key policy mismatch: None vs BiometricOnly"
        );

        let err = StorageError::PlatformError("unsupported".into());
        assert_eq!(err.to_string(), "platform error: unsupported");
    }

    #[test]
    fn re_exports_work() {
        // Verify core types are re-exported.
        let _ = AccessPolicy::None;
        let _ = AccessPolicy::Any;
        let _ = AccessPolicy::BiometricOnly;
        let _ = AccessPolicy::PasswordOnly;
        let _ = KeyType::Signing;
        let _ = KeyType::Encryption;
        let _ = BackendKind::SecureEnclave;
    }
}
