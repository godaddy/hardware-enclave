// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! High-level signing backend with automatic platform detection.
//!
//! Thin wrapper that handles platform detection and initialization.
//! Exposes the underlying `EnclaveSigner` and `EnclaveKeyManager` traits
//! so sshenc can build its richer `KeyBackend` on top.
#![allow(dead_code, unused_imports, unused_qualifications, unreachable_patterns)]

#[allow(unused_imports)]
use super::error::{Result, StorageError};
use super::platform::BackendKind;
use super::StorageConfig;
use crate::internal::core::traits::{EnclaveKeyManager, EnclaveSigner};
use tracing::debug;

/// High-level signing backend for sshenc.
///
/// Provides platform detection and initialization, then exposes the
/// underlying enclave signer and key manager for the app to use.
/// Does NOT generate keys automatically — sshenc manages its own key lifecycle.
pub struct AppSigningBackend {
    kind: BackendKind,
    inner: SigningInner,
}

enum SigningInner {
    #[cfg(target_os = "macos")]
    SecureEnclave(crate::internal::apple::SecureEnclaveSigner),

    #[cfg(target_os = "windows")]
    Tpm(crate::internal::windows::TpmSigner),

    #[cfg(all(target_os = "linux", target_env = "gnu", feature = "linux-tpm"))]
    LinuxTpm(crate::internal::linux_tpm::LinuxTpmSigner),

    #[cfg(target_os = "linux")]
    Software(crate::internal::keyring::SoftwareSigner),

    #[cfg(target_os = "linux")]
    WslBridge(BridgeSignerWrapper),
}

/// Wrapper that implements `EnclaveSigner` + `EnclaveKeyManager` by calling
/// the WSL TPM bridge for signing operations.
#[cfg(target_os = "linux")]
struct BridgeSignerWrapper {
    bridge_path: std::path::PathBuf,
    app_name: String,
    key_label: String,
    access_policy: crate::internal::core::types::AccessPolicy,
}

#[cfg(target_os = "linux")]
impl EnclaveKeyManager for BridgeSignerWrapper {
    fn generate(
        &self,
        label: &str,
        _key_type: crate::internal::core::types::KeyType,
        _policy: crate::internal::core::types::AccessPolicy,
    ) -> crate::internal::core::Result<Vec<u8>> {
        // Key generation happens via init_signing on the bridge side
        // (it has load-or-create semantics). Explicitly call it
        // first, then read the resulting public key. We can't rely
        // on `self.public_key` to drive the create as a side effect
        // anymore -- as of enclave PR #114 `bridge_public_key`
        // is standalone and only reads existing keys.
        crate::internal::bridge::bridge_init_signing(
            &self.bridge_path,
            &self.app_name,
            label,
            self.access_policy,
        )?;
        self.public_key(label)
    }

    fn public_key(&self, label: &str) -> crate::internal::core::Result<Vec<u8>> {
        crate::internal::bridge::bridge_public_key(
            &self.bridge_path,
            &self.app_name,
            label,
            self.access_policy,
        )
    }

    fn list_keys(&self) -> crate::internal::core::Result<Vec<String>> {
        crate::internal::bridge::bridge_list_keys(
            &self.bridge_path,
            &self.app_name,
            &self.key_label,
            self.access_policy,
        )
    }

    fn delete_key(&self, label: &str) -> crate::internal::core::Result<()> {
        crate::internal::bridge::bridge_delete_signing(&self.bridge_path, &self.app_name, label)
    }

    fn is_available(&self) -> bool {
        true
    }

    fn key_exists(&self, label: &str) -> crate::internal::core::Result<bool> {
        // MUST NOT use the default `public_key`-based impl: on the WSL bridge,
        // `public_key` routes through `init_signing` which has load-or-create
        // semantics and would create the key as a side effect of the check.
        crate::internal::bridge::bridge_signing_key_exists(&self.bridge_path, &self.app_name, label)
    }
}

#[cfg(target_os = "linux")]
impl EnclaveSigner for BridgeSignerWrapper {
    fn sign(&self, label: &str, data: &[u8]) -> crate::internal::core::Result<Vec<u8>> {
        crate::internal::bridge::bridge_sign(
            &self.bridge_path,
            &self.app_name,
            label,
            data,
            self.access_policy,
        )
    }
}

// BridgeSignerWrapper holds only paths and strings — safe to send between threads.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
unsafe impl Send for BridgeSignerWrapper {}
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
unsafe impl Sync for BridgeSignerWrapper {}

impl std::fmt::Debug for AppSigningBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppSigningBackend")
            .field("kind", &self.kind)
            .finish()
    }
}

impl AppSigningBackend {
    /// Initialize signing backend with automatic platform detection.
    /// Does NOT generate keys — the consumer app manages key lifecycle.
    ///
    /// When the `mock` feature is compiled in and `ENCLAVEAPP_MOCK_STORAGE` is set
    /// to a non-empty value, returns a keyring-based software signer backed by a
    /// temporary directory — no HSM, no Secure Enclave, no TPM accessed.
    #[allow(clippy::needless_return, unreachable_code)]
    pub fn init(mut config: StorageConfig) -> Result<Self> {
        config.app_name = crate::internal::core::signing::ensure_safe_app_name(&config.app_name);

        // Mock signing backend (Linux only — keyring::SoftwareSigner is Linux-specific).
        // On macOS and Windows the real hardware backend is used even in mock mode.
        #[cfg(all(feature = "mock", target_os = "linux"))]
        {
            use super::MOCK_STORAGE_ENV;
            if let Ok(val) = std::env::var(MOCK_STORAGE_ENV) {
                if !val.is_empty() {
                    tracing::warn!(
                        app = %config.app_name,
                        "{MOCK_STORAGE_ENV} is set — returning software signer (no hardware backing)"
                    );
                    let keys_dir = config.keys_dir.clone().unwrap_or_else(|| {
                        std::env::temp_dir()
                            .join(format!("hardware-enclave-mock-signing-{}", config.app_name))
                    });
                    drop(std::fs::create_dir_all(&keys_dir));
                    let signer = crate::internal::keyring::SoftwareSigner::with_keys_dir(
                        &config.app_name,
                        keys_dir.clone(),
                    );
                    return Ok(Self {
                        kind: BackendKind::Keyring,
                        inner: SigningInner::Software(signer),
                    });
                }
            }
        }
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
                debug!("--keyring flag: forcing software keyring backend for signing");
                return Self::init_linux_keyring(&config);
            }
            // On WSL, use the bridge to the Windows TPM. No implicit
            // keyring fallback — use --keyring to explicitly opt in.
            if crate::internal::wsl::is_wsl() {
                debug!("WSL detected, trying bridge for signing");
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

    #[cfg(target_os = "macos")]
    fn init_macos(config: &StorageConfig) -> Result<Self> {
        let keys_dir = config
            .keys_dir
            .clone()
            .unwrap_or_else(|| crate::internal::core::metadata::keys_dir(&config.app_name));
        let mut keychain_config = crate::internal::apple::KeychainConfig::with_keys_dir(
            &config.app_name,
            keys_dir.clone(),
        )
        .with_user_presence(config.wrapping_key_user_presence)
        .with_cache_ttl(config.wrapping_key_cache_ttl);
        if let Some(ref group) = config.keychain_access_group {
            keychain_config = keychain_config.with_access_group(group.clone());
        }
        let signer = crate::internal::apple::SecureEnclaveSigner::with_config(keychain_config);

        if !signer.is_available() {
            return Err(StorageError::NotAvailable);
        }

        // Verify the configured-label `.meta.hmac` sidecar at init.
        // sshenc has many labels per agent so this is just a probe
        // for the canonical one; per-label verification on enumerate
        // / sign goes through `platform::verify_meta_integrity` from
        // the agent.
        crate::internal::app_storage::platform::verify_meta_integrity(
            &config.app_name,
            &keys_dir,
            &config.key_label,
        )?;

        debug!(
            "Secure Enclave signing backend ready (app={})",
            config.app_name,
        );
        Ok(Self {
            kind: BackendKind::SecureEnclave,
            inner: SigningInner::SecureEnclave(signer),
        })
    }

    #[cfg(target_os = "windows")]
    fn init_windows(config: &StorageConfig) -> Result<Self> {
        let keys_dir = config
            .keys_dir
            .clone()
            .unwrap_or_else(|| crate::internal::core::metadata::keys_dir(&config.app_name));
        let signer =
            crate::internal::windows::TpmSigner::with_keys_dir(&config.app_name, keys_dir.clone());

        if !signer.is_available() {
            return Err(StorageError::NotAvailable);
        }

        // Same as macOS init — probe the configured label's HMAC
        // sidecar; per-label verification on enumerate happens in
        // the agent.
        crate::internal::app_storage::platform::verify_meta_integrity(
            &config.app_name,
            &keys_dir,
            &config.key_label,
        )?;

        debug!("TPM signing backend ready (app={})", config.app_name,);
        Ok(Self {
            kind: BackendKind::Tpm,
            inner: SigningInner::Tpm(signer),
        })
    }

    #[cfg(target_os = "linux")]
    fn init_linux(config: &StorageConfig) -> Result<Self> {
        use super::backend_marker;

        // Sticky backend marker: if a previous successful init
        // recorded `Tpm` here, refuse to silently downgrade to
        // keyring just because `is_available()` returned `false` on
        // this run (transient TPM hiccup, daemon restart, etc.).
        // The keyring path can't sign with TPM keys, so the silent
        // downgrade would surface as a confusing "key not found"
        // error far away from the real cause.
        let prior = backend_marker::read(&config.app_name).ok().flatten();

        #[cfg(all(target_env = "gnu", feature = "linux-tpm"))]
        if crate::internal::linux_tpm::is_available() {
            let keys_dir = config
                .keys_dir
                .clone()
                .unwrap_or_else(|| crate::internal::core::metadata::keys_dir(&config.app_name));
            let signer = crate::internal::linux_tpm::LinuxTpmSigner::with_keys_dir(
                &config.app_name,
                keys_dir.clone(),
            );
            // Probe the configured label's HMAC sidecar at init.
            crate::internal::app_storage::platform::verify_meta_integrity(
                &config.app_name,
                &keys_dir,
                &config.key_label,
            )?;
            debug!("Linux TPM signing backend ready (app={})", config.app_name);
            // Best-effort marker write — losing this is not a hard
            // failure. The next successful init will write it again.
            drop(backend_marker::write(&config.app_name, BackendKind::Tpm));
            return Ok(Self {
                kind: BackendKind::Tpm,
                inner: SigningInner::LinuxTpm(signer),
            });
        }

        if matches!(prior, Some(BackendKind::Tpm)) {
            return Err(StorageError::KeyInitFailed(format!(
                "TPM backend was used previously for app {} but is no longer available; \
                 refusing to silently downgrade to the keyring backend (TPM keys can't be \
                 used by it). Restore TPM access (check tcsd / tpm2-abrmd / kernel module) \
                 or, if you are intentionally migrating away from TPM, delete \
                 {} and regenerate the affected keys.",
                config.app_name,
                crate::internal::core::metadata::config_dir(&config.app_name)
                    .join(".backend")
                    .display()
            )));
        }

        let backend = Self::init_linux_keyring(config)?;
        let keys_dir = config
            .keys_dir
            .clone()
            .unwrap_or_else(|| crate::internal::core::metadata::keys_dir(&config.app_name));
        crate::internal::app_storage::platform::verify_meta_integrity(
            &config.app_name,
            &keys_dir,
            &config.key_label,
        )?;
        drop(backend_marker::write(&config.app_name, backend.kind));
        Ok(backend)
    }

    #[cfg(target_os = "linux")]
    fn init_wsl(config: &StorageConfig) -> Result<Self> {
        let bridge_path = crate::internal::app_storage::platform::find_bridge_executable(
            &config.app_name,
            &config.extra_bridge_paths,
        )
        .ok_or(StorageError::NotAvailable)?;

        debug!(
            "WSL TPM signing bridge found at {} (app={})",
            bridge_path.display(),
            config.app_name
        );

        // Verify the bridge is responsive without side effects. We
        // can't use `bridge_init_signing` here -- it has load-or-create
        // semantics on the server side, so probing with the configured
        // key_label (defaults to "default") creates that key on the
        // Windows TPM as a side effect of every WSL backend init.
        // `bridge_signing_key_exists` was added for exactly this case.
        crate::internal::bridge::bridge_signing_key_exists(
            &bridge_path,
            &config.app_name,
            &config.key_label,
        )
        .map_err(|e| StorageError::KeyInitFailed(e.to_string()))?;

        let wrapper = BridgeSignerWrapper {
            bridge_path,
            app_name: config.app_name.clone(),
            key_label: config.key_label.clone(),
            access_policy: config.access_policy,
        };

        Ok(Self {
            kind: BackendKind::TpmBridge,
            inner: SigningInner::WslBridge(wrapper),
        })
    }

    #[cfg(target_os = "linux")]
    fn init_linux_keyring(config: &StorageConfig) -> Result<Self> {
        if !crate::internal::keyring::has_keyring_feature() {
            return Err(StorageError::NotAvailable);
        }

        let keys_dir = config
            .keys_dir
            .clone()
            .unwrap_or_else(|| crate::internal::core::metadata::keys_dir(&config.app_name));
        let signer =
            crate::internal::keyring::SoftwareSigner::with_keys_dir(&config.app_name, keys_dir);
        debug!(
            "Linux keyring signing backend ready (app={})",
            config.app_name
        );
        Ok(Self {
            kind: BackendKind::Keyring,
            inner: SigningInner::Software(signer),
        })
    }

    /// Access the underlying platform signer.
    pub fn signer(&self) -> &dyn EnclaveSigner {
        match &self.inner {
            #[cfg(target_os = "macos")]
            SigningInner::SecureEnclave(s) => s,

            #[cfg(target_os = "windows")]
            SigningInner::Tpm(s) => s,

            #[cfg(all(target_os = "linux", target_env = "gnu", feature = "linux-tpm"))]
            SigningInner::LinuxTpm(s) => s,

            #[cfg(target_os = "linux")]
            SigningInner::Software(s) => s,

            #[cfg(target_os = "linux")]
            SigningInner::WslBridge(s) => s,
        }
    }

    /// Access the underlying key manager.
    pub fn key_manager(&self) -> &dyn EnclaveKeyManager {
        match &self.inner {
            #[cfg(target_os = "macos")]
            SigningInner::SecureEnclave(s) => s,

            #[cfg(target_os = "windows")]
            SigningInner::Tpm(s) => s,

            #[cfg(all(target_os = "linux", target_env = "gnu", feature = "linux-tpm"))]
            SigningInner::LinuxTpm(s) => s,

            #[cfg(target_os = "linux")]
            SigningInner::Software(s) => s,

            #[cfg(target_os = "linux")]
            SigningInner::WslBridge(s) => s,
        }
    }

    /// Which backend is in use.
    pub fn backend_kind(&self) -> BackendKind {
        self.kind
    }
}
