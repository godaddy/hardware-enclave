// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

use enclaveapp_app_storage::BackendKind;

use crate::auth::AuthHandle;
#[cfg(target_os = "macos")]
use crate::capabilities::has_keychain_entitlement;
use crate::security_key::SecurityKeyHandle;

use crate::config::EnclaveConfig;
use crate::encryption::EncryptorHandle;
use crate::error::{Error, Result};
use crate::integrity::TamperEvidentHandle;
use crate::signing::SignerHandle;

/// Create a signing handle for the current platform.
///
/// Validates the config against the binary's signing state:
/// - `wrapping_key_user_presence: true` + no access group + unsigned -> `Error::RequiresSigning`
/// - `keychain_access_group` set but entitlement absent -> downgrade (no error)
pub fn create_signer(config: &EnclaveConfig) -> Result<SignerHandle> {
    let storage_config = validate_and_resolve_config(config)?;
    let backend =
        enclaveapp_app_storage::AppSigningBackend::init(storage_config).map_err(Error::from)?;
    let kind = backend.backend_kind();
    Ok(SignerHandle::new(backend, kind))
}

/// Create an encryption handle for the current platform.
pub fn create_encryptor(config: &EnclaveConfig) -> Result<EncryptorHandle> {
    let storage_config = validate_and_resolve_config(config)?;
    let kind = resolve_backend_kind();
    let storage =
        enclaveapp_app_storage::AppEncryptionStorage::init(storage_config).map_err(Error::from)?;
    Ok(EncryptorHandle::new(storage, kind))
}

/// Create an auth handle for the current platform.
///
/// The `config` parameter is accepted for API consistency with the other factory
/// functions but is not currently used — `AuthHandle` only requires platform
/// detection. It is reserved for Phase 2 when access-group entitlement validation
/// will be wired in.
pub fn create_auth(config: &EnclaveConfig) -> Result<AuthHandle> {
    let _ = config; // reserved for Phase 2 entitlement validation
    let kind = resolve_backend_kind();
    Ok(AuthHandle::new(kind))
}

/// Create a [`SecurityKeyHandle`] for the current platform.
///
/// Unlike the other factory functions, this is **infallible** — it always
/// returns a handle regardless of whether the platform authenticator is
/// available. Call [`SecurityKeyHandle::is_available()`] to check at runtime
/// whether Windows Hello is reachable before calling
/// [`generate`][SecurityKeyHandle::generate] or [`sign`][SecurityKeyHandle::sign].
///
/// This design allows the handle to be constructed once at startup and
/// re-used across multiple operations without repeating the availability check.
pub fn create_security_key(config: &EnclaveConfig) -> SecurityKeyHandle {
    crate::security_key::make_security_key_handle(config)
}

/// Create a tamper-evident handle for the given app.
///
/// The per-app HMAC key is loaded from the platform secure store
/// (Keychain on macOS, DPAPI on Windows, D-Bus Secret Service on Linux).
/// On first use the key is created, which on macOS may prompt for the
/// login keychain password if the binary is unsigned.
///
/// **For testing and development** where no interactive prompt is acceptable,
/// use [`create_tamper_evident_ephemeral`] instead, which uses a random
/// in-memory key and never touches the platform secure store.
pub fn create_tamper_evident(app_name: &str) -> Result<TamperEvidentHandle> {
    let effective = enclaveapp_core::signing::ensure_safe_app_name(app_name);
    Ok(TamperEvidentHandle::new(effective))
}

/// Create a tamper-evident handle with an ephemeral random HMAC key.
///
/// The key is generated from `OsRng` and held in memory only — no platform
/// secure store (Keychain / DPAPI / Secret Service) is accessed. This means:
///
/// - **No interactive prompts.** Safe to call from CI, tests, and examples.
/// - **Key is not persisted.** Files written with this handle cannot be
///   verified after the process restarts. Use [`create_tamper_evident`] for
///   persistent integrity protection.
///
/// Suitable for: automated tests, CI pipelines, development examples, and
/// any non-production scenario where prompt-free operation is required.
pub fn create_tamper_evident_ephemeral(app_name: &str) -> TamperEvidentHandle {
    let effective = enclaveapp_core::signing::ensure_safe_app_name(app_name);
    TamperEvidentHandle::new_ephemeral(effective)
}

// ── internal helpers ──────────────────────────────────────────────────

fn validate_and_resolve_config(
    config: &EnclaveConfig,
) -> Result<enclaveapp_app_storage::StorageConfig> {
    // `mut` is only used by the macOS cfg block below; suppress the lint
    // on platforms where the mutation code is compiled out.
    #[cfg_attr(not(target_os = "macos"), allow(unused_mut))]
    let mut sc = config.to_storage_config();

    // Hard error: user_presence without access_group on unsigned binary.
    // The legacy keychain rejects the userPresence ACL with errSecParam.
    #[cfg(target_os = "macos")]
    if sc.wrapping_key_user_presence
        && sc.keychain_access_group.is_none()
        && !enclaveapp_core::signing::is_binary_signed()
    {
        return Err(Error::RequiresSigning {
            feature: "wrapping_key_user_presence (requires keychain_access_group + entitlement)"
                .into(),
        });
    }

    // Log when macOS-specific config options are set on non-macOS platforms.
    #[cfg(not(target_os = "macos"))]
    if sc.wrapping_key_user_presence || sc.keychain_access_group.is_some() {
        tracing::debug!(
            app = %sc.app_name,
            wrapping_key_user_presence = sc.wrapping_key_user_presence,
            keychain_access_group = ?sc.keychain_access_group,
            "macOS-specific config options set on non-macOS platform; they will be ignored"
        );
    }

    // Downgrade: access_group requested but entitlement absent -> use legacy keychain.
    #[cfg(target_os = "macos")]
    if let Some(ref group) = sc.keychain_access_group.clone() {
        if !has_keychain_entitlement(group) {
            tracing::warn!(
                app = %sc.app_name,
                group = %group,
                "keychain_access_group requested but entitlement is absent; \
                 downgrading to legacy keychain (no user_presence gate)"
            );
            sc.keychain_access_group = None;
            sc.wrapping_key_user_presence = false;
        }
    }

    Ok(sc)
}

#[allow(clippy::needless_return, unreachable_code)]
fn resolve_backend_kind() -> BackendKind {
    #[cfg(target_os = "macos")]
    {
        return BackendKind::SecureEnclave;
    }
    #[cfg(target_os = "windows")]
    {
        return BackendKind::Tpm;
    }
    #[cfg(target_os = "linux")]
    {
        if enclaveapp_wsl::is_wsl() {
            return BackendKind::TpmBridge;
        }
        return BackendKind::Keyring;
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    BackendKind::Keyring
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn create_auth_does_not_panic() {
        let config = EnclaveConfig::new("testapp", "default");
        let _handle = create_auth(&config).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn user_presence_without_access_group_unsigned_returns_requires_signing() {
        use crate::config::{MacOsConfig, PlatformConfig};
        use std::time::Duration;
        let config = EnclaveConfig {
            app_name: "testapp".into(),
            default_key_label: "key".into(),
            access_policy: None,
            keys_dir: None,
            platform: PlatformConfig::MacOs(MacOsConfig {
                wrapping_key_user_presence: true,
                wrapping_key_cache_ttl: Duration::ZERO,
                keychain_access_group: None,
                extra_bridge_paths: Vec::new(),
            }),
        };
        // In test env the binary is unsigned, so this must return RequiresSigning.
        let result = create_signer(&config);
        assert!(
            result.is_err(),
            "unsigned binary with user_presence must return an error"
        );
        assert!(
            matches!(result, Err(Error::RequiresSigning { .. })),
            "expected RequiresSigning, got: {:?}",
            result
        );
    }
}
