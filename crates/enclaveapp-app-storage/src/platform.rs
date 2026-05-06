// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Platform detection and backend identification.

#[allow(unused_imports)]
use std::path::PathBuf;
use zeroize::Zeroizing;

/// Load (or generate-and-persist) the per-app meta-HMAC key from
/// the platform's native secure store.
///
/// - macOS: legacy Keychain via `enclaveapp-apple::meta_hmac`.
/// - Windows: DPAPI blob under `%APPDATA%\<app>` via
///   `enclaveapp-windows::meta_hmac`.
/// - Linux: Secret Service via `enclaveapp-keyring::meta_hmac_key`.
///
/// Returns `Some(key)` on success and `None` when the underlying
/// store is unreachable (Keychain locked, no Secret Service, DPAPI
/// failure). Production callers should treat `None` the same way:
/// refuse to persist or load unauthenticated meta. Test paths can
/// fall back to plain `metadata::save_meta` / `load_meta` when this
/// returns `None`.
///
/// Errors from the platform layer are surfaced (RNG failure, FFI
/// failure on a store request the caller explicitly initiated). The
/// "store happens to be locked / not configured" path is always
/// `Ok(None)` so consumers can branch unconditionally.
pub fn meta_hmac_key(app_name: &str) -> Option<Zeroizing<Vec<u8>>> {
    #[cfg(target_os = "macos")]
    {
        match enclaveapp_apple::meta_hmac::load_or_create(app_name) {
            Ok(key) => key,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "macOS meta-HMAC key load failed; falling back to no-HMAC mode"
                );
                None
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        match enclaveapp_windows::meta_hmac::load_or_create(app_name) {
            Ok(key) => key,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "Windows DPAPI meta-HMAC key load failed; falling back to no-HMAC mode"
                );
                None
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        enclaveapp_keyring::meta_hmac_key(app_name)
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        let _ = app_name;
        None
    }
}

/// Verify the on-disk `<label>.meta` for `app_name` against its
/// `<label>.meta.hmac` sidecar, auto-migrating a missing sidecar
/// from the current meta content as a one-shot upgrade path.
///
/// Returns:
/// - `Ok(())` when the sidecar verifies, when the sidecar is
///   absent and migration writes a fresh one, when the meta file
///   itself is absent (caller's job to handle key-not-found), or
///   when the platform store is unreachable (legacy fallback,
///   matches the existing encryption-side behavior).
/// - `Err(StorageError::KeyInitFailed)` only on confirmed tamper:
///   `.meta.hmac` exists but doesn't match the recomputed HMAC of
///   `.meta`. Caller refuses to use the key.
///
/// Designed for callers that don't have an `AppSigningBackend`-
/// managed lifecycle for the labels they care about (sshenc-agent's
/// per-label `list`/`sign`/`get` flows). The encryption-side
/// `AppEncryptionStorage::ensure_key` runs the same logic inline
/// for its single configured label; this helper is the equivalent
/// for the signing path's many user-managed labels.
pub fn verify_meta_integrity(
    app_name: &str,
    keys_dir: &std::path::Path,
    label: &str,
) -> crate::error::Result<()> {
    // Don't reach into the platform secure store unless there's
    // actually a `.meta` file to verify. Without this guard, a
    // synthetic call site (test binary, fresh install probe, dev
    // tool) hits the macOS Keychain for an item that doesn't exist
    // yet — which triggers the unsigned-binary ACL prompt to
    // *create* one and pollutes the user's login keychain with
    // debris from every distinct binary signature.
    let meta_path = keys_dir.join(format!("{label}.meta"));
    if !meta_path.exists() {
        return Ok(());
    }
    let hmac_key = match meta_hmac_key(app_name) {
        Some(k) => k,
        None => {
            // Platform store unreachable — skip verification rather
            // than refuse to proceed. Matches the legacy "Linux
            // without Secret Service" fallback. The dispatch layer
            // already logged a warn.
            return Ok(());
        }
    };
    match enclaveapp_core::metadata::load_meta_with_hmac(
        keys_dir,
        label,
        hmac_key.as_slice(),
        enclaveapp_core::metadata::MetaIntegrityMode::RequireSidecar,
    ) {
        Ok(_) => Ok(()),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains(enclaveapp_core::metadata::META_HMAC_VERIFY_OP) {
                return Err(crate::error::StorageError::KeyInitFailed(msg));
            }
            if msg.contains(enclaveapp_core::metadata::META_HMAC_MISSING_OP) {
                tracing::warn!(
                    label = %label,
                    "`.meta.hmac` sidecar missing — migrating from existing meta. \
                     If you did not just upgrade, treat this as suspicious and \
                     regenerate the key."
                );
                if let Err(migrate_err) = enclaveapp_core::metadata::migrate_meta_to_hmac(
                    keys_dir,
                    label,
                    hmac_key.as_slice(),
                ) {
                    return Err(crate::error::StorageError::KeyInitFailed(
                        migrate_err.to_string(),
                    ));
                }
                return Ok(());
            }
            // Other errors (file missing, deserialize, IO) — the
            // caller handles them. We don't fail the integrity
            // check on them; key-not-found is the caller's flow.
            Ok(())
        }
    }
}

/// Remove the per-app meta-HMAC key from the platform's secure
/// store. Used by the uninstall flow so a clean reinstall doesn't
/// reuse a stale key. Idempotent: missing-entry is success.
///
/// Failures are returned to the caller so the uninstall path can
/// log them; they do not propagate as `Err` from the higher-level
/// uninstall sequence today, but exposing them here keeps the API
/// honest.
pub fn delete_meta_hmac_key(app_name: &str) -> enclaveapp_core::Result<()> {
    #[cfg(target_os = "macos")]
    {
        enclaveapp_apple::meta_hmac::delete(app_name)
    }
    #[cfg(target_os = "windows")]
    {
        enclaveapp_windows::meta_hmac::delete(app_name)
    }
    #[cfg(target_os = "linux")]
    {
        // Linux keyring path doesn't expose an explicit delete today;
        // the keyring entry survives uninstall by design (lets the
        // user roll their own cleanup with `secret-tool`). If a
        // delete becomes necessary, add it to enclaveapp-keyring and
        // dispatch here.
        let _ = app_name;
        Ok(())
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        let _ = app_name;
        Ok(())
    }
}

/// Which hardware/software backend is in use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    /// macOS Secure Enclave via CryptoKit.
    SecureEnclave,
    /// Windows TPM 2.0 via CNG.
    Tpm,
    /// WSL bridge to Windows TPM.
    TpmBridge,
    /// Keyring-backed P-256 keys (Linux without TPM).
    Keyring,
}

impl std::fmt::Display for BackendKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackendKind::SecureEnclave => write!(f, "Secure Enclave"),
            BackendKind::Tpm => write!(f, "TPM 2.0"),
            BackendKind::TpmBridge => write!(f, "TPM 2.0 (WSL Bridge)"),
            BackendKind::Keyring => write!(f, "Keyring"),
        }
    }
}

/// Search for a WSL TPM bridge executable.
///
/// Tries in order:
/// 1. `enclaveapp_bridge::find_bridge(app_name)` (standard libenclaveapp discovery)
/// 2. Auto-derived paths: `/mnt/c/Program Files/{app_name}/{app_name}-tpm-bridge.exe`
///    and `/mnt/c/ProgramData/{app_name}/{app_name}-tpm-bridge.exe`
/// 3. Any absolute extra paths provided by the caller as explicit overrides
#[cfg(target_os = "linux")]
pub fn find_bridge_executable(app_name: &str, extra_paths: &[String]) -> Option<PathBuf> {
    // Standard libenclaveapp discovery.
    if let Some(path) = enclaveapp_bridge::find_bridge(app_name) {
        return Some(path);
    }

    // Auto-derived paths.
    let auto_paths = [
        format!("/mnt/c/Program Files/{app_name}/{app_name}-tpm-bridge.exe"),
        format!("/mnt/c/ProgramData/{app_name}/{app_name}-tpm-bridge.exe"),
    ];

    for path_str in &auto_paths {
        let path = std::path::Path::new(path_str);
        if path.exists() {
            return Some(path.to_path_buf());
        }
    }

    for path_str in extra_paths {
        let path = std::path::Path::new(path_str);
        if path.is_absolute() && path.exists() {
            return Some(path.to_path_buf());
        }
    }

    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn backend_kind_display() {
        assert_eq!(BackendKind::SecureEnclave.to_string(), "Secure Enclave");
        assert_eq!(BackendKind::Tpm.to_string(), "TPM 2.0");
        assert_eq!(BackendKind::TpmBridge.to_string(), "TPM 2.0 (WSL Bridge)");
        assert_eq!(BackendKind::Keyring.to_string(), "Keyring");
    }

    #[test]
    fn backend_kind_eq() {
        assert_eq!(BackendKind::SecureEnclave, BackendKind::SecureEnclave);
        assert_ne!(BackendKind::SecureEnclave, BackendKind::Tpm);
    }

    #[test]
    fn backend_kind_clone() {
        let kind = BackendKind::Tpm;
        let cloned = kind;
        assert_eq!(kind, cloned);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn find_bridge_executable_returns_none_on_dev_machine() {
        // Should return None on most dev machines (not WSL with bridge installed).
        drop(find_bridge_executable("test-app", &[]));
    }
}
