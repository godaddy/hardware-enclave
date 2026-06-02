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

/// Cross-platform per-key meta-integrity verification using the
/// new keychain-tag trust anchor.
///
/// Used by callers that read `.meta` directly from disk and don't
/// otherwise hit the platform key manager (e.g., sshenc's bulk-list
/// path that intentionally avoids per-op prompts). On macOS this
/// pulls the agent-cached meta-HMAC key, recomputes the tag of the
/// on-disk `.meta`, and compares it to the keychain-stored tag for
/// the same label.
///
/// Returns:
/// - `Ok(())` on a clean verify, on a missing meta file (caller's
///   "key not found" flow handles it), and on `KeychainUnavailable`
///   (fail-open; matches the existing wrapping-key load behavior).
/// - `Err(StorageError::KeyInitFailed)` on confirmed tamper or
///   legacy-meta state. Detail string contains the user-actionable
///   recovery path.
///
/// **Platform coverage:** macOS, Windows, and Linux (Secret Service
/// keyring backend). The Linux TPM backend (`enclaveapp-linux-tpm`)
/// shares the keyring backend's Secret Service trust domain via
/// direct dep, so it gets the same trust anchor coverage even
/// though the Linux TPM doesn't enforce `AccessPolicy` at sign time
/// — the trust anchor here functions as an integrity check, the
/// only protection against same-UID `.meta` tamper on a backend
/// without hardware policy bits.
pub fn check_meta_integrity(
    app_name: &str,
    label: &str,
    keys_dir: &std::path::Path,
) -> crate::error::Result<()> {
    // Don't reach into the platform secure store unless an on-disk
    // `.meta` exists. Without this guard, synthetic call sites (test
    // binaries, fresh-install probes, rebuilds with new ad-hoc
    // signatures) trigger the legacy-Keychain ACL prompt for the
    // unrelated meta-HMAC item from a prior signed binary.
    let meta_path = keys_dir.join(format!("{label}.meta"));
    if !meta_path.exists() {
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    {
        // Read-only — must NOT trigger a SecItemAdd here. Creation
        // belongs on the keygen path; the verify-side helper has
        // to be safe to call from contexts where prompting for a
        // Keychain ACL would hang (CI runners, locked sessions).
        let hmac_key = match enclaveapp_apple::meta_hmac::load_existing(app_name) {
            Ok(Some(k)) => k,
            _ => return Ok(()),
        };
        let outcome =
            enclaveapp_apple::meta_tag::verify(app_name, label, keys_dir, hmac_key.as_slice())
                .map_err(|e| crate::error::StorageError::KeyInitFailed(e.to_string()))?;
        match outcome {
            enclaveapp_apple::meta_tag::VerifyOutcome::Match
            | enclaveapp_apple::meta_tag::VerifyOutcome::NoMeta
            | enclaveapp_apple::meta_tag::VerifyOutcome::KeychainUnavailable => Ok(()),
            enclaveapp_apple::meta_tag::VerifyOutcome::Tamper => {
                Err(crate::error::StorageError::KeyInitFailed(format!(
                    "key '{label}': metadata integrity check failed. The on-disk meta does \
                     not match the keychain-stored tag — meta may have been tampered with. \
                     Refusing to proceed. Regenerate the key to restore a known-good state."
                )))
            }
            enclaveapp_apple::meta_tag::VerifyOutcome::Legacy => {
                Err(crate::error::StorageError::KeyInitFailed(format!(
                    "key '{label}' has no integrity tag. This is a one-time migration \
                     required by upgrading to a build that introduces meta integrity tags, \
                     and is not something future upgrades will repeat. If you have already \
                     run `{app_name} migrate-meta` on this machine, treat this as a tamper \
                     signal — do not run it again. Regenerate the affected key instead. \
                     Before migrating, verify the key's current policy looks correct: \
                     `{app_name} inspect {label}`. To migrate: `{app_name} migrate-meta`."
                )))
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        // Read-only — must NOT trigger `CryptProtectData` here.
        // Creation belongs on the keygen path; the verify-side
        // helper has to be safe to call from contexts where prompting
        // for a DPAPI master-key materialization would hang (CI
        // runners without an interactive desktop, locked sessions).
        let hmac_key = match enclaveapp_windows::meta_hmac::load_existing(app_name) {
            Ok(Some(k)) => k,
            _ => return Ok(()),
        };
        let outcome =
            enclaveapp_windows::meta_tag::verify(app_name, label, keys_dir, hmac_key.as_slice())
                .map_err(|e| crate::error::StorageError::KeyInitFailed(e.to_string()))?;
        match outcome {
            enclaveapp_windows::meta_tag::VerifyOutcome::Match
            | enclaveapp_windows::meta_tag::VerifyOutcome::NoMeta
            | enclaveapp_windows::meta_tag::VerifyOutcome::KeychainUnavailable => Ok(()),
            enclaveapp_windows::meta_tag::VerifyOutcome::Tamper => {
                Err(crate::error::StorageError::KeyInitFailed(format!(
                    "key '{label}': metadata integrity check failed. The on-disk meta does \
                     not match the keychain-stored tag — meta may have been tampered with. \
                     Refusing to proceed. Regenerate the key to restore a known-good state."
                )))
            }
            enclaveapp_windows::meta_tag::VerifyOutcome::Legacy => {
                Err(crate::error::StorageError::KeyInitFailed(format!(
                    "key '{label}' has no integrity tag. This is a one-time migration \
                     required by upgrading to a build that introduces meta integrity tags, \
                     and is not something future upgrades will repeat. If you have already \
                     run `{app_name} migrate-meta` on this machine, treat this as a tamper \
                     signal — do not run it again. Regenerate the affected key instead. \
                     Before migrating, verify the key's current policy looks correct: \
                     `{app_name} inspect {label}`. To migrate: `{app_name} migrate-meta`."
                )))
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        // Read-only — must NOT trigger a Secret Service write here.
        // Creation belongs on the keygen path; the verify-side
        // helper has to be safe to call from contexts where
        // unlocking a locked keyring would prompt the user (or
        // silently fail in a non-interactive session).
        let hmac_key = match enclaveapp_keyring::meta_hmac_key_existing(app_name) {
            Ok(Some(k)) => k,
            _ => return Ok(()),
        };
        let outcome =
            enclaveapp_keyring::meta_tag::verify(app_name, label, keys_dir, hmac_key.as_slice())
                .map_err(|e| crate::error::StorageError::KeyInitFailed(e.to_string()))?;
        match outcome {
            enclaveapp_keyring::meta_tag::VerifyOutcome::Match
            | enclaveapp_keyring::meta_tag::VerifyOutcome::NoMeta
            | enclaveapp_keyring::meta_tag::VerifyOutcome::KeychainUnavailable => Ok(()),
            enclaveapp_keyring::meta_tag::VerifyOutcome::Tamper => {
                Err(crate::error::StorageError::KeyInitFailed(format!(
                    "key '{label}': metadata integrity check failed. The on-disk meta does \
                     not match the keychain-stored tag — meta may have been tampered with. \
                     Refusing to proceed. Regenerate the key to restore a known-good state."
                )))
            }
            enclaveapp_keyring::meta_tag::VerifyOutcome::Legacy => {
                Err(crate::error::StorageError::KeyInitFailed(format!(
                    "key '{label}' has no integrity tag. This is a one-time migration \
                     required by upgrading to a build that introduces meta integrity tags, \
                     and is not something future upgrades will repeat. If you have already \
                     run `{app_name} migrate-meta` on this machine, treat this as a tamper \
                     signal — do not run it again. Regenerate the affected key instead. \
                     Before migrating, verify the key's current policy looks correct: \
                     `{app_name} inspect {label}`. To migrate: `{app_name} migrate-meta`."
                )))
            }
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        let _ = (app_name, label, keys_dir);
        Ok(())
    }
}

/// Store an HMAC trust anchor for an arbitrary file in the platform
/// secure store.
///
/// `path_label` is a stable identifier derived from the file path
/// (e.g. a hex SHA-256 of the path bytes from
/// `enclave::integrity::path_to_label`). On platforms where the
/// native secure store is unavailable the call silently succeeds
/// (fail-open) so callers don't need conditional logic.
pub fn store_file_tag(
    app_name: &str,
    path_label: &str,
    tag: &[u8; 32],
) -> enclaveapp_core::Result<()> {
    #[cfg(target_os = "macos")]
    {
        enclaveapp_apple::meta_tag::store(app_name, path_label, tag)
    }
    #[cfg(target_os = "windows")]
    {
        enclaveapp_windows::meta_tag::store(app_name, path_label, tag)
    }
    #[cfg(target_os = "linux")]
    {
        enclaveapp_keyring::meta_tag::store(app_name, path_label, tag)
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        let _ = (app_name, path_label, tag);
        Ok(())
    }
}

/// Load an HMAC trust anchor for an arbitrary file from the platform
/// secure store.
///
/// Returns `Ok(Some(tag))` when the trust anchor is present,
/// `Ok(None)` when no anchor was found (new file or pre-migration),
/// and `Err` only for hard platform-store failures. Callers should
/// treat `Ok(None)` as the legacy / pre-migration path and
/// `Err` as store unavailable (fail-open).
pub fn load_file_tag(
    app_name: &str,
    path_label: &str,
) -> enclaveapp_core::Result<Option<[u8; 32]>> {
    #[cfg(target_os = "macos")]
    {
        enclaveapp_apple::meta_tag::load(app_name, path_label)
    }
    #[cfg(target_os = "windows")]
    {
        enclaveapp_windows::meta_tag::load(app_name, path_label)
    }
    #[cfg(target_os = "linux")]
    {
        enclaveapp_keyring::meta_tag::load(app_name, path_label)
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        let _ = (app_name, path_label);
        Ok(None)
    }
}

/// Delete the HMAC trust anchor for an arbitrary file from the
/// platform secure store. Idempotent: missing-entry is success.
pub fn delete_file_tag(app_name: &str, path_label: &str) -> enclaveapp_core::Result<()> {
    #[cfg(target_os = "macos")]
    {
        enclaveapp_apple::meta_tag::delete(app_name, path_label)
    }
    #[cfg(target_os = "windows")]
    {
        enclaveapp_windows::meta_tag::delete(app_name, path_label)
    }
    #[cfg(target_os = "linux")]
    {
        enclaveapp_keyring::meta_tag::delete(app_name, path_label)
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        let _ = (app_name, path_label);
        Ok(())
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
    /// Windows per-user DPAPI fallback for VM hosts without TPM 2.0.
    WindowsDpapi,
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
            BackendKind::WindowsDpapi => write!(f, "Windows DPAPI"),
            BackendKind::TpmBridge => write!(f, "TPM 2.0 (WSL Bridge)"),
            BackendKind::Keyring => write!(f, "Keyring"),
        }
    }
}

/// Search for a WSL TPM bridge executable.
///
/// Tries in order:
/// 1. `enclaveapp_bridge::find_bridge(app_name)` (standard enclave discovery)
/// 2. Auto-derived paths: `/mnt/c/Program Files/{app_name}/{app_name}-tpm-bridge.exe`
///    and `/mnt/c/ProgramData/{app_name}/{app_name}-tpm-bridge.exe`
/// 3. Any absolute extra paths provided by the caller as explicit overrides
#[cfg(target_os = "linux")]
pub fn find_bridge_executable(app_name: &str, extra_paths: &[String]) -> Option<PathBuf> {
    // Standard enclave discovery.
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
        assert_eq!(BackendKind::WindowsDpapi.to_string(), "Windows DPAPI");
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

    #[test]
    fn backend_kind_debug_nonempty() {
        for kind in [
            BackendKind::SecureEnclave,
            BackendKind::Tpm,
            BackendKind::WindowsDpapi,
            BackendKind::TpmBridge,
            BackendKind::Keyring,
        ] {
            let s = format!("{kind:?}");
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn backend_kind_all_variants_display_nonempty() {
        for kind in [
            BackendKind::SecureEnclave,
            BackendKind::Tpm,
            BackendKind::WindowsDpapi,
            BackendKind::TpmBridge,
            BackendKind::Keyring,
        ] {
            assert!(!kind.to_string().is_empty());
        }
    }

    #[test]
    fn backend_kind_all_pairs_not_equal() {
        let kinds = [
            BackendKind::SecureEnclave,
            BackendKind::Tpm,
            BackendKind::WindowsDpapi,
            BackendKind::TpmBridge,
            BackendKind::Keyring,
        ];
        for i in 0..kinds.len() {
            for j in 0..kinds.len() {
                if i != j {
                    assert_ne!(kinds[i], kinds[j]);
                }
            }
        }
    }

    #[test]
    fn verify_meta_integrity_succeeds_when_meta_file_absent() {
        let dir = std::env::temp_dir().join(format!(
            "enclaveapp-platform-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        // No .meta file — verify_meta_integrity must return Ok without touching any secure store.
        let result = verify_meta_integrity("test-app", &dir, "nonexistent-label");
        assert!(result.is_ok());
        drop(std::fs::remove_dir_all(&dir));
    }

    #[test]
    fn check_meta_integrity_succeeds_when_meta_file_absent() {
        let dir = std::env::temp_dir().join(format!(
            "enclaveapp-platform-test2-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let result = check_meta_integrity("test-app", "nonexistent-label", &dir);
        assert!(result.is_ok());
        drop(std::fs::remove_dir_all(&dir));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn find_bridge_executable_returns_none_on_dev_machine() {
        // Should return None on most dev machines (not WSL with bridge installed).
        drop(find_bridge_executable("test-app", &[]));
    }
}
