// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Per-key meta-integrity tag stored in the macOS legacy Keychain.
//!
//! See `docs/design-meta-hmac-trust-anchor.md` for the rationale.
//!
//! ## What this stores and why
//!
//! For each key `<label>`, we persist a 32-byte HMAC-SHA256 tag of
//! the key's `<label>.meta` JSON contents under service
//! `com.godaddy.<app>.meta-tag`, account `<label>`. The keychain item
//! shares the same legacy-Keychain code-signature ACL as the
//! per-key wrapping key — an attacker without our entitled signed
//! binary cannot read or write either.
//!
//! At every per-op load (sign / public_key) we recompute the HMAC of
//! the on-disk `.meta` and compare it (constant-time) against the
//! keychain-stored tag. Mismatch is **tamper**; missing keychain tag
//! on an existing key is **legacy_meta** (user must run
//! `sshenc migrate-meta`); both refuse the operation.
//!
//! The on-disk `<label>.meta.hmac` sidecar is a derivable cache: it
//! continues to be written for crash-resilience and forensic
//! comparison, but it is **not** the trust anchor. Deleting it does
//! not change the verification outcome — the keychain tag is the
//! authority. This closes the auto-migrate hole where a same-UID
//! attacker could `rm` the sidecar to force a re-bless of tampered
//! meta JSON.
//!
//! ## ACL invariant
//!
//! Same as [`crate::meta_hmac`]: this module is intended to be called
//! from the agent process (sshenc-agent) only. CLI binaries forward
//! to the agent over IPC; they do not read or write `.meta-tag`
//! items directly. Cross-binary access fires the legacy-Keychain ACL
//! prompt.

use crate::ffi;
use enclaveapp_core::{Error, Result};
use std::path::Path;
use zeroize::Zeroize;

/// Length of the meta-integrity tag in bytes (HMAC-SHA256 output).
pub const META_TAG_LEN: usize = 32;

fn service_name_for(app_name: &str) -> String {
    format!("com.godaddy.{app_name}.meta-tag")
}

/// Outcome of a meta-integrity verification against the on-disk
/// `.meta` file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// Keychain has a tag and it matches the recomputed HMAC of the
    /// on-disk `.meta`. Caller proceeds with the operation.
    Match,
    /// Keychain has a tag but it does not match the on-disk `.meta`.
    /// Caller MUST refuse the operation (tamper).
    Tamper,
    /// Keychain has no tag for this label. Caller MUST refuse the
    /// operation and surface the legacy-meta error message that
    /// points at `sshenc migrate-meta`.
    Legacy,
    /// On-disk `.meta` does not exist. Caller's "key not found" flow
    /// applies; no verification was needed. This is distinct from
    /// `Legacy` so the caller can distinguish "no key" from "untagged
    /// key."
    NoMeta,
    /// Keychain is unreachable (e.g., locked + no after-first-unlock
    /// match). Verification could not run. Caller decides whether
    /// this is fatal or fail-open; current consumers treat it as
    /// fail-open to avoid bricking access on transient Keychain
    /// hiccups, matching the existing wrapping-key load behavior.
    KeychainUnavailable,
}

/// Persist or replace the meta-integrity tag for `(app_name, label)`.
/// Idempotent: an existing tag for the same key is overwritten.
///
/// Errors only on hard FFI failures the caller should surface (length
/// overflow, store error). "Keychain unreachable" is reported via the
/// returned error code; callers that want to treat it as soft can
/// inspect the error.
pub fn store(app_name: &str, label: &str, tag: &[u8]) -> Result<()> {
    if tag.len() != META_TAG_LEN {
        return Err(Error::KeyOperation {
            operation: "meta_tag_store".into(),
            detail: format!("tag must be {META_TAG_LEN} bytes, got {}", tag.len()),
        });
    }
    // Replace semantics: delete-then-store. The Swift bridge's
    // SecItemAdd refuses duplicates with an error code, so we can't
    // rely on it being update-or-insert. Best-effort delete first;
    // ignore "not found".
    drop(delete(app_name, label));

    let service = service_name_for(app_name);
    let service_bytes = service.as_bytes();
    let account_bytes = label.as_bytes();
    let service_len = i32::try_from(service_bytes.len()).map_err(|_| Error::KeyOperation {
        operation: "meta_tag_store".into(),
        detail: "service name too long".into(),
    })?;
    let account_len = i32::try_from(account_bytes.len()).map_err(|_| Error::KeyOperation {
        operation: "meta_tag_store".into(),
        detail: "label too long".into(),
    })?;

    // SAFETY: pointers from live slices, lengths bounded above; Swift
    // bridge does not retain pointers past return.
    #[allow(unsafe_code)]
    let rc = unsafe {
        ffi::enclaveapp_keychain_store(
            service_bytes.as_ptr(),
            service_len,
            account_bytes.as_ptr(),
            account_len,
            tag.as_ptr(),
            META_TAG_LEN as i32,
            0,                // no user-presence ACL on the tag item
            std::ptr::null(), // legacy keychain
            0,
        )
    };
    if rc != 0 {
        return Err(Error::KeyOperation {
            operation: "meta_tag_store".into(),
            detail: format!("Swift bridge returned error code {rc}"),
        });
    }
    Ok(())
}

/// Load the meta-integrity tag for `(app_name, label)`. Returns:
///
/// - `Ok(Some(tag))` on a successful Keychain read.
/// - `Ok(None)` only for the explicit not-found case
///   (`SE_ERR_KEYCHAIN_NOT_FOUND`, rc=12) — a key with no tag
///   stored yet (legacy or never written).
/// - `Err` for every other Keychain failure (locked, FFI failure,
///   permission denied). Distinguished here so [`verify`] can
///   report `KeychainUnavailable` separately from `Legacy`; the
///   former is fail-open, the latter is hard-error.
pub fn load(app_name: &str, label: &str) -> Result<Option<[u8; META_TAG_LEN]>> {
    let service = service_name_for(app_name);
    let service_bytes = service.as_bytes();
    let account_bytes = label.as_bytes();
    let service_len = i32::try_from(service_bytes.len()).map_err(|_| Error::KeyOperation {
        operation: "meta_tag_load".into(),
        detail: "service name too long".into(),
    })?;
    let account_len = i32::try_from(account_bytes.len()).map_err(|_| Error::KeyOperation {
        operation: "meta_tag_load".into(),
        detail: "label too long".into(),
    })?;
    let mut out = [0_u8; META_TAG_LEN];
    let mut out_len: i32 = META_TAG_LEN as i32;
    // SAFETY: pointers from live mutable buffer; Swift bridge writes
    // at most out_len bytes and updates out_len with actual count.
    #[allow(unsafe_code)]
    let rc = unsafe {
        ffi::enclaveapp_keychain_load(
            service_bytes.as_ptr(),
            service_len,
            account_bytes.as_ptr(),
            account_len,
            out.as_mut_ptr(),
            &mut out_len,
            std::ptr::null(),
            0,
            0,
        )
    };
    match rc {
        0 => {
            if out_len as usize != META_TAG_LEN {
                out.zeroize();
                return Err(Error::KeyOperation {
                    operation: "meta_tag_load".into(),
                    detail: format!(
                        "loaded meta tag has unexpected length {out_len}, expected {META_TAG_LEN}"
                    ),
                });
            }
            Ok(Some(out))
        }
        12 => {
            // SE_ERR_KEYCHAIN_NOT_FOUND — no tag for this label.
            Ok(None)
        }
        _ => {
            // Keychain unreachable (locked, FFI failure, permission
            // denied). Distinct from not-found so the verify path
            // reports KeychainUnavailable instead of Legacy.
            tracing::debug!(rc, label = %label, "meta_tag_load: keychain unreachable");
            Err(Error::KeyOperation {
                operation: "meta_tag_load".into(),
                detail: format!("Swift bridge returned error code {rc}"),
            })
        }
    }
}

/// Delete the meta-integrity tag for `(app_name, label)`. Idempotent:
/// missing-entry is success.
pub fn delete(app_name: &str, label: &str) -> Result<()> {
    let service = service_name_for(app_name);
    let service_bytes = service.as_bytes();
    let account_bytes = label.as_bytes();
    let service_len = i32::try_from(service_bytes.len()).map_err(|_| Error::KeyOperation {
        operation: "meta_tag_delete".into(),
        detail: "service name too long".into(),
    })?;
    let account_len = i32::try_from(account_bytes.len()).map_err(|_| Error::KeyOperation {
        operation: "meta_tag_delete".into(),
        detail: "label too long".into(),
    })?;
    // SAFETY: pointers from live slices, lengths bounded above.
    #[allow(unsafe_code)]
    let rc = unsafe {
        ffi::enclaveapp_keychain_delete(
            service_bytes.as_ptr(),
            service_len,
            account_bytes.as_ptr(),
            account_len,
            std::ptr::null(),
            0,
        )
    };
    match rc {
        0 | 12 => Ok(()),
        _ => Err(Error::KeyOperation {
            operation: "meta_tag_delete".into(),
            detail: format!("Swift bridge returned error code {rc}"),
        }),
    }
}

/// Move the meta-integrity tag from `old_label` to `new_label`.
/// Idempotent on the source: a missing source tag is treated as
/// "nothing to move" and returns Ok. The destination is overwritten
/// if a tag already exists there.
pub fn rename(app_name: &str, old_label: &str, new_label: &str) -> Result<()> {
    if let Some(tag) = load(app_name, old_label)? {
        store(app_name, new_label, &tag)?;
        delete(app_name, old_label)?;
    }
    Ok(())
}

// Use the public `compute_meta_hmac_bytes` from enclaveapp-core so
// the tag stored in the keychain stays bit-identical to the bytes
// implied by the hex sidecar — same algorithm, no parallel impl.

/// Verify the on-disk `<label>.meta` against the keychain-stored
/// integrity tag for `(app_name, label)`.
///
/// This is the per-op trust-anchor check. The caller passes the
/// process-loaded meta-HMAC key (from [`crate::meta_hmac`]) so this
/// function does not perform a second Keychain round-trip for it on
/// every call. The meta-HMAC key is loaded once at agent startup and
/// cached; the per-key tag is the only thing read here.
pub fn verify(
    app_name: &str,
    label: &str,
    keys_dir: &Path,
    meta_hmac_key: &[u8],
) -> Result<VerifyOutcome> {
    let meta_path = keys_dir.join(format!("{label}.meta"));
    if !meta_path.exists() {
        return Ok(VerifyOutcome::NoMeta);
    }
    let stored = match load(app_name, label) {
        Ok(Some(tag)) => tag,
        Ok(None) => {
            // No tag. Could be legacy (key created before this
            // change shipped) or keychain unavailable. The current
            // FFI bridge collapses both cases into rc != 0 / not
            // found. We treat "FFI returned nothing" as Legacy here
            // because that's the user-actionable case — they run
            // migrate-meta. If the keychain truly is locked, the
            // wrapping-key load downstream will fail with its own
            // clearer error.
            return Ok(VerifyOutcome::Legacy);
        }
        Err(_) => return Ok(VerifyOutcome::KeychainUnavailable),
    };

    let meta_bytes = std::fs::read(&meta_path).map_err(|e| Error::KeyOperation {
        operation: "meta_tag_verify".into(),
        detail: format!("read {}: {e}", meta_path.display()),
    })?;
    let actual = enclaveapp_core::metadata::compute_meta_hmac_bytes(meta_hmac_key, &meta_bytes);

    // Constant-time comparison to avoid leaking which byte differed.
    let mut diff: u8 = 0;
    for i in 0..META_TAG_LEN {
        diff |= stored[i] ^ actual[i];
    }
    if diff == 0 {
        Ok(VerifyOutcome::Match)
    } else {
        Ok(VerifyOutcome::Tamper)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, let_underscore_drop)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn unique_app() -> String {
        format!(
            "enclaveapp-apple-meta-tag-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst),
        )
    }

    #[test]
    fn service_name_format() {
        assert_eq!(service_name_for("sshenc"), "com.godaddy.sshenc.meta-tag");
        assert_eq!(service_name_for("awsenc"), "com.godaddy.awsenc.meta-tag");
    }

    #[test]
    fn service_name_for_npmenc() {
        assert_eq!(service_name_for("npmenc"), "com.godaddy.npmenc.meta-tag");
    }

    #[test]
    fn meta_tag_len_is_32() {
        assert_eq!(META_TAG_LEN, 32);
    }

    #[test]
    fn verify_outcome_variants_equal_to_themselves() {
        assert_eq!(VerifyOutcome::Match, VerifyOutcome::Match);
        assert_eq!(VerifyOutcome::Tamper, VerifyOutcome::Tamper);
        assert_eq!(VerifyOutcome::Legacy, VerifyOutcome::Legacy);
        assert_eq!(VerifyOutcome::NoMeta, VerifyOutcome::NoMeta);
        assert_eq!(
            VerifyOutcome::KeychainUnavailable,
            VerifyOutcome::KeychainUnavailable
        );
    }

    #[test]
    fn verify_outcome_distinct_variants_not_equal() {
        assert_ne!(VerifyOutcome::Match, VerifyOutcome::Tamper);
        assert_ne!(VerifyOutcome::Match, VerifyOutcome::Legacy);
        assert_ne!(VerifyOutcome::Match, VerifyOutcome::NoMeta);
        assert_ne!(VerifyOutcome::Tamper, VerifyOutcome::Legacy);
        assert_ne!(VerifyOutcome::Legacy, VerifyOutcome::NoMeta);
        assert_ne!(VerifyOutcome::NoMeta, VerifyOutcome::KeychainUnavailable);
    }

    #[test]
    fn verify_outcome_clone_equals_original() {
        let original = VerifyOutcome::Tamper;
        let cloned = original;
        assert_eq!(original, cloned);
    }

    #[test]
    fn store_rejects_empty_tag() {
        let result = store(&unique_app(), "label", &[]);
        assert!(result.is_err());
    }

    #[test]
    fn verify_no_meta_when_file_missing() {
        let dir = std::env::temp_dir().join(format!(
            "meta-tag-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let outcome = verify(&unique_app(), "missing-label", &dir, &[0_u8; 32]).unwrap();
        assert_eq!(outcome, VerifyOutcome::NoMeta);
        drop(std::fs::remove_dir_all(&dir));
    }

    /// Ignored: this exercises the real FFI keychain path because
    /// `verify()` calls `load()` unconditionally when the meta file
    /// exists. CI macOS runners typically have a locked / no-user-
    /// session keychain that HANGS the SecItem lookup waiting for a
    /// dialog nobody can dismiss — same reason every other real-
    /// keychain test in this crate (`meta_hmac::*` roundtrip,
    /// `keychain_wrap::*` cross-binary tests) is also ignored.
    /// Run locally on a logged-in macOS dev machine to verify the
    /// `Legacy` outcome.
    #[test]
    #[ignore = "hits the real macOS Keychain; run locally"]
    fn verify_legacy_when_meta_present_but_no_keychain_tag() {
        let dir = std::env::temp_dir().join(format!(
            "meta-tag-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let label = "no-tag-label";
        std::fs::write(dir.join(format!("{label}.meta")), b"{}").unwrap();

        let outcome = verify(&unique_app(), label, &dir, &[0_u8; 32]).unwrap();
        assert!(
            matches!(
                outcome,
                VerifyOutcome::Legacy | VerifyOutcome::KeychainUnavailable
            ),
            "expected Legacy or KeychainUnavailable, got {outcome:?}"
        );
        drop(std::fs::remove_dir_all(&dir));
    }

    #[test]
    fn store_rejects_wrong_length_tag() {
        let result = store(&unique_app(), "label", &[0_u8; 16]);
        assert!(result.is_err());
        let result = store(&unique_app(), "label", &[0_u8; 33]);
        assert!(result.is_err());
    }

    /// Real-keychain roundtrip — store, load, verify-match, tamper,
    /// verify-tamper, delete, verify-legacy.
    #[test]
    #[ignore = "hits the real macOS Keychain; run locally"]
    fn end_to_end_roundtrip() {
        let app = unique_app();
        let label = "roundtrip-key";
        let dir = std::env::temp_dir().join(format!(
            "meta-tag-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let meta_path = dir.join(format!("{label}.meta"));
        let meta_content = b"{\"label\":\"roundtrip-key\",\"presence_mode\":\"strict\"}";
        std::fs::write(&meta_path, meta_content).unwrap();

        let hmac_key = [0x55_u8; 32];
        let tag = enclaveapp_core::metadata::compute_meta_hmac_bytes(&hmac_key, meta_content);

        store(&app, label, &tag).expect("store");

        let outcome = verify(&app, label, &dir, &hmac_key).expect("verify match");
        assert_eq!(outcome, VerifyOutcome::Match);

        // Tamper: rewrite meta with different content.
        std::fs::write(
            &meta_path,
            b"{\"label\":\"roundtrip-key\",\"presence_mode\":\"none\"}",
        )
        .unwrap();
        let outcome = verify(&app, label, &dir, &hmac_key).expect("verify tamper");
        assert_eq!(outcome, VerifyOutcome::Tamper);

        delete(&app, label).expect("delete");
        let outcome = verify(&app, label, &dir, &hmac_key).expect("verify legacy");
        assert_eq!(outcome, VerifyOutcome::Legacy);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
