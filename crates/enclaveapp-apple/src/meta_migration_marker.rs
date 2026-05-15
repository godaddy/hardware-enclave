// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! macOS Keychain-backed marker indicating that a one-time meta-
//! integrity migration has completed for this install.
//!
//! See `docs/design-meta-hmac-trust-anchor.md`.
//!
//! ## Why a Keychain item, not a file
//!
//! The marker exists to distinguish "first time after upgrade" from
//! "second time, this is suspicious." A free-floating file in the
//! user's home directory is trivially `rm`-able by a same-UID
//! attacker — exactly the deletion primitive that re-opens the
//! auto-migrate hole the trust anchor closes. Putting the marker in
//! the legacy Keychain under the agent's signed-binary ACL means the
//! attacker (without our entitled signed binary) can neither delete
//! nor read it. Same trust anchor as the per-key meta-tags.
//!
//! Service: `com.godaddy.<app>.migrate-marker`
//! Account: `__completed__`
//! Body:    a small fixed sentinel ("v1") — we don't need version
//!          history here; presence is the signal.
//!
//! ## ACL invariant
//!
//! As with [`crate::meta_hmac`] / [`crate::meta_tag`], the agent is
//! the only binary that should ever read or write this marker. The
//! CLI delegates over IPC.

use crate::ffi;
use enclaveapp_core::{Error, Result};

/// The single byte payload of the marker. Presence/absence is the
/// signal; the body just exists because the keychain bridge expects
/// non-empty bytes.
const MARKER_PAYLOAD: &[u8] = b"v1";

/// Keychain account string under which the marker is stored.
const MARKER_ACCOUNT: &str = "__completed__";

/// Keychain service name for the migration marker.
fn service_name_for(app_name: &str) -> String {
    format!("com.godaddy.{app_name}.migrate-marker")
}

/// Returns whether the migration marker is set for `app_name`.
///
/// `Ok(true)` — marker is present in the Keychain.
/// `Ok(false)` — marker is explicitly absent (rc=12 NOT_FOUND).
/// `Err(_)` — every other Keychain failure (locked, FFI error,
///   ACL refused). Callers that want to fail-open should map the
///   error to `false`; callers that want to fail-closed (like the
///   CLI's "are we already migrated?" check) should treat the
///   error as "I can't tell" and bail with a clear message.
#[allow(unsafe_code)] // FFI call to Swift Keychain bridge
pub fn is_set(app_name: &str) -> Result<bool> {
    let service = service_name_for(app_name);
    let service_bytes = service.as_bytes();
    let account_bytes = MARKER_ACCOUNT.as_bytes();
    let service_len = i32::try_from(service_bytes.len()).map_err(|_| Error::KeyOperation {
        operation: "migrate_marker_load".into(),
        detail: "service name too long".into(),
    })?;
    let account_len = i32::try_from(account_bytes.len()).map_err(|_| Error::KeyOperation {
        operation: "migrate_marker_load".into(),
        detail: "account name too long".into(),
    })?;
    let mut out = [0_u8; 16];
    let mut out_len: i32 = out.len() as i32;
    // SAFETY: pointers from live mutable buffer; bridge writes at
    // most out_len bytes and updates out_len to actual count.
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
        0 => Ok(true),
        12 => Ok(false),
        _ => Err(Error::KeyOperation {
            operation: "migrate_marker_load".into(),
            detail: format!("Swift bridge returned error code {rc}"),
        }),
    }
}

/// Set the migration marker for `app_name`. Idempotent: replacing
/// an existing marker is fine.
#[allow(unsafe_code)] // FFI call to Swift Keychain bridge
pub fn set(app_name: &str) -> Result<()> {
    // Replace semantics: delete-then-store, mirroring meta_tag::store.
    drop(clear(app_name));

    let service = service_name_for(app_name);
    let service_bytes = service.as_bytes();
    let account_bytes = MARKER_ACCOUNT.as_bytes();
    let service_len = i32::try_from(service_bytes.len()).map_err(|_| Error::KeyOperation {
        operation: "migrate_marker_set".into(),
        detail: "service name too long".into(),
    })?;
    let account_len = i32::try_from(account_bytes.len()).map_err(|_| Error::KeyOperation {
        operation: "migrate_marker_set".into(),
        detail: "account name too long".into(),
    })?;
    let payload_len = i32::try_from(MARKER_PAYLOAD.len()).map_err(|_| Error::KeyOperation {
        operation: "migrate_marker_set".into(),
        detail: "payload too long".into(),
    })?;
    // SAFETY: pointers from live slices, lengths bounded above.
    let rc = unsafe {
        ffi::enclaveapp_keychain_store(
            service_bytes.as_ptr(),
            service_len,
            account_bytes.as_ptr(),
            account_len,
            MARKER_PAYLOAD.as_ptr(),
            payload_len,
            0,                // no user-presence ACL
            std::ptr::null(), // legacy keychain
            0,
        )
    };
    if rc != 0 {
        return Err(Error::KeyOperation {
            operation: "migrate_marker_set".into(),
            detail: format!("Swift bridge returned error code {rc}"),
        });
    }
    Ok(())
}

/// Clear the migration marker for `app_name`. Idempotent: missing
/// entry is success.
#[allow(unsafe_code)] // FFI call to Swift Keychain bridge
pub fn clear(app_name: &str) -> Result<()> {
    let service = service_name_for(app_name);
    let service_bytes = service.as_bytes();
    let account_bytes = MARKER_ACCOUNT.as_bytes();
    let service_len = i32::try_from(service_bytes.len()).map_err(|_| Error::KeyOperation {
        operation: "migrate_marker_clear".into(),
        detail: "service name too long".into(),
    })?;
    let account_len = i32::try_from(account_bytes.len()).map_err(|_| Error::KeyOperation {
        operation: "migrate_marker_clear".into(),
        detail: "account name too long".into(),
    })?;
    // SAFETY: pointers from live slices, lengths bounded above.
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
            operation: "migrate_marker_clear".into(),
            detail: format!("Swift bridge returned error code {rc}"),
        }),
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
            "enclaveapp-apple-migrate-marker-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst),
        )
    }

    #[test]
    fn service_name_format() {
        assert_eq!(
            service_name_for("sshenc"),
            "com.godaddy.sshenc.migrate-marker"
        );
        assert_eq!(
            service_name_for("awsenc"),
            "com.godaddy.awsenc.migrate-marker"
        );
    }

    #[test]
    fn service_name_for_npmenc() {
        assert_eq!(
            service_name_for("npmenc"),
            "com.godaddy.npmenc.migrate-marker"
        );
    }

    #[test]
    fn marker_payload_is_v1() {
        assert_eq!(MARKER_PAYLOAD, b"v1");
    }

    #[test]
    fn marker_account_is_completed() {
        assert_eq!(MARKER_ACCOUNT, "__completed__");
    }

    #[test]
    fn service_name_contains_app_name_and_suffix() {
        let name = service_name_for("my-app");
        assert!(name.contains("my-app"));
        assert!(name.ends_with(".migrate-marker"));
        assert!(name.starts_with("com.godaddy."));
    }

    /// Real-keychain roundtrip: set / is_set true / clear / is_set
    /// false. Hits the legacy Keychain on the test runner.
    #[test]
    #[ignore = "hits the real macOS Keychain; run locally"]
    fn set_clear_roundtrip() {
        let app = unique_app();
        // Pre-clear to handle the case where a prior aborted run
        // left the marker behind. is_set after clear must be false.
        clear(&app).expect("clear is idempotent");
        assert!(matches!(is_set(&app), Ok(false)));

        set(&app).expect("set succeeds");
        assert!(matches!(is_set(&app), Ok(true)));

        // Set again — replace semantics, still Ok and still set.
        set(&app).expect("repeat set");
        assert!(matches!(is_set(&app), Ok(true)));

        clear(&app).expect("clear succeeds");
        assert!(matches!(is_set(&app), Ok(false)));
    }
}
