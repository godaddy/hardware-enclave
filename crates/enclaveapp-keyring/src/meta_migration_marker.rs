// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! System Secret Service-backed marker indicating that the one-time
//! meta-integrity migration has completed for this install.
//!
//! See `docs/design-meta-hmac-trust-anchor.md`. This is the Linux
//! analogue of `enclaveapp-apple::meta_migration_marker` and
//! `enclaveapp-windows::meta_migration_marker`.
//!
//! ## Mechanism
//!
//! Single Secret Service entry under service `<app_name>`, account
//! `__meta_migration_marker__`. Body is a fixed `b"v1"` sentinel —
//! presence/absence is the signal we read; the body just exists
//! because some Secret Service backends reject zero-byte secrets.
//!
//! ## Why Secret Service, not a file
//!
//! The marker exists to distinguish "first time after upgrade" from
//! "second time, this is suspicious." A free-floating file in the
//! user's home directory is trivially `rm`-able by a same-UID
//! attacker — exactly the deletion primitive the trust anchor
//! exists to close. Secret Service entries are bound to the user's
//! unlocked session keyring; a same-UID attacker without the
//! session key (e.g. pre-unlock) cannot read or delete. Same trust
//! domain as the per-app meta-HMAC key and the per-key meta-tag
//! entries.

use enclaveapp_core::{Error, Result};

/// Account name for the migration marker entry.
#[cfg(all(feature = "keyring-storage", target_env = "gnu"))]
const MARKER_ACCOUNT: &str = "__meta_migration_marker__";

/// Sentinel payload — presence/absence is the only signal we read,
/// the body just exists because some Secret Service backends reject
/// zero-byte secrets. Versioned so a future schema bump can be
/// detected.
#[cfg(all(feature = "keyring-storage", target_env = "gnu"))]
const MARKER_PAYLOAD: &[u8] = b"v1";

/// Returns whether the migration marker is set for `app_name`.
///
/// `Ok(true)` — marker is present in Secret Service.
/// `Ok(false)` — marker explicitly absent (`keyring::Error::NoEntry`).
/// `Err(_)` — every other Secret Service failure (no daemon,
///   D-Bus unreachable, etc.). Callers that want to fail-open should
///   map the error to `false`; callers that want to fail-closed
///   (the CLI's "are we already migrated?" check) should bail with
///   a clear message so the user knows the recommendation can't be
///   trusted.
#[cfg(all(feature = "keyring-storage", target_env = "gnu"))]
pub fn is_set(app_name: &str) -> Result<bool> {
    let entry = keyring::Entry::new(app_name, MARKER_ACCOUNT).map_err(|e| Error::KeyOperation {
        operation: "migrate_marker_load".into(),
        detail: format!("keyring::Entry::new: {e}"),
    })?;
    match entry.get_secret() {
        Ok(_) => Ok(true),
        Err(keyring::Error::NoEntry) => Ok(false),
        Err(e) => Err(Error::KeyOperation {
            operation: "migrate_marker_load".into(),
            detail: format!("get_secret: {e}"),
        }),
    }
}

#[cfg(not(all(feature = "keyring-storage", target_env = "gnu")))]
pub fn is_set(_app_name: &str) -> Result<bool> {
    Ok(false)
}

/// Set the migration marker for `app_name`. Idempotent: replacing
/// an existing marker is fine — `set_secret` upserts.
#[cfg(all(feature = "keyring-storage", target_env = "gnu"))]
pub fn set(app_name: &str) -> Result<()> {
    let entry = keyring::Entry::new(app_name, MARKER_ACCOUNT).map_err(|e| Error::KeyOperation {
        operation: "migrate_marker_set".into(),
        detail: format!("keyring::Entry::new: {e}"),
    })?;
    entry
        .set_secret(MARKER_PAYLOAD)
        .map_err(|e| Error::KeyOperation {
            operation: "migrate_marker_set".into(),
            detail: format!("set_secret: {e}"),
        })
}

#[cfg(not(all(feature = "keyring-storage", target_env = "gnu")))]
pub fn set(_app_name: &str) -> Result<()> {
    Err(Error::KeyOperation {
        operation: "migrate_marker_set".into(),
        detail: "keyring-storage feature not compiled in for this target".into(),
    })
}

/// Clear the migration marker for `app_name`. Idempotent: missing
/// entry is success.
#[cfg(all(feature = "keyring-storage", target_env = "gnu"))]
pub fn clear(app_name: &str) -> Result<()> {
    let entry = keyring::Entry::new(app_name, MARKER_ACCOUNT).map_err(|e| Error::KeyOperation {
        operation: "migrate_marker_clear".into(),
        detail: format!("keyring::Entry::new: {e}"),
    })?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(Error::KeyOperation {
            operation: "migrate_marker_clear".into(),
            detail: format!("delete_credential: {e}"),
        }),
    }
}

#[cfg(not(all(feature = "keyring-storage", target_env = "gnu")))]
pub fn clear(_app_name: &str) -> Result<()> {
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, let_underscore_drop)]
mod tests {
    #[cfg(all(feature = "keyring-storage", target_env = "gnu"))]
    use super::*;
    #[cfg(all(feature = "keyring-storage", target_env = "gnu"))]
    use std::sync::atomic::{AtomicU64, Ordering};

    #[cfg(all(feature = "keyring-storage", target_env = "gnu"))]
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    #[cfg(all(feature = "keyring-storage", target_env = "gnu"))]
    fn unique_app() -> String {
        format!(
            "enclaveapp-keyring-migrate-marker-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst),
        )
    }

    #[cfg(all(feature = "keyring-storage", target_env = "gnu"))]
    #[test]
    fn account_constant_format() {
        assert_eq!(MARKER_ACCOUNT, "__meta_migration_marker__");
    }

    /// Real Secret Service round-trip. Persists state in the user's
    /// session keyring under a unique app name so concurrent runs
    /// don't collide. `#[ignore]`d on default `cargo test` because
    /// it requires a running Secret Service daemon.
    #[cfg(all(feature = "keyring-storage", target_env = "gnu"))]
    #[test]
    #[ignore = "hits real Secret Service; run on a desktop Linux session"]
    fn set_clear_roundtrip() {
        let app = unique_app();
        clear(&app).expect("clear is idempotent");
        assert!(matches!(is_set(&app), Ok(false)));

        set(&app).expect("set succeeds");
        assert!(matches!(is_set(&app), Ok(true)));

        // Replace semantics — second set still leaves marker present.
        set(&app).expect("repeat set");
        assert!(matches!(is_set(&app), Ok(true)));

        clear(&app).expect("clear succeeds");
        assert!(matches!(is_set(&app), Ok(false)));
    }
}
