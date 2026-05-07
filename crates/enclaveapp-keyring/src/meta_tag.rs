// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Per-key meta-integrity tag stored in the system Secret Service
//! (Linux keyring backend).
//!
//! See `docs/design-meta-hmac-trust-anchor.md` for the rationale; this
//! is the Linux analogue of `enclaveapp-apple::meta_tag` and
//! `enclaveapp-windows::meta_tag`.
//!
//! ## Mechanism
//!
//! For each key `<label>`, we persist a 32-byte HMAC-SHA256 tag of
//! the key's `<label>.meta` JSON contents as a Secret Service entry
//! under service `<app_name>`, account `__meta_tag_<label>__`. The
//! `keyring` crate picks the platform's running secret-store backend
//! (typically GNOME Keyring or KWallet via the freedesktop Secret
//! Service spec). Same trust domain as the per-app meta-HMAC key
//! (`__meta_hmac_key__`) and the migration marker
//! (`__meta_migration_marker__`).
//!
//! Why Secret Service over the kernel keyring (`keyutils`):
//! Secret Service is what already holds the meta-HMAC key and the
//! per-key wrapping KEK on this backend, so it's the same trust
//! domain we already accept. Kernel-keyring entries are
//! per-session-by-default and require explicit persistence
//! ceremonies that don't fit our agent's lifecycle. The design doc
//! Track 2 lists Secret Service as the recommended choice for those
//! reasons; the kernel-keyring variant was an alternative that
//! would have introduced a parallel trust boundary for no
//! security upside.
//!
//! At every per-op load (sign / public_key) we recompute the HMAC of
//! the on-disk `.meta` and compare it (constant-time) against the
//! Secret-Service-stored tag. Mismatch is **tamper**; missing
//! entry on an existing key is **legacy_meta** (user must run
//! `sshenc migrate-meta`); both refuse the operation.
//!
//! The on-disk `<label>.meta.hmac` sidecar is a derivable cache: it
//! continues to be written for crash-resilience and forensic
//! comparison, but it is **not** the trust anchor. Deleting the
//! sidecar does not change the verification outcome — the Secret
//! Service tag is the authority. This closes the auto-migrate hole
//! where a same-UID attacker could `rm` the sidecar to force a
//! re-bless of tampered meta JSON.
//!
//! ## Trust domain
//!
//! Reading or writing the entry uses the keyring crate's wrappers
//! around `org.freedesktop.secrets.Service`. The store is per-user;
//! an attacker without the user's session keyring (e.g. a different
//! UID on the same host, or a same-UID-but-pre-unlock attacker) cannot
//! read or write. Same-user processes within an unlocked session can
//! call `delete_credential`, which surfaces as `VerifyOutcome::Legacy`
//! on next op. After `migrate-meta` runs once, the migration marker
//! switches the `legacy_meta` error to its strong-tamper variant —
//! so the deletion primitive is observable, not silently
//! exploitable.

use enclaveapp_core::{Error, Result};
use std::path::Path;
#[cfg(all(feature = "keyring-storage", target_env = "gnu"))]
use zeroize::Zeroize;

/// Length of the meta-integrity tag in bytes (HMAC-SHA256 output).
pub const META_TAG_LEN: usize = 32;

/// Outcome of a meta-integrity verification against the on-disk
/// `.meta` file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// Entry has a tag and it matches the recomputed HMAC of the
    /// on-disk `.meta`. Caller proceeds with the operation.
    Match,
    /// Entry has a tag but it does not match the on-disk `.meta`.
    /// Caller MUST refuse the operation (tamper).
    Tamper,
    /// No entry for this label — pre-trust-anchor key, or the entry
    /// was removed out of band. Caller MUST refuse the operation and
    /// surface the legacy-meta error message that points at
    /// `sshenc migrate-meta`.
    Legacy,
    /// On-disk `.meta` does not exist. Caller's "key not found" flow
    /// applies; no verification was needed. Distinct from `Legacy` so
    /// the caller can distinguish "no key" from "untagged key".
    NoMeta,
    /// Secret Service unreachable. Verification could not run.
    /// Caller decides whether this is fatal or fail-open; current
    /// consumers treat it as fail-open to match the existing
    /// meta-HMAC-key load behavior on this backend.
    KeychainUnavailable,
}

/// Build the per-key Secret Service account name. `service` is the
/// `app_name` (e.g. "sshenc"); the keyring crate uses the
/// `(service, account)` pair as a unique key.
#[cfg_attr(
    not(all(feature = "keyring-storage", target_env = "gnu")),
    allow(dead_code)
)]
fn account_for(label: &str) -> String {
    format!("__meta_tag_{label}__")
}

/// Persist or replace the meta-integrity tag for `(app_name, label)`.
/// Idempotent: an existing tag for the same key is overwritten.
#[cfg(all(feature = "keyring-storage", target_env = "gnu"))]
pub fn store(app_name: &str, label: &str, tag: &[u8]) -> Result<()> {
    if tag.len() != META_TAG_LEN {
        return Err(Error::KeyOperation {
            operation: "meta_tag_store".into(),
            detail: format!("tag must be {META_TAG_LEN} bytes, got {}", tag.len()),
        });
    }
    let entry =
        keyring::Entry::new(app_name, &account_for(label)).map_err(|e| Error::KeyOperation {
            operation: "meta_tag_store".into(),
            detail: format!("keyring::Entry::new: {e}"),
        })?;
    entry.set_secret(tag).map_err(|e| Error::KeyOperation {
        operation: "meta_tag_store".into(),
        detail: format!("set_secret: {e}"),
    })
}

/// Stub for non-Linux-gnu builds (musl, cross-compile to other OSes).
/// Returns an error so the caller knows the trust anchor is not
/// available on this build target.
#[cfg(not(all(feature = "keyring-storage", target_env = "gnu")))]
pub fn store(_app_name: &str, _label: &str, _tag: &[u8]) -> Result<()> {
    Err(Error::KeyOperation {
        operation: "meta_tag_store".into(),
        detail: "keyring-storage feature not compiled in for this target".into(),
    })
}

/// Load the meta-integrity tag for `(app_name, label)`. Returns:
///
/// - `Ok(Some(tag))` on a successful Secret Service read.
/// - `Ok(None)` for the explicit not-found case (the `keyring`
///   crate's `NoEntry` error). Surfaces as `Legacy` from `verify`.
/// - `Err` for every other failure. [`verify`] maps these to
///   `KeychainUnavailable` (fail-open) so a transient store hiccup
///   doesn't brick access.
#[cfg(all(feature = "keyring-storage", target_env = "gnu"))]
pub fn load(app_name: &str, label: &str) -> Result<Option<[u8; META_TAG_LEN]>> {
    let entry =
        keyring::Entry::new(app_name, &account_for(label)).map_err(|e| Error::KeyOperation {
            operation: "meta_tag_load".into(),
            detail: format!("keyring::Entry::new: {e}"),
        })?;
    match entry.get_secret() {
        Ok(bytes) if bytes.len() == META_TAG_LEN => {
            let mut out = [0_u8; META_TAG_LEN];
            out.copy_from_slice(&bytes);
            // Wipe the local Vec copy returned by keyring before drop.
            let mut wipe = bytes;
            wipe.zeroize();
            Ok(Some(out))
        }
        Ok(bytes) => {
            // Wrong length — treat as missing rather than panicking.
            // This shouldn't normally happen but a corrupted entry
            // shouldn't break the verify flow. Wipe and report None.
            let mut wipe = bytes;
            wipe.zeroize();
            Ok(None)
        }
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => {
            tracing::debug!(label = %label, error = %e, "meta_tag_load: keyring error");
            Err(Error::KeyOperation {
                operation: "meta_tag_load".into(),
                detail: format!("get_secret: {e}"),
            })
        }
    }
}

#[cfg(not(all(feature = "keyring-storage", target_env = "gnu")))]
pub fn load(_app_name: &str, _label: &str) -> Result<Option<[u8; META_TAG_LEN]>> {
    Ok(None)
}

/// Delete the meta-integrity tag for `(app_name, label)`. Idempotent:
/// missing entry is success.
#[cfg(all(feature = "keyring-storage", target_env = "gnu"))]
pub fn delete(app_name: &str, label: &str) -> Result<()> {
    let entry =
        keyring::Entry::new(app_name, &account_for(label)).map_err(|e| Error::KeyOperation {
            operation: "meta_tag_delete".into(),
            detail: format!("keyring::Entry::new: {e}"),
        })?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(Error::KeyOperation {
            operation: "meta_tag_delete".into(),
            detail: format!("delete_credential: {e}"),
        }),
    }
}

#[cfg(not(all(feature = "keyring-storage", target_env = "gnu")))]
pub fn delete(_app_name: &str, _label: &str) -> Result<()> {
    Ok(())
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

/// Recompute and store the meta-integrity tag for `(app_name, label)`
/// from the current on-disk `<label>.meta` content.
///
/// Used at the end of the higher-level keygen flow after every meta-
/// mutating step (the `app_specific` fields the sshenc CLI / agent
/// layer adds — `comment`, `pub_file_path`, `presence_mode` — land
/// AFTER the platform backend's `generate` returns, so a tag stamped
/// inline in the platform backend is invalidated by the time keygen
/// completes). Calling `stamp_from_disk` once at the end stamps the
/// authoritative final meta. Idempotent with the inline stamp;
/// `keyring::Entry::set_secret` upserts.
pub fn stamp_from_disk(
    app_name: &str,
    label: &str,
    keys_dir: &Path,
    meta_hmac_key: &[u8],
) -> Result<()> {
    let meta_path = keys_dir.join(format!("{label}.meta"));
    let meta_bytes = std::fs::read(&meta_path).map_err(|e| Error::KeyOperation {
        operation: "meta_tag_stamp".into(),
        detail: format!("read {}: {e}", meta_path.display()),
    })?;
    let tag = enclaveapp_core::metadata::compute_meta_hmac_bytes(meta_hmac_key, &meta_bytes);
    store(app_name, label, &tag)
}

/// Verify the on-disk `<label>.meta` against the Secret-Service-stored
/// integrity tag for `(app_name, label)`.
///
/// This is the per-op trust-anchor check. The caller passes the
/// process-loaded meta-HMAC key (from
/// [`crate::key_storage::meta_hmac_key_existing`]) so this function
/// does not perform a second secret-store round-trip on every call.
/// The meta-HMAC key is loaded once at agent startup and cached;
/// the per-key tag is the only thing read here.
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
        Ok(None) => return Ok(VerifyOutcome::Legacy),
        Err(_) => return Ok(VerifyOutcome::KeychainUnavailable),
    };

    let meta_bytes = std::fs::read(&meta_path).map_err(|e| Error::KeyOperation {
        operation: "meta_tag_verify".into(),
        detail: format!("read {}: {e}", meta_path.display()),
    })?;
    let actual = enclaveapp_core::metadata::compute_meta_hmac_bytes(meta_hmac_key, &meta_bytes);

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
            "enclaveapp-keyring-meta-tag-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst),
        )
    }

    #[test]
    fn account_format() {
        assert_eq!(account_for("default"), "__meta_tag_default__");
        assert_eq!(account_for("prod-key"), "__meta_tag_prod-key__");
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

    #[cfg(all(feature = "keyring-storage", target_env = "gnu"))]
    #[test]
    fn store_rejects_wrong_length_tag() {
        let result = store(&unique_app(), "label", &[0_u8; 16]);
        assert!(result.is_err());
        let result = store(&unique_app(), "label", &[0_u8; 33]);
        assert!(result.is_err());
    }

    /// Real Secret Service round-trip — store, load, verify-match,
    /// tamper, verify-tamper, delete, verify-legacy. Persists state
    /// in the user's session keyring under a unique app name so
    /// concurrent test runs don't collide. `#[ignore]`d by default
    /// because it requires a running Secret Service daemon (gnome-
    /// keyring-daemon / kwalletd / similar); CI Linux runners often
    /// don't have one.
    #[cfg(all(feature = "keyring-storage", target_env = "gnu"))]
    #[test]
    #[ignore = "hits real Secret Service; run on a desktop Linux session"]
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
