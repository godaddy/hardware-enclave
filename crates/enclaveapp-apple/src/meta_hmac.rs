// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! macOS legacy-Keychain backing for the per-app meta-HMAC key.
//!
//! See `docs/design-cross-platform-meta-hmac.md` for the rationale.
//! Mirrors the wrapping-key storage pattern in
//! [`crate::keychain_wrap`] but stores 32 bytes of generic HMAC key
//! material under a distinct service name, with no user-presence ACL
//! and no Data Protection access group. The HMAC key authenticates
//! `<label>.meta` JSON contents so a same-UID attacker without
//! Keychain access cannot rewrite policy-bearing meta fields without
//! detection.
//!
//! ## ACL invariant
//!
//! The legacy Keychain ties an item's ACL to the **creating binary's
//! code signature**. To keep the meta-HMAC key reachable without
//! per-rebuild approval prompts, this module is intended to be called
//! from `sshenc-agent` (and the equivalent agent process for awsenc /
//! sso-jwt / npmenc) **only**. CLI binaries have no need to verify
//! the HMAC sidecar themselves — they treat their on-disk `keys_dir`
//! as a derived cache and let the agent serve as the source of
//! truth. This is the same agent-only-reads pattern that the wrapping
//! keys already follow; see "Cross-Binary Keychain ACL Prompt /
//! Fatigue" in sshenc/THREAT_MODEL.md.

use crate::ffi;
use enclaveapp_core::{Error, Result};
use rand::RngCore;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use zeroize::{Zeroize, Zeroizing};

/// Length of the per-app meta-HMAC key in bytes (HMAC-SHA256 key).
const META_HMAC_KEY_LEN: usize = 32;

type CachedKey = Box<Zeroizing<[u8; META_HMAC_KEY_LEN]>>;
type CacheMap = HashMap<String, CachedKey>;

/// Process-local cache so per-op `verify_meta_integrity` calls
/// after the first one don't re-hit the Keychain. Keyed by
/// `app_name`. The key is zeroized on Drop, mirroring the
/// wrapping-key cache discipline in `crate::keychain_wrap`.
///
/// No TTL — the meta-HMAC key is invalidated only when the process
/// exits or `delete` is called explicitly. That matches the
/// security threshold: an attacker who can rotate the cached value
/// already has process-memory access, against which we don't
/// defend at this layer.
fn cache() -> &'static Mutex<CacheMap> {
    static CACHE: OnceLock<Mutex<CacheMap>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn cache_lookup(app_name: &str) -> Option<Zeroizing<Vec<u8>>> {
    let guard = cache().lock().ok()?;
    let entry = guard.get(app_name)?;
    Some(Zeroizing::new(entry.to_vec()))
}

fn cache_insert(app_name: &str, key: [u8; META_HMAC_KEY_LEN]) {
    if let Ok(mut guard) = cache().lock() {
        guard.insert(app_name.to_string(), Box::new(Zeroizing::new(key)));
    }
}

fn cache_evict(app_name: &str) {
    if let Ok(mut guard) = cache().lock() {
        guard.remove(app_name);
    }
}

/// Keychain account string under which the per-app meta-HMAC key is
/// stored. Matches the convention used by the Linux keyring backend
/// (`enclaveapp-keyring::META_HMAC_ACCOUNT`).
const META_HMAC_ACCOUNT: &str = "__meta_hmac_key__";

/// Keychain service name for the per-app meta-HMAC key.
///
/// Distinct from the wrapping-key service name
/// (`com.godaddy.<app>`) so the legacy-Keychain ACL on the wrapping
/// keys and the meta-HMAC key are separate decisions.
fn service_name_for(app_name: &str) -> String {
    format!("com.godaddy.{app_name}.meta-hmac")
}

/// Load the per-app meta-HMAC key from the legacy macOS Keychain,
/// generating and persisting one on first call.
///
/// Returns `Ok(Some(key))` on success and `Ok(None)` when the
/// Keychain is unreachable (locked + no after-first-unlock policy
/// matched, FFI returned an error). Production callers should treat
/// `None` the same as keyring-unavailable on Linux: refuse to
/// proceed rather than silently writing unauthenticated meta.
///
/// `Result::Err` is reserved for cases the caller is expected to
/// surface as an operator error (RNG failure, internal length
/// invariant violation). The common "Keychain not reachable" path
/// returns `Ok(None)` so consumers can take the
/// no-HMAC-key-available branch uniformly.
pub fn load_or_create(app_name: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
    // Fast path: cache hit. Process-local; subsequent calls within
    // the same agent session never touch the Keychain. This is
    // critical for the per-op verification UX — a sign or list
    // operation must not add a Keychain round-trip on top of the
    // wrapping-key load that the existing flow already does.
    if let Some(cached) = cache_lookup(app_name) {
        return Ok(Some(cached));
    }
    if let Some(existing) = load(app_name)? {
        // Cache the loaded key so subsequent calls within this
        // process don't re-read.
        if existing.len() == META_HMAC_KEY_LEN {
            let mut buf = [0_u8; META_HMAC_KEY_LEN];
            buf.copy_from_slice(&existing);
            cache_insert(app_name, buf);
            buf.zeroize();
        }
        return Ok(Some(existing));
    }
    let created = create_and_store(app_name)?;
    if created.len() == META_HMAC_KEY_LEN {
        let mut buf = [0_u8; META_HMAC_KEY_LEN];
        buf.copy_from_slice(&created);
        cache_insert(app_name, buf);
        buf.zeroize();
    }
    Ok(Some(created))
}

/// Try to load the existing key. Returns `Ok(None)` for both
/// not-found and Keychain-unavailable so the caller's call site is
/// unconditional.
#[allow(unsafe_code)] // FFI call to Swift Keychain bridge
fn load(app_name: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let service = service_name_for(app_name);
    let service_bytes = service.as_bytes();
    let account_bytes = META_HMAC_ACCOUNT.as_bytes();

    let service_len = i32::try_from(service_bytes.len()).map_err(|_| Error::KeyOperation {
        operation: "meta_hmac_load".into(),
        detail: "service name too long".into(),
    })?;
    let account_len = i32::try_from(account_bytes.len()).map_err(|_| Error::KeyOperation {
        operation: "meta_hmac_load".into(),
        detail: "account name too long".into(),
    })?;

    let mut out = [0_u8; META_HMAC_KEY_LEN];
    let mut out_len: i32 = out.len() as i32;
    // SAFETY: pointers are derived from live slices and the integer
    // lengths above; the Swift bridge writes at most `out_len` bytes
    // into `out`, then updates `out_len` to the actual count.
    let rc = unsafe {
        ffi::enclaveapp_keychain_load(
            service_bytes.as_ptr(),
            service_len,
            account_bytes.as_ptr(),
            account_len,
            out.as_mut_ptr(),
            &mut out_len,
            std::ptr::null(), // no access group — legacy keychain
            0,
            0, // no LAContext token — HMAC key is not user-presence-protected
        )
    };
    match rc {
        0 => {
            if out_len as usize != META_HMAC_KEY_LEN {
                out.zeroize();
                return Err(Error::KeyOperation {
                    operation: "meta_hmac_load".into(),
                    detail: format!(
                        "loaded meta-HMAC key has unexpected length {out_len}, \
                         expected {META_HMAC_KEY_LEN}"
                    ),
                });
            }
            let value = Zeroizing::new(out.to_vec());
            out.zeroize();
            Ok(Some(value))
        }
        12 => {
            // SE_ERR_KEYCHAIN_NOT_FOUND — first call, no key yet.
            out.zeroize();
            Ok(None)
        }
        _ => {
            // Other Keychain failures (locked, IO, etc.) are treated
            // as "unavailable" so the caller can take the
            // no-HMAC-key branch. The bridge logs the SecCopyMatching
            // OSStatus on its side; we surface it via a tracing
            // debug here.
            out.zeroize();
            tracing::debug!(rc, "meta_hmac_load: keychain unreachable; returning None");
            Ok(None)
        }
    }
}

/// Generate 32 random bytes and store them in the legacy Keychain.
/// Returns the freshly-generated key so the caller's first
/// `load_or_create` returns it without a second Keychain round-trip.
#[allow(unsafe_code)] // FFI call to Swift Keychain bridge
fn create_and_store(app_name: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut key = [0_u8; META_HMAC_KEY_LEN];
    rand::rng().fill_bytes(&mut key);

    let service = service_name_for(app_name);
    let service_bytes = service.as_bytes();
    let account_bytes = META_HMAC_ACCOUNT.as_bytes();

    let service_len = i32::try_from(service_bytes.len()).map_err(|_| {
        key.zeroize();
        Error::KeyOperation {
            operation: "meta_hmac_store".into(),
            detail: "service name too long".into(),
        }
    })?;
    let account_len = i32::try_from(account_bytes.len()).map_err(|_| {
        key.zeroize();
        Error::KeyOperation {
            operation: "meta_hmac_store".into(),
            detail: "account name too long".into(),
        }
    })?;

    // SAFETY: pointers from live slices, lengths from `i32::try_from`
    // above; Swift bridge does not retain the pointers past return.
    let rc = unsafe {
        ffi::enclaveapp_keychain_store(
            service_bytes.as_ptr(),
            service_len,
            account_bytes.as_ptr(),
            account_len,
            key.as_ptr(),
            META_HMAC_KEY_LEN as i32,
            0,                // no user-presence ACL
            std::ptr::null(), // no access group — legacy keychain
            0,
        )
    };

    if rc != 0 {
        key.zeroize();
        // Same calling convention as `load`: a store failure means
        // the Keychain is unreachable from this binary. Surface as
        // an error here (rather than `Ok(None)`) because the caller
        // explicitly asked us to create one — silent failure would
        // be misleading.
        return Err(Error::KeyOperation {
            operation: "meta_hmac_store".into(),
            detail: format!("Swift bridge returned error code {rc}"),
        });
    }

    let value = Zeroizing::new(key.to_vec());
    key.zeroize();
    Ok(value)
}

/// Remove the per-app meta-HMAC key from the Keychain. Used by the
/// uninstall flow so a clean reinstall doesn't reuse a stale key.
/// Idempotent: missing-entry is success.
#[allow(unsafe_code)] // FFI call to Swift Keychain bridge
pub fn delete(app_name: &str) -> Result<()> {
    let service = service_name_for(app_name);
    let service_bytes = service.as_bytes();
    let account_bytes = META_HMAC_ACCOUNT.as_bytes();
    let service_len = i32::try_from(service_bytes.len()).map_err(|_| Error::KeyOperation {
        operation: "meta_hmac_delete".into(),
        detail: "service name too long".into(),
    })?;
    let account_len = i32::try_from(account_bytes.len()).map_err(|_| Error::KeyOperation {
        operation: "meta_hmac_delete".into(),
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
    cache_evict(app_name);
    match rc {
        0 | 12 => Ok(()), // success or NOT_FOUND
        _ => Err(Error::KeyOperation {
            operation: "meta_hmac_delete".into(),
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
            "enclaveapp-apple-meta-hmac-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst),
        )
    }

    #[test]
    fn service_name_includes_app_and_suffix() {
        assert_eq!(service_name_for("sshenc"), "com.godaddy.sshenc.meta-hmac");
        assert_eq!(service_name_for("awsenc"), "com.godaddy.awsenc.meta-hmac");
    }

    /// Cross-process round-trip test: store, load, delete, load
    /// again. Hits the real Keychain on the test runner. Skipped if
    /// the Keychain is unreachable (CI runners without a login
    /// keychain unlocked) — we treat `Ok(None)` from load on a key
    /// we just stored as "test environment can't actually persist
    /// keychain items" and skip rather than fail.
    #[test]
    #[ignore = "hits the real macOS Keychain; run locally"]
    fn store_load_delete_roundtrip() {
        let app = unique_app();
        let created = load_or_create(&app)
            .expect("create succeeds")
            .expect("created key is Some");
        assert_eq!(created.len(), META_HMAC_KEY_LEN);

        let loaded = load_or_create(&app)
            .expect("re-load succeeds")
            .expect("re-loaded key is Some");
        assert_eq!(loaded.len(), META_HMAC_KEY_LEN);
        assert_eq!(&created[..], &loaded[..], "second load returns same bytes");

        delete(&app).expect("delete succeeds");
        // After delete, load_or_create regenerates a fresh key.
        let regenerated = load_or_create(&app)
            .expect("regen succeeds")
            .expect("regen key is Some");
        assert_eq!(regenerated.len(), META_HMAC_KEY_LEN);
        assert_ne!(
            &created[..],
            &regenerated[..],
            "regen after delete produces a different key"
        );
        let _ = delete(&app);
    }

    /// Delete on a never-stored app must return Ok (idempotent).
    #[test]
    #[ignore = "hits the real macOS Keychain; run locally"]
    fn delete_is_idempotent_on_missing() {
        let app = unique_app();
        delete(&app).expect("delete on missing key is Ok");
        delete(&app).expect("second delete is also Ok");
    }
}
