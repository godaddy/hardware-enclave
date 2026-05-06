// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Windows DPAPI backing for the per-app meta-HMAC key.
//!
//! See `docs/design-cross-platform-meta-hmac.md` for the rationale.
//! Stores 32 random bytes encrypted via `CryptProtectData` under the
//! current Windows user's master key, persisted as an opaque file at
//! `%APPDATA%\<app>\.meta-hmac.dpapi`. The HMAC key authenticates
//! `<label>.meta` JSON contents so a same-UID attacker without the
//! user's Windows credentials cannot rewrite policy-bearing meta
//! fields without detection.
//!
//! ## DPAPI binding
//!
//! `CryptProtectData(CRYPTPROTECT_UI_FORBIDDEN)` ties decryption to
//! the current Windows user. The blob survives package reinstalls
//! and code-signature changes; it does **not** survive a user-
//! profile reset or a Windows reinstall. Profile reset is treated
//! the same as a TPM hardware reset: regenerate the affected keys
//! after the migration window catches up.
//!
//! `CRYPTPROTECT_LOCAL_MACHINE` is intentionally **not** set —
//! per-user binding is the threshold the threat model wants. With
//! `LOCAL_MACHINE`, any local user could decrypt; without it, only
//! the user account that created the blob can.
//!
//! ## Path of stored blob
//!
//! `dirs::data_dir()` resolves to `%APPDATA%\Roaming` on a default
//! Windows configuration. We use a `.meta-hmac.dpapi` filename so
//! the blob is visually distinct from `.meta` / `.handle` /
//! `.meta.hmac` artifacts in the keys directory.

use enclaveapp_core::{Error, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Cryptography::{
    BCryptGenRandom, CryptProtectData, CryptUnprotectData, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
    CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
};
use zeroize::{Zeroize, Zeroizing};

/// Length of the per-app meta-HMAC key in bytes (HMAC-SHA256 key).
const META_HMAC_KEY_LEN: usize = 32;

type CachedKey = Box<Zeroizing<[u8; META_HMAC_KEY_LEN]>>;
type CacheMap = HashMap<String, CachedKey>;

/// Process-local cache so per-op `verify_meta_integrity` calls
/// after the first one don't re-read the on-disk DPAPI blob and
/// re-invoke `CryptUnprotectData`. Mirrors the macOS module's
/// cache so the per-op cost is uniform across platforms: a single
/// HMAC compute against a cached key, no syscalls.
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

/// Filename for the DPAPI blob inside the app's data dir.
const BLOB_FILENAME: &str = ".meta-hmac.dpapi";

/// Compute the on-disk path for the DPAPI blob. Falls back to the
/// system temp directory only if `dirs::data_dir` is unavailable
/// (extremely unusual on Windows; mostly a safety net for stripped-
/// down hosts).
fn blob_path(app_name: &str) -> PathBuf {
    let base = dirs::data_dir().unwrap_or_else(std::env::temp_dir);
    base.join(app_name).join(BLOB_FILENAME)
}

/// Load the per-app meta-HMAC key, generating and persisting one on
/// first call.
///
/// Returns `Ok(Some(key))` on success and `Ok(None)` when DPAPI is
/// unavailable (very rare; mainly profile-reset simulation in tests).
/// Production callers should treat `None` the same as keyring-
/// unavailable on Linux: refuse to proceed in production paths.
pub fn load_or_create(app_name: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
    // Fast path: process-local cache hit so per-op verification
    // calls after the first one don't re-read or re-decrypt.
    if let Some(cached) = cache_lookup(app_name) {
        return Ok(Some(cached));
    }
    let path = blob_path(app_name);
    if let Some(key) = load_existing(&path)? {
        if key.len() == META_HMAC_KEY_LEN {
            let mut buf = [0_u8; META_HMAC_KEY_LEN];
            buf.copy_from_slice(&key);
            cache_insert(app_name, buf);
            buf.zeroize();
        }
        return Ok(Some(key));
    }
    let created = create_and_persist(&path)?;
    if created.len() == META_HMAC_KEY_LEN {
        let mut buf = [0_u8; META_HMAC_KEY_LEN];
        buf.copy_from_slice(&created);
        cache_insert(app_name, buf);
        buf.zeroize();
    }
    Ok(Some(created))
}

/// Try to load and decrypt an existing blob. Returns `Ok(None)` if
/// the file doesn't exist; surfaces other I/O errors. DPAPI failures
/// (corrupt blob, profile change) are surfaced as `Err` so the
/// operator sees them — silently regenerating would mask a real
/// security event.
fn load_existing(path: &Path) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let blob = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(Error::Io(e)),
    };
    decrypt(&blob).map(Some)
}

/// Generate a fresh 32-byte key, DPAPI-encrypt it, and atomic-write
/// the ciphertext to the blob path. Returns the freshly-generated key.
fn create_and_persist(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let mut key = [0_u8; META_HMAC_KEY_LEN];
    gen_random(&mut key)?;

    let blob = encrypt(&key)?;

    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            key.zeroize();
            return Err(Error::Io(e));
        }
    }
    if let Err(e) = enclaveapp_core::metadata::atomic_write(path, &blob) {
        key.zeroize();
        return Err(e);
    }

    let value = Zeroizing::new(key.to_vec());
    key.zeroize();
    Ok(value)
}

/// Remove the DPAPI blob. Used by uninstall flows so a clean
/// reinstall doesn't reuse a stale key. Idempotent.
pub fn delete(app_name: &str) -> Result<()> {
    cache_evict(app_name);
    let path = blob_path(app_name);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::Io(e)),
    }
}

/// Wrap `BCryptGenRandom` for the 32-byte key generation. RNG
/// failures are propagated as `Error::KeyOperation` so the caller
/// can distinguish them from FFI / DPAPI failures.
#[allow(unsafe_code)] // FFI to BCrypt
fn gen_random(out: &mut [u8]) -> Result<()> {
    // SAFETY: `out` is a unique writable slice; `BCryptGenRandom`
    // writes exactly `out.len()` bytes when the
    // `BCRYPT_USE_SYSTEM_PREFERRED_RNG` flag is set with a null
    // algorithm handle.
    let status = unsafe {
        BCryptGenRandom(
            windows::Win32::Security::Cryptography::BCRYPT_ALG_HANDLE::default(),
            out,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    status.ok().map_err(|e| Error::KeyOperation {
        operation: "meta_hmac_rng".into(),
        detail: format!("BCryptGenRandom: {e}"),
    })
}

/// DPAPI-encrypt with `CRYPTPROTECT_UI_FORBIDDEN`.
#[allow(unsafe_code)] // FFI to DPAPI
fn encrypt(plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(plaintext.len()).map_err(|_| Error::KeyOperation {
            operation: "meta_hmac_encrypt".into(),
            detail: "plaintext too large".into(),
        })?,
        pbData: plaintext.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB::default();

    // SAFETY: `input` lives for the duration of the call (slice
    // borrowed). `output` is uninitialized; on success DPAPI fills
    // it with a heap pointer we must `LocalFree`. On failure we
    // never read it. No optional-entropy / prompt struct passed.
    let result = unsafe {
        CryptProtectData(
            &input,
            windows::core::PCWSTR::null(),
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    // Drop the const-borrow projection; the input bytes outlive this.
    let _ = &mut input;

    result.map_err(|e| Error::KeyOperation {
        operation: "meta_hmac_encrypt".into(),
        detail: format!("CryptProtectData: {e}"),
    })?;

    copy_and_free_blob(&output)
}

/// DPAPI-decrypt. The blob must be a CryptProtectData output for
/// the current user. Errors propagate so the caller can distinguish
/// "profile changed / corrupt blob" from "no blob yet" (the latter
/// is handled at the file-IO layer in `load_existing`).
#[allow(unsafe_code)] // FFI to DPAPI
fn decrypt(blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(blob.len()).map_err(|_| Error::KeyOperation {
            operation: "meta_hmac_decrypt".into(),
            detail: "blob too large".into(),
        })?,
        pbData: blob.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB::default();

    // SAFETY: same shape as `encrypt`; `output` is filled by DPAPI
    // on success and we transfer ownership into a Vec we control.
    let result = unsafe {
        CryptUnprotectData(
            &input,
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    let _ = &mut input;

    result.map_err(|e| Error::KeyOperation {
        operation: "meta_hmac_decrypt".into(),
        detail: format!("CryptUnprotectData: {e}"),
    })?;

    let plaintext = copy_and_free_blob(&output)?;
    if plaintext.len() != META_HMAC_KEY_LEN {
        // Wipe the unexpected-length plaintext before returning the
        // error so we don't leak it through the failure path.
        let mut p = plaintext;
        p.zeroize();
        return Err(Error::KeyOperation {
            operation: "meta_hmac_decrypt".into(),
            detail: format!(
                "decrypted meta-HMAC key has unexpected length {}, expected {META_HMAC_KEY_LEN}",
                p.len()
            ),
        });
    }
    Ok(Zeroizing::new(plaintext))
}

/// Copy a DPAPI-allocated blob into a `Vec<u8>` and free the
/// LocalAlloc'd buffer. Always frees regardless of success/failure.
#[allow(unsafe_code)] // FFI: dereferences an opaque DPAPI pointer
fn copy_and_free_blob(blob: &CRYPT_INTEGER_BLOB) -> Result<Vec<u8>> {
    let len = blob.cbData as usize;
    if blob.pbData.is_null() || len == 0 {
        return Err(Error::KeyOperation {
            operation: "meta_hmac_blob_copy".into(),
            detail: "DPAPI returned an empty or null blob".into(),
        });
    }
    // SAFETY: DPAPI guarantees pbData is a valid pointer to cbData
    // bytes when the call succeeded; we copy into a Vec we own and
    // immediately LocalFree the original.
    let copied = unsafe { std::slice::from_raw_parts(blob.pbData, len).to_vec() };
    // SAFETY: pbData was allocated by DPAPI via LocalAlloc; the
    // documented free is LocalFree. HLOCAL is the windows-rs
    // newtype around the same pointer.
    let _ = unsafe { LocalFree(HLOCAL(blob.pbData.cast())) };
    Ok(copied)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, let_underscore_drop)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn unique_app() -> String {
        format!(
            "enclaveapp-windows-meta-hmac-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst),
        )
    }

    fn cleanup(app: &str) {
        let path = blob_path(app);
        let _ = std::fs::remove_file(&path);
        if let Some(parent) = path.parent() {
            let _ = std::fs::remove_dir(parent);
        }
    }

    #[test]
    fn blob_path_lives_under_data_dir() {
        let p = blob_path("sshenc");
        assert!(
            p.ends_with(format!("sshenc/{BLOB_FILENAME}"))
                || p.ends_with(format!("sshenc\\{BLOB_FILENAME}"))
        );
    }

    /// Round-trip through DPAPI on the real test runner. Stored under
    /// a unique app name so concurrent test runs don't collide. Skipped
    /// from default `cargo test` because it persists state in the
    /// user's roaming profile; CI's Windows matrix opts in via
    /// `--ignored`.
    #[test]
    #[ignore = "hits real DPAPI; run on the Windows matrix or locally"]
    fn store_load_delete_roundtrip() {
        let app = unique_app();
        cleanup(&app);
        let created = load_or_create(&app)
            .expect("create succeeds")
            .expect("created key is Some");
        assert_eq!(created.len(), META_HMAC_KEY_LEN);

        let loaded = load_or_create(&app)
            .expect("re-load succeeds")
            .expect("re-loaded key is Some");
        assert_eq!(&created[..], &loaded[..], "second load returns same bytes");

        delete(&app).expect("delete succeeds");
        let regenerated = load_or_create(&app)
            .expect("regen succeeds")
            .expect("regen key is Some");
        assert_ne!(
            &created[..],
            &regenerated[..],
            "regen after delete produces a different key"
        );
        cleanup(&app);
    }

    #[test]
    #[ignore = "hits real DPAPI; run on the Windows matrix or locally"]
    fn delete_is_idempotent_on_missing() {
        let app = unique_app();
        cleanup(&app);
        delete(&app).expect("delete on missing blob is Ok");
        delete(&app).expect("second delete is also Ok");
    }
}
