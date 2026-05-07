// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Key lifecycle operations shared between signing and encryption backends.
//!
//! Handles file storage (.handle, .pub, .meta), key listing, loading, and deletion.

use crate::ffi;
use enclaveapp_core::metadata::{self, KeyMeta};
use enclaveapp_core::types::{validate_label, KeyType};
use enclaveapp_core::{Error, Result};
use std::path::PathBuf;
use zeroize::Zeroizing;

const SE_ERR_BUFFER_TOO_SMALL: i32 = 4;

/// Configuration for keychain operations, scoped to an application.
#[derive(Debug)]
pub struct KeychainConfig {
    pub app_name: String,
    /// Optional override for the keys directory. If None, uses the standard
    /// platform path (~/.config/<app_name>/keys/ on Unix).
    pub keys_dir_override: Option<PathBuf>,
    /// When `true`, new wrapping-key entries are protected with
    /// `SecAccessControl(.userPresence)` instead of the legacy
    /// code-signature ACL. Access then requires Touch ID or the
    /// device passcode — but is tied to the user, not the binary's
    /// signature, so rebuilding an unsigned binary no longer
    /// invalidates access. Defaults to `false` for backward
    /// compatibility; callers opt in per-app.
    pub wrapping_key_user_presence: bool,
    /// How long a loaded wrapping key may be reused without another
    /// keychain round-trip (and, on user-presence items, another
    /// LocalAuthentication prompt). `Duration::ZERO` disables the
    /// cache entirely. Defaults to `ZERO` for backward compatibility.
    pub wrapping_key_cache_ttl: std::time::Duration,
    /// Data Protection keychain access group, in `<TEAMID>.<group>`
    /// form. When `Some`, wrapping-key items are stored in the modern
    /// Data Protection keychain (which actually accepts the
    /// `.userPresence` ACL). The calling binary MUST be codesigned
    /// with a `keychain-access-groups` entitlement listing the same
    /// group, otherwise SecItemAdd returns `errSecMissingEntitlement`
    /// and the bridge falls back to the legacy keychain (no
    /// userPresence gate). When `None` (default), the legacy keychain
    /// is used directly — which accepts unsigned callers but rejects
    /// the userPresence ACL with `errSecParam`.
    pub keychain_access_group: Option<String>,
}

impl KeychainConfig {
    pub fn new(app_name: &str) -> Self {
        KeychainConfig {
            app_name: app_name.to_string(),
            keys_dir_override: None,
            wrapping_key_user_presence: false,
            wrapping_key_cache_ttl: std::time::Duration::ZERO,
            keychain_access_group: None,
        }
    }

    /// Create a config with a custom keys directory path.
    pub fn with_keys_dir(app_name: &str, keys_dir: PathBuf) -> Self {
        KeychainConfig {
            app_name: app_name.to_string(),
            keys_dir_override: Some(keys_dir),
            wrapping_key_user_presence: false,
            wrapping_key_cache_ttl: std::time::Duration::ZERO,
            keychain_access_group: None,
        }
    }

    /// Return a new config with `wrapping_key_user_presence` set.
    #[must_use]
    pub fn with_user_presence(mut self, enabled: bool) -> Self {
        self.wrapping_key_user_presence = enabled;
        self
    }

    /// Return a new config with the wrapping-key cache TTL set.
    #[must_use]
    pub fn with_cache_ttl(mut self, ttl: std::time::Duration) -> Self {
        self.wrapping_key_cache_ttl = ttl;
        self
    }

    /// Return a new config that routes wrapping-key SecItemAdd through
    /// the Data Protection keychain under the given access group. See
    /// the [`Self::keychain_access_group`] field doc for entitlement
    /// requirements.
    #[must_use]
    pub fn with_access_group(mut self, group: impl Into<String>) -> Self {
        self.keychain_access_group = Some(group.into());
        self
    }

    pub fn keys_dir(&self) -> PathBuf {
        self.keys_dir_override
            .clone()
            .unwrap_or_else(|| metadata::keys_dir(&self.app_name))
    }
}

/// Check if the Secure Enclave is available.
#[allow(unsafe_code)] // FFI call to CryptoKit Swift bridge
pub fn is_available() -> bool {
    unsafe { ffi::enclaveapp_se_available() == 1 }
}

/// Generate a new Secure Enclave key.
/// Returns (uncompressed_public_key_65_bytes, data_representation).
#[allow(unsafe_code)] // FFI calls to CryptoKit Swift bridge
pub fn generate_key(key_type: KeyType, auth_policy: i32) -> Result<(Vec<u8>, Vec<u8>)> {
    if !is_available() {
        return Err(Error::NotAvailable);
    }

    match key_type {
        KeyType::Signing => {
            generate_key_with_retry(|pub_key, pub_key_len, data_rep, data_rep_len| unsafe {
                ffi::enclaveapp_se_generate_signing_key(
                    pub_key,
                    pub_key_len,
                    data_rep,
                    data_rep_len,
                    auth_policy,
                )
            })
        }
        KeyType::Encryption => {
            generate_key_with_retry(|pub_key, pub_key_len, data_rep, data_rep_len| unsafe {
                ffi::enclaveapp_se_generate_encryption_key(
                    pub_key,
                    pub_key_len,
                    data_rep,
                    data_rep_len,
                    auth_policy,
                )
            })
        }
    }
}

fn generate_key_with_retry<F>(mut generate_ffi: F) -> Result<(Vec<u8>, Vec<u8>)>
where
    F: FnMut(*mut u8, *mut i32, *mut u8, *mut i32) -> i32,
{
    /// Hard cap on resize retries. `SE_ERR_BUFFER_TOO_SMALL` is only
    /// ever legitimately raised by a genuine buffer-sizing shortfall,
    /// which converges in one retry with the Swift-reported length.
    /// Capping at 4 keeps a Swift-side contract bug (e.g. the FFI
    /// starts returning `SE_ERR_BUFFER_TOO_SMALL` for some other
    /// condition) from spinning forever; we surface it as a hard
    /// error the developer can see.
    const MAX_RESIZE_RETRIES: usize = 4;
    /// Uncompressed P-256 public key is always 65 bytes. We allocate
    /// exactly that size and never grow it. If the FFI reports
    /// `pub_key_len > 65`, something violated the contract — surface
    /// it explicitly rather than blindly resizing.
    const UNCOMPRESSED_P256_PUBKEY_LEN: usize = 65;

    let mut data_rep_capacity = 1024_usize;

    for _ in 0..MAX_RESIZE_RETRIES {
        let mut pub_key = vec![0_u8; UNCOMPRESSED_P256_PUBKEY_LEN];
        let mut pub_key_len: i32 = UNCOMPRESSED_P256_PUBKEY_LEN as i32;
        let mut data_rep = vec![0_u8; data_rep_capacity];
        let mut data_rep_len: i32 = data_rep_capacity as i32;

        let rc = generate_ffi(
            pub_key.as_mut_ptr(),
            &mut pub_key_len,
            data_rep.as_mut_ptr(),
            &mut data_rep_len,
        );

        if rc == SE_ERR_BUFFER_TOO_SMALL {
            // Swift's contract for this code: `*_len.pointee` now
            // holds the required size. Honor it only if it's
            // strictly greater than what we sent — otherwise the
            // return code is being used for something other than
            // "need more buffer space," which is a contract
            // violation we refuse to paper over with a retry.
            let returned = usize::try_from(data_rep_len).unwrap_or(0);
            if returned > data_rep_capacity {
                data_rep_capacity = returned;
                continue;
            }
            return Err(Error::GenerateFailed {
                detail: format!(
                    "FFI reported SE_ERR_BUFFER_TOO_SMALL but did not grow data_rep_len \
                     (sent {data_rep_capacity} bytes, got back {returned}) — \
                     Swift bridge contract violation"
                ),
            });
        }

        if rc != 0 {
            return Err(Error::GenerateFailed {
                detail: format!("FFI returned error code {rc}"),
            });
        }

        // Contract sanity: pub_key buffer is fixed at 65 bytes.
        let pub_key_len_usize = usize::try_from(pub_key_len).unwrap_or(0);
        if pub_key_len_usize > UNCOMPRESSED_P256_PUBKEY_LEN {
            return Err(Error::GenerateFailed {
                detail: format!(
                    "FFI reported pub_key_len = {pub_key_len_usize} but the buffer is \
                     fixed at {UNCOMPRESSED_P256_PUBKEY_LEN} bytes — Swift bridge contract violation"
                ),
            });
        }

        pub_key.truncate(pub_key_len_usize);
        let data_rep_len_usize = usize::try_from(data_rep_len).unwrap_or(0);
        data_rep.truncate(data_rep_len_usize);
        return Ok((pub_key, data_rep));
    }

    Err(Error::GenerateFailed {
        detail: format!(
            "Swift bridge repeatedly returned SE_ERR_BUFFER_TOO_SMALL after {MAX_RESIZE_RETRIES} \
             retries — contract violation"
        ),
    })
}

/// Generate a Secure Enclave key and persist its local metadata atomically.
///
/// The SE `dataRepresentation` handle is wrapped with AES-256-GCM under a
/// fresh 32-byte key stored in the macOS login keychain before being
/// written to `.handle` on disk. See [`crate::keychain_wrap`] for the
/// rationale and ciphertext format.
///
/// If any step after the SE key was created fails, the SE key is deleted
/// and the keychain wrapping-key entry is cleaned up so the label is
/// free to reuse.
pub fn generate_and_save_key(
    config: &KeychainConfig,
    label: &str,
    key_type: KeyType,
    policy: enclaveapp_core::AccessPolicy,
) -> Result<Vec<u8>> {
    validate_label(label)?;
    let dir = config.keys_dir();
    metadata::ensure_dir(&dir)?;
    let _lock = metadata::DirLock::acquire(&dir)?;
    prepare_label_for_save(&dir, label)?;

    let (pub_key, data_rep) = generate_key(key_type, policy.as_ffi_value())?;

    // Ask keychain_wrap to create the wrapping key, persist it, and
    // return the encrypted blob. The raw wrapping-key bytes stay
    // inside that module — we only see the wrapped output.
    let app_name = config.app_name.clone();
    let label_owned = label.to_string();
    let wrapped_blob = match crate::keychain_wrap::generate_and_wrap(
        &app_name,
        label,
        &data_rep,
        config.wrapping_key_user_presence,
        config.keychain_access_group.as_deref(),
    ) {
        Ok(blob) => blob,
        Err(error) => {
            // `generate_and_wrap` already removed any half-stored
            // keychain entry; just roll back the SE side.
            drop(delete_key_from_data_rep(&data_rep));
            return Err(error);
        }
    };

    let app_name_for_cleanup = app_name.clone();
    let access_group_for_cleanup = config.keychain_access_group.clone();
    // Keep a copy of `data_rep` for the post-persist rollback path.
    // The cleanup closure moves the original into the SE-delete FFI
    // call, so without this clone we'd need to round-trip back through
    // the keychain to unwrap the persisted handle just to delete the
    // SE key on a meta-tag failure.
    let data_rep_for_post_persist_rollback = data_rep.clone();
    let cleanup = move || {
        drop(crate::keychain_wrap::keychain_delete(
            &app_name_for_cleanup,
            &label_owned,
            access_group_for_cleanup.as_deref(),
        ));
        delete_key_from_data_rep(&data_rep)
    };
    persist_saved_key_material(
        &dir,
        label,
        key_type,
        policy,
        &wrapped_blob,
        &pub_key,
        cleanup,
    )?;

    // Now layer the meta-integrity tag onto the keychain. This is
    // the trust anchor for `<label>.meta` going forward — the on-disk
    // `<label>.meta.hmac` sidecar is a derivable cache, not the
    // authority. See `docs/design-meta-hmac-trust-anchor.md`.
    //
    // Two failure modes:
    //   - meta-HMAC key unavailable (Keychain locked, FFI failure):
    //     fail-open. Match pre-vN behavior. Key is usable but the
    //     verify path will report `KeychainUnavailable` until the
    //     Keychain comes back, at which point the user can run
    //     migrate-meta to bless the current state.
    //   - meta-HMAC key available but `meta_tag::store` fails: hard
    //     error. The key would be in `legacy_meta` state (refused by
    //     the agent at first op). Roll back the whole keygen so the
    //     user retries cleanly.
    let hmac_key_opt = crate::meta_hmac::load_or_create(&config.app_name)
        .ok()
        .flatten();
    if let Some(hk) = hmac_key_opt {
        let meta_path = dir.join(format!("{label}.meta"));
        let meta_bytes = match std::fs::read(&meta_path) {
            Ok(b) => b,
            Err(e) => {
                rollback_after_persist(
                    &dir,
                    label,
                    &config.app_name,
                    config.keychain_access_group.as_deref(),
                    &data_rep_for_post_persist_rollback,
                );
                return Err(Error::KeyOperation {
                    operation: "post_persist_meta_read".into(),
                    detail: format!("read {}: {e}", meta_path.display()),
                });
            }
        };
        let tag = metadata::compute_meta_hmac_bytes(hk.as_slice(), &meta_bytes);
        if let Err(e) = crate::meta_tag::store(&config.app_name, label, &tag) {
            rollback_after_persist(
                &dir,
                label,
                &config.app_name,
                config.keychain_access_group.as_deref(),
                &data_rep_for_post_persist_rollback,
            );
            return Err(e);
        }

        // On-disk sidecar (best-effort cache; verify uses the
        // keychain tag as authority and rebuilds this from the
        // keychain tag on demand).
        let hmac_path = dir.join(format!("{label}.meta.hmac"));
        let mut tag_hex = String::with_capacity(64);
        for byte in tag {
            tag_hex.push_str(&format!("{byte:02x}"));
        }
        if let Err(e) = metadata::atomic_write(&hmac_path, tag_hex.as_bytes()) {
            tracing::warn!(
                label = label,
                error = %e,
                "post-persist .meta.hmac sidecar write failed (best-effort cache; \
                 verify will rebuild from keychain tag)"
            );
        }
    } else {
        tracing::warn!(
            label = label,
            "meta-HMAC key unavailable at keygen; key persisted without integrity tag. \
             Run `<app> migrate-meta` once the Keychain is reachable."
        );
    }

    Ok(pub_key)
}

/// Run the per-op meta-integrity check against the keychain-stored
/// tag. Returns `Ok(())` on a clean verify, on a missing meta file
/// (`NoMeta` — caller's key-not-found flow handles it downstream),
/// and on `KeychainUnavailable` (fail-open; the wrapping-key load
/// will fail with its own clearer error if the keychain truly is
/// locked).
///
/// Returns `Err` on **tamper** (keychain tag exists but doesn't match
/// the on-disk meta) and on **legacy** (no keychain tag — this is
/// either a pre-migration key or an attacker-induced state). The
/// error messages describe the user's recovery path.
fn ensure_meta_integrity(app_name: &str, label: &str, dir: &std::path::Path) -> Result<()> {
    // CRITICAL: do not touch the platform Keychain unless an on-disk
    // `.meta` actually exists for this label. Without this guard,
    // every test that exercises load_handle / load_pub_key on a
    // synthetic dir without a `.meta` would call into
    // `meta_hmac::load_or_create` — which on macOS hits the legacy
    // Keychain. Each rebuild produces a binary with a different
    // ad-hoc signature, so the legacy-Keychain ACL prompts the user
    // to grant the new binary access to existing items. The result
    // is a string of password prompts during cargo test for the
    // unrelated `test-app` meta-HMAC entry. Mirrors the same guard
    // in `enclaveapp-app-storage::platform::verify_meta_integrity`.
    let meta_path = dir.join(format!("{label}.meta"));
    if !meta_path.exists() {
        return Ok(());
    }

    // Read-only lookup. We must NOT trigger a SecItemAdd here —
    // creation belongs on the keygen path. Without this distinction
    // a CI macOS runner's locked Keychain hangs the verify path
    // forever waiting on an approval dialog (delete_key /
    // load_handle tests would block on the implicit creation).
    let hmac_key = match crate::meta_hmac::load_existing(app_name) {
        Ok(Some(k)) => k,
        // No meta-HMAC key yet (fresh install before any keygen) or
        // Keychain unreachable. Fail-open: the wrapping-key load
        // downstream will produce its own clearer error if the
        // Keychain is truly locked, and on a fresh install
        // verification is genuinely a no-op (no keys to verify
        // against yet).
        Ok(None) | Err(_) => return Ok(()),
    };

    match crate::meta_tag::verify(app_name, label, dir, hmac_key.as_slice())? {
        crate::meta_tag::VerifyOutcome::Match
        | crate::meta_tag::VerifyOutcome::NoMeta
        | crate::meta_tag::VerifyOutcome::KeychainUnavailable => Ok(()),
        crate::meta_tag::VerifyOutcome::Tamper => Err(Error::KeyOperation {
            operation: "meta_tag_verify".into(),
            detail: format!(
                "key '{label}': metadata integrity check failed. The on-disk meta \
                 does not match the keychain-stored tag — meta may have been \
                 tampered with. Refusing to proceed. Regenerate the key to restore \
                 a known-good state."
            ),
        }),
        crate::meta_tag::VerifyOutcome::Legacy => {
            // Check whether `{app} migrate-meta` has already
            // completed on this install. If yes, this is the
            // strong-tamper-warning case (legitimate operation
            // should not produce a missing tag after marker is
            // set). If no, this is the one-time-cutover case.
            // Treat any Keychain-failure on the marker check as
            // "marker not set" (gentle variant) — we'd rather
            // produce a recoverable message than a screaming one
            // when the Keychain is genuinely flaky.
            let marker_set = crate::meta_migration_marker::is_set(app_name).unwrap_or(false);
            if marker_set {
                Err(Error::KeyOperation {
                    operation: "meta_tag_legacy_post_migration".into(),
                    detail: format!(
                        "key '{label}' has no integrity tag, but `{app_name} migrate-meta` \
                         has already completed on this install. This is a strong tamper \
                         signal — legitimate operation should not produce a missing tag \
                         after the marker is set. Recommended: regenerate the affected \
                         key with `{app_name} keygen`. Do NOT run migrate-meta again \
                         unless you can independently explain why this key's tag is \
                         missing (e.g., manual restore from a backup of an unrelated \
                         machine), in which case pass \
                         `--force-rerun-i-understand` to override."
                    ),
                })
            } else {
                Err(Error::KeyOperation {
                    operation: "meta_tag_legacy".into(),
                    detail: format!(
                        "key '{label}' has no integrity tag. This is the one-time \
                         migration required by upgrading to a build that introduces meta \
                         integrity tags, and is not something future upgrades will repeat. \
                         Before migrating, verify the key's current policy looks correct: \
                         `{app_name} inspect {label}`. To migrate: `{app_name} \
                         migrate-meta`."
                    ),
                })
            }
        }
    }
}

/// Roll back a half-completed keygen *after* persist_saved_key_material
/// has succeeded, when a subsequent step (meta-tag write) failed.
///
/// Order matters: SE key delete needs the data_rep we kept from
/// pre-wrap, before files are removed. Each step is best-effort; we
/// log warnings and continue so partial cleanup doesn't strand resources.
fn rollback_after_persist(
    dir: &std::path::Path,
    label: &str,
    app_name: &str,
    access_group: Option<&str>,
    data_rep: &[u8],
) {
    if let Err(e) = crate::meta_tag::delete(app_name, label) {
        tracing::warn!(label = label, error = %e, "rollback: meta_tag::delete failed");
    }
    if let Err(e) = cleanup_persisted_key_material(dir, label) {
        tracing::warn!(label = label, error = %e, "rollback: file cleanup failed");
    }
    if let Err(e) = crate::keychain_wrap::keychain_delete(app_name, label, access_group) {
        tracing::warn!(label = label, error = %e, "rollback: wrapping-key delete failed");
    }
    if let Err(e) = delete_key_from_data_rep(data_rep) {
        tracing::warn!(label = label, error = %e, "rollback: SE key delete failed");
    }
}

/// Extract the public key from a persisted data representation.
/// Returns 65-byte uncompressed public key.
#[allow(unsafe_code)] // FFI calls to CryptoKit Swift bridge
pub fn public_key_from_data_rep(key_type: KeyType, data_rep: &[u8]) -> Result<Vec<u8>> {
    let mut pub_key = vec![0_u8; 65];
    let mut pub_key_len: i32 = 65;

    let rc = match key_type {
        KeyType::Signing => unsafe {
            ffi::enclaveapp_se_signing_public_key(
                data_rep.as_ptr(),
                data_rep.len() as i32,
                pub_key.as_mut_ptr(),
                &mut pub_key_len,
            )
        },
        KeyType::Encryption => unsafe {
            ffi::enclaveapp_se_encryption_public_key(
                data_rep.as_ptr(),
                data_rep.len() as i32,
                pub_key.as_mut_ptr(),
                &mut pub_key_len,
            )
        },
    };

    if rc != 0 {
        return Err(Error::KeyOperation {
            operation: "public_key".into(),
            detail: format!("FFI returned error code {rc}"),
        });
    }

    pub_key.truncate(pub_key_len as usize);
    Ok(pub_key)
}

/// Save a key's data representation, public key, and metadata to the keys directory.
#[cfg_attr(not(test), allow(dead_code))]
fn save_key(
    config: &KeychainConfig,
    label: &str,
    key_type: KeyType,
    policy: enclaveapp_core::AccessPolicy,
    data_rep: &[u8],
    pub_key: &[u8],
) -> Result<()> {
    validate_label(label)?;
    let dir = config.keys_dir();
    metadata::ensure_dir(&dir)?;

    let _lock = metadata::DirLock::acquire(&dir)?;
    prepare_label_for_save(&dir, label)?;

    persist_saved_key_material(&dir, label, key_type, policy, data_rep, pub_key, || {
        delete_key_from_data_rep(data_rep)
    })
}

/// Rename a key from `old_label` to `new_label`, preserving both on-disk
/// metadata and the macOS keychain wrapping-key entry.
///
/// Failure modes handled atomically where possible:
///   - Missing source: returns `KeyNotFound`.
///   - Target already exists on disk or in keychain: returns `DuplicateLabel`.
///   - Disk rename fails: keychain untouched.
///   - Keychain store of new entry fails: disk files rolled back.
///   - Keychain delete of old entry fails: logged as warning (a harmless
///     dangling keychain entry; the new entry is consistent).
pub fn rename_key(config: &KeychainConfig, old_label: &str, new_label: &str) -> Result<()> {
    validate_label(old_label)?;
    validate_label(new_label)?;
    if old_label == new_label {
        return Ok(());
    }

    let dir = config.keys_dir();
    let _lock = metadata::DirLock::acquire(&dir)?;

    // Don't touch the platform Keychain (meta-HMAC key lookup) until
    // we know the source key actually exists on disk. Without this
    // pre-check, a `rename` against a missing label still hits the
    // legacy Keychain and fires an ACL prompt on first call from a
    // test binary or rebuilt unsigned dev binary.
    let old_handle = dir.join(format!("{old_label}.handle"));
    let old_meta = dir.join(format!("{old_label}.meta"));
    if !old_handle.exists() && !old_meta.exists() {
        return Err(Error::KeyNotFound {
            label: old_label.to_string(),
        });
    }

    // Pull the per-app meta-HMAC key once so the file rename can
    // recompute the `.meta.hmac` sidecar under the new label, and so
    // we can re-stamp the keychain meta-tag below. None when the
    // Keychain is unreachable — sidecar/tag work is skipped, matching
    // pre-vN behavior. The agent's verify path will treat the result
    // as `Legacy` until the next migrate-meta run.
    let hmac_key_opt = crate::meta_hmac::load_or_create(&config.app_name)
        .ok()
        .flatten();

    // Disk rename first — cheap to roll back and doesn't touch the
    // keychain. If this fails the keychain is untouched. Pass the
    // meta-HMAC key so the sidecar is recomputed against the
    // rewritten meta JSON; without it `rename_key_files` would error
    // out if a sidecar is present (and it always is post-vN keygen).
    metadata::rename_key_files(
        &dir,
        old_label,
        new_label,
        hmac_key_opt.as_ref().map(|z| z.as_slice()),
    )?;

    // Move the wrapping-key entry via the oracle API. The raw key
    // bytes never escape `keychain_wrap`. On failure, roll back the
    // disk rename so we don't leave a handle file whose wrapping key
    // is unreachable.
    if let Err(error) = crate::keychain_wrap::relabel_wrapping_key(
        &config.app_name,
        old_label,
        new_label,
        config.wrapping_key_user_presence,
        config.keychain_access_group.as_deref(),
    ) {
        let rollback = metadata::rename_key_files(
            &dir,
            new_label,
            old_label,
            hmac_key_opt.as_ref().map(|z| z.as_slice()),
        );
        if let Err(rollback_err) = rollback {
            tracing::error!(
                "rename_key: relabel_wrapping_key failed ({error}) and disk rollback ALSO failed \
                 ({rollback_err}); key material may be in an inconsistent state"
            );
        }
        return Err(error);
    }

    // Move the keychain meta-tag entry to the new label. The tag is
    // recomputed against the rewritten meta JSON (which now embeds
    // `new_label`). Failure here is logged and surfaced as an error;
    // the user re-runs `<app> migrate-meta` to re-tag if needed.
    if let Some(hk) = hmac_key_opt {
        let new_meta_path = dir.join(format!("{new_label}.meta"));
        if let Ok(meta_bytes) = std::fs::read(&new_meta_path) {
            let tag = metadata::compute_meta_hmac_bytes(hk.as_slice(), &meta_bytes);
            if let Err(e) = crate::meta_tag::store(&config.app_name, new_label, &tag) {
                tracing::error!(
                    old_label = old_label,
                    new_label = new_label,
                    error = %e,
                    "rename_key: meta_tag store under new label failed; \
                     run `<app> migrate-meta` to restore the integrity tag"
                );
                return Err(e);
            }
        }
        // Best-effort cleanup of the old-label tag. If this fails the
        // orphan is harmless (no on-disk meta to verify against).
        if let Err(e) = crate::meta_tag::delete(&config.app_name, old_label) {
            tracing::warn!(
                old_label = old_label,
                error = %e,
                "rename_key: stale meta-tag for old label could not be deleted (harmless orphan)"
            );
        }
    }

    Ok(())
}

/// Load a key's data representation from the keys directory.
///
/// The `.handle` file may be either a wrapped blob (magic prefix `EHW1`)
/// or a legacy plaintext CryptoKit `dataRepresentation`. Wrapped blobs
/// are decrypted with the wrapping key loaded from the login keychain;
/// legacy plaintext blobs are returned unchanged for transparent
/// migration — they'll be re-wrapped the next time `generate_and_save_key`
/// replaces the label.
pub fn load_handle(config: &KeychainConfig, label: &str) -> Result<Zeroizing<Vec<u8>>> {
    load_handle_with_context(config, label, 0)
}

/// Variant of [`load_handle`] that threads a registered `LAContext`
/// token into the wrapping-key keychain query so a previously-
/// authenticated context covers the keychain decrypt without an
/// independent biometric prompt. Pass token `0` for the legacy
/// "no context, prompt independently if userPresence-protected"
/// behaviour. Used by the sign path so a single `evaluatePolicy`
/// covers both the keychain decrypt and the SE sign that follows.
///
/// The returned data-representation handle is wrapped in
/// [`Zeroizing`] so its plaintext bytes are wiped on drop. The
/// `data_rep` is the SE-key reference that lets a caller derive
/// the public key, sign, encrypt, decrypt, or delete the key — it
/// is not the raw private-key bytes (those never leave the SEP),
/// but it is sensitive enough that we don't want copies lingering
/// in the heap allocator's freelist.
pub fn load_handle_with_context(
    config: &KeychainConfig,
    label: &str,
    lacontext_token: u64,
) -> Result<Zeroizing<Vec<u8>>> {
    validate_label(label)?;
    let dir = config.keys_dir();

    // Verify meta integrity before unwrapping the handle. This is the
    // per-op trust-anchor check: keychain-stored tag must match the
    // on-disk `.meta`. Tamper or legacy-meta states refuse the
    // operation here, before the wrapping key is loaded — so the
    // user never burns a Touch ID on a key whose policy fields have
    // been edited.
    ensure_meta_integrity(&config.app_name, label, &dir)?;

    let path = dir.join(format!("{label}.handle"));
    if !path.exists() {
        return Err(Error::KeyNotFound {
            label: label.to_string(),
        });
    }
    let contents = metadata::read_no_follow(&path)?;

    if !crate::keychain_wrap::is_wrapped_handle(&contents) {
        // Legacy plaintext handle (pre-EHW1). Return as-is; the caller
        // can sign/decrypt directly, and the next rotation picks up
        // the wrapping. Logged for visibility.
        tracing::debug!(
            label = label,
            "loaded legacy plaintext SE handle; re-save to upgrade to wrapped format"
        );
        return Ok(Zeroizing::new(contents));
    }

    match crate::keychain_wrap::decrypt_with_cached_key(
        &config.app_name,
        label,
        &contents,
        config.wrapping_key_cache_ttl,
        config.keychain_access_group.as_deref(),
        lacontext_token,
    )? {
        Some(plaintext) => Ok(Zeroizing::new(plaintext)),
        None => Err(Error::KeyOperation {
            operation: "load_handle".into(),
            detail: format!(
                "wrapped handle for label `{label}` is missing its keychain wrapping key; \
                 the keychain entry may have been deleted or the user denied access"
            ),
        }),
    }
}

/// Load the cached public key for a label. Falls back to extracting from data rep.
pub fn load_pub_key(config: &KeychainConfig, label: &str, key_type: KeyType) -> Result<Vec<u8>> {
    validate_label(label)?;
    let dir = config.keys_dir();

    // Verify meta integrity before returning anything for this label.
    // The `.pub` cache is fast-path data, but we don't want a tampered
    // `.meta` to be silently consumed downstream (e.g., a CLI showing
    // "presence_mode: none" when the user expects strict). The verify
    // surfaces the policy-tamper before the public key is returned.
    ensure_meta_integrity(&config.app_name, label, &dir)?;

    // Fast path: the `.pub` file is written at key-creation time by
    // `persist_saved_key_material` and re-synced after any successful
    // handle decrypt, so for every well-formed key it holds the
    // authoritative public key bytes. Reading it here avoids a
    // `load_handle` round-trip, which on user-presence-protected
    // wrapping keys is a LocalAuthentication prompt. Public keys are
    // public — there's no reason to gate reading them on biometric.
    //
    // Anything that looks even slightly off (missing file, wrong
    // length, not a valid P-256 SEC1 point) falls through to the slow
    // authoritative path so a tampered or truncated cache can't
    // produce an invalid public key.
    if let Ok(pub_key) = metadata::load_pub_key(&dir, label) {
        if enclaveapp_core::types::validate_p256_point(&pub_key).is_ok() {
            return Ok(pub_key);
        }
    }

    // Slow authoritative path: decrypt the handle (may prompt) and
    // re-sync the `.pub` cache so subsequent calls hit the fast path.
    let data_rep = load_handle(config, label)?;
    let pub_key = public_key_from_data_rep(key_type, &data_rep)?;
    metadata::sync_pub_key(&dir, label, &pub_key)
}

/// List all key labels in the keys directory.
pub fn list_labels(config: &KeychainConfig) -> Result<Vec<String>> {
    metadata::list_labels_for_extensions(&config.keys_dir(), &["meta", "handle"])
}

/// Delete a key and all associated files.
///
/// Also removes the key's wrapping-key entry from the login keychain.
/// The keychain removal is best-effort — if it fails for any reason
/// other than "not found" the overall delete still proceeds so the
/// on-disk state isn't left half-cleaned. A leftover keychain entry
/// is harmless if the `.handle` file is gone (no one can use it).
pub fn delete_key(config: &KeychainConfig, label: &str) -> Result<()> {
    validate_label(label)?;
    let dir = config.keys_dir();
    let handle_path = dir.join(format!("{label}.handle"));
    let key_exists =
        dir.exists() && (handle_path.exists() || metadata::key_files_exist(&dir, label)?);
    if !key_exists {
        return Err(Error::KeyNotFound {
            label: label.to_string(),
        });
    }
    let _lock = metadata::DirLock::acquire(&dir)?;
    let result = match load_handle(config, label) {
        Ok(data_rep) => {
            delete_key_from_data_rep(&data_rep).map_err(|error| Error::KeyOperation {
                operation: "delete_key".into(),
                detail: format!("delete Secure Enclave key: {error}"),
            })?;
            metadata::delete_key_files(&dir, label)
        }
        Err(Error::KeyNotFound { .. }) => metadata::delete_key_files(&dir, label),
        Err(error) => Err(Error::KeyOperation {
            operation: "delete_key".into(),
            detail: format!(
                "failed to read Secure Enclave handle; preserving local key material for retry: {error}"
            ),
        }),
    };

    // Clean up the keychain wrapping-key entry regardless of whether
    // the local files were fully removed. If it fails here, log but
    // don't propagate — a stale keychain entry without its handle is
    // useless.
    if let Err(error) = crate::keychain_wrap::keychain_delete(
        &config.app_name,
        label,
        config.keychain_access_group.as_deref(),
    ) {
        tracing::warn!(
            label = label,
            "keychain_delete failed during delete_key (harmless if the handle is already gone): {error}"
        );
    }

    // And the per-key meta-integrity tag. Same best-effort treatment:
    // an orphan tag entry without its meta file can't be used by
    // anything (verify keys off the meta presence on disk).
    if let Err(error) = crate::meta_tag::delete(&config.app_name, label) {
        tracing::warn!(
            label = label,
            "meta_tag::delete failed during delete_key (harmless orphan if the meta is already gone): {error}"
        );
    }

    result
}

#[allow(unsafe_code)] // FFI call to CryptoKit Swift bridge
fn delete_key_from_data_rep(data_rep: &[u8]) -> Result<()> {
    let rc = unsafe { ffi::enclaveapp_se_delete_key(data_rep.as_ptr(), data_rep.len() as i32) };
    if rc == 0 {
        Ok(())
    } else {
        Err(Error::KeyOperation {
            operation: "delete_key".into(),
            detail: format!("FFI returned error code {rc}"),
        })
    }
}

fn persist_saved_key_material<F>(
    dir: &std::path::Path,
    label: &str,
    key_type: KeyType,
    policy: enclaveapp_core::AccessPolicy,
    data_rep: &[u8],
    pub_key: &[u8],
    cleanup_created_key: F,
) -> Result<()>
where
    F: FnOnce() -> Result<()>,
{
    let handle_path = dir.join(format!("{label}.handle"));

    if let Err(error) = metadata::atomic_write(&handle_path, data_rep) {
        return Err(with_cleanup_context(
            "persist handle",
            error,
            dir,
            label,
            cleanup_created_key,
        ));
    }
    if let Err(error) = metadata::restrict_file_permissions(&handle_path) {
        return Err(with_cleanup_context(
            "persist handle permissions",
            error,
            dir,
            label,
            cleanup_created_key,
        ));
    }
    if let Err(error) = metadata::save_pub_key(dir, label, pub_key) {
        return Err(with_cleanup_context(
            "persist public key cache",
            error,
            dir,
            label,
            cleanup_created_key,
        ));
    }

    let meta = KeyMeta::new(label, key_type, policy);
    // Plain meta write only. The HMAC sidecar is layered on top
    // by the higher-level `generate_and_save_key` after persist
    // returns — that keeps `persist_saved_key_material` free of
    // any Keychain dependency so tests of this helper don't drag
    // the platform meta-HMAC store into a real Keychain access.
    if let Err(error) = metadata::save_meta(dir, label, &meta) {
        return Err(with_cleanup_context(
            "persist metadata",
            error,
            dir,
            label,
            cleanup_created_key,
        ));
    }

    Ok(())
}

fn prepare_label_for_save(dir: &std::path::Path, label: &str) -> Result<()> {
    let handle_path = dir.join(format!("{label}.handle"));
    let other_files_exist = metadata::key_files_exist(dir, label)?;
    if !handle_path.exists() && !other_files_exist {
        return Ok(());
    }

    if !handle_path.exists() {
        return metadata::delete_key_files(dir, label);
    }

    let data_rep = metadata::read_no_follow(&handle_path).map_err(|error| Error::KeyOperation {
        operation: "prepare_label_for_save".into(),
        detail: format!("failed to read existing Secure Enclave handle: {error}"),
    })?;

    if public_key_from_data_rep(KeyType::Signing, &data_rep).is_ok()
        || public_key_from_data_rep(KeyType::Encryption, &data_rep).is_ok()
    {
        return Err(Error::DuplicateLabel {
            label: label.to_string(),
        });
    }

    delete_key_from_data_rep(&data_rep).map_err(|error| Error::KeyOperation {
        operation: "prepare_label_for_save".into(),
        detail: format!(
            "failed to delete existing Secure Enclave key before reusing label: {error}"
        ),
    })?;

    metadata::delete_key_files(dir, label)
}

fn cleanup_persisted_key_material(dir: &std::path::Path, label: &str) -> Result<()> {
    for extension in ["handle", "pub", "meta", "meta.hmac", "ssh.pub"] {
        let path = dir.join(format!("{label}.{extension}"));
        if path.is_file() {
            std::fs::remove_file(path)?;
        }
    }
    Ok(())
}

fn with_cleanup_context<F>(
    operation: &str,
    error: Error,
    dir: &std::path::Path,
    label: &str,
    cleanup_created_key: F,
) -> Error
where
    F: FnOnce() -> Result<()>,
{
    let mut cleanup_failures = Vec::new();

    if let Err(cleanup_error) = cleanup_persisted_key_material(dir, label) {
        cleanup_failures.push(format!("remove persisted key files: {cleanup_error}"));
    }
    if let Err(cleanup_error) = cleanup_created_key() {
        cleanup_failures.push(format!("delete Secure Enclave key: {cleanup_error}"));
    }

    if cleanup_failures.is_empty() {
        error
    } else {
        Error::GenerateFailed {
            detail: format!(
                "{operation} failed: {error}; cleanup failed: {}",
                cleanup_failures.join("; ")
            ),
        }
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn keychain_config_new_sets_app_name() {
        let config = KeychainConfig::new("sshenc");
        assert_eq!(config.app_name, "sshenc");
        assert!(config.keys_dir_override.is_none());
    }

    #[test]
    fn keychain_config_new_different_app_name() {
        let config = KeychainConfig::new("awsenc");
        assert_eq!(config.app_name, "awsenc");
    }

    #[test]
    #[allow(unsafe_code)]
    fn generate_key_with_retry_resizes_data_rep_buffer() {
        let mut attempts = 0;
        let (pub_key, data_rep) =
            generate_key_with_retry(|pub_key, pub_key_len, data_rep, data_rep_len| {
                attempts += 1;
                if attempts == 1 {
                    unsafe {
                        *data_rep_len = 2048;
                    }
                    return SE_ERR_BUFFER_TOO_SMALL;
                }

                unsafe {
                    *pub_key_len = 65;
                    *data_rep_len = 2048;
                    std::ptr::write_bytes(pub_key, 0x04, 65);
                    std::ptr::write_bytes(data_rep, 0xAB, 2048);
                }
                0
            })
            .unwrap();

        assert_eq!(attempts, 2);
        assert_eq!(pub_key.len(), 65);
        assert_eq!(data_rep.len(), 2048);
        assert!(data_rep.iter().all(|byte| *byte == 0xAB));
    }

    #[test]
    fn keychain_config_with_keys_dir_overrides_path() {
        let custom = PathBuf::from("/tmp/custom-keys");
        let config = KeychainConfig::with_keys_dir("sshenc", custom.clone());
        assert_eq!(config.app_name, "sshenc");
        assert_eq!(config.keys_dir_override, Some(custom));
    }

    #[test]
    fn keys_dir_returns_default_when_no_override() {
        let config = KeychainConfig::new("test-app");
        let dir = config.keys_dir();
        // Should use the platform default from metadata::keys_dir
        let expected = metadata::keys_dir("test-app");
        assert_eq!(dir, expected);
    }

    #[test]
    fn keys_dir_returns_override_when_set() {
        let custom = PathBuf::from("/tmp/my-custom-keys");
        let config = KeychainConfig::with_keys_dir("test-app", custom.clone());
        assert_eq!(config.keys_dir(), custom);
    }

    #[test]
    fn delete_missing_key_in_missing_dir_returns_key_not_found() {
        let dir =
            std::env::temp_dir().join(format!("enclaveapp-apple-missing-{}", std::process::id()));
        drop(std::fs::remove_dir_all(&dir));
        let config = KeychainConfig::with_keys_dir("test-app", dir);
        let err = delete_key(&config, "ghost").unwrap_err();
        match err {
            Error::KeyNotFound { label } => assert_eq!(label, "ghost"),
            other => panic!("expected KeyNotFound, got {other}"),
        }
    }

    #[test]
    fn keychain_operations_reject_invalid_labels() {
        let dir =
            std::env::temp_dir().join(format!("enclaveapp-apple-invalid-{}", std::process::id()));
        drop(std::fs::remove_dir_all(&dir));
        let config = KeychainConfig::with_keys_dir("test-app", dir);

        let err = load_handle(&config, "../escape").unwrap_err();
        assert!(matches!(err, Error::InvalidLabel { .. }));

        let err = load_pub_key(&config, "../escape", KeyType::Signing).unwrap_err();
        assert!(matches!(err, Error::InvalidLabel { .. }));

        let err = delete_key(&config, "../escape").unwrap_err();
        assert!(matches!(err, Error::InvalidLabel { .. }));
    }

    #[test]
    fn save_key_rejects_invalid_labels() {
        let dir = std::env::temp_dir().join(format!(
            "enclaveapp-apple-save-invalid-{}",
            std::process::id()
        ));
        drop(std::fs::remove_dir_all(&dir));
        let config = KeychainConfig::with_keys_dir("test-app", dir);

        let err = save_key(
            &config,
            "../escape",
            KeyType::Signing,
            enclaveapp_core::AccessPolicy::None,
            b"handle",
            b"pub",
        )
        .unwrap_err();
        assert!(matches!(err, Error::InvalidLabel { .. }));
    }

    #[test]
    fn save_key_recovers_stale_metadata_artifacts() {
        let dir = std::env::temp_dir().join(format!(
            "enclaveapp-apple-duplicate-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        drop(std::fs::remove_dir_all(&dir));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("existing.pub"), b"pub").unwrap();

        let config = KeychainConfig::with_keys_dir("test-app", dir.clone());
        save_key(
            &config,
            "existing",
            KeyType::Signing,
            enclaveapp_core::AccessPolicy::None,
            b"handle",
            &[0x04; 65],
        )
        .unwrap();
        assert!(dir.join("existing.handle").exists());
        assert!(dir.join("existing.pub").exists());
        assert!(dir.join("existing.meta").exists());

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn persist_saved_key_material_cleans_up_files_and_invokes_key_cleanup() {
        let dir = std::env::temp_dir().join(format!(
            "enclaveapp-apple-persist-cleanup-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        drop(std::fs::remove_dir_all(&dir));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::create_dir(dir.join("work.meta")).unwrap();

        let mut cleaned_up = false;
        let err = persist_saved_key_material(
            &dir,
            "work",
            KeyType::Signing,
            enclaveapp_core::AccessPolicy::None,
            b"handle",
            &[0x04; 65],
            || {
                cleaned_up = true;
                Ok(())
            },
        )
        .unwrap_err();

        assert!(matches!(err, Error::Io(_) | Error::GenerateFailed { .. }));
        assert!(
            cleaned_up,
            "generated Secure Enclave key should be cleaned up"
        );
        assert!(!dir.join("work.handle").exists());
        assert!(!dir.join("work.pub").exists());
        assert!(dir.join("work.meta").is_dir());

        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Ignored: this test fixture writes a real `.meta` file before
    /// calling `delete_key`. With the trust-anchor changes,
    /// `delete_key` now goes through `load_handle` →
    /// `ensure_meta_integrity` → FFI keychain access. CI macOS
    /// runners' keychains hang the SecItem call waiting for an
    /// approval dialog nobody can dismiss, blowing the 6-hour test
    /// timeout. The behavior covered here (delete_key preserves
    /// files when the handle is unreadable) is verified by manual
    /// QA on a logged-in dev machine; the file-preservation logic
    /// itself lives in `cleanup_persisted_key_material` which is
    /// platform-agnostic and exercised by `persist_saved_key_material_cleans_up_files_and_invokes_key_cleanup`.
    #[test]
    #[ignore = "writes .meta + hits real Keychain via load_handle; CI hang"]
    fn delete_key_preserves_files_when_handle_cannot_be_read() {
        let dir = std::env::temp_dir().join(format!(
            "enclaveapp-apple-delete-corrupt-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        drop(std::fs::remove_dir_all(&dir));
        std::fs::create_dir_all(&dir).unwrap();
        let handle_path = dir.join("work.handle");
        std::fs::write(&handle_path, b"handle").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&handle_path, std::fs::Permissions::from_mode(0o000)).unwrap();
        }
        metadata::save_pub_key(&dir, "work", &[0x04; 65]).unwrap();
        metadata::save_meta(
            &dir,
            "work",
            &KeyMeta::new(
                "work",
                KeyType::Signing,
                enclaveapp_core::AccessPolicy::None,
            ),
        )
        .unwrap();

        let config = KeychainConfig::with_keys_dir("test-app", dir.clone());
        let err = delete_key(&config, "work").unwrap_err();
        assert!(matches!(err, Error::KeyOperation { .. }));
        assert!(dir.join("work.handle").exists());
        assert!(dir.join("work.pub").exists());
        assert!(dir.join("work.meta").exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&handle_path, std::fs::Permissions::from_mode(0o600)).ok();
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn list_labels_includes_handle_without_metadata() {
        let dir = std::env::temp_dir().join(format!(
            "enclaveapp-apple-list-live-handle-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        drop(std::fs::remove_dir_all(&dir));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("alpha.handle"), b"handle").unwrap();
        std::fs::write(dir.join("beta.meta"), b"{}").unwrap();

        let config = KeychainConfig::with_keys_dir("test-app", dir.clone());
        assert_eq!(list_labels(&config).unwrap(), vec!["alpha", "beta"]);

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn load_pub_key_returns_cached_pub_without_touching_handle() {
        // Fast path: a format-valid `.pub` cache is authoritative.
        // The handle here is intentionally bogus — if `load_pub_key`
        // touched it, the call would fail. Success proves the cache
        // short-circuits the slow path (and, on real hardware, the
        // biometric prompt it would trigger).
        let dir = std::env::temp_dir().join(format!(
            "enclaveapp-apple-load-pub-cached-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        drop(std::fs::remove_dir_all(&dir));
        std::fs::create_dir_all(&dir).unwrap();

        let config = KeychainConfig::with_keys_dir("test-app", dir.clone());
        let cached_pub = [0x04_u8; 65];
        metadata::save_pub_key(&dir, "cached", &cached_pub).unwrap();
        metadata::atomic_write(&dir.join("cached.handle"), &[0_u8; 32]).unwrap();

        let got = load_pub_key(&config, "cached", KeyType::Signing).unwrap();
        assert_eq!(got, cached_pub);

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn load_pub_key_falls_through_when_cached_pub_is_malformed() {
        // Wrong SEC1 prefix (0x05 instead of 0x04) fails format
        // validation, so the fast path rejects the cache and the slow
        // path decrypts the handle. With a bogus handle here, the
        // slow path errors — proving the fast path did fall through.
        let dir = std::env::temp_dir().join(format!(
            "enclaveapp-apple-load-pub-malformed-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        drop(std::fs::remove_dir_all(&dir));
        std::fs::create_dir_all(&dir).unwrap();

        let config = KeychainConfig::with_keys_dir("test-app", dir.clone());
        metadata::save_pub_key(&dir, "cached", &[0x05; 65]).unwrap();
        metadata::atomic_write(&dir.join("cached.handle"), &[0_u8; 32]).unwrap();

        let err = load_pub_key(&config, "cached", KeyType::Signing).unwrap_err();
        assert!(matches!(err, Error::KeyOperation { .. }));

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn load_pub_key_falls_through_when_cached_pub_is_missing() {
        // No `.pub` cache at all, so the fast path can't trigger.
        // Slow path decrypts the (bogus) handle and errors.
        let dir = std::env::temp_dir().join(format!(
            "enclaveapp-apple-load-pub-missing-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        drop(std::fs::remove_dir_all(&dir));
        std::fs::create_dir_all(&dir).unwrap();

        let config = KeychainConfig::with_keys_dir("test-app", dir.clone());
        metadata::atomic_write(&dir.join("cached.handle"), &[0_u8; 32]).unwrap();

        let err = load_pub_key(&config, "cached", KeyType::Signing).unwrap_err();
        assert!(matches!(err, Error::KeyOperation { .. }));

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn save_key_preserves_unreadable_handle_and_reports_error() {
        let dir = std::env::temp_dir().join(format!(
            "enclaveapp-apple-save-unreadable-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        drop(std::fs::remove_dir_all(&dir));
        std::fs::create_dir_all(&dir).unwrap();
        let handle_path = dir.join("existing.handle");
        std::fs::write(&handle_path, b"handle").unwrap();
        metadata::save_pub_key(&dir, "existing", &[0x04; 65]).unwrap();
        metadata::save_meta(
            &dir,
            "existing",
            &KeyMeta::new(
                "existing",
                KeyType::Signing,
                enclaveapp_core::AccessPolicy::None,
            ),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&handle_path, std::fs::Permissions::from_mode(0o000)).unwrap();
        }

        let config = KeychainConfig::with_keys_dir("test-app", dir.clone());
        let err = save_key(
            &config,
            "existing",
            KeyType::Signing,
            enclaveapp_core::AccessPolicy::None,
            b"new-handle",
            &[0x04; 65],
        )
        .unwrap_err();
        assert!(matches!(err, Error::KeyOperation { .. }));
        assert!(dir.join("existing.handle").exists());
        assert!(dir.join("existing.pub").exists());
        assert!(dir.join("existing.meta").exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&handle_path, std::fs::Permissions::from_mode(0o600)).ok();
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}
