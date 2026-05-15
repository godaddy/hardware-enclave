// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Key metadata and file operations for hardware-backed key management.

use crate::error::{Error, Result};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Metadata stored alongside a hardware-bound key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMeta {
    /// Key label (unique identifier within the app).
    pub label: String,
    /// Type of key (signing or encryption). Defaults to Signing for backward
    /// compatibility with metadata files created before this field existed.
    #[serde(default)]
    pub key_type: crate::KeyType,
    /// Access control policy.
    #[serde(default)]
    pub access_policy: crate::AccessPolicy,
    /// Unix timestamp when the key was created.
    #[serde(default)]
    pub created: String,
    /// Application-specific extra fields (e.g., git_name, git_email for sshenc;
    /// profile name for awsenc; server/env for sso-jwt).
    #[serde(default)]
    pub app_specific: serde_json::Value,
}

impl KeyMeta {
    /// Create a new KeyMeta with the current timestamp.
    pub fn new(label: &str, key_type: crate::KeyType, access_policy: crate::AccessPolicy) -> Self {
        let created = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .to_string();
        KeyMeta {
            label: label.to_string(),
            key_type,
            access_policy,
            created,
            app_specific: serde_json::Value::Null,
        }
    }

    /// Set an app-specific field.
    pub fn set_app_field(&mut self, key: &str, value: impl Into<serde_json::Value>) {
        if self.app_specific.is_null() {
            self.app_specific = serde_json::Value::Object(serde_json::Map::new());
        }
        if let Some(obj) = self.app_specific.as_object_mut() {
            obj.insert(key.to_string(), value.into());
        }
    }

    /// Get an app-specific string field.
    pub fn get_app_field(&self, key: &str) -> Option<&str> {
        self.app_specific.get(key)?.as_str()
    }
}

/// Standard keys directory for an application.
/// - Unix: `~/.config/<app_name>/keys/`
/// - Windows: `%APPDATA%/<app_name>/keys/`
pub fn keys_dir(app_name: &str) -> PathBuf {
    config_dir(app_name).join("keys")
}

/// Standard config directory for an application.
/// - Unix: `~/.config/<app_name>/`
/// - Windows: `%APPDATA%/<app_name>/`
pub fn config_dir(app_name: &str) -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("/tmp"))
                .join(".config")
        })
        .join(app_name)
}

/// Write data atomically: write to a temp file, then rename into place.
pub fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    atomic_write_with_sync(path, data, sync_parent_dir)
}

/// Read a file, refusing to follow symlinks at the target path.
///
/// On Unix uses `open(..., O_NOFOLLOW)` which returns `ELOOP` if `path`
/// is a symlink, closing the TOCTOU window that a pre-stat / post-read
/// symlink swap would open.  On Windows symlinks in the keys directory
/// are uncommon; we use a `symlink_metadata()` pre-check that is racy
/// relative to a simultaneous attacker rename, but good enough given
/// the threat model (same-UID attacker with user-profile write access).
///
/// Intended for loading key material (handle blobs, pub keys, `.meta`
/// files) whose paths are constructed from user-controlled labels.
pub fn read_no_follow(path: &Path) -> Result<Vec<u8>> {
    #[cfg(unix)]
    {
        use std::io::Read;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        Ok(buf)
    }
    #[cfg(not(unix))]
    {
        let meta = std::fs::symlink_metadata(path)?;
        if meta.file_type().is_symlink() {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("refusing to read symlink at {}", path.display()),
            )));
        }
        std::fs::read(path).map_err(Error::Io)
    }
}

/// Read-to-string variant of [`read_no_follow`].
pub fn read_to_string_no_follow(path: &Path) -> Result<String> {
    let bytes = read_no_follow(path)?;
    String::from_utf8(bytes).map_err(|e| {
        Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{} is not valid UTF-8: {e}", path.display()),
        ))
    })
}

fn atomic_write_with_sync<F>(path: &Path, data: &[u8], sync_parent: F) -> Result<()>
where
    F: Fn(&Path) -> Result<()>,
{
    let parent = path.parent().ok_or_else(|| {
        Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "atomic_write path has no parent directory",
        ))
    })?;
    let tmp = unique_temp_path(parent, path);
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&tmp)?;
    file.write_all(data)?;
    file.sync_all()?;
    drop(file);
    if let Err(e) = std::fs::rename(&tmp, path) {
        std::fs::remove_file(&tmp).ok();
        return Err(e.into());
    }
    sync_parent(parent)?;
    Ok(())
}

#[cfg(unix)]
fn sync_parent_dir(path: &Path) -> Result<()> {
    let dir = std::fs::File::open(path)?;
    dir.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent_dir(_path: &Path) -> Result<()> {
    Ok(())
}

fn unique_temp_path(parent: &Path, path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("tmp");
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    parent.join(format!(".{file_name}.{pid}.{nanos}.tmp"))
}

/// File-based directory lock using flock (Unix) or LockFile (Windows).
/// Prevents concurrent writes to the keys directory.
#[derive(Debug)]
pub struct DirLock {
    _file: std::fs::File,
}

impl DirLock {
    /// Acquire an exclusive lock on the given directory.
    pub fn acquire(dir: &Path) -> Result<Self> {
        let lock_path = dir.join(".lock");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)?;
        file.lock_exclusive().map_err(Error::Io)?;
        Ok(DirLock { _file: file })
    }
}

/// Ensure a directory exists with restrictive permissions (0700 on Unix).
pub fn ensure_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Set restrictive file permissions (0600 on Unix).
#[cfg_attr(not(unix), allow(unused_variables))]
pub fn restrict_file_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Save key metadata to a JSON file.
pub fn save_meta(dir: &Path, label: &str, meta: &KeyMeta) -> Result<()> {
    crate::types::validate_label(label)?;
    let meta_path = dir.join(format!("{label}.meta"));
    let json =
        serde_json::to_string_pretty(meta).map_err(|e| Error::Serialization(e.to_string()))?;
    atomic_write(&meta_path, json.as_bytes())
}

/// Save key metadata plus an HMAC sidecar (`<label>.meta.hmac`) that
/// authenticates the meta JSON under `hmac_key`.
///
/// Intended for backends whose meta tamper is a full policy bypass —
/// i.e. the software/keyring backend, where the hardware does not
/// re-enforce `AccessPolicy` at sign/decrypt time. Callers that hold
/// a per-app HMAC key (stored in the system keyring alongside the
/// KEK) invoke this instead of [`save_meta`]. The hardware backends
/// continue to call the plain [`save_meta`] because their key
/// enforcement is fixed at key-creation time on the chip and cannot
/// be relaxed by editing `.meta`.
pub fn save_meta_with_hmac(dir: &Path, label: &str, meta: &KeyMeta, hmac_key: &[u8]) -> Result<()> {
    crate::types::validate_label(label)?;
    let meta_path = dir.join(format!("{label}.meta"));
    let json =
        serde_json::to_string_pretty(meta).map_err(|e| Error::Serialization(e.to_string()))?;
    atomic_write(&meta_path, json.as_bytes())?;

    let tag = compute_meta_hmac(hmac_key, json.as_bytes());
    let hmac_path = dir.join(format!("{label}.meta.hmac"));
    atomic_write(&hmac_path, tag.as_bytes())?;
    Ok(())
}

/// Integrity policy for [`load_meta_with_hmac`].
///
/// On the keyring/software backend, `<label>.meta.hmac` is the only
/// thing that authenticates the `.meta` JSON — meta-tamper without
/// the sidecar means a same-UID attacker can lie about
/// `AccessPolicy` (and any other policy-bearing field) without
/// keyring access. Strict mode refuses missing sidecars so the
/// promise in the threat model ("attacker without keyring access is
/// caught") actually holds. Legacy mode is for one-shot migration
/// from caches that pre-date the sidecar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetaIntegrityMode {
    /// Both `.meta` and `.meta.hmac` must be present and verify. A
    /// missing sidecar is a hard error
    /// (`Error::KeyOperation { operation: "meta_hmac_missing", … }`).
    /// New production code should use this mode.
    RequireSidecar,
    /// A missing sidecar is treated as a legacy cache from before the
    /// HMAC sidecar shipped: the meta JSON is loaded verbatim and the
    /// caller is expected to migrate via [`migrate_meta_to_hmac`]
    /// immediately after a successful load. Reserved for the
    /// one-time upgrade path.
    AllowLegacyMissingSidecar,
}

/// Operation tag used in `Error::KeyOperation` when strict-mode
/// HMAC loading sees `.meta` without a `.meta.hmac` sidecar.
pub const META_HMAC_MISSING_OP: &str = "meta_hmac_missing";

/// Operation tag used when a `.meta.hmac` sidecar exists but does
/// not match the recomputed HMAC of the `.meta` JSON.
pub const META_HMAC_VERIFY_OP: &str = "meta_hmac_verify";

/// Load key metadata from a JSON file. Returns a default if the file doesn't exist.
pub fn load_meta(dir: &Path, label: &str) -> Result<KeyMeta> {
    crate::types::validate_label(label)?;
    let meta_path = dir.join(format!("{label}.meta"));
    if !meta_path.exists() {
        return Ok(KeyMeta {
            label: label.to_string(),
            key_type: crate::KeyType::Signing,
            access_policy: crate::AccessPolicy::None,
            created: String::new(),
            app_specific: serde_json::Value::Null,
        });
    }
    let content = read_to_string_no_follow(&meta_path)?;
    serde_json::from_str(&content).map_err(|e| Error::Serialization(e.to_string()))
}

/// Load key metadata with an HMAC check.
///
/// Behavior depends on `mode`:
///
/// - [`MetaIntegrityMode::RequireSidecar`]: both `<label>.meta` and
///   `<label>.meta.hmac` must be present and verify. A missing
///   `.meta.hmac` returns [`Error::KeyOperation`] with
///   `operation = "meta_hmac_missing"`; a mismatching one returns
///   `operation = "meta_hmac_verify"`.
/// - [`MetaIntegrityMode::AllowLegacyMissingSidecar`]: a missing
///   `.meta.hmac` is treated as a legacy cache — the meta JSON is
///   returned verbatim and the caller is expected to migrate via
///   [`migrate_meta_to_hmac`].
///
/// If `<label>.meta` itself is missing the function returns the
/// default empty `KeyMeta` via [`load_meta`] in either mode.
pub fn load_meta_with_hmac(
    dir: &Path,
    label: &str,
    hmac_key: &[u8],
    mode: MetaIntegrityMode,
) -> Result<KeyMeta> {
    crate::types::validate_label(label)?;
    let meta_path = dir.join(format!("{label}.meta"));
    if !meta_path.exists() {
        return load_meta(dir, label);
    }
    let content = read_to_string_no_follow(&meta_path)?;

    let hmac_path = dir.join(format!("{label}.meta.hmac"));
    if hmac_path.exists() {
        let expected_hex = read_to_string_no_follow(&hmac_path)?;
        let actual_hex = compute_meta_hmac(hmac_key, content.as_bytes());
        if !constant_time_eq(expected_hex.trim().as_bytes(), actual_hex.as_bytes()) {
            return Err(Error::KeyOperation {
                operation: META_HMAC_VERIFY_OP.into(),
                detail: format!(
                    "`.meta.hmac` does not match the stored `.meta` JSON for label {label}: \
                     metadata was tampered with after save"
                ),
            });
        }
    } else if mode == MetaIntegrityMode::RequireSidecar {
        return Err(Error::KeyOperation {
            operation: META_HMAC_MISSING_OP.into(),
            detail: format!(
                "`.meta` is present without a `.meta.hmac` sidecar for label {label}: \
                 either the sidecar was deleted (tamper) or this is a legacy meta \
                 that needs `migrate_meta_to_hmac`"
            ),
        });
    }

    serde_json::from_str(&content).map_err(|e| Error::Serialization(e.to_string()))
}

/// Write a `<label>.meta.hmac` sidecar for an existing `<label>.meta`
/// using `hmac_key`. Used by callers that hit a missing-sidecar load
/// in legacy mode and want to upgrade the on-disk artifacts so
/// subsequent strict loads succeed.
///
/// This blesses the current `.meta` content as authentic. Callers
/// that need to detect tamper before migration must do so via some
/// other channel (e.g. a separately-authenticated marker in the
/// keyring). Returns the sidecar path on success.
pub fn migrate_meta_to_hmac(dir: &Path, label: &str, hmac_key: &[u8]) -> Result<PathBuf> {
    crate::types::validate_label(label)?;
    let meta_path = dir.join(format!("{label}.meta"));
    if !meta_path.exists() {
        return Err(Error::KeyNotFound {
            label: label.to_string(),
        });
    }
    let content = read_to_string_no_follow(&meta_path)?;
    let tag = compute_meta_hmac(hmac_key, content.as_bytes());
    let hmac_path = dir.join(format!("{label}.meta.hmac"));
    atomic_write(&hmac_path, tag.as_bytes())?;
    Ok(hmac_path)
}

/// Compute HMAC-SHA256 over `data` keyed by `key`, hex-encoded.
///
/// Implemented directly over SHA-256 per RFC 2104 so we don't pull in
/// a new dep for a single use. The output is lowercase hex, 64 chars.
fn compute_meta_hmac(key: &[u8], data: &[u8]) -> String {
    let bytes = compute_meta_hmac_bytes(key, data);
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Compute HMAC-SHA256 over `data` keyed by `key`, returned as raw
/// bytes.
///
/// Same algorithm as [`compute_meta_hmac`]; this variant skips the
/// hex encoding for callers that need the raw tag (e.g., the macOS
/// per-key meta-tag store, which persists 32 bytes directly into a
/// keychain item).
pub fn compute_meta_hmac_bytes(key: &[u8], data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    const BLOCK_SIZE: usize = 64; // SHA-256 block size

    // Prepare K' — either pad to block size, or hash first if key > block.
    let mut k = [0_u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let hashed = Sha256::digest(key);
        k[..hashed.len()].copy_from_slice(&hashed);
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36_u8; BLOCK_SIZE];
    let mut opad = [0x5c_u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }

    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(data);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    let outer_digest = outer.finalize();

    let mut out = [0_u8; 32];
    out.copy_from_slice(&outer_digest);
    out
}

/// Constant-time equality. Returns `true` iff `a == b`.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Save a cached public key file.
pub fn save_pub_key(dir: &Path, label: &str, pub_key: &[u8]) -> Result<()> {
    crate::types::validate_label(label)?;
    let path = dir.join(format!("{label}.pub"));
    atomic_write(&path, pub_key)
}

/// Load a cached public key file.
pub fn load_pub_key(dir: &Path, label: &str) -> Result<Vec<u8>> {
    crate::types::validate_label(label)?;
    let path = dir.join(format!("{label}.pub"));
    if !path.exists() {
        return Err(Error::KeyNotFound {
            label: label.to_string(),
        });
    }
    read_no_follow(&path)
}

/// Refresh the cached public key from authoritative source bytes.
pub fn sync_pub_key(dir: &Path, label: &str, pub_key: &[u8]) -> Result<Vec<u8>> {
    crate::types::validate_label(label)?;
    crate::types::validate_p256_point(pub_key)?;

    match load_pub_key(dir, label) {
        Ok(existing) if existing == pub_key => Ok(existing),
        _ => {
            save_pub_key(dir, label, pub_key)?;
            Ok(pub_key.to_vec())
        }
    }
}

/// List all key labels by scanning for `.meta` files in the directory.
pub fn list_labels(dir: &Path) -> Result<Vec<String>> {
    list_labels_for_extensions(dir, &["meta"])
}

/// List key labels by scanning for any of the provided file extensions.
pub fn list_labels_for_extensions(dir: &Path, extensions: &[&str]) -> Result<Vec<String>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut labels = BTreeSet::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if let Some(extension) = path.extension().and_then(|e| e.to_str()) {
            if !extensions.contains(&extension) {
                continue;
            }
            if let Some(stem) = path.file_stem() {
                let label = stem.to_string_lossy().to_string();
                if crate::types::validate_label(&label).is_ok() {
                    labels.insert(label);
                }
            }
        }
    }
    Ok(labels.into_iter().collect())
}

/// Delete all files associated with a key label.
pub fn delete_key_files(dir: &Path, label: &str) -> Result<()> {
    crate::types::validate_label(label)?;
    let extensions = ["meta", "meta.hmac", "pub", "handle", "ssh.pub"];
    let mut found_any = false;
    for ext in &extensions {
        let path = dir.join(format!("{label}.{ext}"));
        if path.exists() {
            std::fs::remove_file(&path)?;
            found_any = true;
        }
    }
    if !found_any {
        return Err(Error::KeyNotFound {
            label: label.to_string(),
        });
    }
    Ok(())
}

/// Returns true if any metadata/public/handle files exist for the given label.
pub fn key_files_exist(dir: &Path, label: &str) -> Result<bool> {
    crate::types::validate_label(label)?;
    Ok(["meta", "pub", "handle", "ssh.pub"]
        .into_iter()
        .any(|ext| dir.join(format!("{label}.{ext}")).exists()))
}

/// Rename all files associated with a key label.
///
/// If a `<old_label>.meta.hmac` sidecar exists, the caller must
/// supply `hmac_key` so the sidecar can be recomputed against the
/// renamed-and-relabeled meta JSON. Passing `None` when a sidecar is
/// present returns an error rather than leaving an orphan or stale
/// sidecar — the latter would break subsequent strict
/// [`load_meta_with_hmac`] calls.
pub fn rename_key_files(
    dir: &Path,
    old_label: &str,
    new_label: &str,
    hmac_key: Option<&[u8]>,
) -> Result<()> {
    rename_key_files_with_writer(dir, old_label, new_label, hmac_key, atomic_write)
}

fn rename_key_files_with_writer<F>(
    dir: &Path,
    old_label: &str,
    new_label: &str,
    hmac_key: Option<&[u8]>,
    metadata_writer: F,
) -> Result<()>
where
    F: Fn(&Path, &[u8]) -> Result<()>,
{
    crate::types::validate_label(old_label)?;
    crate::types::validate_label(new_label)?;
    let old_handle = dir.join(format!("{old_label}.handle"));
    let old_meta = dir.join(format!("{old_label}.meta"));
    if !old_handle.exists() && !old_meta.exists() {
        return Err(Error::KeyNotFound {
            label: old_label.to_string(),
        });
    }
    if key_files_exist(dir, new_label)? {
        return Err(Error::DuplicateLabel {
            label: new_label.to_string(),
        });
    }
    let old_hmac = dir.join(format!("{old_label}.meta.hmac"));
    if old_hmac.exists() && hmac_key.is_none() {
        return Err(Error::KeyOperation {
            operation: "rename_key_files".into(),
            detail: format!(
                "`{old_label}.meta.hmac` sidecar exists but no hmac_key was supplied; \
                 rename would leave the sidecar stale or orphaned"
            ),
        });
    }
    // The handle/pub/ssh.pub files just move; .meta moves too but
    // its content is rewritten below; .meta.hmac is regenerated
    // below from the rewritten meta and is not part of the rename.
    let extensions = ["meta", "pub", "handle", "ssh.pub"];
    let mut renamed = Vec::new();
    for ext in &extensions {
        let old = dir.join(format!("{old_label}.{ext}"));
        let new = dir.join(format!("{new_label}.{ext}"));
        if old.exists() {
            if let Err(err) = std::fs::rename(&old, &new) {
                rollback_renames(&renamed)?;
                return Err(err.into());
            }
            renamed.push((old, new));
        }
    }
    // Update the label in the metadata file
    let new_meta_path = dir.join(format!("{new_label}.meta"));
    let mut new_meta_json: Option<String> = None;
    if new_meta_path.exists() {
        let content = read_to_string_no_follow(&new_meta_path)?;
        let mut meta: KeyMeta =
            serde_json::from_str(&content).map_err(|e| Error::Serialization(e.to_string()))?;
        meta.label = new_label.to_string();
        let json =
            serde_json::to_string_pretty(&meta).map_err(|e| Error::Serialization(e.to_string()))?;
        if let Err(err) = metadata_writer(&new_meta_path, json.as_bytes()) {
            rollback_renames(&renamed)?;
            return Err(err);
        }
        new_meta_json = Some(json);
    }
    // Recompute and rewrite the HMAC sidecar against the new meta.
    // The old sidecar (still under the old label name) is unlinked
    // unconditionally so a stale sidecar can't be picked up later.
    if old_hmac.exists() {
        drop(std::fs::remove_file(&old_hmac));
    }
    if let (Some(json), Some(key)) = (new_meta_json.as_ref(), hmac_key) {
        let new_hmac = dir.join(format!("{new_label}.meta.hmac"));
        let tag = compute_meta_hmac(key, json.as_bytes());
        if let Err(err) = metadata_writer(&new_hmac, tag.as_bytes()) {
            rollback_renames(&renamed)?;
            return Err(err);
        }
    }
    Ok(())
}

fn rollback_renames(renamed: &[(PathBuf, PathBuf)]) -> Result<()> {
    for (old, new) in renamed.iter().rev() {
        if new.exists() {
            std::fs::rename(new, old)?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::used_underscore_binding,
    let_underscore_drop
)]
mod tests {
    use super::*;
    use crate::{AccessPolicy, KeyType};
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_dir() -> PathBuf {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("enclaveapp-core-test-{pid}-{id}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn meta_hmac_roundtrip_accepts_unchanged_meta() {
        let dir = test_dir();
        let hmac_key = b"test-hmac-key-material-32-bytes!";
        let meta = KeyMeta::new(
            "roundtrip",
            KeyType::Encryption,
            AccessPolicy::BiometricOnly,
        );
        save_meta_with_hmac(&dir, "roundtrip", &meta, hmac_key).unwrap();
        let loaded = load_meta_with_hmac(
            &dir,
            "roundtrip",
            hmac_key,
            MetaIntegrityMode::RequireSidecar,
        )
        .unwrap();
        assert_eq!(loaded.access_policy, AccessPolicy::BiometricOnly);
        assert_eq!(loaded.label, "roundtrip");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn meta_hmac_rejects_tampered_meta() {
        let dir = test_dir();
        let hmac_key = b"test-hmac-key-material-32-bytes!";
        let meta = KeyMeta::new("tamper", KeyType::Encryption, AccessPolicy::BiometricOnly);
        save_meta_with_hmac(&dir, "tamper", &meta, hmac_key).unwrap();

        // Rewrite .meta to flip AccessPolicy → None, leaving the HMAC sidecar untouched.
        let meta_path = dir.join("tamper.meta");
        let raw = std::fs::read_to_string(&meta_path).unwrap();
        let tampered = raw.replace("biometric_only", "none");
        std::fs::write(&meta_path, tampered).unwrap();

        let err = load_meta_with_hmac(&dir, "tamper", hmac_key, MetaIntegrityMode::RequireSidecar)
            .unwrap_err();
        assert!(
            err.to_string().contains(META_HMAC_VERIFY_OP),
            "expected HMAC-verify failure, got: {err}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn meta_hmac_rejects_wrong_key() {
        let dir = test_dir();
        let hmac_key = b"test-hmac-key-material-32-bytes!";
        let meta = KeyMeta::new("wrongkey", KeyType::Encryption, AccessPolicy::None);
        save_meta_with_hmac(&dir, "wrongkey", &meta, hmac_key).unwrap();

        let bad_key = b"different-hmac-key-material-32by";
        let err = load_meta_with_hmac(&dir, "wrongkey", bad_key, MetaIntegrityMode::RequireSidecar)
            .unwrap_err();
        assert!(err.to_string().contains(META_HMAC_VERIFY_OP));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn meta_hmac_legacy_mode_accepts_missing_sidecar() {
        // Legacy caches saved before the sidecar shipped must load OK
        // in legacy/migration mode.
        let dir = test_dir();
        let hmac_key = b"test-hmac-key-material-32-bytes!";
        let meta = KeyMeta::new("legacy", KeyType::Signing, AccessPolicy::None);
        save_meta(&dir, "legacy", &meta).unwrap(); // no sidecar
        let loaded = load_meta_with_hmac(
            &dir,
            "legacy",
            hmac_key,
            MetaIntegrityMode::AllowLegacyMissingSidecar,
        )
        .unwrap();
        assert_eq!(loaded.label, "legacy");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn meta_hmac_strict_rejects_missing_sidecar() {
        // Same scenario as the legacy test, but in strict mode the
        // load must fail — otherwise an attacker who deletes the
        // sidecar bypasses HMAC verification entirely.
        let dir = test_dir();
        let hmac_key = b"test-hmac-key-material-32-bytes!";
        let meta = KeyMeta::new("legacy", KeyType::Signing, AccessPolicy::None);
        save_meta(&dir, "legacy", &meta).unwrap();
        let err = load_meta_with_hmac(&dir, "legacy", hmac_key, MetaIntegrityMode::RequireSidecar)
            .unwrap_err();
        assert!(
            err.to_string().contains(META_HMAC_MISSING_OP),
            "expected meta_hmac_missing, got: {err}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn migrate_meta_to_hmac_writes_sidecar_for_legacy_meta() {
        let dir = test_dir();
        let hmac_key = b"test-hmac-key-material-32-bytes!";
        let meta = KeyMeta::new("legacy", KeyType::Signing, AccessPolicy::None);
        save_meta(&dir, "legacy", &meta).unwrap();
        assert!(!dir.join("legacy.meta.hmac").exists());

        migrate_meta_to_hmac(&dir, "legacy", hmac_key).unwrap();
        assert!(dir.join("legacy.meta.hmac").exists());

        // After migration, strict load succeeds.
        let loaded =
            load_meta_with_hmac(&dir, "legacy", hmac_key, MetaIntegrityMode::RequireSidecar)
                .unwrap();
        assert_eq!(loaded.label, "legacy");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn migrate_meta_to_hmac_errors_for_missing_meta() {
        let dir = test_dir();
        let hmac_key = b"test-hmac-key-material-32-bytes!";
        let err = migrate_meta_to_hmac(&dir, "ghost", hmac_key).unwrap_err();
        assert!(matches!(err, Error::KeyNotFound { .. }));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn compute_meta_hmac_is_stable() {
        // HMAC-SHA256 of an empty message under an empty key, from RFC 4231
        // test vector 1 isn't directly applicable (uses 20-byte key), so we
        // just assert our function is deterministic.
        let key = b"k";
        let data = b"message";
        let a = compute_meta_hmac(key, data);
        let b = compute_meta_hmac(key, data);
        assert_eq!(a, b);
        assert_eq!(a.len(), 64); // 32 bytes hex-encoded
    }

    #[test]
    fn constant_time_eq_rejects_length_mismatch() {
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
    }

    #[test]
    fn constant_time_eq_empty_slices_are_equal() {
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn compute_meta_hmac_bytes_output_is_32_bytes() {
        let tag = compute_meta_hmac_bytes(b"k", b"d");
        assert_eq!(tag.len(), 32);
    }

    #[test]
    fn compute_meta_hmac_bytes_is_deterministic() {
        let key = b"stable-key";
        let data = b"stable-data";
        let a = compute_meta_hmac_bytes(key, data);
        let b = compute_meta_hmac_bytes(key, data);
        assert_eq!(a, b);
    }

    #[test]
    fn compute_meta_hmac_bytes_long_key_exercises_hash_path() {
        // key > 64 bytes (SHA-256 block size) triggers the hash-then-pad branch
        let long_key = vec![0x5a_u8; 128];
        let short_key = &long_key[..8];
        let data = b"test-data";
        let long_tag = compute_meta_hmac_bytes(&long_key, data);
        let short_tag = compute_meta_hmac_bytes(short_key, data);
        assert_ne!(long_tag, short_tag);
        assert_eq!(long_tag.len(), 32);
    }

    #[test]
    fn compute_meta_hmac_bytes_different_data_produces_different_tag() {
        let key = b"same-key";
        let tag_a = compute_meta_hmac_bytes(key, b"data-a");
        let tag_b = compute_meta_hmac_bytes(key, b"data-b");
        assert_ne!(tag_a, tag_b);
    }

    #[test]
    fn compute_meta_hmac_bytes_different_key_produces_different_tag() {
        let data = b"same-data";
        let tag_a = compute_meta_hmac_bytes(b"key-a", data);
        let tag_b = compute_meta_hmac_bytes(b"key-b", data);
        assert_ne!(tag_a, tag_b);
    }

    #[test]
    fn key_meta_new_sets_timestamp() {
        let meta = KeyMeta::new("test", KeyType::Signing, AccessPolicy::None);
        assert_eq!(meta.label, "test");
        assert_eq!(meta.key_type, KeyType::Signing);
        assert!(!meta.created.is_empty());
        let ts: u64 = meta.created.parse().unwrap();
        assert!(ts > 0);
    }

    #[test]
    fn key_meta_clone_preserves_all_fields() {
        let mut meta = KeyMeta::new(
            "clone-test",
            KeyType::Encryption,
            AccessPolicy::BiometricOnly,
        );
        meta.set_app_field("field", "value");
        let cloned = meta.clone();
        assert_eq!(cloned.label, meta.label);
        assert_eq!(cloned.key_type, meta.key_type);
        assert_eq!(cloned.access_policy, meta.access_policy);
        assert_eq!(cloned.get_app_field("field"), Some("value"));
    }

    #[test]
    fn key_meta_app_field_roundtrip() {
        let mut meta = KeyMeta::new("test", KeyType::Signing, AccessPolicy::None);
        assert!(meta.get_app_field("git_email").is_none());
        meta.set_app_field("git_email", "jay@example.com");
        assert_eq!(meta.get_app_field("git_email"), Some("jay@example.com"));
    }

    #[test]
    fn key_meta_serde_roundtrip() {
        let mut meta = KeyMeta::new("test", KeyType::Encryption, AccessPolicy::BiometricOnly);
        meta.set_app_field("profile", "default");
        let json = serde_json::to_string_pretty(&meta).unwrap();
        let parsed: KeyMeta = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.label, "test");
        assert_eq!(parsed.key_type, KeyType::Encryption);
        assert_eq!(parsed.access_policy, AccessPolicy::BiometricOnly);
        assert_eq!(parsed.get_app_field("profile"), Some("default"));
    }

    #[test]
    #[cfg_attr(miri, ignore)] // File I/O not supported by Miri isolation
    fn atomic_write_creates_file() {
        let dir = test_dir();
        let path = dir.join("test.txt");
        atomic_write(&path, b"hello world").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "hello world");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)] // File I/O not supported by Miri isolation
    fn atomic_write_ignores_preexisting_legacy_tmp_file() {
        let dir = test_dir();
        let path = dir.join("test.txt");
        let legacy_tmp = path.with_extension("tmp");
        std::fs::write(&legacy_tmp, b"legacy").unwrap();

        atomic_write(&path, b"fresh").unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "fresh");
        assert_eq!(std::fs::read_to_string(&legacy_tmp).unwrap(), "legacy");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)] // File I/O not supported by Miri isolation
    fn atomic_write_syncs_parent_directory_after_rename() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let dir = test_dir();
        let path = dir.join("test.txt");
        let synced = AtomicBool::new(false);

        atomic_write_with_sync(&path, b"hello world", |parent| {
            assert_eq!(parent, dir.as_path());
            synced.store(true, Ordering::SeqCst);
            Ok(())
        })
        .unwrap();

        assert!(synced.load(Ordering::SeqCst));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "hello world");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)] // File I/O not supported by Miri isolation
    fn read_no_follow_reads_file_content() {
        let dir = test_dir();
        let path = dir.join("data.bin");
        std::fs::write(&path, b"hello bytes").unwrap();
        let result = read_no_follow(&path).unwrap();
        assert_eq!(result, b"hello bytes");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)] // File I/O not supported by Miri isolation
    fn read_no_follow_returns_error_for_missing_file() {
        let dir = test_dir();
        let path = dir.join("nonexistent.bin");
        let result = read_no_follow(&path);
        assert!(result.is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)] // File I/O not supported by Miri isolation
    fn save_load_meta_roundtrip() {
        let dir = test_dir();
        let meta = KeyMeta::new("mykey", KeyType::Signing, AccessPolicy::Any);
        save_meta(&dir, "mykey", &meta).unwrap();
        let loaded = load_meta(&dir, "mykey").unwrap();
        assert_eq!(loaded.label, "mykey");
        assert_eq!(loaded.key_type, KeyType::Signing);
        assert_eq!(loaded.access_policy, AccessPolicy::Any);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)] // File I/O (mkdir) not supported under Miri isolation
    fn load_meta_returns_default_for_missing() {
        let dir = test_dir();
        let meta = load_meta(&dir, "nonexistent").unwrap();
        assert_eq!(meta.label, "nonexistent");
        assert_eq!(meta.key_type, KeyType::Signing);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)] // File I/O not supported by Miri isolation
    fn save_load_pub_key_roundtrip() {
        let dir = test_dir();
        let pub_key = vec![0x04; 65];
        save_pub_key(&dir, "mykey", &pub_key).unwrap();
        let loaded = load_pub_key(&dir, "mykey").unwrap();
        assert_eq!(loaded, pub_key);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)] // File I/O (mkdir) not supported under Miri isolation
    fn load_pub_key_returns_key_not_found() {
        let dir = test_dir();
        let err = load_pub_key(&dir, "missing").unwrap_err();
        match err {
            Error::KeyNotFound { label } => assert_eq!(label, "missing"),
            other => panic!("expected KeyNotFound, got: {other}"),
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)] // File I/O (mkdir) not supported under Miri isolation
    fn sync_pub_key_writes_missing_cache() {
        let dir = test_dir();
        let pub_key = vec![0x04; 65];

        let synced = sync_pub_key(&dir, "sync", &pub_key).unwrap();
        assert_eq!(synced, pub_key);
        assert_eq!(load_pub_key(&dir, "sync").unwrap(), pub_key);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)] // File I/O (mkdir) not supported under Miri isolation
    fn sync_pub_key_repairs_mismatched_cache() {
        let dir = test_dir();
        let mut authoritative = vec![0x04];
        authoritative.extend_from_slice(&[0x11; 64]);

        save_pub_key(&dir, "sync", &[0x04; 65]).unwrap();

        let synced = sync_pub_key(&dir, "sync", &authoritative).unwrap();
        assert_eq!(synced, authoritative);
        assert_eq!(load_pub_key(&dir, "sync").unwrap(), authoritative);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)] // File I/O (mkdir) not supported under Miri isolation
    fn metadata_label_operations_reject_invalid_labels() {
        let dir = test_dir();
        let meta = KeyMeta::new("valid", KeyType::Signing, AccessPolicy::None);

        let err = save_meta(&dir, "../escape", &meta).unwrap_err();
        assert!(matches!(err, Error::InvalidLabel { .. }));

        let err = load_meta(&dir, "../escape").unwrap_err();
        assert!(matches!(err, Error::InvalidLabel { .. }));

        let err = save_pub_key(&dir, "../escape", b"pubkey").unwrap_err();
        assert!(matches!(err, Error::InvalidLabel { .. }));

        let err = load_pub_key(&dir, "../escape").unwrap_err();
        assert!(matches!(err, Error::InvalidLabel { .. }));

        let err = delete_key_files(&dir, "../escape").unwrap_err();
        assert!(matches!(err, Error::InvalidLabel { .. }));

        let err = rename_key_files(&dir, "valid", "../escape", None).unwrap_err();
        assert!(matches!(err, Error::InvalidLabel { .. }));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)] // File I/O not supported under Miri isolation
    fn list_labels_empty_for_nonexistent_dir() {
        let dir = std::env::temp_dir().join("enclaveapp-core-test-nonexistent-dir");
        let _ = std::fs::remove_dir_all(&dir);
        let labels = list_labels(&dir).unwrap();
        assert!(labels.is_empty());
    }

    #[test]
    #[cfg_attr(miri, ignore)] // File I/O + libc::umask not supported by Miri
    fn list_labels_finds_meta_files() {
        let dir = test_dir();
        let meta_a = KeyMeta::new("alpha", KeyType::Signing, AccessPolicy::None);
        let meta_b = KeyMeta::new("beta", KeyType::Encryption, AccessPolicy::Any);
        save_meta(&dir, "alpha", &meta_a).unwrap();
        save_meta(&dir, "beta", &meta_b).unwrap();
        // Also create a .pub file that should be ignored
        std::fs::write(dir.join("alpha.pub"), b"pubkey").unwrap();
        let labels = list_labels(&dir).unwrap();
        assert_eq!(labels, vec!["alpha", "beta"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)] // File I/O not supported by Miri isolation
    fn list_labels_for_extensions_includes_unique_sorted_stems() {
        let dir = test_dir();
        std::fs::write(dir.join("alpha.handle"), b"handle").unwrap();
        std::fs::write(dir.join("beta.meta"), b"{}").unwrap();
        std::fs::write(dir.join("beta.handle"), b"handle").unwrap();
        std::fs::write(dir.join("gamma.pub"), b"pub").unwrap();

        let labels = list_labels_for_extensions(&dir, &["meta", "handle"]).unwrap();
        assert_eq!(labels, vec!["alpha", "beta"]);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)] // File I/O not supported by Miri isolation
    fn list_labels_for_extensions_skips_invalid_labels() {
        let dir = test_dir();
        std::fs::write(dir.join("valid.handle"), b"handle").unwrap();
        std::fs::write(dir.join("bad label.handle"), b"handle").unwrap();
        std::fs::write(dir.join("also.bad.handle"), b"handle").unwrap();

        let labels = list_labels_for_extensions(&dir, &["handle"]).unwrap();
        assert_eq!(labels, vec!["valid"]);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)] // File I/O (mkdir) not supported under Miri isolation
    fn delete_key_files_removes_all() {
        let dir = test_dir();
        std::fs::write(dir.join("mykey.meta"), b"{}").unwrap();
        std::fs::write(dir.join("mykey.pub"), b"pub").unwrap();
        std::fs::write(dir.join("mykey.handle"), b"handle").unwrap();
        delete_key_files(&dir, "mykey").unwrap();
        assert!(!dir.join("mykey.meta").exists());
        assert!(!dir.join("mykey.pub").exists());
        assert!(!dir.join("mykey.handle").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)] // File I/O (mkdir) not supported under Miri isolation
    fn delete_key_files_returns_key_not_found() {
        let dir = test_dir();
        let err = delete_key_files(&dir, "ghost").unwrap_err();
        match err {
            Error::KeyNotFound { label } => assert_eq!(label, "ghost"),
            other => panic!("expected KeyNotFound, got: {other}"),
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)] // File I/O not supported by Miri isolation
    fn rename_key_files_renames_and_updates_meta() {
        let dir = test_dir();
        let meta = KeyMeta::new("old-name", KeyType::Signing, AccessPolicy::None);
        save_meta(&dir, "old-name", &meta).unwrap();
        save_pub_key(&dir, "old-name", b"pubkey").unwrap();

        rename_key_files(&dir, "old-name", "new-name", None).unwrap();

        assert!(!dir.join("old-name.meta").exists());
        assert!(!dir.join("old-name.pub").exists());
        assert!(dir.join("new-name.meta").exists());
        assert!(dir.join("new-name.pub").exists());

        let loaded = load_meta(&dir, "new-name").unwrap();
        assert_eq!(loaded.label, "new-name");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)] // File I/O not supported by Miri isolation
    fn rename_key_files_rejects_existing_target() {
        let dir = test_dir();
        let meta = KeyMeta::new("src", KeyType::Signing, AccessPolicy::None);
        save_meta(&dir, "src", &meta).unwrap();
        let meta2 = KeyMeta::new("dst", KeyType::Signing, AccessPolicy::None);
        save_meta(&dir, "dst", &meta2).unwrap();

        let err = rename_key_files(&dir, "src", "dst", None).unwrap_err();
        match err {
            Error::DuplicateLabel { label } => assert_eq!(label, "dst"),
            other => panic!("expected DuplicateLabel, got: {other}"),
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)] // File I/O not supported by Miri isolation
    fn rename_key_files_rejects_existing_target_pub_without_meta() {
        let dir = test_dir();
        let meta = KeyMeta::new("src", KeyType::Signing, AccessPolicy::None);
        save_meta(&dir, "src", &meta).unwrap();
        save_pub_key(&dir, "dst", b"existing").unwrap();

        let err = rename_key_files(&dir, "src", "dst", None).unwrap_err();
        match err {
            Error::DuplicateLabel { label } => assert_eq!(label, "dst"),
            other => panic!("expected DuplicateLabel, got: {other}"),
        }
        assert!(dir.join("src.meta").exists());
        assert!(dir.join("dst.pub").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)] // File I/O not supported by Miri isolation
    fn rename_key_files_rolls_back_when_metadata_update_fails() {
        let dir = test_dir();
        let meta = KeyMeta::new("old-name", KeyType::Signing, AccessPolicy::None);
        save_meta(&dir, "old-name", &meta).unwrap();
        save_pub_key(&dir, "old-name", b"pubkey").unwrap();

        let err = rename_key_files_with_writer(&dir, "old-name", "new-name", None, |_, _| {
            Err(Error::Serialization("forced failure".into()))
        })
        .unwrap_err();
        assert!(matches!(err, Error::Serialization(_)));
        assert!(dir.join("old-name.meta").exists());
        assert!(dir.join("old-name.pub").exists());
        assert!(!dir.join("new-name.meta").exists());
        assert!(!dir.join("new-name.pub").exists());
        let loaded = load_meta(&dir, "old-name").unwrap();
        assert_eq!(loaded.label, "old-name");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)] // File I/O not supported by Miri isolation
    fn rename_key_files_with_sidecar_recomputes_hmac_under_new_label() {
        let dir = test_dir();
        let hmac_key = b"test-hmac-key-material-32-bytes!";
        let meta = KeyMeta::new("old-name", KeyType::Signing, AccessPolicy::None);
        save_meta_with_hmac(&dir, "old-name", &meta, hmac_key).unwrap();
        save_pub_key(&dir, "old-name", b"pubkey").unwrap();

        rename_key_files(&dir, "old-name", "new-name", Some(hmac_key)).unwrap();

        assert!(!dir.join("old-name.meta").exists());
        assert!(!dir.join("old-name.meta.hmac").exists());
        assert!(dir.join("new-name.meta").exists());
        assert!(dir.join("new-name.meta.hmac").exists());

        // Strict load against the new label must succeed — i.e. the
        // sidecar was rewritten to authenticate the relabeled meta,
        // not left over as the old-name HMAC.
        let loaded = load_meta_with_hmac(
            &dir,
            "new-name",
            hmac_key,
            MetaIntegrityMode::RequireSidecar,
        )
        .unwrap();
        assert_eq!(loaded.label, "new-name");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)] // File I/O not supported by Miri isolation
    fn rename_key_files_with_sidecar_requires_hmac_key() {
        // If the .meta.hmac sidecar is present but the caller forgot
        // to pass the hmac_key, refuse the rename rather than leaving
        // a stale or orphaned sidecar.
        let dir = test_dir();
        let hmac_key = b"test-hmac-key-material-32-bytes!";
        let meta = KeyMeta::new("old-name", KeyType::Signing, AccessPolicy::None);
        save_meta_with_hmac(&dir, "old-name", &meta, hmac_key).unwrap();

        let err = rename_key_files(&dir, "old-name", "new-name", None).unwrap_err();
        match err {
            Error::KeyOperation { operation, .. } => assert_eq!(operation, "rename_key_files"),
            other => panic!("expected KeyOperation, got: {other}"),
        }
        // No partial rename left behind.
        assert!(dir.join("old-name.meta").exists());
        assert!(dir.join("old-name.meta.hmac").exists());
        assert!(!dir.join("new-name.meta").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)] // File I/O (mkdir) not supported under Miri isolation
    fn rename_key_files_rejects_missing_source() {
        let dir = test_dir();
        let err = rename_key_files(&dir, "missing", "new", None).unwrap_err();
        match err {
            Error::KeyNotFound { label } => assert_eq!(label, "missing"),
            other => panic!("expected KeyNotFound, got: {other}"),
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)] // dirs::data_dir() calls FFI not supported by Miri
    fn keys_dir_returns_absolute_path() {
        let dir = keys_dir("test-app");
        assert!(dir.is_absolute());
        assert!(dir.to_string_lossy().contains("test-app"));
        assert!(dir.to_string_lossy().contains("keys"));
    }

    #[test]
    #[cfg_attr(miri, ignore)] // dirs::config_dir() calls FFI not supported by Miri
    fn config_dir_returns_absolute_path() {
        let dir = config_dir("test-app");
        assert!(dir.is_absolute());
        assert!(dir.to_string_lossy().contains("test-app"));
    }

    #[test]
    #[cfg_attr(miri, ignore)] // File I/O not supported by Miri isolation
    fn ensure_dir_creates_nested() {
        let dir = test_dir();
        let nested = dir.join("a").join("b").join("c");
        ensure_dir(&nested).unwrap();
        assert!(nested.exists());
        assert!(nested.is_dir());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)] // File I/O (mkdir) not supported under Miri isolation
    fn dir_lock_acquire_and_drop() {
        let dir = test_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let _lock = DirLock::acquire(&dir).unwrap();
        assert!(dir.join(".lock").exists());
        drop(_lock);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)] // Threaded file locking not supported under Miri isolation
    fn dir_lock_blocks_until_first_holder_releases() {
        use std::sync::mpsc;
        use std::thread;
        use std::time::{Duration, Instant};

        let dir = test_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let first = DirLock::acquire(&dir).unwrap();
        let (tx, rx) = mpsc::channel();
        let thread_dir = dir.clone();

        let handle = thread::spawn(move || {
            tx.send(Instant::now()).unwrap();
            let _second = DirLock::acquire(&thread_dir).unwrap();
            tx.send(Instant::now()).unwrap();
        });

        let start = rx.recv().unwrap();
        thread::sleep(Duration::from_millis(150));
        drop(first);
        let acquired = rx.recv().unwrap();
        assert!(acquired.duration_since(start) >= Duration::from_millis(100));
        handle.join().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)] // libc::chmod not supported by Miri
    fn restrict_file_permissions_succeeds() {
        let dir = test_dir();
        let path = dir.join("secret.txt");
        std::fs::write(&path, b"secret").unwrap();
        restrict_file_permissions(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
