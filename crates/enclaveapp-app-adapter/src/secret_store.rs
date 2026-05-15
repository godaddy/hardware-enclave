#![cfg_attr(test, allow(clippy::panic, clippy::unwrap_used))]

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use enclaveapp_app_storage::{
    create_encryption_storage, AccessPolicy, EncryptionStorage, StorageConfig,
};
use fs4::fs_std::FileExt;
use sha2::{Digest, Sha256};

use crate::binding_store::app_data_dir;
use crate::error::{AdapterError, Result};
use crate::types::BindingId;

/// Placeholder value returned by the legacy [`SecretStore::get`] method
/// from read-only secret stores instead of the actual secret.
///
/// **Prefer [`SecretStore::get_read`]**, which returns a typed
/// [`SecretRead`] enum and cannot be confused with a real secret whose
/// bytes happen to equal this literal. The constant is retained for the
/// old `get` path and for back-compat with persisted state (npmenc
/// stores per-binding token-source state strings that may literally be
/// `"<redacted>"` after a `show --raw` export).
pub const REDACTED_PLACEHOLDER: &str = "<redacted>";

/// Check whether a legacy string return is the redaction sentinel.
///
/// Equivalent to `value == REDACTED_PLACEHOLDER`. New code should
/// compare against [`SecretRead::Redacted`] instead — this helper is
/// kept for call sites that still consume the legacy
/// [`SecretStore::get`] result.
#[must_use]
pub fn is_redacted_placeholder(value: &str) -> bool {
    value == REDACTED_PLACEHOLDER
}

/// Typed outcome of reading a secret from a [`SecretStore`].
///
/// Callers that distinguish "secret exists but cannot be read" from
/// "secret present" should match on this enum instead of inspecting a
/// string. The [`Present`](SecretRead::Present) variant owns the
/// plaintext; [`Redacted`](SecretRead::Redacted) carries no material;
/// [`Absent`](SecretRead::Absent) means nothing was stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretRead {
    /// Secret material was successfully read.
    Present(String),
    /// A value is stored for this id but the store will not hand it over
    /// — for example the read-only inspection store that knows an entry
    /// exists but intentionally refuses to decrypt.
    Redacted,
    /// No entry is stored for this id.
    Absent,
}

impl SecretRead {
    /// True if the variant is `Present`.
    #[must_use]
    pub fn is_present(&self) -> bool {
        matches!(self, SecretRead::Present(_))
    }

    /// True if the variant is `Redacted`.
    #[must_use]
    pub fn is_redacted(&self) -> bool {
        matches!(self, SecretRead::Redacted)
    }

    /// True if the variant is `Absent`.
    #[must_use]
    pub fn is_absent(&self) -> bool {
        matches!(self, SecretRead::Absent)
    }

    /// Consume and return the plaintext if `Present`, else `None`.
    /// Redacted is mapped to `None` — callers that need to distinguish
    /// redaction from absence must match on the enum directly.
    #[must_use]
    pub fn into_present(self) -> Option<String> {
        match self {
            SecretRead::Present(s) => Some(s),
            SecretRead::Redacted | SecretRead::Absent => None,
        }
    }
}

pub trait SecretStore {
    fn set(&self, id: &BindingId, secret: &str) -> Result<()>;

    /// Legacy string-return read. Kept for back-compat. Prefer
    /// [`get_read`](SecretStore::get_read), which returns a typed
    /// [`SecretRead`] and cannot be confused with a real secret whose
    /// bytes equal [`REDACTED_PLACEHOLDER`].
    fn get(&self, id: &BindingId) -> Result<Option<String>>;

    /// Typed-return read. Default implementation forwards to `get` and
    /// maps `Some("<redacted>")` → [`SecretRead::Redacted`]. Store
    /// implementations that can distinguish present-vs-redacted
    /// natively should override to avoid the string-sentinel round-trip.
    fn get_read(&self, id: &BindingId) -> Result<SecretRead> {
        match self.get(id)? {
            Some(value) if value == REDACTED_PLACEHOLDER => Ok(SecretRead::Redacted),
            Some(value) => Ok(SecretRead::Present(value)),
            None => Ok(SecretRead::Absent),
        }
    }

    fn delete(&self, id: &BindingId) -> Result<bool>;
}

#[derive(Debug, Clone)]
pub struct ReadOnlyEncryptedFileSecretStore {
    dir: PathBuf,
}

impl ReadOnlyEncryptedFileSecretStore {
    pub fn for_app(app_name: &str) -> Result<Self> {
        Ok(Self {
            dir: app_data_dir(app_name)?.join("secrets"),
        })
    }

    fn path_for(&self, id: &BindingId) -> PathBuf {
        self.dir.join(hash_id(id))
    }
}

pub struct EncryptedFileSecretStore {
    app_name: String,
    dir: PathBuf,
    storage: OnceLock<std::result::Result<Box<dyn EncryptionStorage>, String>>,
}

impl std::fmt::Debug for EncryptedFileSecretStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedFileSecretStore")
            .field("app_name", &self.app_name)
            .field("dir", &self.dir)
            .finish()
    }
}

impl EncryptedFileSecretStore {
    pub fn for_app(app_name: &str) -> Result<Self> {
        let dir = app_data_dir(app_name)?.join("secrets");
        Ok(Self {
            app_name: app_name.to_string(),
            dir,
            storage: OnceLock::new(),
        })
    }

    /// Test-only constructor that injects a pre-built `EncryptionStorage`
    /// rather than letting the store lazily create a hardware-backed one.
    /// This makes `EncryptedFileSecretStore` testable in CI without
    /// platform credentials.
    #[cfg(test)]
    pub fn with_storage_for_test(dir: PathBuf, storage: Box<dyn EncryptionStorage>) -> Self {
        let lock = OnceLock::new();
        // OnceLock::set fails when already initialised. A fresh OnceLock always
        // accepts the first set, so the only failure mode here is an unreachable
        // double-init; map it to a panic with a useful message.
        if lock.set(Ok(storage)).is_err() {
            panic!("fresh OnceLock already initialised — this is a test bug");
        }
        Self {
            app_name: "test".to_string(),
            dir,
            storage: lock,
        }
    }

    fn path_for(&self, id: &BindingId) -> PathBuf {
        self.dir.join(hash_id(id))
    }

    fn lock_path_for(&self, id: &BindingId) -> PathBuf {
        self.dir.join(format!("{}.lock", hash_id(id)))
    }

    fn storage(&self) -> Result<&dyn EncryptionStorage> {
        match self.storage.get_or_init(|| {
            create_encryption_storage(StorageConfig {
                app_name: self.app_name.clone(),
                key_label: "adapter-secrets".to_string(),
                access_policy: AccessPolicy::None,
                extra_bridge_paths: Vec::new(),
                keys_dir: None,
                force_keyring: false,
                wrapping_key_user_presence: false,
                wrapping_key_cache_ttl: std::time::Duration::ZERO,
                keychain_access_group: None,
                prefer_windows_hello_ux: false,
            })
            .map_err(|error| error.to_string())
        }) {
            Ok(storage) => Ok(storage.as_ref()),
            Err(error) => Err(AdapterError::Storage(error.clone())),
        }
    }

    fn with_shared_lock<T>(
        &self,
        id: &BindingId,
        work: impl FnOnce(&Self) -> Result<T>,
    ) -> Result<T> {
        fs::create_dir_all(&self.dir)?;
        let lock_path = self.lock_path_for(id);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)?;
        FileExt::lock_shared(&file).map_err(|error| AdapterError::Storage(error.to_string()))?;
        let result = work(self);
        let unlock_result =
            FileExt::unlock(&file).map_err(|error| AdapterError::Storage(error.to_string()));
        match (result, unlock_result) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) | (Ok(_), Err(error)) => Err(error),
        }
    }

    fn with_exclusive_lock<T>(
        &self,
        id: &BindingId,
        work: impl FnOnce(&Self) -> Result<T>,
    ) -> Result<T> {
        fs::create_dir_all(&self.dir)?;
        set_dir_permissions(&self.dir)?;
        let lock_path = self.lock_path_for(id);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)?;
        FileExt::lock_exclusive(&file).map_err(|error| AdapterError::Storage(error.to_string()))?;
        let result = work(self);
        let unlock_result =
            FileExt::unlock(&file).map_err(|error| AdapterError::Storage(error.to_string()));
        match (result, unlock_result) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) | (Ok(_), Err(error)) => Err(error),
        }
    }
}

impl SecretStore for EncryptedFileSecretStore {
    fn set(&self, id: &BindingId, secret: &str) -> Result<()> {
        self.with_exclusive_lock(id, |store| {
            let ciphertext = store.storage()?.encrypt(secret.as_bytes())?;
            let encoded = base64::engine::general_purpose::STANDARD.encode(ciphertext);
            let path = store.path_for(id);
            let temp_path = temp_path_for(&path);
            fs::write(&temp_path, encoded)?;
            set_file_permissions(&temp_path)?;
            fs::rename(&temp_path, &path)?;
            Ok(())
        })
    }

    fn get(&self, id: &BindingId) -> Result<Option<String>> {
        if !self.dir.exists() {
            return Ok(None);
        }
        let path = self.path_for(id);
        if !path.exists() {
            return Ok(None);
        }
        if !self.lock_path_for(id).exists() {
            let encoded = fs::read_to_string(path)?;
            let ciphertext = base64::engine::general_purpose::STANDARD
                .decode(encoded.trim())
                .map_err(|error| AdapterError::Storage(error.to_string()))?;
            let plaintext = self.storage()?.decrypt(&ciphertext)?;
            let value = String::from_utf8(plaintext)
                .map_err(|error| AdapterError::Storage(error.to_string()))?;
            return Ok(Some(value));
        }

        self.with_shared_lock(id, |store| {
            let path = store.path_for(id);
            if !path.exists() {
                return Ok(None);
            }

            let encoded = fs::read_to_string(path)?;
            let ciphertext = base64::engine::general_purpose::STANDARD
                .decode(encoded.trim())
                .map_err(|error| AdapterError::Storage(error.to_string()))?;
            let plaintext = store.storage()?.decrypt(&ciphertext)?;
            let value = String::from_utf8(plaintext)
                .map_err(|error| AdapterError::Storage(error.to_string()))?;
            Ok(Some(value))
        })
    }

    fn delete(&self, id: &BindingId) -> Result<bool> {
        self.with_exclusive_lock(id, |store| {
            let path = store.path_for(id);
            if !path.exists() {
                return Ok(false);
            }

            fs::remove_file(path)?;
            Ok(true)
        })
    }

    fn get_read(&self, id: &BindingId) -> Result<SecretRead> {
        // The encrypted store always returns real plaintext via `get`,
        // so Present is the only non-Absent outcome. A real secret that
        // happens to equal `"<redacted>"` in bytes is returned as
        // `Present("<redacted>")` here — *not* as `Redacted` — so the
        // typed API is collision-free on read-write stores.
        Ok(match self.get(id)? {
            Some(value) => SecretRead::Present(value),
            None => SecretRead::Absent,
        })
    }
}

impl SecretStore for ReadOnlyEncryptedFileSecretStore {
    fn set(&self, id: &BindingId, _secret: &str) -> Result<()> {
        Err(AdapterError::Storage(format!(
            "read-only secret store cannot set `{id:?}`"
        )))
    }

    fn get(&self, id: &BindingId) -> Result<Option<String>> {
        if !self.dir.exists() {
            return Ok(None);
        }
        let path = self.path_for(id);
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(REDACTED_PLACEHOLDER.to_string()))
    }

    fn delete(&self, id: &BindingId) -> Result<bool> {
        Err(AdapterError::Storage(format!(
            "read-only secret store cannot delete `{id:?}`"
        )))
    }

    fn get_read(&self, id: &BindingId) -> Result<SecretRead> {
        // Bypass the string sentinel — report Redacted directly so a
        // stored secret whose bytes are literally `"<redacted>"` can
        // still be distinguished from "exists but not handed over."
        if !self.dir.exists() {
            return Ok(SecretRead::Absent);
        }
        if !self.path_for(id).exists() {
            return Ok(SecretRead::Absent);
        }
        Ok(SecretRead::Redacted)
    }
}

/// Per-id outcome that the in-memory store will report.
///
/// `Material(String)` is the normal path — real plaintext stored and
/// returned. `Redacted` is an explicit inspection simulation: `get`
/// returns `Some(REDACTED_PLACEHOLDER)` for legacy callers, `get_read`
/// returns `SecretRead::Redacted`. Tests that want to exercise the
/// redacted-state code path should use
/// [`MemorySecretStore::mark_redacted`] rather than writing the
/// sentinel string via `set` — writing the sentinel via `set` now
/// round-trips as `Present(<redacted>)` through the typed API, per
/// the design that makes the sentinel collision-free.
#[derive(Debug, Clone)]
enum MemoryEntry {
    Material(String),
    Redacted,
}

#[derive(Debug, Default)]
pub struct MemorySecretStore {
    values: Mutex<HashMap<BindingId, MemoryEntry>>,
}

impl MemorySecretStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark an entry as redacted — `get_read` will return
    /// [`SecretRead::Redacted`] and the legacy `get` will return
    /// `Some(REDACTED_PLACEHOLDER)`. Test-only: mirrors what a
    /// real [`ReadOnlyEncryptedFileSecretStore`] does without
    /// requiring the test to spin up a filesystem-backed store.
    pub fn mark_redacted(&self, id: &BindingId) -> Result<()> {
        self.values
            .lock()
            .map_err(|_| AdapterError::Storage("secret store mutex poisoned".to_string()))?
            .insert(id.clone(), MemoryEntry::Redacted);
        Ok(())
    }
}

impl SecretStore for MemorySecretStore {
    fn set(&self, id: &BindingId, secret: &str) -> Result<()> {
        self.values
            .lock()
            .map_err(|_| AdapterError::Storage("secret store mutex poisoned".to_string()))?
            .insert(id.clone(), MemoryEntry::Material(secret.to_string()));
        Ok(())
    }

    fn get(&self, id: &BindingId) -> Result<Option<String>> {
        Ok(self
            .values
            .lock()
            .map_err(|_| AdapterError::Storage("secret store mutex poisoned".to_string()))?
            .get(id)
            .map(|entry| match entry {
                MemoryEntry::Material(value) => value.clone(),
                MemoryEntry::Redacted => REDACTED_PLACEHOLDER.to_string(),
            }))
    }

    fn delete(&self, id: &BindingId) -> Result<bool> {
        Ok(self
            .values
            .lock()
            .map_err(|_| AdapterError::Storage("secret store mutex poisoned".to_string()))?
            .remove(id)
            .is_some())
    }

    fn get_read(&self, id: &BindingId) -> Result<SecretRead> {
        // Stored `Material("<redacted>")` round-trips as Present, not
        // Redacted — the typed API is collision-free by construction.
        // Only explicit `mark_redacted` surfaces `SecretRead::Redacted`.
        Ok(self
            .values
            .lock()
            .map_err(|_| AdapterError::Storage("secret store mutex poisoned".to_string()))?
            .get(id)
            .map_or(SecretRead::Absent, |entry| match entry {
                MemoryEntry::Material(value) => SecretRead::Present(value.clone()),
                MemoryEntry::Redacted => SecretRead::Redacted,
            }))
    }
}

fn hash_id(id: &BindingId) -> String {
    let digest = Sha256::digest(id.as_str().as_bytes());
    digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn temp_path_for(path: &Path) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let pid = std::process::id();
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("secret");
    path.with_file_name(format!(".{file_name}.{pid}.{nonce}.tmp"))
}

#[cfg(unix)]
fn set_dir_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_dir_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_store_round_trip() {
        let store = MemorySecretStore::new();
        let id = BindingId::new("npm:default");

        store.set(&id, "token").expect("set");
        assert_eq!(store.get(&id).expect("get"), Some("token".to_string()));
        assert!(store.delete(&id).expect("delete"));
        assert_eq!(store.get(&id).expect("get"), None);
    }

    #[test]
    fn redacted_placeholder_constant_is_not_empty() {
        assert!(!REDACTED_PLACEHOLDER.is_empty());
    }

    #[test]
    fn redacted_placeholder_is_recognizable() {
        // The placeholder should be a clearly non-secret sentinel value
        assert_eq!(REDACTED_PLACEHOLDER, "<redacted>");
    }

    #[test]
    fn get_read_on_memory_store_wraps_present() {
        let store = MemorySecretStore::new();
        let id = BindingId::new("npm:tm");
        store.set(&id, "real-token").unwrap();
        match store.get_read(&id).unwrap() {
            SecretRead::Present(value) => assert_eq!(value, "real-token"),
            other => panic!("expected Present, got {other:?}"),
        }
    }

    #[test]
    fn get_read_on_memory_store_wraps_absent() {
        let store = MemorySecretStore::new();
        let id = BindingId::new("npm:missing");
        assert_eq!(store.get_read(&id).unwrap(), SecretRead::Absent);
    }

    #[test]
    fn get_read_on_memory_store_returns_present_even_for_sentinel_bytes() {
        // A secret that literally equals "<redacted>" must not be
        // misclassified as Redacted — that's the whole point of the
        // typed API.
        let store = MemorySecretStore::new();
        let id = BindingId::new("npm:collision");
        store.set(&id, REDACTED_PLACEHOLDER).unwrap();
        match store.get_read(&id).unwrap() {
            SecretRead::Present(value) => assert_eq!(value, REDACTED_PLACEHOLDER),
            other => panic!("expected Present(<redacted>), got {other:?}"),
        }
    }

    #[test]
    fn get_read_on_read_only_store_returns_redacted_for_existing_entry() {
        let dir = tempfile::tempdir().expect("temp dir");
        let secrets_dir = dir.path().join("secrets");
        fs::create_dir_all(&secrets_dir).expect("mkdir");

        let store = ReadOnlyEncryptedFileSecretStore {
            dir: secrets_dir.clone(),
        };
        let id = BindingId::new("npm:ro-collision");
        fs::write(store.path_for(&id), b"ignored-ciphertext").unwrap();

        assert_eq!(store.get_read(&id).unwrap(), SecretRead::Redacted);
    }

    #[test]
    fn get_read_on_read_only_store_returns_absent_when_no_entry() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = ReadOnlyEncryptedFileSecretStore {
            dir: dir.path().join("secrets"),
        };
        let id = BindingId::new("npm:missing");
        assert_eq!(store.get_read(&id).unwrap(), SecretRead::Absent);
    }

    #[test]
    fn secret_read_helpers() {
        assert!(SecretRead::Present("t".into()).is_present());
        assert!(SecretRead::Redacted.is_redacted());
        assert!(SecretRead::Absent.is_absent());
        assert_eq!(
            SecretRead::Present("t".into()).into_present(),
            Some("t".into())
        );
        assert_eq!(SecretRead::Redacted.into_present(), None);
        assert_eq!(SecretRead::Absent.into_present(), None);
    }

    #[test]
    fn read_only_store_returns_redacted_for_existing_secret() {
        let dir = tempfile::tempdir().expect("temp dir");
        let secrets_dir = dir.path().join("secrets");
        fs::create_dir_all(&secrets_dir).expect("mkdir");

        let store = ReadOnlyEncryptedFileSecretStore {
            dir: secrets_dir.clone(),
        };
        let id = BindingId::new("npm:test");
        let secret_path = store.path_for(&id);

        // Write some dummy ciphertext so the file exists
        fs::write(&secret_path, "dummy-encrypted-data").expect("write");

        let result = store.get(&id).expect("get");
        assert_eq!(result, Some(REDACTED_PLACEHOLDER.to_string()));
    }

    #[test]
    fn read_only_store_returns_none_when_no_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let secrets_dir = dir.path().join("secrets");
        fs::create_dir_all(&secrets_dir).expect("mkdir");

        let store = ReadOnlyEncryptedFileSecretStore { dir: secrets_dir };
        let id = BindingId::new("npm:nonexistent");

        let result = store.get(&id).expect("get");
        assert_eq!(result, None);
    }

    #[test]
    fn read_only_store_returns_none_when_dir_missing() {
        let dir = tempfile::tempdir().expect("temp dir");
        let secrets_dir = dir.path().join("does-not-exist");

        let store = ReadOnlyEncryptedFileSecretStore { dir: secrets_dir };
        let id = BindingId::new("npm:whatever");

        let result = store.get(&id).expect("get");
        assert_eq!(result, None);
    }

    #[test]
    fn read_only_store_set_returns_error() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = ReadOnlyEncryptedFileSecretStore {
            dir: dir.path().to_path_buf(),
        };
        let id = BindingId::new("npm:test");

        let result = store.set(&id, "secret");
        assert!(result.is_err());
    }

    #[test]
    fn read_only_store_delete_returns_error() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = ReadOnlyEncryptedFileSecretStore {
            dir: dir.path().to_path_buf(),
        };
        let id = BindingId::new("npm:test");

        let result = store.delete(&id);
        assert!(result.is_err());
    }

    #[test]
    fn is_redacted_placeholder_true_for_sentinel() {
        assert!(is_redacted_placeholder(REDACTED_PLACEHOLDER));
    }

    #[test]
    fn is_redacted_placeholder_false_for_empty_string() {
        assert!(!is_redacted_placeholder(""));
    }

    #[test]
    fn is_redacted_placeholder_false_for_other_strings() {
        assert!(!is_redacted_placeholder("real-token"));
        assert!(!is_redacted_placeholder("<REDACTED>"));
        assert!(!is_redacted_placeholder("redacted"));
    }

    #[test]
    fn secret_read_is_present_false_for_redacted_and_absent() {
        assert!(!SecretRead::Redacted.is_present());
        assert!(!SecretRead::Absent.is_present());
    }

    #[test]
    fn secret_read_is_redacted_false_for_present_and_absent() {
        assert!(!SecretRead::Present("x".into()).is_redacted());
        assert!(!SecretRead::Absent.is_redacted());
    }

    #[test]
    fn secret_read_is_absent_false_for_present_and_redacted() {
        assert!(!SecretRead::Present("x".into()).is_absent());
        assert!(!SecretRead::Redacted.is_absent());
    }

    #[test]
    fn secret_read_into_present_returns_value() {
        let result = SecretRead::Present("my-token".into()).into_present();
        assert_eq!(result, Some("my-token".into()));
    }

    #[test]
    fn secret_read_clone_preserves_variant() {
        let p = SecretRead::Present("v".into());
        assert_eq!(p.clone(), p);
        assert_eq!(SecretRead::Redacted.clone(), SecretRead::Redacted);
        assert_eq!(SecretRead::Absent.clone(), SecretRead::Absent);
    }

    #[test]
    fn memory_store_mark_redacted_makes_get_read_return_redacted() {
        let store = MemorySecretStore::new();
        let id = BindingId::new("npm:marked");
        store.mark_redacted(&id).expect("mark_redacted");
        assert_eq!(store.get_read(&id).expect("get_read"), SecretRead::Redacted);
    }

    #[test]
    fn memory_store_mark_redacted_makes_legacy_get_return_sentinel() {
        let store = MemorySecretStore::new();
        let id = BindingId::new("npm:legacy");
        store.mark_redacted(&id).expect("mark_redacted");
        assert_eq!(
            store.get(&id).expect("get"),
            Some(REDACTED_PLACEHOLDER.to_string())
        );
    }

    #[test]
    fn memory_store_get_nonexistent_returns_none() {
        let store = MemorySecretStore::new();
        let id = BindingId::new("npm:nonexistent");

        assert_eq!(store.get(&id).expect("get"), None);
    }

    #[test]
    fn memory_store_delete_nonexistent_returns_false() {
        let store = MemorySecretStore::new();
        let id = BindingId::new("npm:nonexistent");

        assert!(!store.delete(&id).expect("delete"));
    }

    #[test]
    fn memory_store_set_overwrites() {
        let store = MemorySecretStore::new();
        let id = BindingId::new("npm:default");

        store.set(&id, "first").expect("set");
        store.set(&id, "second").expect("set");
        assert_eq!(store.get(&id).expect("get"), Some("second".to_string()));
    }

    // --- EncryptedFileSecretStore tests ---

    fn make_encrypted_store() -> (tempfile::TempDir, EncryptedFileSecretStore) {
        let dir = tempfile::tempdir().expect("temp dir");
        let secrets_dir = dir.path().join("secrets");
        let storage = enclaveapp_app_storage::mock::MockEncryptionStorage::new();
        let store = EncryptedFileSecretStore::with_storage_for_test(secrets_dir, Box::new(storage));
        (dir, store)
    }

    #[test]
    fn encrypted_store_round_trip_same_instance() {
        let (_dir, store) = make_encrypted_store();
        let id = BindingId::new("test:round-trip");
        store.set(&id, "secret-value").expect("set");
        let result = store.get(&id).expect("get");
        assert_eq!(result, Some("secret-value".to_string()));
    }

    #[test]
    fn encrypted_store_get_nonexistent_returns_none() {
        let (_dir, store) = make_encrypted_store();
        let id = BindingId::new("test:missing");
        assert_eq!(store.get(&id).expect("get"), None);
    }

    #[test]
    fn encrypted_store_delete_removes_entry() {
        let (_dir, store) = make_encrypted_store();
        let id = BindingId::new("test:delete-me");
        store.set(&id, "bye").expect("set");
        assert!(store.delete(&id).expect("delete"));
        assert_eq!(store.get(&id).expect("get after delete"), None);
    }

    #[test]
    fn encrypted_store_delete_nonexistent_returns_false() {
        let (_dir, store) = make_encrypted_store();
        let id = BindingId::new("test:phantom");
        assert!(!store.delete(&id).expect("delete non-existent"));
    }

    #[test]
    fn encrypted_store_overwrite_returns_latest_value() {
        let (_dir, store) = make_encrypted_store();
        let id = BindingId::new("test:overwrite");
        store.set(&id, "v1").expect("set v1");
        store.set(&id, "v2").expect("set v2");
        assert_eq!(store.get(&id).expect("get"), Some("v2".to_string()));
    }

    #[test]
    fn encrypted_store_get_read_present() {
        let (_dir, store) = make_encrypted_store();
        let id = BindingId::new("test:get-read-present");
        store.set(&id, "data").expect("set");
        assert!(matches!(
            store.get_read(&id).expect("get_read"),
            SecretRead::Present(_)
        ));
    }

    #[test]
    fn encrypted_store_get_read_absent() {
        let (_dir, store) = make_encrypted_store();
        let id = BindingId::new("test:get-read-absent");
        assert_eq!(store.get_read(&id).expect("get_read"), SecretRead::Absent);
    }

    #[test]
    #[cfg(unix)]
    fn encrypted_store_creates_dir_with_restricted_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("temp dir");
        let secrets_dir = dir.path().join("secrets");
        let storage = enclaveapp_app_storage::mock::MockEncryptionStorage::new();
        let store =
            EncryptedFileSecretStore::with_storage_for_test(secrets_dir.clone(), Box::new(storage));
        let id = BindingId::new("test:perms");
        store.set(&id, "check-perms").expect("set");
        let meta = fs::metadata(&secrets_dir).expect("metadata");
        assert_eq!(meta.permissions().mode() & 0o777, 0o700);
    }

    #[test]
    #[cfg(unix)]
    fn encrypted_store_creates_file_with_restricted_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("temp dir");
        let secrets_dir = dir.path().join("secrets");
        let storage = enclaveapp_app_storage::mock::MockEncryptionStorage::new();
        let store =
            EncryptedFileSecretStore::with_storage_for_test(secrets_dir.clone(), Box::new(storage));
        let id = BindingId::new("test:file-perms");
        store.set(&id, "value").expect("set");
        let path = store.path_for(&id);
        let meta = fs::metadata(&path).expect("file metadata");
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn encrypted_store_persistence_across_fresh_instance() {
        // Write via one store instance; read back via a fresh instance that
        // shares the same directory and deterministic MockEncryptionStorage key.
        let dir = tempfile::tempdir().expect("temp dir");
        let secrets_dir = dir.path().join("secrets");

        // Use for_app (deterministic key) so both instances share the same key.
        use enclaveapp_app_storage::mock::MockEncryptionStorage;
        let id = BindingId::new("test:persist");

        let store1 = EncryptedFileSecretStore::with_storage_for_test(
            secrets_dir.clone(),
            Box::new(MockEncryptionStorage::for_app("test")),
        );
        store1.set(&id, "persisted").expect("set");

        let store2 = EncryptedFileSecretStore::with_storage_for_test(
            secrets_dir.clone(),
            Box::new(MockEncryptionStorage::for_app("test")),
        );
        assert_eq!(
            store2.get(&id).expect("get from fresh instance"),
            Some("persisted".to_string())
        );
    }

    #[test]
    fn encrypted_store_get_returns_error_for_truncated_file() {
        let (_dir, store) = make_encrypted_store();
        let id = BindingId::new("test:truncated");
        store.set(&id, "some value").expect("set");
        // Overwrite with zero bytes so base64-decode yields empty plaintext,
        // which will fail the AES-GCM authentication tag check in decrypt().
        fs::write(store.path_for(&id), b"").expect("truncate");
        let result = store.get(&id);
        assert!(result.is_err(), "truncated file must return Err, not panic");
    }

    #[test]
    fn encrypted_store_get_returns_error_for_corrupt_ciphertext() {
        let (_dir, store) = make_encrypted_store();
        let id = BindingId::new("test:corrupt");
        store.set(&id, "some value").expect("set");
        // Random bytes that are not valid base64 → base64 decode error.
        fs::write(store.path_for(&id), b"this is not valid ciphertext at all").expect("corrupt");
        let result = store.get(&id);
        assert!(
            result.is_err(),
            "corrupt ciphertext must return Err, not panic"
        );
    }

    #[test]
    fn encrypted_store_concurrent_writes_leave_file_valid() {
        use enclaveapp_app_storage::mock::MockEncryptionStorage;
        use std::sync::Arc;

        let dir = tempfile::tempdir().expect("temp dir");
        let secrets_dir = dir.path().join("secrets");
        let id = BindingId::new("test:concurrent");

        // Two stores sharing the same directory and deterministic key so
        // either can decrypt the other's output.
        let store_a = Arc::new(EncryptedFileSecretStore::with_storage_for_test(
            secrets_dir.clone(),
            Box::new(MockEncryptionStorage::for_app("test")),
        ));
        let store_b = Arc::new(EncryptedFileSecretStore::with_storage_for_test(
            secrets_dir.clone(),
            Box::new(MockEncryptionStorage::for_app("test")),
        ));

        let id_a = id.clone();
        let id_b = id.clone();
        let sa = Arc::clone(&store_a);
        let sb = Arc::clone(&store_b);

        let t_a = std::thread::spawn(move || sa.set(&id_a, "value-a").expect("set-a"));
        let t_b = std::thread::spawn(move || sb.set(&id_b, "value-b").expect("set-b"));

        t_a.join().expect("thread-a panicked");
        t_b.join().expect("thread-b panicked");

        // After both writes, the file must be readable and contain one of the two values.
        let reader = EncryptedFileSecretStore::with_storage_for_test(
            secrets_dir.clone(),
            Box::new(MockEncryptionStorage::for_app("test")),
        );
        let result = reader.get(&id).expect("get after concurrent writes");
        assert!(
            result == Some("value-a".to_string()) || result == Some("value-b".to_string()),
            "expected value-a or value-b, got {result:?}"
        );
    }
}
