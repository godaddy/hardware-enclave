#![cfg_attr(test, allow(clippy::panic, clippy::unwrap_used))]

use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{AdapterError, Result};
use crate::types::{BindingId, BindingRecord};
use fs4::fs_std::FileExt;

pub trait BindingStore {
    fn list(&self) -> Result<Vec<BindingRecord>>;
    fn get(&self, id: &BindingId) -> Result<Option<BindingRecord>>;
    fn upsert(&self, record: BindingRecord) -> Result<()>;
    fn delete(&self, id: &BindingId) -> Result<bool>;
    fn mutate<T, F>(&self, update: F) -> Result<T>
    where
        F: FnOnce(&mut Vec<BindingRecord>) -> Result<T>;
}

#[derive(Debug, Clone)]
pub struct JsonFileBindingStore {
    path: PathBuf,
}

impl JsonFileBindingStore {
    pub fn for_app(app_name: &str) -> Result<Self> {
        let path = app_data_dir(app_name)?.join("bindings.json");
        Ok(Self { path })
    }

    pub fn at_path(path: PathBuf) -> Self {
        Self { path }
    }

    fn lock_path(&self) -> PathBuf {
        self.path.with_extension("lock")
    }

    fn read_all_unlocked(&self) -> Result<Vec<BindingRecord>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }

        let contents = fs::read_to_string(&self.path)?;
        if contents.trim().is_empty() {
            return Ok(Vec::new());
        }

        Ok(serde_json::from_str(&contents)?)
    }

    fn write_all_unlocked(&self, records: &[BindingRecord]) -> Result<()> {
        ensure_parent_dir(&self.path)?;
        let json = serde_json::to_string_pretty(records)?;
        let temp_path = temp_path_for(&self.path);
        {
            use std::io::Write;
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&temp_path)?;
            file.write_all(json.as_bytes())?;
            file.flush()?;
        }
        fs::rename(&temp_path, &self.path)?;
        Ok(())
    }

    fn with_shared_lock<T>(&self, work: impl FnOnce(&Self) -> Result<T>) -> Result<T> {
        let lock_path = self.lock_path();
        if !lock_path.exists() {
            return work(self);
        }

        let file = OpenOptions::new()
            .read(true)
            .write(true)
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

    fn with_exclusive_lock<T>(&self, work: impl FnOnce(&Self) -> Result<T>) -> Result<T> {
        ensure_parent_dir(&self.lock_path())?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.lock_path())?;
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

#[derive(Debug, Default)]
pub struct MemoryBindingStore {
    records: Mutex<Vec<BindingRecord>>,
}

impl MemoryBindingStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl BindingStore for MemoryBindingStore {
    fn list(&self) -> Result<Vec<BindingRecord>> {
        Ok(self
            .records
            .lock()
            .map_err(|_| AdapterError::Storage("binding store mutex poisoned".to_string()))?
            .clone())
    }

    fn get(&self, id: &BindingId) -> Result<Option<BindingRecord>> {
        Ok(self
            .records
            .lock()
            .map_err(|_| AdapterError::Storage("binding store mutex poisoned".to_string()))?
            .iter()
            .find(|record| &record.id == id)
            .cloned())
    }

    fn upsert(&self, record: BindingRecord) -> Result<()> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| AdapterError::Storage("binding store mutex poisoned".to_string()))?;
        if let Some(existing) = records.iter_mut().find(|entry| entry.id == record.id) {
            *existing = record;
        } else {
            records.push(record);
        }
        Ok(())
    }

    fn delete(&self, id: &BindingId) -> Result<bool> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| AdapterError::Storage("binding store mutex poisoned".to_string()))?;
        let before = records.len();
        records.retain(|record| &record.id != id);
        Ok(before != records.len())
    }

    fn mutate<T, F>(&self, update: F) -> Result<T>
    where
        F: FnOnce(&mut Vec<BindingRecord>) -> Result<T>,
    {
        let mut records = self
            .records
            .lock()
            .map_err(|_| AdapterError::Storage("binding store mutex poisoned".to_string()))?;
        update(&mut records)
    }
}

/// Derive the conventional config dir environment variable name for an app.
///
/// Converts hyphens to underscores and uppercases: `npmenc` -> `NPMENC_CONFIG_DIR`.
fn default_config_dir_env(app_name: &str) -> String {
    let upper = app_name.to_uppercase().replace('-', "_");
    format!("{upper}_CONFIG_DIR")
}

/// Resolve the application data directory.
///
/// Checks the conventional `{APP_NAME_UPPER}_CONFIG_DIR` environment variable
/// first (e.g., `NPMENC_CONFIG_DIR` for app_name "npmenc"), then falls back to
/// the platform-standard config directory.
pub fn app_data_dir(app_name: &str) -> Result<PathBuf> {
    app_data_dir_with_env(app_name, None)
}

/// Resolve the application data directory with a custom env var override.
///
/// When `env_override` is `Some`, that environment variable name is checked
/// first. Otherwise the default `{APP_NAME_UPPER}_CONFIG_DIR` variable is
/// consulted. Falls back to the platform-standard config directory.
pub fn app_data_dir_with_env(app_name: &str, env_override: Option<&str>) -> Result<PathBuf> {
    let default_env = default_config_dir_env(app_name);
    let env_key = env_override.unwrap_or(&default_env);
    if let Some(path) = std::env::var_os(env_key) {
        let dir = PathBuf::from(path).join(app_name);
        return Ok(dir);
    }

    let config_dir = dirs::config_dir().ok_or(AdapterError::MissingConfigDir)?;
    Ok(config_dir.join(app_name))
}

impl BindingStore for JsonFileBindingStore {
    fn list(&self) -> Result<Vec<BindingRecord>> {
        self.with_shared_lock(|store| store.read_all_unlocked())
    }

    fn get(&self, id: &BindingId) -> Result<Option<BindingRecord>> {
        self.with_shared_lock(|store| {
            Ok(store
                .read_all_unlocked()?
                .into_iter()
                .find(|record| &record.id == id))
        })
    }

    fn upsert(&self, record: BindingRecord) -> Result<()> {
        self.with_exclusive_lock(|store| {
            let mut records = store.read_all_unlocked()?;
            if let Some(existing) = records.iter_mut().find(|entry| entry.id == record.id) {
                *existing = record;
            } else {
                records.push(record);
            }
            store.write_all_unlocked(&records)
        })
    }

    fn delete(&self, id: &BindingId) -> Result<bool> {
        self.with_exclusive_lock(|store| {
            let mut records = store.read_all_unlocked()?;
            let before = records.len();
            records.retain(|record| &record.id != id);
            if before == records.len() {
                return Ok(false);
            }

            store.write_all_unlocked(&records)?;
            Ok(true)
        })
    }

    fn mutate<T, F>(&self, update: F) -> Result<T>
    where
        F: FnOnce(&mut Vec<BindingRecord>) -> Result<T>,
    {
        self.with_exclusive_lock(|store| {
            let mut records = store.read_all_unlocked()?;
            let result = update(&mut records)?;
            store.write_all_unlocked(&records)?;
            Ok(result)
        })
    }
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
        .unwrap_or("state");
    path.with_file_name(format!(".{file_name}.{pid}.{nonce}.tmp"))
}

fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        set_dir_permissions(parent)?;
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::{LazyLock, Mutex};

    use tempfile::TempDir;

    use super::*;

    /// Serialize env-var-mutating tests so they don't race.
    static ENV_MUTEX: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    #[test]
    fn default_config_dir_env_derives_correctly() {
        assert_eq!(default_config_dir_env("npmenc"), "NPMENC_CONFIG_DIR");
        assert_eq!(default_config_dir_env("awsenc"), "AWSENC_CONFIG_DIR");
        assert_eq!(default_config_dir_env("sso-jwt"), "SSO_JWT_CONFIG_DIR");
        assert_eq!(default_config_dir_env("my-app"), "MY_APP_CONFIG_DIR");
    }

    #[test]
    fn upserts_and_reads_records() {
        let dir = TempDir::new().expect("temp dir");
        let store = JsonFileBindingStore::at_path(dir.path().join("bindings.json"));

        let record = BindingRecord {
            id: BindingId::new("npm:default"),
            label: "default".into(),
            target: "https://registry.npmjs.org/".into(),
            secret_env_var: "NPM_TOKEN_DEFAULT".into(),
            metadata: BTreeMap::new(),
        };

        store.upsert(record.clone()).expect("write");
        let loaded = store.get(&record.id).expect("get").expect("record");
        assert_eq!(loaded, record);
    }

    #[test]
    fn memory_store_round_trip() {
        let store = MemoryBindingStore::new();
        let record = BindingRecord {
            id: BindingId::new("npm:default"),
            label: "default".into(),
            target: "https://registry.npmjs.org/".into(),
            secret_env_var: "NPM_TOKEN_DEFAULT".into(),
            metadata: BTreeMap::new(),
        };

        store.upsert(record.clone()).expect("upsert");
        assert_eq!(store.list().expect("list"), vec![record.clone()]);
        assert!(store.delete(&record.id).expect("delete"));
    }

    #[test]
    fn app_data_dir_with_env_respects_override() {
        let _lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let dir = TempDir::new().expect("temp dir");
        let env_key = "NPMENC_TEST_OVERRIDE_1";
        let previous = std::env::var_os(env_key);
        std::env::set_var(env_key, dir.path());

        let result = app_data_dir_with_env("test-app", Some(env_key));

        match previous {
            Some(val) => std::env::set_var(env_key, val),
            None => std::env::remove_var(env_key),
        }

        assert_eq!(result.expect("ok"), dir.path().join("test-app"));
    }

    #[test]
    fn app_data_dir_with_env_default_uses_derived_env_var() {
        let _lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let dir = TempDir::new().expect("temp dir");
        // For app_name "test-app", the derived env var is TEST_APP_CONFIG_DIR
        let env_key = "TEST_APP_CONFIG_DIR";
        let previous = std::env::var_os(env_key);
        std::env::set_var(env_key, dir.path());

        let result = app_data_dir_with_env("test-app", None);

        match previous {
            Some(val) => std::env::set_var(env_key, val),
            None => std::env::remove_var(env_key),
        }

        assert_eq!(result.expect("ok"), dir.path().join("test-app"));
    }

    #[test]
    fn app_data_dir_with_env_falls_through_when_unset() {
        let _lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let env_key = "ADAPTER_TEST_NONEXISTENT_VAR_BINDING";
        let previous = std::env::var_os(env_key);
        std::env::remove_var(env_key);

        // Also ensure the derived default env var is unset so we fall through
        let default_env = "TEST_APP_CONFIG_DIR";
        let prev_default = std::env::var_os(default_env);
        std::env::remove_var(default_env);

        let result = app_data_dir_with_env("test-app", Some(env_key));

        // Restore env vars
        match previous {
            Some(val) => std::env::set_var(env_key, val),
            None => std::env::remove_var(env_key),
        }
        match prev_default {
            Some(val) => std::env::set_var(default_env, val),
            None => std::env::remove_var(default_env),
        }

        // Should still succeed using the platform config dir
        assert!(result.is_ok());
    }

    #[test]
    fn app_data_dir_with_env_joins_app_name() {
        let _lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let dir = TempDir::new().expect("temp dir");
        let env_key = "NPMENC_TEST_JOIN_APP_NAME";
        let previous = std::env::var_os(env_key);
        std::env::set_var(env_key, dir.path());

        let result = app_data_dir_with_env("my-custom-app", Some(env_key));

        match previous {
            Some(val) => std::env::set_var(env_key, val),
            None => std::env::remove_var(env_key),
        }

        let path = result.expect("ok");
        assert!(path.ends_with("my-custom-app"));
        assert!(path.starts_with(dir.path()));
    }

    #[test]
    fn app_data_dir_delegates_to_with_env() {
        // app_data_dir(name) should be identical to app_data_dir_with_env(name, None)
        let _lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        // Derived env var for "adapter-test-delegate" is ADAPTER_TEST_DELEGATE_CONFIG_DIR
        let env_key = "ADAPTER_TEST_DELEGATE_CONFIG_DIR";
        let previous = std::env::var_os(env_key);
        std::env::remove_var(env_key);

        let a = app_data_dir("adapter-test-delegate").expect("a");
        let b = app_data_dir_with_env("adapter-test-delegate", None).expect("b");

        match previous {
            Some(val) => std::env::set_var(env_key, val),
            None => std::env::remove_var(env_key),
        }

        assert_eq!(a, b);
    }

    // --- JsonFileBindingStore CRUD tests ---

    fn make_record(id: &str) -> BindingRecord {
        BindingRecord {
            id: BindingId::new(id),
            label: format!("label-{id}"),
            target: "https://example.com/".into(),
            secret_env_var: "SECRET_VAR".into(),
            metadata: BTreeMap::new(),
        }
    }

    fn file_store(dir: &TempDir) -> JsonFileBindingStore {
        JsonFileBindingStore::at_path(dir.path().join("bindings.json"))
    }

    #[test]
    fn json_store_persistence_round_trip() {
        let dir = TempDir::new().expect("temp dir");
        let store = file_store(&dir);
        let rec = make_record("npm:default");
        store.upsert(rec.clone()).expect("upsert");

        let fresh = file_store(&dir);
        let loaded = fresh.get(&rec.id).expect("get").expect("record");
        assert_eq!(loaded, rec);
    }

    #[test]
    fn json_store_list_returns_all_records() {
        let dir = TempDir::new().expect("temp dir");
        let store = file_store(&dir);
        store.upsert(make_record("a")).expect("upsert a");
        store.upsert(make_record("b")).expect("upsert b");
        store.upsert(make_record("c")).expect("upsert c");
        let list = store.list().expect("list");
        assert_eq!(list.len(), 3);
    }

    #[test]
    fn json_store_list_on_empty_directory_returns_empty_vec() {
        let dir = TempDir::new().expect("temp dir");
        let store = file_store(&dir);
        assert!(store.list().expect("list").is_empty());
    }

    #[test]
    fn json_store_get_nonexistent_returns_none() {
        let dir = TempDir::new().expect("temp dir");
        let store = file_store(&dir);
        let id = BindingId::new("npm:ghost");
        assert!(store.get(&id).expect("get").is_none());
    }

    #[test]
    fn json_store_delete_removes_record() {
        let dir = TempDir::new().expect("temp dir");
        let store = file_store(&dir);
        let rec = make_record("npm:del");
        store.upsert(rec.clone()).expect("upsert");
        assert!(store.delete(&rec.id).expect("delete"));
        assert!(store.get(&rec.id).expect("get after delete").is_none());
        assert!(store.list().expect("list after delete").is_empty());
    }

    #[test]
    fn json_store_delete_nonexistent_returns_false() {
        let dir = TempDir::new().expect("temp dir");
        let store = file_store(&dir);
        let id = BindingId::new("npm:never-existed");
        assert!(!store.delete(&id).expect("delete non-existent"));
    }

    #[test]
    fn json_store_mutate_applies_and_persists_change() {
        let dir = TempDir::new().expect("temp dir");
        let store = file_store(&dir);
        let mut rec = make_record("npm:mutate");
        store.upsert(rec.clone()).expect("upsert");

        store
            .mutate::<(), _>(|records| {
                if let Some(r) = records.iter_mut().find(|r| r.id == rec.id) {
                    r.label = "mutated-label".into();
                }
                Ok(())
            })
            .expect("mutate");

        rec.label = "mutated-label".into();
        let loaded = store.get(&rec.id).expect("get").expect("record");
        assert_eq!(loaded.label, "mutated-label");
    }

    #[test]
    fn json_store_mutate_nonexistent_id_leaves_store_unchanged() {
        let dir = TempDir::new().expect("temp dir");
        let store = file_store(&dir);
        store.upsert(make_record("npm:present")).expect("upsert");

        // Mutate that searches for a non-existent id is a no-op, not an error.
        let result = store.mutate::<(), _>(|records| {
            if let Some(r) = records
                .iter_mut()
                .find(|r| r.id == BindingId::new("npm:ghost"))
            {
                r.label = "changed".into();
            }
            Ok(())
        });
        assert!(result.is_ok());
        assert_eq!(store.list().expect("list").len(), 1);
    }

    #[test]
    fn json_store_upsert_overwrites_existing_record() {
        let dir = TempDir::new().expect("temp dir");
        let store = file_store(&dir);
        let mut rec = make_record("npm:upsert");
        store.upsert(rec.clone()).expect("first upsert");
        rec.label = "updated-label".into();
        store.upsert(rec.clone()).expect("second upsert");
        let list = store.list().expect("list");
        assert_eq!(list.len(), 1, "upsert must not duplicate the record");
        assert_eq!(list[0].label, "updated-label");
    }

    #[test]
    #[cfg(unix)]
    fn json_store_creates_parent_dir_with_restricted_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().expect("temp dir");
        let nested = dir.path().join("nested-dir");
        let store = JsonFileBindingStore::at_path(nested.join("bindings.json"));
        store.upsert(make_record("npm:perm-test")).expect("upsert");
        let meta = fs::metadata(&nested).expect("metadata");
        assert_eq!(meta.permissions().mode() & 0o777, 0o700);
    }

    /// A truncated (corrupt) JSON file on disk must produce a parse error on
    /// all access paths — no panic. Deleting the corrupt file restores normal
    /// operation.
    #[test]
    fn json_store_corrupt_file_returns_error_no_panic() {
        let dir = TempDir::new().expect("temp dir");
        let store = file_store(&dir);
        // Seed a valid record so the file exists.
        store.upsert(make_record("npm:seed")).expect("upsert seed");
        // Overwrite with truncated / invalid JSON.
        fs::write(store.path.clone(), b"{[broken json").expect("corrupt");

        // get / list / upsert must all return errors, not panic.
        assert!(
            store.list().is_err(),
            "list on corrupt file must return Err"
        );
        assert!(
            store.get(&BindingId::new("npm:seed")).is_err(),
            "get on corrupt file must return Err"
        );
        assert!(
            store.upsert(make_record("npm:new")).is_err(),
            "upsert on corrupt file must return Err (read-before-write fails)"
        );

        // After removing the corrupt file the store is fully operational.
        fs::remove_file(store.path.clone()).expect("remove corrupt file");
        store
            .upsert(make_record("npm:fresh"))
            .expect("upsert after removing corrupt file");
        let list = store.list().expect("list after recovery");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, BindingId::new("npm:fresh"));
    }

    /// `list()` with 1,000+ records must complete without panic and return
    /// the correct count.
    #[test]
    fn json_store_large_record_count_lists_correctly() {
        let dir = TempDir::new().expect("temp dir");
        let store = file_store(&dir);
        for i in 0..1000_usize {
            store
                .upsert(make_record(&format!("npm:bulk-{i}")))
                .expect("upsert");
        }
        let list = store.list().expect("list");
        assert_eq!(list.len(), 1000, "all 1000 records must be present");
    }

    #[test]
    fn json_store_concurrent_upserts_with_different_ids_both_persist() {
        use std::sync::Arc;
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("bindings.json");

        let store1 = Arc::new(JsonFileBindingStore::at_path(path.clone()));
        let store2 = Arc::new(JsonFileBindingStore::at_path(path));

        let rec1 = make_record("npm:thread-1");
        let rec2 = make_record("npm:thread-2");

        let s1 = Arc::clone(&store1);
        let r1 = rec1.clone();
        let t1 = std::thread::spawn(move || s1.upsert(r1).expect("upsert t1"));

        let s2 = Arc::clone(&store2);
        let r2 = rec2.clone();
        let t2 = std::thread::spawn(move || s2.upsert(r2).expect("upsert t2"));

        t1.join().unwrap();
        t2.join().unwrap();

        let list = store1.list().expect("list");
        assert_eq!(
            list.len(),
            2,
            "both records must be present after concurrent upserts"
        );
    }
}
