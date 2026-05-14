use std::fs::{self, OpenOptions};
use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use fs4::fs_std::FileExt;

use crate::binding_store::app_data_dir;

const STATE_MUTATING_PREFIX: &str = "mutating:";
const STATE_STABLE_PREFIX: &str = "stable:";
const STATE_DIRTY_PREFIX: &str = "dirty:";

pub fn with_state_lock<T>(app_name: &str, work: impl FnOnce() -> Result<T>) -> Result<T> {
    #[cfg(test)]
    let _env_lock = crate::test_support::lock_env();
    let app_dir = app_data_dir(app_name)?;
    let lock_path = app_dir.join("state.lock");
    if let Some(parent) = lock_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)?;
    FileExt::lock_exclusive(&file)?;
    let mutation_result = write_state_version(&app_dir, STATE_MUTATING_PREFIX);
    if let Err(error) = mutation_result {
        drop(FileExt::unlock(&file));
        return Err(error);
    }
    let result = match catch_unwind(AssertUnwindSafe(work)) {
        Ok(result) => result,
        Err(panic) => {
            drop(mark_state_dirty(&app_dir));
            drop(FileExt::unlock(&file));
            resume_unwind(panic);
        }
    };
    let version_result = write_state_version(&app_dir, STATE_STABLE_PREFIX);
    let unlock_result = FileExt::unlock(&file);
    let clear_result = if version_result.is_err() {
        Some(clear_state_version(&app_dir))
    } else {
        None
    };
    match (result, version_result, clear_result, unlock_result) {
        (Ok(value), Ok(()), _, Ok(())) => Ok(value),
        (Ok(_), Err(error), Some(Err(clear_error)), _) => Err(anyhow::anyhow!(
            "{error}; additionally failed to clear mutating state marker: {clear_error}"
        )),
        (Err(error), Ok(()), _, _) | (Ok(_), Err(error), _, _) => Err(error),
        (Err(error), Err(version_error), Some(Err(clear_error)), _) => Err(anyhow::anyhow!(
            "{error}; additionally failed to mark managed state stable: {version_error}; additionally failed to clear mutating state marker: {clear_error}"
        )),
        (Err(error), Err(version_error), _, _) => Err(anyhow::anyhow!(
            "{error}; additionally failed to mark managed state stable: {version_error}"
        )),
        (Ok(_), Ok(()), _, Err(error)) => Err(error.into()),
    }
}

pub fn with_state_lock_read_only<T>(app_name: &str, work: impl FnOnce() -> Result<T>) -> Result<T> {
    #[cfg(test)]
    let _env_lock = crate::test_support::lock_env();
    let app_dir = app_data_dir(app_name)?;
    let lock_path = app_dir.join("state.lock");
    recover_stale_mutating_state(&app_dir, &lock_path)?;
    let version_before = read_state_version(&app_dir)?;
    if let Some(error) = read_only_state_error(version_before.as_deref()) {
        return Err(error);
    }
    if !lock_path.exists() {
        if managed_state_exists_without_lock(&app_dir) {
            return Err(anyhow::anyhow!(
                "managed state exists without a global state lock; run a stateful command before inspection"
            ));
        }
        let result = work()?;
        let version_after = read_state_version(&app_dir)?;
        if read_only_state_error(version_after.as_deref()).is_some()
            || version_before != version_after
        {
            return Err(anyhow::anyhow!(
                "managed state changed during inspection; rerun the inspection command"
            ));
        }
        return Ok(result);
    }

    let file = OpenOptions::new().read(true).open(lock_path)?;
    FileExt::lock_shared(&file)?;
    if let Some(error) = read_only_state_error(read_state_version(&app_dir)?.as_deref()) {
        let unlock_result = FileExt::unlock(&file);
        return match unlock_result {
            Ok(()) => Err(error),
            Err(unlock_error) => Err(anyhow::anyhow!(
                "{error}; additionally failed to unlock shared state lock: {unlock_error}"
            )),
        };
    }
    let result = work();
    let unlock_result = FileExt::unlock(&file);
    match (result, unlock_result) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error.into()),
    }
}

fn recover_stale_mutating_state(app_dir: &Path, lock_path: &Path) -> Result<()> {
    let version = read_state_version(app_dir)?;
    if !state_version_is_mutating(version.as_deref()) {
        return Ok(());
    }

    if !lock_path.exists() {
        return mark_state_dirty(app_dir);
    }

    let file = OpenOptions::new().read(true).write(true).open(lock_path)?;
    match FileExt::try_lock_exclusive(&file) {
        Ok(()) => {
            let result = match read_state_version(app_dir)?.as_deref() {
                Some(value) if state_version_is_mutating(Some(value)) => mark_state_dirty(app_dir),
                _ => Ok(()),
            };
            let unlock_result = FileExt::unlock(&file);
            match (result, unlock_result) {
                (Ok(()), Ok(())) => Ok(()),
                (Err(error), Ok(())) => Err(error),
                (Ok(()), Err(error)) => Err(error.into()),
                (Err(error), Err(unlock_error)) => Err(anyhow::anyhow!(
                    "{error}; additionally failed to unlock stale state lock: {unlock_error}"
                )),
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn managed_state_exists_without_lock(app_dir: &Path) -> bool {
    app_dir.join("bindings.json").exists() || app_dir.join("secrets").exists()
}

fn state_version_path(app_dir: &Path) -> PathBuf {
    app_dir.join("state.version")
}

fn read_state_version(app_dir: &Path) -> Result<Option<String>> {
    let path = state_version_path(app_dir);
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(fs::read_to_string(path)?))
}

fn write_state_version(app_dir: &Path, prefix: &str) -> Result<()> {
    let version = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            anyhow::anyhow!("system clock error while updating state version: {error}")
        })?
        .as_nanos()
        .to_string();
    fs::write(state_version_path(app_dir), format!("{prefix}{version}"))?;
    Ok(())
}

fn clear_state_version(app_dir: &Path) -> Result<()> {
    let path = state_version_path(app_dir);
    if !path.exists() {
        return Ok(());
    }
    fs::remove_file(path)?;
    Ok(())
}

fn state_version_is_mutating(version: Option<&str>) -> bool {
    version.is_some_and(|value| value.starts_with(STATE_MUTATING_PREFIX))
}

fn state_version_is_dirty(version: Option<&str>) -> bool {
    version.is_some_and(|value| value.starts_with(STATE_DIRTY_PREFIX))
}

fn read_only_state_error(version: Option<&str>) -> Option<anyhow::Error> {
    if state_version_is_mutating(version) {
        return Some(anyhow::anyhow!(
            "managed state is currently being mutated; rerun the inspection command"
        ));
    }
    if state_version_is_dirty(version) {
        return Some(anyhow::anyhow!(
            "managed state may be inconsistent from a previous failed operation; rerun a stateful command first"
        ));
    }
    None
}

fn mark_state_dirty(app_dir: &Path) -> Result<()> {
    match write_state_version(app_dir, STATE_DIRTY_PREFIX) {
        Ok(()) => Ok(()),
        Err(error) => match clear_state_version(app_dir) {
            Ok(()) => Ok(()),
            Err(clear_error) => Err(anyhow::anyhow!(
                "{error}; additionally failed to clear stale state marker: {clear_error}"
            )),
        },
    }
}

#[cfg(test)]
mod tests {
    use std::panic::catch_unwind;

    use tempfile::TempDir;

    use crate::test_support::{lock_env, EnvVarGuard};

    use super::*;

    const TEST_APP: &str = "testapp";
    const TEST_ENV_VAR: &str = "TESTAPP_CONFIG_DIR";

    #[test]
    fn read_only_lock_detects_unlocked_state_change() {
        let _env_lock = lock_env();
        let dir = TempDir::new().expect("temp dir");
        let _config_guard = EnvVarGuard::set(TEST_ENV_VAR, dir.path());

        let app_dir = app_data_dir(TEST_APP).expect("app dir");
        let result = with_state_lock_read_only(TEST_APP, || {
            fs::create_dir_all(&app_dir).expect("create app dir");
            fs::write(state_version_path(&app_dir), "changed").expect("write version");
            Ok(())
        });

        assert!(result.is_err());
        assert!(result
            .expect_err("version mismatch")
            .to_string()
            .contains("managed state changed during inspection"));
    }

    #[test]
    fn read_only_lock_recovers_stale_mutating_state_without_lock() {
        let _env_lock = lock_env();
        let dir = TempDir::new().expect("temp dir");
        let _config_guard = EnvVarGuard::set(TEST_ENV_VAR, dir.path());

        let app_dir = app_data_dir(TEST_APP).expect("app dir");
        fs::create_dir_all(&app_dir).expect("create app dir");
        fs::write(state_version_path(&app_dir), "mutating:123").expect("write version");

        let result = with_state_lock_read_only(TEST_APP, || Ok(()));

        assert!(result.is_err());
        assert!(result
            .expect_err("dirty version")
            .to_string()
            .contains("may be inconsistent"));
        let version = fs::read_to_string(state_version_path(&app_dir)).expect("state version");
        assert!(version.starts_with(STATE_DIRTY_PREFIX));
    }

    #[test]
    fn read_only_lock_recovers_stale_mutating_state_with_unlocked_lock_file() {
        let _env_lock = lock_env();
        let dir = TempDir::new().expect("temp dir");
        let _config_guard = EnvVarGuard::set(TEST_ENV_VAR, dir.path());

        let app_dir = app_data_dir(TEST_APP).expect("app dir");
        fs::create_dir_all(&app_dir).expect("create app dir");
        fs::write(state_version_path(&app_dir), "mutating:123").expect("write version");
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(app_dir.join("state.lock"))
            .expect("lock file");

        let result = with_state_lock_read_only(TEST_APP, || Ok(()));

        assert!(result.is_err());
        assert!(result
            .expect_err("dirty version")
            .to_string()
            .contains("may be inconsistent"));
        let version = fs::read_to_string(state_version_path(&app_dir)).expect("state version");
        assert!(version.starts_with(STATE_DIRTY_PREFIX));
    }

    #[test]
    #[allow(clippy::panic)]
    fn stateful_lock_marks_state_dirty_on_panic() {
        let _env_lock = lock_env();
        let dir = TempDir::new().expect("temp dir");
        let _config_guard = EnvVarGuard::set(TEST_ENV_VAR, dir.path());

        let panic = catch_unwind(|| {
            drop(with_state_lock(TEST_APP, || -> Result<()> {
                panic!("boom");
            }));
        });
        assert!(panic.is_err());

        let app_dir = app_data_dir(TEST_APP).expect("app dir");
        let version = fs::read_to_string(state_version_path(&app_dir)).expect("state version");
        assert!(version.starts_with(STATE_DIRTY_PREFIX));
    }

    #[test]
    fn read_only_lock_rejects_dirty_state_version() {
        let _env_lock = lock_env();
        let dir = TempDir::new().expect("temp dir");
        let _config_guard = EnvVarGuard::set(TEST_ENV_VAR, dir.path());

        let app_dir = app_data_dir(TEST_APP).expect("app dir");
        fs::create_dir_all(&app_dir).expect("create app dir");
        fs::write(state_version_path(&app_dir), "dirty:123").expect("write version");

        let result = with_state_lock_read_only(TEST_APP, || Ok(()));

        assert!(result.is_err());
        assert!(result
            .expect_err("dirty version")
            .to_string()
            .contains("may be inconsistent"));
    }

    // -----------------------------------------------------------------------
    // Pure helper unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn state_version_is_mutating_with_none_is_false() {
        assert!(!state_version_is_mutating(None));
    }

    #[test]
    fn state_version_is_mutating_with_mutating_prefix_is_true() {
        assert!(state_version_is_mutating(Some("mutating:12345")));
    }

    #[test]
    fn state_version_is_mutating_with_dirty_prefix_is_false() {
        assert!(!state_version_is_mutating(Some("dirty:123")));
    }

    #[test]
    fn state_version_is_mutating_with_stable_prefix_is_false() {
        assert!(!state_version_is_mutating(Some("stable:123")));
    }

    #[test]
    fn state_version_is_mutating_with_empty_string_is_false() {
        assert!(!state_version_is_mutating(Some("")));
    }

    #[test]
    fn state_version_is_dirty_with_none_is_false() {
        assert!(!state_version_is_dirty(None));
    }

    #[test]
    fn state_version_is_dirty_with_dirty_prefix_is_true() {
        assert!(state_version_is_dirty(Some("dirty:67890")));
    }

    #[test]
    fn state_version_is_dirty_with_mutating_prefix_is_false() {
        assert!(!state_version_is_dirty(Some("mutating:123")));
    }

    #[test]
    fn state_version_is_dirty_with_stable_prefix_is_false() {
        assert!(!state_version_is_dirty(Some("stable:123")));
    }

    #[test]
    fn state_version_is_dirty_with_empty_string_is_false() {
        assert!(!state_version_is_dirty(Some("")));
    }

    #[test]
    fn read_only_state_error_with_none_is_none() {
        assert!(read_only_state_error(None).is_none());
    }

    #[test]
    fn read_only_state_error_with_stable_is_none() {
        assert!(read_only_state_error(Some("stable:42")).is_none());
    }

    #[test]
    fn read_only_state_error_with_mutating_contains_mutating_message() {
        let err = read_only_state_error(Some("mutating:99")).expect("should be an error");
        assert!(err.to_string().contains("mutated") || err.to_string().contains("mutating"));
    }

    #[test]
    fn read_only_state_error_with_dirty_contains_inconsistent_message() {
        let err = read_only_state_error(Some("dirty:77")).expect("should be an error");
        assert!(err.to_string().contains("inconsistent"));
    }

    #[test]
    fn with_state_lock_happy_path_returns_value() {
        let _env_lock = lock_env();
        let dir = TempDir::new().expect("temp dir");
        let _config_guard = EnvVarGuard::set(TEST_ENV_VAR, dir.path());

        let result = with_state_lock(TEST_APP, || Ok(42_u32));
        assert_eq!(result.expect("lock succeeded"), 42);
    }

    #[test]
    fn with_state_lock_writes_stable_version_on_success() {
        let _env_lock = lock_env();
        let dir = TempDir::new().expect("temp dir");
        let _config_guard = EnvVarGuard::set(TEST_ENV_VAR, dir.path());

        with_state_lock(TEST_APP, || Ok(())).expect("lock succeeded");

        let app_dir = app_data_dir(TEST_APP).expect("app dir");
        let version = fs::read_to_string(state_version_path(&app_dir)).expect("state version");
        assert!(version.starts_with(STATE_STABLE_PREFIX));
    }
}
