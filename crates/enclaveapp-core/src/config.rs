// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Config helpers for TOML-based application configuration.

use crate::Result;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::path::Path;

/// Load a TOML config file, returning `T::default()` if the file doesn't exist.
pub fn load_toml<T: DeserializeOwned + Default>(path: &Path) -> Result<T> {
    if !path.exists() {
        return Ok(T::default());
    }
    let content = std::fs::read_to_string(path)?;
    toml::from_str(&content).map_err(|e| crate::Error::Config(e.to_string()))
}

/// Save a value as pretty-printed TOML, creating parent directories as needed.
pub fn save_toml<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        crate::metadata::ensure_dir(parent)?;
    }
    let content = toml::to_string_pretty(value).map_err(|e| crate::Error::Config(e.to_string()))?;
    crate::metadata::atomic_write(path, content.as_bytes())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_dir() -> PathBuf {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("enclaveapp-core-config-test-{pid}-{id}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
    struct TestConfig {
        #[serde(default)]
        name: String,
        #[serde(default)]
        count: u32,
    }

    #[test]
    #[cfg_attr(miri, ignore)] // File I/O (mkdir) not supported under Miri isolation
    fn load_toml_returns_default_for_missing() {
        let dir = test_dir();
        let path = dir.join("nonexistent.toml");
        let cfg: TestConfig = load_toml(&path).unwrap();
        assert_eq!(cfg, TestConfig::default());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)] // File I/O (mkdir) not supported under Miri isolation
    fn load_toml_parses_valid() {
        let dir = test_dir();
        let path = dir.join("config.toml");
        std::fs::write(&path, "name = \"hello\"\ncount = 42\n").unwrap();
        let cfg: TestConfig = load_toml(&path).unwrap();
        assert_eq!(cfg.name, "hello");
        assert_eq!(cfg.count, 42);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)] // File I/O (mkdir) not supported under Miri isolation
    fn load_toml_rejects_invalid() {
        let dir = test_dir();
        let path = dir.join("bad.toml");
        std::fs::write(&path, "= not valid toml [[[").unwrap();
        assert!(load_toml::<TestConfig>(&path).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)] // save_toml calls libc::umask -> FFI not supported by Miri
    fn save_toml_creates_parent_dirs() {
        let dir = test_dir();
        let path = dir.join("sub").join("dir").join("config.toml");
        let cfg = TestConfig {
            name: "test".into(),
            count: 7,
        };
        save_toml(&path, &cfg).unwrap();
        assert!(path.exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)] // save_toml calls libc::umask -> FFI not supported by Miri
    fn save_load_toml_roundtrip() {
        let dir = test_dir();
        let path = dir.join("roundtrip.toml");
        let cfg = TestConfig {
            name: "roundtrip".into(),
            count: 99,
        };
        save_toml(&path, &cfg).unwrap();
        let loaded: TestConfig = load_toml(&path).unwrap();
        assert_eq!(loaded, cfg);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_toml_empty_file_uses_defaults() {
        let dir = test_dir();
        let path = dir.join("empty.toml");
        std::fs::write(&path, "").unwrap();
        let cfg: TestConfig = load_toml(&path).unwrap();
        assert_eq!(cfg, TestConfig::default());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_toml_partial_fields_uses_defaults_for_missing() {
        let dir = test_dir();
        let path = dir.join("partial.toml");
        std::fs::write(&path, "name = \"only-name\"\n").unwrap();
        let cfg: TestConfig = load_toml(&path).unwrap();
        assert_eq!(cfg.name, "only-name");
        assert_eq!(cfg.count, 0);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn save_toml_overwrites_existing_file() {
        let dir = test_dir();
        let path = dir.join("overwrite.toml");
        let first = TestConfig {
            name: "first".into(),
            count: 1,
        };
        let second = TestConfig {
            name: "second".into(),
            count: 2,
        };
        save_toml(&path, &first).unwrap();
        save_toml(&path, &second).unwrap();
        let loaded: TestConfig = load_toml(&path).unwrap();
        assert_eq!(loaded, second);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn save_toml_produces_valid_toml_content() {
        let dir = test_dir();
        let path = dir.join("valid.toml");
        let cfg = TestConfig {
            name: "check".into(),
            count: 5,
        };
        save_toml(&path, &cfg).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        // The output should be parseable TOML
        let re_parsed: toml::Value = toml::from_str(&content).unwrap();
        assert_eq!(re_parsed["name"].as_str().unwrap(), "check");
        assert_eq!(re_parsed["count"].as_integer().unwrap(), 5);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn save_load_roundtrip_with_special_characters_in_name() {
        let dir = test_dir();
        let path = dir.join("special.toml");
        let cfg = TestConfig {
            name: "hello world / test".into(),
            count: 42,
        };
        save_toml(&path, &cfg).unwrap();
        let loaded: TestConfig = load_toml(&path).unwrap();
        assert_eq!(loaded, cfg);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
