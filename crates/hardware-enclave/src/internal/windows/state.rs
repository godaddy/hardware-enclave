// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Shared on-disk state handling for Windows TPM-backed keys.
#![allow(dead_code, unused_imports, unused_qualifications, unreachable_patterns)]

use crate::internal::core::metadata::{self, DirLock};
use crate::internal::core::{AccessPolicy, Error, KeyMeta, KeyType, Result};
use std::path::{Path, PathBuf};

pub struct KeyMaterialState {
    dir: PathBuf,
    _lock: DirLock,
}

pub enum AuthoritativeKeyState {
    Present,
    Missing,
}

impl KeyMaterialState {
    pub fn acquire(dir: &Path) -> Result<Self> {
        metadata::ensure_dir(dir)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            _lock: DirLock::acquire(dir)?,
        })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn ensure_label_available<F>(&self, label: &str, authoritative_key_state: F) -> Result<()>
    where
        F: FnOnce() -> Result<AuthoritativeKeyState>,
    {
        let local_exists = metadata::key_files_exist(&self.dir, label)?;
        match authoritative_key_state()? {
            AuthoritativeKeyState::Present => {
                return Err(Error::DuplicateLabel {
                    label: label.to_string(),
                });
            }
            AuthoritativeKeyState::Missing if local_exists => {
                self.remove_cached_key_artifacts(label)?;
            }
            AuthoritativeKeyState::Missing => {}
        }
        Ok(())
    }

    pub fn reconcile_deleted_key<F>(&self, label: &str, delete_authoritative_key: F) -> Result<()>
    where
        F: FnOnce() -> Result<AuthoritativeKeyState>,
    {
        let local_exists = metadata::key_files_exist(&self.dir, label)?;
        match delete_authoritative_key()? {
            AuthoritativeKeyState::Present => {
                self.remove_cached_key_artifacts(label)?;
                Ok(())
            }
            AuthoritativeKeyState::Missing if local_exists => {
                self.remove_cached_key_artifacts(label)?;
                Ok(())
            }
            AuthoritativeKeyState::Missing => Err(Error::KeyNotFound {
                label: label.to_string(),
            }),
        }
    }

    pub fn persist_generated_key<F>(
        &self,
        label: &str,
        key_type: KeyType,
        policy: AccessPolicy,
        pub_key: &[u8],
        cleanup_created_key: F,
    ) -> Result<()>
    where
        F: FnOnce() -> Result<()>,
    {
        let meta = KeyMeta::new(label, key_type, policy);
        persist_generated_key_with_writers(
            &self.dir,
            &meta,
            pub_key,
            metadata::save_meta,
            metadata::save_pub_key,
            cleanup_created_key,
        )
    }

    pub fn remove_cached_key_artifacts(&self, label: &str) -> Result<()> {
        match metadata::delete_key_files(&self.dir, label) {
            Ok(()) | Err(Error::KeyNotFound { .. }) => Ok(()),
            Err(error) => Err(error),
        }
    }
}

fn persist_generated_key_with_writers<SM, SP, F>(
    dir: &Path,
    meta: &KeyMeta,
    pub_key: &[u8],
    save_meta: SM,
    save_pub_key: SP,
    cleanup_created_key: F,
) -> Result<()>
where
    SM: Fn(&Path, &str, &KeyMeta) -> Result<()>,
    SP: Fn(&Path, &str, &[u8]) -> Result<()>,
    F: FnOnce() -> Result<()>,
{
    if let Err(error) = save_meta(dir, &meta.label, meta) {
        return Err(with_cleanup_context(
            "persist generated key metadata",
            error,
            dir,
            &meta.label,
            cleanup_created_key,
        ));
    }

    if let Err(error) = save_pub_key(dir, &meta.label, pub_key) {
        return Err(with_cleanup_context(
            "persist generated key public key",
            error,
            dir,
            &meta.label,
            cleanup_created_key,
        ));
    }

    Ok(())
}

fn with_cleanup_context<F>(
    operation: &str,
    error: Error,
    dir: &Path,
    label: &str,
    cleanup_created_key: F,
) -> Error
where
    F: FnOnce() -> Result<()>,
{
    let mut cleanup_failures = Vec::new();

    if let Err(cleanup_error) = cleanup_cached_key_artifacts(dir, label) {
        cleanup_failures.push(format!("remove cached artifacts: {cleanup_error}"));
    }

    if let Err(cleanup_error) = cleanup_created_key() {
        cleanup_failures.push(format!("delete TPM key: {cleanup_error}"));
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

fn cleanup_cached_key_artifacts(dir: &Path, label: &str) -> Result<()> {
    match metadata::delete_key_files(dir, label) {
        Ok(()) | Err(Error::KeyNotFound { .. }) => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_dir(name: &str) -> PathBuf {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "enclaveapp-windows-state-test-{}-{}-{name}",
            std::process::id(),
            id
        ));
        drop(std::fs::remove_dir_all(&dir));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn key_material_state_rejects_existing_artifacts() {
        let dir = test_dir("duplicate");
        std::fs::write(dir.join("work.meta"), "{}").unwrap();

        let state = KeyMaterialState::acquire(&dir).unwrap();
        let error = state
            .ensure_label_available("work", || Ok(AuthoritativeKeyState::Present))
            .unwrap_err();
        match error {
            Error::DuplicateLabel { label } => assert_eq!(label, "work"),
            other => panic!("expected duplicate label, got {other:?}"),
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn persist_generated_key_cleans_up_partial_disk_state_on_write_failure() {
        let dir = test_dir("cleanup");
        let pub_key = [1_u8; 65];
        let mut cleaned_up = false;

        let error = persist_generated_key_with_writers(
            &dir,
            &KeyMeta::new("work", KeyType::Signing, AccessPolicy::None),
            &pub_key,
            metadata::save_meta,
            |_dir, _label, _pub_key| {
                Err(Error::Io(std::io::Error::other(
                    "simulated public key write failure",
                )))
            },
            || {
                cleaned_up = true;
                Ok(())
            },
        )
        .unwrap_err();

        assert!(matches!(error, Error::Io(_) | Error::GenerateFailed { .. }));
        assert!(cleaned_up, "generated TPM key should be cleaned up");
        assert!(!dir.join("work.meta").exists());
        assert!(!dir.join("work.pub").exists());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn remove_cached_key_artifacts_ignores_missing_files() {
        let dir = test_dir("missing");
        let state = KeyMaterialState::acquire(&dir).unwrap();
        state.remove_cached_key_artifacts("missing").unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn ensure_label_available_recovers_stale_local_artifacts_when_authoritative_key_is_missing() {
        let dir = test_dir("recover-stale");
        std::fs::write(dir.join("work.meta"), "{}").unwrap();
        std::fs::write(dir.join("work.pub"), "pub").unwrap();

        let state = KeyMaterialState::acquire(&dir).unwrap();
        state
            .ensure_label_available("work", || Ok(AuthoritativeKeyState::Missing))
            .unwrap();

        assert!(!dir.join("work.meta").exists());
        assert!(!dir.join("work.pub").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn ensure_label_available_rejects_authoritative_key_without_local_artifacts() {
        let dir = test_dir("authoritative-present");
        let state = KeyMaterialState::acquire(&dir).unwrap();

        let err = state
            .ensure_label_available("work", || Ok(AuthoritativeKeyState::Present))
            .unwrap_err();
        assert!(matches!(err, Error::DuplicateLabel { .. }));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn reconcile_deleted_key_removes_stale_local_artifacts_when_authoritative_key_is_missing() {
        let dir = test_dir("delete-stale");
        std::fs::write(dir.join("work.meta"), "{}").unwrap();
        std::fs::write(dir.join("work.pub"), "pub").unwrap();

        let state = KeyMaterialState::acquire(&dir).unwrap();
        state
            .reconcile_deleted_key("work", || Ok(AuthoritativeKeyState::Missing))
            .unwrap();

        assert!(!dir.join("work.meta").exists());
        assert!(!dir.join("work.pub").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn reconcile_deleted_key_keeps_local_artifacts_when_authoritative_delete_fails() {
        let dir = test_dir("delete-fails");
        std::fs::write(dir.join("work.meta"), "{}").unwrap();
        std::fs::write(dir.join("work.pub"), "pub").unwrap();

        let state = KeyMaterialState::acquire(&dir).unwrap();
        let err = state
            .reconcile_deleted_key("work", || {
                Err(Error::KeyOperation {
                    operation: "open_key".into(),
                    detail: "NCryptOpenKey: simulated TPM busy".into(),
                })
            })
            .unwrap_err();

        assert!(matches!(err, Error::KeyOperation { .. }));
        assert!(dir.join("work.meta").exists());
        assert!(dir.join("work.pub").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn key_material_state_acquire_creates_dir() {
        let dir = test_dir("create");
        std::fs::remove_dir_all(&dir).unwrap();

        let state = KeyMaterialState::acquire(&dir).unwrap();
        assert!(state.dir().exists());

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
