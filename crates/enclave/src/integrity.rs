// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

use std::path::Path;

use enclaveapp_core::metadata::{atomic_write, compute_meta_hmac_bytes};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Result of a verification check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// File matches its trust anchor.
    Match,
    /// HMAC mismatch — file has been modified outside the API.
    Tamper,
    /// No trust anchor exists yet (pre-migration or new path).
    Legacy,
    /// File does not exist.
    NotFound,
    /// Secure store is unreachable; verification was skipped (fail-open).
    StoreUnavailable,
}

/// Handle to the tamper-evident file subsystem for one app.
/// HMAC key loaded from platform secure store on construction.
pub struct TamperEvidentHandle {
    app_name: String,
    hmac_key: Option<Zeroizing<Vec<u8>>>,
}

impl std::fmt::Debug for TamperEvidentHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TamperEvidentHandle")
            .field("app_name", &self.app_name)
            .field("hmac_key_loaded", &self.hmac_key.is_some())
            .finish()
    }
}

impl TamperEvidentHandle {
    pub(crate) fn new(app_name: String) -> Self {
        let hmac_key = enclaveapp_app_storage::platform::meta_hmac_key(&app_name);
        Self { app_name, hmac_key }
    }

    /// Write `content` to `path` atomically and update the HMAC sidecar.
    pub fn write(&self, path: &Path, content: &[u8]) -> Result<()> {
        atomic_write(path, content).map_err(Error::from)?;

        if let Some(key) = &self.hmac_key {
            let tag = compute_meta_hmac_bytes(key.as_slice(), content);
            let hex = bytes_to_hex(&tag);
            let sidecar = sidecar_path(path);
            atomic_write(&sidecar, hex.as_bytes()).map_err(Error::from)?;
        }
        Ok(())
    }

    /// Read `path`, verify its HMAC against the trust anchor, and return the content.
    ///
    /// Returns `Error::TamperDetected` if the HMAC doesn't match.
    ///
    /// **Fail-open cases:** If no sidecar exists (`VerifyOutcome::Legacy`) or the
    /// platform secure store is unavailable (`VerifyOutcome::StoreUnavailable`),
    /// verification is skipped and the file contents are returned unverified.
    /// Use [`verify()`] explicitly and check the outcome if your threat model
    /// requires fail-closed behavior.
    pub fn read(&self, path: &Path) -> Result<Vec<u8>> {
        if !path.exists() {
            return Err(Error::KeyNotFound {
                label: path.display().to_string(),
            });
        }
        let outcome = self.verify(path)?;
        match outcome {
            VerifyOutcome::Match | VerifyOutcome::Legacy | VerifyOutcome::StoreUnavailable => {}
            VerifyOutcome::Tamper => {
                return Err(Error::TamperDetected {
                    path: path.display().to_string(),
                });
            }
            VerifyOutcome::NotFound => {
                return Err(Error::KeyNotFound {
                    label: path.display().to_string(),
                });
            }
        }
        std::fs::read(path).map_err(Error::Io)
    }

    /// Verify `path` without reading content.
    pub fn verify(&self, path: &Path) -> Result<VerifyOutcome> {
        if !path.exists() {
            return Ok(VerifyOutcome::NotFound);
        }
        let Some(key) = &self.hmac_key else {
            return Ok(VerifyOutcome::StoreUnavailable);
        };
        let sidecar = sidecar_path(path);
        if !sidecar.exists() {
            return Ok(VerifyOutcome::Legacy);
        }
        let content = std::fs::read(path).map_err(Error::Io)?;
        let stored_hex = std::fs::read_to_string(&sidecar).map_err(Error::Io)?;
        let stored_hex = stored_hex.trim();

        // Decode stored hex to raw bytes (structural check, not secret comparison).
        if stored_hex.len() != 64 {
            return Ok(VerifyOutcome::Tamper);
        }
        let mut stored_bytes = [0_u8; 32];
        for (i, chunk) in stored_hex.as_bytes().chunks(2).enumerate() {
            let hex_str = std::str::from_utf8(chunk)
                .map_err(|_| Error::Config("invalid sidecar hex".into()))?;
            stored_bytes[i] = u8::from_str_radix(hex_str, 16)
                .map_err(|_| Error::Config("invalid sidecar hex".into()))?;
        }

        let computed: [u8; 32] = compute_meta_hmac_bytes(key.as_slice(), &content);

        // Constant-time comparison using the `subtle` crate.
        if computed.ct_eq(&stored_bytes).into() {
            Ok(VerifyOutcome::Match)
        } else {
            Ok(VerifyOutcome::Tamper)
        }
    }

    /// Write HMAC sidecar for an existing file (idempotent).
    pub fn migrate(&self, path: &Path) -> Result<()> {
        if !path.exists() {
            return Err(Error::KeyNotFound {
                label: path.display().to_string(),
            });
        }
        let key = match &self.hmac_key {
            Some(k) => k,
            None => return Ok(()), // Can't migrate without a key; fail-open.
        };
        let content = std::fs::read(path).map_err(Error::Io)?;
        let tag = compute_meta_hmac_bytes(key.as_slice(), &content);
        let hex = bytes_to_hex(&tag);
        let sidecar = sidecar_path(path);
        atomic_write(&sidecar, hex.as_bytes()).map_err(Error::from)
    }

    /// Delete the HMAC sidecar for `path`. Does not delete the file itself.
    pub fn remove_integrity_data(&self, path: &Path) -> Result<()> {
        let sidecar = sidecar_path(path);
        if sidecar.exists() {
            std::fs::remove_file(&sidecar).map_err(Error::Io)?;
        }
        Ok(())
    }

    /// App name this handle was created for.
    pub fn app_name(&self) -> &str {
        &self.app_name
    }
}

fn sidecar_path(path: &Path) -> std::path::PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".hmac");
    std::path::PathBuf::from(s)
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let hi = (b >> 4) as usize;
        let lo = (b & 0xf) as usize;
        const HEX: &[u8] = b"0123456789abcdef";
        s.push(HEX[hi] as char);
        s.push(HEX[lo] as char);
    }
    s
}

#[cfg(test)]
impl TamperEvidentHandle {
    fn with_key(app_name: &str, key: Vec<u8>) -> Self {
        Self {
            app_name: app_name.into(),
            hmac_key: Some(Zeroizing::new(key)),
        }
    }
    fn without_key(app_name: &str) -> Self {
        Self {
            app_name: app_name.into(),
            hmac_key: None,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn write_and_verify_match() {
        let dir = TempDir::new().unwrap();
        let handle = TamperEvidentHandle::with_key("test", vec![0x42_u8; 32]);
        let path = dir.path().join("file.txt");
        handle.write(&path, b"hello").unwrap();
        assert_eq!(handle.verify(&path).unwrap(), VerifyOutcome::Match);
    }

    #[test]
    fn tampered_file_detected() {
        let dir = TempDir::new().unwrap();
        let handle = TamperEvidentHandle::with_key("test", vec![0x42_u8; 32]);
        let path = dir.path().join("file.txt");
        handle.write(&path, b"hello").unwrap();
        // Overwrite file directly, bypassing the API
        fs::write(&path, b"tampered").unwrap();
        assert_eq!(handle.verify(&path).unwrap(), VerifyOutcome::Tamper);
    }

    #[test]
    fn read_tampered_file_returns_error() {
        let dir = TempDir::new().unwrap();
        let handle = TamperEvidentHandle::with_key("test", vec![0x42_u8; 32]);
        let path = dir.path().join("file.txt");
        handle.write(&path, b"hello").unwrap();
        fs::write(&path, b"tampered").unwrap();
        let result = handle.read(&path);
        assert!(matches!(result, Err(Error::TamperDetected { .. })));
    }

    #[test]
    fn missing_sidecar_is_legacy() {
        let dir = TempDir::new().unwrap();
        let handle = TamperEvidentHandle::with_key("test", vec![0x42_u8; 32]);
        let path = dir.path().join("file.txt");
        fs::write(&path, b"legacy").unwrap();
        // No sidecar written
        assert_eq!(handle.verify(&path).unwrap(), VerifyOutcome::Legacy);
    }

    #[test]
    fn store_unavailable_returns_correct_outcome() {
        let handle = TamperEvidentHandle::without_key("test");
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("file.txt");
        fs::write(&path, b"content").unwrap();
        // Write a fake sidecar to avoid Legacy outcome
        fs::write(dir.path().join("file.txt.hmac"), b"fakehex").unwrap();
        assert_eq!(
            handle.verify(&path).unwrap(),
            VerifyOutcome::StoreUnavailable
        );
    }

    #[test]
    fn migrate_creates_valid_sidecar() {
        let dir = TempDir::new().unwrap();
        let handle = TamperEvidentHandle::with_key("test", vec![0x42_u8; 32]);
        let path = dir.path().join("file.txt");
        fs::write(&path, b"existing content").unwrap();
        // No sidecar yet
        assert_eq!(handle.verify(&path).unwrap(), VerifyOutcome::Legacy);
        handle.migrate(&path).unwrap();
        // Now sidecar exists and verifies
        assert_eq!(handle.verify(&path).unwrap(), VerifyOutcome::Match);
    }

    #[test]
    fn truncated_sidecar_is_tamper() {
        let dir = TempDir::new().unwrap();
        let handle = TamperEvidentHandle::with_key("test", vec![0x42_u8; 32]);
        let path = dir.path().join("file.txt");
        handle.write(&path, b"hello").unwrap();
        // Truncate sidecar to wrong length
        let sidecar = dir.path().join("file.txt.hmac");
        fs::write(&sidecar, b"tooshort").unwrap();
        assert_eq!(handle.verify(&path).unwrap(), VerifyOutcome::Tamper);
    }

    #[test]
    fn not_found_on_missing_file() {
        let handle = TamperEvidentHandle::with_key("test", vec![0x42_u8; 32]);
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nonexistent.txt");
        assert_eq!(handle.verify(&path).unwrap(), VerifyOutcome::NotFound);
    }
}
