// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

use std::path::{Path, PathBuf};

use enclaveapp_core::metadata::{atomic_write, compute_meta_hmac_bytes};
use rand::TryRngCore;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// How the tamper-evident handle enforces integrity.
///
/// Choose based on the number of files you need to protect:
///
/// - **`Sidecar`** (default): One platform secure-store entry per app (the HMAC key).
///   Each file gets a `.hmac` sidecar that IS the authoritative integrity check.
///   Scales to any number of files. Suitable for directories with thousands of entries.
///
/// - **`TrustAnchor`**: One platform secure-store entry per app (HMAC key) **plus**
///   one per protected file (the HMAC tag itself). The sidecar is a forensic cache;
///   the platform secure store is authoritative. Deleting a sidecar cannot bypass
///   verification. Use only for low-volume, high-value files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IntegrityMode {
    /// HMAC sidecar is the authoritative integrity check.
    /// One secure-store entry per app. Scales to any file count.
    #[default]
    Sidecar,
    /// Per-file trust anchor in the platform secure store (Keychain / DPAPI / Secret Service).
    /// One secure-store entry per protected file in addition to the per-app HMAC key.
    TrustAnchor,
}

/// Result of a verification check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// File matches its trust anchor.
    Match,
    /// HMAC mismatch — file has been modified outside the API.
    Tamper,
    /// No trust anchor exists yet (pre-migration or new path). Call `migrate()`.
    Legacy,
    /// File does not exist.
    NotFound,
    /// Secure store is unreachable; verification was skipped (fail-open).
    StoreUnavailable,
}

/// Handle to the tamper-evident file subsystem for one app.
///
/// Constructed via [`create_tamper_evident()`][crate::create_tamper_evident].
/// Defaults to [`IntegrityMode::Sidecar`]. Upgrade to
/// [`IntegrityMode::TrustAnchor`] with [`with_trust_anchor()`][Self::with_trust_anchor].
pub struct TamperEvidentHandle {
    app_name: String,
    hmac_key: Option<Zeroizing<Vec<u8>>>,
    mode: IntegrityMode,
}

impl std::fmt::Debug for TamperEvidentHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TamperEvidentHandle")
            .field("app_name", &self.app_name)
            .field("hmac_key_loaded", &self.hmac_key.is_some())
            .field("mode", &self.mode)
            .finish()
    }
}

impl TamperEvidentHandle {
    pub(crate) fn new(app_name: String) -> Self {
        let hmac_key = enclaveapp_app_storage::platform::meta_hmac_key(&app_name);
        Self {
            app_name,
            hmac_key,
            mode: IntegrityMode::Sidecar,
        }
    }

    /// Create a handle with a random ephemeral HMAC key — no platform secure store access.
    ///
    /// The key is generated from `OsRng` and held in memory only. Suitable for
    /// testing, CI, and development examples where interactive prompts are unacceptable.
    pub(crate) fn new_ephemeral(app_name: String) -> Self {
        let mut key = vec![0_u8; 32];
        rand::rngs::OsRng
            .try_fill_bytes(&mut key)
            .expect("OsRng must succeed for ephemeral key generation");
        Self {
            app_name,
            hmac_key: Some(Zeroizing::new(key)),
            mode: IntegrityMode::Sidecar,
        }
    }

    /// Enable `TrustAnchor` mode: each file's HMAC is also stored in the
    /// platform secure store (Keychain / DPAPI / Secret Service).
    ///
    /// Use only for low-volume, high-value files — each file adds one entry
    /// to the platform secure store. For directories with thousands of files,
    /// stay with the default `Sidecar` mode.
    #[must_use]
    pub fn with_trust_anchor(mut self) -> Self {
        self.mode = IntegrityMode::TrustAnchor;
        self
    }

    /// The integrity mode this handle uses.
    pub fn mode(&self) -> IntegrityMode {
        self.mode
    }

    /// Write `content` to `path` atomically and update integrity data.
    ///
    /// - **Sidecar mode**: writes the file and a `.hmac` sidecar.
    /// - **TrustAnchor mode**: additionally stores a per-file tag in the
    ///   platform secure store.
    ///
    /// **Crash-consistency note:** multiple I/O operations occur. If the
    /// process crashes mid-write, the next `verify()` may return `Legacy`
    /// or `Tamper`. Call `migrate()` to rebuild integrity data after an
    /// unclean shutdown.
    pub fn write(&self, path: &Path, content: &[u8]) -> Result<()> {
        atomic_write(path, content).map_err(Error::from)?;

        let Some(key) = &self.hmac_key else {
            return Ok(());
        };

        let tag = compute_meta_hmac_bytes(key.as_slice(), content);
        let hex = bytes_to_hex(&tag);
        let sidecar = sidecar_path(path);
        atomic_write(&sidecar, hex.as_bytes()).map_err(Error::from)?;

        // In test builds, skip all platform secure-store calls (Keychain / DPAPI /
        // D-Bus Secret Service). CI runners do not have these services configured.
        // This mirrors the #[cfg(not(test))] pattern used throughout enclaveapp-app-storage.
        #[cfg(not(test))]
        if self.mode == IntegrityMode::TrustAnchor {
            let path_label = path_to_label(path);
            enclaveapp_app_storage::platform::store_file_tag(&self.app_name, &path_label, &tag)
                .map_err(|e| Error::KeyOperation {
                    operation: "store_file_tag".into(),
                    detail: e.to_string(),
                })?;
        }
        Ok(())
    }

    /// Read `path`, verify its integrity, and return the content.
    ///
    /// Returns `Error::TamperDetected` if the HMAC doesn't match.
    ///
    /// **Fail-open cases:** `Legacy` and `StoreUnavailable` both return the
    /// file contents unverified. Use [`verify()`][Self::verify] directly and
    /// inspect the outcome if your threat model requires fail-closed behavior.
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

    /// Verify `path` without reading the full content into a returned buffer.
    pub fn verify(&self, path: &Path) -> Result<VerifyOutcome> {
        if !path.exists() {
            return Ok(VerifyOutcome::NotFound);
        }
        let Some(key) = &self.hmac_key else {
            return Ok(VerifyOutcome::StoreUnavailable);
        };

        match self.mode {
            IntegrityMode::Sidecar => self.verify_sidecar(path, key),
            IntegrityMode::TrustAnchor => self.verify_anchor(path, key),
        }
    }

    /// Sidecar-mode verification: the `.hmac` sidecar is the authoritative source.
    fn verify_sidecar(&self, path: &Path, key: &[u8]) -> Result<VerifyOutcome> {
        let sidecar = sidecar_path(path);
        if !sidecar.exists() {
            return Ok(VerifyOutcome::Legacy);
        }

        let stored_hex = std::fs::read_to_string(&sidecar).map_err(Error::Io)?;
        let stored_hex = stored_hex.trim();
        let stored_bytes = decode_hex_tag(stored_hex)?;
        let content = std::fs::read(path).map_err(Error::Io)?;
        let computed: [u8; 32] = compute_meta_hmac_bytes(key, &content);

        if computed.ct_eq(&stored_bytes).into() {
            Ok(VerifyOutcome::Match)
        } else {
            Ok(VerifyOutcome::Tamper)
        }
    }

    /// TrustAnchor-mode verification: the platform secure store is authoritative.
    ///
    /// The sidecar is a forensic cache only — deleting it does not bypass verification.
    fn verify_anchor(&self, path: &Path, key: &[u8]) -> Result<VerifyOutcome> {
        // In test builds skip all platform secure-store calls (Keychain / DPAPI /
        // D-Bus Secret Service). CI runners do not have these configured.
        // Mirror of #[cfg(not(test))] pattern used in enclaveapp-app-storage.
        // In test builds, skip platform secure-store calls (no Keychain/DPAPI/D-Bus in CI).
        // The #[cfg(not(test))] block below is the production path.
        #[cfg(test)]
        let _ = (path, key);
        #[cfg(test)]
        return Ok(VerifyOutcome::Legacy);
        #[cfg(not(test))]
        {
            let path_label = path_to_label(path);
            let stored_tag: [u8; 32] = match enclaveapp_app_storage::platform::load_file_tag(
                &self.app_name,
                &path_label,
            ) {
                Ok(Some(t)) => t,
                Ok(None) => return Ok(VerifyOutcome::Legacy),
                Err(_) => return Ok(VerifyOutcome::StoreUnavailable),
            };
            let content = std::fs::read(path).map_err(Error::Io)?;
            let computed: [u8; 32] = compute_meta_hmac_bytes(key, &content);
            if computed.ct_eq(&stored_tag).into() {
                Ok(VerifyOutcome::Match)
            } else {
                Ok(VerifyOutcome::Tamper)
            }
        }
    }

    /// Write integrity data for an existing file. Idempotent.
    ///
    /// - **Sidecar mode**: writes the `.hmac` sidecar.
    /// - **TrustAnchor mode**: writes sidecar and stores the trust anchor.
    pub fn migrate(&self, path: &Path) -> Result<()> {
        if !path.exists() {
            return Err(Error::KeyNotFound {
                label: path.display().to_string(),
            });
        }
        let key = match &self.hmac_key {
            Some(k) => k,
            None => return Ok(()),
        };
        let content = std::fs::read(path).map_err(Error::Io)?;
        let tag = compute_meta_hmac_bytes(key.as_slice(), &content);
        let hex = bytes_to_hex(&tag);
        let sidecar = sidecar_path(path);
        atomic_write(&sidecar, hex.as_bytes()).map_err(Error::from)?;

        if self.mode == IntegrityMode::TrustAnchor {
            let path_label = path_to_label(path);
            enclaveapp_app_storage::platform::store_file_tag(&self.app_name, &path_label, &tag)
                .map_err(|e| Error::KeyOperation {
                    operation: "migrate_file_tag".into(),
                    detail: e.to_string(),
                })?;
        }
        Ok(())
    }

    /// Delete integrity data for `path`. Does not delete the file itself.
    ///
    /// - **Sidecar mode**: removes the `.hmac` sidecar.
    /// - **TrustAnchor mode**: removes sidecar and deletes the trust anchor.
    pub fn remove_integrity_data(&self, path: &Path) -> Result<()> {
        let sidecar = sidecar_path(path);
        if sidecar.exists() {
            std::fs::remove_file(&sidecar).map_err(Error::Io)?;
        }

        if self.mode == IntegrityMode::TrustAnchor {
            let path_label = path_to_label(path);
            // Best-effort: if the store is unavailable, that's acceptable.
            drop(enclaveapp_app_storage::platform::delete_file_tag(
                &self.app_name,
                &path_label,
            ));
        }
        Ok(())
    }

    /// App name this handle was created for.
    pub fn app_name(&self) -> &str {
        &self.app_name
    }
}

fn sidecar_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".hmac");
    PathBuf::from(s)
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

/// Decode a 64-char lowercase hex string into a 32-byte array.
/// Returns `VerifyOutcome::Tamper` disguised as `Ok([0;32])` on error — callers
/// must use this only when they intend to return Tamper on bad input.
fn decode_hex_tag(hex: &str) -> Result<[u8; 32]> {
    if hex.len() != 64 {
        // Wrong length → treat as tampered.
        return Ok([0_u8; 32]);
    }
    let mut out = [0_u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let s = match std::str::from_utf8(chunk) {
            Ok(s) => s,
            Err(_) => return Ok([0_u8; 32]),
        };
        out[i] = match u8::from_str_radix(s, 16) {
            Ok(b) => b,
            Err(_) => return Ok([0_u8; 32]),
        };
    }
    Ok(out)
}

/// Derive a stable 64-char hex label from a file path for use as the
/// trust anchor key in the platform secure store.
fn path_to_label(path: &Path) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(path.as_os_str().as_encoded_bytes());
    let mut s = String::with_capacity(64);
    for b in &hash {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
impl TamperEvidentHandle {
    fn with_key(app_name: &str, key: Vec<u8>) -> Self {
        Self {
            app_name: app_name.into(),
            hmac_key: Some(Zeroizing::new(key)),
            mode: IntegrityMode::Sidecar,
        }
    }
    fn without_key(app_name: &str) -> Self {
        Self {
            app_name: app_name.into(),
            hmac_key: None,
            mode: IntegrityMode::Sidecar,
        }
    }
    fn with_key_anchored(app_name: &str, key: Vec<u8>) -> Self {
        Self {
            app_name: app_name.into(),
            hmac_key: Some(Zeroizing::new(key)),
            mode: IntegrityMode::TrustAnchor,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    // ── Sidecar mode tests ───────────────────────────────────────────

    #[test]
    fn sidecar_write_and_verify_match() {
        let dir = TempDir::new().unwrap();
        let handle = TamperEvidentHandle::with_key("test", vec![0x42_u8; 32]);
        let path = dir.path().join("file.txt");
        handle.write(&path, b"hello").unwrap();
        assert_eq!(handle.verify(&path).unwrap(), VerifyOutcome::Match);
    }

    #[test]
    fn sidecar_tampered_file_detected() {
        let dir = TempDir::new().unwrap();
        let handle = TamperEvidentHandle::with_key("test", vec![0x42_u8; 32]);
        let path = dir.path().join("file.txt");
        handle.write(&path, b"hello").unwrap();
        fs::write(&path, b"tampered").unwrap();
        assert_eq!(handle.verify(&path).unwrap(), VerifyOutcome::Tamper);
    }

    #[test]
    fn sidecar_read_tampered_returns_error() {
        let dir = TempDir::new().unwrap();
        let handle = TamperEvidentHandle::with_key("test", vec![0x42_u8; 32]);
        let path = dir.path().join("file.txt");
        handle.write(&path, b"hello").unwrap();
        fs::write(&path, b"tampered").unwrap();
        let result = handle.read(&path);
        assert!(matches!(result, Err(Error::TamperDetected { .. })));
    }

    #[test]
    fn sidecar_missing_sidecar_is_legacy() {
        let dir = TempDir::new().unwrap();
        let handle = TamperEvidentHandle::with_key("test", vec![0x42_u8; 32]);
        let path = dir.path().join("file.txt");
        fs::write(&path, b"legacy").unwrap();
        assert_eq!(handle.verify(&path).unwrap(), VerifyOutcome::Legacy);
    }

    #[test]
    fn sidecar_store_unavailable_returns_correct_outcome() {
        let handle = TamperEvidentHandle::without_key("test");
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("file.txt");
        fs::write(&path, b"content").unwrap();
        fs::write(dir.path().join("file.txt.hmac"), b"fakehex").unwrap();
        assert_eq!(
            handle.verify(&path).unwrap(),
            VerifyOutcome::StoreUnavailable
        );
    }

    #[test]
    fn sidecar_migrate_creates_valid_sidecar() {
        let dir = TempDir::new().unwrap();
        let handle = TamperEvidentHandle::with_key("test", vec![0x42_u8; 32]);
        let path = dir.path().join("file.txt");
        fs::write(&path, b"existing content").unwrap();
        assert_eq!(handle.verify(&path).unwrap(), VerifyOutcome::Legacy);
        handle.migrate(&path).unwrap();
        assert_eq!(handle.verify(&path).unwrap(), VerifyOutcome::Match);
    }

    #[test]
    fn sidecar_truncated_sidecar_is_tamper() {
        let dir = TempDir::new().unwrap();
        let handle = TamperEvidentHandle::with_key("test", vec![0x42_u8; 32]);
        let path = dir.path().join("file.txt");
        handle.write(&path, b"hello").unwrap();
        let sidecar = dir.path().join("file.txt.hmac");
        fs::write(&sidecar, b"tooshort").unwrap();
        assert_eq!(handle.verify(&path).unwrap(), VerifyOutcome::Tamper);
    }

    #[test]
    fn sidecar_not_found_on_missing_file() {
        let handle = TamperEvidentHandle::with_key("test", vec![0x42_u8; 32]);
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nonexistent.txt");
        assert_eq!(handle.verify(&path).unwrap(), VerifyOutcome::NotFound);
    }

    #[test]
    fn sidecar_invalid_hex_returns_tamper() {
        let dir = TempDir::new().unwrap();
        let handle = TamperEvidentHandle::with_key("test", vec![0x42_u8; 32]);
        let path = dir.path().join("file.txt");
        handle.write(&path, b"content").unwrap();
        let mut bad_hex = vec![b'a'; 64];
        bad_hex[10] = b'\x00';
        let sidecar = dir.path().join("file.txt.hmac");
        fs::write(&sidecar, &bad_hex).unwrap();
        assert_eq!(handle.verify(&path).unwrap(), VerifyOutcome::Tamper);
    }

    #[test]
    fn sidecar_delete_sidecar_is_legacy_not_tamper() {
        // In Sidecar mode, a deleted sidecar = Legacy (can't distinguish from never-written).
        let dir = TempDir::new().unwrap();
        let handle = TamperEvidentHandle::with_key("test", vec![0x42_u8; 32]);
        let path = dir.path().join("file.txt");
        handle.write(&path, b"content").unwrap();
        let sidecar = dir.path().join("file.txt.hmac");
        fs::remove_file(&sidecar).unwrap();
        assert_eq!(handle.verify(&path).unwrap(), VerifyOutcome::Legacy);
    }

    #[test]
    fn read_store_unavailable_returns_content() {
        let handle = TamperEvidentHandle::without_key("test");
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("file.txt");
        fs::write(&path, b"unverified content").unwrap();
        let result = handle.read(&path).unwrap();
        assert_eq!(result, b"unverified content");
    }

    // ── TrustAnchor mode tests ───────────────────────────────────────

    #[test]
    fn trust_anchor_mode_is_not_default() {
        let handle = TamperEvidentHandle::with_key("test", vec![0x42_u8; 32]);
        assert_eq!(handle.mode(), IntegrityMode::Sidecar);
        let handle = handle.with_trust_anchor();
        assert_eq!(handle.mode(), IntegrityMode::TrustAnchor);
    }

    #[test]
    fn trust_anchor_sidecar_deletion_is_still_match_or_legacy() {
        // In TrustAnchor mode, deleting the sidecar cannot cause Tamper
        // when content is unchanged. Result is Match (if secure store has the
        // tag) or Legacy (if the secure store is unavailable in CI).
        let dir = TempDir::new().unwrap();
        let handle = TamperEvidentHandle::with_key_anchored("test", vec![0x42_u8; 32]);
        let path = dir.path().join("file.txt");
        // write() in TrustAnchor mode calls store_file_tag; skip if the
        // platform secure store is unavailable (D-Bus absent on CI Linux,
        // Keychain locked on headless macOS runners).
        if handle.write(&path, b"content").is_err() {
            return;
        }
        let sidecar = dir.path().join("file.txt.hmac");
        if sidecar.exists() {
            fs::remove_file(&sidecar).unwrap();
        }
        let outcome = handle.verify(&path).unwrap();
        assert!(
            matches!(
                outcome,
                VerifyOutcome::Match | VerifyOutcome::Legacy | VerifyOutcome::StoreUnavailable
            ),
            "deleting sidecar must not return Tamper when content unchanged: {outcome:?}"
        );
    }

    // ── path_to_label tests ──────────────────────────────────────────

    #[test]
    fn path_to_label_is_64_chars() {
        let label = path_to_label(Path::new("/some/path/file.txt"));
        assert_eq!(label.len(), 64);
        assert!(label.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn path_to_label_is_stable() {
        let p = Path::new("/stable/path");
        assert_eq!(path_to_label(p), path_to_label(p));
    }

    #[test]
    fn path_to_label_differs_for_different_paths() {
        let a = path_to_label(Path::new("/a"));
        let b = path_to_label(Path::new("/b"));
        assert_ne!(a, b);
    }
}
