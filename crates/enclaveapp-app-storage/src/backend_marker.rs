// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Per-app sticky marker for the chosen storage backend.
//!
//! Several platforms have multiple legitimate backends — Linux native
//! has TPM and keyring, WSL has the bridge plus keyring, etc. The
//! marker records which one was used on first init so a later init
//! that sees the preferred backend gone can refuse rather than
//! silently downgrade to a weaker substitute.
//!
//! Concrete bug this guards against: a Linux user generates a TPM-
//! backed key, then a transient TPM hiccup (service restart, hot-
//! unplug, kernel update) makes `enclaveapp_linux_tpm::is_available`
//! return `false` on the next init. Without the marker, the
//! library silently falls through to `init_linux_keyring` and any
//! sign attempt against the TPM key fails confusingly. With the
//! marker, the init returns a clear "TPM was used previously but
//! is now unavailable" error and the operator can fix the system
//! before the app tries to use a backend it never created keys in.
//!
//! The marker file is one line of plain text (e.g. `"tpm\n"`) at
//! `~/.config/<app>/.backend`. It is deliberately not hashed,
//! signed, or HMAC'd — anyone who can write that file can also
//! write the keys directory, so authentication adds no security
//! property here. The marker exists for diagnostic stickiness, not
//! for tamper resistance.

use crate::platform::BackendKind;
use std::path::PathBuf;

const MARKER_FILENAME: &str = ".backend";

/// Path of the marker file for `app_name`.
fn marker_path(app_name: &str) -> PathBuf {
    enclaveapp_core::metadata::config_dir(app_name).join(MARKER_FILENAME)
}

/// Read the previously-recorded backend, if any.
///
/// Returns `Ok(None)` if the marker is absent (first run, or a fresh
/// app config). Returns `Err` only on filesystem I/O errors that
/// prevent reading; an unrecognized backend value is treated as
/// `Ok(None)` (a future build may have written something this build
/// doesn't understand — proceed and let the init flow handle it).
pub fn read(app_name: &str) -> std::io::Result<Option<BackendKind>> {
    let path = marker_path(app_name);
    let content = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    Ok(parse_kind(content.trim()))
}

/// Record that `kind` was the chosen backend for `app_name`.
///
/// Idempotent: writing the same kind that's already stored is a
/// no-op for callers (the file is rewritten, but the content is
/// stable). Writing a different kind overwrites the marker — the
/// caller is responsible for deciding whether that is allowed; this
/// helper is just the storage layer.
pub fn write(app_name: &str, kind: BackendKind) -> std::io::Result<()> {
    let path = marker_path(app_name);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let value = format!("{}\n", kind_str(kind));
    enclaveapp_core::metadata::atomic_write(&path, value.as_bytes())
        .map_err(|e| std::io::Error::other(e.to_string()))
}

/// Stable on-disk string for a backend kind. Kept narrow on purpose
/// — only the kinds that actually persist a marker need a string.
fn kind_str(kind: BackendKind) -> &'static str {
    match kind {
        BackendKind::SecureEnclave => "se",
        BackendKind::Tpm => "tpm",
        BackendKind::TpmBridge => "tpm-bridge",
        BackendKind::Keyring => "keyring",
    }
}

fn parse_kind(s: &str) -> Option<BackendKind> {
    match s {
        "se" => Some(BackendKind::SecureEnclave),
        "tpm" => Some(BackendKind::Tpm),
        "tpm-bridge" => Some(BackendKind::TpmBridge),
        "keyring" => Some(BackendKind::Keyring),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, let_underscore_drop)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn unique_app_name() -> String {
        format!(
            "enclaveapp-app-storage-marker-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        )
    }

    fn cleanup(app_name: &str) {
        let dir = enclaveapp_core::metadata::config_dir(app_name);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_returns_none_when_marker_absent() {
        let app = unique_app_name();
        cleanup(&app);
        assert_eq!(read(&app).unwrap(), None);
    }

    #[test]
    fn write_then_read_roundtrips_each_kind() {
        let app = unique_app_name();
        cleanup(&app);
        for kind in [
            BackendKind::SecureEnclave,
            BackendKind::Tpm,
            BackendKind::TpmBridge,
            BackendKind::Keyring,
        ] {
            write(&app, kind).unwrap();
            assert_eq!(read(&app).unwrap(), Some(kind));
        }
        cleanup(&app);
    }

    #[test]
    fn read_returns_none_for_unrecognized_kind() {
        let app = unique_app_name();
        let path = marker_path(&app);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "tpm-quantum\n").unwrap();
        assert_eq!(read(&app).unwrap(), None);
        cleanup(&app);
    }

    #[test]
    fn write_overwrites_existing_marker() {
        let app = unique_app_name();
        cleanup(&app);
        write(&app, BackendKind::Tpm).unwrap();
        write(&app, BackendKind::Keyring).unwrap();
        assert_eq!(read(&app).unwrap(), Some(BackendKind::Keyring));
        cleanup(&app);
    }

    // Pure function unit tests for parse_kind and kind_str

    #[test]
    fn parse_kind_se_returns_secure_enclave() {
        assert_eq!(parse_kind("se"), Some(BackendKind::SecureEnclave));
    }

    #[test]
    fn parse_kind_tpm_returns_tpm() {
        assert_eq!(parse_kind("tpm"), Some(BackendKind::Tpm));
    }

    #[test]
    fn parse_kind_tpm_bridge_returns_tpm_bridge() {
        assert_eq!(parse_kind("tpm-bridge"), Some(BackendKind::TpmBridge));
    }

    #[test]
    fn parse_kind_keyring_returns_keyring() {
        assert_eq!(parse_kind("keyring"), Some(BackendKind::Keyring));
    }

    #[test]
    fn parse_kind_unknown_returns_none() {
        assert_eq!(parse_kind("unknown"), None);
        assert_eq!(parse_kind(""), None);
        assert_eq!(parse_kind("SE"), None);
        assert_eq!(parse_kind("TPM"), None);
    }

    #[test]
    fn kind_str_roundtrips_through_parse_kind() {
        for kind in [
            BackendKind::SecureEnclave,
            BackendKind::Tpm,
            BackendKind::TpmBridge,
            BackendKind::Keyring,
        ] {
            let s = kind_str(kind);
            assert_eq!(parse_kind(s), Some(kind));
        }
    }

    #[test]
    fn kind_str_values_are_lowercase_ascii() {
        for kind in [
            BackendKind::SecureEnclave,
            BackendKind::Tpm,
            BackendKind::TpmBridge,
            BackendKind::Keyring,
        ] {
            let s = kind_str(kind);
            assert!(
                s.chars().all(|c| c.is_ascii_lowercase() || c == '-'),
                "kind_str({kind:?}) = '{s}' contains unexpected characters"
            );
        }
    }
}
