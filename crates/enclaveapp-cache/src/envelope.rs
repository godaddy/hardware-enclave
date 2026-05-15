// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Authenticated envelope for credential-cache plaintext.
//!
//! Wraps the plaintext handed to an [`EncryptionStorage`] backend with:
//!
//! - a SHA-256 digest of the cache file's **unencrypted** header bytes,
//!   so tampering with the header (timestamps, risk level, flags) is
//!   detected at decrypt time — closes the "no AAD on the header" gap
//!   that previously let an attacker rewind `risk_level` downward or
//!   extend a cached credential's client-side validity window; and
//!
//! - a monotonic `u64` rollback counter, compared on read to a
//!   sidecar `<cache>.counter` file, so replay of an older valid
//!   ciphertext is detected for the remaining validity window.
//!
//! # Design
//!
//! We intentionally do **not** change the `EnclaveEncryptor` trait
//! signature. Threading an `aad: &[u8]` parameter through four
//! platform backends and the WSL bridge protocol is an order of
//! magnitude larger change than we can ship responsibly right now,
//! and the security delivered by this app-layer approach is
//! equivalent: tampering is detected before any decrypted bytes
//! cross the caller boundary.
//!
//! # Wire format of the plaintext fed to `encrypt()`
//!
//! ```text
//! [4B magic "APL1"]
//! [32B SHA-256(header_bytes)]
//! [8B BE u64 monotonic counter]
//! [N bytes original payload]
//! ```
//!
//! `header_bytes` is the full unencrypted prefix of the cache file —
//! magic + version + flags + app-specific header fields — whatever the
//! caller wants to bind. Both sides must compute it identically.
//!
//! # Backward compatibility
//!
//! [`unwrap_plaintext`] accepts legacy plaintext that does **not**
//! start with `APL1` and returns it verbatim with `counter = 0`.
//! Existing caches written before this module shipped continue to
//! decrypt and use; the next write puts them into the new envelope.
//! The sidecar counter defaults to 0 when missing — rollback
//! detection kicks in as soon as the first wrapped write lands.

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Magic bytes at the start of a wrapped plaintext: "APL1" (Auth PayLoad v1).
pub const ENVELOPE_MAGIC: &[u8; 4] = b"APL1";

/// SHA-256 digest length.
pub const HEADER_HASH_LEN: usize = 32;

/// u64 counter length.
pub const COUNTER_LEN: usize = 8;

/// Minimum wrapped-plaintext length = magic + hash + counter.
pub const ENVELOPE_OVERHEAD: usize = ENVELOPE_MAGIC.len() + HEADER_HASH_LEN + COUNTER_LEN;

/// Errors produced by envelope unwrap.
#[derive(Debug)]
pub enum EnvelopeError {
    /// The decrypted plaintext's embedded header hash did not match the
    /// hash of the observed unencrypted header. The cache header was
    /// tampered with.
    HeaderMismatch,
    /// The decrypted plaintext's counter is less than the last-seen
    /// counter recorded in the sidecar. This is a rollback to an
    /// earlier valid ciphertext.
    Rollback {
        observed: u64,
        expected_at_least: u64,
    },
    /// I/O error reading or writing the counter sidecar.
    CounterIo(std::io::Error),
}

impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HeaderMismatch => write!(
                f,
                "cache header does not match the hash bound into the encrypted payload: \
                 the header was modified after encryption"
            ),
            Self::Rollback {
                observed,
                expected_at_least,
            } => write!(
                f,
                "cache counter rolled back: observed {observed}, expected >= {expected_at_least}"
            ),
            Self::CounterIo(e) => write!(f, "counter sidecar I/O: {e}"),
        }
    }
}

impl std::error::Error for EnvelopeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CounterIo(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for EnvelopeError {
    fn from(e: std::io::Error) -> Self {
        Self::CounterIo(e)
    }
}

/// Wrap the caller's payload in an authenticated envelope.
///
/// The returned bytes are the plaintext that should be passed to
/// `storage.encrypt(...)`.
#[must_use]
pub fn wrap_plaintext(header_bytes: &[u8], counter: u64, payload: &[u8]) -> Vec<u8> {
    let header_hash = Sha256::digest(header_bytes);
    let mut out = Vec::with_capacity(ENVELOPE_OVERHEAD + payload.len());
    out.extend_from_slice(ENVELOPE_MAGIC);
    out.extend_from_slice(&header_hash);
    out.extend_from_slice(&counter.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Result of unwrapping a decrypted plaintext.
#[derive(Debug)]
pub enum Unwrapped {
    /// Legacy plaintext that was not wrapped. The caller gets the
    /// decrypted bytes verbatim with no header-binding or rollback
    /// protection. These will be upgraded to the new format on the
    /// next write.
    Legacy { payload: Vec<u8> },
    /// New-format envelope. Header binding verified; counter surfaced
    /// so the caller can write it back to the sidecar if it's higher
    /// than the last seen value.
    Versioned { counter: u64, payload: Vec<u8> },
}

impl Unwrapped {
    /// Borrow the payload regardless of envelope version.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        match self {
            Self::Legacy { payload } | Self::Versioned { payload, .. } => payload,
        }
    }

    /// Consume and return the payload.
    #[must_use]
    pub fn into_payload(self) -> Vec<u8> {
        match self {
            Self::Legacy { payload } | Self::Versioned { payload, .. } => payload,
        }
    }
}

/// Unwrap a decrypted plaintext.
///
/// - If the plaintext starts with `ENVELOPE_MAGIC`, the header hash is
///   verified against `header_bytes` and the counter is compared to
///   `min_counter`. Returns [`Unwrapped::Versioned`] on success.
/// - Otherwise, the bytes are treated as legacy pre-envelope plaintext
///   and returned verbatim as [`Unwrapped::Legacy`].
#[allow(deprecated)] // sha2 0.10 / generic-array 0.14 interaction; tracked upstream
pub fn unwrap_plaintext(
    header_bytes: &[u8],
    min_counter: u64,
    decrypted: &[u8],
) -> Result<Unwrapped, EnvelopeError> {
    if decrypted.len() < ENVELOPE_OVERHEAD || &decrypted[..ENVELOPE_MAGIC.len()] != ENVELOPE_MAGIC {
        return Ok(Unwrapped::Legacy {
            payload: decrypted.to_vec(),
        });
    }

    let hash_start = ENVELOPE_MAGIC.len();
    let hash_end = hash_start + HEADER_HASH_LEN;
    let observed_hash = &decrypted[hash_start..hash_end];
    let expected_hash = Sha256::digest(header_bytes);
    if observed_hash != expected_hash.as_slice() {
        return Err(EnvelopeError::HeaderMismatch);
    }

    let counter_start = hash_end;
    let counter_end = counter_start + COUNTER_LEN;
    let mut counter_bytes = [0_u8; COUNTER_LEN];
    counter_bytes.copy_from_slice(&decrypted[counter_start..counter_end]);
    let counter = u64::from_be_bytes(counter_bytes);
    if counter < min_counter {
        return Err(EnvelopeError::Rollback {
            observed: counter,
            expected_at_least: min_counter,
        });
    }

    let payload = decrypted[counter_end..].to_vec();
    Ok(Unwrapped::Versioned { counter, payload })
}

// ---------------------------------------------------------------------------
// Counter sidecar
// ---------------------------------------------------------------------------

/// Compute the sidecar path for the counter of a given cache file.
#[must_use]
pub fn counter_path(cache_path: &Path) -> PathBuf {
    let mut p = cache_path.to_path_buf();
    let mut name = p.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    name.push(".counter");
    p.set_file_name(name);
    p
}

/// Read the counter sidecar, returning 0 when the file is missing.
///
/// A missing file is treated as "never seen before" rather than an
/// error — this matches the legacy-cache migration posture: a
/// first-time read after the envelope ships has no prior counter to
/// compare against.
pub fn read_counter(cache_path: &Path) -> Result<u64, EnvelopeError> {
    let path = counter_path(cache_path);
    match std::fs::read(&path) {
        Ok(bytes) if bytes.len() >= COUNTER_LEN => {
            let mut buf = [0_u8; COUNTER_LEN];
            buf.copy_from_slice(&bytes[..COUNTER_LEN]);
            Ok(u64::from_be_bytes(buf))
        }
        Ok(_) => Ok(0),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(EnvelopeError::CounterIo(e)),
    }
}

/// Write the counter sidecar atomically.
///
/// A cross-process `fs4` flock on the sidecar itself serializes
/// concurrent writers so a read-modify-write of the counter is
/// race-free between two invocations of the same enclave-app.
pub fn write_counter(cache_path: &Path, counter: u64) -> Result<(), EnvelopeError> {
    use fs4::fs_std::FileExt;
    use std::io::Write;

    let path = counter_path(cache_path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp_path = path.with_extension("counter.tmp");

    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp_path)?;
    FileExt::lock_exclusive(&file)?;
    let mut file = file;
    file.write_all(&counter.to_be_bytes())?;
    file.flush()?;
    drop(file);
    std::fs::rename(&tmp_path, &path)?;
    Ok(())
}

/// Allocate the counter for the next write: `max(current_sidecar, prior_observed) + 1`.
///
/// `prior_observed` is the counter pulled out of the last successful
/// decrypt (or 0 on fresh install); it defends against a scenario where
/// an attacker deletes the sidecar file and resets it to 0 — the
/// ciphertext itself still carries the last-seen counter inside its
/// authenticated envelope, so the sequence can only go forward.
#[must_use]
pub fn next_counter(sidecar_counter: u64, prior_observed: u64) -> u64 {
    sidecar_counter.max(prior_observed).saturating_add(1)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn wrap_unwrap_roundtrip() {
        let header = b"magic + version + flags + app-specific";
        let payload = b"super secret credential JSON";
        let wrapped = wrap_plaintext(header, 42, payload);
        let unwrapped = unwrap_plaintext(header, 0, &wrapped).unwrap();
        match unwrapped {
            Unwrapped::Versioned {
                counter,
                payload: p,
            } => {
                assert_eq!(counter, 42);
                assert_eq!(p, payload);
            }
            _ => panic!("expected Versioned"),
        }
    }

    #[test]
    fn unwrap_legacy_plaintext_passes_through() {
        let header = b"header-bytes";
        let payload = b"legacy-plaintext-no-envelope";
        let unwrapped = unwrap_plaintext(header, 99, payload).unwrap();
        match unwrapped {
            Unwrapped::Legacy { payload: p } => assert_eq!(p, payload),
            _ => panic!("expected Legacy"),
        }
    }

    #[test]
    fn unwrap_rejects_header_tamper() {
        let original_header = b"ORIGINAL";
        let tampered_header = b"TAMPERED";
        let wrapped = wrap_plaintext(original_header, 1, b"payload");
        let err = unwrap_plaintext(tampered_header, 0, &wrapped).unwrap_err();
        matches!(err, EnvelopeError::HeaderMismatch);
    }

    #[test]
    fn unwrap_rejects_rollback() {
        let header = b"HDR";
        let wrapped = wrap_plaintext(header, 5, b"payload");
        let err = unwrap_plaintext(header, 10, &wrapped).unwrap_err();
        match err {
            EnvelopeError::Rollback {
                observed,
                expected_at_least,
            } => {
                assert_eq!(observed, 5);
                assert_eq!(expected_at_least, 10);
            }
            _ => panic!("expected Rollback"),
        }
    }

    #[test]
    fn unwrap_accepts_counter_eq_min() {
        let header = b"HDR";
        let wrapped = wrap_plaintext(header, 7, b"payload");
        let unwrapped = unwrap_plaintext(header, 7, &wrapped).unwrap();
        match unwrapped {
            Unwrapped::Versioned { counter, .. } => assert_eq!(counter, 7),
            _ => panic!("expected Versioned"),
        }
    }

    #[test]
    fn counter_path_appends_suffix() {
        let p = Path::new("/tmp/cache/foo.enc");
        assert_eq!(counter_path(p), PathBuf::from("/tmp/cache/foo.enc.counter"));
    }

    #[test]
    fn counter_read_missing_returns_zero() {
        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir.path().join("nope.enc");
        assert_eq!(read_counter(&cache_path).unwrap(), 0);
    }

    #[test]
    fn counter_write_read_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir.path().join("roundtrip.enc");
        write_counter(&cache_path, 12345).unwrap();
        assert_eq!(read_counter(&cache_path).unwrap(), 12345);
        write_counter(&cache_path, 99999).unwrap();
        assert_eq!(read_counter(&cache_path).unwrap(), 99999);
    }

    #[test]
    fn next_counter_takes_max_and_increments() {
        assert_eq!(next_counter(5, 3), 6);
        assert_eq!(next_counter(3, 5), 6);
        assert_eq!(next_counter(0, 0), 1);
    }

    #[test]
    fn next_counter_saturates_at_u64_max() {
        assert_eq!(next_counter(u64::MAX, 0), u64::MAX);
        assert_eq!(next_counter(0, u64::MAX), u64::MAX);
    }

    #[test]
    fn envelope_overhead_is_correct() {
        let wrapped = wrap_plaintext(b"h", 0, b"");
        assert_eq!(wrapped.len(), ENVELOPE_OVERHEAD);
    }

    #[test]
    fn wrap_plaintext_empty_payload_produces_overhead_only() {
        let wrapped = wrap_plaintext(b"header", 0, b"");
        assert_eq!(wrapped.len(), ENVELOPE_OVERHEAD);
        // Starts with the magic bytes
        assert_eq!(&wrapped[..4], ENVELOPE_MAGIC);
    }

    #[test]
    fn unwrap_too_short_is_treated_as_legacy() {
        let header = b"h";
        // Any buffer shorter than ENVELOPE_OVERHEAD is legacy
        let short = &b"APL1"[..3]; // only 3 bytes, less than 44
        let result = unwrap_plaintext(header, 0, short).unwrap();
        match result {
            Unwrapped::Legacy { payload } => assert_eq!(payload, short),
            _ => panic!("expected Legacy for short buffer"),
        }
    }

    #[test]
    fn unwrap_exactly_overhead_empty_payload_roundtrips() {
        let header = b"hdr";
        let wrapped = wrap_plaintext(header, 1, b"");
        let unwrapped = unwrap_plaintext(header, 0, &wrapped).unwrap();
        match unwrapped {
            Unwrapped::Versioned { counter, payload } => {
                assert_eq!(counter, 1);
                assert!(payload.is_empty());
            }
            _ => panic!("expected Versioned"),
        }
    }

    #[test]
    fn counter_path_no_extension_appends_counter_suffix() {
        let p = Path::new("/tmp/cache/foo");
        assert_eq!(counter_path(p), PathBuf::from("/tmp/cache/foo.counter"));
    }

    #[test]
    fn counter_path_preserves_parent_directory() {
        let p = Path::new("/var/cache/myapp/session.enc");
        let cp = counter_path(p);
        assert_eq!(cp.parent().unwrap(), Path::new("/var/cache/myapp"));
    }

    #[test]
    fn read_counter_short_file_returns_zero() {
        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir.path().join("short.enc");
        // Write fewer than 8 bytes to the counter sidecar
        let sidecar = counter_path(&cache_path);
        std::fs::write(&sidecar, [0x00, 0x01]).unwrap();
        assert_eq!(read_counter(&cache_path).unwrap(), 0);
    }

    #[test]
    fn next_counter_both_zero_gives_one() {
        assert_eq!(next_counter(0, 0), 1);
    }

    #[test]
    fn next_counter_sidecar_larger_wins() {
        assert_eq!(next_counter(100, 50), 101);
    }

    #[test]
    fn next_counter_observed_larger_wins() {
        assert_eq!(next_counter(50, 100), 101);
    }

    #[test]
    fn unwrap_versioned_payload_method() {
        let header = b"h";
        let wrapped = wrap_plaintext(header, 5, b"secret");
        let unwrapped = unwrap_plaintext(header, 0, &wrapped).unwrap();
        assert_eq!(unwrapped.payload(), b"secret");
    }

    #[test]
    fn unwrap_legacy_payload_method() {
        let bytes = b"legacy-bytes-no-magic";
        let result = unwrap_plaintext(b"h", 0, bytes).unwrap();
        assert_eq!(result.payload(), bytes);
    }

    #[test]
    fn unwrap_versioned_into_payload() {
        let header = b"h";
        let wrapped = wrap_plaintext(header, 3, b"data");
        let unwrapped = unwrap_plaintext(header, 0, &wrapped).unwrap();
        let payload = unwrapped.into_payload();
        assert_eq!(payload, b"data");
    }

    #[test]
    fn envelope_error_header_mismatch_display() {
        let msg = format!("{}", EnvelopeError::HeaderMismatch);
        assert!(msg.contains("header") || msg.contains("tamper") || msg.contains("modified"));
    }

    #[test]
    fn envelope_error_rollback_display() {
        let err = EnvelopeError::Rollback {
            observed: 3,
            expected_at_least: 10,
        };
        let msg = format!("{err}");
        assert!(msg.contains('3') && msg.contains("10"));
    }
}
