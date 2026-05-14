// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Shared binary cache format for enclave apps.
//!
//! Provides a generic, configurable binary cache format used by multiple enclave
//! applications (e.g. awsenc, sso-jwt). The format is:
//!
//! ```text
//! [4 bytes magic][1 byte version][1 byte flags][N bytes app-specific header][M length-prefixed blobs]
//! ```
//!
//! Each blob is encoded as a `u32` big-endian length followed by that many bytes.
//! File I/O uses atomic writes and restrictive permissions (0o600 on Unix).

use std::path::Path;

use enclaveapp_core::metadata;

pub mod envelope;

/// Error type for cache operations.
#[derive(Debug)]
pub enum CacheError {
    /// The file contained invalid magic bytes.
    BadMagic { expected: [u8; 4], actual: [u8; 4] },
    /// The file contained an unsupported format version.
    BadVersion { expected: u8, actual: u8 },
    /// The data was truncated (too short to contain the expected content).
    Truncated(String),
    /// An I/O error occurred.
    Io(std::io::Error),
}

impl std::fmt::Display for CacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadMagic { expected, actual } => {
                write!(
                    f,
                    "invalid magic bytes: expected {expected:?}, got {actual:?}"
                )
            }
            Self::BadVersion { expected, actual } => {
                write!(
                    f,
                    "unsupported format version: expected {expected}, got {actual}"
                )
            }
            Self::Truncated(msg) => write!(f, "truncated cache data: {msg}"),
            Self::Io(e) => write!(f, "cache I/O error: {e}"),
        }
    }
}

impl std::error::Error for CacheError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for CacheError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<enclaveapp_core::Error> for CacheError {
    fn from(e: enclaveapp_core::Error) -> Self {
        Self::Io(std::io::Error::other(e.to_string()))
    }
}

pub type Result<T> = std::result::Result<T, CacheError>;

/// Configuration for a binary cache format.
///
/// Each application creates a `CacheFormat` with its own magic bytes and version.
#[derive(Debug, Clone)]
pub struct CacheFormat {
    /// 4-byte magic identifier (e.g. `b"AWSE"`, `b"SJWT"`).
    pub magic: [u8; 4],
    /// Format version byte (e.g. `0x01`).
    pub version: u8,
}

/// A raw cache entry: flags + app-specific header bytes + length-prefixed blobs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheEntry {
    /// Flags byte from the header.
    pub flags: u8,
    /// App-specific header bytes between the flags byte and the first blob.
    ///
    /// For awsenc this is 16 bytes (expires_at + issued_at as i64 BE).
    /// For sso-jwt this is 16 bytes (token_iat + session_start as u64 BE).
    pub header_data: Vec<u8>,
    /// Encrypted blobs, each stored as `[u32 BE length][bytes]` in the file.
    pub blobs: Vec<Vec<u8>>,
}

/// Size of the fixed prefix: 4 (magic) + 1 (version) + 1 (flags).
const PREFIX_LEN: usize = 6;

impl CacheFormat {
    /// Create a new cache format with the given magic bytes and version.
    #[must_use]
    pub fn new(magic: [u8; 4], version: u8) -> Self {
        Self { magic, version }
    }

    /// Read a full cache entry from a file.
    ///
    /// Returns `Ok(None)` if the file does not exist.
    /// Returns `Err` if the file exists but is malformed.
    ///
    /// The `header_data_len` is the number of app-specific header bytes expected
    /// between the flags byte and the first blob.
    pub fn read(&self, path: &Path, header_data_len: usize) -> Result<Option<CacheEntry>> {
        if !path.exists() {
            return Ok(None);
        }
        let data = std::fs::read(path)?;
        self.decode(&data, header_data_len).map(Some)
    }

    /// Read only the header (flags + app-specific header bytes) without reading blobs.
    ///
    /// Returns `Ok(None)` if the file does not exist.
    /// Returns `Ok(Some((flags, header_data)))` on success.
    ///
    /// This is useful for status classification without decrypting ciphertext.
    pub fn read_header(
        &self,
        path: &Path,
        header_data_len: usize,
    ) -> Result<Option<(u8, Vec<u8>)>> {
        if !path.exists() {
            return Ok(None);
        }
        let data = std::fs::read(path)?;
        let min_len = PREFIX_LEN + header_data_len;
        if data.len() < min_len {
            return Err(CacheError::Truncated(format!(
                "need at least {min_len} bytes for header, got {}",
                data.len()
            )));
        }
        self.validate_prefix(&data)?;
        let flags = data[5];
        let header_data = data[PREFIX_LEN..PREFIX_LEN + header_data_len].to_vec();
        Ok(Some((flags, header_data)))
    }

    /// Write a cache entry atomically with restricted permissions.
    ///
    /// The `header_data_len` parameter is used only for validation: if the entry's
    /// `header_data` length doesn't match, this is a programming error and will panic
    /// in debug builds (and silently truncate/pad in release).
    pub fn write(&self, path: &Path, entry: &CacheEntry, header_data_len: usize) -> Result<()> {
        debug_assert_eq!(
            entry.header_data.len(),
            header_data_len,
            "header_data length mismatch: expected {header_data_len}, got {}",
            entry.header_data.len()
        );
        let encoded = self.encode(entry);

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        metadata::atomic_write(path, &encoded)?;
        #[cfg(unix)]
        metadata::restrict_file_permissions(path)?;
        Ok(())
    }

    /// Encode a cache entry into bytes.
    #[must_use]
    pub fn encode(&self, entry: &CacheEntry) -> Vec<u8> {
        let blob_size: usize = entry.blobs.iter().map(|b| 4 + b.len()).sum();
        let capacity = PREFIX_LEN + entry.header_data.len() + blob_size;
        let mut buf = Vec::with_capacity(capacity);

        // Fixed prefix
        buf.extend_from_slice(&self.magic);
        buf.push(self.version);
        buf.push(entry.flags);

        // App-specific header
        buf.extend_from_slice(&entry.header_data);

        // Length-prefixed blobs
        for blob in &entry.blobs {
            let len = u32::try_from(blob.len()).unwrap_or(u32::MAX);
            buf.extend_from_slice(&len.to_be_bytes());
            buf.extend_from_slice(blob);
        }

        buf
    }

    /// Decode a cache entry from bytes.
    ///
    /// `header_data_len` is the expected number of app-specific header bytes.
    pub fn decode(&self, data: &[u8], header_data_len: usize) -> Result<CacheEntry> {
        let min_len = PREFIX_LEN + header_data_len;
        if data.len() < min_len {
            return Err(CacheError::Truncated(format!(
                "need at least {min_len} bytes, got {}",
                data.len()
            )));
        }

        self.validate_prefix(data)?;

        let flags = data[5];
        let header_data = data[PREFIX_LEN..PREFIX_LEN + header_data_len].to_vec();

        // Parse blobs
        let mut offset = PREFIX_LEN + header_data_len;
        let mut blobs = Vec::new();

        while offset + 4 <= data.len() {
            let blob_len = read_u32_be(data, offset) as usize;
            offset += 4;
            if offset + blob_len > data.len() {
                return Err(CacheError::Truncated(format!(
                    "blob claims {blob_len} bytes at offset {}, but only {} bytes remain",
                    offset - 4,
                    data.len() - offset
                )));
            }
            blobs.push(data[offset..offset + blob_len].to_vec());
            offset += blob_len;
        }

        Ok(CacheEntry {
            flags,
            header_data,
            blobs,
        })
    }

    /// Validate the magic and version prefix.
    fn validate_prefix(&self, data: &[u8]) -> Result<()> {
        if data.len() < PREFIX_LEN {
            return Err(CacheError::Truncated(format!(
                "need at least {PREFIX_LEN} bytes for prefix, got {}",
                data.len()
            )));
        }

        let mut actual_magic = [0_u8; 4];
        actual_magic.copy_from_slice(&data[0..4]);
        if actual_magic != self.magic {
            return Err(CacheError::BadMagic {
                expected: self.magic,
                actual: actual_magic,
            });
        }

        let actual_version = data[4];
        if actual_version != self.version {
            return Err(CacheError::BadVersion {
                expected: self.version,
                actual: actual_version,
            });
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Big-endian helpers
// ---------------------------------------------------------------------------

/// Read a `u32` in big-endian byte order from `data` at the given offset.
///
/// # Panics
///
/// Panics if `offset + 4 > data.len()`.
#[must_use]
pub fn read_u32_be(data: &[u8], offset: usize) -> u32 {
    let bytes: [u8; 4] = data[offset..offset + 4]
        .try_into()
        .expect("slice is exactly 4 bytes");
    u32::from_be_bytes(bytes)
}

/// Write a `u32` in big-endian byte order into `buf`.
pub fn write_u32_be(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_be_bytes());
}

/// Read an `i64` in big-endian byte order from `data` at the given offset.
///
/// # Panics
///
/// Panics if `offset + 8 > data.len()`.
#[must_use]
pub fn read_i64_be(data: &[u8], offset: usize) -> i64 {
    let bytes: [u8; 8] = data[offset..offset + 8]
        .try_into()
        .expect("slice is exactly 8 bytes");
    i64::from_be_bytes(bytes)
}

/// Write an `i64` in big-endian byte order into `buf`.
pub fn write_i64_be(buf: &mut Vec<u8>, value: i64) {
    buf.extend_from_slice(&value.to_be_bytes());
}

/// Read a `u64` in big-endian byte order from `data` at the given offset.
///
/// # Panics
///
/// Panics if `offset + 8 > data.len()`.
#[must_use]
pub fn read_u64_be(data: &[u8], offset: usize) -> u64 {
    let bytes: [u8; 8] = data[offset..offset + 8]
        .try_into()
        .expect("slice is exactly 8 bytes");
    u64::from_be_bytes(bytes)
}

/// Write a `u64` in big-endian byte order into `buf`.
pub fn write_u64_be(buf: &mut Vec<u8>, value: u64) {
    buf.extend_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::fs;

    const TEST_MAGIC: [u8; 4] = *b"TEST";
    const TEST_VERSION: u8 = 0x01;

    fn test_format() -> CacheFormat {
        CacheFormat::new(TEST_MAGIC, TEST_VERSION)
    }

    // ---- Encode/decode round-trips ----

    #[test]
    fn round_trip_zero_blobs() {
        let fmt = test_format();
        let entry = CacheEntry {
            flags: 0x00,
            header_data: vec![0xAA, 0xBB, 0xCC, 0xDD],
            blobs: vec![],
        };
        let encoded = fmt.encode(&entry);
        let decoded = fmt.decode(&encoded, 4).unwrap();
        assert_eq!(decoded, entry);
    }

    #[test]
    fn round_trip_one_blob() {
        let fmt = test_format();
        let entry = CacheEntry {
            flags: 0x42,
            header_data: vec![1, 2, 3, 4, 5, 6, 7, 8],
            blobs: vec![vec![10, 20, 30]],
        };
        let encoded = fmt.encode(&entry);
        let decoded = fmt.decode(&encoded, 8).unwrap();
        assert_eq!(decoded, entry);
    }

    #[test]
    fn round_trip_two_blobs() {
        let fmt = test_format();
        let entry = CacheEntry {
            flags: 0x01,
            header_data: vec![0; 16],
            blobs: vec![vec![1, 2, 3], vec![4, 5, 6, 7]],
        };
        let encoded = fmt.encode(&entry);
        let decoded = fmt.decode(&encoded, 16).unwrap();
        assert_eq!(decoded, entry);
    }

    #[test]
    fn round_trip_three_blobs() {
        let fmt = test_format();
        let entry = CacheEntry {
            flags: 0xFF,
            header_data: vec![],
            blobs: vec![vec![0xAA], vec![0xBB, 0xCC], vec![0xDD, 0xEE, 0xFF]],
        };
        let encoded = fmt.encode(&entry);
        let decoded = fmt.decode(&encoded, 0).unwrap();
        assert_eq!(decoded, entry);
    }

    #[test]
    fn round_trip_empty_blobs() {
        let fmt = test_format();
        let entry = CacheEntry {
            flags: 0x00,
            header_data: vec![1, 2],
            blobs: vec![vec![], vec![], vec![]],
        };
        let encoded = fmt.encode(&entry);
        let decoded = fmt.decode(&encoded, 2).unwrap();
        assert_eq!(decoded, entry);
    }

    #[test]
    fn round_trip_large_blob() {
        let fmt = test_format();
        let big = vec![0xAB; 100_000];
        let entry = CacheEntry {
            flags: 0x00,
            header_data: vec![0; 8],
            blobs: vec![big],
        };
        let encoded = fmt.encode(&entry);
        let decoded = fmt.decode(&encoded, 8).unwrap();
        assert_eq!(decoded, entry);
    }

    #[test]
    fn round_trip_no_header_data() {
        let fmt = test_format();
        let entry = CacheEntry {
            flags: 0x03,
            header_data: vec![],
            blobs: vec![vec![1, 2, 3]],
        };
        let encoded = fmt.encode(&entry);
        let decoded = fmt.decode(&encoded, 0).unwrap();
        assert_eq!(decoded, entry);
    }

    // ---- Error cases ----

    #[test]
    fn decode_wrong_magic() {
        let fmt = test_format();
        let mut data = vec![0x00, 0x00, 0x00, 0x00, TEST_VERSION, 0x00];
        data.extend_from_slice(&[0; 8]);
        let err = fmt.decode(&data, 8).unwrap_err();
        match err {
            CacheError::BadMagic { expected, actual } => {
                assert_eq!(expected, TEST_MAGIC);
                assert_eq!(actual, [0x00, 0x00, 0x00, 0x00]);
            }
            other => panic!("expected BadMagic, got: {other}"),
        }
    }

    #[test]
    fn decode_wrong_version() {
        let fmt = test_format();
        let mut data = Vec::new();
        data.extend_from_slice(&TEST_MAGIC);
        data.push(0xFF);
        data.push(0x00);
        data.extend_from_slice(&[0; 8]);
        let err = fmt.decode(&data, 8).unwrap_err();
        match err {
            CacheError::BadVersion { expected, actual } => {
                assert_eq!(expected, TEST_VERSION);
                assert_eq!(actual, 0xFF);
            }
            other => panic!("expected BadVersion, got: {other}"),
        }
    }

    #[test]
    fn decode_truncated_too_short_for_prefix() {
        let fmt = test_format();
        let data = vec![0x54, 0x45, 0x53, 0x54]; // just magic, no version/flags
        let err = fmt.decode(&data, 0).unwrap_err();
        assert!(matches!(err, CacheError::Truncated(_)));
    }

    #[test]
    fn decode_truncated_too_short_for_header_data() {
        let fmt = test_format();
        // Valid prefix but not enough bytes for 16 bytes of header_data
        let mut data = Vec::new();
        data.extend_from_slice(&TEST_MAGIC);
        data.push(TEST_VERSION);
        data.push(0x00);
        data.extend_from_slice(&[0; 4]); // only 4 bytes, need 16
        let err = fmt.decode(&data, 16).unwrap_err();
        assert!(matches!(err, CacheError::Truncated(_)));
    }

    #[test]
    fn decode_truncated_blob_data() {
        let fmt = test_format();
        let mut data = Vec::new();
        data.extend_from_slice(&TEST_MAGIC);
        data.push(TEST_VERSION);
        data.push(0x00);
        // 4 bytes header_data
        data.extend_from_slice(&[0; 4]);
        // Blob length says 100 but we only provide 2 bytes
        data.extend_from_slice(&100_u32.to_be_bytes());
        data.extend_from_slice(&[0xAA, 0xBB]);
        let err = fmt.decode(&data, 4).unwrap_err();
        assert!(matches!(err, CacheError::Truncated(_)));
    }

    #[test]
    fn decode_trailing_bytes_less_than_4_ignored() {
        // If there are 1-3 trailing bytes after the last blob, they're
        // not enough to form a u32 length prefix so they're silently ignored.
        let fmt = test_format();
        let entry = CacheEntry {
            flags: 0x00,
            header_data: vec![0; 4],
            blobs: vec![vec![1, 2, 3]],
        };
        let mut encoded = fmt.encode(&entry);
        encoded.extend_from_slice(&[0xFF, 0xFF]); // trailing garbage < 4 bytes
        let decoded = fmt.decode(&encoded, 4).unwrap();
        assert_eq!(decoded, entry);
    }

    // ---- File I/O ----

    #[test]
    fn write_and_read_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.enc");
        let fmt = test_format();
        let entry = CacheEntry {
            flags: 0x01,
            header_data: vec![0xDE, 0xAD, 0xBE, 0xEF],
            blobs: vec![vec![1, 2, 3, 4, 5]],
        };
        fmt.write(&path, &entry, 4).unwrap();
        let loaded = fmt.read(&path, 4).unwrap().unwrap();
        assert_eq!(loaded, entry);
    }

    #[test]
    fn read_nonexistent_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent.enc");
        let fmt = test_format();
        let result = fmt.read(&path, 4).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn read_header_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("header.enc");
        let fmt = test_format();
        let entry = CacheEntry {
            flags: 0x42,
            header_data: vec![1, 2, 3, 4, 5, 6, 7, 8],
            blobs: vec![vec![0xAA; 1000]],
        };
        fmt.write(&path, &entry, 8).unwrap();

        let (flags, header_data) = fmt.read_header(&path, 8).unwrap().unwrap();
        assert_eq!(flags, 0x42);
        assert_eq!(header_data, vec![1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn read_header_nonexistent_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent.enc");
        let fmt = test_format();
        let result = fmt.read_header(&path, 8).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn read_header_truncated_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("truncated.enc");
        // Write a file shorter than the expected header
        fs::write(&path, [0x54, 0x45, 0x53, 0x54, 0x01]).unwrap();
        let fmt = test_format();
        let err = fmt.read_header(&path, 8).unwrap_err();
        assert!(matches!(err, CacheError::Truncated(_)));
    }

    #[test]
    fn write_creates_parent_directories() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a").join("b").join("c").join("test.enc");
        let fmt = test_format();
        let entry = CacheEntry {
            flags: 0x00,
            header_data: vec![],
            blobs: vec![],
        };
        fmt.write(&path, &entry, 0).unwrap();
        assert!(path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn write_sets_restricted_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("perms.enc");
        let fmt = test_format();
        let entry = CacheEntry {
            flags: 0x00,
            header_data: vec![0; 4],
            blobs: vec![vec![1]],
        };
        fmt.write(&path, &entry, 4).unwrap();

        let metadata = fs::metadata(&path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0600 permissions, got {mode:o}");
    }

    #[test]
    fn write_is_atomic_overwrites_existing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("overwrite.enc");
        let fmt = test_format();

        let entry1 = CacheEntry {
            flags: 0x01,
            header_data: vec![1, 2, 3, 4],
            blobs: vec![vec![0xAA]],
        };
        fmt.write(&path, &entry1, 4).unwrap();

        let entry2 = CacheEntry {
            flags: 0x02,
            header_data: vec![5, 6, 7, 8],
            blobs: vec![vec![0xBB, 0xCC]],
        };
        fmt.write(&path, &entry2, 4).unwrap();

        let loaded = fmt.read(&path, 4).unwrap().unwrap();
        assert_eq!(loaded, entry2);
    }

    // ---- Big-endian helpers ----

    #[test]
    fn u32_be_helpers() {
        let mut buf = Vec::new();
        write_u32_be(&mut buf, 0x0102_0304);
        assert_eq!(buf, vec![0x01, 0x02, 0x03, 0x04]);
        assert_eq!(read_u32_be(&buf, 0), 0x0102_0304);
    }

    #[test]
    fn i64_be_helpers() {
        let mut buf = Vec::new();
        write_i64_be(&mut buf, -1);
        assert_eq!(buf, vec![0xFF; 8]);
        assert_eq!(read_i64_be(&buf, 0), -1);

        let mut buf2 = Vec::new();
        write_i64_be(&mut buf2, 1_700_000_000);
        assert_eq!(read_i64_be(&buf2, 0), 1_700_000_000);
    }

    #[test]
    fn u64_be_helpers() {
        let mut buf = Vec::new();
        write_u64_be(&mut buf, 0x0102_0304_0506_0708);
        assert_eq!(buf, vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        assert_eq!(read_u64_be(&buf, 0), 0x0102_0304_0506_0708);
    }

    #[test]
    fn be_helpers_with_offset() {
        let data = vec![0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert_eq!(read_u32_be(&data, 2), 0x0102_0304);
        assert_eq!(read_i64_be(&data, 2), 0x0102_0304_0506_0708);
        assert_eq!(read_u64_be(&data, 2), 0x0102_0304_0506_0708);
    }

    // ---- Display/Error trait coverage ----

    #[test]
    fn error_display_bad_magic() {
        let e = CacheError::BadMagic {
            expected: *b"TEST",
            actual: *b"XXXX",
        };
        let msg = e.to_string();
        assert!(msg.contains("invalid magic"));
    }

    #[test]
    fn error_display_bad_version() {
        let e = CacheError::BadVersion {
            expected: 1,
            actual: 99,
        };
        let msg = e.to_string();
        assert!(msg.contains("unsupported format version"));
        assert!(msg.contains("99"));
    }

    #[test]
    fn error_display_truncated() {
        let e = CacheError::Truncated("test message".into());
        assert!(e.to_string().contains("truncated"));
    }

    #[test]
    fn error_display_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let e = CacheError::Io(io_err);
        assert!(e.to_string().contains("file missing"));
    }

    #[test]
    fn error_source_io() {
        let io_err = std::io::Error::other("inner");
        let e = CacheError::Io(io_err);
        assert!(std::error::Error::source(&e).is_some());
    }

    #[test]
    fn error_source_non_io() {
        let e = CacheError::BadMagic {
            expected: *b"TEST",
            actual: *b"XXXX",
        };
        assert!(std::error::Error::source(&e).is_none());
    }

    // ---- Simulated awsenc format ----

    #[test]
    fn awsenc_format_round_trip() {
        let fmt = CacheFormat::new(*b"AWSE", 0x01);

        // Build header_data: expires_at (i64 BE) + issued_at (i64 BE)
        let mut hdr = Vec::new();
        write_i64_be(&mut hdr, 1_700_000_000);
        write_i64_be(&mut hdr, 1_699_996_400);
        assert_eq!(hdr.len(), 16);

        let entry = CacheEntry {
            flags: 0x01, // has_okta_session
            header_data: hdr,
            blobs: vec![
                vec![0xDE, 0xAD, 0xBE, 0xEF], // AWS ciphertext
                vec![0xCA, 0xFE],             // Okta session ciphertext
            ],
        };

        let encoded = fmt.encode(&entry);
        let decoded = fmt.decode(&encoded, 16).unwrap();
        assert_eq!(decoded, entry);

        // Verify we can read back the timestamps
        let expires_at = read_i64_be(&decoded.header_data, 0);
        let issued_at = read_i64_be(&decoded.header_data, 8);
        assert_eq!(expires_at, 1_700_000_000);
        assert_eq!(issued_at, 1_699_996_400);
    }

    /// Atomic rename-over semantics: an open file descriptor from before the
    /// write still sees the old content; a fresh `read()` from the path sees
    /// the new content. This verifies that `write()` uses atomic rename rather
    /// than truncate-in-place, which would corrupt in-progress readers.
    #[cfg(unix)]
    #[test]
    fn write_atomic_old_fd_sees_old_content_new_reader_sees_new_content() {
        use std::io::Read;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("atomic.enc");
        let fmt = test_format();

        let entry1 = CacheEntry {
            flags: 0x01,
            header_data: vec![0xAA, 0xBB, 0xCC, 0xDD],
            blobs: vec![vec![0x11, 0x22]],
        };
        fmt.write(&path, &entry1, 4).unwrap();

        // Open an fd to the current file (old inode) before the overwrite.
        let mut old_fd = fs::File::open(&path).unwrap();
        let mut old_bytes = Vec::new();
        old_fd.read_to_end(&mut old_bytes).unwrap();

        let entry2 = CacheEntry {
            flags: 0x02,
            header_data: vec![0x55, 0x66, 0x77, 0x88],
            blobs: vec![vec![0x33, 0x44, 0x55]],
        };
        fmt.write(&path, &entry2, 4).unwrap();

        // New reader via path sees entry2.
        let loaded_new = fmt.read(&path, 4).unwrap().unwrap();
        assert_eq!(loaded_new, entry2, "new reader must see entry2 after write");

        // Old bytes (read before rename) must decode as entry1.
        let loaded_old = fmt.decode(&old_bytes, 4).unwrap();
        assert_eq!(
            loaded_old, entry1,
            "fd opened before atomic overwrite must still see entry1"
        );
    }

    // ---- Simulated sso-jwt format ----

    #[test]
    fn ssojwt_format_round_trip() {
        let fmt = CacheFormat::new(*b"SJWT", 0x01);

        // Build header_data: token_iat (u64 BE) + session_start (u64 BE)
        let mut hdr = Vec::new();
        write_u64_be(&mut hdr, 1_700_000_000);
        write_u64_be(&mut hdr, 1_699_990_000);
        assert_eq!(hdr.len(), 16);

        let entry = CacheEntry {
            flags: 2, // risk_level
            header_data: hdr,
            blobs: vec![vec![0x01, 0x02, 0x03]], // JWT ciphertext
        };

        let encoded = fmt.encode(&entry);
        let decoded = fmt.decode(&encoded, 16).unwrap();
        assert_eq!(decoded, entry);

        let token_iat = read_u64_be(&decoded.header_data, 0);
        let session_start = read_u64_be(&decoded.header_data, 8);
        assert_eq!(token_iat, 1_700_000_000);
        assert_eq!(session_start, 1_699_990_000);
    }
}
