// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! WSL detection and distribution enumeration.

/// Decode WSL output, handling UTF-8, UTF-16LE BOM, and common UTF-16LE-without-BOM output.
pub fn decode_wsl_output(bytes: &[u8]) -> String {
    if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE {
        return decode_utf16le(&bytes[2..]);
    }

    let nul_bytes = bytes.iter().filter(|&&b| b == 0).count();
    if bytes.len() >= 4 && nul_bytes >= bytes.len() / 4 {
        return decode_utf16le(bytes);
    }

    String::from_utf8_lossy(bytes).to_string()
}

fn decode_utf16le(bytes: &[u8]) -> String {
    let u16s: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();
    String::from_utf16_lossy(&u16s)
}

/// Information about a detected WSL distribution.
#[derive(Debug, Clone)]
pub struct WslDistro {
    /// Distribution name (e.g., "Ubuntu", "Debian").
    pub name: String,
    /// Windows UNC path to the distro's home directory
    /// (e.g., `\\wsl.localhost\Ubuntu\home\user`).
    pub home_path: Option<std::path::PathBuf>,
}

/// Returns true if the current process is running inside WSL.
pub fn is_wsl() -> bool {
    #[cfg(target_os = "linux")]
    {
        if std::env::var("WSL_DISTRO_NAME").is_ok() {
            return true;
        }
        if let Ok(version) = std::fs::read_to_string("/proc/version") {
            let lower = version.to_lowercase();
            if lower.contains("microsoft") || lower.contains("wsl") {
                return true;
            }
        }
        false
    }
    #[cfg(not(target_os = "linux"))]
    false
}

/// Detect installed WSL distributions (runs on Windows host).
///
/// Returns an empty list on non-Windows platforms.
pub fn detect_distros() -> Vec<WslDistro> {
    #[cfg(target_os = "windows")]
    {
        use enclaveapp_core::timeout::{run_with_timeout, TimeoutResult};
        use std::time::Duration;
        // Run: wsl --list --quiet — normally sub-second. Cap at 15s so a
        // wedged WSL service can't freeze callers.
        let mut cmd = std::process::Command::new("wsl");
        cmd.args(["--list", "--quiet"]);
        let output = match run_with_timeout(cmd, Duration::from_secs(15)) {
            Ok(TimeoutResult::Completed(o)) if o.status.success() => o,
            _ => return Vec::new(),
        };

        let stdout = decode_wsl_output(&output.stdout);
        let names: Vec<String> = stdout
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();

        names
            .into_iter()
            .map(|name| {
                let home_path = get_distro_home(&name);
                WslDistro { name, home_path }
            })
            .collect()
    }
    #[cfg(not(target_os = "windows"))]
    Vec::new()
}

/// Get the home directory path for a WSL distro, converted to a Windows UNC path.
#[cfg(target_os = "windows")]
fn get_distro_home(distro: &str) -> Option<std::path::PathBuf> {
    let home = linux_home(distro)?;
    if home.is_empty() {
        return None;
    }
    // Convert Linux path to Windows UNC path
    Some(std::path::PathBuf::from(format!(
        "\\\\wsl.localhost\\{distro}{home}"
    )))
}

/// Resolve a distro's `$HOME` by running a shell inside WSL.
#[cfg(target_os = "windows")]
pub(crate) fn linux_home(distro: &str) -> Option<String> {
    use enclaveapp_core::timeout::{run_with_timeout, TimeoutResult};
    use std::time::Duration;
    let mut cmd = std::process::Command::new("wsl");
    cmd.args(["-d", distro, "-e", "sh", "-lc", r#"printf '%s' "$HOME""#]);
    let output = match run_with_timeout(cmd, Duration::from_secs(15)) {
        Ok(TimeoutResult::Completed(o)) => o,
        _ => return None,
    };
    if !output.status.success() {
        return None;
    }
    let home = decode_wsl_output(&output.stdout).trim().to_string();
    if home.is_empty() {
        return None;
    }
    Some(home)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_is_wsl_false_on_non_linux() {
        // On macOS (where CI runs), is_wsl() must return false.
        #[cfg(not(target_os = "linux"))]
        assert!(!is_wsl());
    }

    #[test]
    fn test_detect_distros_empty_on_non_windows() {
        // On macOS/Linux, detect_distros() returns empty.
        #[cfg(not(target_os = "windows"))]
        assert!(detect_distros().is_empty());
    }

    #[test]
    fn test_decode_wsl_output_utf16le_without_bom() {
        let bytes = b"U\0b\0u\0n\0t\0u\0";
        assert_eq!(decode_wsl_output(bytes), "Ubuntu");
    }

    #[test]
    fn decode_wsl_output_pure_utf8_returns_as_is() {
        let bytes = b"hello world";
        assert_eq!(decode_wsl_output(bytes), "hello world");
    }

    #[test]
    fn decode_wsl_output_empty_bytes_returns_empty_string() {
        assert_eq!(decode_wsl_output(b""), "");
    }

    #[test]
    fn decode_wsl_output_utf16le_with_bom_decoded() {
        // 0xFF 0xFE = BOM, followed by "Hi" in UTF-16LE
        let bytes: &[u8] = &[0xFF, 0xFE, b'H', 0, b'i', 0];
        assert_eq!(decode_wsl_output(bytes), "Hi");
    }

    #[test]
    fn decode_wsl_output_only_bom_returns_empty() {
        let bytes: &[u8] = &[0xFF, 0xFE];
        assert_eq!(decode_wsl_output(bytes), "");
    }

    #[test]
    fn decode_wsl_output_utf16le_bom_with_newline() {
        // BOM + "A\n" in UTF-16LE
        let bytes: &[u8] = &[0xFF, 0xFE, b'A', 0, b'\n', 0];
        assert_eq!(decode_wsl_output(bytes), "A\n");
    }

    #[test]
    fn decode_wsl_output_ascii_no_nulls_treated_as_utf8() {
        let bytes = b"Debian";
        assert_eq!(decode_wsl_output(bytes), "Debian");
    }

    #[test]
    fn decode_wsl_output_high_null_density_treated_as_utf16le() {
        // "ABCD" as UTF-16LE without BOM: 8 bytes, 4 nulls (density = 50% > 25%)
        let bytes: &[u8] = &[b'A', 0, b'B', 0, b'C', 0, b'D', 0];
        assert_eq!(decode_wsl_output(bytes), "ABCD");
    }

    #[test]
    fn decode_wsl_output_low_null_density_treated_as_utf8() {
        // 8 bytes with only 1 null (density = 12.5% < 25%) → UTF-8
        let bytes: &[u8] = &[b'A', b'B', b'C', b'D', b'E', b'F', b'G', 0];
        // from_utf8_lossy on bytes with embedded NUL: the NUL survives as NUL char
        let result = decode_wsl_output(bytes);
        assert!(result.starts_with("ABCDEFG"));
    }

    #[test]
    fn decode_wsl_output_utf16le_bom_multiline() {
        // BOM + "Ubuntu\nDebian" in UTF-16LE
        let mut bytes = vec![0xFF_u8, 0xFE];
        for ch in "Ubuntu\nDebian".encode_utf16() {
            bytes.extend_from_slice(&ch.to_le_bytes());
        }
        let result = decode_wsl_output(&bytes);
        assert!(result.contains("Ubuntu"));
        assert!(result.contains("Debian"));
    }

    #[test]
    fn decode_wsl_output_utf16le_without_bom_multiline() {
        // "Ubuntu\nDebian" as UTF-16LE without BOM (high null density)
        let mut bytes: Vec<u8> = Vec::new();
        for ch in "Ubuntu\nDebian".encode_utf16() {
            bytes.extend_from_slice(&ch.to_le_bytes());
        }
        let result = decode_wsl_output(&bytes);
        assert!(result.contains("Ubuntu"));
        assert!(result.contains("Debian"));
    }

    #[test]
    fn decode_wsl_output_three_bytes_not_bom_not_utf16le() {
        // Fewer than 4 bytes can't hit the null-density branch
        let bytes: &[u8] = &[b'A', 0, b'B'];
        // 3 bytes, 1 null: len < 4 so nul_density check fails → UTF-8
        let result = decode_wsl_output(bytes);
        assert!(result.contains('A'));
    }

    #[test]
    fn decode_wsl_output_utf8_with_multibyte_char() {
        let input = "Ubuntu 22.04 LTS";
        assert_eq!(decode_wsl_output(input.as_bytes()), input);
    }

    #[test]
    fn decode_utf16le_odd_length_ignores_trailing_byte() {
        // chunks_exact(2) silently drops the trailing unpaired byte.
        // "AB" as UTF-16LE = [0x41, 0x00, 0x42, 0x00], plus one extra byte.
        let bytes: &[u8] = &[0x41, 0x00, 0x42, 0x00, 0xFF];
        assert_eq!(decode_utf16le(bytes), "AB");
    }

    #[test]
    fn decode_utf16le_non_ascii_codepoint() {
        // U+00E9 LATIN SMALL LETTER E WITH ACUTE, encoded as UTF-16LE: [0xE9, 0x00]
        let bytes: &[u8] = &[0xE9, 0x00];
        assert_eq!(decode_utf16le(bytes), "\u{00E9}");
    }
}
