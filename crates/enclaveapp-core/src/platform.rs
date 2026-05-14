// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Platform detection utilities.

/// Returns true if running on macOS.
pub fn is_macos() -> bool {
    cfg!(target_os = "macos")
}

/// Returns true if running on Windows.
pub fn is_windows() -> bool {
    cfg!(target_os = "windows")
}

/// Returns true if running inside Windows Subsystem for Linux.
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

/// Returns a human-readable name for the current platform's hardware security module.
pub fn hardware_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "Secure Enclave"
    } else if cfg!(target_os = "windows") {
        "TPM 2.0"
    } else {
        "none"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_functions_are_consistent() {
        // At most one of these can be true
        let count = [is_macos(), is_windows()].iter().filter(|&&v| v).count();
        assert!(count <= 1);
    }

    #[test]
    fn hardware_name_is_not_empty() {
        let name = hardware_name();
        assert!(!name.is_empty());
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn is_macos_true_on_macos() {
        assert!(is_macos());
        assert!(!is_windows());
        assert_eq!(hardware_name(), "Secure Enclave");
        assert!(!is_wsl());
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn is_windows_true_on_windows() {
        assert!(is_windows());
        assert!(!is_macos());
        assert_eq!(hardware_name(), "TPM 2.0");
        assert!(!is_wsl());
    }

    #[test]
    fn hardware_name_is_one_of_known_values() {
        let name = hardware_name();
        assert!(
            name == "Secure Enclave" || name == "TPM 2.0" || name == "none",
            "unexpected hardware_name: {name}"
        );
    }

    #[test]
    fn is_macos_and_is_windows_are_mutually_exclusive() {
        assert!(!(is_macos() && is_windows()));
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn is_wsl_false_on_non_linux() {
        assert!(!is_wsl());
    }
}
