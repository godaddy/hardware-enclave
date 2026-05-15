// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Path and value quoting utilities for config file generation.
//!
//! Different config file formats have different quoting requirements:
//! - AWS credential_process: backslash/quote escaping, double-quote wrapping
//! - SSH config: forward-slash normalization on Windows, space-triggered quoting
//! - Shell config: no special quoting (values are shell expressions)

/// Quote a value for embedding in a config file.
///
/// If the value contains whitespace, double quotes, or backslashes, it is
/// escaped and wrapped in double quotes. Otherwise returned as-is.
///
/// Suitable for AWS `credential_process`, INI-style configs, and similar formats.
pub fn quote_config_value(value: &str) -> String {
    if value.is_empty() {
        return "\"\"".to_string();
    }

    let needs_quoting = value
        .chars()
        .any(|c| c.is_whitespace() || c == '"' || c == '\\');

    if needs_quoting {
        let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
        format!("\"{escaped}\"")
    } else {
        value.to_string()
    }
}

/// Quote a path for SSH config files.
///
/// On Windows, backslashes are converted to forward slashes (OpenSSH parser
/// requirement). Paths containing spaces are wrapped in double quotes.
pub fn quote_ssh_path(path: &std::path::Path) -> String {
    let s = path.display().to_string();

    #[cfg(windows)]
    let s = s.replace('\\', "/");

    if s.contains(' ') {
        format!("\"{s}\"")
    } else {
        s
    }
}

/// Quote a path specifically for the `credential_process` directive in AWS config.
///
/// This is identical to [`quote_config_value`] but takes a `Path` for convenience.
pub fn quote_credential_process_arg(path: &std::path::Path) -> String {
    quote_config_value(&path.display().to_string())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn quote_config_value_no_quoting_needed() {
        assert_eq!(quote_config_value("simple-path"), "simple-path");
        assert_eq!(quote_config_value("/usr/bin/awsenc"), "/usr/bin/awsenc");
    }

    #[test]
    fn quote_config_value_empty() {
        assert_eq!(quote_config_value(""), "\"\"");
    }

    #[test]
    fn quote_config_value_with_spaces() {
        assert_eq!(
            quote_config_value("/Program Files/app/bin"),
            "\"/Program Files/app/bin\""
        );
    }

    #[test]
    fn quote_config_value_with_backslashes() {
        assert_eq!(
            quote_config_value("C:\\Users\\jay\\bin"),
            "\"C:\\\\Users\\\\jay\\\\bin\""
        );
    }

    #[test]
    fn quote_config_value_with_quotes() {
        assert_eq!(
            quote_config_value("value with \"quotes\""),
            "\"value with \\\"quotes\\\"\""
        );
    }

    #[test]
    fn quote_config_value_mixed() {
        assert_eq!(
            quote_config_value("C:\\Program Files\\app"),
            "\"C:\\\\Program Files\\\\app\""
        );
    }

    #[test]
    fn quote_ssh_path_simple() {
        let path = PathBuf::from("/home/user/.sshenc/agent.sock");
        assert_eq!(quote_ssh_path(&path), "/home/user/.sshenc/agent.sock");
    }

    #[test]
    fn quote_ssh_path_with_spaces() {
        let path = PathBuf::from("/home/my user/.sshenc/agent.sock");
        assert_eq!(
            quote_ssh_path(&path),
            "\"/home/my user/.sshenc/agent.sock\""
        );
    }

    #[test]
    fn quote_credential_process_simple() {
        let path = PathBuf::from("/usr/local/bin/awsenc");
        assert_eq!(quote_credential_process_arg(&path), "/usr/local/bin/awsenc");
    }

    #[test]
    fn quote_credential_process_with_spaces() {
        let path = PathBuf::from("/Program Files/awsenc/awsenc");
        assert_eq!(
            quote_credential_process_arg(&path),
            "\"/Program Files/awsenc/awsenc\""
        );
    }

    #[test]
    fn quote_config_value_with_tab() {
        // Tab is whitespace, must be quoted
        let result = quote_config_value("key\tvalue");
        assert!(result.starts_with('"'));
        assert!(result.ends_with('"'));
    }

    #[test]
    fn quote_config_value_only_backslash() {
        assert_eq!(quote_config_value("\\"), "\"\\\\\"");
    }

    #[test]
    fn quote_config_value_only_double_quote() {
        assert_eq!(quote_config_value("\""), "\"\\\"\"");
    }

    #[test]
    fn quote_config_value_backslash_and_space() {
        // Both backslash and space present: both must be escaped
        let result = quote_config_value("C:\\Program Files");
        assert!(result.starts_with('"'));
        assert!(result.contains("\\\\"));
        assert!(result.contains(' '));
    }

    #[test]
    fn quote_config_value_newline_is_quoted() {
        // Newline is whitespace
        let result = quote_config_value("line1\nline2");
        assert!(result.starts_with('"'));
    }

    #[test]
    fn quote_ssh_path_no_spaces_not_quoted() {
        let path = PathBuf::from("/home/user/bin");
        let result = quote_ssh_path(&path);
        assert!(!result.starts_with('"'));
        assert_eq!(result, "/home/user/bin");
    }

    #[test]
    fn quote_credential_process_backslash_path() {
        // Backslash triggers quoting regardless of spaces
        let path = PathBuf::from("C:\\Windows\\System32\\app.exe");
        let result = quote_credential_process_arg(&path);
        assert!(result.starts_with('"'));
        // Backslashes should be doubled
        assert!(result.contains("\\\\"));
    }
}
