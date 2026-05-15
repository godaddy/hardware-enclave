// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Managed block injection/removal for shell config files.
//!
//! Supports injecting and removing comment-delimited blocks in `.bashrc`,
//! `.zshrc`, `.profile`, etc. Each block is parameterized by application name
//! so multiple enclave apps can coexist without conflicts.

use enclaveapp_core::Result;
use std::path::Path;

/// Configuration for managed shell blocks.
#[derive(Debug)]
pub struct ShellBlockConfig {
    /// Application name, used in markers.
    pub app_name: String,
    /// The content to inject between markers (the shell script body).
    pub block_content: String,
}

impl ShellBlockConfig {
    pub fn new(app_name: &str, block_content: &str) -> Self {
        ShellBlockConfig {
            app_name: app_name.to_string(),
            block_content: block_content.to_string(),
        }
    }

    fn begin_marker(&self) -> String {
        format!("# BEGIN {} managed block -- do not edit", self.app_name)
    }

    fn end_marker(&self) -> String {
        format!("# END {} managed block", self.app_name)
    }

    fn full_block(&self) -> String {
        format!(
            "{}\n{}\n{}",
            self.begin_marker(),
            self.block_content,
            self.end_marker()
        )
    }
}

/// Result of an install operation.
#[derive(Debug, PartialEq, Eq)]
pub enum InstallResult {
    Installed,
    AlreadyPresent,
}

/// Result of an uninstall operation.
#[derive(Debug, PartialEq, Eq)]
pub enum UninstallResult {
    Removed,
    NotPresent,
}

/// Check if a managed block is present in the given file.
pub fn is_installed(path: &Path, config: &ShellBlockConfig) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let content = std::fs::read_to_string(path)?;
    Ok(content.contains(&config.begin_marker()))
}

/// Install a managed block into a shell config file.
///
/// Three outcomes:
///
/// - **Block missing** → append the new block at the end of the
///   file, separated by a blank line from any existing content.
///   Returns `Installed`.
/// - **Block present with the *same* content** → no-op.
///   Returns `AlreadyPresent`.
/// - **Block present with *different* content** (e.g. an older
///   release of the same app shipped a different shell block) →
///   replace the block in place, preserving everything outside the
///   markers. Returns `Installed`. This is what makes
///   `sshenc install` on a newer release actually update the
///   bashrc — without this, an older marker keeps the old block
///   alive forever and the user never gets the v0.6.37 native-only
///   transport.
///
/// Creates the file and parent directories if needed.
pub fn install_block(path: &Path, config: &ShellBlockConfig) -> Result<InstallResult> {
    let content = if path.exists() {
        std::fs::read_to_string(path)?
    } else {
        String::new()
    };

    // Normalize line endings
    let content = content.replace("\r\n", "\n");
    let begin = config.begin_marker();
    let end = config.end_marker();
    let new_block = config.full_block();

    // Block already present — diff it against the current shipped
    // content. If identical, no-op; if different, replace in place.
    if let Some(begin_idx) = content.find(&begin) {
        if let Some(rel_end_idx) = content[begin_idx..].find(&end) {
            let block_end = begin_idx + rel_end_idx + end.len();
            let existing = &content[begin_idx..block_end];
            if existing == new_block {
                return Ok(InstallResult::AlreadyPresent);
            }
            // Replace the block in place — keep everything before
            // and after the markers exactly as-is.
            let mut output = String::with_capacity(content.len() + new_block.len());
            output.push_str(&content[..begin_idx]);
            output.push_str(&new_block);
            output.push_str(&content[block_end..]);
            std::fs::write(path, &output)?;
            return Ok(InstallResult::Installed);
        }
        // BEGIN marker present but no END marker — file got
        // truncated or hand-edited. Fall through to append, even
        // though that produces a messy file; better than refusing
        // to install. The duplicate BEGIN will be picked up by
        // `uninstall_block` and `is_installed`.
    }

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut output = content;
    // Ensure existing content ends with newline
    if !output.is_empty() && !output.ends_with('\n') {
        output.push('\n');
    }
    // Add blank separator line if there's existing content
    if !output.is_empty() {
        output.push('\n');
    }
    output.push_str(&new_block);
    output.push('\n');

    std::fs::write(path, &output)?;
    Ok(InstallResult::Installed)
}

/// Remove a managed block from a shell config file.
///
/// Removes everything between (and including) the BEGIN and END markers,
/// plus any single blank line immediately before the block.
pub fn uninstall_block(path: &Path, config: &ShellBlockConfig) -> Result<UninstallResult> {
    if !path.exists() {
        return Ok(UninstallResult::NotPresent);
    }

    let content = std::fs::read_to_string(path)?;
    let content = content.replace("\r\n", "\n");

    if !content.contains(&config.begin_marker()) {
        return Ok(UninstallResult::NotPresent);
    }

    let begin = &config.begin_marker();
    let end = &config.end_marker();

    let lines: Vec<&str> = content.lines().collect();
    let mut new_lines: Vec<&str> = Vec::new();
    let mut in_block = false;

    for line in &lines {
        if line.contains(begin.as_str()) {
            in_block = true;
            // Remove a trailing blank line before the block
            if let Some(last) = new_lines.last() {
                if last.is_empty() {
                    new_lines.pop();
                }
            }
            continue;
        }
        if in_block {
            if line.contains(end.as_str()) {
                in_block = false;
            }
            continue;
        }
        new_lines.push(line);
    }

    // Rebuild content
    let mut result = new_lines.join("\n");
    // Trim trailing whitespace but keep a final newline if file is non-empty
    let trimmed = result.trim_end().to_string();
    result = if trimmed.is_empty() {
        trimmed
    } else {
        trimmed + "\n"
    };

    std::fs::write(path, &result)?;
    Ok(UninstallResult::Removed)
}

/// Validate shell config syntax by running `bash -n` or `zsh -n` on the file.
///
/// Returns `Ok(())` if valid or if the shell is not available.
/// Returns `Err` with details if the syntax check fails.
pub fn validate_shell_syntax(path: &Path, shell: &str) -> Result<()> {
    use enclaveapp_core::timeout::{run_with_timeout, TimeoutResult};
    use std::time::Duration;
    let mut cmd = std::process::Command::new(shell);
    cmd.arg("-n").arg(path);
    // bash/zsh `-n` parses without executing — always fast. Cap at 10s
    // so an unexpected hang (stuck interactive init, wedged shim) can't
    // freeze install/uninstall.
    let output = run_with_timeout(cmd, Duration::from_secs(10));

    match output {
        Ok(TimeoutResult::Completed(o)) if o.status.success() => Ok(()),
        Ok(TimeoutResult::TimedOut) => Err(enclaveapp_core::Error::Config(format!(
            "{shell} syntax check timed out after 10s"
        ))),
        Ok(TimeoutResult::Completed(o)) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            Err(enclaveapp_core::Error::Config(format!(
                "{shell} syntax check failed: {stderr}"
            )))
        }
        Err(_) => {
            // Shell not available, skip validation
            Ok(())
        }
    }
}

/// Shell config file candidates in priority order.
pub fn shell_config_paths(home: &Path) -> Vec<(&'static str, std::path::PathBuf)> {
    vec![
        ("bash", home.join(".bashrc")),
        ("zsh", home.join(".zshrc")),
        ("bash", home.join(".profile")),
    ]
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, let_underscore_drop)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_dir(name: &str) -> PathBuf {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("enclaveapp-wsl-test-{pid}-{id}-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn test_config() -> ShellBlockConfig {
        ShellBlockConfig::new(
            "sshenc",
            "export SSH_AUTH_SOCK=\"$HOME/.sshenc/agent.sock\"",
        )
    }

    #[test]
    fn test_install_new_file() {
        let dir = test_dir("install-new");
        let path = dir.join(".bashrc");
        let config = test_config();

        let result = install_block(&path, &config).unwrap();
        assert_eq!(result, InstallResult::Installed);

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains(&config.begin_marker()));
        assert!(content.contains("SSH_AUTH_SOCK"));
        assert!(content.contains(&config.end_marker()));
        // Should end with newline
        assert!(content.ends_with('\n'));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_install_existing_file() {
        let dir = test_dir("install-existing");
        let path = dir.join(".bashrc");
        let config = test_config();

        std::fs::write(&path, "# existing config\nexport PATH=/usr/bin\n").unwrap();

        let result = install_block(&path, &config).unwrap();
        assert_eq!(result, InstallResult::Installed);

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.starts_with("# existing config"));
        assert!(content.contains(&config.begin_marker()));
        // Blank separator line between existing content and block
        assert!(content.contains("PATH=/usr/bin\n\n"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_install_idempotent() {
        let dir = test_dir("install-idempotent");
        let path = dir.join(".bashrc");
        let config = test_config();

        let result1 = install_block(&path, &config).unwrap();
        assert_eq!(result1, InstallResult::Installed);
        let content_first = std::fs::read_to_string(&path).unwrap();

        let result2 = install_block(&path, &config).unwrap();
        assert_eq!(result2, InstallResult::AlreadyPresent);
        let content_second = std::fs::read_to_string(&path).unwrap();

        assert_eq!(content_first, content_second);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_install_replaces_outdated_block() {
        // The exact scenario `sshenc install` v0.6.37 hit on hosts
        // upgraded from v0.6.33: a managed block already exists,
        // but its content is the older shipped block (e.g. socat
        // fallback). The new install must overwrite it in place,
        // keeping everything outside the markers untouched.
        let dir = test_dir("install-replaces-outdated");
        let path = dir.join(".bashrc");

        // Stamp an old block with the same markers but different
        // body, surrounded by user content.
        let old_config = ShellBlockConfig::new("testapp", "export OLD=1");
        std::fs::write(
            &path,
            format!(
                "# user pre-content\nexport USER_VAR=keep\n\n{}\n\n# user post-content\nalias ll='ls -la'\n",
                old_config.full_block()
            ),
        )
        .unwrap();

        // Install a *new* block under the same app name.
        let new_config = ShellBlockConfig::new("testapp", "export NEW=v2");
        let result = install_block(&path, &new_config).unwrap();
        assert_eq!(result, InstallResult::Installed);

        let content = std::fs::read_to_string(&path).unwrap();
        // New body present, old body gone.
        assert!(content.contains("export NEW=v2"), "new body missing");
        assert!(!content.contains("export OLD=1"), "old body still present");
        // User content outside the markers untouched.
        assert!(content.contains("export USER_VAR=keep"));
        assert!(content.contains("alias ll='ls -la'"));
        // Exactly one block, not two appended.
        let block_count = content.matches(&new_config.begin_marker()).count();
        assert_eq!(
            block_count, 1,
            "expected exactly one block, got {block_count}"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_uninstall_removes_block() {
        let dir = test_dir("uninstall-removes");
        let path = dir.join(".bashrc");
        let config = test_config();

        install_block(&path, &config).unwrap();

        let result = uninstall_block(&path, &config).unwrap();
        assert_eq!(result, UninstallResult::Removed);

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(!content.contains(&config.begin_marker()));
        assert!(!content.contains(&config.end_marker()));
        assert!(!content.contains("SSH_AUTH_SOCK"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_uninstall_not_present() {
        let dir = test_dir("uninstall-not-present");
        let path = dir.join(".bashrc");
        let config = test_config();

        std::fs::write(&path, "# just a comment\n").unwrap();

        let result = uninstall_block(&path, &config).unwrap();
        assert_eq!(result, UninstallResult::NotPresent);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_uninstall_missing_file() {
        let config = test_config();
        let result = uninstall_block(Path::new("/nonexistent/path/.bashrc"), &config).unwrap();
        assert_eq!(result, UninstallResult::NotPresent);
    }

    #[test]
    fn test_is_installed_true() {
        let dir = test_dir("is-installed-true");
        let path = dir.join(".bashrc");
        let config = test_config();

        install_block(&path, &config).unwrap();
        assert!(is_installed(&path, &config).unwrap());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_is_installed_false() {
        let dir = test_dir("is-installed-false");
        let path = dir.join(".bashrc");
        let config = test_config();

        std::fs::write(&path, "").unwrap();
        assert!(!is_installed(&path, &config).unwrap());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_uninstall_preserves_other_content() {
        let dir = test_dir("uninstall-preserves");
        let path = dir.join(".bashrc");
        let config = test_config();

        std::fs::write(&path, "# before\nexport FOO=bar\n").unwrap();
        install_block(&path, &config).unwrap();

        uninstall_block(&path, &config).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("# before"));
        assert!(content.contains("export FOO=bar"));
        assert!(!content.contains(&config.begin_marker()));
        assert!(!content.contains("SSH_AUTH_SOCK"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_install_block_content() {
        let dir = test_dir("block-content");
        let path = dir.join(".bashrc");
        let config = test_config();

        install_block(&path, &config).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        // Verify exact structure: begin marker, content, end marker
        let begin = content.find(&config.begin_marker()).unwrap();
        let end = content.find(&config.end_marker()).unwrap();
        assert!(begin < end);

        let block_body = &content[begin + config.begin_marker().len()..end];
        assert!(block_body.contains("SSH_AUTH_SOCK"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_custom_app_name() {
        let sshenc = ShellBlockConfig::new("sshenc", "# sshenc stuff");
        let awsenc = ShellBlockConfig::new("awsenc", "# awsenc stuff");

        assert_ne!(sshenc.begin_marker(), awsenc.begin_marker());
        assert_ne!(sshenc.end_marker(), awsenc.end_marker());

        assert!(sshenc.begin_marker().contains("sshenc"));
        assert!(awsenc.begin_marker().contains("awsenc"));
    }

    #[test]
    fn test_crlf_normalization() {
        let dir = test_dir("crlf");
        let path = dir.join(".bashrc");
        let config = test_config();

        // Write file with CRLF line endings
        std::fs::write(&path, "# existing\r\nexport FOO=bar\r\n").unwrap();

        let result = install_block(&path, &config).unwrap();
        assert_eq!(result, InstallResult::Installed);

        let content = std::fs::read_to_string(&path).unwrap();
        // CRLF should have been normalized to LF
        assert!(!content.contains("\r\n"));
        assert!(content.contains("# existing"));
        assert!(content.contains(&config.begin_marker()));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_shell_config_paths() {
        let home = PathBuf::from("/home/testuser");
        let paths = shell_config_paths(&home);

        assert_eq!(paths.len(), 3);
        assert_eq!(paths[0].0, "bash");
        assert_eq!(paths[0].1, home.join(".bashrc"));
        assert_eq!(paths[1].0, "zsh");
        assert_eq!(paths[1].1, home.join(".zshrc"));
        assert_eq!(paths[2].0, "bash");
        assert_eq!(paths[2].1, home.join(".profile"));
    }

    #[test]
    fn test_install_block_special_characters() {
        let dir = test_dir("special-chars");
        let path = dir.join(".bashrc");
        let config = ShellBlockConfig::new(
            "sshenc",
            r#"export FOO="$HOME/.sshenc/agent.sock"
export BAR=`whoami`
export BAZ=\\escaped"#,
        );

        let result = install_block(&path, &config).unwrap();
        assert_eq!(result, InstallResult::Installed);

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("$HOME"));
        assert!(content.contains("`whoami`"));
        assert!(content.contains("\\\\escaped"));
        assert!(content.contains(&config.begin_marker()));
        assert!(content.contains(&config.end_marker()));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_uninstall_preserves_content_before_and_after_exactly() {
        let dir = test_dir("preserve-exact");
        let path = dir.join(".bashrc");
        let config = ShellBlockConfig::new("sshenc", "export X=1");

        let before = "# line one\nexport PATH=/usr/bin\n";
        let after = "# line three\nexport Y=2\n";
        // Write before content, install block, then append after content
        std::fs::write(&path, before).unwrap();
        install_block(&path, &config).unwrap();
        // Append content after the block
        let mut content = std::fs::read_to_string(&path).unwrap();
        content.push_str(after);
        std::fs::write(&path, &content).unwrap();

        uninstall_block(&path, &config).unwrap();

        let result = std::fs::read_to_string(&path).unwrap();
        assert!(result.contains("# line one"));
        assert!(result.contains("export PATH=/usr/bin"));
        assert!(result.contains("# line three"));
        assert!(result.contains("export Y=2"));
        assert!(!result.contains(&config.begin_marker()));
        assert!(!result.contains("export X=1"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_multiple_different_app_blocks_coexist() {
        let dir = test_dir("multi-blocks");
        let path = dir.join(".bashrc");
        let sshenc_config =
            ShellBlockConfig::new("sshenc", "export SSH_AUTH_SOCK=/tmp/sshenc.sock");
        let awsenc_config = ShellBlockConfig::new("awsenc", "export AWS_PROFILE=default");

        install_block(&path, &sshenc_config).unwrap();
        install_block(&path, &awsenc_config).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains(&sshenc_config.begin_marker()));
        assert!(content.contains(&sshenc_config.end_marker()));
        assert!(content.contains(&awsenc_config.begin_marker()));
        assert!(content.contains(&awsenc_config.end_marker()));
        assert!(content.contains("SSH_AUTH_SOCK"));
        assert!(content.contains("AWS_PROFILE"));

        // Remove sshenc, awsenc should remain
        uninstall_block(&path, &sshenc_config).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(!content.contains(&sshenc_config.begin_marker()));
        assert!(content.contains(&awsenc_config.begin_marker()));
        assert!(content.contains("AWS_PROFILE"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_install_then_update_pattern() {
        let dir = test_dir("install-update");
        let path = dir.join(".bashrc");
        let config_v1 = ShellBlockConfig::new("sshenc", "export VERSION=1");

        install_block(&path, &config_v1).unwrap();
        let content_v1 = std::fs::read_to_string(&path).unwrap();
        assert!(content_v1.contains("VERSION=1"));

        // Remove old, install new
        uninstall_block(&path, &config_v1).unwrap();
        let config_v2 = ShellBlockConfig::new("sshenc", "export VERSION=2");
        install_block(&path, &config_v2).unwrap();

        let content_v2 = std::fs::read_to_string(&path).unwrap();
        assert!(!content_v2.contains("VERSION=1"));
        assert!(content_v2.contains("VERSION=2"));
        assert!(content_v2.contains(&config_v2.begin_marker()));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    // Pure helper unit tests for ShellBlockConfig markers

    #[test]
    fn begin_marker_contains_app_name() {
        let config = ShellBlockConfig::new("myapp", "content");
        assert!(config.begin_marker().contains("myapp"));
    }

    #[test]
    fn begin_marker_format_is_correct() {
        let config = ShellBlockConfig::new("sshenc", "content");
        assert_eq!(
            config.begin_marker(),
            "# BEGIN sshenc managed block -- do not edit"
        );
    }

    #[test]
    fn end_marker_contains_app_name() {
        let config = ShellBlockConfig::new("myapp", "content");
        assert!(config.end_marker().contains("myapp"));
    }

    #[test]
    fn end_marker_format_is_correct() {
        let config = ShellBlockConfig::new("sshenc", "content");
        assert_eq!(config.end_marker(), "# END sshenc managed block");
    }

    #[test]
    fn full_block_contains_begin_and_end_markers() {
        let config = ShellBlockConfig::new("sshenc", "export SSH_AUTH_SOCK=test");
        let block = config.full_block();
        assert!(block.contains(&config.begin_marker()));
        assert!(block.contains(&config.end_marker()));
    }

    #[test]
    fn full_block_contains_block_content() {
        let config = ShellBlockConfig::new("sshenc", "export SSH_AUTH_SOCK=test");
        let block = config.full_block();
        assert!(block.contains("export SSH_AUTH_SOCK=test"));
    }

    #[test]
    fn full_block_structure_is_begin_content_end() {
        let config = ShellBlockConfig::new("app", "body_line");
        let block = config.full_block();
        let begin_pos = block.find(&config.begin_marker()).unwrap();
        let content_pos = block.find("body_line").unwrap();
        let end_pos = block.find(&config.end_marker()).unwrap();
        assert!(begin_pos < content_pos);
        assert!(content_pos < end_pos);
    }

    #[test]
    fn shell_config_paths_contains_bashrc() {
        let home = Path::new("/home/user");
        let paths = shell_config_paths(home);
        assert!(paths.iter().any(|(_, p)| p.ends_with(".bashrc")));
    }

    #[test]
    fn shell_config_paths_contains_zshrc() {
        let home = Path::new("/home/user");
        let paths = shell_config_paths(home);
        assert!(paths.iter().any(|(_, p)| p.ends_with(".zshrc")));
    }

    #[test]
    fn shell_config_paths_contains_profile() {
        let home = Path::new("/home/user");
        let paths = shell_config_paths(home);
        assert!(paths.iter().any(|(_, p)| p.ends_with(".profile")));
    }

    #[test]
    fn shell_config_paths_all_under_home() {
        let home = Path::new("/home/testuser");
        let paths = shell_config_paths(home);
        assert!(!paths.is_empty());
        for (_, path) in &paths {
            assert!(
                path.starts_with(home),
                "path {path:?} should be under home dir"
            );
        }
    }
}
