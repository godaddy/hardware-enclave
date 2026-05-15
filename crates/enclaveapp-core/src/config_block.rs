// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Generic managed config block injection and removal.
//!
//! Many enclave apps inject managed blocks into config files (SSH config,
//! AWS config, shell rc files). This module provides the shared logic for
//! finding, inserting, replacing, and removing comment-delimited blocks.
//!
//! # Marker Format
//!
//! Blocks are delimited by comment markers:
//! ```text
//! # BEGIN app-name managed block -- do not edit
//! ... managed content ...
//! # END app-name managed block
//! ```
//!
//! An optional sub-identifier (e.g., profile name) can be included:
//! ```text
//! # --- BEGIN awsenc managed (production) ---
//! ... content ...
//! # --- END awsenc managed (production) ---
//! ```

use std::path::Path;

/// Configuration for a managed block's markers.
#[derive(Debug, Clone)]
pub struct BlockMarkers {
    /// The begin marker line (without trailing newline).
    pub begin: String,
    /// The end marker line (without trailing newline).
    pub end: String,
}

impl BlockMarkers {
    /// Create markers using the standard format: `# BEGIN {app} managed block -- do not edit`.
    pub fn standard(app_name: &str) -> Self {
        Self {
            begin: format!("# BEGIN {app_name} managed block -- do not edit"),
            end: format!("# END {app_name} managed block"),
        }
    }

    /// Create markers with an optional sub-identifier.
    ///
    /// Format: `# --- BEGIN {app} managed ({id}) ---`
    pub fn with_id(app_name: &str, id: &str) -> Self {
        Self {
            begin: format!("# --- BEGIN {app_name} managed ({id}) ---"),
            end: format!("# --- END {app_name} managed ({id}) ---"),
        }
    }

    /// Create markers with fully custom begin/end strings.
    pub fn custom(begin: impl Into<String>, end: impl Into<String>) -> Self {
        Self {
            begin: begin.into(),
            end: end.into(),
        }
    }
}

/// Result of an install/upsert operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockInstallResult {
    /// Block was newly appended.
    Installed,
    /// An existing block was replaced.
    Replaced,
    /// Block was already present with identical content.
    AlreadyPresent,
}

/// Result of a removal operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockRemoveResult {
    /// Block was found and removed.
    Removed,
    /// Block was not present.
    NotPresent,
}

/// Find the byte range of a managed block in the content.
///
/// Returns `Some((start, end))` where the range includes the begin marker,
/// all content, and the end marker (including its trailing newline if present).
pub fn find_block(content: &str, markers: &BlockMarkers) -> Option<(usize, usize)> {
    let begin_idx = content.find(&markers.begin)?;
    let after_begin = begin_idx + markers.begin.len();
    let end_idx = content[after_begin..].find(&markers.end)?;
    let absolute_end = after_begin + end_idx + markers.end.len();
    // Include trailing newline if present.
    let end_with_newline = if content[absolute_end..].starts_with('\n') {
        absolute_end + 1
    } else {
        absolute_end
    };
    Some((begin_idx, end_with_newline))
}

/// Check whether a managed block is present.
pub fn has_block(content: &str, markers: &BlockMarkers) -> bool {
    find_block(content, markers).is_some()
}

/// Build a complete block string from markers and body content.
///
/// The body should NOT include the markers — they are added automatically.
/// A trailing newline is ensured on the body.
pub fn build_block(markers: &BlockMarkers, body: &str) -> String {
    let mut block = String::new();
    block.push_str(&markers.begin);
    block.push('\n');
    block.push_str(body);
    if !body.ends_with('\n') {
        block.push('\n');
    }
    block.push_str(&markers.end);
    block
}

/// Insert or replace a managed block in the content.
///
/// If the block already exists, it is replaced. Otherwise, it is appended
/// with a blank separator line.
pub fn upsert_block(content: &str, markers: &BlockMarkers, block: &str) -> String {
    if let Some((start, end)) = find_block(content, markers) {
        // Replace existing block.
        let mut result = String::with_capacity(content.len());
        result.push_str(&content[..start]);
        result.push_str(block);
        if !block.ends_with('\n') {
            result.push('\n');
        }
        result.push_str(&content[end..]);
        result
    } else {
        // Append with blank separator.
        let mut result = content.to_string();
        if !result.is_empty() && !result.ends_with('\n') {
            result.push('\n');
        }
        if !result.is_empty() && !result.ends_with("\n\n") {
            result.push('\n');
        }
        result.push_str(block);
        if !block.ends_with('\n') {
            result.push('\n');
        }
        result
    }
}

/// Remove a managed block from the content.
///
/// Returns the content with the block removed and excessive blank lines
/// cleaned up. Returns unchanged content if the block is not found.
pub fn remove_block(content: &str, markers: &BlockMarkers) -> (String, BlockRemoveResult) {
    let Some((start, end)) = find_block(content, markers) else {
        return (content.to_string(), BlockRemoveResult::NotPresent);
    };

    let mut result = String::with_capacity(content.len());
    result.push_str(&content[..start]);
    result.push_str(&content[end..]);

    // Clean up double blank lines left by removal.
    while result.contains("\n\n\n") {
        result = result.replace("\n\n\n", "\n\n");
    }

    // Trim trailing whitespace but keep one final newline.
    let trimmed = result.trim_end();
    let mut final_result = trimmed.to_string();
    if !final_result.is_empty() {
        final_result.push('\n');
    }

    (final_result, BlockRemoveResult::Removed)
}

/// Read a file, normalize CRLF to LF, and return the content.
///
/// Returns `Ok(None)` if the file does not exist.
pub fn read_config_file(path: &Path) -> std::io::Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(content) => Ok(Some(content.replace("\r\n", "\n"))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Write a config file, creating parent directories if needed.
pub fn write_config_file(path: &Path, content: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, content)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Convenience: install or replace a managed block in a config file.
///
/// Reads the file (creating it if missing), upserts the block, and writes back.
pub fn install_block_in_file(
    path: &Path,
    markers: &BlockMarkers,
    body: &str,
) -> std::io::Result<BlockInstallResult> {
    let content = read_config_file(path)?.unwrap_or_default();
    let block = build_block(markers, body);

    if let Some((start, end)) = find_block(&content, markers) {
        let existing = &content[start..end];
        let new_with_nl = if block.ends_with('\n') {
            block.clone()
        } else {
            format!("{block}\n")
        };
        if existing == new_with_nl {
            return Ok(BlockInstallResult::AlreadyPresent);
        }
    }

    let result = upsert_block(&content, markers, &block);
    write_config_file(path, &result)?;

    if has_block(&content, markers) {
        Ok(BlockInstallResult::Replaced)
    } else {
        Ok(BlockInstallResult::Installed)
    }
}

/// Convenience: remove a managed block from a config file.
///
/// Returns `NotPresent` if the file doesn't exist or doesn't contain the block.
pub fn remove_block_from_file(
    path: &Path,
    markers: &BlockMarkers,
) -> std::io::Result<BlockRemoveResult> {
    let Some(content) = read_config_file(path)? else {
        return Ok(BlockRemoveResult::NotPresent);
    };
    let (result, status) = remove_block(&content, markers);
    if status == BlockRemoveResult::Removed {
        write_config_file(path, &result)?;
    }
    Ok(status)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn standard_markers() {
        let m = BlockMarkers::standard("sshenc");
        assert_eq!(m.begin, "# BEGIN sshenc managed block -- do not edit");
        assert_eq!(m.end, "# END sshenc managed block");
    }

    #[test]
    fn markers_with_id() {
        let m = BlockMarkers::with_id("awsenc", "production");
        assert_eq!(m.begin, "# --- BEGIN awsenc managed (production) ---");
        assert_eq!(m.end, "# --- END awsenc managed (production) ---");
    }

    #[test]
    fn build_block_adds_markers() {
        let m = BlockMarkers::standard("test");
        let block = build_block(&m, "key = value\n");
        assert_eq!(
            block,
            "# BEGIN test managed block -- do not edit\nkey = value\n# END test managed block"
        );
    }

    #[test]
    fn build_block_ensures_trailing_newline_on_body() {
        let m = BlockMarkers::standard("test");
        let block = build_block(&m, "key = value");
        assert!(block.contains("key = value\n# END"));
    }

    #[test]
    fn find_block_locates_markers() {
        let m = BlockMarkers::standard("app");
        let content = "before\n# BEGIN app managed block -- do not edit\nstuff\n# END app managed block\nafter\n";
        let (start, end) = find_block(content, &m).unwrap();
        assert_eq!(
            &content[start..end],
            "# BEGIN app managed block -- do not edit\nstuff\n# END app managed block\n"
        );
    }

    #[test]
    fn find_block_returns_none_when_missing() {
        let m = BlockMarkers::standard("app");
        assert!(find_block("no markers here", &m).is_none());
    }

    #[test]
    fn find_block_returns_none_for_begin_without_end() {
        let m = BlockMarkers::standard("app");
        let content = "# BEGIN app managed block -- do not edit\nstuff\n";
        assert!(find_block(content, &m).is_none());
    }

    #[test]
    fn upsert_appends_to_empty() {
        let m = BlockMarkers::standard("app");
        let block = build_block(&m, "content\n");
        let result = upsert_block("", &m, &block);
        assert_eq!(result, format!("{block}\n"));
    }

    #[test]
    fn upsert_appends_with_separator() {
        let m = BlockMarkers::standard("app");
        let block = build_block(&m, "content\n");
        let result = upsert_block("existing\n", &m, &block);
        assert!(result.starts_with("existing\n\n"));
        assert!(result.contains("content\n"));
    }

    #[test]
    fn upsert_replaces_existing() {
        let m = BlockMarkers::standard("app");
        let old = "before\n# BEGIN app managed block -- do not edit\nold\n# END app managed block\nafter\n";
        let new_block = build_block(&m, "new content\n");
        let result = upsert_block(old, &m, &new_block);
        assert!(result.contains("new content"));
        assert!(!result.contains("old"));
        assert!(result.contains("before\n"));
        assert!(result.contains("after\n"));
    }

    #[test]
    fn remove_block_removes_and_cleans() {
        let m = BlockMarkers::standard("app");
        let content = "before\n\n# BEGIN app managed block -- do not edit\nstuff\n# END app managed block\n\nafter\n";
        let (result, status) = remove_block(content, &m);
        assert_eq!(status, BlockRemoveResult::Removed);
        assert!(!result.contains("stuff"));
        assert!(result.contains("before"));
        assert!(result.contains("after"));
        assert!(!result.contains("\n\n\n"));
    }

    #[test]
    fn remove_block_not_present() {
        let m = BlockMarkers::standard("app");
        let (result, status) = remove_block("no block\n", &m);
        assert_eq!(status, BlockRemoveResult::NotPresent);
        assert_eq!(result, "no block\n");
    }

    #[test]
    fn has_block_true_when_present() {
        let m = BlockMarkers::standard("app");
        let content = "# BEGIN app managed block -- do not edit\nx\n# END app managed block\n";
        assert!(has_block(content, &m));
    }

    #[test]
    fn has_block_false_when_absent() {
        let m = BlockMarkers::standard("app");
        assert!(!has_block("nothing here", &m));
    }

    #[test]
    fn multiple_blocks_with_different_ids() {
        let m1 = BlockMarkers::with_id("awsenc", "dev");
        let m2 = BlockMarkers::with_id("awsenc", "prod");

        let mut content = String::new();
        let b1 = build_block(&m1, "dev config\n");
        content = upsert_block(&content, &m1, &b1);
        let b2 = build_block(&m2, "prod config\n");
        content = upsert_block(&content, &m2, &b2);

        assert!(has_block(&content, &m1));
        assert!(has_block(&content, &m2));

        let (content, _) = remove_block(&content, &m1);
        assert!(!has_block(&content, &m1));
        assert!(has_block(&content, &m2));
    }

    #[test]
    fn upsert_preserves_content_around_block() {
        let m = BlockMarkers::standard("app");
        let existing = "[section1]\nkey1 = val1\n\n# BEGIN app managed block -- do not edit\nold\n# END app managed block\n\n[section2]\nkey2 = val2\n";
        let new_block = build_block(&m, "new\n");
        let result = upsert_block(existing, &m, &new_block);
        assert!(result.contains("[section1]\nkey1 = val1"));
        assert!(result.contains("[section2]\nkey2 = val2"));
        assert!(result.contains("new\n"));
        assert!(!result.contains("old"));
    }

    #[test]
    fn read_config_file_normalizes_crlf() {
        let dir = std::env::temp_dir().join(format!(
            "enclaveapp-config-block-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.conf");
        std::fs::write(&path, "line1\r\nline2\r\n").unwrap();
        let content = read_config_file(&path).unwrap().unwrap();
        assert_eq!(content, "line1\nline2\n");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn read_config_file_returns_none_for_missing() {
        let path = std::path::PathBuf::from("/nonexistent/path/to/file");
        assert!(read_config_file(&path).unwrap().is_none());
    }

    #[test]
    fn install_and_remove_file_round_trip() {
        let dir = std::env::temp_dir().join(format!(
            "enclaveapp-config-block-file-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config");
        std::fs::write(&path, "[existing]\nkey = value\n").unwrap();

        let m = BlockMarkers::standard("test-app");
        let result = install_block_in_file(&path, &m, "managed = true\n").unwrap();
        assert_eq!(result, BlockInstallResult::Installed);

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("[existing]"));
        assert!(content.contains("managed = true"));

        // Install again with same content → AlreadyPresent
        let result = install_block_in_file(&path, &m, "managed = true\n").unwrap();
        assert_eq!(result, BlockInstallResult::AlreadyPresent);

        // Install with different content → Replaced
        let result = install_block_in_file(&path, &m, "managed = updated\n").unwrap();
        assert_eq!(result, BlockInstallResult::Replaced);

        let result = remove_block_from_file(&path, &m).unwrap();
        assert_eq!(result, BlockRemoveResult::Removed);

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("[existing]"));
        assert!(!content.contains("managed"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn install_block_creates_file_if_missing() {
        let dir = std::env::temp_dir().join(format!(
            "enclaveapp-config-block-create-test-{}",
            std::process::id()
        ));
        drop(std::fs::remove_dir_all(&dir));
        let path = dir.join("subdir").join("new-config");

        let m = BlockMarkers::standard("test");
        let result = install_block_in_file(&path, &m, "content\n").unwrap();
        assert_eq!(result, BlockInstallResult::Installed);
        assert!(path.exists());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn custom_markers_exact_strings() {
        let m = BlockMarkers::custom("##START", "##END");
        assert_eq!(m.begin, "##START");
        assert_eq!(m.end, "##END");
    }

    #[test]
    fn custom_markers_used_in_find_block() {
        let m = BlockMarkers::custom("// MANAGED START", "// MANAGED END");
        let content = "code before\n// MANAGED START\nmanaged code\n// MANAGED END\ncode after\n";
        assert!(find_block(content, &m).is_some());
    }

    #[test]
    fn custom_markers_used_in_build_and_upsert() {
        let m = BlockMarkers::custom("/* managed-start */", "/* managed-end */");
        let block = build_block(&m, "content = 42;\n");
        assert!(block.starts_with("/* managed-start */"));
        assert!(block.ends_with("/* managed-end */"));
        let result = upsert_block("", &m, &block);
        assert!(has_block(&result, &m));
    }

    #[test]
    fn build_block_body_already_has_trailing_newline() {
        let m = BlockMarkers::standard("app");
        let block = build_block(&m, "body line\n");
        // Should not double the newline
        assert!(!block.contains("\n\n# END"));
        assert!(block.contains("body line\n# END"));
    }

    #[test]
    fn build_block_empty_body() {
        let m = BlockMarkers::standard("app");
        let block = build_block(&m, "");
        // Empty body still gets a newline before the end marker
        assert!(block.contains("# BEGIN app managed block -- do not edit\n\n# END"));
    }

    #[test]
    fn find_block_no_trailing_newline_at_end_of_string() {
        let m = BlockMarkers::standard("app");
        // End marker is at the very end of content with no trailing newline.
        let content = "# BEGIN app managed block -- do not edit\nstuff\n# END app managed block";
        let result = find_block(content, &m);
        assert!(result.is_some());
        let (start, end) = result.unwrap();
        // No newline to consume
        assert_eq!(end, content.len());
        assert_eq!(
            &content[start..end],
            "# BEGIN app managed block -- do not edit\nstuff\n# END app managed block"
        );
    }

    #[test]
    fn remove_block_at_start_of_content() {
        let m = BlockMarkers::standard("app");
        let content = "# BEGIN app managed block -- do not edit\nmanaged\n# END app managed block\n\nafter content\n";
        let (result, status) = remove_block(content, &m);
        assert_eq!(status, BlockRemoveResult::Removed);
        assert!(!result.contains("managed"));
        assert!(result.contains("after content"));
    }

    #[test]
    fn remove_block_at_end_of_content() {
        let m = BlockMarkers::standard("app");
        let content = "before content\n\n# BEGIN app managed block -- do not edit\nmanaged\n# END app managed block\n";
        let (result, status) = remove_block(content, &m);
        assert_eq!(status, BlockRemoveResult::Removed);
        assert!(!result.contains("managed"));
        assert!(result.contains("before content"));
    }

    #[test]
    fn remove_block_leaves_empty_string_when_only_content() {
        let m = BlockMarkers::standard("app");
        let content = "# BEGIN app managed block -- do not edit\nonly\n# END app managed block\n";
        let (result, status) = remove_block(content, &m);
        assert_eq!(status, BlockRemoveResult::Removed);
        assert!(result.is_empty());
    }

    #[test]
    fn upsert_content_already_ending_with_double_newline() {
        let m = BlockMarkers::standard("app");
        let block = build_block(&m, "new\n");
        // Content already ends with two newlines → should not add a third
        let result = upsert_block("existing\n\n", &m, &block);
        assert!(!result.contains("\n\n\n"));
    }

    #[test]
    fn remove_block_from_file_missing_file_is_not_present() {
        let path = Path::new("/nonexistent/absolutely/missing.conf");
        let m = BlockMarkers::standard("app");
        let result = remove_block_from_file(path, &m).unwrap();
        assert_eq!(result, BlockRemoveResult::NotPresent);
    }

    #[test]
    fn read_config_file_empty_file_returns_some_empty_string() {
        let dir = std::env::temp_dir().join(format!(
            "enclaveapp-config-block-empty-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("empty.conf");
        std::fs::write(&path, "").unwrap();
        let content = read_config_file(&path).unwrap();
        assert_eq!(content, Some(String::new()));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn has_block_false_with_only_begin_no_end() {
        let m = BlockMarkers::standard("app");
        let content = "# BEGIN app managed block -- do not edit\nstuff but no end";
        assert!(!has_block(content, &m));
    }

    #[test]
    fn markers_with_id_blocks_distinguish_by_id() {
        // A block with id "foo" should not be found when searching for id "bar"
        let m_foo = BlockMarkers::with_id("app", "foo");
        let m_bar = BlockMarkers::with_id("app", "bar");
        let content =
            "# --- BEGIN app managed (foo) ---\ncontent\n# --- END app managed (foo) ---\n";
        assert!(has_block(content, &m_foo));
        assert!(!has_block(content, &m_bar));
    }

    #[cfg(unix)]
    #[test]
    fn write_config_file_sets_permissions() {
        let dir = std::env::temp_dir().join(format!(
            "enclaveapp-config-block-perms-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("restricted");
        write_config_file(&path, "secret\n").unwrap();

        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&path).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
