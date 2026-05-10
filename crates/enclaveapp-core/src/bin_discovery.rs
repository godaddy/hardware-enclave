// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Trusted-binary discovery for enclaveapp consumers.
//!
//! Each enclaveapp consumer (sshenc, awsenc, …) typically ships a
//! small set of binaries that need to locate each other on disk —
//! e.g. `sshenc` spawning `sshenc-agent`, or a similar helper-tool
//! pairing in another app. Rather than each app reimplementing the
//! "find a sibling binary in a trusted install location" search,
//! this module centralizes the logic and parameterizes it by the
//! consuming app's name so the per-platform install-dir conventions
//! can flex:
//!
//! - Unix: `~/.local/bin`, `~/.cargo/bin`, `/opt/homebrew/bin`,
//!   `/usr/local/bin`, `/usr/bin`, then current-exe sibling as fallback.
//! - Windows: current-exe sibling,
//!   `%LOCALAPPDATA%\<app_name>\bin`,
//!   `%ProgramFiles%\<app_name>`,
//!   `%ProgramFiles%\<app_name>\bin`, and the 32-bit equivalents.
//!
//! PATH is **deliberately excluded** — an attacker who controls the
//! user's PATH shouldn't be able to smuggle a fake daemon binary
//! into a position where enclaveapp launches it.
//!
//! ## Stable vs. canonical paths
//!
//! Candidates are validated via `canonicalize()` (symlinks resolved) to
//! confirm they are real executables, but the **original pre-canonicalized
//! path is returned**. This ensures callers receive a stable, upgrade-
//! surviving path (e.g. `/opt/homebrew/bin/sshenc`) rather than a
//! version-pinned Cellar path (e.g. `.../Cellar/sshenc/0.6.74/…/sshenc`)
//! that breaks when Homebrew removes the old version. Stable dirs are
//! searched before the current-exe sibling so that production Homebrew
//! or system installs are preferred over versioned side-by-side directories.

use std::path::PathBuf;

#[cfg(windows)]
use std::io::Read;

/// Inputs to [`find_trusted_binary_with_context`]. Parameterized so
/// callers can inject synthetic paths in tests (and so the real
/// call site stays a thin wrapper over [`std::env::current_exe`] +
/// [`dirs::home_dir`]).
#[derive(Debug, Clone, Default)]
pub struct BinaryDiscoveryContext {
    pub current_exe: Option<PathBuf>,
    #[cfg(not(windows))]
    pub home_dir: Option<PathBuf>,
    #[cfg(windows)]
    pub local_app_data: Option<PathBuf>,
    #[cfg(windows)]
    pub program_files: Option<PathBuf>,
    #[cfg(windows)]
    pub program_files_x86: Option<PathBuf>,
}

impl BinaryDiscoveryContext {
    /// Capture the real process's discovery context at the moment
    /// of the call. The returned value is a snapshot — subsequent
    /// env changes don't affect it.
    #[must_use]
    pub fn current() -> Self {
        Self {
            current_exe: std::env::current_exe().ok(),
            #[cfg(not(windows))]
            home_dir: dirs::home_dir(),
            #[cfg(windows)]
            local_app_data: std::env::var_os("LOCALAPPDATA").map(PathBuf::from),
            #[cfg(windows)]
            program_files: std::env::var_os("ProgramFiles").map(PathBuf::from),
            #[cfg(windows)]
            program_files_x86: std::env::var_os("ProgramFiles(x86)").map(PathBuf::from),
        }
    }
}

fn candidate_dirs(context: &BinaryDiscoveryContext, app_name: &str) -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    #[cfg(windows)]
    {
        // On Windows keep current-exe sibling first: Scoop's `current`
        // junction and MSI installs put sibling binaries next to each other.
        if let Some(current_exe) = context.current_exe.as_ref() {
            if let Some(parent) = current_exe.parent() {
                dirs.push(parent.to_path_buf());
            }
        }
        if let Some(local_app_data) = context.local_app_data.as_ref() {
            dirs.push(local_app_data.join(app_name).join("bin"));
        }
        if let Some(program_files) = context.program_files.as_ref() {
            dirs.push(program_files.join(app_name));
            dirs.push(program_files.join(app_name).join("bin"));
        }
        if let Some(program_files_x86) = context.program_files_x86.as_ref() {
            dirs.push(program_files_x86.join(app_name));
            dirs.push(program_files_x86.join(app_name).join("bin"));
        }
    }

    #[cfg(not(windows))]
    {
        let _ = app_name;
        // Stable dirs first so callers receive an upgrade-surviving symlink
        // path (e.g. /opt/homebrew/bin/sshenc) rather than a versioned Cellar
        // path that breaks when Homebrew removes the old version.
        if let Some(home_dir) = context.home_dir.as_ref() {
            dirs.push(home_dir.join(".local").join("bin"));
            dirs.push(home_dir.join(".cargo").join("bin"));
        }
        dirs.push(PathBuf::from("/opt/homebrew/bin"));
        dirs.push(PathBuf::from("/usr/local/bin"));
        dirs.push(PathBuf::from("/usr/bin"));
        // current-exe sibling last: fallback for dev builds or installs in
        // non-standard locations not covered by the dirs above.
        if let Some(current_exe) = context.current_exe.as_ref() {
            if let Some(parent) = current_exe.parent() {
                dirs.push(parent.to_path_buf());
            }
        }
    }

    let mut unique_dirs = Vec::new();
    for dir in dirs {
        if !unique_dirs.iter().any(|existing| existing == &dir) {
            unique_dirs.push(dir);
        }
    }
    unique_dirs
}

/// Look for `binary_name` inside the install directories of app
/// `app_name`, in the order they're typically shipped. Returns the
/// canonical path of the first match that exists and looks
/// executable, or `None` if no candidate qualifies.
///
/// The `app_name` parameter only affects Windows paths
/// (`%ProgramFiles%\<app_name>\…`); on Unix the search set is
/// fixed to the common install locations and `app_name` is unused.
#[must_use]
pub fn find_trusted_binary_with_context(
    binary_name: &str,
    app_name: &str,
    context: &BinaryDiscoveryContext,
) -> Option<PathBuf> {
    candidate_dirs(context, app_name)
        .into_iter()
        .map(|dir| dir.join(binary_name))
        .find_map(|candidate| resolve_trusted_binary_candidate(&candidate))
}

/// Convenience wrapper: discover `binary_name` using the current
/// process's environment. Every enclaveapp consumer should prefer
/// this over PATH lookups — an attacker who controls the user's
/// PATH should not be able to redirect enclaveapp's launch of its
/// own daemons.
#[must_use]
pub fn find_trusted_binary(binary_name: &str, app_name: &str) -> Option<PathBuf> {
    find_trusted_binary_with_context(binary_name, app_name, &BinaryDiscoveryContext::current())
}

/// Validate a candidate path by resolving it canonically, then return
/// the original (pre-canonicalized) path if it passes. Validation uses
/// the canonical form to confirm the binary really exists and is
/// executable; returning the original path ensures callers get a
/// stable, symlink-bearing path (e.g. `/opt/homebrew/bin/sshenc`)
/// that survives Homebrew upgrades rather than a pinned Cellar path.
fn resolve_trusted_binary_candidate(path: &std::path::Path) -> Option<PathBuf> {
    let resolved = path.canonicalize().ok()?;
    if resolved.is_file() && candidate_looks_executable(&resolved) {
        Some(path.to_path_buf())
    } else {
        None
    }
}

#[cfg(unix)]
fn candidate_looks_executable(path: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(windows)]
fn candidate_looks_executable(path: &std::path::Path) -> bool {
    path.extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
        && has_pe_header(path)
}

#[cfg(windows)]
fn has_pe_header(path: &std::path::Path) -> bool {
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    let mut header = [0_u8; 2];
    file.read_exact(&mut header).is_ok() && header == *b"MZ"
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_dir(name: &str) -> PathBuf {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "enclaveapp-bin-discovery-test-{}-{}-{name}",
            std::process::id(),
            id
        ));
        let _unused = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_test_binary(path: &std::path::Path) {
        #[cfg(unix)]
        {
            std::fs::write(path, b"#!/bin/sh\nexit 0\n").unwrap();
            let mut permissions = std::fs::metadata(path).unwrap().permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(path, permissions).unwrap();
        }
        #[cfg(windows)]
        {
            std::fs::write(path, b"MZtest-binary").unwrap();
        }
    }

    #[test]
    fn finds_current_exe_sibling_as_fallback() {
        // When the binary only exists next to current_exe (not in any of
        // the stable dirs), the current-exe sibling is found as a fallback
        // and the original (non-canonicalized) path is returned.
        let root = test_dir("sibling");
        let bin_dir = root.join("bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        #[cfg(not(windows))]
        let (current_exe, sibling) = (bin_dir.join("myapp"), bin_dir.join("myapp-helper"));
        #[cfg(windows)]
        let (current_exe, sibling) = (bin_dir.join("myapp.exe"), bin_dir.join("myapp-helper.exe"));
        write_test_binary(&current_exe);
        write_test_binary(&sibling);

        let context = BinaryDiscoveryContext {
            current_exe: Some(current_exe),
            #[cfg(not(windows))]
            home_dir: Some(root.join("home")),
            #[cfg(windows)]
            local_app_data: Some(root.join("LocalAppData")),
            #[cfg(windows)]
            program_files: Some(root.join("ProgramFiles")),
            #[cfg(windows)]
            program_files_x86: Some(root.join("ProgramFilesX86")),
        };

        #[cfg(not(windows))]
        let binary_name = "myapp-helper";
        #[cfg(windows)]
        let binary_name = "myapp-helper.exe";

        let found =
            find_trusted_binary_with_context(binary_name, "myapp", &context).expect("found");
        // Returns the original candidate path, not the canonicalized form.
        assert_eq!(found, sibling);

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn app_name_parameterizes_windows_install_dir() {
        // On Windows, two apps can ship side-by-side under
        // `%ProgramFiles%\<app_name>`. Verify lookup picks the one
        // matching the supplied `app_name`.
        #[cfg(windows)]
        {
            let root = test_dir("app-name");
            let pf_a = root.join("pf").join("appA");
            let pf_b = root.join("pf").join("appB");
            std::fs::create_dir_all(&pf_a).unwrap();
            std::fs::create_dir_all(&pf_b).unwrap();
            let bin_a = pf_a.join("helper.exe");
            let bin_b = pf_b.join("helper.exe");
            write_test_binary(&bin_a);
            write_test_binary(&bin_b);

            let context = BinaryDiscoveryContext {
                current_exe: None,
                local_app_data: None,
                program_files: Some(root.join("pf")),
                program_files_x86: None,
            };

            let a_found = find_trusted_binary_with_context("helper.exe", "appA", &context)
                .expect("find appA's helper");
            assert_eq!(a_found, bin_a);

            let b_found = find_trusted_binary_with_context("helper.exe", "appB", &context)
                .expect("find appB's helper");
            assert_eq!(b_found, bin_b);

            std::fs::remove_dir_all(&root).unwrap();
        }
        // On Unix, `app_name` is unused — just confirm the call
        // still succeeds with any value.
        #[cfg(not(windows))]
        {
            drop(find_trusted_binary("some-binary-name", "my-app"));
        }
    }
}
