// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Higher-level WSL installation orchestration.
//!
//! Provides the full "detect distros, find homes, inject shell blocks, install
//! dependencies" flow that sshenc, sso-jwt, and other enclave apps share.

use crate::detect::{detect_distros, WslDistro};
use crate::shell_config::{install_block, uninstall_block, ShellBlockConfig};
use std::path::{Path, PathBuf};
#[cfg(target_os = "windows")]
use std::time::Duration;

/// Timeout for downloading a Linux release tarball from GitHub
/// (used by [`LinuxReleaseSpec`]). Generous so a slow GitHub mirror
/// doesn't kill the install, bounded so a wedged route doesn't
/// hang it forever.
#[cfg(target_os = "windows")]
const WSL_DEP_INSTALL_TIMEOUT: Duration = Duration::from_secs(300);

/// Timeout for quick WSL shell commands (chmod, which, ldd, etc.).
#[cfg(target_os = "windows")]
const WSL_QUICK_CMD_TIMEOUT: Duration = Duration::from_secs(15);

pub use crate::detect::decode_wsl_output;

/// GitHub-release-driven Linux binary install spec.
///
/// When set on [`WslInstallConfig::auto_install_linux_release`], the
/// installer probes each detected distro's libc (glibc → `_gnu`,
/// musl → `_musl`), `curl`s the matching tarball from a GitHub
/// release URL, and `tar`-extracts the listed binaries straight to
/// `/usr/local/bin/`.
///
/// This replaces the old socat + npiperelay bridge-dependency install.
/// Native `sshenc-agent` (or whichever app) running inside the distro
/// supersedes the SSH-protocol-over-socat hack — the native agent
/// handles SSH protocol locally and crosses the WSL/Windows boundary
/// only for the JSON-RPC TPM bridge, which is a different
/// (deterministic) transport.
#[derive(Debug, Clone)]
pub struct LinuxReleaseSpec {
    /// GitHub repo in `owner/name` form, e.g. `"godaddy/sshenc"`.
    pub repo: String,
    /// Release tag to install, e.g. `"v0.6.36"`. Caller passes this
    /// in rather than reading `CARGO_PKG_VERSION` so consumer apps
    /// can pin to a known-good version on rollback if needed.
    pub tag: String,
    /// Tarball name for glibc-based distros, e.g.
    /// `"sshenc-x86_64-unknown-linux-gnu.tar.gz"`. Resolved to
    /// `https://github.com/{repo}/releases/download/{tag}/{asset_gnu}`.
    pub asset_gnu: String,
    /// Tarball name for musl-based distros, e.g.
    /// `"sshenc-x86_64-unknown-linux-musl.tar.gz"`. Used when the
    /// distro's `ldd --version` output doesn't mention "GNU".
    pub asset_musl: String,
    /// Binaries to install from the extracted tarball, e.g.
    /// `["sshenc", "sshenc-agent", "sshenc-keygen", "gitenc"]`.
    pub binaries: Vec<String>,
}

/// Configuration for WSL installation.
#[derive(Debug, Clone)]
pub struct WslInstallConfig {
    /// Application name (used in markers and messages).
    pub app_name: String,
    /// Shell block content to inject (the script body, without markers).
    pub shell_block: String,
    /// Optional: path to a Linux binary to copy into each distro.
    pub linux_binary_path: Option<PathBuf>,
    /// Target path for the Linux binary inside each distro
    /// (relative to home, e.g., `.local/bin/myapp`).
    pub linux_binary_target: Option<String>,
    /// Optional: download a matching Linux release tarball from
    /// GitHub at install time and extract the named binaries into
    /// `/usr/local/bin/`. Replaces the old socat+npiperelay dance.
    pub auto_install_linux_release: Option<LinuxReleaseSpec>,
}

/// Result of configuring or unconfiguring a single distro.
#[derive(Debug)]
pub struct DistroResult {
    /// Distribution name.
    pub distro_name: String,
    /// Outcome: Ok with a list of actions taken, or Err with an error message.
    pub outcome: Result<Vec<String>, String>,
}

/// Configure all detected WSL distros.
///
/// For each distro:
/// 1. Discovers the home directory via UNC path
/// 2. Copies a Linux binary if configured
/// 3. Injects the managed shell block into `.bashrc`/`.zshrc`
/// 4. Downloads + extracts the matching Linux release tarball into
///    `/usr/local/bin/` if `auto_install_linux_release` is set
///    (replaces the old socat + npiperelay bridge dependency path —
///    keeping a native agent inside the distro is the deterministic
///    transport, the SSH-protocol-over-socat hack is gone).
///
/// Returns one result per distro so the caller can report progress.
pub fn configure_all_distros(config: &WslInstallConfig) -> Vec<DistroResult> {
    let distros = detect_distros();
    distros
        .into_iter()
        .map(|distro| {
            let name = distro.name.clone();
            let outcome = configure_distro(&distro, config);
            DistroResult {
                distro_name: name,
                outcome,
            }
        })
        .collect()
}

/// Remove configuration from all detected WSL distros.
///
/// For each distro:
/// 1. Removes the managed shell block from `.bashrc`/`.zshrc`/`.profile`
/// 2. Removes the Linux binary if `linux_binary_target` is set
///
/// Returns one result per distro.
pub fn unconfigure_all_distros(config: &WslInstallConfig) -> Vec<DistroResult> {
    let distros = detect_distros();
    distros
        .into_iter()
        .map(|distro| {
            let name = distro.name.clone();
            let outcome = unconfigure_distro(&distro, config);
            DistroResult {
                distro_name: name,
                outcome,
            }
        })
        .collect()
}

/// Find the WSL user's home directory path from Windows as a UNC path.
///
/// Tries `\\wsl$\<distro>\<path>` first, then `\\wsl.localhost\<distro>\<path>`.
#[cfg(target_os = "windows")]
pub fn find_wsl_home(distro: &str) -> Option<PathBuf> {
    let linux_home = find_linux_home(distro)?;
    if linux_home.is_empty() {
        return None;
    }

    for prefix in &[r"\\wsl$", r"\\wsl.localhost"] {
        let win_path = format!(r"{}\{}{}", prefix, distro, linux_home.replace('/', r"\"));
        let path = PathBuf::from(&win_path);
        if path.exists() {
            return Some(path);
        }
    }

    None
}

/// Stub on non-Windows: always returns None.
#[cfg(not(target_os = "windows"))]
pub fn find_wsl_home(_distro: &str) -> Option<PathBuf> {
    None
}

/// Get the Linux home path string for a distro (e.g., `/home/user`).
#[cfg(target_os = "windows")]
fn find_linux_home(distro: &str) -> Option<String> {
    crate::detect::linux_home(distro)
}

/// Configure a single WSL distro.
fn configure_distro(distro: &WslDistro, config: &WslInstallConfig) -> Result<Vec<String>, String> {
    let home_path = distro
        .home_path
        .as_ref()
        .ok_or_else(|| format!("could not find home directory for {}", distro.name))?;

    let mut actions = Vec::new();

    // Copy Linux binary if configured
    #[cfg(target_os = "windows")]
    if let (Some(src), Some(target)) = (&config.linux_binary_path, &config.linux_binary_target) {
        copy_linux_binary(home_path, src, target, &distro.name, &mut actions)?;
    }

    // Inject shell block into config files
    let block_config = ShellBlockConfig::new(&config.app_name, &config.shell_block);
    inject_shell_configs(home_path, &block_config, &mut actions)?;

    // Install Linux release binaries from GitHub (replaces the old
    // socat + npiperelay path).
    #[cfg(target_os = "windows")]
    if let Some(release) = config.auto_install_linux_release.as_ref() {
        install_linux_release(&distro.name, release, &mut actions)?;
    }

    Ok(actions)
}

/// Remove configuration from a single WSL distro.
fn unconfigure_distro(
    distro: &WslDistro,
    config: &WslInstallConfig,
) -> Result<Vec<String>, String> {
    let home_path = distro
        .home_path
        .as_ref()
        .ok_or_else(|| format!("could not find home directory for {}", distro.name))?;

    let mut actions = Vec::new();

    // Remove shell blocks
    let block_config = ShellBlockConfig::new(&config.app_name, &config.shell_block);
    for name in &[".bashrc", ".zshrc", ".profile"] {
        let path = home_path.join(name);
        if path.exists() {
            match uninstall_block(&path, &block_config) {
                Ok(crate::shell_config::UninstallResult::Removed) => {
                    actions.push(format!("Removed block from {name}"));
                }
                Ok(crate::shell_config::UninstallResult::NotPresent) => {}
                Err(e) => {
                    return Err(format!("{name}: {e}"));
                }
            }
        }
    }

    // Remove Linux binary if configured
    if let Some(target) = &config.linux_binary_target {
        let binary_path = home_path.join(target);
        if binary_path.exists() {
            std::fs::remove_file(&binary_path).map_err(|e| format!("remove binary: {e}"))?;
            actions.push(format!("Removed ~/{target}"));
        }
    }

    Ok(actions)
}

/// Inject the managed shell block into shell config files.
fn inject_shell_configs(
    home_path: &Path,
    block_config: &ShellBlockConfig,
    actions: &mut Vec<String>,
) -> Result<(), String> {
    let mut configured = false;

    // .bashrc -- primary target for bash users
    let bashrc = home_path.join(".bashrc");
    if bashrc.exists() {
        match install_block(&bashrc, block_config) {
            Ok(crate::shell_config::InstallResult::Installed) => {
                actions.push("Updated .bashrc".to_string());
                configured = true;
            }
            Ok(crate::shell_config::InstallResult::AlreadyPresent) => {
                configured = true;
            }
            Err(e) => return Err(format!(".bashrc: {e}")),
        }
    }

    // .zshrc -- for zsh users
    let zshrc = home_path.join(".zshrc");
    if zshrc.exists() {
        match install_block(&zshrc, block_config) {
            Ok(crate::shell_config::InstallResult::Installed) => {
                actions.push("Updated .zshrc".to_string());
                configured = true;
            }
            Ok(crate::shell_config::InstallResult::AlreadyPresent) => {
                configured = true;
            }
            Err(e) => return Err(format!(".zshrc: {e}")),
        }
    }

    // Fallback: .profile or create .bashrc
    if !configured {
        let profile = home_path.join(".profile");
        if profile.exists() {
            match install_block(&profile, block_config) {
                Ok(crate::shell_config::InstallResult::Installed) => {
                    actions.push("Updated .profile".to_string());
                }
                Ok(crate::shell_config::InstallResult::AlreadyPresent) => {}
                Err(e) => return Err(format!(".profile: {e}")),
            }
        } else {
            // Create .bashrc as last resort
            match install_block(&bashrc, block_config) {
                Ok(_) => {
                    actions.push("Created .bashrc".to_string());
                }
                Err(e) => return Err(format!("create .bashrc: {e}")),
            }
        }
    }

    Ok(())
}

/// Copy a Linux binary into the distro's home directory.
#[cfg(target_os = "windows")]
fn copy_linux_binary(
    home_path: &Path,
    src: &Path,
    target: &str,
    distro_name: &str,
    actions: &mut Vec<String>,
) -> Result<(), String> {
    let dest = home_path.join(target);
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("create directory {}: {e}", parent.display()))?;
    }
    std::fs::copy(src, &dest).map_err(|e| format!("copy binary: {e}"))?;

    // Make executable via WSL (bounded timeout so a wedged distro can't hang us).
    if let Some(linux_home) = find_linux_home(distro_name) {
        let linux_path = format!("{linux_home}/{target}");
        let mut cmd = std::process::Command::new("wsl");
        cmd.args(["-d", distro_name, "--", "chmod", "+x", &linux_path]);
        drop(enclaveapp_core::timeout::run_status_with_timeout(
            cmd,
            WSL_QUICK_CMD_TIMEOUT,
        ));
    }

    actions.push(format!("Installed binary to ~/{target}"));
    Ok(())
}

/// Detect whether the distro's libc is glibc (`Ok(true)`) or musl
/// (`Ok(false)`). Done by running `ldd --version` inside the
/// distro and checking the first line — glibc says "GNU libc",
/// musl says "musl libc". Anything else (e.g., Alpine where `ldd`
/// is part of busybox) defaults to musl since that's the only
/// statically-linked tarball that's guaranteed to run there.
#[cfg(target_os = "windows")]
fn distro_is_glibc(distro_name: &str) -> bool {
    let mut wsl = std::process::Command::new("wsl");
    wsl.args(["-d", distro_name, "--", "ldd", "--version"]);
    match enclaveapp_core::timeout::run_with_timeout(wsl, WSL_QUICK_CMD_TIMEOUT) {
        Ok(enclaveapp_core::timeout::TimeoutResult::Completed(o)) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            let stderr = String::from_utf8_lossy(&o.stderr);
            let combined = format!("{stdout}{stderr}");
            // glibc's ldd prints to stdout and includes "GNU libc";
            // musl's ldd writes a usage line to stderr that mentions
            // "musl". Check both streams either way.
            combined.contains("GNU libc") || combined.contains("Free Software Foundation")
        }
        _ => false, // ldd missing → assume musl (statically-linked tarball runs anywhere)
    }
}

/// Download the matching Linux release tarball from GitHub and
/// extract the listed binaries into `/usr/local/bin/` inside the
/// distro. Done with `curl` and `tar`, both of which are present
/// in WSL distros (and on Windows but we run them inside the
/// distro so the artifacts go straight to the right filesystem
/// without crossing the WSL/Windows boundary).
#[cfg(target_os = "windows")]
fn install_linux_release(
    distro_name: &str,
    spec: &LinuxReleaseSpec,
    actions: &mut Vec<String>,
) -> Result<(), String> {
    let asset = if distro_is_glibc(distro_name) {
        &spec.asset_gnu
    } else {
        &spec.asset_musl
    };
    let url = format!(
        "https://github.com/{}/releases/download/{}/{}",
        spec.repo, spec.tag, asset
    );

    // Curl the tarball, untar into a per-PID work dir, atomically
    // replace the binaries under /usr/local/bin/. All in one bash
    // invocation so the installer runs in a single subprocess per
    // distro.
    //
    // Atomic rename rather than `cp` in place: writing over a
    // running ELF returns ETXTBSY on Linux ("text file busy"). The
    // previous mitigation tried `pkill -x sshenc-agent` before
    // `cp`, but in practice it was unreliable — on some distros
    // (`pgrep -x` doesn't match its own running agent on
    // AlmaLinux 9; pkill leaves siblings alive on Debian under
    // some race), so the `cp` still hit ETXTBSY and the user saw
    // a misleading "(network? release missing?)" warning. The
    // rename pattern (`cp src dst.tmp && mv dst.tmp dst`) sidesteps
    // the issue entirely: rename(2) atomically swaps the path
    // entry, leaving any running process with the old inode
    // (which lives until that process exits) and pointing all
    // future invocations at the new file. No kernel text-page
    // conflict, no install failure.
    //
    // Using a fixed `/tmp/sshenc-install-$$` rather than mktemp:
    // mktemp under `wsl bash -c` was observed to silently land in
    // `cd ""` on some distros, at which point `tar` extracted into
    // `$HOME` and collided with existing files.
    let bins = spec.binaries.join(" ");
    let script = format!(
        "rm -rf /tmp/sshenc-install-$$ \
         && mkdir -p /tmp/sshenc-install-$$ \
         && cd /tmp/sshenc-install-$$ \
         && set -e \
         && trap 'rm -rf /tmp/sshenc-install-$$' EXIT \
         && curl -fsSL '{url}' -o release.tar.gz \
         && tar xzf release.tar.gz \
         && for b in {bins}; do \
              sudo cp \"$b\" \"/usr/local/bin/$b.new\" \
              && sudo chmod +x \"/usr/local/bin/$b.new\" \
              && sudo mv \"/usr/local/bin/$b.new\" \"/usr/local/bin/$b\"; \
            done \
         ; pkill -KILL -x sshenc-agent 2>/dev/null || true"
    );
    let mut cmd = std::process::Command::new("wsl");
    cmd.args(["-d", distro_name, "--", "bash", "-c", &script]);
    match enclaveapp_core::timeout::run_with_timeout(cmd, WSL_DEP_INSTALL_TIMEOUT) {
        Ok(enclaveapp_core::timeout::TimeoutResult::Completed(output))
            if output.status.success() =>
        {
            actions.push(format!(
                "Installed {} from {} {}",
                spec.binaries.join(", "),
                spec.repo,
                spec.tag
            ));
            Ok(())
        }
        Ok(enclaveapp_core::timeout::TimeoutResult::TimedOut) => {
            actions.push(format!(
                "Warning: {} install timed out after {}s",
                spec.repo,
                WSL_DEP_INSTALL_TIMEOUT.as_secs()
            ));
            Ok(())
        }
        Ok(enclaveapp_core::timeout::TimeoutResult::Completed(output)) => {
            // Non-zero exit. Surface the actual stderr (last few
            // lines, trimmed) instead of the old "(network? release
            // missing?)" guess that masked the real failure for
            // operators trying to diagnose a stuck distro.
            let stderr = String::from_utf8_lossy(&output.stderr);
            let tail: Vec<&str> = stderr
                .lines()
                .rev()
                .filter(|l| !l.trim().is_empty())
                .take(3)
                .collect();
            let detail: String = tail.into_iter().rev().collect::<Vec<_>>().join(" / ");
            let exit = output
                .status
                .code()
                .map(|c| format!("exit {c}"))
                .unwrap_or_else(|| "signaled".to_string());
            actions.push(format!(
                "Warning: failed to install {} from {} ({}: {})",
                spec.binaries.join(", "),
                url,
                exit,
                if detail.is_empty() {
                    "no stderr"
                } else {
                    detail.as_str()
                }
            ));
            Ok(())
        }
        Err(e) => {
            actions.push(format!(
                "Warning: failed to launch wsl install for {} ({e})",
                spec.binaries.join(", "),
            ));
            Ok(())
        }
    }
}

// `wsl_has_command` was used by the old socat / npiperelay path and
// is no longer needed — `install_linux_release` invokes `curl` + `tar`
// (both ubiquitous in WSL distros) directly via a single bash script.
// Removed rather than dead-coded so the per-distro setup path stays
// transparent.

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, let_underscore_drop)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_dir(name: &str) -> PathBuf {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let dir =
            std::env::temp_dir().join(format!("enclaveapp-wsl-install-test-{pid}-{id}-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_inject_shell_configs_bashrc() {
        let dir = test_dir("inject-bashrc");
        std::fs::write(dir.join(".bashrc"), "# existing\n").unwrap();

        let config = ShellBlockConfig::new("testapp", "export FOO=bar");
        let mut actions = Vec::new();
        inject_shell_configs(&dir, &config, &mut actions).unwrap();

        assert!(!actions.is_empty());
        let content = std::fs::read_to_string(dir.join(".bashrc")).unwrap();
        assert!(content.contains("BEGIN testapp managed block"));
        assert!(content.contains("export FOO=bar"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_inject_shell_configs_zshrc() {
        let dir = test_dir("inject-zshrc");
        std::fs::write(dir.join(".zshrc"), "# zsh config\n").unwrap();

        let config = ShellBlockConfig::new("testapp", "export BAR=baz");
        let mut actions = Vec::new();
        inject_shell_configs(&dir, &config, &mut actions).unwrap();

        assert!(actions.iter().any(|a| a.contains(".zshrc")));
        let content = std::fs::read_to_string(dir.join(".zshrc")).unwrap();
        assert!(content.contains("export BAR=baz"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_inject_shell_configs_both() {
        let dir = test_dir("inject-both");
        std::fs::write(dir.join(".bashrc"), "# bash\n").unwrap();
        std::fs::write(dir.join(".zshrc"), "# zsh\n").unwrap();

        let config = ShellBlockConfig::new("testapp", "export X=1");
        let mut actions = Vec::new();
        inject_shell_configs(&dir, &config, &mut actions).unwrap();

        assert!(actions.iter().any(|a| a.contains(".bashrc")));
        assert!(actions.iter().any(|a| a.contains(".zshrc")));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_inject_shell_configs_fallback_profile() {
        let dir = test_dir("inject-profile");
        // No .bashrc or .zshrc, only .profile
        std::fs::write(dir.join(".profile"), "# profile\n").unwrap();

        let config = ShellBlockConfig::new("testapp", "export Y=2");
        let mut actions = Vec::new();
        inject_shell_configs(&dir, &config, &mut actions).unwrap();

        assert!(actions.iter().any(|a| a.contains(".profile")));
        let content = std::fs::read_to_string(dir.join(".profile")).unwrap();
        assert!(content.contains("export Y=2"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_inject_shell_configs_creates_bashrc() {
        let dir = test_dir("inject-create");
        // No existing shell configs at all

        let config = ShellBlockConfig::new("testapp", "export Z=3");
        let mut actions = Vec::new();
        inject_shell_configs(&dir, &config, &mut actions).unwrap();

        assert!(actions.iter().any(|a| a.contains(".bashrc")));
        let content = std::fs::read_to_string(dir.join(".bashrc")).unwrap();
        assert!(content.contains("export Z=3"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_inject_idempotent() {
        let dir = test_dir("inject-idempotent");
        std::fs::write(dir.join(".bashrc"), "# existing\n").unwrap();

        let config = ShellBlockConfig::new("testapp", "export A=1");
        let mut actions1 = Vec::new();
        inject_shell_configs(&dir, &config, &mut actions1).unwrap();
        let content1 = std::fs::read_to_string(dir.join(".bashrc")).unwrap();

        let mut actions2 = Vec::new();
        inject_shell_configs(&dir, &config, &mut actions2).unwrap();
        let content2 = std::fs::read_to_string(dir.join(".bashrc")).unwrap();

        assert_eq!(content1, content2);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_unconfigure_distro_removes_blocks() {
        let dir = test_dir("unconfigure");
        std::fs::write(dir.join(".bashrc"), "# before\n").unwrap();

        let block_config = ShellBlockConfig::new("testapp", "export Q=1");
        install_block(dir.join(".bashrc").as_path(), &block_config).unwrap();

        let distro = WslDistro {
            name: "TestDistro".to_string(),
            home_path: Some(dir.clone()),
        };
        let config = WslInstallConfig {
            app_name: "testapp".to_string(),
            shell_block: "export Q=1".to_string(),
            auto_install_linux_release: None,
            linux_binary_path: None,
            linux_binary_target: None,
        };
        let result = unconfigure_distro(&distro, &config).unwrap();
        assert!(result.iter().any(|a| a.contains("Removed")));

        let content = std::fs::read_to_string(dir.join(".bashrc")).unwrap();
        assert!(!content.contains("BEGIN testapp managed block"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_decode_wsl_output_utf8() {
        let input = b"Ubuntu\nDebian\n";
        let result = decode_wsl_output(input);
        assert_eq!(result, "Ubuntu\nDebian\n");
    }

    #[test]
    fn test_decode_wsl_output_utf16le_bom() {
        // UTF-16LE with BOM: "Hi\n"
        let mut bytes = vec![0xFF_u8, 0xFE]; // BOM
        for ch in "Hi\n".encode_utf16() {
            bytes.extend_from_slice(&ch.to_le_bytes());
        }
        let result = decode_wsl_output(&bytes);
        assert_eq!(result, "Hi\n");
    }

    #[test]
    fn test_find_wsl_home_non_windows() {
        // On non-Windows, always returns None
        #[cfg(not(target_os = "windows"))]
        assert!(find_wsl_home("Ubuntu").is_none());
    }

    #[test]
    fn test_distro_result_debug() {
        let result = DistroResult {
            distro_name: "Ubuntu".to_string(),
            outcome: Ok(vec!["Updated .bashrc".to_string()]),
        };
        let debug_str = format!("{result:?}");
        assert!(debug_str.contains("Ubuntu"));
    }

    #[test]
    fn test_wsl_install_config_clone() {
        let config = WslInstallConfig {
            app_name: "test".to_string(),
            shell_block: "# test".to_string(),
            auto_install_linux_release: None,
            linux_binary_path: None,
            linux_binary_target: None,
        };
        let cloned = config.clone();
        assert_eq!(cloned.app_name, config.app_name);
        assert_eq!(cloned.shell_block, config.shell_block);
    }

    #[test]
    fn test_decode_wsl_output_real_utf16le_bom() {
        // Simulate real UTF-16LE BOM output: "Ubuntu\r\n"
        let text = "Ubuntu\r\n";
        let mut bytes = vec![0xFF_u8, 0xFE]; // BOM
        for ch in text.encode_utf16() {
            bytes.extend_from_slice(&ch.to_le_bytes());
        }
        let result = decode_wsl_output(&bytes);
        assert_eq!(result, "Ubuntu\r\n");
    }

    #[test]
    fn test_decode_wsl_output_plain_utf8() {
        let input = b"Debian GNU/Linux\n";
        let result = decode_wsl_output(input);
        assert_eq!(result, "Debian GNU/Linux\n");
    }

    #[test]
    fn test_configure_distro_creates_backup_like_file() {
        // Configure a distro with shell configs — the .bashrc should be modified
        let dir = test_dir("configure-backup");
        let bashrc = dir.join(".bashrc");
        std::fs::write(&bashrc, "# original content\nexport PATH=/usr/bin\n").unwrap();
        let original_content = std::fs::read_to_string(&bashrc).unwrap();

        let distro = WslDistro {
            name: "TestDistro".to_string(),
            home_path: Some(dir.clone()),
        };
        let config = WslInstallConfig {
            app_name: "testapp".to_string(),
            shell_block: "export TEST=1".to_string(),
            auto_install_linux_release: None,
            linux_binary_path: None,
            linux_binary_target: None,
        };

        let result = configure_distro(&distro, &config).unwrap();
        assert!(!result.is_empty());

        // .bashrc should now contain the block
        let new_content = std::fs::read_to_string(&bashrc).unwrap();
        assert!(new_content.contains("BEGIN testapp managed block"));
        // Original content should still be present
        assert!(new_content.contains(&original_content.trim_end().to_string()));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_unconfigure_distro_removes_block_but_keeps_content() {
        let dir = test_dir("unconfigure-keep");
        let bashrc = dir.join(".bashrc");
        std::fs::write(&bashrc, "# my config\nexport FOO=bar\n").unwrap();

        let block_config = ShellBlockConfig::new("testapp", "export Q=1");
        install_block(bashrc.as_path(), &block_config).unwrap();

        // Verify block is there
        let content = std::fs::read_to_string(&bashrc).unwrap();
        assert!(content.contains("BEGIN testapp managed block"));

        let distro = WslDistro {
            name: "TestDistro".to_string(),
            home_path: Some(dir.clone()),
        };
        let config = WslInstallConfig {
            app_name: "testapp".to_string(),
            shell_block: "export Q=1".to_string(),
            auto_install_linux_release: None,
            linux_binary_path: None,
            linux_binary_target: None,
        };
        let result = unconfigure_distro(&distro, &config).unwrap();
        assert!(result.iter().any(|a| a.contains("Removed")));

        let final_content = std::fs::read_to_string(&bashrc).unwrap();
        assert!(!final_content.contains("BEGIN testapp managed block"));
        assert!(final_content.contains("# my config"));
        assert!(final_content.contains("export FOO=bar"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_decode_wsl_output_utf16le_multiple_lines() {
        // UTF-16LE BOM with multiple lines: "Ubuntu\nDebian\n"
        let text = "Ubuntu\nDebian\n";
        let mut bytes = vec![0xFF_u8, 0xFE];
        for ch in text.encode_utf16() {
            bytes.extend_from_slice(&ch.to_le_bytes());
        }
        let result = decode_wsl_output(&bytes);
        assert_eq!(result, "Ubuntu\nDebian\n");
    }

    #[test]
    fn test_decode_wsl_output_empty_utf8() {
        let result = decode_wsl_output(b"");
        assert_eq!(result, "");
    }
}
