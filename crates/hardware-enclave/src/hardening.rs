// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Process hardening — available in all build configurations including memory-only.
//!
//! Call [`harden_process`] as the **first line of `main()`** — before any argument
//! parsing, environment inspection, or secret material loading. The protections must
//! be in place before secrets exist in process memory.

// Requires unsafe for raw libc calls and Win32 FFI.
#![allow(unsafe_code)]

/// Apply best-effort platform hardening mitigations to the current process.
///
/// # What this does
///
/// - **All Unix:** `setrlimit(RLIMIT_CORE, 0)` — disables core dumps that could
///   expose in-memory secrets to the filesystem.
/// - **Linux:** `prctl(PR_SET_DUMPABLE, 0)` — makes `/proc/<pid>/mem` root-only;
///   denies ptrace-attach from non-root same-UID peers.
/// - **Linux:** `prctl(PR_SET_NO_NEW_PRIVS, 1)` — subsequent `exec*` cannot gain
///   setuid or file-capability privileges.
/// - **Windows** (when built with `signing` or `encryption` features): the full set
///   of `SetProcessMitigationPolicy` hardening flags is applied via the internal
///   implementation. In memory-only builds on Windows a reduced best-effort set is
///   applied without requiring the `windows` crate.
///
/// All mitigations are applied on a best-effort basis — individual failures are
/// logged at `warn` level but do not abort the process.
pub fn harden_process() {
    #[cfg(unix)]
    harden_unix();
    #[cfg(target_os = "linux")]
    harden_linux();
    #[cfg(windows)]
    harden_windows();
}

#[cfg(unix)]
fn harden_unix() {
    let zero = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: setrlimit with a zeroed rlimit struct is always well-defined.
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &zero) };
    if rc != 0 {
        tracing::warn!("harden_process: setrlimit(RLIMIT_CORE, 0) failed (rc={rc})");
    }
}

#[cfg(target_os = "linux")]
fn harden_linux() {
    // PR_SET_DUMPABLE = 0: /proc/<pid>/mem becomes root-only; ptrace from non-root denied.
    // SAFETY: prctl is a well-defined syscall with documented integer arguments.
    let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    if rc != 0 {
        tracing::warn!("harden_process: prctl(PR_SET_DUMPABLE, 0) failed (rc={rc})");
    }

    // PR_SET_NO_NEW_PRIVS: subsequent exec* cannot gain setuid/file-capabilities.
    // SAFETY: same as above.
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        tracing::warn!("harden_process: prctl(PR_SET_NO_NEW_PRIVS, 1) failed (rc={rc})");
    }
}

#[cfg(windows)]
fn harden_windows() {
    // When signing/encryption is enabled, the full internal implementation (which
    // uses SetProcessMitigationPolicy via the `windows` crate) is called.
    // In memory-only builds we apply the subset available without that crate.
    #[cfg(any(feature = "signing", feature = "encryption"))]
    {
        // Delegate to the full implementation in internal/core/process.
        crate::internal::core::process::harden_process();
    }
    #[cfg(not(any(feature = "signing", feature = "encryption")))]
    {
        // Memory-only Windows build: suppress GUI error dialogs as a minimal hardening.
        // Full mitigation-policy hardening requires the 'signing' or 'encryption' feature.
        extern "system" {
            fn SetErrorMode(uMode: u32) -> u32;
        }
        // SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX
        // SAFETY: SetErrorMode is a well-defined Win32 API with no preconditions.
        unsafe { SetErrorMode(0x0001 | 0x0002) };
        tracing::debug!(
            "harden_process: partial Windows hardening applied \
             (memory-only build; enable 'signing' or 'encryption' for full mitigation coverage)"
        );
    }
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used, unsafe_code)]
mod tests {
    use super::*;

    #[test]
    fn harden_process_zeroes_core_dump_rlimit() {
        harden_process();
        // SAFETY: getrlimit is a well-defined POSIX syscall.
        let mut lim: libc::rlimit = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut lim) };
        assert_eq!(rc, 0, "getrlimit failed");
        assert_eq!(lim.rlim_cur, 0, "rlim_cur must be 0 after harden_process");
        assert_eq!(lim.rlim_max, 0, "rlim_max must be 0 after harden_process");
    }
}
