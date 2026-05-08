// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Ensure a per-app helper daemon is running and listening on a
//! Unix socket.
//!
//! The sshenc / awsenc / … family each pair a foreground CLI with a
//! long-lived helper daemon that owns all Secure-Enclave / keychain
//! state, so the CLI binary's code signature never appears on an
//! `SecItem*` call and macOS's legacy-keychain ACL doesn't fire a
//! cross-binary approval prompt on every install. This module is
//! the "make sure the daemon is up to accept RPCs" step that every
//! CLI invocation runs before it proxies a request.
//!
//! Discovery is intentionally PATH-free: a malicious binary sitting
//! on PATH shouldn't be a launchable daemon. [`find_trusted_binary`]
//! limits the search to known install dirs, and spawn arguments are
//! fixed (`--socket <path>`) so no user-controlled flags can leak
//! in.

#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(unix)]
use crate::bin_discovery;

/// Outcome of [`ensure_daemon_ready`] when the spawn path is taken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonSpawn {
    /// The socket was already accepting connections — nothing was
    /// spawned.
    AlreadyRunning,
    /// The daemon was spawned and became ready within the timeout.
    Spawned { binary: PathBuf },
}

/// Error path for [`ensure_daemon_ready`]. String-only so the helper
/// stays dependency-free of the richer error taxonomies each
/// consumer defines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonReadyError {
    /// No trusted copy of `binary_name` could be located. The user
    /// has likely not installed the app, or the install layout
    /// deviates from what [`bin_discovery`] knows about.
    BinaryNotFound { binary_name: String },
    /// Spawn failed (OS refused, binary not executable on the
    /// target architecture, etc.).
    SpawnFailed { binary: PathBuf, reason: String },
    /// A filesystem op on the socket's parent directory failed.
    SocketDirSetupFailed { parent: PathBuf, reason: String },
    /// The daemon was spawned but did not accept a connection on
    /// `socket_path` before the readiness timeout elapsed.
    ///
    /// `diagnostic` carries best-effort capture of why the wait
    /// failed so callers / log readers can root-cause without
    /// having to rerun with extra instrumentation. See
    /// [`ReadyDiagnostic`] for the captured fields.
    NotReady {
        socket_path: PathBuf,
        timeout: Duration,
        diagnostic: ReadyDiagnostic,
    },
}

/// Captured state at the moment [`ensure_daemon_ready`] gives up.
/// Populated on both the "child exited 0 but socket invisible"
/// path and the full-timeout-elapsed path.
///
/// All fields are best-effort — none of the capture steps is
/// allowed to fail in a way that hides the original timeout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadyDiagnostic {
    /// `Some(code)` if `try_wait` showed the spawned process had
    /// exited at the moment we gave up; `None` if it was still
    /// running. The most useful single bit: "did the daemon die,
    /// or just never bind?"
    pub child_exit_code: Option<i32>,
    /// Whether `socket_path` exists on the filesystem at the
    /// moment we gave up. `false` for the common "agent never
    /// reached `bind()`" case; `true` if the socket appeared but
    /// connect attempts kept failing (a race between bind and
    /// listen, or a wrong-uid mismatch on the listener).
    pub socket_present: bool,
    /// If `socket_present` is true, the io::ErrorKind of the most
    /// recent connect attempt as a stable string (e.g.
    /// `"ConnectionRefused"`). `None` if the socket wasn't there
    /// or the last connect succeeded (in which case we wouldn't
    /// have reached the `NotReady` path at all).
    pub connect_error_kind: Option<String>,
    /// Up to ~8 KiB of the spawned daemon's stderr, captured from
    /// process startup until the timeout fired. Truncation is
    /// indicated with a trailing `"\n... (truncated)"` marker. The
    /// daemon's startup panic / config-error / TPM-init-failure
    /// almost always lands in this window.
    pub stderr_excerpt: String,
}

/// Maximum bytes of spawned-daemon stderr we keep for diagnostic.
/// 8 KiB is plenty for startup-panic backtraces and tracing init
/// errors; bigger means our drain thread holds more memory for
/// the lifetime of every spawned daemon, which is a real cost
/// because we leave the drain running after success.
///
/// Unix-only: the Windows stub of `ensure_daemon_ready` doesn't
/// spawn anything (named-pipe daemons are managed as Services),
/// so there's no stderr to capture and the constant is unused.
#[cfg(unix)]
const STDERR_DIAGNOSTIC_CAP: usize = 8 * 1024;

impl std::fmt::Display for DaemonReadyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BinaryNotFound { binary_name } => {
                write!(f, "{binary_name} binary not found in known install dirs")
            }
            Self::SpawnFailed { binary, reason } => {
                write!(f, "spawning {}: {reason}", binary.display())
            }
            Self::SocketDirSetupFailed { parent, reason } => {
                write!(
                    f,
                    "creating daemon socket dir {}: {reason}",
                    parent.display()
                )
            }
            Self::NotReady {
                socket_path,
                timeout,
                diagnostic,
            } => {
                write!(
                    f,
                    "daemon did not become ready at {} within {:?}",
                    socket_path.display(),
                    timeout
                )?;
                let exit_part = match diagnostic.child_exit_code {
                    Some(code) => format!("child exited (status {code})"),
                    None => "child still running at timeout".to_string(),
                };
                let socket_part = if diagnostic.socket_present {
                    if let Some(kind) = &diagnostic.connect_error_kind {
                        format!("socket present but connect failed ({kind})")
                    } else {
                        "socket present".to_string()
                    }
                } else {
                    "socket never appeared".to_string()
                };
                write!(f, " [{exit_part}; {socket_part}]")?;
                if !diagnostic.stderr_excerpt.is_empty() {
                    write!(f, "\nchild stderr:\n{}", diagnostic.stderr_excerpt)?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for DaemonReadyError {}

/// Exponential-backoff schedule used by [`ensure_daemon_ready`] when
/// it has to wait for a freshly-spawned daemon. ≈30 s in aggregate
/// before giving up — generous enough to absorb cold-start spawn
/// of the WSL → Windows TPM bridge. `sshenc-agent` on a fresh WSL
/// shell on AlmaLinux musl was observed to take ~12 s to bind its
/// socket because the agent has to spawn the
/// `sshenc-tpm-bridge.exe` Windows process and complete an
/// `init_signing` handshake before listening — a one-time cost per
/// shell, not per request. The original 10 s budget cleared the
/// glibc-on-Ubuntu cold-start path but flaked on AlmaLinux musl;
/// the previous 3 s budget flaked even on Linux CI containers.
///
/// Unix only — the Windows stub doesn't spawn anything.
#[cfg(unix)]
const READINESS_BACKOFF_MS: &[u64] = &[50, 100, 200, 400, 800, 1600, 3000, 4000, 8000, 12000];

/// Total timeout across the [`READINESS_BACKOFF_MS`] schedule. Used
/// when reporting [`DaemonReadyError::NotReady`].
#[cfg(unix)]
fn readiness_total_timeout() -> Duration {
    Duration::from_millis(READINESS_BACKOFF_MS.iter().sum())
}

/// Make sure `binary_name` is listening on `socket_path`, spawning
/// it via the [`bin_discovery`] search (parameterized by
/// `app_name`) if it isn't already. Returns `AlreadyRunning` if the
/// socket was already live, or `Spawned { binary }` when this call
/// launched it. Errors out without retrying if the binary can't be
/// found or if spawn fails — callers should surface a clear message
/// pointing at the installer rather than silently falling back to
/// an in-process code path, because the whole point of this
/// daemon-only architecture is to keep the CLI's code signature
/// off the crypto FFI.
///
/// Invoke shape is fixed: `<binary> --socket <socket_path>`. Every
/// current consumer (sshenc-agent and awsenc-daemon both) honors
/// that interface; if a future consumer needs a different CLI shape
/// we'll add a parameter instead of allowing unbounded args here,
/// to keep the "no attacker-controlled flags" property.
#[cfg(unix)]
pub fn ensure_daemon_ready(
    binary_name: &str,
    app_name: &str,
    socket_path: &Path,
) -> Result<DaemonSpawn, DaemonReadyError> {
    if is_socket_ready(socket_path) {
        return Ok(DaemonSpawn::AlreadyRunning);
    }

    let binary = bin_discovery::find_trusted_binary(binary_name, app_name).ok_or_else(|| {
        DaemonReadyError::BinaryNotFound {
            binary_name: binary_name.to_string(),
        }
    })?;

    if let Some(parent) = socket_path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent).map_err(|e| {
                DaemonReadyError::SocketDirSetupFailed {
                    parent: parent.to_path_buf(),
                    reason: e.to_string(),
                }
            })?;
        }
    }

    use std::process::Stdio;
    let mut child = std::process::Command::new(&binary)
        .arg("--socket")
        .arg(socket_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        // Pipe stderr (was: null) so we can capture startup
        // panics / tracing-subscriber errors / TPM init failures
        // for the NotReady diagnostic. A drain thread (below)
        // keeps the kernel pipe buffer from filling and blocking
        // the daemon's writes; the captured bytes are bounded by
        // STDERR_DIAGNOSTIC_CAP so memory stays small even for a
        // long-running daemon.
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| DaemonReadyError::SpawnFailed {
            binary: binary.clone(),
            reason: e.to_string(),
        })?;

    // Spawn the stderr drain. It outlives this function — on the
    // success path the daemon keeps running and writing stderr;
    // the drain thread reads-and-bounds-buffer-or-discards forever
    // (cheap) and exits naturally when the daemon closes its
    // stderr (i.e. when it dies). The Arc<Mutex<...>> is shared
    // with this function so we can snapshot the buffer for the
    // NotReady diagnostic.
    let stderr_buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::with_capacity(1024)));
    if let Some(stderr) = child.stderr.take() {
        let buf = std::sync::Arc::clone(&stderr_buf);
        std::thread::spawn(move || drain_capped(stderr, buf));
    }

    // Two readiness signals, polled together:
    //
    // 1. The socket accepts connections — the universal sign of
    //    readiness.
    // 2. The spawned process exited with status 0 — emitted by
    //    daemonize-style binaries (sshenc-agent, awsenc-daemon)
    //    that fork and have the parent block on a per-app
    //    `wait_for_ready_file` before calling `exit(0)`. When that
    //    parent exits cleanly, the actual daemon child is already
    //    bound on the socket, so this is a strong signal we can
    //    short-circuit on. Non-zero exit → spawn-time failure that
    //    we should surface immediately rather than wait out.
    for backoff_ms in READINESS_BACKOFF_MS {
        std::thread::sleep(Duration::from_millis(*backoff_ms));

        if is_socket_ready(socket_path) {
            // Best-effort reap: don't leave a zombie if the parent
            // already exited. Ignore the result either way.
            drop(child.try_wait());
            return Ok(DaemonSpawn::Spawned { binary });
        }

        // try_wait → Some(status) means the spawned process exited.
        // None means still running; Err means the call itself failed
        // (e.g. EINTR). For both of those, keep polling — the socket
        // is the ground truth.
        if let Ok(Some(status)) = child.try_wait() {
            if status.success() {
                // Parent reported ready (exit 0) but the socket
                // isn't yet visible — give the kernel one tiny
                // window for the listening child to finish bind.
                if is_socket_ready(socket_path) {
                    return Ok(DaemonSpawn::Spawned { binary });
                }
                std::thread::sleep(Duration::from_millis(50));
                if is_socket_ready(socket_path) {
                    return Ok(DaemonSpawn::Spawned { binary });
                }
                return Err(DaemonReadyError::NotReady {
                    socket_path: socket_path.to_path_buf(),
                    timeout: readiness_total_timeout(),
                    diagnostic: capture_diagnostic(socket_path, Some(status), &stderr_buf),
                });
            }
            return Err(DaemonReadyError::SpawnFailed {
                binary: binary.clone(),
                reason: format!(
                    "daemon exited with status {} before becoming ready",
                    status.code().unwrap_or(-1)
                ),
            });
        }
    }
    // Final reap attempt before bailing.
    let final_status = child.try_wait().ok().flatten();
    Err(DaemonReadyError::NotReady {
        socket_path: socket_path.to_path_buf(),
        timeout: readiness_total_timeout(),
        diagnostic: capture_diagnostic(socket_path, final_status, &stderr_buf),
    })
}

/// Read from `reader` indefinitely. The first
/// `STDERR_DIAGNOSTIC_CAP` bytes are appended to `buf`; bytes
/// beyond that are discarded so the daemon's stderr writes don't
/// block on a full pipe but our memory footprint stays bounded.
/// Truncation is signaled with a trailing `"\n... (truncated)"`
/// the first time we hit the cap.
#[cfg(unix)]
fn drain_capped<R: std::io::Read>(mut reader: R, buf: std::sync::Arc<std::sync::Mutex<Vec<u8>>>) {
    let mut tmp = [0_u8; 1024];
    let mut truncation_marked = false;
    loop {
        // EOF (Ok(0)) and any read error both mean the drain is
        // done — the daemon either closed its stderr or the pipe
        // died — so we collapse to a single arm.
        let n = match reader.read(&mut tmp) {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        let mut guard = match buf.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let remaining = STDERR_DIAGNOSTIC_CAP.saturating_sub(guard.len());
        if remaining > 0 {
            let take = remaining.min(n);
            guard.extend_from_slice(&tmp[..take]);
        } else if !truncation_marked {
            guard.extend_from_slice(b"\n... (truncated)");
            truncation_marked = true;
        }
        // Bytes beyond the cap (after the marker) are read-and-discarded
        // here on purpose — the loop continues so the kernel pipe
        // doesn't fill up and block the daemon's stderr writes.
    }
}

/// Build a [`ReadyDiagnostic`] snapshot from the current state of
/// the spawn handles + filesystem at the moment we give up. Each
/// field is best-effort; failure to capture one shouldn't lose the
/// others.
#[cfg(unix)]
fn capture_diagnostic(
    socket_path: &Path,
    child_status: Option<std::process::ExitStatus>,
    stderr_buf: &std::sync::Mutex<Vec<u8>>,
) -> ReadyDiagnostic {
    let socket_present = socket_path.exists();
    let connect_error_kind = if socket_present {
        match UnixStream::connect(socket_path) {
            Ok(_) => None, // shouldn't happen — we just checked is_socket_ready=false
            Err(e) => Some(format!("{:?}", e.kind())),
        }
    } else {
        None
    };
    let stderr_excerpt = match stderr_buf.lock() {
        Ok(g) => String::from_utf8_lossy(&g).into_owned(),
        Err(p) => String::from_utf8_lossy(&p.into_inner()).into_owned(),
    };
    ReadyDiagnostic {
        child_exit_code: child_status.and_then(|s| s.code()),
        socket_present,
        connect_error_kind,
        stderr_excerpt,
    }
}

/// Windows stub: daemons on Windows talk over named pipes, not Unix
/// sockets, and every current named-pipe daemon is managed as a
/// Service rather than spawned on demand. Callers get
/// `AlreadyRunning` so they proceed to the RPC attempt; the RPC
/// itself will surface any "daemon unreachable" condition.
#[cfg(not(unix))]
pub fn ensure_daemon_ready(
    _binary_name: &str,
    _app_name: &str,
    _socket_path: &Path,
) -> Result<DaemonSpawn, DaemonReadyError> {
    Ok(DaemonSpawn::AlreadyRunning)
}

#[cfg(unix)]
fn is_socket_ready(socket_path: &Path) -> bool {
    socket_path.exists() && UnixStream::connect(socket_path).is_ok()
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used, clippy::panic, clippy::print_stderr)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Mutex, MutexGuard};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    /// Tests that mutate process-global `$HOME` must not run in
    /// parallel — the test runner spawns multiple test threads by
    /// default, and concurrent `set_var("HOME", ...)` calls would
    /// stomp on each other and break `bin_discovery`'s home_dir
    /// resolution. Hold this mutex for the duration of any test
    /// that calls `with_fake_home_bin`.
    static HOME_MUTEX: Mutex<()> = Mutex::new(());

    fn lock_home() -> MutexGuard<'static, ()> {
        // Recover from a poisoned mutex (a previous test panicked
        // while holding it); for serialization purposes the data
        // we're protecting is `$HOME`, which the Drop guard always
        // restores regardless of whether we panicked.
        HOME_MUTEX.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// `ensure_daemon_ready` wrapper that absorbs the Linux ETXTBSY
    /// race seen in CI. `cargo test` runs the test binary multi-
    /// threaded, and Linux's `i_writecount` exec check is global to
    /// the file's inode: between the `fork()` and the `exec()` of
    /// any other test thread's `Command::spawn`, that fork's child
    /// inherits writer FDs the parent had open at fork time
    /// (O_CLOEXEC closes them at exec, but not at fork). If our
    /// `with_fake_home_bin`'s O_WRONLY FD on the script is still
    /// open in some other thread's in-flight fork at the moment we
    /// exec the script, the kernel returns `ETXTBSY` (`os error
    /// 26`, "Text file busy"). The window is small but real on a
    /// loaded CI runner and produces a `SpawnFailed { reason:
    /// "Text file busy ..." }` instead of the test-relevant
    /// SpawnFailed/NotReady the test was designed to assert on.
    ///
    /// Retry briefly on that exact reason; let any other error
    /// (and any success) through unchanged. The retries are
    /// per-call, capped, and short — total wait is bounded by the
    /// backoff schedule below — so the per-test timing assertions
    /// (~800ms) still hold on any sane host.
    fn ensure_daemon_ready_etxtbsy_resilient(
        binary_name: &str,
        app_name: &str,
        socket_path: &Path,
    ) -> Result<DaemonSpawn, DaemonReadyError> {
        const ETXTBSY_BACKOFF_MS: &[u64] = &[5, 10, 20, 40, 80];
        for backoff_ms in ETXTBSY_BACKOFF_MS {
            match ensure_daemon_ready(binary_name, app_name, socket_path) {
                Err(DaemonReadyError::SpawnFailed { reason, .. })
                    if reason.contains("Text file busy") =>
                {
                    std::thread::sleep(Duration::from_millis(*backoff_ms));
                }
                other => return other,
            }
        }
        // Final attempt — surface whatever it returns.
        ensure_daemon_ready(binary_name, app_name, socket_path)
    }

    /// Build a unique socket path under a short root to stay under
    /// macOS's 104-byte `SUN_LEN` limit. `std::env::temp_dir()` on
    /// GitHub's macos-latest runner resolves to a deeply-nested
    /// `/private/var/folders/…/T/` which, with a descriptive per-
    /// test suffix, blows past the cap — stick to `/tmp` so Unix
    /// socket creation succeeds regardless of temp-dir layout.
    fn unique_socket(tag: &str) -> PathBuf {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = PathBuf::from("/tmp").join(format!("eacd-{}-{}-{tag}", std::process::id(), id));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("d.sock")
    }

    #[test]
    fn already_running_short_circuits_without_spawning() {
        let sock = unique_socket("already-running");
        let _unused = std::fs::remove_file(&sock);
        let listener = UnixListener::bind(&sock).unwrap();

        // binary_name is intentionally bogus — if we reach spawn,
        // this test fails.
        let got =
            ensure_daemon_ready("definitely-not-on-disk", "myapp", &sock).expect("should succeed");
        assert_eq!(got, DaemonSpawn::AlreadyRunning);

        drop(listener);
        let _unused = std::fs::remove_file(&sock);
    }

    #[test]
    fn missing_binary_reports_binary_not_found() {
        let sock = unique_socket("missing-binary");
        let _unused = std::fs::remove_file(&sock);

        let err = ensure_daemon_ready("enclaveapp-definitely-not-a-binary", "myapp", &sock)
            .expect_err("should fail");
        assert!(matches!(err, DaemonReadyError::BinaryNotFound { .. }));

        let _unused = std::fs::remove_file(&sock);
    }

    /// Plant the fake binary under a fake `~/.local/bin` so
    /// bin_discovery finds it via the home_dir lookup. Returns a
    /// guard whose Drop cleans up.
    struct FakeBinaryHome {
        home: PathBuf,
        original_home: Option<std::ffi::OsString>,
    }
    impl Drop for FakeBinaryHome {
        fn drop(&mut self) {
            // SAFETY: tests in this module aren't multi-threaded
            // (cargo runs them serially on a single binary by
            // default unless --test-threads>1, and these don't
            // mutate any other thread-shared state).
            #[allow(unsafe_code)]
            unsafe {
                if let Some(prev) = self.original_home.take() {
                    std::env::set_var("HOME", prev);
                } else {
                    std::env::remove_var("HOME");
                }
            }
            let _unused = std::fs::remove_dir_all(&self.home);
        }
    }

    /// Set `HOME` to a tempdir and plant a fake binary at
    /// `$HOME/.local/bin/<name>`. The bin_discovery search path
    /// includes `$HOME/.local/bin`, so this is enough for
    /// `find_trusted_binary` to pick it up. Returns a Drop guard
    /// that restores `HOME` and removes the tempdir.
    fn with_fake_home_bin(name: &str, contents: &[u8]) -> FakeBinaryHome {
        use std::os::unix::fs::PermissionsExt;
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let home =
            PathBuf::from("/tmp").join(format!("eacd-home-{}-{}-{name}", std::process::id(), id));
        let bindir = home.join(".local").join("bin");
        std::fs::create_dir_all(&bindir).unwrap();
        let bin_path = bindir.join(name);
        std::fs::write(&bin_path, contents).unwrap();
        std::fs::set_permissions(&bin_path, std::fs::Permissions::from_mode(0o755)).unwrap();
        let original = std::env::var_os("HOME");
        // SAFETY: see Drop impl above.
        #[allow(unsafe_code)]
        unsafe {
            std::env::set_var("HOME", &home);
        }
        FakeBinaryHome {
            home,
            original_home: original,
        }
    }

    /// A binary that exits 0 immediately without binding the
    /// socket simulates a daemonize-style parent that signals
    /// "ready" via exit. With the new logic, ensure_daemon_ready
    /// should observe the exit, peek at the socket (still absent),
    /// and report NotReady promptly — *not* wait the full 10s
    /// readiness budget.
    #[test]
    fn binary_exits_zero_without_socket_returns_not_ready_promptly() {
        let _home_guard = lock_home();
        let bin_name = format!("eacd-exit0-{}", std::process::id());
        let _fake = with_fake_home_bin(&bin_name, b"#!/bin/sh\nexit 0\n");
        let sock = unique_socket("exit0");
        let _unused = std::fs::remove_file(&sock);

        let start = std::time::Instant::now();
        let err = ensure_daemon_ready_etxtbsy_resilient(&bin_name, "myapp", &sock)
            .expect_err("should fail (no socket)");
        let elapsed = start.elapsed();

        assert!(
            matches!(err, DaemonReadyError::NotReady { .. }),
            "expected NotReady; got {err:?}"
        );
        // The full readiness schedule sums to ~10s; the exit-0
        // short-circuit should resolve well under 1s on any
        // halfway sane machine. Allow extra slack for the ETXTBSY
        // retry budget (worst case ~155ms of sleeps).
        assert!(
            elapsed < Duration::from_millis(1200),
            "exit-0 short-circuit took too long: {elapsed:?}",
        );
    }

    /// A binary that exits non-zero immediately is a spawn-time
    /// failure (failed config load, missing dependency, etc.). The
    /// new logic should surface SpawnFailed promptly rather than
    /// silently waiting out the full readiness budget on a
    /// guaranteed-fail spawn.
    #[test]
    fn binary_exits_nonzero_returns_spawn_failed_promptly() {
        let _home_guard = lock_home();
        let bin_name = format!("eacd-exit42-{}", std::process::id());
        let _fake = with_fake_home_bin(&bin_name, b"#!/bin/sh\nexit 42\n");
        let sock = unique_socket("exit42");
        let _unused = std::fs::remove_file(&sock);

        let start = std::time::Instant::now();
        let err = ensure_daemon_ready_etxtbsy_resilient(&bin_name, "myapp", &sock)
            .expect_err("should fail (exit 42)");
        let elapsed = start.elapsed();

        match err {
            DaemonReadyError::SpawnFailed { reason, .. } => {
                assert!(
                    reason.contains("42") || reason.contains("status"),
                    "SpawnFailed reason should reference the exit status; got: {reason}"
                );
            }
            other => panic!("expected SpawnFailed; got {other:?}"),
        }
        // Slack for the ETXTBSY retry budget (worst case ~155ms).
        assert!(
            elapsed < Duration::from_millis(1200),
            "exit-nonzero short-circuit took too long: {elapsed:?}",
        );
    }

    /// A binary that forks: parent exits 0 quickly (signaling
    /// readiness in daemonize style), the forked child binds the
    /// socket and stays alive. This is the sshenc-agent code path
    /// — covered to verify the new try_wait branch still treats
    /// exit-0 as a real ready signal when the socket comes up.
    ///
    /// Implemented with a sh-based fork: a background subshell
    /// binds the socket via `nc -lU`; the foreground exits 0
    /// immediately. We skip if `nc` lacks `-U` (rare).
    #[test]
    fn fork_style_daemon_exit_zero_after_socket_bound_returns_spawned() {
        // Validate that the platform's nc has the `-U` Unix-socket
        // listener flag. macOS nc does; busybox nc on minimal
        // Linux distros doesn't. Skip rather than fail when not.
        let nc_check = std::process::Command::new("nc")
            .arg("-h")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .output();
        let supports_unix = match nc_check {
            Ok(out) => {
                let h = String::from_utf8_lossy(&out.stderr) + String::from_utf8_lossy(&out.stdout);
                h.contains("-U")
            }
            Err(_) => false,
        };
        if !supports_unix {
            eprintln!("skip: nc -U not supported on this host");
            return;
        }

        let _home_guard = lock_home();
        let bin_name = format!("eacd-fork-{}", std::process::id());
        // Fork: background nc binds the socket; foreground exits
        // immediately. The shebang invokes /bin/sh which is
        // guaranteed present on macOS / Linux test runners.
        // `nc -lU "$2"` listens on the Unix socket given as $2
        // (i.e. the socket path we pass via `--socket <path>`).
        let script = b"#!/bin/sh\n\
            (nc -lU \"$2\" >/dev/null 2>&1 &)\n\
            sleep 0.05\n\
            exit 0\n";
        let _fake = with_fake_home_bin(&bin_name, script);
        let sock = unique_socket("fork-bind");
        let _unused = std::fs::remove_file(&sock);

        let got = ensure_daemon_ready_etxtbsy_resilient(&bin_name, "myapp", &sock)
            .expect("should succeed");
        assert!(
            matches!(got, DaemonSpawn::Spawned { .. }),
            "expected Spawned; got {got:?}"
        );

        // Cleanup: kill the lingering nc process (best-effort).
        drop(
            std::process::Command::new("pkill")
                .arg("-f")
                .arg(format!("nc -lU.*{}", sock.display()))
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status(),
        );
        let _unused = std::fs::remove_file(&sock);
    }

    /// The exit-0-without-socket NotReady path captures the
    /// child's stderr in the diagnostic. A daemon that prints
    /// "TPM init failed" on stderr and then exits is the exact
    /// case this exists to root-cause.
    #[test]
    fn not_ready_diagnostic_includes_child_stderr_on_exit_zero_path() {
        let _home_guard = lock_home();
        let bin_name = format!("eacd-stderr-{}", std::process::id());
        // Print to stderr, then exit 0 without binding.
        let script = b"#!/bin/sh\necho 'TPM init failed: bridge unreachable' >&2\nexit 0\n";
        let _fake = with_fake_home_bin(&bin_name, script);
        let sock = unique_socket("stderr-exit0");
        let _unused = std::fs::remove_file(&sock);

        let err = ensure_daemon_ready_etxtbsy_resilient(&bin_name, "myapp", &sock)
            .expect_err("should fail (no socket)");

        match err {
            DaemonReadyError::NotReady { diagnostic, .. } => {
                assert_eq!(
                    diagnostic.child_exit_code,
                    Some(0),
                    "exit-0 path should record the actual exit code"
                );
                assert!(
                    !diagnostic.socket_present,
                    "socket should not exist (script never bound)"
                );
                assert!(
                    diagnostic
                        .stderr_excerpt
                        .contains("TPM init failed: bridge unreachable"),
                    "stderr_excerpt should contain the script's stderr; got {:?}",
                    diagnostic.stderr_excerpt
                );
            }
            other => panic!("expected NotReady; got {other:?}"),
        }
    }

    /// `Display` for NotReady should embed the diagnostic so log
    /// readers can root-cause from a single line / message
    /// without having to introspect the error type.
    #[test]
    fn not_ready_display_embeds_diagnostic() {
        let err = DaemonReadyError::NotReady {
            socket_path: PathBuf::from("/tmp/x.sock"),
            timeout: Duration::from_secs(30),
            diagnostic: ReadyDiagnostic {
                child_exit_code: None,
                socket_present: true,
                connect_error_kind: Some("ConnectionRefused".to_string()),
                stderr_excerpt: "thread 'main' panicked at 'no key found'".to_string(),
            },
        };
        let s = format!("{err}");
        assert!(s.contains("/tmp/x.sock"));
        assert!(s.contains("child still running"));
        assert!(s.contains("socket present but connect failed"));
        assert!(s.contains("ConnectionRefused"));
        assert!(s.contains("no key found"));
    }

    /// A binary that prints more than `STDERR_DIAGNOSTIC_CAP` bytes
    /// has its stderr capped with a truncation marker. The test
    /// uses the exit-0 path because we want a fast failure (vs.
    /// the full 30 s timeout).
    #[test]
    fn not_ready_diagnostic_caps_stderr_at_8kib() {
        let _home_guard = lock_home();
        let bin_name = format!("eacd-cap-{}", std::process::id());
        // Emit ~16 KiB of stderr, then exit 0 without binding.
        // `yes` would loop forever; cap with `head -c` so the
        // child actually exits and the test doesn't depend on
        // racing the drain thread.
        let script = b"#!/bin/sh\nyes 'aaaaaaaa' | head -c 16384 >&2\nexit 0\n";
        let _fake = with_fake_home_bin(&bin_name, script);
        let sock = unique_socket("stderr-cap");
        let _unused = std::fs::remove_file(&sock);

        let err = ensure_daemon_ready_etxtbsy_resilient(&bin_name, "myapp", &sock)
            .expect_err("should fail (no socket)");

        match err {
            DaemonReadyError::NotReady { diagnostic, .. } => {
                assert!(
                    diagnostic.stderr_excerpt.len() <= STDERR_DIAGNOSTIC_CAP + 32,
                    "excerpt should be capped near {STDERR_DIAGNOSTIC_CAP}, got {}",
                    diagnostic.stderr_excerpt.len()
                );
                assert!(
                    diagnostic.stderr_excerpt.contains("(truncated)"),
                    "excerpt should carry the truncation marker"
                );
            }
            other => panic!("expected NotReady; got {other:?}"),
        }
    }
}
