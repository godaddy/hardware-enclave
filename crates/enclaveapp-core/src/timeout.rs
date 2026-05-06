//! Timeout utilities for subprocess execution and blocking reads.
//!
//! Cross-platform helpers to prevent enclave apps from hanging on
//! unresponsive subprocesses, bridge calls, or slow OS operations.

use std::io::{self, BufRead, BufReader, Read};
use std::process::{Child, ExitStatus, Output, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

/// Result of a bounded subprocess operation.
#[derive(Debug)]
pub enum TimeoutResult<T> {
    /// Operation completed within the deadline.
    Completed(T),
    /// Operation exceeded the deadline and the child was killed.
    TimedOut,
}

impl<T> TimeoutResult<T> {
    pub fn into_option(self) -> Option<T> {
        match self {
            TimeoutResult::Completed(v) => Some(v),
            TimeoutResult::TimedOut => None,
        }
    }

    pub fn is_timed_out(&self) -> bool {
        matches!(self, TimeoutResult::TimedOut)
    }
}

/// Poll interval for `try_wait`-based timeout loops.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Wait for a child process to exit, or return `TimedOut` after `timeout`
/// elapses. On timeout, the caller is responsible for killing the child.
pub fn wait_with_timeout(
    child: &mut Child,
    timeout: Duration,
) -> io::Result<TimeoutResult<ExitStatus>> {
    let start = Instant::now();
    loop {
        match child.try_wait()? {
            Some(status) => return Ok(TimeoutResult::Completed(status)),
            None => {
                if start.elapsed() >= timeout {
                    return Ok(TimeoutResult::TimedOut);
                }
                thread::sleep(POLL_INTERVAL);
            }
        }
    }
}

/// Run a child to completion, collecting stdout/stderr, bounded by `timeout`.
/// On timeout the child is killed and `TimedOut` is returned.
///
/// The child must already be configured via `.stdout(Stdio::piped())` etc.
/// if you want to capture output.
pub fn wait_output_with_timeout(
    mut child: Child,
    timeout: Duration,
) -> io::Result<TimeoutResult<Output>> {
    // Drain stdout/stderr on threads so the child's OS pipe buffers don't
    // fill up and deadlock before we hit the timeout.
    let stdout_thread = child.stdout.take().map(|mut s| {
        thread::Builder::new()
            .name("enclaveapp-child-stdout".into())
            .spawn(move || -> io::Result<Vec<u8>> {
                let mut buf = Vec::new();
                s.read_to_end(&mut buf)?;
                Ok(buf)
            })
    });
    let stderr_thread = child.stderr.take().map(|mut s| {
        thread::Builder::new()
            .name("enclaveapp-child-stderr".into())
            .spawn(move || -> io::Result<Vec<u8>> {
                let mut buf = Vec::new();
                s.read_to_end(&mut buf)?;
                Ok(buf)
            })
    });

    match wait_with_timeout(&mut child, timeout)? {
        TimeoutResult::Completed(status) => {
            let stdout = match stdout_thread {
                Some(Ok(t)) => t.join().unwrap_or_else(|_| Ok(Vec::new()))?,
                _ => Vec::new(),
            };
            let stderr = match stderr_thread {
                Some(Ok(t)) => t.join().unwrap_or_else(|_| Ok(Vec::new()))?,
                _ => Vec::new(),
            };
            Ok(TimeoutResult::Completed(Output {
                status,
                stdout,
                stderr,
            }))
        }
        TimeoutResult::TimedOut => {
            drop(child.kill());
            drop(child.wait());
            Ok(TimeoutResult::TimedOut)
        }
    }
}

/// Spawn a command with piped stdout/stderr and run it to completion
/// bounded by `timeout`.
pub fn run_with_timeout(
    mut cmd: std::process::Command,
    timeout: Duration,
) -> io::Result<TimeoutResult<Output>> {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let child = cmd.spawn()?;
    wait_output_with_timeout(child, timeout)
}

/// Spawn a command (inheriting stdout/stderr) and wait for its exit status
/// bounded by `timeout`. Kills the child on timeout.
pub fn run_status_with_timeout(
    mut cmd: std::process::Command,
    timeout: Duration,
) -> io::Result<TimeoutResult<ExitStatus>> {
    let mut child = cmd.spawn()?;
    match wait_with_timeout(&mut child, timeout)? {
        TimeoutResult::Completed(status) => Ok(TimeoutResult::Completed(status)),
        TimeoutResult::TimedOut => {
            drop(child.kill());
            drop(child.wait());
            Ok(TimeoutResult::TimedOut)
        }
    }
}

/// Blocking reader of `read_line` with a timeout. Spawns a worker thread
/// that owns the reader and sends each line over a channel.
///
/// The worker continues reading until EOF/error and cannot be cancelled
/// once started — intended for cases where the reader is owned by the
/// caller for the remainder of the session.
#[derive(Debug)]
pub struct LineReaderWithTimeout {
    rx: mpsc::Receiver<io::Result<String>>,
    _thread: thread::JoinHandle<()>,
}

impl LineReaderWithTimeout {
    /// Build a line reader with no per-line size cap. The worker reads
    /// until a newline regardless of length — only suitable for
    /// readers under our own control. Untrusted-peer cases (the WSL
    /// bridge, anything across a process boundary) should use
    /// [`Self::with_max_line_bytes`] so a malicious or malfunctioning
    /// peer can't drive unbounded heap allocation.
    pub fn new<R: Read + Send + 'static>(reader: R) -> Self {
        Self::spawn(reader, None)
    }

    /// Build a line reader that aborts (returns `InvalidData`) if a
    /// single line exceeds `max_line_bytes` before its terminating
    /// newline. Use this whenever the peer is across a trust boundary
    /// — it bounds the worst-case allocation per line at
    /// `max_line_bytes` rather than at the peer's discretion.
    pub fn with_max_line_bytes<R: Read + Send + 'static>(reader: R, max_line_bytes: usize) -> Self {
        Self::spawn(reader, Some(max_line_bytes))
    }

    fn spawn<R: Read + Send + 'static>(reader: R, max_line_bytes: Option<usize>) -> Self {
        let (tx, rx) = mpsc::channel();
        let thread = thread::Builder::new()
            .name("enclaveapp-line-reader".into())
            .spawn(move || {
                let mut buf_reader = BufReader::new(reader);
                loop {
                    let result = match max_line_bytes {
                        Some(max) => read_line_bounded(&mut buf_reader, max),
                        None => {
                            let mut line = String::new();
                            match buf_reader.read_line(&mut line) {
                                Ok(0) => Ok(None),
                                Ok(_) => Ok(Some(line)),
                                Err(e) => Err(e),
                            }
                        }
                    };
                    match result {
                        Ok(None) => break, // EOF
                        Ok(Some(line)) => {
                            if tx.send(Ok(line)).is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            drop(tx.send(Err(e)));
                            break;
                        }
                    }
                }
            })
            .expect("spawn line reader thread");
        Self {
            rx,
            _thread: thread,
        }
    }

    /// Receive the next line, or return `TimedOut` after `timeout`.
    /// Returns `Completed(Err(_))` on read error and `Completed(Ok(""))`
    /// on EOF.
    pub fn recv_line(&self, timeout: Duration) -> TimeoutResult<io::Result<String>> {
        match self.rx.recv_timeout(timeout) {
            Ok(result) => TimeoutResult::Completed(result),
            Err(mpsc::RecvTimeoutError::Timeout) => TimeoutResult::TimedOut,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                TimeoutResult::Completed(Ok(String::new()))
            }
        }
    }
}

/// Read a single line into a `String`, returning `Ok(None)` on EOF
/// before any byte arrives, `Ok(Some(line))` when a newline is hit
/// (with the newline included, matching `BufRead::read_line`), or
/// `Err` if the line exceeds `max_bytes` before a newline. The cap
/// is on the line content excluding any oversize byte that wasn't
/// consumed.
///
/// Public so it can be exercised by fuzz harnesses; production
/// callers should normally use `LineReaderWithTimeout::with_max_line_bytes`
/// instead, which adds the timeout-aware worker thread on top.
pub fn read_line_bounded<R: BufRead>(
    reader: &mut R,
    max_bytes: usize,
) -> io::Result<Option<String>> {
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let available = match reader.fill_buf() {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if available.is_empty() {
            // EOF
            return if buf.is_empty() {
                Ok(None)
            } else {
                String::from_utf8(buf)
                    .map(Some)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
            };
        }
        // Up to `max_bytes` of remaining capacity, consume bytes
        // through the next newline if one exists in that slice.
        let remaining = max_bytes.saturating_sub(buf.len());
        let usable = &available[..available.len().min(remaining + 1)];
        if let Some(pos) = usable.iter().position(|&b| b == b'\n') {
            buf.extend_from_slice(&usable[..=pos]);
            reader.consume(pos + 1);
            return String::from_utf8(buf)
                .map(Some)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e));
        }
        // No newline in the usable slice. Either we have headroom
        // (remaining > 0) and just consume what we have, or we've
        // hit the cap with no newline — that's a hard error, and we
        // do NOT consume the offending bytes (so the caller could
        // resync if they had any way to, though in practice the
        // session is dead).
        if remaining == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("line exceeds {max_bytes}-byte cap before newline"),
            ));
        }
        let take = remaining.min(available.len());
        buf.extend_from_slice(&available[..take]);
        reader.consume(take);
    }
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used, clippy::panic, let_underscore_drop)]
mod tests {
    use super::*;
    use std::process::Command;

    #[cfg(unix)]
    #[test]
    fn run_with_timeout_completes_fast_command() {
        let result = run_with_timeout(
            {
                let mut c = Command::new("/bin/sh");
                c.args(["-c", "echo hello"]);
                c
            },
            Duration::from_secs(5),
        )
        .unwrap();
        match result {
            TimeoutResult::Completed(output) => {
                assert!(output.status.success());
                assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "hello");
            }
            TimeoutResult::TimedOut => panic!("fast command should not time out"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn run_with_timeout_kills_slow_command() {
        let start = Instant::now();
        let result = run_with_timeout(
            {
                let mut c = Command::new("/bin/sh");
                c.args(["-c", "sleep 10"]);
                c
            },
            Duration::from_millis(200),
        )
        .unwrap();
        assert!(result.is_timed_out());
        // Should fire well before the 10s sleep finishes
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[cfg(unix)]
    #[test]
    fn line_reader_delivers_line_within_timeout() {
        use std::io::Write;
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "cat"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        let mut child = cmd.spawn().unwrap();
        let r = child.stdout.take().unwrap();
        let mut w = child.stdin.take().unwrap();
        let reader = LineReaderWithTimeout::new(r);
        writeln!(w, "hello world").unwrap();
        w.flush().unwrap();
        match reader.recv_line(Duration::from_secs(2)) {
            TimeoutResult::Completed(Ok(line)) => assert_eq!(line.trim(), "hello world"),
            other => panic!("unexpected result: {:?}", other),
        }
        // Close stdin so cat exits, then reap the child to avoid a zombie.
        drop(w);
        drop(child.wait());
    }

    #[cfg(unix)]
    #[test]
    fn bounded_line_reader_aborts_when_line_exceeds_cap() {
        // Feed 200 bytes followed by a newline through a bounded
        // reader with a 100-byte cap. The reader must surface an
        // InvalidData error rather than allocating the full 200.
        //
        // Use `seq 1 200 | xargs printf 'x%.0s'` rather than bash
        // brace expansion (`{1..200}`). `/bin/sh` on Linux runners
        // is `dash`, which doesn't expand `{1..200}` and produces a
        // single `x` — leading to a flaky pass on macOS (where
        // `/bin/sh` is bash) and a hard fail on the Linux CI runner.
        use std::io::Write;
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "seq 1 200 | xargs printf 'x%.0s' && printf '\\n'"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped());
        let mut child = cmd.spawn().unwrap();
        let stdout = child.stdout.take().unwrap();
        let reader = LineReaderWithTimeout::with_max_line_bytes(stdout, 100);
        match reader.recv_line(Duration::from_secs(2)) {
            TimeoutResult::Completed(Err(e)) => {
                assert_eq!(e.kind(), io::ErrorKind::InvalidData);
            }
            other => panic!("expected InvalidData, got: {:?}", other),
        }
        drop(child.kill());
        drop(child.wait());
        let _ = Write::flush(&mut io::stdout());
    }

    #[cfg(unix)]
    #[test]
    fn bounded_line_reader_accepts_line_within_cap() {
        use std::io::Write;
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "printf 'short line\\n'"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped());
        let mut child = cmd.spawn().unwrap();
        let stdout = child.stdout.take().unwrap();
        let reader = LineReaderWithTimeout::with_max_line_bytes(stdout, 1024);
        match reader.recv_line(Duration::from_secs(2)) {
            TimeoutResult::Completed(Ok(line)) => assert_eq!(line, "short line\n"),
            other => panic!("expected short line, got: {:?}", other),
        }
        drop(child.wait());
        let _ = Write::flush(&mut io::stdout());
    }

    #[cfg(unix)]
    #[test]
    fn line_reader_times_out_when_no_data() {
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "sleep 10"]).stdout(Stdio::piped());
        let mut child = cmd.spawn().unwrap();
        let stdout = child.stdout.take().unwrap();
        let reader = LineReaderWithTimeout::new(stdout);
        let start = Instant::now();
        let result = reader.recv_line(Duration::from_millis(200));
        assert!(result.is_timed_out());
        assert!(start.elapsed() < Duration::from_secs(1));
        drop(child.kill());
        drop(child.wait());
    }
}
