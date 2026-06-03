// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Bridge client for WSL/Linux. Spawns the Windows bridge binary and
//! communicates via JSON-RPC over stdin/stdout.
#![allow(dead_code, unused_imports, unused_qualifications, unreachable_patterns)]

use super::protocol::*;
use crate::internal::core::timeout::{wait_with_timeout, LineReaderWithTimeout, TimeoutResult};
use crate::internal::core::{AccessPolicy, Result};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

/// Maximum response size from the bridge (64 KB).
const MAX_BRIDGE_RESPONSE_BYTES: usize = 64 * 1024;

/// Default timeout for a single bridge request/response cycle.
///
/// 240 s — sized to cover four overlapping cold-start cases without
/// erroring:
///
/// 1. TPM service warmup (5–30 s typical, up to ~60 s on contended
///    boxes). The Windows TBS service may not be running yet on first
///    call after boot or after a Hyper-V cycle.
/// 2. Windows Hello / biometric prompt (up to ~60 s in practice while
///    the user finds their security key, fingerprint, or PIN).
/// 3. Authenticode verification + first-time process spawn on a cold
///    disk (antivirus on-access scan, slow disk).
/// 4. Some combination of the above on the same call.
///
/// Override via `ENCLAVEAPP_BRIDGE_TIMEOUT_SECS` for pathological
/// hardware.
const DEFAULT_BRIDGE_REQUEST_TIMEOUT: Duration = Duration::from_secs(240);

/// Timeout for bridge shutdown (after we close stdin, it should exit promptly).
const BRIDGE_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

fn bridge_request_timeout() -> Duration {
    std::env::var("ENCLAVEAPP_BRIDGE_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_BRIDGE_REQUEST_TIMEOUT)
}

/// Find the bridge executable on the Windows filesystem (from WSL).
///
/// Discovery order:
/// 1. The `ENCLAVEAPP_BRIDGE_PATH` environment variable (or the app-specific
///    `{APP_NAME_UPPER}_BRIDGE_PATH`) — explicit opt-in by the user. Needed for
///    non-admin installs like scoop where the bridge lives under
///    `%USERPROFILE%\scoop\apps\...`, which is not one of the default
///    candidate paths.
/// 2. Among the fixed install locations under `/mnt/c/Program Files/` and
///    `/mnt/c/ProgramData/` that actually exist, the one with the newest
///    modification time. This avoids silently picking a stale binary left
///    behind by a previous installer when the user has since installed a
///    newer version to a different location.
///
/// Only fixed admin-path install locations are included in the auto-discovery
/// fallback. PATH-based lookup via `which` was removed intentionally — a
/// user-writable `$PATH` entry on the WSL side could substitute a malicious
/// bridge binary. Users who install to non-admin paths (scoop, a manual
/// build) must set `ENCLAVEAPP_BRIDGE_PATH` explicitly.
///
/// The resolved executable is additionally gated by
/// [`require_bridge_is_authenticode_signed`] at spawn time — but only if
/// this build was compiled with `ENCLAVEAPP_BRIDGE_REQUIRE_SIGNED=1`.
/// Builds without that flag (including the current default release
/// pipeline) skip the signature check. See [`BUILD_REQUIRES_SIGNED`]
/// and THREAT_MODEL.md for the rationale.
#[allow(clippy::print_stderr)] // user-facing warning for misconfigured env var
pub fn find_bridge(app_name: &str) -> Option<PathBuf> {
    // 1. Explicit env var override (app-specific, then generic).
    let app_specific = format!("{}_BRIDGE_PATH", app_name.to_uppercase().replace('-', "_"));
    for var in [app_specific.as_str(), "ENCLAVEAPP_BRIDGE_PATH"] {
        if let Ok(value) = std::env::var(var) {
            let p = PathBuf::from(&value);
            if p.exists() {
                return Some(p);
            }
            // Env var was set but the path is missing — surface clearly
            // rather than silently falling through to auto-discovery.
            eprintln!(
                "warning: {var}={value} is set but the file does not exist; falling back to auto-discovery"
            );
        }
    }

    // 2. Auto-discovery: newest-mtime wins among existing admin-path candidates.
    let candidates = [
        format!("/mnt/c/Program Files/{app_name}/{app_name}-tpm-bridge.exe"),
        format!("/mnt/c/ProgramData/{app_name}/{app_name}-tpm-bridge.exe"),
        format!("/mnt/c/Program Files/{app_name}/{app_name}-bridge.exe"),
        format!("/mnt/c/ProgramData/{app_name}/{app_name}-bridge.exe"),
    ];
    candidates
        .iter()
        .filter_map(|path| {
            let p = PathBuf::from(path);
            let mtime = std::fs::metadata(&p).ok()?.modified().ok()?;
            Some((p, mtime))
        })
        .max_by_key(|(_, mtime)| *mtime)
        .map(|(path, _)| path)
}

/// Whether this build claims to be distributed as Authenticode-signed.
///
/// Set by the release workflow *at build time* via
/// `ENCLAVEAPP_BRIDGE_REQUIRE_SIGNED=1` when the signing pipeline is
/// actually configured. Default (unset) is **off** — matching the
/// current distribution reality where releases ship unsigned. When on,
/// [`require_bridge_is_authenticode_signed`] refuses unsigned bridges.
///
/// There is deliberately **no runtime opt-out**. Security is not a
/// runtime toggle — if the build enforces signing, it enforces it.
/// Operators who need to run with an unsigned bridge (local dev, a
/// custom fork) must compile without `ENCLAVEAPP_BRIDGE_REQUIRE_SIGNED`
/// set. This prevents a compromised WSL-side attacker from flipping
/// the security posture with a single env var.
const BUILD_REQUIRES_SIGNED: bool = option_env!("ENCLAVEAPP_BRIDGE_REQUIRE_SIGNED").is_some();

/// Refuse to spawn a bridge binary that lacks an Authenticode signature
/// block — but only if this build was compiled with
/// `ENCLAVEAPP_BRIDGE_REQUIRE_SIGNED=1`.
///
/// Parses the PE header's Certificate Table data directory
/// (`IMAGE_DIRECTORY_ENTRY_SECURITY`, index 4) and rejects the binary if
/// that directory is absent or zero-sized. This does NOT verify the
/// signature cryptographically or chase the certificate chain — that
/// requires `WinVerifyTrust` on Windows, which isn't reachable from the
/// WSL side without an extra helper process. What it does catch is the
/// concrete attack in the threat model: an attacker who replaces the
/// bridge binary with one they compiled themselves (e.g. ad-hoc `cargo
/// build` output that ships no signature at all). Admin-held replacement
/// with a validly-signed-but-malicious binary is out of scope and
/// acknowledged as such in the threat model.
///
/// Builds that are **not** compiled with `ENCLAVEAPP_BRIDGE_REQUIRE_SIGNED`
/// skip the check entirely (see [`BUILD_REQUIRES_SIGNED`]). This is
/// because the library is consumed by apps whose release pipeline does
/// not currently sign binaries; requiring signatures there would make
/// apps unable to spawn their own just-installed bridges. The trade-off
/// is documented in THREAT_MODEL.md.
pub fn require_bridge_is_authenticode_signed(bridge_path: &Path) -> Result<()> {
    check_bridge_signature(bridge_path, BUILD_REQUIRES_SIGNED)
}

/// Testable inner function — `require` is the compile-time default
/// [`BUILD_REQUIRES_SIGNED`] in production, but tests pass it explicitly
/// so they can exercise both branches without recompiling.
fn check_bridge_signature(bridge_path: &Path, require: bool) -> Result<()> {
    if !require {
        return Ok(());
    }
    // Only PE binaries have Authenticode. Anything that's not `.exe`
    // (test shell scripts, developer wrappers) bypasses this check —
    // the real WSL bridge is always `*.exe`.
    let is_exe = bridge_path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("exe"));
    if !is_exe {
        return Ok(());
    }
    match pe_has_authenticode_table(bridge_path) {
        Ok(true) => Ok(()),
        Ok(false) => Err(crate::internal::core::Error::KeyOperation {
            operation: "bridge_verify".into(),
            detail: format!(
                "bridge binary at {} has no Authenticode signature; refusing to spawn. \
                 This build was compiled with ENCLAVEAPP_BRIDGE_REQUIRE_SIGNED=1; \
                 reinstall from a signed release or recompile without that flag.",
                bridge_path.display()
            ),
        }),
        Err(detail) => Err(crate::internal::core::Error::KeyOperation {
            operation: "bridge_verify".into(),
            detail,
        }),
    }
}

/// Inspect a PE file's optional-header data-directory table and return
/// whether the `IMAGE_DIRECTORY_ENTRY_SECURITY` (index 4) slot points to
/// a non-empty certificate table.
///
/// Layout references:
/// - DOS header: 64 bytes, with `e_lfanew: u32` at offset 0x3C
///   pointing to the NT header.
/// - NT signature: "PE\0\0" (4 bytes).
/// - COFF file header: 20 bytes; `machine` at offset 0.
/// - Optional header: starts immediately after COFF. First 2 bytes are
///   the magic (PE32 = 0x10b, PE32+ = 0x20b) which determines whether
///   the data directory table starts at offset 96 (PE32) or 112 (PE32+).
/// - Data directory `IMAGE_DIRECTORY_ENTRY_SECURITY` is slot 4:
///   `virtual_address: u32, size: u32` — size > 0 means the binary
///   has an Authenticode cert table appended.
fn pe_has_authenticode_table(path: &Path) -> std::result::Result<bool, String> {
    let data = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    if data.len() < 0x40 {
        return Err("file too small for DOS header".into());
    }
    if &data[0..2] != b"MZ" {
        return Err("not a PE image (missing MZ magic)".into());
    }
    let e_lfanew = u32::from_le_bytes(
        data[0x3C..0x40]
            .try_into()
            .map_err(|_| "bad e_lfanew slice".to_string())?,
    ) as usize;
    if data.len() < e_lfanew + 0x18 {
        return Err("file too small for NT header".into());
    }
    if &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return Err("not a PE image (missing PE signature)".into());
    }
    let coff_start = e_lfanew + 4;
    let opt_header_start = coff_start + 20;
    if data.len() < opt_header_start + 2 {
        return Err("file too small for optional header magic".into());
    }
    let magic = u16::from_le_bytes(
        data[opt_header_start..opt_header_start + 2]
            .try_into()
            .map_err(|_| "bad optional-header magic slice".to_string())?,
    );
    // Offset within the optional header to DataDirectory[0].
    let data_dir_offset = match magic {
        0x10b => 96,  // PE32
        0x20b => 112, // PE32+
        _ => return Err(format!("unknown PE optional-header magic 0x{magic:x}")),
    };
    // Each DataDirectory is 8 bytes; SECURITY is index 4.
    let security_dir = opt_header_start + data_dir_offset + 4 * 8;
    if data.len() < security_dir + 8 {
        return Err("file too small for data directory table".into());
    }
    let size = u32::from_le_bytes(
        data[security_dir + 4..security_dir + 8]
            .try_into()
            .map_err(|_| "bad security dir size slice".to_string())?,
    );
    Ok(size > 0)
}

struct BridgeSession {
    child: std::process::Child,
    reader: LineReaderWithTimeout,
    finished: bool,
    request_timeout: Duration,
}

impl BridgeSession {
    fn spawn(bridge_path: &Path) -> Result<Self> {
        require_bridge_is_authenticode_signed(bridge_path)?;
        let mut child = Command::new(bridge_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| crate::internal::core::Error::KeyOperation {
                operation: "bridge_spawn".into(),
                detail: e.to_string(),
            })?;

        let stdout =
            child
                .stdout
                .take()
                .ok_or_else(|| crate::internal::core::Error::KeyOperation {
                    operation: "bridge_read".into(),
                    detail: "no stdout".into(),
                })?;

        Ok(Self {
            child,
            // The bridge is across a process boundary and may be
            // compromised or buggy; cap the per-line read at
            // MAX_BRIDGE_RESPONSE_BYTES so a malicious peer can't
            // drive unbounded heap allocation by withholding the
            // newline. The reader returns InvalidData if the cap is
            // hit before the terminator.
            reader: LineReaderWithTimeout::with_max_line_bytes(stdout, MAX_BRIDGE_RESPONSE_BYTES),
            finished: false,
            request_timeout: bridge_request_timeout(),
        })
    }

    fn request(&mut self, request: &BridgeRequest) -> Result<BridgeResponse> {
        let request_json = serde_json::to_string(request)
            .map_err(|e| crate::internal::core::Error::Serialization(e.to_string()))?;

        if let Some(ref mut stdin) = self.child.stdin {
            writeln!(stdin, "{request_json}").map_err(crate::internal::core::Error::Io)?;
            stdin.flush().map_err(crate::internal::core::Error::Io)?;
        }

        let line = match self.reader.recv_line(self.request_timeout) {
            TimeoutResult::Completed(Ok(line)) => line,
            TimeoutResult::Completed(Err(e)) => {
                // Kill the child on read errors too — the most common
                // case is the bounded reader's InvalidData cap-hit,
                // which means the bridge is misbehaving and the
                // session is unrecoverable. Surface it as a typed
                // KeyOperation so the operator sees the size cap in
                // the error rather than a raw io::Error chain.
                let cap_hit = e.kind() == std::io::ErrorKind::InvalidData;
                drop(self.child.kill());
                drop(self.child.wait());
                self.finished = true;
                return if cap_hit {
                    Err(crate::internal::core::Error::KeyOperation {
                        operation: "bridge_read".into(),
                        detail: format!(
                            "bridge response exceeded {MAX_BRIDGE_RESPONSE_BYTES}-byte cap \
                             before newline ({e})"
                        ),
                    })
                } else {
                    Err(crate::internal::core::Error::Io(e))
                };
            }
            TimeoutResult::TimedOut => {
                // Kill the child so we're not leaving a stuck TPM op running.
                drop(self.child.kill());
                drop(self.child.wait());
                self.finished = true;
                return Err(crate::internal::core::Error::KeyOperation {
                    operation: "bridge_read".into(),
                    detail: format!(
                        "bridge did not respond within {}s (set ENCLAVEAPP_BRIDGE_TIMEOUT_SECS to override)",
                        self.request_timeout.as_secs()
                    ),
                });
            }
        };

        if line.trim().is_empty() {
            return Err(crate::internal::core::Error::KeyOperation {
                operation: "bridge_read".into(),
                detail: "bridge returned no response".into(),
            });
        }

        let response: BridgeResponse = serde_json::from_str(&line).map_err(|e| {
            crate::internal::core::Error::Serialization(format!("bridge response: {e}"))
        })?;

        Ok(response)
    }
}

impl Drop for BridgeSession {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        // Close stdin first: the bridge protocol exits cleanly on
        // EOF, and waiting for that beats SIGKILL when feasible.
        // We bound the wait so a wedged TPM op can't pin us.
        drop(self.child.stdin.take());
        match wait_with_timeout(&mut self.child, BRIDGE_SHUTDOWN_TIMEOUT) {
            Ok(TimeoutResult::Completed(_)) => {
                self.finished = true;
                return;
            }
            Ok(TimeoutResult::TimedOut) | Err(_) => {
                // Fall through to kill.
            }
        }
        drop(self.child.kill());
        drop(self.child.wait());
        self.finished = true;
    }
}

/// Process-shared map of `bridge_path` → persistent session.
///
/// Each entry is a `Mutex<Option<BridgeSession>>` shared via `Arc`.
/// The `Option` holds the (lazily-spawned) child process; `None`
/// before first use, after a session error that forced a respawn,
/// or after the subprocess died. The `Mutex` serializes calls
/// against a single bridge subprocess (same UX semantics as the
/// previous `BRIDGE_SESSION_LOCK` — Windows Hello prompts must not
/// race; TPM key slot contention; interleaved-stderr ambiguity).
///
/// Why per-path rather than truly global: a single process could in
/// principle have multiple distinct bridge installs reachable
/// (e.g. a sshenc + an awsenc both exposing their own bridge.exe).
/// Serializing per-path lets independent bridges run in parallel
/// while a single bridge's calls remain ordered. In practice every
/// known consumer uses one path per process, so this collapses to
/// the same behavior as the previous global lock.
///
/// The bridge subprocess is **persistent across calls** within a
/// process (the architectural change in this commit). Previously
/// every `call_bridge` / `call_bridge_after_init` spawned a fresh
/// `sshenc-tpm-bridge.exe`, paying the WSL→Windows interop +
/// TPM-service warmup cost on every call. With the persistent
/// session, the subprocess is spawned once on first call and
/// reused — agent-side bridge ops drop from "5-10s cold first
/// call, ~50ms warm thereafter" to "5-10s once at first call,
/// effectively zero subprocess overhead thereafter."
///
/// Server-side state across multiple `init` calls on the same
/// connection: handle_request in enclaveapp-tpm-bridge replaces
/// `Option<TpmStorage>` on each `init`, so reusing the connection
/// across different (app, label, policy) tuples is safe.
///
/// On any session error (subprocess died, IO failure, request
/// timeout fired and killed the child), the `Option` is cleared
/// and the next call will respawn. Callers retry exactly once
/// per call so a transient subprocess loss is invisible.
type PersistentSessionMap = HashMap<PathBuf, Arc<Mutex<Option<BridgeSession>>>>;
static PERSISTENT_BRIDGES: OnceLock<Mutex<PersistentSessionMap>> = OnceLock::new();

/// Get-or-create the per-path persistent session handle. Map lock
/// is held briefly (just to look up / insert); the per-path session
/// mutex is what serializes actual calls.
fn persistent_session(bridge_path: &Path) -> Arc<Mutex<Option<BridgeSession>>> {
    let map = PERSISTENT_BRIDGES.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = match map.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    guard
        .entry(bridge_path.to_path_buf())
        .or_insert_with(|| Arc::new(Mutex::new(None)))
        .clone()
}

fn lock_session(
    arc: &Arc<Mutex<Option<BridgeSession>>>,
) -> std::sync::MutexGuard<'_, Option<BridgeSession>> {
    match arc.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

/// Send `request` over the persistent bridge session for
/// `bridge_path`. Spawns a fresh session if none exists. Retries
/// exactly once (with a freshly spawned session) if the existing
/// session errors — covers the case where a previous request's
/// timeout killed the subprocess or the subprocess crashed
/// between calls.
pub fn call_bridge(bridge_path: &Path, request: &BridgeRequest) -> Result<BridgeResponse> {
    let session_arc = persistent_session(bridge_path);
    let mut guard = lock_session(&session_arc);
    let mut last_err: Option<crate::internal::core::Error> = None;
    for _attempt in 0..2 {
        if guard.is_none() {
            *guard = Some(BridgeSession::spawn(bridge_path)?);
        }
        match guard.as_mut().expect("just-spawned").request(request) {
            Ok(resp) => return Ok(resp),
            Err(e) => {
                // Drop the dead session. Drop impl kills + waits.
                drop(guard.take());
                last_err = Some(e);
            }
        }
    }
    Err(last_err.expect("retry loop never recorded an error"))
}

fn init_request(app_name: &str, key_label: &str, access_policy: AccessPolicy) -> BridgeRequest {
    BridgeRequest {
        method: "init".to_string(),
        params: BridgeParams::new(
            String::new(),
            access_policy,
            app_name.to_string(),
            key_label.to_string(),
        ),
    }
}

/// Send `init` then `request` atomically against the same
/// persistent session. Same retry semantics as `call_bridge`:
/// one transparent re-spawn-and-retry on session-level errors.
fn call_bridge_after_init(
    bridge_path: &Path,
    app_name: &str,
    key_label: &str,
    access_policy: AccessPolicy,
    request: &BridgeRequest,
) -> Result<BridgeResponse> {
    let session_arc = persistent_session(bridge_path);
    let mut guard = lock_session(&session_arc);
    let mut last_err: Option<crate::internal::core::Error> = None;
    for _attempt in 0..2 {
        if guard.is_none() {
            *guard = Some(BridgeSession::spawn(bridge_path)?);
        }
        let session = guard.as_mut().expect("just-spawned");
        let result = (|| -> Result<BridgeResponse> {
            session
                .request(&init_request(app_name, key_label, access_policy))?
                .require_ok("bridge_init")?;
            session.request(request)
        })();
        match result {
            Ok(resp) => return Ok(resp),
            Err(e) => {
                drop(guard.take());
                last_err = Some(e);
            }
        }
    }
    Err(last_err.expect("retry loop never recorded an error"))
}

/// Initialize the bridge-side key lifecycle for a specific app/label pair.
pub fn bridge_init(
    bridge_path: &Path,
    app_name: &str,
    key_label: &str,
    access_policy: AccessPolicy,
) -> Result<()> {
    let response = call_bridge(
        bridge_path,
        &init_request(app_name, key_label, access_policy),
    )?;
    response.require_ok("bridge_init")
}

/// Convenience: encrypt data via the bridge.
pub fn bridge_encrypt(
    bridge_path: &Path,
    app_name: &str,
    key_label: &str,
    plaintext: &[u8],
    access_policy: AccessPolicy,
) -> Result<Vec<u8>> {
    let request = BridgeRequest {
        method: "encrypt".to_string(),
        params: BridgeParams::new(
            encode_data(plaintext),
            access_policy,
            app_name.to_string(),
            key_label.to_string(),
        ),
    };
    let response =
        call_bridge_after_init(bridge_path, app_name, key_label, access_policy, &request)?;
    response.decode_result("bridge_encrypt")
}

/// Convenience: decrypt data via the bridge.
pub fn bridge_decrypt(
    bridge_path: &Path,
    app_name: &str,
    key_label: &str,
    ciphertext: &[u8],
    access_policy: AccessPolicy,
) -> Result<Vec<u8>> {
    let request = BridgeRequest {
        method: "decrypt".to_string(),
        params: BridgeParams::new(
            encode_data(ciphertext),
            access_policy,
            app_name.to_string(),
            key_label.to_string(),
        ),
    };
    let response =
        call_bridge_after_init(bridge_path, app_name, key_label, access_policy, &request)?;
    response.decode_result("bridge_decrypt")
}

/// Destroy the bridge-side key for a specific app/label pair.
/// Sends "delete" on the wire for backward compatibility with existing bridge servers.
pub fn bridge_destroy(bridge_path: &Path, app_name: &str, key_label: &str) -> Result<()> {
    let request = BridgeRequest {
        method: "delete".to_string(),
        params: BridgeParams::new(
            String::new(),
            AccessPolicy::None,
            app_name.to_string(),
            key_label.to_string(),
        ),
    };
    let response = call_bridge(bridge_path, &request)?;
    response.require_ok("bridge_destroy")
}

/// Alias for backward compatibility.
pub fn bridge_delete(bridge_path: &Path, app_name: &str, key_label: &str) -> Result<()> {
    bridge_destroy(bridge_path, app_name, key_label)
}

// ---------------------------------------------------------------------------
// Signing bridge operations
// ---------------------------------------------------------------------------

fn init_signing_request(
    app_name: &str,
    key_label: &str,
    access_policy: AccessPolicy,
) -> BridgeRequest {
    BridgeRequest {
        method: "init_signing".to_string(),
        params: BridgeParams::new(
            String::new(),
            access_policy,
            app_name.to_string(),
            key_label.to_string(),
        ),
    }
}

fn call_bridge_after_signing_init(
    bridge_path: &Path,
    app_name: &str,
    key_label: &str,
    access_policy: AccessPolicy,
    request: &BridgeRequest,
) -> Result<BridgeResponse> {
    // Same pattern as call_bridge_after_init: persistent session +
    // one retry on session-level error.
    let session_arc = persistent_session(bridge_path);
    let mut guard = lock_session(&session_arc);
    let mut last_err: Option<crate::internal::core::Error> = None;
    for _attempt in 0..2 {
        if guard.is_none() {
            *guard = Some(BridgeSession::spawn(bridge_path)?);
        }
        let session = guard.as_mut().expect("just-spawned");
        let result = (|| -> Result<BridgeResponse> {
            session
                .request(&init_signing_request(app_name, key_label, access_policy))?
                .require_ok("bridge_init_signing")?;
            session.request(request)
        })();
        match result {
            Ok(resp) => return Ok(resp),
            Err(e) => {
                drop(guard.take());
                last_err = Some(e);
            }
        }
    }
    Err(last_err.expect("retry loop never recorded an error"))
}

/// Initialize the bridge-side signing key lifecycle for a specific app/label pair.
pub fn bridge_init_signing(
    bridge_path: &Path,
    app_name: &str,
    key_label: &str,
    access_policy: AccessPolicy,
) -> Result<()> {
    let response = call_bridge(
        bridge_path,
        &init_signing_request(app_name, key_label, access_policy),
    )?;
    response.require_ok("bridge_init_signing")
}

/// Convenience: sign data via the bridge.
pub fn bridge_sign(
    bridge_path: &Path,
    app_name: &str,
    key_label: &str,
    data: &[u8],
    access_policy: AccessPolicy,
) -> Result<Vec<u8>> {
    let request = BridgeRequest {
        method: "sign".to_string(),
        params: BridgeParams::new(
            encode_data(data),
            access_policy,
            app_name.to_string(),
            key_label.to_string(),
        ),
    };
    let response =
        call_bridge_after_signing_init(bridge_path, app_name, key_label, access_policy, &request)?;
    response.decode_result("bridge_sign")
}

/// Read the public key for an existing (app_name, key_label) pair
/// via the bridge. Standalone: does NOT prefix with `init_signing`.
///
/// Callers that need create-if-missing semantics (e.g. keygen) should
/// invoke `bridge_init_signing` explicitly first, then call this to
/// fetch the resulting public key. Read-only callers (e.g. agent
/// identity enumeration, sshenc-se's proxy fetching pubkey bytes for
/// a known label) get a clean read with no side effect; if the key
/// is missing, the bridge surfaces the underlying `KeyNotFound`
/// shape rather than silently creating it.
///
/// History: paired with `bridge_list_keys` becoming standalone
/// (enclave PR #110), this finishes off the
/// `call_bridge_after_signing_init` audit -- of the public bridge
/// helpers, only `bridge_sign` legitimately needs the init prelude
/// (signing requires a real key for the given label).
pub fn bridge_public_key(
    bridge_path: &Path,
    app_name: &str,
    key_label: &str,
    access_policy: AccessPolicy,
) -> Result<Vec<u8>> {
    let request = BridgeRequest {
        method: "public_key".to_string(),
        params: BridgeParams::new(
            String::new(),
            access_policy,
            app_name.to_string(),
            key_label.to_string(),
        ),
    };
    let response = call_bridge(bridge_path, &request)?;
    response.decode_result("bridge_public_key")
}

/// Convenience: list signing keys via the bridge.
///
/// Sends `list_keys` directly without the `init_signing` prelude that
/// other helpers go through. This is deliberately *not* using
/// `call_bridge_after_signing_init`: doing so would create a signing
/// key with the configured `key_label` (defaults to `"default"`) as a
/// side effect of every list call, which surfaced as the agent's
/// identity-enumeration silently leaking a `default` key on every
/// matrix run. The server-side `list_keys` handler is now standalone
/// and enumerates by `app_name`, so the per-label `init_signing` is
/// no longer needed (and was never semantically right for a list-all
/// operation in the first place).
pub fn bridge_list_keys(
    bridge_path: &Path,
    app_name: &str,
    _key_label: &str,
    access_policy: AccessPolicy,
) -> Result<Vec<String>> {
    let request = BridgeRequest {
        method: "list_keys".to_string(),
        params: BridgeParams::new(
            String::new(),
            access_policy,
            app_name.to_string(),
            String::new(),
        ),
    };
    let response = call_bridge(bridge_path, &request)?;
    let result_str = response.require_result("bridge_list_keys")?;
    serde_json::from_str(result_str)
        .map_err(|e| crate::internal::core::Error::Serialization(format!("list_keys JSON: {e}")))
}

/// Delete a signing key via the bridge.
pub fn bridge_delete_signing(bridge_path: &Path, app_name: &str, key_label: &str) -> Result<()> {
    let request = BridgeRequest {
        method: "delete_signing".to_string(),
        params: BridgeParams::new(
            String::new(),
            AccessPolicy::None,
            app_name.to_string(),
            key_label.to_string(),
        ),
    };
    let response = call_bridge(bridge_path, &request)?;
    response.require_ok("bridge_delete_signing")
}

/// Check if a signing key exists on the bridge side without creating it.
///
/// Unlike `bridge_public_key` / `bridge_list_keys`, this does NOT invoke
/// `init_signing`, so the TPM key is never created as a side effect of
/// the check. Use this for duplicate-label guards.
pub fn bridge_signing_key_exists(
    bridge_path: &Path,
    app_name: &str,
    key_label: &str,
) -> Result<bool> {
    let request = BridgeRequest {
        method: "signing_key_exists".to_string(),
        params: BridgeParams::new(
            String::new(),
            AccessPolicy::None,
            app_name.to_string(),
            key_label.to_string(),
        ),
    };
    let response = call_bridge(bridge_path, &request)?;
    let result = response.require_result("bridge_signing_key_exists")?;
    match result {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(crate::internal::core::Error::KeyOperation {
            operation: "bridge_signing_key_exists".into(),
            detail: format!("unexpected result: {other}"),
        }),
    }
}

// ============================================================
// WebAuthn / SK convenience wrappers
// ============================================================
//
// These let WSL Linux callers route SK keygen / sign / delete /
// availability through the Windows-side `webauthn.dll` via the
// existing JSON-RPC bridge. Hello prompt fires on the Windows
// desktop; the SSH key lives in WSL `~/.ssh`. Wire format is
// identical to native-Windows SK signing -- the bridge only
// shuttles the WebAuthn primitives.

/// Probe the bridge for `WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable`.
/// Returns `Ok(true)` only when the Windows host's WebAuthn API
/// reports an available platform authenticator (Hello enrolled).
pub fn bridge_webauthn_is_available(bridge_path: &Path) -> Result<bool> {
    let request = BridgeRequest {
        method: "webauthn_is_available".to_string(),
        params: BridgeParams::default(),
    };
    let response = call_bridge(bridge_path, &request)?;
    let result = response.require_result("bridge_webauthn_is_available")?;
    Ok(result == "true")
}

/// Make a TPM-bound credential through the Windows-side WebAuthn
/// platform authenticator. Fires a Hello prompt on the Windows
/// desktop. Returns the parsed `WebauthnMakeCredentialResult`
/// (credential id + EC pubkey x/y + authenticator data).
#[allow(clippy::too_many_arguments)]
pub fn bridge_webauthn_make_credential(
    bridge_path: &Path,
    rp_id: &str,
    rp_name: &str,
    user_id: &[u8],
    user_name: &str,
    user_display_name: &str,
    timeout_ms: u32,
) -> Result<WebauthnMakeCredentialResult> {
    let params = BridgeParams {
        rp_id: Some(rp_id.to_string()),
        rp_name: Some(rp_name.to_string()),
        user_id_b64: Some(encode_data(user_id)),
        user_name: Some(user_name.to_string()),
        user_display_name: Some(user_display_name.to_string()),
        timeout_ms: Some(timeout_ms),
        ..BridgeParams::default()
    };
    let request = BridgeRequest {
        method: "webauthn_make_credential".to_string(),
        params,
    };
    let response = call_bridge(bridge_path, &request)?;
    let result_json = response.require_result("bridge_webauthn_make_credential")?;
    serde_json::from_str(result_json).map_err(|e| crate::internal::core::Error::KeyOperation {
        operation: "bridge_webauthn_make_credential".into(),
        detail: format!("failed to parse make_credential result: {e}"),
    })
}

/// Sign `client_data` through the Windows-side WebAuthn platform
/// authenticator using a previously-made `credential_id`. Fires a
/// Hello prompt on the Windows desktop. Returns the parsed
/// `WebauthnAssertionResult` (DER signature + authenticator data
/// + flags + counter).
pub fn bridge_webauthn_get_assertion(
    bridge_path: &Path,
    rp_id: &str,
    credential_id: &[u8],
    client_data: &[u8],
    timeout_ms: u32,
) -> Result<WebauthnAssertionResult> {
    let params = BridgeParams {
        rp_id: Some(rp_id.to_string()),
        credential_id_b64: Some(encode_data(credential_id)),
        client_data_b64: Some(encode_data(client_data)),
        timeout_ms: Some(timeout_ms),
        ..BridgeParams::default()
    };
    let request = BridgeRequest {
        method: "webauthn_get_assertion".to_string(),
        params,
    };
    let response = call_bridge(bridge_path, &request)?;
    let result_json = response.require_result("bridge_webauthn_get_assertion")?;
    serde_json::from_str(result_json).map_err(|e| crate::internal::core::Error::KeyOperation {
        operation: "bridge_webauthn_get_assertion".into(),
        detail: format!("failed to parse get_assertion result: {e}"),
    })
}

/// Remove a previously-made platform credential from the user's
/// Windows passkey list. Best-effort -- if the credential is
/// already gone (user pruned via Settings > Passkeys), the
/// underlying API returns an error we generally want to ignore.
pub fn bridge_webauthn_delete_platform_credential(
    bridge_path: &Path,
    credential_id: &[u8],
) -> Result<()> {
    let params = BridgeParams {
        credential_id_b64: Some(encode_data(credential_id)),
        ..BridgeParams::default()
    };
    let request = BridgeRequest {
        method: "webauthn_delete_platform_credential".to_string(),
        params,
    };
    let response = call_bridge(bridge_path, &request)?;
    response.require_ok("bridge_webauthn_delete_platform_credential")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[cfg(unix)]
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    #[cfg(unix)]
    use std::sync::atomic::{AtomicU64, Ordering};
    #[cfg(unix)]
    use std::sync::Mutex;

    #[cfg(unix)]
    static SCRIPT_COUNTER: AtomicU64 = AtomicU64::new(0);
    #[cfg(unix)]
    static SCRIPT_TEST_MUTEX: Mutex<()> = Mutex::new(());

    #[cfg(unix)]
    fn temp_script(name: &str, body: &str) -> PathBuf {
        let id = SCRIPT_COUNTER.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!(
            "enclaveapp-bridge-test-{}-{}-{}",
            std::process::id(),
            id,
            name
        ));
        fs::write(&path, body).unwrap();
        let mut perms = fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&path, perms).unwrap();
        path
    }

    #[cfg(unix)]
    fn cleanup_script(path: &Path) {
        drop(fs::remove_file(path));
    }

    #[cfg(unix)]
    #[test]
    fn find_bridge_returns_none_when_not_found() {
        // Must hold the mutex: other tests in this file set ENCLAVEAPP_BRIDGE_PATH
        // and if this test runs concurrently it would see the env var and return Some.
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        // Ensure neither bridge-path env var is set.
        std::env::remove_var("ENCLAVEAPP_BRIDGE_PATH");
        std::env::remove_var("ENCLAVEAPP_NONEXISTENT_TEST_APP_BRIDGE_PATH");
        let result = find_bridge("enclaveapp-nonexistent-test-app");
        assert!(result.is_none(), "expected None, got: {result:?}");
    }

    // ---- Authenticode / PE signature check -----------------------------

    #[cfg(unix)]
    fn make_pe_bytes(security_size: u32, magic: u16) -> Vec<u8> {
        // DOS header (64 bytes) + NT sig (4) + COFF (20) + optional header
        // + data directories.
        //
        // Optional header size varies by magic (PE32 vs PE32+).
        let opt_header_size: usize = if magic == 0x10b {
            96 + 16 * 8
        } else {
            112 + 16 * 8
        };
        let total = 0x40 + 4 + 20 + opt_header_size;
        let mut buf = vec![0_u8; total];
        // "MZ"
        buf[0] = b'M';
        buf[1] = b'Z';
        // e_lfanew → NT headers start at offset 0x40.
        buf[0x3C..0x40].copy_from_slice(&0x40_u32.to_le_bytes());
        // "PE\0\0"
        buf[0x40] = b'P';
        buf[0x41] = b'E';
        // COFF at 0x44 is all zeros (acceptable for the check).
        // Optional header starts at 0x40 + 4 + 20 = 0x58.
        let opt_header_start = 0x58;
        buf[opt_header_start..opt_header_start + 2].copy_from_slice(&magic.to_le_bytes());
        // Data directory offset within the optional header.
        let data_dir_offset = if magic == 0x10b { 96 } else { 112 };
        // Security directory is index 4: 8 bytes per entry, skip 4.
        let security_dir = opt_header_start + data_dir_offset + 4 * 8;
        // VirtualAddress (unused by the check).
        buf[security_dir..security_dir + 4].copy_from_slice(&0_u32.to_le_bytes());
        // Size — this is what we check.
        buf[security_dir + 4..security_dir + 8].copy_from_slice(&security_size.to_le_bytes());
        buf
    }

    #[cfg(unix)]
    #[test]
    fn pe_has_authenticode_table_detects_signed_pe32() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        let bytes = make_pe_bytes(1024, 0x10b);
        let path = std::env::temp_dir().join(format!(
            "enclaveapp-pe-signed-{}-{}.exe",
            std::process::id(),
            SCRIPT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        fs::write(&path, &bytes).unwrap();
        assert!(pe_has_authenticode_table(&path).unwrap());
        drop(fs::remove_file(&path));
    }

    #[cfg(unix)]
    #[test]
    fn pe_has_authenticode_table_detects_signed_pe32plus() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        let bytes = make_pe_bytes(4096, 0x20b);
        let path = std::env::temp_dir().join(format!(
            "enclaveapp-pe-signed64-{}-{}.exe",
            std::process::id(),
            SCRIPT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        fs::write(&path, &bytes).unwrap();
        assert!(pe_has_authenticode_table(&path).unwrap());
        drop(fs::remove_file(&path));
    }

    #[cfg(unix)]
    #[test]
    fn pe_has_authenticode_table_detects_unsigned() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        let bytes = make_pe_bytes(0, 0x10b);
        let path = std::env::temp_dir().join(format!(
            "enclaveapp-pe-unsigned-{}-{}.exe",
            std::process::id(),
            SCRIPT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        fs::write(&path, &bytes).unwrap();
        assert!(!pe_has_authenticode_table(&path).unwrap());
        drop(fs::remove_file(&path));
    }

    #[cfg(unix)]
    #[test]
    fn pe_has_authenticode_table_rejects_non_pe() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        let path = std::env::temp_dir().join(format!(
            "enclaveapp-pe-notpe-{}-{}.exe",
            std::process::id(),
            SCRIPT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        // Write > 64 bytes of arbitrary non-PE content so we clear the
        // "too small for DOS header" check and actually hit the
        // "missing MZ magic" branch.
        let content: Vec<u8> = b"#!/bin/sh\n# not a PE image\nexit 0\n"
            .iter()
            .copied()
            .chain(std::iter::repeat(b'x').take(128))
            .collect();
        fs::write(&path, &content).unwrap();
        let err = pe_has_authenticode_table(&path).unwrap_err();
        assert!(err.contains("MZ"), "expected MZ-missing error, got: {err}");
        drop(fs::remove_file(&path));
    }

    #[cfg(unix)]
    #[test]
    fn check_bridge_signature_skips_non_exe_paths_when_required() {
        // Shell scripts (our test-bridge pattern) must pass the gate
        // unconditionally so existing integration tests keep working,
        // even when signing is required.
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        let script = temp_script("unsigned-script.sh", "#!/bin/sh\nexit 0\n");
        check_bridge_signature(&script, true).unwrap();
        cleanup_script(&script);
    }

    #[cfg(unix)]
    #[test]
    fn check_bridge_signature_rejects_unsigned_exe_when_required() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        let bytes = make_pe_bytes(0, 0x10b);
        let path = std::env::temp_dir().join(format!(
            "enclaveapp-pe-rejected-{}-{}.exe",
            std::process::id(),
            SCRIPT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        fs::write(&path, &bytes).unwrap();
        let err = check_bridge_signature(&path, true).unwrap_err();
        assert!(
            err.to_string().contains("no Authenticode signature"),
            "got: {err}"
        );
        drop(fs::remove_file(&path));
    }

    #[cfg(unix)]
    #[test]
    fn check_bridge_signature_accepts_unsigned_exe_when_not_required() {
        // When the build is not compiled with
        // ENCLAVEAPP_BRIDGE_REQUIRE_SIGNED, unsigned binaries are accepted.
        // This is the default posture for the current release pipeline.
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        let bytes = make_pe_bytes(0, 0x10b);
        let path = std::env::temp_dir().join(format!(
            "enclaveapp-pe-default-{}-{}.exe",
            std::process::id(),
            SCRIPT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        fs::write(&path, &bytes).unwrap();
        check_bridge_signature(&path, false).unwrap();
        drop(fs::remove_file(&path));
    }

    #[cfg(unix)]
    #[test]
    fn find_bridge_env_var_override_wins_when_path_exists() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        // Create a temp file and point the env var at it.
        let script = temp_script("override-bridge", "#!/bin/sh\nexit 0\n");
        std::env::set_var("ENCLAVEAPP_BRIDGE_PATH", &script);
        let found = find_bridge("some-app-that-has-no-admin-install");
        std::env::remove_var("ENCLAVEAPP_BRIDGE_PATH");
        assert_eq!(found.as_deref(), Some(script.as_path()));
        cleanup_script(&script);
    }

    #[cfg(unix)]
    #[test]
    fn find_bridge_env_var_override_ignored_when_path_missing() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        std::env::set_var("ENCLAVEAPP_BRIDGE_PATH", "/nonexistent/path/to/bridge.exe");
        let found = find_bridge("another-nonexistent-app");
        std::env::remove_var("ENCLAVEAPP_BRIDGE_PATH");
        // Env var points at nothing and no admin-path candidate exists → None.
        assert!(found.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn bridge_init_sends_key_label() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        let script = temp_script(
            "init.sh",
            r#"#!/bin/sh
read request_line
case "$request_line" in
  *'"method":"init"'*'"app_name":"awsenc"'*'"key_label":"cache-key"'*) printf '{"result":"","error":null}\n' ;;
  *) printf '{"result":null,"error":"unexpected request"}\n' ;;
esac
"#,
        );
        bridge_init(&script, "awsenc", "cache-key", AccessPolicy::BiometricOnly).unwrap();
        cleanup_script(&script);
    }

    #[cfg(unix)]
    #[test]
    fn bridge_encrypt_initializes_before_encrypting() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        let script = temp_script(
            "encrypt.sh",
            r#"#!/bin/sh
read init_line
case "$init_line" in
  *'"method":"init"'*'"key_label":"cache-key"'*) printf '{"result":"","error":null}\n' ;;
  *) printf '{"result":null,"error":"unexpected init request"}\n'; exit 0 ;;
esac
read request_line
case "$request_line" in
  *'"method":"encrypt"'*) printf '{"result":"aGVsbG8=","error":null}\n' ;;
  *) printf '{"result":null,"error":"unexpected request"}\n' ;;
esac
"#,
        );
        let plaintext = bridge_encrypt(
            &script,
            "awsenc",
            "cache-key",
            b"ignored",
            AccessPolicy::BiometricOnly,
        )
        .unwrap();
        assert_eq!(plaintext, b"hello");
        cleanup_script(&script);
    }

    #[cfg(unix)]
    #[test]
    fn bridge_delete_sends_delete_request() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        let script = temp_script(
            "delete.sh",
            r#"#!/bin/sh
read request_line
case "$request_line" in
  *'"method":"delete"'*'"key_label":"cache-key"'*) printf '{"result":"","error":null}\n' ;;
  *) printf '{"result":null,"error":"unexpected request"}\n' ;;
esac
"#,
        );
        bridge_destroy(&script, "awsenc", "cache-key").unwrap();
        cleanup_script(&script);
    }

    #[cfg(unix)]
    #[test]
    fn bridge_encrypt_rejects_missing_result_payload() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        let script = temp_script(
            "encrypt-missing-result.sh",
            r#"#!/bin/sh
read init_line
printf '{"result":"","error":null}\n'
read request_line
printf '{"result":null,"error":null}\n'
"#,
        );
        let error = bridge_encrypt(
            &script,
            "awsenc",
            "cache-key",
            b"ignored",
            AccessPolicy::None,
        )
        .unwrap_err();
        assert!(error.to_string().contains("missing result payload"));
        cleanup_script(&script);
    }

    #[cfg(unix)]
    #[test]
    fn bridge_init_rejects_missing_result_payload() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        let script = temp_script(
            "init-missing-result.sh",
            r#"#!/bin/sh
read request_line
printf '{"result":null,"error":null}\n'
"#,
        );
        let error = bridge_init(&script, "awsenc", "cache-key", AccessPolicy::None).unwrap_err();
        assert!(error.to_string().contains("missing result payload"));
        cleanup_script(&script);
    }

    #[cfg(unix)]
    #[test]
    fn bridge_rejects_oversized_response() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        let script = temp_script(
            "oversized.sh",
            "#!/bin/sh\nread req\npython3 -c \"print('{\\\"result\\\":\\\"' + 'A' * 70000 + '\\\",\\\"error\\\":null}')\"\n",
        );
        let request = BridgeRequest {
            method: "init".to_string(),
            params: BridgeParams::new(
                String::new(),
                AccessPolicy::None,
                "test".into(),
                "key".into(),
            ),
        };
        let err = call_bridge(&script, &request).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("byte limit") || msg.contains("bridge response"),
            "expected size limit error, got: {msg}"
        );
        cleanup_script(&script);
    }

    #[cfg(unix)]
    #[test]
    fn bridge_decrypt_initializes_before_decrypting() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        let script = temp_script(
            "decrypt.sh",
            r#"#!/bin/sh
read init_line
case "$init_line" in
  *'"method":"init"'*) printf '{"result":"","error":null}\n' ;;
  *) printf '{"result":null,"error":"unexpected init"}\n'; exit 0 ;;
esac
read request_line
case "$request_line" in
  *'"method":"decrypt"'*) printf '{"result":"cGxhaW50ZXh0","error":null}\n' ;;
  *) printf '{"result":null,"error":"unexpected request"}\n' ;;
esac
"#,
        );
        let result =
            bridge_decrypt(&script, "test-app", "key", b"ignored", AccessPolicy::None).unwrap();
        assert_eq!(result, b"plaintext");
        cleanup_script(&script);
    }

    #[cfg(unix)]
    #[test]
    fn bridge_decrypt_rejects_missing_result_payload() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        let script = temp_script(
            "decrypt-missing.sh",
            r#"#!/bin/sh
read init_line
printf '{"result":"","error":null}\n'
read request_line
printf '{"result":null,"error":null}\n'
"#,
        );
        let err =
            bridge_decrypt(&script, "test-app", "key", b"ignored", AccessPolicy::None).unwrap_err();
        assert!(err.to_string().contains("missing result payload"));
        cleanup_script(&script);
    }

    #[cfg(unix)]
    #[test]
    fn bridge_destroy_sends_delete_method_on_wire() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        let script = temp_script(
            "wire-method.sh",
            r#"#!/bin/sh
read request_line
case "$request_line" in
  *'"method":"delete"'*) printf '{"result":"","error":null}\n' ;;
  *'"method":"destroy"'*) printf '{"result":null,"error":"got destroy instead of delete"}\n' ;;
  *) printf '{"result":null,"error":"unexpected method"}\n' ;;
esac
"#,
        );
        bridge_destroy(&script, "test-app", "key").unwrap();
        cleanup_script(&script);
    }

    #[cfg(unix)]
    #[test]
    fn bridge_delete_alias_works() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        let script = temp_script(
            "delete-alias.sh",
            r#"#!/bin/sh
read req
printf '{"result":"","error":null}\n'
"#,
        );
        bridge_delete(&script, "test-app", "key").unwrap();
        cleanup_script(&script);
    }

    #[cfg(unix)]
    #[test]
    fn bridge_session_drop_kills_child() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        let script = temp_script("drop-kill.sh", "#!/bin/sh\nwhile true; do sleep 1; done\n");
        // Spawn a session, grab the child PID, then drop it
        let child_pid: u32;
        {
            let session = BridgeSession::spawn(&script).unwrap();
            child_pid = session.child.id();
            // Session dropped here — Drop should kill + wait the child
        }
        // Give the OS a moment to reap
        std::thread::sleep(Duration::from_millis(100));
        // Verify the process is gone using `kill -0 <pid>` (signal 0 checks existence)
        let status = Command::new("kill")
            .args(["-0", &child_pid.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        assert!(
            status.is_err() || !status.unwrap().success(),
            "bridge child (pid={child_pid}) should no longer exist after Drop"
        );
        cleanup_script(&script);
    }

    #[cfg(unix)]
    #[test]
    fn bridge_init_encodes_access_policy_only() {
        // The legacy `biometric: bool` compat field has been removed.
        // Accept the init when `access_policy` is present and reject
        // if a legacy `biometric` field is observed on the wire — we
        // must not regress to encoding it.
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        let script = temp_script(
            "access-policy-only.sh",
            r#"#!/bin/sh
read request_line
case "$request_line" in
  *'"biometric"'*) printf '{"result":null,"error":"legacy biometric field leaked onto wire"}\n' ;;
  *'"access_policy":"biometric_only"'*) printf '{"result":"","error":null}\n' ;;
  *) printf '{"result":null,"error":"missing access_policy"}\n' ;;
esac
"#,
        );
        bridge_init(&script, "test-app", "key", AccessPolicy::BiometricOnly).unwrap();
        cleanup_script(&script);
    }

    #[cfg(unix)]
    #[test]
    fn bridge_rejects_empty_response() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        let script = temp_script("empty-response.sh", "#!/bin/sh\nread req\n");
        let request = BridgeRequest {
            method: "init".to_string(),
            params: BridgeParams::new(String::new(), AccessPolicy::None, "t".into(), "k".into()),
        };
        let err = call_bridge(&script, &request).unwrap_err();
        assert!(
            err.to_string().contains("no response") || err.to_string().contains("bridge"),
            "expected bridge error, got: {}",
            err
        );
        cleanup_script(&script);
    }

    #[cfg(unix)]
    #[test]
    fn bridge_rejects_invalid_json_response() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        let script = temp_script("invalid-json.sh", "#!/bin/sh\nread req\necho 'not json'\n");
        let request = BridgeRequest {
            method: "init".to_string(),
            params: BridgeParams::new(String::new(), AccessPolicy::None, "t".into(), "k".into()),
        };
        let err = call_bridge(&script, &request).unwrap_err();
        assert!(err.to_string().contains("bridge response"));
        cleanup_script(&script);
    }

    // ----- Signing bridge client tests -----

    #[cfg(unix)]
    #[test]
    fn bridge_init_signing_sends_init_signing_method() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        let script = temp_script(
            "init-signing.sh",
            r#"#!/bin/sh
read request_line
case "$request_line" in
  *'"method":"init_signing"'*'"app_name":"sshenc"'*'"key_label":"default"'*) printf '{"result":"","error":null}\n' ;;
  *) printf '{"result":null,"error":"unexpected request"}\n' ;;
esac
"#,
        );
        bridge_init_signing(&script, "sshenc", "default", AccessPolicy::None).unwrap();
        cleanup_script(&script);
    }

    #[cfg(unix)]
    #[test]
    fn bridge_sign_initializes_before_signing() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        let script = temp_script(
            "sign.sh",
            r#"#!/bin/sh
read init_line
case "$init_line" in
  *'"method":"init_signing"'*) printf '{"result":"","error":null}\n' ;;
  *) printf '{"result":null,"error":"unexpected init request"}\n'; exit 0 ;;
esac
read request_line
case "$request_line" in
  *'"method":"sign"'*) printf '{"result":"c2lnbmF0dXJl","error":null}\n' ;;
  *) printf '{"result":null,"error":"unexpected request"}\n' ;;
esac
"#,
        );
        let signature =
            bridge_sign(&script, "sshenc", "default", b"data", AccessPolicy::None).unwrap();
        assert_eq!(signature, b"signature");
        cleanup_script(&script);
    }

    #[cfg(unix)]
    #[test]
    fn bridge_public_key_is_standalone() {
        // Locks in the new contract (parallel of bridge_list_keys
        // becoming standalone in PR #110): bridge_public_key no
        // longer prefixes the request with init_signing. The
        // previous "initializes before requesting" behaviour was
        // the source of read-only callers (sshenc-se's proxy
        // fetching pubkey bytes for an unknown label, the agent's
        // identity-enumeration during a list-keys cache miss)
        // silently creating a "default" signing key as a side
        // effect of every read. Mock script reads exactly one line
        // and replies with a public_key-shaped result.
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        let script = temp_script(
            "pubkey.sh",
            r#"#!/bin/sh
read request_line
case "$request_line" in
  *'"method":"public_key"'*) printf '{"result":"cHVia2V5","error":null}\n' ;;
  *) printf '{"result":null,"error":"unexpected request"}\n' ;;
esac
"#,
        );
        let pubkey = bridge_public_key(&script, "sshenc", "default", AccessPolicy::None).unwrap();
        assert_eq!(pubkey, b"pubkey");
        cleanup_script(&script);
    }

    #[cfg(unix)]
    #[test]
    fn bridge_list_keys_is_standalone() {
        // Locks in the new contract: bridge_list_keys does NOT prefix
        // the request with init_signing. The previous "initializes
        // before requesting" behavior was the source of the agent's
        // identity-enumeration silently creating a "default" signing
        // key as a side effect of every list. Mock script reads
        // exactly one line and replies with a list_keys-shaped result.
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        let dir = std::env::temp_dir().join("bridge-list-keys-test");
        fs::create_dir_all(&dir).unwrap();
        let resp = dir.join("resp.json");
        fs::write(
            &resp,
            "{\"result\":\"[\\\"key1\\\",\\\"key2\\\"]\",\"error\":null}\n",
        )
        .unwrap();
        let script = temp_script(
            "list-keys.sh",
            &format!("#!/bin/sh\nread request_line\ncat {}\n", resp.display()),
        );
        let keys = bridge_list_keys(&script, "sshenc", "default", AccessPolicy::None).unwrap();
        assert_eq!(keys, vec!["key1".to_string(), "key2".to_string()]);
        drop(fs::remove_dir_all(&dir));
        cleanup_script(&script);
    }

    #[cfg(unix)]
    #[test]
    fn bridge_delete_signing_sends_delete_signing_method() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        let script = temp_script(
            "delete-signing.sh",
            r#"#!/bin/sh
read request_line
case "$request_line" in
  *'"method":"delete_signing"'*'"key_label":"default"'*) printf '{"result":"","error":null}\n' ;;
  *) printf '{"result":null,"error":"unexpected request"}\n' ;;
esac
"#,
        );
        bridge_delete_signing(&script, "sshenc", "default").unwrap();
        cleanup_script(&script);
    }

    #[cfg(unix)]
    #[test]
    fn bridge_signing_key_exists_returns_true() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        let script = temp_script(
            "exists-true.sh",
            r#"#!/bin/sh
read request_line
case "$request_line" in
  *'"method":"signing_key_exists"'*'"key_label":"mine"'*) printf '{"result":"true","error":null}\n' ;;
  *) printf '{"result":null,"error":"unexpected request"}\n' ;;
esac
"#,
        );
        let exists = bridge_signing_key_exists(&script, "sshenc", "mine").unwrap();
        assert!(exists);
        cleanup_script(&script);
    }

    #[cfg(unix)]
    #[test]
    fn bridge_signing_key_exists_returns_false() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        let script = temp_script(
            "exists-false.sh",
            r#"#!/bin/sh
read request_line
case "$request_line" in
  *'"method":"signing_key_exists"'*) printf '{"result":"false","error":null}\n' ;;
  *) printf '{"result":null,"error":"unexpected request"}\n' ;;
esac
"#,
        );
        let exists = bridge_signing_key_exists(&script, "sshenc", "missing").unwrap();
        assert!(!exists);
        cleanup_script(&script);
    }

    #[cfg(unix)]
    #[test]
    fn bridge_signing_key_exists_does_not_call_init_signing() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        // Bridge that records every request into a sentinel file and
        // rejects any init_signing request.
        let sentinel = std::env::temp_dir().join(format!(
            "enclaveapp-bridge-exists-nolog-{}-{}",
            std::process::id(),
            SCRIPT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        drop(fs::remove_file(&sentinel));
        let script = temp_script(
            "exists-no-init.sh",
            &format!(
                r#"#!/bin/sh
read request_line
echo "$request_line" >> "{sentinel}"
case "$request_line" in
  *'"method":"init_signing"'*) printf '{{"result":null,"error":"should not init"}}\n'; exit 0 ;;
  *'"method":"signing_key_exists"'*) printf '{{"result":"false","error":null}}\n' ;;
  *) printf '{{"result":null,"error":"unexpected method"}}\n' ;;
esac
"#,
                sentinel = sentinel.display()
            ),
        );
        let exists = bridge_signing_key_exists(&script, "sshenc", "probe").unwrap();
        assert!(!exists);
        let log = fs::read_to_string(&sentinel).unwrap_or_default();
        assert!(
            !log.contains("init_signing"),
            "exists-check must not invoke init_signing, log was: {log}"
        );
        cleanup_script(&script);
        drop(fs::remove_file(&sentinel));
    }

    #[cfg(unix)]
    #[test]
    fn bridge_read_times_out_on_silent_bridge() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        // Bridge that accepts a request but never responds.
        let script = temp_script("silent-bridge.sh", "#!/bin/sh\nread req\nsleep 120\n");
        // Force a very short timeout for this test.
        std::env::set_var("ENCLAVEAPP_BRIDGE_TIMEOUT_SECS", "1");
        let start = std::time::Instant::now();
        let request = BridgeRequest {
            method: "init".to_string(),
            params: BridgeParams::new(String::new(), AccessPolicy::None, "t".into(), "k".into()),
        };
        let err = call_bridge(&script, &request).unwrap_err();
        std::env::remove_var("ENCLAVEAPP_BRIDGE_TIMEOUT_SECS");
        // Should fail well before the bridge's 120s sleep finishes.
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "timeout should fire quickly, took {:?}",
            start.elapsed()
        );
        let msg = err.to_string();
        assert!(
            msg.contains("did not respond") || msg.contains("timeout"),
            "expected timeout error, got: {msg}"
        );
        cleanup_script(&script);
    }
}
