// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Generic credential caching with lifecycle management for Type 4 (CredentialSource) apps.
//!
//! Provides the common infrastructure for any enclave app that obtains credentials
//! from an external source, encrypts and caches them locally, and hands them to
//! any consumer that asks.
//!
//! **Security boundary:** A Type 4 app secures the *acquisition and storage* of
//! credentials (hardware-encrypted cache, automatic expiration, risk-level-based
//! lifecycle). It provides **no guardrails on delivery** — once a credential is
//! handed out via `get`, the consumer can export it to an environment variable,
//! pipe it to a file, or use it through a Type 1/2/3 enclave app. Types 1-3
//! control the entire delivery lifecycle; Type 4 does not.
//!
//! # Lifecycle
//!
//! Cached credentials pass through a state machine based on age:
//!
//! ```text
//! Fresh → RefreshWindow → Grace → Expired
//!   │         │              │        │
//!   │    try refresh    serve stale   must re-acquire
//!   └── serve from cache
//! ```
//!
//! The transition times are controlled by a [`LifecyclePolicy`] which maps
//! a risk level (u8) to duration thresholds.
//!
//! # Usage
//!
//! ```rust,ignore
//! use enclaveapp_app_adapter::credential_cache::*;
//!
//! // Define your policy
//! struct MyPolicy;
//! impl LifecyclePolicy for MyPolicy {
//!     fn max_age_secs(&self, risk_level: u8) -> u64 { ... }
//!     fn refresh_window_secs(&self, risk_level: u8) -> u64 { ... }
//!     fn grace_period_secs(&self, risk_level: u8) -> u64 { ... }
//! }
//!
//! // Classify cached credential state without decrypting
//! let state = classify_credential(issued_at, session_start, now, &MyPolicy, risk_level);
//! match state {
//!     CredentialState::Fresh => { /* serve from cache */ }
//!     CredentialState::RefreshWindow => { /* try background refresh, serve stale */ }
//!     CredentialState::Grace => { /* serve stale, warn */ }
//!     CredentialState::Expired => { /* must re-acquire */ }
//! }
//! ```

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Lifecycle state of a cached credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialState {
    /// Credential is within its primary validity period. Serve directly.
    Fresh,
    /// Credential is aging — a background refresh should be attempted, but the
    /// cached value can still be served if refresh fails.
    RefreshWindow,
    /// Credential is past the refresh window but within the grace period.
    /// Serve the stale value as a last resort while re-acquisition is attempted.
    Grace,
    /// Credential has fully expired. Must re-acquire from the external source.
    Expired,
}

/// Policy that controls credential lifecycle transitions.
///
/// Implementations map a risk level (0-255) to duration thresholds. Higher risk
/// levels should use shorter durations.
///
/// Example policy for JWT tokens:
/// - Risk 1 (low): 24h max, 6h refresh window, 1h grace
/// - Risk 2 (medium): 12h max, 3h refresh window, 30m grace
/// - Risk 3 (high): 1h max, 15m refresh window, 5m grace
pub trait LifecyclePolicy: Send + Sync {
    /// Maximum age in seconds before the credential enters the refresh window.
    fn max_age_secs(&self, risk_level: u8) -> u64;

    /// Duration of the refresh window in seconds. During this period, the cached
    /// credential is served while a background refresh is attempted.
    fn refresh_window_secs(&self, risk_level: u8) -> u64;

    /// Grace period in seconds after the refresh window. The stale credential
    /// can be served as a last resort.
    fn grace_period_secs(&self, risk_level: u8) -> u64;

    /// Total session timeout — if the session itself (not just the credential)
    /// has been active longer than this, force re-acquisition regardless of
    /// credential age. Returns `None` to disable session timeout.
    fn session_timeout_secs(&self, _risk_level: u8) -> Option<u64> {
        None
    }
}

/// Classify a cached credential's lifecycle state.
///
/// This can be called using only the unencrypted cache header metadata — no
/// decryption is needed. This avoids unnecessary hardware-backed decrypt
/// operations when the credential is expired.
///
/// # Arguments
///
/// - `issued_at` — Unix timestamp when the credential was obtained
/// - `session_start` — Unix timestamp when the session began (for session timeout)
/// - `now` — Current Unix timestamp
/// - `policy` — Lifecycle policy that defines transition durations
/// - `risk_level` — Risk level for this credential (policy-dependent)
pub fn classify_credential(
    issued_at: u64,
    session_start: u64,
    now: u64,
    policy: &dyn LifecyclePolicy,
    risk_level: u8,
) -> CredentialState {
    // Check session timeout first (if configured)
    if let Some(session_max) = policy.session_timeout_secs(risk_level) {
        if now.saturating_sub(session_start) >= session_max {
            return CredentialState::Expired;
        }
    }

    let age = now.saturating_sub(issued_at);
    let max_age = policy.max_age_secs(risk_level);
    let refresh = policy.refresh_window_secs(risk_level);
    let grace = policy.grace_period_secs(risk_level);

    if age < max_age {
        CredentialState::Fresh
    } else if age < max_age + refresh {
        CredentialState::RefreshWindow
    } else if age < max_age + refresh + grace {
        CredentialState::Grace
    } else {
        CredentialState::Expired
    }
}

/// Get the current time as Unix seconds.
pub fn now_secs() -> u64 {
    system_time_secs(SystemTime::now())
}

/// Convert a `SystemTime` to Unix seconds.
pub fn system_time_secs(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Encode a string for safe use as a filename component.
///
/// Replaces characters that are problematic in filenames with `~XX` hex encoding.
/// This is used for cache file paths derived from server names, environments, etc.
pub fn encode_cache_component(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' => output.push(c),
            _ => {
                for byte in c.to_string().as_bytes() {
                    output.push('~');
                    output.push_str(&format!("{byte:02X}"));
                }
            }
        }
    }
    output
}

/// Build a cache file path from components.
///
/// Creates a path like `{cache_dir}/{encoded_component1}-{encoded_component2}.cache`
/// where each component is safely encoded for filesystem use.
pub fn cache_file_path(cache_dir: &Path, components: &[&str], extension: &str) -> PathBuf {
    let encoded: Vec<String> = components
        .iter()
        .map(|c| encode_cache_component(c))
        .collect();
    let filename = format!("{}.{}", encoded.join("-"), extension);
    cache_dir.join(filename)
}

/// Validate that a URL uses HTTPS.
///
/// Credential source endpoints must use HTTPS to prevent credential interception.
/// Returns an error with the field name for user-facing diagnostics.
#[allow(unused_qualifications)]
pub fn validate_https_url(url: &str, field_name: &str) -> std::result::Result<(), String> {
    if url.starts_with("https://") {
        Ok(())
    } else if url.starts_with("http://") {
        Err(format!(
            "{field_name} must use HTTPS (got {url}); cleartext HTTP is not allowed for credential endpoints"
        ))
    } else {
        Err(format!("{field_name} must be an HTTPS URL (got {url})"))
    }
}

/// Clear all cache files matching a set of paths.
///
/// Best-effort: logs warnings for individual file deletion failures but does
/// not fail the overall operation.
pub fn clear_cache_files(paths: &[PathBuf]) {
    for path in paths {
        if path.exists() {
            if let Err(e) = std::fs::remove_file(path) {
                tracing::warn!("failed to remove cache file {}: {e}", path.display());
            }
        }
    }
}

/// Run a command with a credential injected as an environment variable.
///
/// This is the standard "exec" pattern for Type 4 credential sources:
/// obtain the credential, then launch the target command with the credential
/// available in the specified env var.
pub fn exec_with_credential(
    env_var: &str,
    credential: &str,
    command: &[String],
) -> std::io::Result<std::process::ExitStatus> {
    if command.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "no command specified",
        ));
    }

    let mut cmd = std::process::Command::new(&command[0]);
    if command.len() > 1 {
        cmd.args(&command[1..]);
    }
    cmd.env(env_var, credential);
    cmd.status()
}

/// Like [`exec_with_credential`], but takes ownership of the credential
/// string and zeroizes it in memory after the child process exits.
///
/// Prefer this over `exec_with_credential` when the caller does not need
/// the credential value after launching the command.
pub fn exec_with_credential_owned(
    env_var: &str,
    mut credential: String,
    command: &[String],
) -> std::io::Result<std::process::ExitStatus> {
    let status = exec_with_credential(env_var, &credential, command)?;
    zeroize::Zeroize::zeroize(&mut credential);
    Ok(status)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    /// Simple test policy with fixed durations.
    struct TestPolicy {
        max_age: u64,
        refresh: u64,
        grace: u64,
        session_timeout: Option<u64>,
    }

    impl TestPolicy {
        fn new(max_age: u64, refresh: u64, grace: u64) -> Self {
            Self {
                max_age,
                refresh,
                grace,
                session_timeout: None,
            }
        }

        fn with_session_timeout(mut self, timeout: u64) -> Self {
            self.session_timeout = Some(timeout);
            self
        }
    }

    impl LifecyclePolicy for TestPolicy {
        fn max_age_secs(&self, _risk_level: u8) -> u64 {
            self.max_age
        }
        fn refresh_window_secs(&self, _risk_level: u8) -> u64 {
            self.refresh
        }
        fn grace_period_secs(&self, _risk_level: u8) -> u64 {
            self.grace
        }
        fn session_timeout_secs(&self, _risk_level: u8) -> Option<u64> {
            self.session_timeout
        }
    }

    #[test]
    fn fresh_within_max_age() {
        let policy = TestPolicy::new(3600, 600, 300);
        let now = 10_000;
        let issued = now - 1800; // 30 min ago
        assert_eq!(
            classify_credential(issued, issued, now, &policy, 1),
            CredentialState::Fresh
        );
    }

    #[test]
    fn refresh_window_after_max_age() {
        let policy = TestPolicy::new(3600, 600, 300);
        let now = 10_000;
        let issued = now - 3900; // 65 min ago (past 60 min max, within 10 min refresh)
        assert_eq!(
            classify_credential(issued, issued, now, &policy, 1),
            CredentialState::RefreshWindow
        );
    }

    #[test]
    fn grace_after_refresh_window() {
        let policy = TestPolicy::new(3600, 600, 300);
        let now = 10_000;
        let issued = now - 4300; // past max + refresh, within grace
        assert_eq!(
            classify_credential(issued, issued, now, &policy, 1),
            CredentialState::Grace
        );
    }

    #[test]
    fn expired_after_grace() {
        let policy = TestPolicy::new(3600, 600, 300);
        let now = 10_000;
        let issued = now - 5000; // past everything
        assert_eq!(
            classify_credential(issued, issued, now, &policy, 1),
            CredentialState::Expired
        );
    }

    #[test]
    fn session_timeout_overrides_fresh() {
        let policy = TestPolicy::new(3600, 600, 300).with_session_timeout(7200);
        let now = 10_000;
        let session_start = now - 8000; // session started 8000s ago (> 7200 timeout)
        let issued = now - 100; // credential itself is fresh
        assert_eq!(
            classify_credential(issued, session_start, now, &policy, 1),
            CredentialState::Expired
        );
    }

    #[test]
    fn no_session_timeout_by_default() {
        let policy = TestPolicy::new(3600, 600, 300);
        let now = 10_000;
        let session_start = 0; // session started at epoch (very old)
        let issued = now - 100; // credential is fresh
        assert_eq!(
            classify_credential(issued, session_start, now, &policy, 1),
            CredentialState::Fresh
        );
    }

    #[test]
    fn boundary_exactly_at_max_age() {
        let policy = TestPolicy::new(3600, 600, 300);
        let now = 10_000;
        let issued = now - 3600; // exactly at max age
        assert_eq!(
            classify_credential(issued, issued, now, &policy, 1),
            CredentialState::RefreshWindow
        );
    }

    #[test]
    fn zero_age_is_fresh() {
        let policy = TestPolicy::new(3600, 600, 300);
        let now = 10_000;
        assert_eq!(
            classify_credential(now, now, now, &policy, 1),
            CredentialState::Fresh
        );
    }

    #[test]
    fn encode_cache_component_simple() {
        assert_eq!(encode_cache_component("my-server"), "my-server");
        assert_eq!(
            encode_cache_component("prod.example.com"),
            "prod.example.com"
        );
    }

    #[test]
    fn encode_cache_component_special_chars() {
        assert_eq!(encode_cache_component("foo/bar"), "foo~2Fbar");
        assert_eq!(encode_cache_component("a:b"), "a~3Ab");
        assert_eq!(encode_cache_component("hello world"), "hello~20world");
    }

    #[test]
    fn encode_cache_component_empty() {
        assert_eq!(encode_cache_component(""), "");
    }

    #[test]
    fn cache_file_path_single_component() {
        let dir = Path::new("/tmp/cache");
        let path = cache_file_path(dir, &["myserver"], "bin");
        assert_eq!(path, PathBuf::from("/tmp/cache/myserver.bin"));
    }

    #[test]
    fn cache_file_path_multiple_components() {
        let dir = Path::new("/tmp/cache");
        let path = cache_file_path(dir, &["server", "prod", "default"], "bin");
        assert_eq!(path, PathBuf::from("/tmp/cache/server-prod-default.bin"));
    }

    #[test]
    fn cache_file_path_encodes_special_chars() {
        let dir = Path::new("/tmp/cache");
        let path = cache_file_path(dir, &["my/server", "env:prod"], "cache");
        assert_eq!(
            path,
            PathBuf::from("/tmp/cache/my~2Fserver-env~3Aprod.cache")
        );
    }

    #[test]
    fn validate_https_url_accepts_https() {
        assert!(validate_https_url("https://example.com/auth", "oauth_url").is_ok());
    }

    #[test]
    fn validate_https_url_rejects_http() {
        let err = validate_https_url("http://example.com/auth", "oauth_url").unwrap_err();
        assert!(err.contains("HTTPS"));
        assert!(err.contains("oauth_url"));
    }

    #[test]
    fn validate_https_url_rejects_other() {
        let err = validate_https_url("ftp://example.com", "token_url").unwrap_err();
        assert!(err.contains("HTTPS"));
    }

    #[test]
    fn exec_with_credential_rejects_empty_command() {
        let result = exec_with_credential("TOKEN", "secret", &[]);
        assert!(result.is_err());
    }

    #[test]
    fn now_secs_returns_nonzero() {
        assert!(now_secs() > 1_000_000_000); // after 2001
    }

    #[test]
    fn classify_issued_in_future_is_fresh() {
        // issued_at > now: saturating_sub gives age 0 → Fresh
        let policy = TestPolicy::new(3600, 600, 300);
        let now = 10_000;
        let issued = now + 100; // clock skew: issued in the future
        assert_eq!(
            classify_credential(issued, issued, now, &policy, 1),
            CredentialState::Fresh
        );
    }

    #[test]
    fn classify_exactly_one_before_refresh_window() {
        let policy = TestPolicy::new(3600, 600, 300);
        let now = 10_000;
        let issued = now - 3599; // age 3599 < max_age 3600 → still Fresh
        assert_eq!(
            classify_credential(issued, issued, now, &policy, 1),
            CredentialState::Fresh
        );
    }

    #[test]
    fn classify_exactly_at_refresh_window_end() {
        let policy = TestPolicy::new(3600, 600, 300);
        let now = 10_000;
        // age == max_age + refresh → Grace
        let issued = now - (3600 + 600);
        assert_eq!(
            classify_credential(issued, issued, now, &policy, 1),
            CredentialState::Grace
        );
    }

    #[test]
    fn classify_one_before_refresh_window_end() {
        let policy = TestPolicy::new(3600, 600, 300);
        let now = 10_000;
        // age == max_age + refresh - 1 → still RefreshWindow
        let issued = now - (3600 + 600 - 1);
        assert_eq!(
            classify_credential(issued, issued, now, &policy, 1),
            CredentialState::RefreshWindow
        );
    }

    #[test]
    fn classify_exactly_at_grace_end() {
        let policy = TestPolicy::new(3600, 600, 300);
        let now = 10_000;
        // age == max_age + refresh + grace → Expired
        let issued = now - (3600 + 600 + 300);
        assert_eq!(
            classify_credential(issued, issued, now, &policy, 1),
            CredentialState::Expired
        );
    }

    #[test]
    fn classify_one_before_grace_end() {
        let policy = TestPolicy::new(3600, 600, 300);
        let now = 10_000;
        // age == max_age + refresh + grace - 1 → still Grace
        let issued = now - (3600 + 600 + 300 - 1);
        assert_eq!(
            classify_credential(issued, issued, now, &policy, 1),
            CredentialState::Grace
        );
    }

    #[test]
    fn session_timeout_at_exact_boundary_is_expired() {
        // now - session_start == session_max → Expired (>=)
        let policy = TestPolicy::new(3600, 600, 300).with_session_timeout(1000);
        let now = 10_000;
        let session_start = now - 1000;
        let issued = now - 10; // credential itself is fresh
        assert_eq!(
            classify_credential(issued, session_start, now, &policy, 1),
            CredentialState::Expired
        );
    }

    #[test]
    fn session_timeout_one_before_boundary_is_not_expired() {
        let policy = TestPolicy::new(3600, 600, 300).with_session_timeout(1000);
        let now = 10_000;
        let session_start = now - 999; // one second before timeout
        let issued = now - 10;
        assert_eq!(
            classify_credential(issued, session_start, now, &policy, 1),
            CredentialState::Fresh
        );
    }

    #[test]
    fn encode_cache_component_tilde_is_encoded() {
        // Tilde is not in the safe charset, so it must be encoded
        let encoded = encode_cache_component("a~b");
        assert!(!encoded.contains('~') || encoded.contains("~7E") || encoded.starts_with("a~7E"));
        // After encoding, it should decode to the original if we unescape ~XX
        assert!(encoded.contains("7E") || !encoded.contains('~'));
    }

    #[test]
    fn encode_cache_component_unicode_multi_byte() {
        // A multi-byte UTF-8 character (é = U+00E9 = 0xC3 0xA9 in UTF-8)
        let encoded = encode_cache_component("café");
        // The ASCII part is unchanged, the non-ASCII is hex-encoded
        assert!(encoded.starts_with("caf"));
        assert!(!encoded.contains('é'));
        assert!(encoded.contains('~')); // should be percent-style encoded with ~
    }

    #[test]
    fn validate_https_url_empty_string_is_error() {
        let err = validate_https_url("", "endpoint").unwrap_err();
        assert!(err.contains("HTTPS") || err.contains("endpoint"));
    }

    #[test]
    fn validate_https_url_no_scheme() {
        let err = validate_https_url("example.com/api", "url").unwrap_err();
        assert!(err.contains("HTTPS"));
    }

    #[test]
    fn validate_https_url_ftp_scheme_is_error() {
        let err = validate_https_url("ftp://example.com/auth", "ftp_url").unwrap_err();
        assert!(err.contains("HTTPS"));
        assert!(err.contains("ftp_url"));
    }

    #[test]
    fn cache_file_path_empty_components_list() {
        let dir = Path::new("/tmp/cache");
        let path = cache_file_path(dir, &[], "bin");
        // Empty join should produce ".bin"
        assert_eq!(path, PathBuf::from("/tmp/cache/.bin"));
    }

    #[test]
    fn system_time_secs_before_epoch_returns_zero() {
        // SystemTime before UNIX_EPOCH should not panic and returns 0
        let before_epoch = SystemTime::UNIX_EPOCH
            .checked_sub(std::time::Duration::from_secs(1))
            .unwrap();
        assert_eq!(system_time_secs(before_epoch), 0);
    }
}
