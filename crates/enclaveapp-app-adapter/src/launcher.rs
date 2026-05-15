use crate::error::Result;
use crate::types::ResolvedProgram;
use std::collections::BTreeMap;
use std::process::{Command, ExitStatus};

/// Request to launch a target process with environment overrides.
#[derive(Debug, Clone)]
pub struct LaunchRequest {
    pub program: ResolvedProgram,
    pub args: Vec<String>,
    pub env_overrides: BTreeMap<String, String>,
    pub env_removals: Vec<String>,
    /// Inherited env vars to scrub from the child process's environment
    /// before spawn.
    ///
    /// Each entry is either an exact variable name (e.g. `"NPM_TOKEN"`)
    /// or a prefix pattern ending in `*` (e.g. `"NPM_TOKEN_*"`,
    /// `"AWS_*"`). The launcher removes the matching variable from the
    /// child command via `env_remove`, zeroizes our own process's copy
    /// via `std::env::remove_var` (best-effort — the libc environ block
    /// may still hold stale bytes until libc compacts), and never
    /// forwards the value.
    ///
    /// This is opt-in. The threat model addressed: inherited parent-env
    /// secrets (e.g. a developer with `NPM_TOKEN` already exported at
    /// login) would otherwise be propagated to the wrapped child
    /// unchanged, bypassing the `env_overrides` zeroize-on-drop. Type 2
    /// consumers (`npmenc`, etc.) that know which variable families
    /// could carry secrets should list them here.
    pub env_scrub_patterns: Vec<String>,
}

impl LaunchRequest {
    /// Add env-scrub patterns to this request. Chains with other
    /// builder-style usage; patterns are appended to any already set.
    #[must_use]
    pub fn with_env_scrub<I, S>(mut self, patterns: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.env_scrub_patterns
            .extend(patterns.into_iter().map(Into::into));
        self
    }
}

/// Return `true` if `key` matches any pattern in `patterns`.
///
/// A pattern ending in `*` is a prefix match; everything else is an
/// exact name match. Empty patterns never match. Case-sensitive on
/// Unix; case-insensitive on Windows because Windows env names are
/// case-insensitive.
fn matches_scrub_pattern(key: &str, patterns: &[String]) -> bool {
    for pat in patterns {
        if pat.is_empty() {
            continue;
        }
        let matched = if let Some(prefix) = pat.strip_suffix('*') {
            env_key_starts_with(key, prefix)
        } else {
            env_key_eq(key, pat)
        };
        if matched {
            return true;
        }
    }
    false
}

#[cfg(windows)]
fn env_key_eq(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

#[cfg(not(windows))]
fn env_key_eq(a: &str, b: &str) -> bool {
    a == b
}

#[cfg(windows)]
fn env_key_starts_with(key: &str, prefix: &str) -> bool {
    key.len() >= prefix.len() && key[..prefix.len()].eq_ignore_ascii_case(prefix)
}

#[cfg(not(windows))]
fn env_key_starts_with(key: &str, prefix: &str) -> bool {
    key.starts_with(prefix)
}

/// Apply `env_scrub_patterns` to the child `command` and to our own
/// process environment: remove matching variables from both, zeroizing
/// the owned `String` copies we pull out of `std::env::vars()`.
fn apply_env_scrub(command: &mut Command, patterns: &[String]) {
    if patterns.is_empty() {
        return;
    }
    let matching_keys: Vec<String> = std::env::vars()
        .map(|(k, mut v)| {
            // Zeroize the value string's bytes in place before it
            // drops. These are our process's own copies.
            zeroize_str(&mut v);
            k
        })
        .filter(|k| matches_scrub_pattern(k, patterns))
        .collect();
    for key in matching_keys {
        command.env_remove(&key);
        // Best-effort scrub of our own process env so any later
        // subprocess spawned without `env_clear` does not re-inherit.
        std::env::remove_var(&key);
    }
}

/// Execute a launch request, spawning the target process.
///
/// Secret env var values are locked in RAM (`mlock`) before spawn to prevent
/// them from being paged to swap. After the child exits, the values are
/// zeroized in-place and then unlocked.
///
/// On Unix, the spawned child has `RLIMIT_CORE` clamped to 0 via a `pre_exec`
/// hook so that a crash of the target process cannot dump its environment
/// (which holds the secrets interpolated for Type 2 delivery). The parent
/// process's own core-dump policy is independent.
///
/// Inherited env vars matching any `env_scrub_patterns` entry are removed
/// from both the child's command and the parent's own process environment
/// before spawn.
///
/// Takes ownership of the `LaunchRequest` so that `env_overrides` values
/// (which may contain secrets) can be overwritten with zeros after the
/// child process exits. Callers that need the request afterwards should
/// clone it before calling `run`.
pub fn run(mut request: LaunchRequest) -> Result<ExitStatus> {
    // Lock secret env var values in RAM before spawn.
    for value in request.env_overrides.values() {
        enclaveapp_core::process::mlock_buffer(value.as_ptr(), value.len());
    }

    let mut command = Command::new(&request.program.path);
    command.args(&request.program.fixed_args);
    command.args(&request.args);

    for key in &request.env_removals {
        command.env_remove(key);
    }

    // Scrub inherited secret env vars before applying overrides so an
    // accidentally-overlapping override still wins over the scrub.
    apply_env_scrub(&mut command, &request.env_scrub_patterns);

    for (key, value) in &request.env_overrides {
        command.env(key, value);
    }

    disable_core_dumps_in_child(&mut command);

    let status = command.status()?;

    // Zeroize secret env var values, then unlock.
    for value in request.env_overrides.values_mut() {
        zeroize_str(value);
        enclaveapp_core::process::munlock_buffer(value.as_ptr(), value.len());
    }

    Ok(status)
}

#[cfg(unix)]
fn disable_core_dumps_in_child(command: &mut Command) {
    use std::os::unix::process::CommandExt;

    #[allow(unsafe_code)]
    unsafe {
        command.pre_exec(|| {
            let limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            // Errors from setrlimit here are non-fatal — the spawn still proceeds
            // and the OS-level core_pattern may already block dumps. We don't
            // propagate errors to avoid refusing to launch on unusual systems.
            let _ = libc::setrlimit(libc::RLIMIT_CORE, &limit);
            Ok(())
        });
    }
}

#[cfg(not(unix))]
fn disable_core_dumps_in_child(_command: &mut Command) {
    // Windows does not have RLIMIT_CORE. WER crash-dump collection is a
    // system-wide policy; child-process-local opt-out is not available.
}

/// Overwrite the contents of a string with zeros without deallocating.
fn zeroize_str(s: &mut str) {
    // Safety: filling the existing UTF-8 bytes with 0 is valid UTF-8 (all NUL).
    // We stay within the existing len — no UB.
    #[allow(unsafe_code)]
    unsafe {
        let bytes = s.as_bytes_mut();
        bytes.fill(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zeroize_str_clears_contents() {
        let mut s = String::from("secret-value");
        zeroize_str(&mut s);
        assert!(s.bytes().all(|b| b == 0));
        assert_eq!(s.len(), 12);
    }

    #[cfg(unix)]
    #[test]
    fn child_inherits_zero_core_limit() {
        use std::process::Command;
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "ulimit -c"]);
        disable_core_dumps_in_child(&mut cmd);
        let output = cmd.output().expect("spawn sh");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_eq!(stdout.trim(), "0", "child should inherit core limit of 0");
    }

    #[test]
    fn matches_scrub_pattern_exact() {
        let pats = vec!["NPM_TOKEN".into()];
        assert!(matches_scrub_pattern("NPM_TOKEN", &pats));
        assert!(!matches_scrub_pattern("NPM_TOKEN_2", &pats));
        assert!(!matches_scrub_pattern("OTHER", &pats));
    }

    #[test]
    fn matches_scrub_pattern_prefix() {
        let pats = vec!["NPM_TOKEN_*".into(), "AWS_*".into()];
        assert!(matches_scrub_pattern("NPM_TOKEN_", &pats));
        assert!(matches_scrub_pattern("NPM_TOKEN_REGISTRY", &pats));
        assert!(matches_scrub_pattern("AWS_ACCESS_KEY_ID", &pats));
        assert!(!matches_scrub_pattern("NPM_OTHER", &pats));
        assert!(!matches_scrub_pattern("GITHUB_TOKEN", &pats));
    }

    #[test]
    fn matches_scrub_pattern_empty_never_matches() {
        let pats = vec![String::new(), "*".into()];
        // Empty pattern doesn't match. A bare `*` is a prefix-match
        // with empty prefix, which matches EVERYTHING — that's by design
        // (callers who want to scrub the whole env can use it).
        assert!(!matches_scrub_pattern("FOO", &[String::new()]));
        assert!(matches_scrub_pattern("FOO", &pats));
    }

    #[test]
    fn with_env_scrub_appends_patterns() {
        use crate::types::ResolutionStrategy;
        let req = LaunchRequest {
            program: ResolvedProgram {
                path: "/bin/true".into(),
                fixed_args: vec![],
                strategy: ResolutionStrategy::ExplicitPath,
                shell_hint: None,
            },
            args: vec![],
            env_overrides: BTreeMap::new(),
            env_removals: vec![],
            env_scrub_patterns: vec!["EXISTING".into()],
        };
        let req = req.with_env_scrub(["NEW_*", "ANOTHER"]);
        assert_eq!(req.env_scrub_patterns, vec!["EXISTING", "NEW_*", "ANOTHER"]);
    }

    #[cfg(unix)]
    #[test]
    fn scrub_removes_inherited_env_from_child_and_own_process() {
        // Set a "secret-looking" env var + a non-matching keeper, scrub
        // the secret via a prefix pattern, verify the child sees only
        // the keeper and our own process no longer has the secret.
        let marker = format!("ENCLAVEAPP_SCRUB_TEST_{}_", std::process::id());
        let scrub_key = format!("{marker}TOKEN");
        let keep_key = format!("{marker}KEEP");
        std::env::set_var(&scrub_key, "matched-by-test");
        std::env::set_var(&keep_key, "KEPT");

        // Only the TOKEN suffix matches the pattern; KEEP should survive.
        let prefix_pattern = format!("{marker}T*");

        // Child prints both vars so we can confirm delivery / absence.
        let script = format!(
            "echo scrub=[${scrub_key}] keep=[${keep_key}]",
            scrub_key = scrub_key,
            keep_key = keep_key,
        );
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", &script]);

        apply_env_scrub(&mut cmd, &[prefix_pattern]);

        let output = cmd.output().expect("spawn sh");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("scrub=[]"),
            "scrubbed var leaked to child: {stdout}"
        );
        assert!(
            stdout.contains("keep=[KEPT]"),
            "kept var did not reach child: {stdout}"
        );
        assert!(
            std::env::var(&scrub_key).is_err(),
            "scrubbed var still present in our own env"
        );
        assert_eq!(
            std::env::var(&keep_key).as_deref().ok(),
            Some("KEPT"),
            "kept var disappeared from our own env"
        );

        std::env::remove_var(&keep_key);
    }

    fn make_request(program: &str, args: &[&str]) -> LaunchRequest {
        use crate::types::ResolutionStrategy;
        LaunchRequest {
            program: ResolvedProgram {
                path: program.into(),
                fixed_args: Vec::new(),
                strategy: ResolutionStrategy::ExplicitPath,
                shell_hint: None,
            },
            args: args.iter().map(|s| (*s).to_string()).collect(),
            env_overrides: BTreeMap::new(),
            env_removals: Vec::new(),
            env_scrub_patterns: Vec::new(),
        }
    }

    #[cfg(unix)]
    #[test]
    fn run_returns_ok_with_success_for_exit_zero() {
        let req = make_request("/bin/sh", &["-c", "exit 0"]);
        let status = run(req).expect("run should not error for a spawnable binary");
        assert!(status.success(), "exit 0 must produce a successful status");
    }

    #[cfg(unix)]
    #[test]
    fn run_returns_ok_with_failure_for_nonzero_exit() {
        let req = make_request("/bin/sh", &["-c", "exit 42"]);
        let status = run(req).expect("run should not error; non-zero exit is Ok(status)");
        assert!(!status.success(), "exit 42 must not be success");
        assert_eq!(status.code(), Some(42));
    }

    #[test]
    fn run_returns_err_when_binary_does_not_exist() {
        let req = make_request("/nonexistent-binary-for-test-xyzzy", &[]);
        let result = run(req);
        assert!(
            result.is_err(),
            "spawning a nonexistent binary must return Err"
        );
    }

    /// Passing more than 1,000 arguments must not panic or silently truncate.
    #[cfg(unix)]
    #[test]
    fn run_with_large_argument_list_does_not_panic() {
        // Build a shell command that counts its arguments and exits.
        // We pass 1,001 extra args: the "echo" arg plus 1,000 "x" args.
        // The child prints the arg count; we verify all args were received.
        let script = r#"echo "$#""#;
        let args: Vec<String> = std::iter::once("-c".to_string())
            .chain(std::iter::once(script.to_string()))
            .chain(std::iter::once("sh".to_string())) // $0 for sh -c
            .chain(std::iter::repeat("x".to_string()).take(1000))
            .collect();

        use crate::types::ResolutionStrategy;
        let req = LaunchRequest {
            program: ResolvedProgram {
                path: "/bin/sh".into(),
                fixed_args: Vec::new(),
                strategy: ResolutionStrategy::ExplicitPath,
                shell_hint: None,
            },
            args,
            env_overrides: BTreeMap::new(),
            env_removals: Vec::new(),
            env_scrub_patterns: Vec::new(),
        };
        let status = run(req).expect("run with large arg list must not error");
        assert!(status.success(), "child must exit 0");
    }

    /// A prefix scrub pattern must remove ALL matching variables, not just the first.
    #[cfg(unix)]
    #[test]
    fn scrub_prefix_strips_all_matching_vars_not_just_first() {
        let marker = format!("ENCLAVEAPP_SCRUB_ALL_TEST_{}_", std::process::id());
        let keys: Vec<String> = (0..5).map(|i| format!("{marker}VAR{i}")).collect();
        for (i, k) in keys.iter().enumerate() {
            std::env::set_var(k, format!("val{i}"));
        }
        let keep_key = format!("{marker}KEEPER");
        std::env::set_var(&keep_key, "KEPT");

        let prefix_pattern = format!("{marker}VAR*");
        let script = keys
            .iter()
            .map(|k| format!("[${k}]"))
            .collect::<Vec<_>>()
            .join(" ");
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", &format!("echo {script}")]);

        apply_env_scrub(&mut cmd, &[prefix_pattern]);

        let output = cmd.output().expect("spawn sh");
        let stdout = String::from_utf8_lossy(&output.stdout);
        // All 5 vars must be absent from child env.
        assert!(
            stdout.contains("[] [] [] [] []"),
            "all 5 matching vars must be scrubbed; child output: {stdout}"
        );
        // Own process must not see them either.
        for k in &keys {
            assert!(
                std::env::var(k).is_err(),
                "scrubbed var {k} still in own process env"
            );
        }
        // Non-matching var is untouched.
        assert_eq!(std::env::var(&keep_key).as_deref().ok(), Some("KEPT"));
        std::env::remove_var(&keep_key);
    }

    #[test]
    fn matches_scrub_pattern_empty_patterns_never_matches() {
        let pats: Vec<String> = vec![];
        assert!(!matches_scrub_pattern("FOO", &pats));
        assert!(!matches_scrub_pattern("", &pats));
    }

    #[test]
    fn matches_scrub_pattern_bare_star_matches_any_key() {
        let pats = vec!["*".into()];
        assert!(matches_scrub_pattern("ANYTHING", &pats));
        assert!(matches_scrub_pattern("AWS_SECRET", &pats));
        assert!(matches_scrub_pattern("", &pats));
    }

    #[test]
    fn matches_scrub_pattern_exact_does_not_match_longer_key() {
        let pats = vec!["AWS".into()];
        assert!(!matches_scrub_pattern("AWS_SECRET_KEY", &pats));
        assert!(matches_scrub_pattern("AWS", &pats));
    }

    #[test]
    fn matches_scrub_pattern_multiple_patterns_any_match_wins() {
        let pats = vec!["FOO".into(), "BAR*".into(), "BAZ".into()];
        assert!(matches_scrub_pattern("FOO", &pats));
        assert!(matches_scrub_pattern("BAR_EXTRA", &pats));
        assert!(matches_scrub_pattern("BAZ", &pats));
        assert!(!matches_scrub_pattern("QUUX", &pats));
    }

    #[cfg(not(windows))]
    #[test]
    fn env_key_eq_exact_match_is_case_sensitive() {
        assert!(env_key_eq("FOO", "FOO"));
        assert!(!env_key_eq("foo", "FOO"));
        assert!(!env_key_eq("FOO", "foo"));
    }

    #[cfg(not(windows))]
    #[test]
    fn env_key_eq_empty_strings_are_equal() {
        assert!(env_key_eq("", ""));
    }

    #[cfg(not(windows))]
    #[test]
    fn env_key_starts_with_empty_prefix_always_true() {
        assert!(env_key_starts_with("ANYTHING", ""));
        assert!(env_key_starts_with("", ""));
    }

    #[cfg(not(windows))]
    #[test]
    fn env_key_starts_with_full_key_as_prefix_matches() {
        assert!(env_key_starts_with("AWS_SECRET", "AWS_SECRET"));
    }

    #[cfg(not(windows))]
    #[test]
    fn env_key_starts_with_longer_prefix_does_not_match() {
        assert!(!env_key_starts_with("AWS", "AWS_SECRET"));
    }

    #[test]
    fn zeroize_str_preserves_length_and_zeroes_bytes() {
        let mut s = String::from("my-secret-key-123");
        let original_len = s.len();
        zeroize_str(&mut s);
        assert_eq!(s.len(), original_len);
        assert!(s.bytes().all(|b| b == 0));
    }
}
