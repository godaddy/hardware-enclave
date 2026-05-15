#![cfg_attr(test, allow(clippy::panic, clippy::unwrap_used))]

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::{AdapterError, Result};
use crate::types::{ResolutionStrategy, ResolvedProgram};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveMode {
    Auto,
    PathOnly,
    CommandV,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveOptions {
    pub explicit_path: Option<PathBuf>,
    pub mode: ResolveMode,
    pub shell: Option<PathBuf>,
}

pub fn resolve_program(command_name: &str, options: &ResolveOptions) -> Result<ResolvedProgram> {
    resolve_program_inner(command_name, options, 0)
}

fn resolve_program_inner(
    command_name: &str,
    options: &ResolveOptions,
    depth: usize,
) -> Result<ResolvedProgram> {
    if depth > 8 {
        return Err(AdapterError::UnsupportedShellResolution {
            command: command_name.to_string(),
            raw: "resolution recursion limit exceeded".to_string(),
        });
    }

    if let Some(explicit_path) = options.explicit_path.clone() {
        if is_executable_candidate(&explicit_path) {
            return Ok(ResolvedProgram {
                path: explicit_path,
                fixed_args: Vec::new(),
                strategy: ResolutionStrategy::ExplicitPath,
                shell_hint: None,
            });
        }

        return Err(AdapterError::ProgramNotFound(
            explicit_path.display().to_string(),
        ));
    }

    if matches!(options.mode, ResolveMode::Auto) {
        if let Ok(resolved) = resolve_via_command_v(command_name, options, depth) {
            return Ok(resolved);
        }

        if let Some(path) = find_on_path(command_name) {
            return Ok(ResolvedProgram {
                path,
                fixed_args: Vec::new(),
                strategy: ResolutionStrategy::PathLookup,
                shell_hint: None,
            });
        }
    }

    if matches!(options.mode, ResolveMode::PathOnly) {
        if let Some(path) = find_on_path(command_name) {
            return Ok(ResolvedProgram {
                path,
                fixed_args: Vec::new(),
                strategy: ResolutionStrategy::PathLookup,
                shell_hint: None,
            });
        }
    }

    if matches!(options.mode, ResolveMode::CommandV) {
        return resolve_via_command_v(command_name, options, depth);
    }

    Err(AdapterError::ProgramNotFound(command_name.to_string()))
}

fn resolve_via_command_v(
    command_name: &str,
    options: &ResolveOptions,
    depth: usize,
) -> Result<ResolvedProgram> {
    let shell_path = options
        .shell
        .clone()
        .or_else(|| env::var_os("SHELL").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("/bin/sh"));

    let quoted_command = shell_quote(command_name);
    let output = Command::new(&shell_path)
        .arg("-lc")
        .arg(format!("command -v -- {quoted_command}"))
        .output()?;

    if !output.status.success() {
        return Err(AdapterError::CommandVFailed {
            command: command_name.to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let raw = stdout.lines().next().unwrap_or_default().trim().to_string();

    if raw.is_empty() {
        return Err(AdapterError::ProgramNotFound(command_name.to_string()));
    }

    let candidate = PathBuf::from(&raw);
    if candidate.is_absolute() || raw.contains(std::path::MAIN_SEPARATOR) {
        return Ok(ResolvedProgram {
            path: candidate,
            fixed_args: Vec::new(),
            strategy: ResolutionStrategy::CommandV,
            shell_hint: Some(raw),
        });
    }

    if let Some(chain) = parse_symbolic_resolution(command_name, &shell_path)? {
        let nested_options = ResolveOptions {
            explicit_path: None,
            mode: ResolveMode::Auto,
            shell: Some(shell_path.clone()),
        };
        let resolved_program =
            resolve_program_inner(&chain.program_token, &nested_options, depth + 1)?;
        let mut fixed_args = resolved_program.fixed_args;
        fixed_args.extend(chain.fixed_args);

        return Ok(ResolvedProgram {
            path: resolved_program.path,
            fixed_args,
            strategy: ResolutionStrategy::CommandV,
            shell_hint: Some(chain.raw),
        });
    }

    Err(AdapterError::UnsupportedShellResolution {
        command: command_name.to_string(),
        raw,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SymbolicResolution {
    raw: String,
    program_token: String,
    fixed_args: Vec<String>,
}

fn parse_symbolic_resolution(
    command_name: &str,
    shell_path: &Path,
) -> Result<Option<SymbolicResolution>> {
    let quoted_command = shell_quote(command_name);
    let output = Command::new(shell_path)
        .arg("-lc")
        .arg(format!("command -V -- {quoted_command}"))
        .output()?;

    if !output.status.success() {
        return Ok(None);
    }

    let description = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if description.is_empty() {
        return Ok(None);
    }

    if let Some(command_string) = extract_alias_command(&description) {
        return Ok(parse_command_string(command_string, description));
    }

    if let Some(command_string) = extract_function_command(&description) {
        return Ok(parse_command_string(command_string, description));
    }

    Ok(None)
}

fn parse_command_string(command_string: String, raw: String) -> Option<SymbolicResolution> {
    let sanitized = command_string
        .replace("\"$@\"", "")
        .replace("$@", "")
        .replace("\"$*\"", "")
        .replace("$*", "")
        .replace("${@}", "");
    let tokens = shlex::split(&sanitized).unwrap_or_else(|| {
        sanitized
            .split_whitespace()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
    });
    if tokens.is_empty() {
        return None;
    }

    let mut filtered = tokens
        .into_iter()
        .filter(|token| !matches!(token.as_str(), "$@" | "\"$@\"" | "${@}" | "$*" | "\""))
        .collect::<Vec<_>>();
    normalize_wrapper_tokens(&mut filtered);
    if filtered.is_empty() {
        return None;
    }

    let program_token = filtered.remove(0);
    Some(SymbolicResolution {
        raw,
        program_token,
        fixed_args: filtered,
    })
}

fn normalize_wrapper_tokens(tokens: &mut Vec<String>) {
    loop {
        let Some(first) = tokens.first().map(String::as_str) else {
            return;
        };
        match first {
            "command" | "builtin" | "exec" => {
                drop(tokens.remove(0));
                while tokens.first().is_some_and(|token| token == "--") {
                    drop(tokens.remove(0));
                }
            }
            "env" => {
                drop(tokens.remove(0));
                while tokens.first().is_some_and(|token| token == "--") {
                    drop(tokens.remove(0));
                }
                while tokens
                    .first()
                    .is_some_and(|token| token.contains('=') && !token.starts_with('='))
                {
                    drop(tokens.remove(0));
                }
            }
            _ => return,
        }
    }
}

fn extract_alias_command(description: &str) -> Option<String> {
    let marker = [" is an alias for ", " aliased to "]
        .into_iter()
        .find(|marker| description.contains(marker))?;
    let command = description.split_once(marker)?.1.trim();
    Some(unquote_command(command))
}

fn extract_function_command(description: &str) -> Option<String> {
    let start = description.find('{')?;
    let end = description.rfind('}')?;
    if end <= start {
        return None;
    }

    let body = &description[start + 1..end];
    body.lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'))
        .map(unquote_command)
}

fn unquote_command(command: &str) -> String {
    command
        .trim()
        .trim_matches('`')
        .trim_matches('\'')
        .trim_matches('"')
        .to_string()
}

fn shell_quote(value: &str) -> String {
    let escaped = value.replace('\'', r#"'\''"#);
    format!("'{escaped}'")
}

fn find_on_path(command_name: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;

    for dir in env::split_paths(&path) {
        #[cfg(windows)]
        {
            let candidates = windows_candidates(&dir, command_name);
            for candidate in candidates {
                if is_executable_candidate(&candidate) {
                    return Some(candidate);
                }
            }
        }

        #[cfg(not(windows))]
        {
            let candidate = dir.join(command_name);
            if is_executable_candidate(&candidate) {
                return Some(candidate);
            }
        }
    }

    None
}

#[cfg(windows)]
fn windows_candidates(dir: &Path, command_name: &str) -> Vec<PathBuf> {
    let mut candidates = vec![dir.join(command_name)];
    let pathext = env::var_os("PATHEXT")
        .unwrap_or_else(|| ".COM;.EXE;.BAT;.CMD".into())
        .to_string_lossy()
        .into_owned();

    for ext in pathext.split(';').filter(|ext| !ext.is_empty()) {
        candidates.push(dir.join(format!("{command_name}{ext}")));
    }

    candidates
}

fn is_executable_candidate(path: &Path) -> bool {
    if !(path.exists() && path.is_file()) {
        return false;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        path.metadata()
            .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }

    #[cfg(not(unix))]
    {
        true
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::env;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use super::*;
    #[cfg(unix)]
    use tempfile::TempDir;

    #[cfg(unix)]
    #[test]
    fn alias_recursion_depth_exceeded_returns_error() {
        // A fake shell that always says "cmd is an alias for cmd" causes
        // infinite recursion. The resolver must bail with a descriptive
        // error rather than stack-overflowing.
        let dir = TempDir::new().expect("temp dir");
        let shell_path = dir.path().join("fake-recursive-shell");

        // command -v returns "cmd" (relative, not absolute → triggers symbolic resolution)
        // command -V returns the alias line that points back to itself.
        std::fs::write(
            &shell_path,
            b"#!/bin/sh\ncmd=\"$2\"\ncase \"$cmd\" in\n  \"command -v -- 'cmd'\") printf 'cmd\\n' ;;\n  \"command -V -- 'cmd'\") printf 'cmd is an alias for cmd\\n' ;;\n  *) exit 1 ;;\nesac\n",
        )
        .expect("write fake shell");
        let mut perms = std::fs::metadata(&shell_path)
            .expect("metadata")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&shell_path, perms).expect("chmod");

        let err = resolve_program(
            "cmd",
            &ResolveOptions {
                explicit_path: None,
                mode: ResolveMode::CommandV,
                shell: Some(shell_path),
            },
        )
        .expect_err("recursive alias must return an error, not stack-overflow");

        // The recursion limit error may be swallowed by the Auto-mode fallback path
        // and surface as ProgramNotFound. Both are acceptable — neither panics or
        // stack-overflows. What's NOT acceptable is a stack overflow or hang.
        assert!(
            matches!(
                err,
                AdapterError::UnsupportedShellResolution { .. } | AdapterError::ProgramNotFound(_)
            ),
            "recursive alias must return a known error (not stack-overflow): {err:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn resolve_in_path_only_mode_with_shell_env_absent_does_not_panic() {
        // PathOnly mode never consults the SHELL env var. Removing SHELL
        // and calling in PathOnly mode must not panic even if the command
        // is absent.
        let original_shell = env::var_os("SHELL");
        env::remove_var("SHELL");

        let result = resolve_program(
            "this-command-definitely-does-not-exist-zz99",
            &ResolveOptions {
                explicit_path: None,
                mode: ResolveMode::PathOnly,
                shell: None,
            },
        );

        if let Some(s) = original_shell {
            env::set_var("SHELL", s);
        }

        assert!(
            matches!(result, Err(AdapterError::ProgramNotFound(_))),
            "absent command must return ProgramNotFound, got: {result:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn empty_path_component_does_not_panic() {
        // PATH with a leading or trailing colon contains an empty component.
        // env::split_paths returns an empty PathBuf for the empty component.
        // The resolver must handle this gracefully: no panic, returns ProgramNotFound.
        let original_path = env::var_os("PATH");
        // Leading colon: empty component before /tmp
        env::set_var("PATH", ":/tmp");

        let result = resolve_program(
            "this-command-definitely-does-not-exist-zz99",
            &ResolveOptions {
                explicit_path: None,
                mode: ResolveMode::PathOnly,
                shell: None,
            },
        );

        if let Some(p) = original_path {
            env::set_var("PATH", p);
        } else {
            env::remove_var("PATH");
        }

        assert!(
            result.is_err(),
            "absent command with malformed PATH must return Err, not panic"
        );
    }

    #[cfg(unix)]
    #[test]
    fn resolves_explicit_path() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("npm");
        std::fs::write(&path, b"#!/bin/sh\n").expect("write");
        let mut perms = std::fs::metadata(&path).expect("metadata").permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).expect("chmod");

        let resolved = resolve_program(
            "npm",
            &ResolveOptions {
                explicit_path: Some(path.clone()),
                mode: ResolveMode::Auto,
                shell: None,
            },
        )
        .expect("resolved");

        assert_eq!(resolved.path, path);
        assert!(resolved.fixed_args.is_empty());
        assert_eq!(resolved.strategy, ResolutionStrategy::ExplicitPath);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_non_path_command_v_output() {
        let error = resolve_via_command_v(
            "cd",
            &ResolveOptions {
                explicit_path: None,
                mode: ResolveMode::CommandV,
                shell: Some(PathBuf::from("/bin/sh")),
            },
            0,
        )
        .expect_err("unsupported shell result");

        match error {
            AdapterError::UnsupportedShellResolution { .. }
            | AdapterError::ProgramNotFound(_)
            | AdapterError::CommandVFailed { .. } => {}
            other => unreachable!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn parses_alias_description() {
        let parsed = parse_command_string(
            extract_alias_command("npm is an alias for asdf exec npm").expect("alias"),
            "npm is an alias for asdf exec npm".to_string(),
        )
        .expect("parsed");

        assert_eq!(parsed.program_token, "asdf");
        assert_eq!(
            parsed.fixed_args,
            vec!["exec".to_string(), "npm".to_string()]
        );
    }

    #[test]
    fn parses_function_description() {
        let description = "npm is a shell function\nnpm () {\n  volta run npm \"$@\"\n}";
        let parsed = parse_command_string(
            extract_function_command(description).expect("function"),
            description.to_string(),
        )
        .expect("parsed");

        assert_eq!(parsed.program_token, "volta");
        assert_eq!(
            parsed.fixed_args,
            vec!["run".to_string(), "npm".to_string()]
        );
    }

    #[test]
    fn parses_shell_builtin_wrapper_function_description() {
        let description = "npm is a shell function\nnpm () {\n  command npm \"$@\"\n}";
        let parsed = parse_command_string(
            extract_function_command(description).expect("function"),
            description.to_string(),
        )
        .expect("parsed");

        assert_eq!(parsed.program_token, "npm");
        assert!(parsed.fixed_args.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn resolves_alias_chain_via_fake_shell() {
        let dir = TempDir::new().expect("temp dir");
        let shell_path = dir.path().join("fake-shell");
        let asdf_path = dir.path().join("asdf");
        let original_path = env::var_os("PATH");

        std::fs::write(
            &shell_path,
            format!(
                "#!/bin/sh\ncmd=\"$2\"\ncase \"$cmd\" in\n  \"command -v -- 'npm'\") printf 'npm\\n' ;;\n  \"command -V -- 'npm'\") printf 'npm is an alias for asdf exec npm\\n' ;;\n  \"command -v -- 'asdf'\") printf '{}\\n' ;;\n  \"command -V -- 'asdf'\") printf '{}\\n' ;;\n  *) exit 1 ;;\nesac\n",
                asdf_path.display(),
                asdf_path.display()
            ),
        )
        .expect("write shell");
        let mut shell_perms = std::fs::metadata(&shell_path)
            .expect("metadata")
            .permissions();
        shell_perms.set_mode(0o755);
        std::fs::set_permissions(&shell_path, shell_perms).expect("chmod shell");

        std::fs::write(&asdf_path, b"#!/bin/sh\n").expect("write asdf");
        let mut asdf_perms = std::fs::metadata(&asdf_path)
            .expect("metadata")
            .permissions();
        asdf_perms.set_mode(0o755);
        std::fs::set_permissions(&asdf_path, asdf_perms).expect("chmod asdf");
        env::set_var("PATH", dir.path());

        let resolved = resolve_program(
            "npm",
            &ResolveOptions {
                explicit_path: None,
                mode: ResolveMode::CommandV,
                shell: Some(shell_path),
            },
        )
        .expect("resolved");

        assert_eq!(resolved.path, asdf_path);
        assert_eq!(
            resolved.fixed_args,
            vec!["exec".to_string(), "npm".to_string()]
        );
        assert_eq!(resolved.strategy, ResolutionStrategy::CommandV);

        if let Some(path) = original_path {
            env::set_var("PATH", path);
        } else {
            env::remove_var("PATH");
        }
    }

    #[cfg(unix)]
    #[test]
    fn auto_resolution_prefers_command_v_over_path_lookup() {
        let dir = TempDir::new().expect("temp dir");
        let shell_path = dir.path().join("fake-shell");
        let shim_path = dir.path().join("npm");
        let real_path = dir.path().join("real-npm");
        let original_path = env::var_os("PATH");

        std::fs::write(
            &shell_path,
            format!(
                "#!/bin/sh\ncmd=\"$2\"\ncase \"$cmd\" in\n  \"command -v -- 'npm'\") printf 'npm\\n' ;;\n  \"command -V -- 'npm'\") printf 'npm is an alias for {} --wrapped\\n' ;;\n  \"command -v -- '{}'\"|\"command -V -- '{}'\" ) printf '{}\\n' ;;\n  *) exit 1 ;;\nesac\n",
                real_path.display(),
                real_path.display(),
                real_path.display(),
                real_path.display()
            ),
        )
        .expect("write shell");
        let mut shell_perms = std::fs::metadata(&shell_path)
            .expect("metadata")
            .permissions();
        shell_perms.set_mode(0o755);
        std::fs::set_permissions(&shell_path, shell_perms).expect("chmod shell");

        std::fs::write(&shim_path, b"#!/bin/sh\n").expect("write shim");
        let mut shim_perms = std::fs::metadata(&shim_path)
            .expect("metadata")
            .permissions();
        shim_perms.set_mode(0o755);
        std::fs::set_permissions(&shim_path, shim_perms).expect("chmod shim");

        std::fs::write(&real_path, b"#!/bin/sh\n").expect("write real");
        let mut real_perms = std::fs::metadata(&real_path)
            .expect("metadata")
            .permissions();
        real_perms.set_mode(0o755);
        std::fs::set_permissions(&real_path, real_perms).expect("chmod real");

        env::set_var("PATH", dir.path());

        let resolved = resolve_program(
            "npm",
            &ResolveOptions {
                explicit_path: None,
                mode: ResolveMode::Auto,
                shell: Some(shell_path),
            },
        )
        .expect("resolved");

        assert_eq!(resolved.path, real_path);
        assert_eq!(resolved.fixed_args, vec!["--wrapped".to_string()]);
        assert_eq!(resolved.strategy, ResolutionStrategy::CommandV);

        if let Some(path) = original_path {
            env::set_var("PATH", path);
        } else {
            env::remove_var("PATH");
        }
    }

    #[cfg(unix)]
    #[test]
    fn path_lookup_ignores_non_executable_files() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("npm");
        let original_path = env::var_os("PATH");
        std::fs::write(&path, b"not executable\n").expect("write");
        let mut perms = std::fs::metadata(&path).expect("metadata").permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(&path, perms).expect("chmod");

        env::set_var("PATH", dir.path());

        let error = resolve_program(
            "npm",
            &ResolveOptions {
                explicit_path: None,
                mode: ResolveMode::PathOnly,
                shell: None,
            },
        )
        .expect_err("path-only resolution should reject non-executable files");

        assert!(matches!(error, AdapterError::ProgramNotFound(command) if command == "npm"));

        if let Some(path) = original_path {
            env::set_var("PATH", path);
        } else {
            env::remove_var("PATH");
        }
    }

    // -----------------------------------------------------------------------
    // Pure function unit tests (no subprocess needed)
    // -----------------------------------------------------------------------

    #[test]
    fn extract_alias_command_is_an_alias_for_marker() {
        let result = extract_alias_command("git is an alias for /usr/bin/git");
        assert_eq!(result.as_deref(), Some("/usr/bin/git"));
    }

    #[test]
    fn extract_alias_command_aliased_to_marker() {
        let result = extract_alias_command("npm aliased to /usr/local/bin/npm");
        assert_eq!(result.as_deref(), Some("/usr/local/bin/npm"));
    }

    #[test]
    fn extract_alias_command_no_marker_returns_none() {
        let result = extract_alias_command("git is a shell function");
        assert!(result.is_none());
    }

    #[test]
    fn extract_alias_command_trims_trailing_whitespace() {
        let result = extract_alias_command("cmd is an alias for   /bin/cmd  ");
        assert_eq!(result.as_deref(), Some("/bin/cmd"));
    }

    #[test]
    fn extract_alias_command_strips_single_quotes() {
        let result = extract_alias_command("g is an alias for 'git'");
        assert_eq!(result.as_deref(), Some("git"));
    }

    #[test]
    fn extract_alias_command_strips_backtick() {
        let result = extract_alias_command("g is an alias for `git`");
        assert_eq!(result.as_deref(), Some("git"));
    }

    #[test]
    fn extract_alias_command_multiword_command_preserved() {
        let result = extract_alias_command("npm is an alias for asdf exec npm");
        assert_eq!(result.as_deref(), Some("asdf exec npm"));
    }

    #[test]
    fn extract_function_command_basic() {
        let result = extract_function_command("() { git status }");
        assert_eq!(result.as_deref(), Some("git status"));
    }

    #[test]
    fn extract_function_command_skips_empty_lines() {
        let result = extract_function_command("() {\n\n  git status\n}");
        assert_eq!(result.as_deref(), Some("git status"));
    }

    #[test]
    fn extract_function_command_skips_comment_lines() {
        let result = extract_function_command("() {\n  # comment\n  git commit\n}");
        assert_eq!(result.as_deref(), Some("git commit"));
    }

    #[test]
    fn extract_function_command_no_braces_returns_none() {
        let result = extract_function_command("git is a function");
        assert!(result.is_none());
    }

    #[test]
    fn extract_function_command_only_comment_lines_returns_none() {
        let result = extract_function_command("() { # only a comment }");
        assert!(result.is_none());
    }

    #[test]
    fn extract_function_command_closing_before_opening_returns_none() {
        let result = extract_function_command("} some text {");
        assert!(result.is_none());
    }

    #[test]
    fn unquote_command_backtick_wrapped() {
        assert_eq!(unquote_command("`git`"), "git");
    }

    #[test]
    fn unquote_command_single_quoted() {
        assert_eq!(unquote_command("'git'"), "git");
    }

    #[test]
    fn unquote_command_double_quoted() {
        assert_eq!(unquote_command("\"git\""), "git");
    }

    #[test]
    fn unquote_command_no_quotes_unchanged() {
        assert_eq!(unquote_command("git"), "git");
    }

    #[test]
    fn unquote_command_trims_whitespace() {
        assert_eq!(unquote_command("  git  "), "git");
    }

    #[test]
    fn unquote_command_empty_string() {
        assert_eq!(unquote_command(""), "");
    }

    #[test]
    fn unquote_command_whitespace_then_single_quotes() {
        assert_eq!(unquote_command("  'git'  "), "git");
    }

    #[test]
    fn shell_quote_simple_string() {
        assert_eq!(shell_quote("hello"), "'hello'");
    }

    #[test]
    fn shell_quote_string_with_single_quote() {
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
    }

    #[test]
    fn shell_quote_empty_string() {
        assert_eq!(shell_quote(""), "''");
    }

    #[test]
    fn shell_quote_string_with_spaces() {
        assert_eq!(shell_quote("hello world"), "'hello world'");
    }

    #[test]
    fn shell_quote_dollar_sign_not_escaped() {
        assert_eq!(shell_quote("$PATH"), "'$PATH'");
    }

    #[test]
    fn normalize_wrapper_tokens_command_prefix_stripped() {
        let mut tokens = vec!["command".to_string(), "git".to_string()];
        normalize_wrapper_tokens(&mut tokens);
        assert_eq!(tokens, vec!["git"]);
    }

    #[test]
    fn normalize_wrapper_tokens_builtin_prefix_stripped() {
        let mut tokens = vec!["builtin".to_string(), "git".to_string()];
        normalize_wrapper_tokens(&mut tokens);
        assert_eq!(tokens, vec!["git"]);
    }

    #[test]
    fn normalize_wrapper_tokens_exec_prefix_stripped() {
        let mut tokens = vec!["exec".to_string(), "git".to_string()];
        normalize_wrapper_tokens(&mut tokens);
        assert_eq!(tokens, vec!["git"]);
    }

    #[test]
    fn normalize_wrapper_tokens_command_with_double_dash() {
        let mut tokens = vec!["command".to_string(), "--".to_string(), "git".to_string()];
        normalize_wrapper_tokens(&mut tokens);
        assert_eq!(tokens, vec!["git"]);
    }

    #[test]
    fn normalize_wrapper_tokens_env_prefix_stripped() {
        let mut tokens = vec!["env".to_string(), "git".to_string()];
        normalize_wrapper_tokens(&mut tokens);
        assert_eq!(tokens, vec!["git"]);
    }

    #[test]
    fn normalize_wrapper_tokens_env_with_assignment_stripped() {
        let mut tokens = vec!["env".to_string(), "FOO=bar".to_string(), "git".to_string()];
        normalize_wrapper_tokens(&mut tokens);
        assert_eq!(tokens, vec!["git"]);
    }

    #[test]
    fn normalize_wrapper_tokens_env_dash_dash_and_assignment_stripped() {
        let mut tokens = vec![
            "env".to_string(),
            "--".to_string(),
            "KEY=val".to_string(),
            "git".to_string(),
        ];
        normalize_wrapper_tokens(&mut tokens);
        assert_eq!(tokens, vec!["git"]);
    }

    #[test]
    fn normalize_wrapper_tokens_no_wrapper_unchanged() {
        let mut tokens = vec!["git".to_string(), "status".to_string()];
        normalize_wrapper_tokens(&mut tokens);
        assert_eq!(tokens, vec!["git", "status"]);
    }

    #[test]
    fn normalize_wrapper_tokens_empty_vec_unchanged() {
        let mut tokens: Vec<String> = vec![];
        normalize_wrapper_tokens(&mut tokens);
        assert!(tokens.is_empty());
    }

    #[test]
    fn normalize_wrapper_tokens_nested_command_builtin() {
        let mut tokens = vec![
            "command".to_string(),
            "builtin".to_string(),
            "git".to_string(),
        ];
        normalize_wrapper_tokens(&mut tokens);
        assert_eq!(tokens, vec!["git"]);
    }

    #[test]
    fn normalize_wrapper_tokens_preserves_trailing_args() {
        let mut tokens = vec![
            "command".to_string(),
            "git".to_string(),
            "--version".to_string(),
        ];
        normalize_wrapper_tokens(&mut tokens);
        assert_eq!(tokens, vec!["git", "--version"]);
    }

    #[test]
    fn parse_command_string_simple_program() {
        let result = parse_command_string("git".to_string(), "raw".to_string());
        let parsed = result.expect("should parse");
        assert_eq!(parsed.program_token, "git");
        assert!(parsed.fixed_args.is_empty());
    }

    #[test]
    fn parse_command_string_strips_dollar_at() {
        let result = parse_command_string("git $@".to_string(), "raw".to_string());
        let parsed = result.expect("should parse");
        assert_eq!(parsed.program_token, "git");
        assert!(parsed.fixed_args.is_empty());
    }

    #[test]
    fn parse_command_string_strips_quoted_dollar_at() {
        let result = parse_command_string("git \"$@\"".to_string(), "raw".to_string());
        let parsed = result.expect("should parse");
        assert_eq!(parsed.program_token, "git");
        assert!(parsed.fixed_args.is_empty());
    }

    #[test]
    fn parse_command_string_with_fixed_args() {
        let result = parse_command_string("asdf exec npm".to_string(), "raw".to_string());
        let parsed = result.expect("should parse");
        assert_eq!(parsed.program_token, "asdf");
        assert_eq!(parsed.fixed_args, vec!["exec", "npm"]);
    }

    #[test]
    fn parse_command_string_empty_after_strip_returns_none() {
        let result = parse_command_string("$@".to_string(), "raw".to_string());
        assert!(result.is_none());
    }

    #[test]
    fn parse_command_string_wrapper_stripped() {
        let result = parse_command_string("command git $@".to_string(), "raw".to_string());
        let parsed = result.expect("should parse");
        assert_eq!(parsed.program_token, "git");
        assert!(parsed.fixed_args.is_empty());
    }

    #[test]
    fn parse_command_string_raw_preserved() {
        let result = parse_command_string("git".to_string(), "original description".to_string());
        let parsed = result.expect("should parse");
        assert_eq!(parsed.raw, "original description");
    }
}
