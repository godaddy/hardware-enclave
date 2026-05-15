// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Shell integration script generation.
//!
//! Generates shell-specific scripts that detect misuse of `export` for
//! sensitive environment variables and optionally provide helper functions.
//! Supports bash, zsh, fish, and PowerShell.

/// Configuration for shell integration script generation.
#[derive(Debug, Clone)]
pub struct ShellInitConfig {
    /// Command name (e.g., "awsenc", "sso-jwt").
    pub command: String,
    /// Environment variable patterns to detect in export statements.
    /// For bash/zsh these appear in a regex alternation.
    pub export_patterns: Vec<String>,
    /// Warning message lines when export is detected (each line printed to stderr).
    pub export_warning: Vec<String>,
    /// Whether to include PowerShell output support.
    pub include_powershell: bool,
    /// Optional: shell function name and body for a helper function
    /// (e.g., "awsenc-use" that sets env vars in the parent shell).
    /// If None, generates a command wrapper that intercepts the command itself.
    pub helper_function: Option<ShellHelperFunction>,
    /// If true, generates a command-wrapping function (like sso-jwt)
    /// that refuses to run when called inside an export statement.
    /// If false, generates a preexec/DEBUG hook that warns (like awsenc).
    pub command_wrapper: bool,
}

/// A helper shell function to include in the init script.
#[derive(Debug, Clone)]
pub struct ShellHelperFunction {
    /// Function name (e.g., "awsenc-use").
    pub name: String,
    /// Bash/zsh function body (the commands inside the function).
    pub bash_body: String,
    /// Fish function body.
    pub fish_body: String,
    /// PowerShell function body (if applicable).
    pub powershell_body: String,
}

/// Detect the user's current shell from the SHELL environment variable.
pub fn detect_shell(explicit: Option<&str>) -> Result<String, String> {
    if let Some(s) = explicit {
        return Ok(s.to_lowercase());
    }

    if let Ok(shell) = std::env::var("SHELL") {
        if let Some(name) = shell.rsplit('/').next() {
            match name {
                "zsh" => return Ok("zsh".into()),
                "bash" => return Ok("bash".into()),
                "fish" => return Ok("fish".into()),
                _ => {}
            }
        }
        if shell.contains("zsh") {
            return Ok("zsh".into());
        }
        if shell.contains("bash") {
            return Ok("bash".into());
        }
        if shell.contains("fish") {
            return Ok("fish".into());
        }
    }

    // Check PSModulePath for PowerShell
    if std::env::var("PSModulePath").is_ok() {
        return Ok("powershell".into());
    }

    Err("could not detect shell; specify one: bash, zsh, fish, powershell".into())
}

/// Generate a shell integration script for the given shell.
pub fn generate_shell_init(shell: &str, config: &ShellInitConfig) -> Result<String, String> {
    match shell {
        "bash" => Ok(generate_bash(config)),
        "zsh" => Ok(generate_zsh(config)),
        "fish" => Ok(generate_fish(config)),
        "powershell" | "pwsh" => {
            if config.include_powershell {
                Ok(generate_powershell(config))
            } else {
                Err(format!("PowerShell is not supported by {}", config.command))
            }
        }
        other => Err(format!("unsupported shell: {other}")),
    }
}

/// Build a regex alternation from export patterns for bash/zsh.
fn pattern_alternation(patterns: &[String]) -> String {
    patterns.join("|")
}

/// Build fish pattern match expression.
fn fish_pattern_match(patterns: &[String]) -> String {
    patterns.join("|")
}

/// Build the warning echo lines for bash/zsh.
fn bash_warning_lines(warning: &[String]) -> String {
    warning
        .iter()
        .map(|line| format!("    echo \"{}\" >&2", line.replace('"', "\\\"")))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Build the warning echo lines for fish.
fn fish_warning_lines(warning: &[String]) -> String {
    warning
        .iter()
        .map(|line| format!("        echo \"{}\" >&2", line.replace('"', "\\\"")))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Build the warning lines for PowerShell.
fn powershell_warning_lines(warning: &[String]) -> String {
    warning
        .iter()
        .map(|line| {
            format!(
                "        Write-Host \"{}\" -ForegroundColor Yellow",
                line.replace('"', "`\"")
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn generate_bash(config: &ShellInitConfig) -> String {
    let cmd = &config.command;
    let patterns = pattern_alternation(&config.export_patterns);
    let warnings = bash_warning_lines(&config.export_warning);
    // Sanitize command name for use as identifier prefix
    let prefix = cmd.replace('-', "_");

    if config.command_wrapper {
        // sso-jwt style: command wrapper that refuses to run inside export
        let mut script = format!(
            r#"# {cmd} shell integration for bash
# Add to your .bashrc: eval "$({cmd} shell-init bash)"

__{prefix}_debug() {{
    __{prefix}_CURRENT_CMD="$BASH_COMMAND"
}}

# Chain with existing DEBUG trap if present
__{prefix}_existing_trap=$(trap -p DEBUG 2>/dev/null | sed "s/^trap -- '//;s/' DEBUG$//")
if [[ -n "$__{prefix}_existing_trap" ]]; then
    eval "trap '${{__{prefix}_existing_trap}}; __{prefix}_debug' DEBUG"
else
    trap '__{prefix}_debug' DEBUG
fi
unset __{prefix}_existing_trap

{cmd}() {{
    if [[ "$__{prefix}_CURRENT_CMD" =~ ^[[:space:]]*(export|declare\ -x)[[:space:]] ]]; then
{warnings}
        return 1
    fi
    command {cmd} "$@"
}}
"#
        );

        if let Some(helper) = &config.helper_function {
            script.push('\n');
            script.push_str(&format!("{}() {{\n{}\n}}\n", helper.name, helper.bash_body));
        }

        script
    } else {
        // awsenc style: preexec hook that warns but doesn't block
        let mut script = format!(
            r#"# {cmd} shell integration (bash)
# Add to ~/.bashrc: eval "$({cmd} shell-init bash)"

_{cmd}_preexec() {{
  local cmd="$BASH_COMMAND"
  if [[ "$cmd" =~ ^[[:space:]]*(export|declare\ -x)[[:space:]]+({patterns})= ]]; then
{warnings}
  fi
}}

# Install the DEBUG trap, chaining with any existing trap
if [[ -z "${{_{cmd}_trap_installed:-}}" ]]; then
  _{cmd}_existing_trap=$(trap -p DEBUG | sed "s/^trap -- '//;s/' DEBUG$//")
  if [[ -n "$_{cmd}_existing_trap" ]]; then
    trap '_{cmd}_preexec; eval "$_{cmd}_existing_trap"' DEBUG
  else
    trap '_{cmd}_preexec' DEBUG
  fi
  _{cmd}_trap_installed=1
fi
"#
        );

        if let Some(helper) = &config.helper_function {
            script.push('\n');
            script.push_str(&format!("{}() {{\n{}\n}}\n", helper.name, helper.bash_body));
        }

        script
    }
}

fn generate_zsh(config: &ShellInitConfig) -> String {
    let cmd = &config.command;
    let patterns = pattern_alternation(&config.export_patterns);
    let warnings = bash_warning_lines(&config.export_warning);
    let prefix = cmd.replace('-', "_");

    if config.command_wrapper {
        // sso-jwt style: command wrapper
        let mut script = format!(
            r#"# {cmd} shell integration for zsh
# Add to your .zshrc: eval "$({cmd} shell-init zsh)"

__{prefix}_preexec() {{
    __{prefix}_CURRENT_CMD="$1"
}}
autoload -Uz add-zsh-hook
add-zsh-hook preexec __{prefix}_preexec

{cmd}() {{
    if [[ "$__{prefix}_CURRENT_CMD" =~ '^[[:space:]]*(export|declare[[:space:]]+-x|typeset[[:space:]]+-x)[[:space:]]' ]]; then
{warnings}
        __{prefix}_CURRENT_CMD=""
        return 1
    fi
    __{prefix}_CURRENT_CMD=""
    command {cmd} "$@"
}}
"#
        );

        if let Some(helper) = &config.helper_function {
            script.push('\n');
            script.push_str(&format!("{}() {{\n{}\n}}\n", helper.name, helper.bash_body));
        }

        script
    } else {
        // awsenc style: preexec warning
        let mut script = format!(
            r#"# {cmd} shell integration (zsh)
# Add to ~/.zshrc: eval "$({cmd} shell-init zsh)"

autoload -Uz add-zsh-hook

_{cmd}_preexec() {{
  local cmd="$1"
  if [[ "$cmd" =~ ^[[:space:]]*(export|declare\ -x)[[:space:]]+({patterns})= ]]; then
{warnings}
  fi
}}

add-zsh-hook preexec _{cmd}_preexec
"#
        );

        if let Some(helper) = &config.helper_function {
            script.push('\n');
            script.push_str(&format!("{}() {{\n{}\n}}\n", helper.name, helper.bash_body));
        }

        script
    }
}

fn generate_fish(config: &ShellInitConfig) -> String {
    let cmd = &config.command;
    let patterns = fish_pattern_match(&config.export_patterns);
    let warnings = fish_warning_lines(&config.export_warning);
    let prefix = cmd.replace('-', "_");

    if config.command_wrapper {
        // sso-jwt style: function wrapper
        format!(
            r#"# {cmd} shell integration for fish
# Add to your config.fish: {cmd} shell-init fish | source

function {cmd} --wraps='{cmd}' --description '{cmd} with export detection'
    set -l current_cmd (commandline)
    if string match -qr '^\s*(set -gx|set --global --export)' -- $current_cmd
{warnings}
        return 1
    end
    command {cmd} $argv
end
"#
        )
    } else {
        // awsenc style: preexec event function
        let mut script = format!(
            r#"# {cmd} shell integration (fish)
# Add to ~/.config/fish/config.fish: {cmd} shell-init fish | source

function __{prefix}_check_export --on-event fish_preexec
    set -l cmd $argv[1]
    if string match -rq '^\s*set\s+(-gx|-Ux)\s+({patterns})\s' -- "$cmd"
{warnings}
    end
end
"#
        );

        if let Some(helper) = &config.helper_function {
            script.push('\n');
            script.push_str(&format!(
                "function {}\n{}\nend\n",
                helper.name, helper.fish_body
            ));
        }

        script
    }
}

fn generate_powershell(config: &ShellInitConfig) -> String {
    let cmd = &config.command;
    let patterns = pattern_alternation(&config.export_patterns);
    let warnings = powershell_warning_lines(&config.export_warning);
    let prefix = cmd.replace('-', "");

    let mut script = format!(
        r#"# {cmd} shell integration (PowerShell)
# Add to $PROFILE: Invoke-Expression ({cmd} shell-init powershell)

$_{prefix}OriginalPrompt = $function:prompt

function prompt {{
    # Check recent history for credential exports
    $lastCmd = (Get-History -Count 1).CommandLine 2>$null
    if ($lastCmd -match '\$env:({patterns})\s*=') {{
{warnings}
    }}
    & $_{prefix}OriginalPrompt
}}
"#
    );

    if let Some(helper) = &config.helper_function {
        script.push('\n');
        script.push_str(&format!(
            "function {} {{\n{}\n}}\n",
            helper.name, helper.powershell_body
        ));
    }

    script
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn awsenc_config() -> ShellInitConfig {
        ShellInitConfig {
            command: "awsenc".to_string(),
            export_patterns: vec![
                "AWS_ACCESS_KEY_ID".to_string(),
                "AWS_SECRET_ACCESS_KEY".to_string(),
                "AWS_SESSION_TOKEN".to_string(),
            ],
            export_warning: vec![
                "[awsenc] Warning: Exporting AWS credentials as environment variables defeats"
                    .to_string(),
                "hardware-backed protection. Use 'awsenc exec' or credential_process instead."
                    .to_string(),
            ],
            include_powershell: true,
            helper_function: Some(ShellHelperFunction {
                name: "awsenc-use".to_string(),
                bash_body: r#"  local profile
  profile=$(command awsenc use "$@" --print-profile) || return $?
  export AWSENC_PROFILE="$profile"
  export AWS_PROFILE="$profile"
  echo "Switched to profile: $profile" >&2"#
                    .to_string(),
                fish_body: r#"    set -l profile (command awsenc use $argv --print-profile)
    or return $status
    set -gx AWSENC_PROFILE $profile
    set -gx AWS_PROFILE $profile
    echo "Switched to profile: $profile" >&2"#
                    .to_string(),
                powershell_body: r#"    $profile = & awsenc use @args --print-profile
    if ($LASTEXITCODE -eq 0) {
        $env:AWSENC_PROFILE = $profile
        $env:AWS_PROFILE = $profile
        Write-Host "Switched to profile: $profile" -ForegroundColor Green
    }"#
                .to_string(),
            }),
            command_wrapper: false,
        }
    }

    fn ssojwt_config() -> ShellInitConfig {
        ShellInitConfig {
            command: "sso-jwt".to_string(),
            export_patterns: vec!["SSO_JWT".to_string(), "COMPANY_JWT".to_string()],
            export_warning: vec![
                "error: refusing to output JWT for 'export'. This would persist the token in your shell environment.".to_string(),
                "       Use: COMPANY_JWT=$(sso-jwt) your-command".to_string(),
                "       Or:  sso-jwt exec -- your-command".to_string(),
            ],
            include_powershell: true,
            helper_function: None,
            command_wrapper: true,
        }
    }

    #[test]
    fn bash_awsenc_contains_preexec() {
        let script = generate_shell_init("bash", &awsenc_config()).unwrap();
        assert!(script.contains("_awsenc_preexec"));
        assert!(script.contains("DEBUG"));
        assert!(script.contains("AWS_ACCESS_KEY_ID"));
    }

    #[test]
    fn bash_awsenc_contains_helper() {
        let script = generate_shell_init("bash", &awsenc_config()).unwrap();
        assert!(script.contains("awsenc-use()"));
        assert!(script.contains("AWSENC_PROFILE"));
    }

    #[test]
    fn zsh_awsenc_contains_hook() {
        let script = generate_shell_init("zsh", &awsenc_config()).unwrap();
        assert!(script.contains("add-zsh-hook preexec"));
        assert!(script.contains("awsenc-use()"));
    }

    #[test]
    fn fish_awsenc_contains_event() {
        let script = generate_shell_init("fish", &awsenc_config()).unwrap();
        assert!(script.contains("__awsenc_check_export"));
        assert!(script.contains("fish_preexec"));
        assert!(script.contains("function awsenc-use"));
    }

    #[test]
    fn powershell_awsenc_contains_prompt() {
        let script = generate_shell_init("powershell", &awsenc_config()).unwrap();
        assert!(script.contains("function prompt"));
        assert!(script.contains("function awsenc-use"));
    }

    #[test]
    fn bash_ssojwt_contains_wrapper() {
        let script = generate_shell_init("bash", &ssojwt_config()).unwrap();
        assert!(script.contains("sso-jwt()"));
        assert!(script.contains("command sso-jwt"));
        assert!(script.contains("refusing to output JWT"));
    }

    #[test]
    fn zsh_ssojwt_contains_wrapper() {
        let script = generate_shell_init("zsh", &ssojwt_config()).unwrap();
        assert!(script.contains("sso-jwt()"));
        assert!(script.contains("command sso-jwt"));
        assert!(script.contains("add-zsh-hook preexec"));
    }

    #[test]
    fn fish_ssojwt_contains_wrapper() {
        let script = generate_shell_init("fish", &ssojwt_config()).unwrap();
        assert!(script.contains("function sso-jwt"));
        assert!(script.contains("command sso-jwt"));
    }

    #[test]
    fn powershell_supported_for_ssojwt() {
        let result = generate_shell_init("powershell", &ssojwt_config());
        assert!(result.is_ok());
        let script = result.unwrap();
        assert!(script.contains("$PROFILE"));
        assert!(script.contains("sso-jwt shell-init powershell"));
    }

    #[test]
    fn unsupported_shell() {
        let result = generate_shell_init("tcsh", &awsenc_config());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unsupported shell"));
    }

    // Mutex for tests that modify SHELL env var
    static SHELL_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn detect_shell_explicit() {
        assert_eq!(detect_shell(Some("bash")).unwrap(), "bash");
        assert_eq!(detect_shell(Some("ZSH")).unwrap(), "zsh");
        assert_eq!(detect_shell(Some("fish")).unwrap(), "fish");
        assert_eq!(detect_shell(Some("PowerShell")).unwrap(), "powershell");
    }

    #[test]
    fn detect_shell_from_env_zsh() {
        let _lock = SHELL_ENV_LOCK.lock().expect("mutex poisoned");
        let prev = std::env::var("SHELL").ok();
        std::env::set_var("SHELL", "/bin/zsh");
        let result = detect_shell(None);
        match prev {
            Some(v) => std::env::set_var("SHELL", v),
            None => std::env::remove_var("SHELL"),
        }
        assert_eq!(result.unwrap(), "zsh");
    }

    #[test]
    fn detect_shell_from_env_bash() {
        let _lock = SHELL_ENV_LOCK.lock().expect("mutex poisoned");
        let prev = std::env::var("SHELL").ok();
        std::env::set_var("SHELL", "/bin/bash");
        let result = detect_shell(None);
        match prev {
            Some(v) => std::env::set_var("SHELL", v),
            None => std::env::remove_var("SHELL"),
        }
        assert_eq!(result.unwrap(), "bash");
    }

    #[test]
    fn detect_shell_from_env_fish() {
        let _lock = SHELL_ENV_LOCK.lock().expect("mutex poisoned");
        let prev = std::env::var("SHELL").ok();
        std::env::set_var("SHELL", "/usr/local/bin/fish");
        let result = detect_shell(None);
        match prev {
            Some(v) => std::env::set_var("SHELL", v),
            None => std::env::remove_var("SHELL"),
        }
        assert_eq!(result.unwrap(), "fish");
    }

    #[test]
    fn bash_wrapper_chains_existing_trap() {
        let script = generate_shell_init("bash", &ssojwt_config()).unwrap();
        assert!(script.contains("trap -p DEBUG"));
        assert!(script.contains("__sso_jwt_existing_trap"));
        assert!(script.contains("if [[ -n \"$__sso_jwt_existing_trap\" ]]; then"));
    }

    #[test]
    fn zsh_wrapper_uses_preexec() {
        let script = generate_shell_init("zsh", &ssojwt_config()).unwrap();
        assert!(script.contains("__sso_jwt_preexec"));
        assert!(script.contains("autoload -Uz add-zsh-hook"));
    }

    #[test]
    fn all_awsenc_shells_have_comment_header() {
        let config = awsenc_config();
        for shell in &["bash", "zsh", "fish", "powershell"] {
            let script = generate_shell_init(shell, &config).unwrap();
            assert!(
                script.starts_with("# awsenc"),
                "{shell} output should start with '# awsenc'"
            );
        }
    }

    #[test]
    fn all_ssojwt_shells_have_comment_header() {
        let config = ssojwt_config();
        for shell in &["bash", "zsh", "fish"] {
            let script = generate_shell_init(shell, &config).unwrap();
            assert!(
                script.starts_with("# sso-jwt"),
                "{shell} output should start with '# sso-jwt'"
            );
        }
    }

    #[test]
    fn all_ssojwt_shells_suggest_exec() {
        let config = ssojwt_config();
        for shell in &["bash", "zsh", "fish"] {
            let script = generate_shell_init(shell, &config).unwrap();
            assert!(
                script.contains("sso-jwt exec"),
                "{shell} output missing exec suggestion"
            );
        }
    }

    #[test]
    fn all_ssojwt_shells_use_command_prefix() {
        let config = ssojwt_config();
        for shell in &["bash", "zsh", "fish"] {
            let script = generate_shell_init(shell, &config).unwrap();
            assert!(
                script.contains("command sso-jwt"),
                "{shell} output missing 'command sso-jwt'"
            );
        }
    }

    #[test]
    fn bash_output_contains_trap_chaining() {
        let script = generate_shell_init("bash", &awsenc_config()).unwrap();
        // The bash awsenc-style output chains with existing DEBUG trap
        assert!(
            script.contains("trap"),
            "bash output should contain trap for DEBUG"
        );
        assert!(
            script.contains("existing_trap"),
            "bash output should chain with existing trap"
        );
    }

    #[test]
    fn zsh_output_contains_add_zsh_hook() {
        let script = generate_shell_init("zsh", &awsenc_config()).unwrap();
        assert!(
            script.contains("add-zsh-hook"),
            "zsh output should contain add-zsh-hook"
        );
    }

    #[test]
    fn fish_output_contains_commandline_check() {
        // For the command_wrapper style (sso-jwt), fish uses `commandline`
        let script = generate_shell_init("fish", &ssojwt_config()).unwrap();
        assert!(
            script.contains("commandline"),
            "fish command wrapper output should check commandline"
        );
    }

    #[test]
    fn powershell_output_when_enabled() {
        let script = generate_shell_init("powershell", &awsenc_config()).unwrap();
        assert!(script.contains("PowerShell"));
        assert!(script.contains("function prompt"));
        assert!(script.contains("Get-History"));
    }

    #[test]
    fn generate_unknown_shell_returns_error() {
        let result = generate_shell_init("csh", &awsenc_config());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("unsupported shell"));
    }

    #[test]
    fn export_patterns_appear_in_generated_output() {
        let config = awsenc_config();
        for shell in &["bash", "zsh"] {
            let script = generate_shell_init(shell, &config).unwrap();
            assert!(
                script.contains("AWS_ACCESS_KEY_ID"),
                "{shell} output should contain export pattern AWS_ACCESS_KEY_ID"
            );
            assert!(
                script.contains("AWS_SECRET_ACCESS_KEY"),
                "{shell} output should contain export pattern AWS_SECRET_ACCESS_KEY"
            );
            assert!(
                script.contains("AWS_SESSION_TOKEN"),
                "{shell} output should contain export pattern AWS_SESSION_TOKEN"
            );
        }
    }

    #[test]
    fn command_name_appears_in_generated_output() {
        let config = awsenc_config();
        for shell in &["bash", "zsh", "fish", "powershell"] {
            let script = generate_shell_init(shell, &config).unwrap();
            assert!(
                script.contains("awsenc"),
                "{shell} output should contain command name 'awsenc'"
            );
        }
    }

    #[test]
    fn helper_function_appears_in_bash_output() {
        let script = generate_shell_init("bash", &awsenc_config()).unwrap();
        assert!(
            script.contains("awsenc-use()"),
            "bash output should contain helper function 'awsenc-use()'"
        );
        assert!(
            script.contains("AWSENC_PROFILE"),
            "bash output should contain helper function body"
        );
    }

    #[test]
    fn pwsh_alias_works_for_powershell() {
        // "pwsh" should be treated the same as "powershell"
        let script = generate_shell_init("pwsh", &awsenc_config()).unwrap();
        assert!(script.contains("PowerShell"));
    }

    // Pure helper unit tests

    #[test]
    fn pattern_alternation_empty_produces_empty_string() {
        assert_eq!(pattern_alternation(&[]), "");
    }

    #[test]
    fn pattern_alternation_single_pattern() {
        let pats = vec!["AWS_ACCESS_KEY_ID".to_string()];
        assert_eq!(pattern_alternation(&pats), "AWS_ACCESS_KEY_ID");
    }

    #[test]
    fn pattern_alternation_multiple_patterns_joined_by_pipe() {
        let pats = vec![
            "AWS_ACCESS_KEY_ID".to_string(),
            "AWS_SECRET_ACCESS_KEY".to_string(),
            "AWS_SESSION_TOKEN".to_string(),
        ];
        assert_eq!(
            pattern_alternation(&pats),
            "AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN"
        );
    }

    #[test]
    fn fish_pattern_match_empty_produces_empty_string() {
        assert_eq!(fish_pattern_match(&[]), "");
    }

    #[test]
    fn fish_pattern_match_multiple_patterns_joined_by_pipe() {
        let pats = vec!["SSO_JWT".to_string(), "COMPANY_JWT".to_string()];
        assert_eq!(fish_pattern_match(&pats), "SSO_JWT|COMPANY_JWT");
    }

    #[test]
    fn bash_warning_lines_empty_list_is_empty_string() {
        assert_eq!(bash_warning_lines(&[]), "");
    }

    #[test]
    fn bash_warning_lines_single_line_uses_4_space_indent() {
        let warning = vec!["danger!".to_string()];
        let result = bash_warning_lines(&warning);
        assert_eq!(result, "    echo \"danger!\" >&2");
    }

    #[test]
    fn bash_warning_lines_multiple_lines_joined_by_newline() {
        let warning = vec!["line one".to_string(), "line two".to_string()];
        let result = bash_warning_lines(&warning);
        assert!(result.contains("line one"));
        assert!(result.contains("line two"));
        assert!(result.contains('\n'));
        let parts: Vec<&str> = result.split('\n').collect();
        assert_eq!(parts.len(), 2);
    }

    #[test]
    fn bash_warning_lines_escapes_double_quotes() {
        let warning = vec!["say \"hello\"".to_string()];
        let result = bash_warning_lines(&warning);
        assert!(
            result.contains("\\\"hello\\\""),
            "double quotes must be escaped: {result}"
        );
    }

    #[test]
    fn fish_warning_lines_empty_list_is_empty_string() {
        assert_eq!(fish_warning_lines(&[]), "");
    }

    #[test]
    fn fish_warning_lines_single_line_uses_8_space_indent() {
        let warning = vec!["oops".to_string()];
        let result = fish_warning_lines(&warning);
        assert!(result.starts_with("        echo \"oops\""));
    }

    #[test]
    fn fish_warning_lines_escapes_double_quotes() {
        let warning = vec!["say \"hello\"".to_string()];
        let result = fish_warning_lines(&warning);
        assert!(
            result.contains("\\\"hello\\\""),
            "double quotes must be escaped: {result}"
        );
    }

    #[test]
    fn powershell_warning_lines_empty_list_is_empty_string() {
        assert_eq!(powershell_warning_lines(&[]), "");
    }

    #[test]
    fn powershell_warning_lines_single_line_contains_write_host() {
        let warning = vec!["danger".to_string()];
        let result = powershell_warning_lines(&warning);
        assert!(result.contains("Write-Host"));
        assert!(result.contains("ForegroundColor Yellow"));
        assert!(result.contains("danger"));
    }

    #[test]
    fn powershell_warning_lines_escapes_double_quotes_with_backtick() {
        let warning = vec!["say \"hello\"".to_string()];
        let result = powershell_warning_lines(&warning);
        assert!(
            result.contains("`\"hello`\""),
            "double quotes must use backtick escape: {result}"
        );
    }

    #[test]
    fn powershell_warning_lines_multiple_lines_joined_by_newline() {
        let warning = vec!["line one".to_string(), "line two".to_string()];
        let result = powershell_warning_lines(&warning);
        let parts: Vec<&str> = result.split('\n').collect();
        assert_eq!(parts.len(), 2);
        assert!(parts[0].contains("line one"));
        assert!(parts[1].contains("line two"));
    }
}
