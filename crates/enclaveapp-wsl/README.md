# enclaveapp-wsl

WSL detection and shell configuration for enclave.

Provides generic, app-name-parameterized WSL integration so that sshenc, awsenc, and sso-jwt can share the same detection and shell config injection logic.

## Capabilities

### WSL detection

- `is_wsl()` -- returns true if running inside WSL (checks `$WSL_DISTRO_NAME` and `/proc/version`)
- `detect_distros()` -- enumerates installed WSL distributions from the Windows host (runs `wsl --list --quiet`, resolves home paths to UNC paths)

### Shell config management

Inject and remove managed blocks in `.bashrc`, `.zshrc`, or `.profile`:

```rust
use enclaveapp_wsl::{ShellBlockConfig, install_block, uninstall_block};

let config = ShellBlockConfig::new("myapp", r#"
export MY_VAR="hello"
"#);

install_block(Path::new("/home/user/.bashrc"), &config)?;
// Inserts:
//   # BEGIN myapp managed block -- do not edit
//   export MY_VAR="hello"
//   # END myapp managed block

uninstall_block(Path::new("/home/user/.bashrc"), &config)?;
// Removes the managed block, preserves everything else
```

### Syntax validation

Before committing shell config changes, validate with the target shell:

```rust
validate_shell_syntax(Path::new("/home/user/.bashrc"), "bash")?;
```

Runs `bash -n` (or `zsh -n`) on the file. If the shell isn't available, validation is silently skipped.

## Design

- App name is a parameter, not hardcoded -- different apps produce different markers
- Idempotent: installing twice returns `AlreadyPresent`
- Safe removal: only the managed block is deleted, surrounding content is preserved
- CRLF normalization: handles Windows-style line endings in shell configs
