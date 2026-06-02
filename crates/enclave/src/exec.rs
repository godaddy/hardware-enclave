// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitStatus;

use enclaveapp_app_adapter::{launcher, LaunchRequest, ResolutionStrategy, ResolvedProgram};

use crate::error::{Error, Result};

pub use enclaveapp_app_adapter::IntegrationType;

/// Launch a child process with hardware-backed secrets injected.
///
/// The [`run()`][SecureProcess::run] method provides full security guarantees:
/// - Secret env var values are mlocked before spawn and zeroized after the child exits.
/// - The spawned child inherits `RLIMIT_CORE=0` on Unix (preventing core dumps of the
///   secret-laden environment).
///
/// The [`exec()`][SecureProcess::exec] method provides **weaker** guarantees:
/// - Secrets are NOT mlocked (they are passed via `Command::env` without locking).
/// - Secrets are NOT zeroized (the current process is replaced; no cleanup runs).
/// - Prefer [`run()`][SecureProcess::run] for Type 2 secret delivery. Use
///   [`exec()`][SecureProcess::exec] only when you need to replace the current
///   process image and accept the weaker guarantees.
pub struct SecureProcess {
    program: PathBuf,
    args: Vec<OsString>,
    secret_env: BTreeMap<String, String>,
    env_additions: BTreeMap<String, String>,
    env_removals: Vec<String>,
    scrub_patterns: Vec<String>,
}

impl std::fmt::Debug for SecureProcess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureProcess")
            .field("program", &self.program)
            .field("args", &self.args)
            .field("env_additions", &self.env_additions)
            .field("env_removals", &self.env_removals)
            .field("scrub_patterns", &self.scrub_patterns)
            // secret_env intentionally omitted
            .finish()
    }
}

impl SecureProcess {
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            secret_env: BTreeMap::new(),
            env_additions: BTreeMap::new(),
            env_removals: Vec::new(),
            scrub_patterns: Vec::new(),
        }
    }

    pub fn arg(mut self, a: impl Into<OsString>) -> Self {
        self.args.push(a.into());
        self
    }

    pub fn args(mut self, args: impl IntoIterator<Item = impl Into<OsString>>) -> Self {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Inject a secret value as an environment variable (Type 2 delivery).
    /// The value is mlocked and zeroized after the child exits.
    pub fn secret_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.secret_env.insert(key.into(), value.into());
        self
    }

    /// Add a non-secret environment variable (e.g. a config file path).
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env_additions.insert(key.into(), value.into());
        self
    }

    /// Remove an environment variable from the child's environment.
    pub fn env_remove(mut self, key: impl Into<String>) -> Self {
        self.env_removals.push(key.into());
        self
    }

    /// Scrub inherited env vars matching this pattern before spawning.
    /// Accepts exact names or prefix patterns ending in `*`.
    pub fn scrub(mut self, pattern: impl Into<String>) -> Self {
        self.scrub_patterns.push(pattern.into());
        self
    }

    /// Spawn the child and wait for it to exit. Zeroizes secret env vars after child returns.
    pub fn run(self) -> Result<ExitStatus> {
        let mut env_overrides: BTreeMap<String, String> = BTreeMap::new();
        for (k, v) in self.secret_env {
            env_overrides.insert(k, v);
        }
        for (k, v) in self.env_additions {
            env_overrides.insert(k, v);
        }

        let request = LaunchRequest {
            program: ResolvedProgram {
                path: self.program,
                fixed_args: Vec::new(),
                strategy: ResolutionStrategy::ExplicitPath,
                shell_hint: None,
            },
            args: self
                .args
                .into_iter()
                .map(|s| s.to_string_lossy().into_owned())
                .collect(),
            env_overrides,
            env_removals: self.env_removals,
            env_scrub_patterns: self.scrub_patterns,
        };

        launcher::run(request).map_err(|e| Error::KeyOperation {
            operation: "exec".into(),
            detail: e.to_string(),
        })
    }

    /// Replace the current process image via execve() (Unix).
    /// On Windows, falls back to run() since CreateProcess cannot replace the calling image.
    ///
    /// WARNING: secret env var zeroization is NOT possible after exec() because
    /// the current process no longer exists. Use run() when zeroization matters.
    #[allow(clippy::needless_return, unreachable_code)]
    pub fn exec(self) -> Result<std::convert::Infallible> {
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            let mut cmd = std::process::Command::new(&self.program);
            cmd.args(&self.args);
            for (k, v) in &self.secret_env {
                cmd.env(k, v);
            }
            for (k, v) in &self.env_additions {
                cmd.env(k, v);
            }
            for k in &self.env_removals {
                cmd.env_remove(k);
            }
            let err = cmd.exec();
            return Err(Error::KeyOperation {
                operation: "exec".into(),
                detail: err.to_string(),
            });
        }
        #[cfg(not(unix))]
        {
            let status = self.run()?;
            let code = status.code().unwrap_or(1);
            std::process::exit(code);
        }
    }
}

/// A temporary file containing secret content, shredded (zeroed) on drop.
///
/// Platform selection:
/// - Linux/WSL2: `memfd_create` (anonymous in-memory file, no filesystem path).
/// - macOS: 0o600 temp file in a 0o700 temp directory, shredded on drop.
/// - Windows: restricted-permission temp directory, shredded on drop.
pub struct TempSecretFile {
    #[cfg(target_os = "linux")]
    _inner: TempSecretInner,
    #[cfg(not(target_os = "linux"))]
    _inner: enclaveapp_app_adapter::TempConfig,
    path_str: String,
}

// Fields held only for their Drop side-effects (auto-cleanup of the fd/file).
#[cfg(target_os = "linux")]
#[allow(dead_code)]
enum TempSecretInner {
    Memfd(enclaveapp_app_adapter::MemfdConfig),
    Fallback(enclaveapp_app_adapter::TempConfig),
}

impl std::fmt::Debug for TempSecretFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TempSecretFile")
            .field("path", &self.path_str)
            .finish()
    }
}

impl TempSecretFile {
    /// Write text content to a platform-appropriate secret temp location.
    pub fn create(content: &str) -> Result<Self> {
        Self::create_bytes(content.as_bytes())
    }

    /// Write binary content.
    pub fn create_bytes(content: &[u8]) -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            match enclaveapp_app_adapter::create_memfd_config("enclave-secret", "secret", content) {
                Ok(memfd) => {
                    let path_str = memfd.path().to_string_lossy().into_owned();
                    Ok(Self {
                        _inner: TempSecretInner::Memfd(memfd),
                        path_str,
                    })
                }
                Err(_) => {
                    // memfd not available (e.g. older kernel); fall back to temp file.
                    let tc = enclaveapp_app_adapter::TempConfig::write(
                        "enclave-secret",
                        "secret",
                        content,
                    )
                    .map_err(|e| Error::KeyOperation {
                        operation: "temp_secret".into(),
                        detail: e.to_string(),
                    })?;
                    let path_str = tc.path().to_string_lossy().into_owned();
                    Ok(Self {
                        _inner: TempSecretInner::Fallback(tc),
                        path_str,
                    })
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let tc = enclaveapp_app_adapter::TempConfig::write("enclave-secret", "secret", content)
                .map_err(|e| Error::KeyOperation {
                    operation: "temp_secret".into(),
                    detail: e.to_string(),
                })?;
            let path_str = tc.path().to_string_lossy().into_owned();
            Ok(Self {
                _inner: tc,
                path_str,
            })
        }
    }

    /// The path to pass to the target process.
    pub fn path(&self) -> &str {
        &self.path_str
    }
}
