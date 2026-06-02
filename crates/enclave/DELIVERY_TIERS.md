# Application Delivery Tiers

How enclave apps deliver secrets to target processes. This document describes the
`SecureProcess`, `TempSecretFile`, and credential lifecycle APIs used by apps that wrap
third-party tools with hardware-backed secrets.

---

## Tier overview

Every enclave app is classified by how it delivers secrets to the target application,
ordered from most controlled to least controlled:

| Type | Name | Secret boundary | Mechanism |
|------|------|----------------|-----------|
| **1** | HelperTool | Never leaves process | SSH agent, `credential_process`, RPC |
| **2** | EnvInterpolation | Env vars via `execve()`, zeroized after | `.npmrc` `${NPM_TOKEN}` |
| **3** | TempMaterializedConfig | Temp file, shredded on drop | Apps with no env/plugin support |
| **4** | CredentialSource | Consumer controls; no delivery guardrail | Token providers |

---

## Type 1 — HelperTool

No generic API. Type 1 apps implement their own protocol (SSH agent wire format,
AWS `credential_process` JSON, git credential helper). Use `SignerHandle` and
`EncryptorHandle` directly.

---

## Type 2 — EnvInterpolation

`SecureProcess` launches a child process with secret env vars mlocked before spawn and
zeroized after the child exits. The child inherits `RLIMIT_CORE=0` on Unix.

```rust
use enclave::SecureProcess;

SecureProcess::new("/usr/bin/npm")
    .args(["install"])
    .secret_env("NPM_TOKEN", token_value)  // mlocked, zeroized after child exits
    .scrub("NPM_TOKEN_*")                  // remove inherited vars matching pattern
    .run()?;
```

`exec()` replaces the current process (Unix `execve`). Note: secrets cannot be zeroized
after `exec()` — use `run()` when zeroization matters.

---

## Type 3 — TempMaterializedConfig

`TempSecretFile` writes secrets to the most secure temp location available:

- **Linux / WSL2**: `memfd_create` — anonymous in-memory file, no filesystem path.
  Target receives `/proc/self/fd/{N}`. Secret never touches disk.
- **macOS**: 0o600 temp file in 0o700 temp directory, shredded on drop.
- **Windows**: restricted-permission temp directory, shredded on drop.

```rust
use enclave::TempSecretFile;

let tmp = TempSecretFile::create(config_content)?;
// Pass tmp.path() to the target program as a --config flag.
// tmp drops here → file shredded.
```

---

## Type 4 — CredentialSource

For apps that obtain credentials from external providers (OAuth, SAML, Vault) and cache
them with hardware-backed encryption. The credential lifecycle is managed by
`CredentialState` and `LifecyclePolicy`.

```rust
use enclave::{classify_credential, CredentialState, LifecyclePolicy};

struct MyPolicy;
impl LifecyclePolicy for MyPolicy {
    fn max_age_secs(&self, risk_level: u8) -> u64 { 3600 }
    fn refresh_window_secs(&self, risk_level: u8) -> u64 { 600 }
    fn grace_period_secs(&self, risk_level: u8) -> u64 { 120 }
}

match classify_credential(issued_at, session_start, now, &MyPolicy, risk_level) {
    CredentialState::Fresh         => { /* serve from cache */ }
    CredentialState::RefreshWindow => { /* try background refresh, serve stale */ }
    CredentialState::Grace         => { /* serve stale, warn */ }
    CredentialState::Expired       => { /* must re-acquire */ }
}
```

Type 4 apps secure credential **acquisition and caching**; they don't control how the
credential is used after it's handed out.
