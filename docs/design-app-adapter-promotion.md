# Design: Promote enclaveapp-app-adapter into enclave

## Problem

Each enclave app (awsenc, sso-jwt, sshenc, npmenc) independently re-implements the same infrastructure: config directory management, credential storage, TPM bridge servers, file I/O patterns, and CLI scaffolding. The `enclaveapp-app-adapter` crate in npmenc already solves the generic portions of this problem but is trapped in a single app's repo. Meanwhile, awsenc and sso-jwt have near-identical TPM bridge binaries, identical binary cache formats, and duplicated config management.

## Goal

Move generic infrastructure into enclave so consuming apps become thin configuration + domain logic. The three integration types from the adapter become first-class concepts in the library.

## Integration Type Taxonomy

Every enclave app falls into one of three categories based on how it delivers secrets to the target application:

### Type 1: Helper/Plugin (HelperTool)
The target application has native support for auth plugins, helpers, or credential processes. Secrets never leave our process boundary — we return them on demand.

**Examples:**
- **sshenc** — SSH agent protocol; keys are used in-process
- **gitenc** — git `credential.helper` / SSH signing via agent
- **awsenc** — `credential_process` in `~/.aws/config`

### Type 2: Environment Variable Interpolation (EnvInterpolation)
The target application reads a config file that supports `${ENV_VAR}` interpolation. We write a config with placeholders and invoke the app with secret env vars set via `execve()`.

**Examples:**
- **npmenc/npxenc** — `.npmrc` supports `${NPM_TOKEN}` interpolation
- **sso-jwt** (when used to supply JWTs to other Type 2 tools)

### Type 3: Temp Materialized Config (TempMaterializedConfig)
The target application can only read a static config file. We write secrets to a temp file with restricted permissions, invoke the app with `--config /tmp/xxx/app.conf`, and delete after.

**Examples:**
- Applications with no env var support in their config format
- **sso-jwt** (for apps that need a JWT written to a file)

## Architecture After Promotion

```
consuming app (awsenc, sshenc, sso-jwt, npmenc)
  │  Thin layer: AppSpec, domain-specific bindings, CLI
  │
  ├── enclaveapp-app-adapter (promoted to enclave)
  │   ├── BindingStore / SecretStore — credential management
  │   ├── AppSpec / IntegrationType — app classification
  │   ├── Resolver — find executables
  │   ├── Launcher — run with injected secrets
  │   ├── TempConfig — lifecycle-managed temp files
  │   └── prepare_launch — integration selection + config injection
  │
  ├── enclaveapp-app-storage (existing)
  │   └── Platform-auto-detected encrypt/decrypt/sign
  │
  ├── enclaveapp-tpm-bridge (NEW: consolidated from app-specific bridges)
  │   └── Generic JSON-RPC TPM bridge server
  │
  └── enclaveapp-core (existing)
      └── Traits, types, metadata, atomic I/O
```

## New Crates in enclave

### 1. `enclaveapp-app-adapter` (moved from npmenc)

Move as-is with these changes:
- Remove `NPMENC_CONFIG_DIR` hardcoding → use `app_data_dir_with_env(app_name, None)` which defaults to `"{APP_NAME_UPPER}_CONFIG_DIR"` pattern, auto-derived from app_name
- Change `key_label: "adapter-secrets"` → parameterize via `SecretStoreConfig { key_label, access_policy }`
- Add feature flag `mock` that re-exports `MemoryBindingStore` and `MemorySecretStore` (for testing in consuming apps)

**Dependencies:** enclaveapp-app-storage, enclaveapp-core, base64, dirs, fs4, serde, serde_json, sha2, shlex, tempfile, thiserror

### 2. `enclaveapp-tpm-bridge` (NEW: consolidated bridge server)

Extract the near-identical JSON-RPC bridge server from awsenc-tpm-bridge and sso-jwt-tpm-bridge into a generic library. The consuming apps' bridge binaries become ~20-line `main()` functions.

**Current state:** awsenc-tpm-bridge/src/main.rs and sso-jwt-tpm-bridge/src/main.rs are >90% identical. Both:
- Read JSON-RPC from stdin
- Parse `BridgeRequestCompat` with `effective_access_policy()`
- Match method: init, encrypt, decrypt, destroy/delete
- Manage `TpmStorage` state
- Write JSON responses to stdout

**Library API:**
```rust
pub struct BridgeServer {
    storage: Option<Box<dyn EncryptionStorage>>,
}

impl BridgeServer {
    pub fn new() -> Self;
    pub fn run_stdio(&mut self) -> Result<()>;  // read stdin, dispatch, write stdout
}
```

Consuming bridge binaries become:
```rust
fn main() {
    let mut server = enclaveapp_tpm_bridge::BridgeServer::new();
    if let Err(e) = server.run_stdio() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
```

### 3. `enclaveapp-cache` (NEW: shared binary cache format)

Extract the identical binary cache format from awsenc-core and sso-jwt-lib. Both use:
- 4-byte magic, 1-byte version, 1-byte flags, timestamp(s), length-prefixed ciphertext blobs
- Header-only peek for state classification (fresh/stale/expired without decrypting)
- Atomic file I/O

**Library API:**
```rust
pub struct CacheFormat {
    magic: [u8; 4],
    version: u8,
}

pub struct CacheHeader {
    pub flags: u8,
    pub expires_at: i64,
    pub issued_at: i64,
}

pub struct CacheEntry {
    pub header: CacheHeader,
    pub blobs: Vec<Vec<u8>>,  // encrypted payloads
}

impl CacheFormat {
    pub fn new(magic: [u8; 4]) -> Self;
    pub fn read_header(path: &Path) -> Result<Option<CacheHeader>>;
    pub fn read(path: &Path) -> Result<Option<CacheEntry>>;
    pub fn write(path: &Path, entry: &CacheEntry) -> Result<()>;
}
```

Each app provides its magic bytes and blob count. awsenc uses `AWSE` with 2 blobs (credentials + optional Okta session). sso-jwt uses `SJWT` with 1 blob (JWT). The library handles the format; the app handles encryption/decryption of the blobs.

## Changes to Consuming Apps

### awsenc
- Delete `awsenc-tpm-bridge/src/tpm.rs` (~300 lines) → use `enclaveapp-tpm-bridge::BridgeServer`
- Slim `awsenc-tpm-bridge/src/main.rs` to ~20 lines
- Replace `awsenc-core/src/cache.rs` binary format code with `enclaveapp-cache`
- Keep domain logic: Okta auth, STS, AWS profile management

### sso-jwt
- Same TPM bridge consolidation as awsenc
- Replace `sso-jwt-lib/src/cache.rs` binary format code with `enclaveapp-cache`
- Keep domain logic: OAuth device flow, JWT validation, heartbeat

### sshenc
- Already thin (Type 1: agent protocol). Minimal changes.
- Could use adapter's `Resolver` for `find_trusted_binary` if signatures match
- TPM bridge not applicable (sshenc uses signing, not encryption)

### npmenc
- Move `enclaveapp-app-adapter/` out of npmenc repo entirely
- Update Cargo.toml path deps to `../enclave/crates/enclaveapp-app-adapter`
- Remove the now-empty adapter directory from npmenc

## Feature Flags

```toml
[features]
# Platform backends (existing)
signing = []
encryption = []

# Adapter features (new)
adapter = ["dep:enclaveapp-app-adapter"]
adapter-mock = ["adapter", "enclaveapp-app-adapter/mock"]
cache = ["dep:enclaveapp-cache"]
tpm-bridge-server = ["dep:enclaveapp-tpm-bridge"]
```

Apps opt-in to what they need:
- **awsenc:** `encryption`, `adapter` (for future), `cache`, `tpm-bridge-server`
- **sso-jwt:** `encryption`, `adapter` (for future), `cache`, `tpm-bridge-server`
- **sshenc:** `signing` (minimal, no adapter needed yet)
- **npmenc:** `encryption`, `adapter`

## Implementation Plan

### Phase 1: Move enclaveapp-app-adapter into enclave (this PR)
1. Copy `enclaveapp-app-adapter/` from npmenc to `enclave/crates/enclaveapp-app-adapter/`
2. Fix the `NPMENC_CONFIG_DIR` hardcoding → derive env var name from app_name
3. Add to workspace members
4. Update npmenc's Cargo.toml to point to the new location
5. Tests pass in both repos

### Phase 2: Consolidate TPM bridge servers
1. Create `enclaveapp-tpm-bridge` crate in enclave
2. Extract shared bridge server logic
3. Slim awsenc-tpm-bridge and sso-jwt-tpm-bridge to thin wrappers
4. Tests pass in all 3 repos

### Phase 3: Extract shared binary cache format
1. Create `enclaveapp-cache` crate in enclave
2. Extract format from awsenc-core and sso-jwt-lib
3. Apps use library with their magic bytes
4. Tests pass in all 3 repos

### Phase 4: Adopt adapter in awsenc and sso-jwt (future)
1. awsenc: migrate profile/credential management to adapter's BindingStore/SecretStore
2. sso-jwt: same migration
3. Both apps get thinner, adapter-based lifecycle management

## What NOT to Extract

- **Domain-specific auth logic** (Okta, STS, OAuth device flow, SSH agent protocol) — stays in apps
- **CLI argument structures** — per-app by nature (each app has unique commands)
- **TOML config schemas** — per-app (awsenc profiles differ from sso-jwt servers)
- **App-specific cache blob semantics** — only the binary wire format is shared, not what's inside the blobs

## Risks

1. **Path dependency management:** All repos use `path = "../enclave/crates/..."`. Adding a new crate to enclave requires updating Cargo.toml in each consuming repo. Mitigated by doing all changes in coordinated PRs.

2. **Feature flag complexity:** More features means more possible build configurations to test. Mitigated by CI testing the common combinations.

3. **Breaking the adapter API during promotion:** The adapter is currently only used by npmenc. Promotion is the time to fix API issues before other apps adopt it.
