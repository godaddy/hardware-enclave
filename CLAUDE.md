# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`enclave` is a shared Rust library for hardware-backed key management across macOS (Secure Enclave via CryptoKit), Windows (TPM 2.0 via CNG), and Linux (keyring or TPM 2.0). It provides signing (ECDSA P-256) and encryption (ECIES via ECDH P-256 + AES-GCM) behind feature flags, plus WSL integration and a TPM bridge for WSL→Windows communication.

Three applications consume this library:
- **sshenc** — SSH key management (signing)
- **awsenc** — AWS credential caching (encryption)
- **sso-jwt** — SSO JWT caching (encryption)

## Build & Development

Rust workspace. Requires Rust 1.75+. macOS builds need Xcode (for swiftc).

```bash
# Build with all features (macOS)
cargo build --workspace --features enclaveapp-apple/signing,enclaveapp-apple/encryption,enclaveapp-keyring/signing,enclaveapp-keyring/encryption

# Build with all features (Windows)
cargo build --workspace --features enclaveapp-windows/signing,enclaveapp-windows/encryption,enclaveapp-keyring/signing,enclaveapp-keyring/encryption

# Build with all features (Linux)
cargo build --workspace --features enclaveapp-keyring/signing,enclaveapp-keyring/encryption

# Test everything
cargo test --workspace --features enclaveapp-apple/signing,enclaveapp-apple/encryption,enclaveapp-keyring/signing,enclaveapp-keyring/encryption

# Lint
cargo clippy --workspace --all-targets --features enclaveapp-apple/signing,enclaveapp-apple/encryption,enclaveapp-keyring/signing,enclaveapp-keyring/encryption -- -D warnings

# Format
cargo fmt --all -- --check
```

## Architecture

Rust workspace under `crates/`:

- **enclaveapp-core** — Platform-agnostic types, traits (`EnclaveKeyManager`, `EnclaveSigner`, `EnclaveEncryptor`), metadata (atomic writes, dir locking, JSON key metadata), config helpers (TOML load/save), error types, platform detection. No FFI.
- **enclaveapp-apple** — macOS Secure Enclave via CryptoKit Swift bridge. Unified bridge supporting both P256.Signing (feature `signing`) and P256.KeyAgreement (feature `encryption`). ECIES uses ephemeral ECDH + X9.63 KDF + AES-GCM.
- **enclaveapp-windows** — Windows TPM 2.0 via CNG NCrypt/BCrypt. ECDSA signing (feature `signing`) and ECIES encryption (feature `encryption`). Shared provider/key/export modules. P1363↔DER conversion in cross-platform `convert` module.
- **enclaveapp-wsl** — WSL detection (`is_wsl`, `detect_distros`), managed shell config block injection/removal for `.bashrc`/`.zshrc`, syntax validation. Parameterized by app name.
- **enclaveapp-bridge** — JSON-RPC over stdin/stdout TPM bridge. Client side (WSL discovers and calls Windows bridge binary) and protocol types. Server implementation lives in consuming apps.
- **enclaveapp-keyring** — Keyring-backed P-256 backend for Linux. Private keys encrypted via system keyring (D-Bus Secret Service). Requires glibc.
- **enclaveapp-test-software** — Test-only plaintext P-256 backend. NOT for production.
- **enclaveapp-app-storage** — High-level shared application storage. Automatic platform detection, key initialization, policy mismatch handling, and encrypt/decrypt/sign wrapping. Used by all three consuming apps (awsenc, sso-jwt, sshenc) to eliminate duplicated secure storage code. Includes `MockEncryptionStorage` behind the `mock` feature.
- **enclaveapp-app-adapter** — Generic secret delivery substrate. BindingStore/SecretStore for credential management, AppSpec with 3 integration types, program resolver, process launcher, config block injection, temp config lifecycle. Used by npmenc; available for adoption by other apps.
- **enclaveapp-tpm-bridge** — Shared JSON-RPC TPM bridge server. Parameterized by app_name/key_label.
- **enclaveapp-cache** — Shared binary cache format with configurable magic bytes and length-prefixed blobs.
- **enclaveapp-build-support** — Shared build.rs helper for Windows PE resource compilation.
- **enclaveapp-test-support** — `MockKeyBackend` implementing all three traits with deterministic in-memory operations. XOR-based mock crypto for testing control flow without hardware.

### macOS Keychain Protection Classes — CRITICAL

There are **two separate protection class decisions** in the Apple backend, and
they **MUST use different values**. Mixing them up causes catastrophic user
impact (broken biometric caching → Touch ID on every sign → key regeneration
required, because the SE key's access control is immutable after creation).

| What | Function | Protection class | Why |
|------|----------|-----------------|-----|
| **SE key access control** | `makeAccessControl()` in `bridge.swift` | `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` | Required for `touchIDAuthenticationAllowableReuseDuration` biometric caching in CryptoKit. Using `AfterFirstUnlock` silently breaks LAContext reuse — every sign requires Touch ID. |
| **Keychain wrapping key** | `keychain_store()` in `bridge.swift` | `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` | Must survive sleep/wake. `WhenUnlocked` purges the keybag class key on device lock, making the wrapping key inaccessible to background agents. |

**NEVER do a blanket find-and-replace of protection class constants.** These two
use sites have different requirements for different reasons. If you change one,
verify you are not changing the other.

**The SE key access control is immutable.** Once a key is generated with a given
`SecAccessControl`, that access control is baked into the Secure Enclave
Processor. There is no migration path — the key must be deleted and
regenerated. This means getting `makeAccessControl()` wrong forces every user
to regenerate all their keys. This has already happened once (PR #158) and
must never happen again.

### Key Patterns

- `EnclaveKeyManager` trait is the base — `EnclaveSigner` and `EnclaveEncryptor` extend it.
- Feature flags (`signing`, `encryption`) control which trait implementations are compiled.
- The Swift bridge compiles all functions regardless of features; feature gates are Rust-side only.
- ECIES ciphertext format: `[0x01 version][65-byte ephemeral pubkey][12-byte nonce][ciphertext][16-byte GCM tag]`.
- Key metadata stored as JSON `.meta` files. Public keys cached as `.pub` files. macOS signing keys also have `.handle` files (CryptoKit dataRepresentation).
- All file writes are atomic (write to `.tmp`, rename into place) with directory locking via `flock`.
- Apps pass their `app_name` (e.g., "sshenc", "awsenc") which determines the keys directory path and CNG key name prefix.

### Process Hardening

Any binary that consumes `enclave` is by definition handling
hardware-backed secret material. **All such binaries MUST call
`enclaveapp_core::process::harden_process()` as the first line of
`main()`** — before any argument parsing, before any environment
inspection, before any decrypt. This is non-optional. Secret material is
present in your process memory the moment you load it; the protections
have to be in place first or they don't apply.

`harden_process()` applies, best-effort, the platform-appropriate
mitigations:

- **All Unix:** `setrlimit(RLIMIT_CORE, 0)` — no core dumps.
- **Linux:** `prctl(PR_SET_DUMPABLE, 0)` — `/proc/<pid>/mem` becomes
  root-only, `ptrace` attach from non-root same-UID peers is denied.
- **Linux:** `prctl(PR_SET_NO_NEW_PRIVS, 1)` — subsequent `exec*` cannot
  gain setuid / file-capabilities privileges.
- **Windows:** strict handle checks, extension-point disable, image-load
  restrictions (no remote or low-mandatory-label DLLs).

For secret memory beyond this baseline:

- `enclaveapp_core::process::mlock_buffer()` / `munlock_buffer()` lock
  pages to prevent swap-out. The launcher does this automatically for
  env_overrides; consuming apps should `mlock` any other buffers
  containing live plaintext key material.
- Credential strings should be wrapped in `zeroize::Zeroizing<…>` or
  scrubbed via `Zeroize::zeroize()` when their lifetime ends. In-memory
  caches that are replaced on a TTL boundary should `zeroize` the
  previous value before dropping it.

### Consuming-app integration checklist

When a new consuming app is added (or an existing app is reviewed), confirm:

- [ ] `harden_process()` is the first line of `main()` for every binary
      the app ships (CLI, agent, bridge — all of them).
- [ ] Live plaintext credential buffers in the app's own memory are
      either short-lived stack values or are wrapped to `zeroize` on
      drop / on cache replacement.
- [ ] No code path writes plaintext credentials to disk under the
      app's control. Tests use `ENCLAVEAPP_MOCK_STORAGE` (gated behind
      the `mock` feature on the dev-dependency, never compiled into
      release).
- [ ] The app surfaces its threat model — what it protects, what it
      doesn't, residual risks accepted — in a `THREAT_MODEL.md` at the
      repo root, sibling to `SECURITY.md`.
- [ ] Cross-tenant safety: any process-wide cache (e.g. a decrypted
      bundle cache) is keyed on the storage location it came from, so
      a long-running agent cannot return one tenant's bundle to
      another.

### Type 3 Implementation Guide

When building a Type 3 (TempMaterializedConfig) enclave app, use `enclaveapp_app_adapter::create_platform_config()` — it automatically selects the best mechanism:
- **Linux and WSL2**: `memfd_create` — anonymous in-memory file, no filesystem path. Target app receives `/proc/self/fd/{N}`. Secrets never touch disk.
- **Windows (including Git Bash)**: Temp file in restricted directory with auto-cleanup and shred-on-drop.
- **macOS**: Temp file with 0o600 permissions and shred-on-drop.

Platform-specific functions are also available directly: `create_memfd_config()` (Linux), `create_anonymous_config()` (Windows), `TempConfig::write()` (all platforms).

### Type 4 Implementation Guide

When building a Type 4 (CredentialSource) enclave app:
- Use `enclaveapp_app_adapter::credential_cache` for lifecycle management (CredentialState, LifecyclePolicy)
- Implement the `LifecyclePolicy` trait to define risk-level-based expiration tiers
- Use `classify_credential()` to check cache state without decrypting (avoids unnecessary HSM operations)
- Zeroize credential strings after printing or passing to child processes
- Use `exec_with_credential_owned()` for the `exec` subcommand (auto-zeroizes)

## Application Integration Types

Every enclave app is classified by how it delivers secrets to the target application. See [DESIGN.md — Application integration types](DESIGN.md#application-integration-types) for full definitions.

| Type | Name | Delivery guardrails | Example apps |
|------|------|:------------------:|-------------|
| **Type 1** | HelperTool | Strongest — secrets never leave process | sshenc (SSH agent), awsenc (`credential_process`) |
| **Type 2** | EnvInterpolation | Strong — secrets in env vars via `execve()` | npmenc (`.npmrc` `${NPM_TOKEN}`) |
| **Type 3** | TempMaterializedConfig | Moderate — secrets briefly on disk (0o600) | Apps with no plugin or env var support |
| **Type 4** | CredentialSource | None — consumer controls what happens | sso-jwt (credential provider for any consumer) |

Types 1-3 wrap a target app and control the secret's lifecycle; the adapter selects the most secure: Type 1 > Type 2 > Type 3. Type 4 apps secure credential acquisition and caching but hand the secret to consumers without controlling its subsequent use.

## Platform

See [DESIGN.md — Platform support](DESIGN.md#platform-support) for the full matrix.

**Target architectures:** macOS Apple Silicon, Windows x64, Windows ARM64, Linux x64, Linux ARM64.

**Hardware security backends:**
- macOS: Secure Enclave via CryptoKit (Swift bridge compiled by build.rs)
- Windows: TPM 2.0 via CNG (NCrypt/BCrypt APIs via `windows` crate)
- Linux (glibc): TPM 2.0 via `tss-esapi`, with keyring-encrypted fallback
- Linux (musl): Not supported (no keyring or TPM)

**Windows shell environments:** PowerShell, Command Prompt, Git Bash (native Windows binary), WSL2 Ubuntu/Debian (Linux binary with JSON-RPC bridge to Windows TPM).

All crates compile (as stubs) on all platforms for cross-compilation support.

## Commits

Do not add Co-Authored-By lines for Claude Code in commit messages.
