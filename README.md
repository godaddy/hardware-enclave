# Enclave

Build hardware-secured wrapper binaries for any application — from SSH agents to npm registries — with minimal code and maximum platform coverage.

## The problem

Every application that handles secrets — SSH keys, API tokens, cloud credentials, registry auth — stores them as plaintext files on disk. An attacker with user-level access can steal them silently.

Hardware security modules (Secure Enclave, TPM 2.0) can make private keys non-exportable and operations require biometric confirmation, but integrating with each platform's HSM APIs is hundreds of hours of platform-specific work that every tool would have to repeat independently.

## The solution

`enclave` provides a shared Rust substrate that handles all the hard parts — platform detection, HSM integration, key lifecycle, encrypted storage, process launching, config file management — so you can build a thin wrapper binary (an **enclave app**) that secures any target application with hardware-backed keys.

A new enclave app needs only its domain-specific logic. Everything else is shared:

- **Automatic platform detection** — Secure Enclave on macOS, TPM 2.0 on Windows, TPM or keyring on Linux, WSL bridge for cross-OS access
- **Four integration strategies** — choose the right one for your target app and the library handles the rest
- **Cross-platform from day one** — one codebase targets macOS Apple Silicon, Windows x64/ARM64, Linux x64/ARM64, and 7+ shell environments
- **Reusable CI/CD** — shared GitHub Actions workflows for building, testing, and releasing across all platforms
- **Shared infrastructure** — config block injection, path quoting, binary cache formats, TPM bridge servers, program resolution, and more

## Integration types

Every enclave app falls into one of four categories. Types 1-3 provide **controlled delivery** with guardrails that prevent user mistakes. Type 4 is a **credential source** that securely acquires and caches credentials but cannot control what happens after delivery. See [DESIGN.md](DESIGN.md#application-integration-types) for full definitions.

| Type | Strategy | How it works | Delivery guardrails | Example |
|:----:|----------|-------------|:-------------------:|---------|
| **1** | [HelperTool](DESIGN.md#type-1-helpertool) | Target app calls back for credentials on demand via a protocol | **Strongest** — secrets never leave the enclave app's process | [sshenc](https://github.com/godaddy/sshenc), [awsenc](https://github.com/godaddy/awsenc) |
| **2** | [EnvInterpolation](DESIGN.md#type-2-envinterpolation) | Config with `${ENV_VAR}` placeholders; secrets injected via `execve()` | **Strong** — secrets in memory only, never on disk | [npmenc](https://github.com/godaddy/npmenc) |
| **3** | [TempMaterializedConfig](DESIGN.md#type-3-tempmaterializedconfig) | Secrets written to temp file (0o600), deleted after exit | **Moderate** — secrets briefly on disk with restricted permissions | Any app with no plugin or env var support |
| **4** | [CredentialSource](DESIGN.md#type-4-credentialsource) | Obtains and caches credentials; hands them to any consumer | **None** — consumer decides what to do with the secret | [sso-jwt](https://github.com/godaddy/sso-jwt) |

Types 1-3 wrap a target application and control the secret's entire lifecycle. The adapter selects the most secure: Type 1 > Type 2 > Type 3. Type 4 apps secure the **acquisition and storage** of credentials but cannot prevent consumers from exporting them to env vars, piping to files, or other uncontrolled use.

## Built with enclave

| Application | Type | What it does | Lines of app-specific code |
|---|:---:|---|---|
| [sshenc](https://github.com/godaddy/sshenc) | 1 | Hardware-backed SSH key management via agent protocol | ~3,000 |
| [awsenc](https://github.com/godaddy/awsenc) | 1 | Encrypted AWS credential caching via `credential_process` | ~2,500 |
| [sso-jwt](https://github.com/godaddy/sso-jwt) | 4 | Encrypted JWT caching; credential source for other enclave apps | ~2,000 |
| [npmenc](https://github.com/godaddy/npmenc) | 2 | Secure npm/npx token wrapper via `.npmrc` env var interpolation | ~2,500 |

Each app is a thin layer of domain logic on top of ~15,000 lines of shared infrastructure.

## Platform and environment support

### Hardware security

| OS | Architecture | Hardware | Private key exportable? | Notes |
|---|---|---|:---:|---|
| macOS | Apple Silicon | Secure Enclave | **No** — SE does all crypto | Handle blob AES-256-GCM wrapped via Keychain. Works signed and unsigned. |
| Windows | x64, ARM64 | TPM 2.0 | **No** — TPM-bound | Windows Hello for user presence. |
| Linux (glibc) | x64, ARM64 | TPM 2.0 | **No** — TPM-bound | Requires `tss2` libraries. |
| Linux (glibc, no TPM) | x64, ARM64 | System keyring | Encrypted at rest | P-256 key encrypted via D-Bus Secret Service. |
| WSL2 (Ubuntu, Debian) | x64 | Windows host TPM | **No** — TPM-bound | JSON-RPC bridge to Windows host for encryption; agent bridge for SSH signing. |

macOS requires Apple Silicon (Secure Enclave always present). Windows requires TPM 2.0 (guaranteed on Windows 11). Linux without TPM requires a system keyring (D-Bus Secret Service). See [DESIGN.md — Security levels](DESIGN.md#security-levels) for the full analysis.

### Signing and encryption capabilities

| Platform | Signing | Encryption | Backend |
|---|:---:|:---:|---|
| macOS | Yes | Yes | CryptoKit via Swift bridge |
| Windows | Yes | Yes | CNG NCrypt/BCrypt |
| Linux (TPM) | Yes | Yes | `tss-esapi` |
| Linux (keyring) | Yes | Yes | `p256`/`aes-gcm` + system keyring |
| WSL | App-dependent | Yes | JSON-RPC bridge to Windows host |

### Shell environments

Enclave apps are native binaries tested across every major shell:

| Shell | Binary invocation | Shell-init / completions | Env var passthrough (Type 2) |
|-------|:-:|:-:|:-:|
| bash (3.2 + 5.3) | pass | pass | pass |
| zsh | pass | pass | pass |
| fish | pass | pass | pass |
| tcsh | pass | — | — |
| dash (POSIX sh) | pass | — | pass |
| nushell | pass | — | — |

On Windows: **PowerShell**, **Command Prompt**, **Git Bash**, and **WSL2** (Ubuntu, Debian). See [DESIGN.md — Shell compatibility](DESIGN.md#shell-compatibility) and [Windows shell environments](DESIGN.md#windows-shell-environments).

### Cryptography

All backends use **ECDSA P-256** — the only curve supported by all three hardware targets (Secure Enclave, Windows TPM, Linux TPM). This provides **128 bits of classical security**. P-256 is not post-quantum secure, but the data protected by enclave apps is short-lived (minutes to hours). See [DESIGN.md — Cryptographic primitives](DESIGN.md#cryptographic-primitives).

## Workspace crates

| Crate | What it provides |
|---|---|
| [enclaveapp-core](crates/enclaveapp-core/) | Traits, types, metadata, config block injection, path quoting |
| [enclaveapp-app-storage](crates/enclaveapp-app-storage/) | Automatic platform detection → encrypt/decrypt/sign |
| [enclaveapp-app-adapter](crates/enclaveapp-app-adapter/) | Secret delivery substrate: binding/secret stores, program resolver, process launcher, temp config |
| [enclaveapp-apple](crates/enclaveapp-apple/) | macOS Secure Enclave via CryptoKit Swift bridge |
| [enclaveapp-windows](crates/enclaveapp-windows/) | Windows TPM 2.0 via CNG |
| [enclaveapp-linux-tpm](crates/enclaveapp-linux-tpm/) | Linux TPM 2.0 via `tss-esapi` |
| [enclaveapp-keyring](crates/enclaveapp-keyring/) | Linux keyring-encrypted P-256 keys |
| [enclaveapp-wsl](crates/enclaveapp-wsl/) | WSL detection, distro config, managed shell blocks |
| [enclaveapp-bridge](crates/enclaveapp-bridge/) | JSON-RPC bridge protocol + WSL client |
| [enclaveapp-tpm-bridge](crates/enclaveapp-tpm-bridge/) | Shared TPM bridge server (parameterized per app) |
| [enclaveapp-cache](crates/enclaveapp-cache/) | Shared binary cache format |
| [enclaveapp-build-support](crates/enclaveapp-build-support/) | Shared build.rs for Windows PE resources |

## Feature flags

Platform crates expose `signing` and `encryption` features. Applications enable only what they need:

```toml
# SSH signing app
enclaveapp-apple = { features = ["signing"] }

# Credential caching app
enclaveapp-apple = { features = ["encryption"] }
```

`enclaveapp-app-storage` handles platform selection automatically and is the preferred integration point for application code.

## Architecture

```
your enclave app (thin domain logic)
  │
  ├── enclaveapp-app-adapter       binding/secret stores, resolver, launcher
  │
  ├── enclaveapp-app-storage       platform-detected encrypt/decrypt/sign
  │     ├── enclaveapp-apple       Secure Enclave (macOS)
  │     ├── enclaveapp-windows     TPM 2.0 (Windows)
  │     ├── enclaveapp-linux-tpm   TPM 2.0 (Linux)
  │     ├── enclaveapp-keyring     keyring-encrypted keys (Linux fallback)
  │     └── enclaveapp-bridge      WSL → Windows TPM bridge
  │
  ├── enclaveapp-tpm-bridge        shared bridge server binary
  ├── enclaveapp-cache             shared binary cache format
  └── enclaveapp-core              traits, types, metadata, utilities
```

## Building

Requires Rust 1.75+. macOS builds require Xcode (for Swift bridge). Linux TPM builds require `tpm2-tss` development libraries.

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

## Documentation

- [DESIGN.md](DESIGN.md) — Architecture, security levels, platform details, cryptographic primitives, integration type taxonomy, shell compatibility
- [docs/design-app-adapter-promotion.md](docs/design-app-adapter-promotion.md) — Adapter promotion and deduplication design

## License

MIT
