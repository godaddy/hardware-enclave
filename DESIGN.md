# libenclaveapp Design Document

## Goal

Provide a shared Rust substrate for hardware-backed key management so derived applications do not each reimplement:

- platform detection
- Secure Enclave / TPM bootstrap
- key lifecycle and metadata storage
- WSL bridge discovery
- keyring fallback behavior

The current workspace supports four active consumers:

| Application | Primary use |
|---|---|
| `sshenc` | signing |
| `awsenc` | encrypted credential caching |
| `sso-jwt` | encrypted token caching |
| `npmenc` | encrypted secret storage through an adapter layer |

## Workspace layout

```
libenclaveapp/
  crates/
    enclaveapp-core/          Traits, types, metadata, shared utilities, process hardening
    enclaveapp-app-storage/   App-level bootstrap for encryption/signing
    enclaveapp-app-adapter/   Secret delivery substrate (BindingStore, SecretStore, launcher, ...)
    enclaveapp-apple/         macOS Secure Enclave backend (CryptoKit + Keychain wrapping)
    enclaveapp-windows/       Windows TPM backend (CNG)
    enclaveapp-linux-tpm/     Linux TPM backend (tss-esapi)
    enclaveapp-keyring/       Keyring-backed backend (Linux production)
    enclaveapp-test-software/ Test-only plaintext backend (not shipped in production)
    enclaveapp-wsl/           WSL detection and shell/profile helpers
    enclaveapp-bridge/        JSON-RPC bridge protocol + WSL client
    enclaveapp-tpm-bridge/    Shared TPM bridge server (JSON-RPC stdio, used by awsenc/sshenc/sso-jwt)
    enclaveapp-cache/         Shared binary cache file format (magic + length-prefixed blobs)
    enclaveapp-build-support/ Shared build.rs helpers (Windows PE resource compilation)
    enclaveapp-test-support/  Mock backend for tests
```

## Layering

### `enclaveapp-core`

Defines the durable contracts:

- `EnclaveKeyManager`
- `EnclaveSigner`
- `EnclaveEncryptor`
- `KeyType`
- `AccessPolicy`
- metadata and config helpers

This crate has no platform FFI.

### `enclaveapp-app-storage`

This is the application-facing integration layer. It wraps platform selection and key initialization so application code can say:

- create encryption storage for app `awsenc`
- create signing backend for app `sshenc`

It also centralizes WSL bridge lookup, access-policy handling, and app-specific key names.

### Platform backends

- `enclaveapp-apple`: Secure Enclave via CryptoKit Swift bridge
- `enclaveapp-windows`: TPM 2.0 via CNG
- `enclaveapp-linux-tpm`: TPM 2.0 via `tss-esapi`
- `enclaveapp-keyring`: keyring-backed backend for Linux without TPM (keys encrypted via system keyring)
- `enclaveapp-test-software`: test-only plaintext backend (not for production)

### WSL support

- `enclaveapp-bridge` defines the JSON-RPC bridge **client** and wire protocol
- `enclaveapp-tpm-bridge` is the shared JSON-RPC bridge **server** (runs natively on Windows; parameterized by `app_name` / `key_label`). `awsenc-tpm-bridge`, `sshenc-tpm-bridge`, and `sso-jwt-tpm-bridge` are thin wrappers over it.
- `enclaveapp-wsl` handles WSL detection, distro enumeration, shell/profile changes, and install helpers

### Shared infrastructure

Beyond the backends, a handful of crates provide cross-consumer utilities:

- **`enclaveapp-app-adapter`** — generic secret-delivery substrate used by Type 1-3 apps. Provides `BindingStore`, `SecretStore` (with typed `SecretRead { Present, Redacted, Absent }` read path that replaces the string-sentinel `"<redacted>"` round-trip), the program resolver, the `execve()`-based launcher (with `mlock` + zeroize of env-override bytes, optional `with_env_scrub(patterns)` to remove matching inherited env vars from both child and parent, and per-child `RLIMIT_CORE = 0`), provenance tracking, state-locking, and `TempConfig::write` (with the per-platform `create_platform_config()` memfd/tempfile selection).
- **`enclaveapp-cache`** — the shared on-disk cache file format (`[magic][version][flags][length-prefixed blobs]`). Consumed by sso-jwt's token cache and awsenc's credential cache.
- **`enclaveapp-tpm-bridge`** — the shared bridge server crate; delegated to by the per-app bridge binaries.
- **`enclaveapp-build-support`** — factored-out helpers for Windows `build.rs` resource compilation.

### Process hardening

`enclaveapp_core::process::harden_process()` is called as the first line of every enclave app binary's `main()`. It applies, best-effort (failures warn but don't abort):

- `setrlimit(RLIMIT_CORE, 0)` on all Unix — no core dumps that could capture secret buffers.
- `prctl(PR_SET_DUMPABLE, 0)` on Linux — `/proc/<pid>/mem` becomes root-only, `ptrace` attach from same-UID peers is denied.
- `prctl(PR_SET_NO_NEW_PRIVS, 1)` on Linux — subsequent `exec*()` can't gain setuid/file-capabilities privileges.
- `SetProcessMitigationPolicy` on Windows (safe subset):
  - `ProcessStrictHandleCheckPolicy` with `RaiseExceptionOnInvalidHandleReference` + `HandleExceptionsPermanentlyEnabled` — turns handle-confusion bugs into `STATUS_INVALID_HANDLE` rather than silent misuse.
  - `ProcessExtensionPointDisablePolicy` with `DisableExtensionPoints` — blocks AppInit_DLLs, shim engines, and other legacy DLL-injection extension points.
  - `ProcessImageLoadPolicy` with `NoRemoteImages` + `NoLowMandatoryLabelImages` — refuses DLL loads from UNC paths and low-integrity files.

See `crates/enclaveapp-core/src/process.rs`. `mlock_buffer` / `munlock_buffer` are exposed for consumer crates that want to pin specific byte buffers in RAM. Type 2 apps also clamp `RLIMIT_CORE = 0` on the **spawned child** via a `pre_exec` hook in `enclaveapp-app-adapter::launcher`, so a crash of the wrapped target (e.g. `npm`) cannot core-dump its secret-laden environment.

## Access policy model

All backends share the same policy vocabulary:

- `None`
- `Any`
- `BiometricOnly`
- `PasswordOnly`

Applications decide which policy to request. Platform backends map that policy to the best native behavior available.

## Cryptographic primitives

### ECDSA P-256 (secp256r1 / prime256v1)

All signing and encryption operations use **NIST P-256** (also known as secp256r1 or prime256v1). This is the sole elliptic curve supported across all backends.

**Why P-256:** It is the only curve universally supported by all three hardware targets — Apple Secure Enclave, Windows TPM 2.0 (CNG), and Linux TPM 2.0 (`tss-esapi`). The Secure Enclave in particular only supports P-256 for key agreement and signing. This constraint drives the choice for the entire library.

**Security strength:** P-256 provides approximately **128 bits of classical security**, comparable to AES-128. This exceeds current best-practice minimums (the NIST recommendation is 112 bits through 2030+). P-256 is widely deployed in TLS 1.3, SSH, code signing, and WebAuthn.

**Post-quantum status:** P-256 is **not post-quantum secure**. A sufficiently capable quantum computer running Shor's algorithm could break ECDSA and ECDH on P-256 in polynomial time. However:

- No such quantum computer exists today, and current estimates place cryptographically relevant quantum computers at least a decade away.
- The data protected by enclave apps (cached credentials, session tokens, SSH signatures) is **short-lived** — typically minutes to hours. Even if a quantum computer were available, the secrets would have expired before they could be extracted.
- When post-quantum algorithms are added to the hardware security modules (Apple has indicated post-quantum support in future SE revisions; TPM 2.0 has a PQC profile in draft), the library can adopt them. The version byte in the ECIES format and the trait-based architecture allow new algorithms without breaking existing caches.

For the use cases served by enclave apps (credential caching, SSH signing, token management), P-256 provides strong security today with a clear migration path to post-quantum algorithms when hardware support materializes.

### Signing: ECDSA with SHA-256

- **Curve:** P-256
- **Hash:** SHA-256
- **Signature format:** DER-encoded ASN.1 (converted from P1363 on Windows CNG). The `enclaveapp-windows` crate includes a `convert` module for P1363 ↔ DER conversion.
- **Use case:** SSH key signing (`sshenc`), git commit/tag signing (`gitenc`)

### Encryption: ECIES (ECDH + AES-256-GCM)

- **Key agreement:** ECDH P-256 with ephemeral sender key
- **KDF:** X9.63 KDF with SHA-256 (derives 32-byte AES key from shared secret)
- **Symmetric cipher:** AES-256-GCM (authenticated encryption)
- **Use case:** Credential caching (`awsenc`), token caching (`sso-jwt`), secret storage (`npmenc`)

**Ciphertext format:**

```
[0x01 version] [65-byte ephemeral pubkey (SEC1 uncompressed)] [12-byte nonce] [ciphertext] [16-byte GCM tag]
```

This format is consistent across all backends — a ciphertext produced by the Secure Enclave can be decrypted by the software backend and vice versa (given the same private key material). The version byte allows future format changes without breaking existing caches.

## Platform support

### Target architectures

| OS | Architecture | Hardware security | Backend |
|---|---|---|---|
| macOS | Apple Silicon (aarch64) | Secure Enclave | `enclaveapp-apple` via CryptoKit Swift bridge |
| Windows | x86_64 | TPM 2.0 | `enclaveapp-windows` via CNG (NCrypt/BCrypt) |
| Windows | ARM64 (aarch64) | TPM 2.0 | `enclaveapp-windows` via CNG (NCrypt/BCrypt) |
| Linux | x86_64 (glibc) | TPM 2.0 | `enclaveapp-linux-tpm` via `tss-esapi` |
| Linux | ARM64 (glibc) | TPM 2.0 | `enclaveapp-linux-tpm` via `tss-esapi` |
| Linux | x86_64 (glibc, no TPM) | System keyring | `enclaveapp-keyring` via D-Bus Secret Service |
| Linux | ARM64 (glibc, no TPM) | System keyring | `enclaveapp-keyring` via D-Bus Secret Service |

All architectures support both signing and encryption.

**Minimum OS requirements and hardware security guarantees:**

- **macOS:** Apple Silicon required (Secure Enclave always present). Intel Macs and macOS VMs without SE passthrough are not supported.
- **Windows:** TPM 2.0 required (Windows 10 or Windows 11). TPM 1.2 is not supported — it lacks ECDSA P-256 and ECDH support (only RSA and SHA-1). The CNG Microsoft Platform Crypto Provider targets TPM 2.0 exclusively. Windows 11 guarantees TPM 2.0 is present; Windows 10 machines must have TPM 2.0 hardware.
- **Linux:** TPM 2.0 used when available (glibc only, via `tss-esapi`). Falls back to software keys when no TPM is present. No minimum OS version — TPM availability depends on hardware and kernel configuration.

### Security levels

Not all backends provide the same level of key protection. The properties differ between **signing keys** (used by `sshenc` for SSH/git signatures) and **encryption keys** (used by `awsenc`, `sso-jwt`, `npmenc` for credential/token caching).

#### Signing key security

Signing keys are long-lived identity keys (e.g., SSH keys). At Levels 1-3, the hardware security module **is** the signer — it performs the ECDSA signature operation directly and the private key material never exists in software, in memory, or on disk.

| Level | Backend | Who signs? | Private key exportable? | User presence | Key storage |
|:-----:|---------|-----------|:----------------------:|---------------|-------------|
| **1** | macOS Secure Enclave | **The SE hardware.** `sshenc` sends data to the SE via CryptoKit; the SE performs ECDSA P-256 internally and returns the signature. The private key never exists outside the chip. Works for both signed and unsigned binaries on Apple Silicon. | **No** — impossible. Even root cannot extract it. The `dataRepresentation` on disk is an opaque SE handle (not key material); it is AES-256-GCM wrapped under a 32-byte key stored in the login Keychain (service `com.godaddy.<app>`, account `<label>`). File format `[EHW1 magic][nonce][ciphertext][tag]`. | Touch ID / biometric enforced by SE hardware per-signature (when access policy is set). | Secure Enclave coprocessor + Keychain-wrapped handle on disk (0600). |
| **2** | Windows TPM 2.0 | **The TPM hardware.** CNG sends signing requests to the TPM via NCrypt. | **No** — key is a non-exportable TPM object. | Windows Hello (biometric/PIN) enforced per-signature via `NCRYPT_UI_POLICY`. | TPM 2.0 chip. |
| **3** | Linux TPM 2.0 | **The TPM hardware.** Signing performed by the TPM via `tss-esapi`. | **No** — key is TPM-resident. | Not enforced (no standard Linux biometric API). | TPM 2.0 device (`/dev/tpmrm0`). glibc only. |
| **4** | Software (Linux glibc, keyring) | **Software.** The P-256 private key is decrypted from the keyring into memory and used for signing via the `p256` crate. | **Yes (encrypted at rest)** — P-256 private key on disk, encrypted via system keyring (D-Bus Secret Service / GNOME Keyring / KWallet). | Not enforced. | `~/.config/{app}/keys/` encrypted via keyring. |
| **—** | `enclaveapp-test-software` | **Software, plaintext.** Test-only. Not used in any shipped binary. Never selected at runtime. | Yes (plaintext). | Not enforced. | Exists only to exercise the trait plumbing in unit tests. Linux musl builds are **not a supported production target** for libenclaveapp. |

#### Encryption key security

Encryption keys protect cached secrets (AWS credentials, JWTs, npm tokens). At Levels 1-3, the hardware performs the ECDH key agreement internally — the private key never exists in software. The encrypted data can only be decrypted on the same device that created the key.

The blast radius of encryption key compromise is further bounded by the expiration of the cached data (typically minutes to hours).

| Level | Backend | Who decrypts? | Private key exportable? | User presence | Cached data protection |
|:-----:|---------|--------------|:----------------------:|---------------|----------------------|
| **1** | macOS Secure Enclave | **The SE hardware.** ECDH key agreement happens inside the SE. The shared secret is derived internally; only the AES-GCM decryption of the ciphertext body happens in software. Handle blob is AES-256-GCM wrapped under a Keychain-held key (see `crates/enclaveapp-apple/src/keychain_wrap.rs`). | **No** — impossible. | Touch ID / biometric can be required per-decrypt. | Ciphertext on disk can only be decrypted by the SE that created the key. Full disk access is insufficient without the SE, and the Keychain wrapping key gates same-UID handle theft. |
| **2** | Windows TPM 2.0 | **The TPM hardware** performs ECDH. | **No** — TPM-bound. | Windows Hello can be required per-decrypt. | Only decryptable on the same machine's TPM. |
| **3** | Linux TPM 2.0 | **The TPM hardware** via `tss-esapi`. | **No** — TPM-bound. | Not enforced. | Same machine-binding as Windows TPM. |
| **4** | Software (Linux glibc, keyring) | **Software.** P-256 key decrypted from keyring. | **Yes (encrypted at rest)** — keyring-protected. | Not enforced. | Keyring-encrypted key protects cache at rest. |
| **—** | `enclaveapp-test-software` | **Software, plaintext.** Test-only; not selected at runtime. | Yes (plaintext). | Not enforced. | Exists to exercise the trait plumbing in unit tests. Linux musl is not a supported production target. |

#### macOS: Secure Enclave access and key persistence

All supported macOS hardware (Apple Silicon) has a Secure Enclave, and **CryptoKit's `SecureEnclave.P256` APIs work without code signing or entitlements**. Both signed and unsigned builds get full SE access — the SE creates the key and performs all signing/key agreement operations. The private key material never leaves the hardware.

The `com.apple.developer.secure-enclave` entitlement is a **Security.framework** concept for Keychain-stored SE keys (`SecItemAdd` with `kSecAttrTokenIDSecureEnclave`). Since libenclaveapp uses CryptoKit's `dataRepresentation` for key persistence (not Security.framework), the entitlement is not required.

**Handle protection for unsigned apps.** The SE's `dataRepresentation` is an opaque handle blob that allows the same device's SE to reconstruct the key reference. While the private key itself cannot be extracted from this blob, the blob is stored as a file on disk — and another process running as the same user could copy it and use it to request SE operations.

**Implemented.** `generate_and_save_key` creates a fresh 32-byte AES-256 wrapping key per label, stores it in the login keychain as a `kSecClassGenericPassword` item (service `com.godaddy.<app>`, account `<label>`), AES-256-GCM encrypts the `dataRepresentation` under that key, and writes the sealed blob to `.handle` with the magic prefix `EHW1`. Format: `[magic(4)][nonce(12)][ciphertext][tag(16)]`. See `crates/enclaveapp-apple/src/keychain_wrap.rs`.

Legacy plaintext `.handle` files are accepted by `load_handle` for transparent migration; they re-wrap on the next rotation. `delete_key` removes the keychain entry alongside the on-disk artifacts.

The Keychain's per-application access control then gates same-user handle theft:

- **Signed app (code-signed with Developer ID):** The Keychain ACL is bound to the app's code signature. Other apps cannot access the wrapping key. Handle files are protected against same-user attacks.

- **Unsigned app (e.g., Homebrew, `cargo build`):** The Keychain ACL is bound to the binary's hash. The user must authorize access on first use (password/biometric prompt) and click "Always Allow." **After a Homebrew update**, the binary hash changes, invalidating the Keychain ACL — the user must re-authorize. This is a UX trade-off, not a security degradation: the SE still performs all cryptographic operations, and the wrapping key prevents other processes from using the handle.

In both cases, the SE performs all ECDSA signing and ECDH key agreement. The AES-256-GCM wrapping layer protects the persistence of the SE handle, not the cryptographic operations themselves.

#### macOS path in practice (signed and unsigned)

There is one code path. `CryptoKit`'s `SecureEnclave.P256.*.PrivateKey` APIs work **without** a Developer ID cert or entitlements, and the SE always performs all ECDSA and ECDH operations regardless of signing state. The signing identity only affects the login-keychain UX for the AES-256-GCM wrapping key (see the previous section):

- **Ad-hoc signed** (default from `swiftc` / `rustc`, `cargo build`, `brew install`): one "Always Allow" prompt per binary rebuild at the same path. Silent until the next upgrade.
- **Trusted signing identity** (e.g. Apple Developer ID): zero prompts across rebuilds — the keychain scopes access by identity, not hash.
- **Different binary at a different path**: always prompted, regardless of signing.

A second "entitled" path (`SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclave` + `kSecAttrIsPermanent`, storing the SE key directly in the Keychain and eliminating the `.handle` file) is **blocked on distribution**. The required `keychain-access-groups` entitlement is AMFI-restricted and needs a provisioning profile — unavailable to Homebrew, `cargo install`, and ad-hoc / self-signed binaries. See `THREAT_MODEL.md` for details. For the distribution models libenclaveapp targets, the Path-2 wrapping already closes the same-UID `.handle` theft threat.

#### Linux

Glibc builds with the system keyring (D-Bus Secret Service / GNOME Keyring / KWallet) use the `enclaveapp-keyring` backend to encrypt private key files at rest (Level 4). Glibc builds also use TPM 2.0 via `tss-esapi` when it's available (Level 3). Linux musl is not a supported production target; the `enclaveapp-test-software` plaintext backend exists only for unit-test plumbing.

### Windows shell environments

On Windows, enclave apps operate across multiple shell environments. Each has distinct behavior for path resolution, environment variable handling, and config file locations:

| Environment | Shell | Path style | Config location | Notes |
|---|---|---|---|---|
| PowerShell | `pwsh.exe` / `powershell.exe` | `C:\Users\...` | `%LOCALAPPDATA%` | Native Windows; full TPM access |
| Command Prompt | `cmd.exe` | `C:\Users\...` | `%LOCALAPPDATA%` | Native Windows; full TPM access |
| Git Bash (MSYS2) | `bash.exe` (MinGW) | `/c/Users/...` | `$APPDATA` or `$HOME` | Runs native Windows binaries; TPM available |
| WSL2 (Ubuntu) | `bash` (Linux) | `/home/user/...` | `~/.config/` | Linux binary; TPM via JSON-RPC bridge to Windows host |
| WSL2 (Debian) | `bash` (Linux) | `/home/user/...` | `~/.config/` | Linux binary; TPM via JSON-RPC bridge to Windows host |

**WSL architecture:** WSL2 distros run a real Linux kernel and use native Linux binaries. To access the Windows host's TPM, enclave apps use the JSON-RPC bridge (`enclaveapp-bridge`): the Linux client spawns the Windows bridge binary (located under `/mnt/c/`) via interop and communicates over stdin/stdout. The bridge server (`enclaveapp-tpm-bridge`) runs natively on the Windows host and performs TPM operations.

**Git Bash:** Unlike WSL, Git Bash runs native Windows executables. The Windows binary works directly with the TPM — no bridge is needed. However, path handling requires care: Git Bash presents Windows paths in Unix-style (`/c/Users/...`), and SSH config requires forward slashes even on Windows.

For `sshenc`, WSL signing is handled by the SSH agent bridge path (named pipe relay via `npiperelay`) rather than the JSON-RPC encryption bridge.

### Shell compatibility

Enclave apps are native binaries and work under any shell that can invoke executables. The following shells have been tested on macOS:

| Shell | Version tested | Binary invocation | Shell-init / completions | Env var passthrough (Type 2) |
|-------|---------------|:-----------------:|:------------------------:|:----------------------------:|
| bash (macOS built-in) | 3.2.57 | pass | pass | pass |
| bash (Homebrew) | 5.3.9 | pass | pass | pass |
| zsh (macOS built-in) | 5.9 | pass | pass | pass |
| fish (Homebrew) | 4.6.0 | pass | pass (completions) | pass |
| tcsh (macOS built-in) | 6.21 | pass | — | — |
| dash (Homebrew) | POSIX sh | pass | — | pass |
| nushell (Homebrew) | 0.112.1 | pass | — | — |

**Shell-init scripts** are provided for bash, zsh, and fish. Other shells can invoke the binaries directly.

**Type 2 env var passthrough** (npmenc/npxenc) is verified to work under bash, zsh, fish, and dash. The `execve()` boundary ensures env vars are passed correctly regardless of shell.

**Not tested:** macOS's built-in ksh (`/bin/ksh`) is broken on Apple Silicon — it segfaults on trivial commands like `echo hello` (exit code 139). This is a macOS system issue unrelated to enclave apps. ksh is excluded from the test matrix.

## Application integration types

Every enclave app is classified by how it delivers secrets to the target application. The `enclaveapp-app-adapter` crate defines four integration types, listed from most-controlled to least-controlled:

### Type 1: HelperTool

The target application has native support for auth plugins, credential helpers, or agents. Secrets never leave the enclave app's process boundary — they are returned on demand via a protocol (SSH agent, `credential_process`, etc.). This is the most secure integration because secrets are never written to disk or exposed in environment variables.

### Type 2: EnvInterpolation

The target application reads a config file that supports environment variable interpolation (`${ENV_VAR}`). The enclave app writes a config with placeholders and invokes the target with secret env vars set via `execve()`. Secrets exist briefly as environment variables but never touch disk in plaintext. The `execve()` boundary is critical — the env vars must not be set in a shell where they would be visible in shell history or to child processes beyond the target.

### Type 3: TempMaterializedConfig

The target application can only read a static config file with no env var support. The enclave app writes secrets to a temp file with restricted permissions (0o600 on Unix), invokes the target with a config path override (e.g. `--config /tmp/xxx/app.conf`), and deletes the file after the process exits.

Use `enclaveapp_app_adapter::create_platform_config()` to automatically select the best mechanism:

- **Linux and WSL2**: Uses `memfd_create` to create an anonymous in-memory file with **no filesystem path at all**. The target app receives `/proc/self/fd/{N}` which looks like a regular file path. The secret never touches the filesystem, completely eliminating same-user temp file read attacks. The file is sealed (read-only) and cleaned up when the fd closes. WSL2 runs a real Linux kernel so `memfd_create` works natively.
- **Windows (including Git Bash)**: Uses a temp file in a restricted temp directory with auto-cleanup on drop. The file is shredded (overwritten with zeros) before deletion.
- **macOS**: Uses a temp file with 0o600 permissions and shred-on-drop.

The platform-specific variants (`create_memfd_config` on Linux, `create_anonymous_config` on Windows) are also available directly for apps that need finer control.

The adapter selects the least-secret-exposing integration automatically: Type 1 > Type 2 > Type 3.

### Type 4: CredentialSource

The enclave app does not wrap a target application. Instead, it **is** the credential source — it obtains credentials from an external provider (OAuth, SAML, Vault, etc.), encrypts and caches them locally with hardware-backed storage, and hands them to any consumer that asks.

Unlike Types 1-3, a Type 4 app provides **no guardrails on how the credential is used after delivery**. The consumer could be a Type 1/2/3 enclave app that delivers the credential securely, or it could be a shell script that exports it to an environment variable, or a user who pipes it to a file. The Type 4 app's responsibility ends at secure acquisition and caching — it cannot enforce how the credential is consumed.

This makes Type 4 the most composable but least controlled integration. A single Type 4 app can serve many consumers:

- **Best case:** A Type 1/2/3 enclave app consumes the credential with proper delivery guardrails (e.g., `npmenc` uses `sso-jwt` as a token source with env var interpolation)
- **Adequate case:** A user runs `sso-jwt get | pbcopy` to get a credential for manual use
- **Worst case:** A CI script stores the credential in a plaintext file — the Type 4 app cannot prevent this

The security value of a Type 4 app is in the **acquisition and caching** layers: hardware-encrypted storage at rest, automatic expiration and refresh, risk-level-based lifecycle management, and biometric-gated access. What happens after `get` returns the credential is outside its control.

### Consumer mapping

| Consumer | Ships binaries | Integration Type | Mechanism |
|---|---|---|---|
| `sshenc` | `sshenc`, `sshenc-agent`, `sshenc-keygen`, `sshenc-pkcs11`, `gitenc`, `sshenc-tpm-bridge` | Type 1 (HelperTool) | SSH agent protocol; keys used in-process for signing |
| `awsenc` | `awsenc`, `awsenc-tpm-bridge` | Type 1 (HelperTool) | `credential_process` directive in `~/.aws/config` |
| `npmenc` | `npmenc`, `npxenc` | Type 2 (EnvInterpolation) | `.npmrc` with `${NPM_TOKEN}` placeholders |
| `sso-jwt` | `sso-jwt`, `sso-jwt-napi`, `sso-jwt-tpm-bridge` | Type 4 (CredentialSource) | Obtains and caches JWTs; consumed by Type 1/2/3 apps as a token provider |

## WSL bridge discovery

The WSL client (`enclaveapp-bridge::client::find_bridge`) searches a fixed list of `/mnt/c/` paths for the Windows bridge binary — PATH-based fallback via `which` was removed because a user-writable `$PATH` entry could substitute a malicious bridge, and the library performs no Authenticode verification on the resolved executable. Candidate paths:

```
/mnt/c/Program Files/<app>/<app>-tpm-bridge.exe
/mnt/c/ProgramData/<app>/<app>-tpm-bridge.exe
/mnt/c/Program Files/<app>/<app>-bridge.exe
/mnt/c/ProgramData/<app>/<app>-bridge.exe
```

Operators who install the bridge outside these locations must symlink into one of them. The bridge protocol enforces additional runtime bounds:

- `MAX_BRIDGE_RESPONSE_BYTES = 64 KB` — oversized responses are rejected.
- `DEFAULT_BRIDGE_REQUEST_TIMEOUT = 120 s` — covers Windows Hello prompts; override via `ENCLAVEAPP_BRIDGE_TIMEOUT_SECS`.
- `BRIDGE_SHUTDOWN_TIMEOUT = 5 s` after stdin close before the child is killed.
- `BridgeSession::Drop` kills and reaps the child — no zombie processes.

Before spawning the bridge binary, `require_bridge_is_authenticode_signed` (`crates/enclaveapp-bridge/src/client.rs`) parses the PE header's `IMAGE_DIRECTORY_ENTRY_SECURITY` slot and refuses binaries that carry no Authenticode signature block — so the "attacker replaces the admin-path install with their own `cargo build` exe" case fails closed. Full `WinVerifyTrust` chain verification is out of scope from the WSL side and is an acknowledged residual risk. Dev builds can opt out via `ENCLAVEAPP_BRIDGE_ALLOW_UNSIGNED=1`.

Concurrent bridge calls from two threads in the same client process are serialized by a process-wide `BRIDGE_SESSION_LOCK: Mutex<()>` held across spawn → request → shutdown. Without it, two threads would fire two back-to-back Windows Hello prompts, contend for the same TPM key slot, and double-bill TPM op quota. Mutex poisoning is recovered with `into_inner()` so one crashed session does not wedge the client for the process lifetime.

## Credential cache file tamper + rollback

Credential caches on disk have an unencrypted header (magic, version, flags, timestamps, risk level, optional session-expiration fields) and an AES-GCM ciphertext. The ciphertext body is already tag-authenticated. Header fields and older-ciphertext replay are addressed by an app-layer envelope that wraps the plaintext before encryption:

- **Envelope format** (`crates/enclaveapp-cache/src/envelope.rs`):
  `[4B "APL1"][32B SHA-256(header bytes)][8B BE u64 counter][payload]`
  passed to `EncryptionStorage::encrypt`.
- **Header binding.** `SHA-256` covers the exact unencrypted header bytes; tampering with any header field is detected on decrypt as an envelope hash mismatch. The trait signature did not change, so all backends (SE, CNG, Linux TPM, keyring, WSL bridge) inherit the protection uniformly.
- **Rollback counter.** The 8-byte counter is bumped on every successful write and persisted in a sibling `<cache>.counter` sidecar guarded by an exclusive `fs4` flock. On decrypt, the embedded counter must be `>= sidecar`; older ciphertexts are rejected as `Rollback { observed, expected_at_least }`.
- **Legacy-cache migration.** `unwrap_plaintext` accepts pre-envelope payloads (no `APL1` magic) as legacy with `counter = 0`. Existing installs continue to decrypt; the first write after upgrade lands in the new format.

Consumer-layer defenses layer on top:

- **`max(header, config)` on read** — sso-jwt and awsenc always clamp the effective risk level to at least the configured minimum (defense-in-depth for pre-migration legacy caches).
- **Server-side expiration is authoritative** — STS credentials carry `Expiration`; JWTs carry `exp`. Even a rolled-back ciphertext expires at the real server-side deadline.
- **Payload-embedded timestamps** — both consumers recheck `session_start` / `token_iat` / `expiration` *after* decrypt.

Residual risk: an attacker who can rewrite **both** the `.enc` cache and the `.counter` sidecar in sync can still replay within the server-side validity window. Same-UID write-access to the cache dir is a generic trust-boundary assumption.

## Metadata `.meta` tamper

`KeyMeta` JSON (type, access policy, app-specific fields) ships next to every key as `<label>.meta`. Hardware backends (Apple SE, Windows CNG, Linux TPM) fix the access policy at key-creation time inside the chip, so `.meta` tamper on those backends is a UI-deception risk only — signing still prompts for Touch ID / Windows Hello regardless of what the JSON claims.

On the **software / keyring backend** the hardware does not re-enforce, so `.meta` tamper was a full policy-downgrade vector. `metadata::save_meta_with_hmac` / `load_meta_with_hmac` now write and verify a `<label>.meta.hmac` HMAC-SHA256 sidecar keyed by a per-app random 32-byte HMAC key stored in the system keyring under `<app>` / `__meta_hmac_key__`. `enclaveapp-app-storage::ensure_key` verifies the sidecar on Linux; a mismatch yields a hard `meta_hmac_verify` error and refuses to load the key. Pre-upgrade keys without a sidecar fall through to the plain `load_meta` path for migration and pick up the sidecar on next regeneration.
