# Threat Model

What can an attacker do, and what can't they do, against systems using libenclaveapp.

## What we protect

| Asset | Where it lives | Who can access it |
|---|---|---|
| P-256 private key (hardware) | Secure Enclave or TPM chip | Only the hardware — nobody can extract it, including root |
| P-256 private key (keyring) | Encrypted file on disk, KEK in system keyring | Any process running as the same user with keyring access |
| Cached credentials (encrypted) | ECIES ciphertext on disk | Anyone can read the file; only the HSM can decrypt it |
| Cache headers (unencrypted) | Timestamps, risk level in cache file | Anyone with read access — no secrets, but reveals usage patterns |

## What an attacker CANNOT do

**With hardware backends (Secure Enclave, TPM 2.0):**

- **Extract the private key.** It physically cannot leave the chip. There is no API, no debug mode, no root exploit that produces the key bytes. This is the entire point.
- **Use the key from another device.** Keys are device-bound. Stealing the disk image is useless.
- **Use the key without biometrics** (when access policy is set). On macOS the Secure Enclave enforces Touch ID inside `SecKeyCreateSignature` and software cannot bypass this. On Windows there are two paths and *both* are hardware-enforced: the **WebAuthn / SK path** (`enclaveapp-windows-webauthn`) routes through the TPM via NGC -- the OS will not sign without a real Hello gesture, gate enforced outside user-mode -- while the **legacy Platform-KSP path** sets `NCRYPT_UI_PROTECT_KEY_FLAG` on every non-`None` access-policy key, so the TPM enforces the gate via the legacy CryptUI password dialog. The library no longer carries any user-mode `UserConsentVerifier` Boolean check (that was removed because the Boolean was hookable by code execution as the user); the only consent UI on Windows is the TPM-side dialog or the WebAuthn-side Hello prompt, both of which the OS gates outside user-mode. Apps that want Hello biometric UX on Windows use the SK path; apps that want any TPM-enforced gate use either path.
- **Tamper with encrypted data.** ECIES uses AES-256-GCM — any modification to the ciphertext is detected and rejected.

**With Type 1 delivery (HelperTool):**

- **Read the private key through the agent socket.** The agent returns signatures, never key material. The SSH agent protocol does not have a "give me the private key" command.

**With Type 2 delivery (EnvInterpolation):**

- **Find secrets in config files on disk.** Config files contain only `${ENV_VAR}` placeholders. The actual secret never touches disk.

## What an attacker CAN do

### Same-user attacks

An attacker running as the same user on the same machine can:

- **Connect to the agent socket and request signatures** (Type 1). Socket permissions and peer UID verification prevent cross-user access, but same-user access is inherent to Unix domain sockets / Windows named pipes. The defense against unlimited signatures is the access-policy / user-presence gate -- Touch ID on macOS, Windows Hello via the WebAuthn / SK path, and the legacy Platform-KSP path's TPM-side CryptUI dialog are all hardware-enforced. The library has no user-mode Boolean check between the agent and the hardware gate, so an attacker who can reach the socket still has to clear the OS-mediated UI ack to get a signature. Without any access policy at all, an attacker who can reach the agent gets unlimited signatures regardless of platform.

- **Read environment variables of running processes** (Type 2). On Linux, `/proc/<pid>/environ` is readable by the same user. The secret exists in the target process's memory for its entire lifetime.

- **Read temp config files during the target process's lifetime** (Type 3). The file has restricted permissions and a randomized path, but a same-user attacker who can enumerate `/tmp` can find and read it.

- **Access the system keyring and decrypt software keys** (keyring backend). The keyring's access control boundary is the user session, not individual processes.

- **Call the Type 4 credential source and get a plaintext credential.** There are no delivery guardrails — `sso-jwt get` returns the JWT to whoever calls it.

### Root/admin attacks

Root can do everything a same-user attacker can, plus:

- **Attach a debugger to any process** and read secrets from memory.
- **Replace binaries** (enclave apps, target apps, bridge executables) with malicious versions.
- **Access the TPM/SE directly** and perform operations with the app's key (though still cannot extract it).

Hardware access policies (Touch ID on macOS, Windows Hello via the WebAuthn / SK path, the legacy CryptUI password dialog on the Windows Platform-KSP path) are the only defense against root -- they require physical presence that root cannot fake. The library no longer contains any user-mode consent gate that root could hook; every consent UI on Windows now fires from the OS itself (TPM-side or NGC-side) before the key is released.

### Offline/physical attacks

- **Stolen disk:** Encrypted cache files are useless without the HSM. Hardware-backed keys cannot be extracted. Keyring-encrypted keys require the user's login session to decrypt.
- **Stolen device (locked):** HSM keys are inaccessible without device unlock. Access-policy-protected keys additionally require biometric/PIN.
- **Stolen device (unlocked):** Same as root access — keys are usable but not extractable.

### Network/protocol attacks

- **ECIES replay:** An old encrypted cache file decrypts successfully as long as the key exists. Applications must check timestamps in the decrypted payload. The library provides cache lifecycle management (`CredentialState`) but not replay prevention at the ECIES layer.
- **Credential replay:** Credentials returned by Type 1 apps (e.g., AWS STS tokens) are replayable within their validity window. SSH signatures include server nonces and cannot be replayed. Credential expiration is the protocol's responsibility.

### Bridge protocol surface

The WSL→Windows bridge is a JSON-RPC channel over a child process's stdin/stdout. Beyond binary replacement (above), the following protocol-level threats are worth naming.

- **Legacy `biometric: bool` field removed.** The `BridgeParams` wire type (`crates/enclaveapp-bridge/src/protocol.rs`) no longer carries a `biometric` field. `access_policy` is the only accepted encoding on the wire. A stray `biometric` key in a received payload is ignored by the deserializer and cannot influence the effective policy. This closes the silent-downgrade path where a bridge server that honored only `biometric` could serve a client's `BiometricOnly` request as `None`.
- **Authenticode signature check is opt-in at build time.** When this crate is compiled with `ENCLAVEAPP_BRIDGE_REQUIRE_SIGNED=1` set in the build environment (checked at `option_env!` time, not runtime), `require_bridge_is_authenticode_signed` (`crates/enclaveapp-bridge/src/client.rs`) parses the PE header's `IMAGE_DIRECTORY_ENTRY_SECURITY` slot and refuses binaries with no signature block before spawning them. Builds without that flag — **including the current release pipeline for sshenc / awsenc / sso-jwt / npmenc, which do not code-sign binaries today** — skip the check entirely and accept unsigned bridges. The check is deliberately not runtime-toggleable: there is no `ENCLAVEAPP_BRIDGE_ALLOW_UNSIGNED` escape hatch, because a security property that an attacker with env-var-setting ability can flip off is not a security property. **Residual risk for the current unsigned-release posture:** an attacker who obtains Windows admin rights (and thus write access to `/mnt/c/Program Files/<app>/` or `/mnt/c/ProgramData/<app>/`) can replace the bridge binary with an arbitrary PE, and the WSL client will spawn it. The only defences in that case are: (1) the binary must land at one of the fixed admin-owned paths — a user-writable location cannot substitute without `ENCLAVEAPP_BRIDGE_PATH` being explicitly set by the user; (2) Windows admin itself is a higher bar than ordinary user privilege. Once the release pipeline acquires a code-signing cert, building with `ENCLAVEAPP_BRIDGE_REQUIRE_SIGNED=1` upgrades the check to catch the "Windows admin replaces the exe with an unsigned ad-hoc `cargo build` artifact" case. Full chain verification (`WinVerifyTrust` against a specific publisher) still requires a Windows-side helper and is out of scope for the WSL-resident client; an admin-on-Windows replacement with a validly-signed-but-malicious binary from a different publisher remains out of scope even under the opt-in enforced path.
- **Method-name alias guarantee (`delete` ↔ `destroy`).** The bridge server (`crates/enclaveapp-tpm-bridge/src/lib.rs`) accepts both `"delete"` and `"destroy"` as synonyms for the same key-removal operation. The `bridge_destroy` client helper sends `"delete"` on the wire; a newer client talking to an older server-in-the-wild that only implemented `"destroy"` is the residual edge case. The `destroy_and_delete_are_aliases` test (`crates/enclaveapp-tpm-bridge/src/lib.rs`) locks the alias in as a compatibility guarantee — a future refactor that drops one name would fail the test rather than silently breaking mixed-version deployments.
- **Accepted guarantees** now explicit in the model: 64 KB response cap (`MAX_BRIDGE_RESPONSE_BYTES`), connection-scoped child kill-on-drop (`BridgeSession::Drop`), and a configurable `ENCLAVEAPP_BRIDGE_TIMEOUT_SECS` read-line timeout.

### FFI trust boundaries

Unsafe FFI surfaces are trusted by design but fragile.

- **Swift ↔ Rust bridge** (`crates/enclaveapp-apple/src/ffi.rs` + `crates/enclaveapp-apple/swift/bridge.swift`). Out-buffer convention: the Swift side returns `SE_ERR_BUFFER_TOO_SMALL` **only** when a caller-supplied out-buffer is genuinely undersized and writes the required size to `*_len.pointee`. The Rust-side retry loop in `keychain.rs::generate_key_with_retry` enforces the contract strictly: it caps retries at `MAX_RESIZE_RETRIES = 4`, refuses to retry when the Swift-reported length does not grow past the buffer it sent, and rejects any post-call `pub_key_len > 65` as a contract violation. A Swift-side regression that starts returning `SE_ERR_BUFFER_TOO_SMALL` for a non-sizing condition now surfaces as a hard `GenerateFailed { detail: "Swift bridge contract violation" }` error instead of spinning in a retry loop or masking the real failure.
- **Windows CNG raw-pointer casts** (`crates/enclaveapp-windows/src/ui_policy.rs`). `NCRYPT_UI_POLICY` is passed to `NCryptSetProperty` / `NCryptGetProperty` via `&policy as *const _ as *const u8` with a computed `size_of::<NCRYPT_UI_POLICY>()`. A module-level `const _: () = assert!(size_of::<NCRYPT_UI_POLICY>() == EXPECTED_NCRYPT_UI_POLICY_SIZE, ...)` fails the build if a future `windows-rs` release silently changes the struct layout (e.g. re-orders `LPCWSTR` fields or pads differently), preventing a `cbInput`-mismatch regression from landing silently.
- **Windows Platform-KSP path: hardware-enforced via NCRYPT UI policy.** `key.rs` sets `NCRYPT_UI_PROTECT_KEY_FLAG` on every non-`None` access-policy key, so the TPM enforces a UI gate via the legacy CryptUI password dialog at sign / decrypt time. `ui_policy::verify_ui_policy_matches` re-reads the flag at use time and refuses the operation if it doesn't match metadata, catching attacker-planted keys with a missing or wrong UI flag. The library no longer issues any user-mode `UserConsentVerifier` consent calls on this path -- the previous design had a soft Boolean check that an attacker with code execution as the user could hook, and was removed because there is no Authenticode trust boundary protecting the agent process. Apps that want Hello biometric UX rather than the legacy password dialog use `enclaveapp-windows-webauthn` instead (TPM via NGC); both paths are hardware-enforced, the choice is purely about UI surface.

### Keychain and key-backend-specific risks

- **macOS `.handle` storage is AES-256-GCM wrapped under a Keychain-held key.** `generate_and_save_key` creates a fresh 32-byte wrapping key per label, stores it in the login keychain as a `kSecClassGenericPassword` item (service `com.godaddy.<app>`, account `<label>`), and writes the AES-GCM-sealed SE `dataRepresentation` to `.handle` (magic `EHW1`, format `[magic][nonce][ciphertext][tag]`). A same-UID attacker who copies the `.handle` file still needs the keychain-held wrapping key to replay SE operations — and the keychain's code-signature-bound ACL blocks access from a different binary, prompting the user on first use of a rebuilt binary. Legacy plaintext `.handle` files are accepted transparently for migration; they upgrade to wrapped format on the next rotation. See `crates/enclaveapp-apple/src/keychain_wrap.rs`.
- **Cross-binary Keychain access on macOS** for ad-hoc signed builds (Homebrew, `cargo build`) is controlled by binary hash; every rebuild invalidates the ACL and reprompts the user. This is the Keychain enforcing its ACL — it's now load-bearing because the wrapping key is what gates same-UID handle theft (above). Trusted signing identities eliminate the per-upgrade prompt.
- **Keyring D-Bus peer trust.** The keyring backend talks to the session D-Bus Secret Service. A hostile session bus (another process running as the user that took over the bus) could intercept unlock / decrypt requests. Same-user already-compromised session; out of scope for the library.

### Filesystem races and metadata tamper

- **Symlink-safe reads of metadata and handle files.** `metadata::read_no_follow` (`crates/enclaveapp-core/src/metadata.rs`) uses `O_NOFOLLOW` on Unix and a `symlink_metadata` pre-check on Windows. It is called from every key-material load path — Apple keychain handle reads (`crates/enclaveapp-apple/src/keychain.rs`), keyring-backend `.key` reads (`crates/enclaveapp-keyring/src/key_storage.rs`), Linux TPM `.pub`/`.priv` reads (`crates/enclaveapp-linux-tpm/src/tpm.rs`), and the shared `load_meta` path. A pre-planted symlink in the keys directory is refused with `ELOOP` rather than silently redirected.
- **`.meta` HMAC sidecar on the keyring backend.** `metadata::save_meta_with_hmac` / `load_meta_with_hmac` write and verify a `<label>.meta.hmac` sidecar keyed by a per-app random HMAC key held in the system keyring (`enclaveapp_keyring::meta_hmac_key`). `enclaveapp-app-storage::ensure_key` verifies the sidecar on Linux and rejects HMAC-mismatched loads with `meta_hmac_verify` — a same-UID attacker who edits `<label>.meta` to flip `BiometricOnly` → `None` without also having keyring access is caught. Apple SE and Windows CNG do not write the sidecar because those chips enforce the access policy at key-creation time; `.meta` tamper changes what the UI displays but cannot bypass the hardware gate. Linux TPM does not write the sidecar either, but for a different reason: the Linux TPM backend does not enforce `AccessPolicy` at sign time (see "Linux TPM backend" below). Extending the HMAC sidecar to Linux TPM is a candidate follow-up. The sidecar is absent for pre-upgrade keys — `load_meta_with_hmac` falls through to `load_meta` verbatim in that case, so existing installs migrate transparently on the next key regeneration.
- **Binding-store / temp-config file creation.** Both `JsonFileBindingStore::write_all_unlocked` (`crates/enclaveapp-app-adapter/src/binding_store.rs`) and `TempConfig::write` (`crates/enclaveapp-app-adapter/src/temp_config.rs`) now create their files with `OpenOptions::mode(0o600)` at creation time (Unix), eliminating the prior default-umask window between `create` and `chmod`. On Windows, ACLs continue to inherit from the parent directory, which the install flow narrows.

### Concurrent access

- **Key creation is cross-process serialized.** `DirLock::acquire`
  (`crates/enclaveapp-core/src/metadata.rs`) wraps every backend's
  `generate` / `generate_and_save_key` path before the hardware call:
  Apple (`crates/enclaveapp-apple/src/keychain.rs:136`), Windows CNG
  (`crates/enclaveapp-windows/src/state.rs:25`), keyring
  (`crates/enclaveapp-keyring/src/key_storage.rs:317`), Linux TPM
  (`crates/enclaveapp-linux-tpm/src/{sign,encrypt}.rs`), and
  test-software. Two concurrent first-run invocations block on the
  `fs4` flock and execute sequentially — no SE/TPM slot orphaning.
  `secret_store.rs` uses per-id shared/exclusive flocks for
  adapter-layer secret mutations.
- **Bridge serialization — client-side lock.**
  `crates/enclaveapp-bridge/src/client.rs` now holds a process-wide
  `BRIDGE_SESSION_LOCK: Mutex<()>` across the full spawn→request→
  shutdown lifetime of every bridge session. Two threads in the same
  client process no longer race to spawn independent bridge children
  against the same TPM, which would (a) fire Windows Hello twice
  back-to-back, (b) contend for the server-side key slot, and (c)
  double-bill TPM op quota. The server still serializes per-session;
  the client-side lock just stops us from paying the spawn + prompt
  cost twice. Poisoning from a prior panicked session is recovered
  with `into_inner()` so one crashed session does not wedge the
  client for the process's lifetime. The
  `concurrent_call_bridge_serializes_via_session_lock` test locks in
  the serialization semantics with two threads whose session
  intervals are required to be non-overlapping.

### Process hardening scope

`enclaveapp_core::process::harden_process()` (`crates/enclaveapp-core/src/process.rs`) applies:

- **All Unix:** `setrlimit(RLIMIT_CORE, 0)` — no core dumps.
- **Linux:** `prctl(PR_SET_DUMPABLE, 0)` — `/proc/<pid>/mem` becomes root-only; `ptrace` attach from non-root peers is denied by the kernel even within the same UID.
- **Linux:** `prctl(PR_SET_NO_NEW_PRIVS, 1)` — subsequent `exec*()` cannot gain setuid / file-capabilities privileges; shrinks the surface for wrapped-child-process escalation.
- **Windows:** `SetProcessMitigationPolicy` applies a safe subset at startup:
  - `ProcessStrictHandleCheckPolicy` with `RaiseExceptionOnInvalidHandleReference` + `HandleExceptionsPermanentlyEnabled` — turns latent handle-confusion bugs into `STATUS_INVALID_HANDLE` exceptions instead of silently operating on the wrong object.
  - `ProcessExtensionPointDisablePolicy` with `DisableExtensionPoints` — blocks AppInit_DLLs, AppCertDlls, shim engines, IMEs, and winevent hooks from loading into the process, killing the most common unsigned-DLL-injection vector.
  - `ProcessImageLoadPolicy` with `NoRemoteImages` + `NoLowMandatoryLabelImages` — refuses DLL loads from UNC paths and from files at the low-mandatory integrity label. Blocks the "drop a DLL onto a writable share and hijack LoadLibrary" pattern.

  Deliberately not applied: `BinarySignaturePolicy.MicrosoftSignedOnly` (breaks cargo-built unsigned apps), `DynamicCodePolicy` / ACG (breaks some JIT / crypto providers), `SystemCallDisablePolicy.DisallowWin32kSystemCalls` (breaks any process with a GUI surface). Each call is best-effort — failure on older Windows builds is logged via `tracing::warn!` and does not abort startup.

Still not applied: `RLIMIT_AS`, seccomp-bpf system-call filtering, macOS `ptrace(PT_DENY_ATTACH)` (deprecated and fragile). Root can still dump memory unconditionally on any platform. Applications that want stricter memory protection must add their own mitigations on top.

### Zeroize coverage

`zeroize` is applied to secret-bearing structures in the launcher (`crates/enclaveapp-app-adapter/src/launcher.rs`), the credential cache (`crates/enclaveapp-app-adapter/src/credential_cache.rs`), and the keyring / software backends:

- **Keyring backend** (`crates/enclaveapp-keyring/src/key_storage.rs`): plaintext private-key byte buffers are returned as `Zeroizing<Vec<u8>>` from `load_private_key_bytes` and `decrypt_private_key`; the random KEK generated in `save_encrypted` is wrapped in `Zeroizing` after filling the intermediate array; `generate_and_save` holds its raw `secret_key.to_bytes()` as `Zeroizing`.
- **Software (test) backend** (`crates/enclaveapp-test-software/src/key_storage.rs`): same pattern on the load/save paths.
- **ECIES intermediate AES key** (`crates/enclaveapp-keyring/src/encrypt.rs`, `crates/enclaveapp-test-software/src/encrypt.rs`): `derive_key` now returns `Zeroizing<[u8; 32]>` so the AES-GCM symmetric key is wiped after each encrypt / decrypt operation.

Still not wrapped: `mlock`ed handle bytes on macOS (tracked separately; the SE-side key never leaves the chip so the in-process `dataRepresentation` is opaque to us). Consumer crates that care about tighter memory hygiene on ciphertext buffers should wrap their own.

### App-adapter surface

- **Typed `SecretRead` return on the read path.** `SecretStore::get_read` returns a typed [`SecretRead`](../libenclaveapp/crates/enclaveapp-app-adapter/src/secret_store.rs) enum with `Present(String) | Redacted | Absent` variants. The read-only inspection store returns `Redacted` directly — it no longer round-trips through the `REDACTED_PLACEHOLDER` sentinel string, so a stored secret whose bytes happen to equal `"<redacted>"` is returned as `Present("<redacted>")` and cannot be misclassified as the sentinel. The legacy `SecretStore::get` is retained for back-compat and still produces `Some(REDACTED_PLACEHOLDER)` from the read-only store; new call sites use `get_read` and match on the enum. Callers that still consume `get` can use `is_redacted_placeholder` for the legacy compare, but the typed API is preferred.
- **Launcher env inheritance — opt-in scrub.** The launcher still forwards the parent process's full environment plus `env_overrides` to the child by default; `env_overrides` are zeroized after the child exits. Callers that know their wrapped child would be better off without specific inherited env families can now opt in via `LaunchRequest::with_env_scrub(patterns)` (`crates/enclaveapp-app-adapter/src/launcher.rs`). Each pattern is either an exact variable name (`"NPM_TOKEN"`) or a `*`-suffixed prefix (`"NPM_TOKEN_*"`, `"AWS_*"`); matching variables are removed from both the child's `Command` and our own `std::env` via `remove_var`, and our owned `String` copies are zeroized before drop. This is additive to the existing `env_overrides` path — existing callers that don't set `env_scrub_patterns` behave identically. Secrets that *must* survive in the parent env (e.g. `SSH_AUTH_SOCK` for the launcher's own SSH ops) should simply be left out of the scrub pattern list. Type 2 consumers like `npmenc` can scrub inherited `NPM_TOKEN_*` to neutralise a developer-exported token getting picked up by the wrapped `npm` child.

### Credential cache header tamper + rollback

The cache file's unencrypted header (magic, version, flags, app-specific timestamps) lives next to the encrypted payload in `awsenc-core/src/cache.rs` and `sso-jwt-lib/src/cache.rs`. Without binding, a same-UID attacker with file-write access could edit the header's risk level or expiration to extend client-side caching, and could replay an older valid ciphertext to roll back to a prior credential.

**Mitigations in place today:**

- **Envelope-bound header + monotonic counter** (`crates/enclaveapp-cache/src/envelope.rs`). Plaintext handed to `EncryptionStorage::encrypt` is wrapped in `[4B "APL1"][32B SHA-256(header bytes)][8B BE u64 counter][payload]`. The SHA-256 covers the exact unencrypted header bytes — any post-encryption header edit is detected on decrypt. The 8-byte counter is read from a sibling `<cache>.counter` sidecar protected by an exclusive `fs4` flock, bumped on every successful write, and verified `>= sidecar` on every successful read. Older-ciphertext replay is rejected as `Rollback { observed, expected_at_least }`. The envelope is transparent to the `EncryptionStorage` backend — the trait signature did not change, so all backends (Secure Enclave, CNG, Linux TPM, keyring, WSL bridge) get the protection uniformly.
- **Legacy-cache migration.** `unwrap_plaintext` accepts payloads without the `APL1` magic as pre-envelope caches (returned with `counter = 0`). Existing user installs continue to work; the first write after upgrading the binary puts them into the new format.
- **Consumer-side `max(header, config)`.** sso-jwt's `effective_cached_risk_level` (`sso-jwt-lib/src/cache.rs`) and awsenc's equivalent always take the greater of the header-written risk level and the configured minimum. Defense-in-depth even in the pre-migration legacy window.
- **Server-side expiration is authoritative.** AWS STS credentials and SSO JWTs carry their own `Expiration` / `exp`; a rolled-back-header cache still expires at the real server-side time.
- **Payload-embedded timestamps.** sso-jwt embeds `token_iat` and `session_start` inside the encrypted payload; awsenc embeds credential `expiration` inside the encrypted `AwsCredentials` JSON. Both consumers recheck these after decrypt.

**Residual risk:** an attacker with write access to both the `.enc` cache and the `.counter` sidecar can still roll back, but only within the ciphertext's own validity window (server enforces `exp`). Deletion of the sidecar does not help the attacker — `next_counter(sidecar, prior_observed)` takes the max, so a decrypt of the current good cache re-seeds `prior_observed` and a subsequent write still bumps forward.

### Build-time trust

`crates/enclaveapp-apple/build.rs` now invokes the system `xcrun` at its absolute path `/usr/bin/xcrun` (system-managed, not user-writable without sudo) and discovers `swiftc` and `ar` via `xcrun --find <tool>` — the resolved paths sit inside the active Xcode developer directory (`xcode-select -p`) rather than walking `$PATH`. A shadowed `xcrun` / `swiftc` / `ar` earlier on the developer's `$PATH` can no longer substitute a poisoned Swift object into the static bridge that ends up linked into the binary. Release-tooling PATH hygiene is no longer load-bearing for this crate. Other build-environment concerns (Cargo registry, rustc toolchain, linker) remain a general developer-machine trust assumption.

## What we explicitly don't protect against

- Physical attacks on hardware security modules (chip decapping, side-channel emanation)
- Kernel exploits or hypervisor escapes
- Supply chain attacks on Rust crates or platform crypto libraries
- Denial of service (key deletion, cache corruption, socket flooding)
- Application-level protocol vulnerabilities (SSH, AWS STS, OAuth, npm registry)
- User error in Type 4 consumption (exporting credentials to plaintext, logging them)

## Platform-specific notes

**macOS Keychain prompts.** The Keychain scopes access to `kSecClassGenericPassword` items by the calling binary's code-signing identity. The prompt behavior is load-bearing for the wrapping-key threat model (items above): it is exactly what blocks a different binary from reading the wrapping key.

Observed behavior by signing scenario:

| Scenario | First run | Rebuild at same path | Different path |
|----------|-----------|----------------------|----------------|
| Ad-hoc signed (`swiftc` / `rustc` default, Homebrew source builds) | no prompt | **prompt** (code hash changed) | **prompt** |
| Untrusted self-signed cert | no prompt | **prompt** (code hash changed) | **prompt** |
| Trusted signing identity (Apple Development / Developer ID) | no prompt | no prompt (identity unchanged) | **prompt** |

Additional behavior:
- "Deny" is not permanent: operations fail with `errSecUserCanceled` (`-128`), but the next invocation prompts again. The user is never locked out.
- "Always Allow" persists until the binary is replaced. After `brew upgrade`, one new prompt appears on first use of the upgraded binary.
- Ad-hoc → trusted-cert transition: one prompt on the first signed run; after "Always Allow," subsequent runs with the same identity are silent.
- Trusting a self-signed cert requires a `security add-trusted-cert` system password dialog and cannot be automated silently in a Homebrew formula.

**Data Protection Keychain not used.** `kSecUseDataProtectionKeychain: true` fails with `errSecMissingEntitlement` (`-34018`) on unsigned / ad-hoc-signed builds. The implementation uses the legacy (file-based) login keychain with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`.

**Entitled Secure Enclave path not enabled.** Storing SE keys directly as Keychain items via `SecKeyCreateRandomKey` + `kSecAttrTokenIDSecureEnclave` + `kSecAttrIsPermanent: true` would remove the `.handle` file entirely. It requires `keychain-access-groups`, which is an AMFI-restricted entitlement that needs a provisioning profile — even a valid Apple Development cert without a matching profile causes AMFI to kill the binary with error `-413`. This path is only viable for App Store / Enterprise / Xcode-provisioned distribution and is not available for Homebrew or `cargo install` builds. The current Path-2 implementation (AES-GCM-wrapped `.handle` + Keychain-held wrapping key) is the hardening target for unsigned distribution.

**WSL bridge:** Communicates over stdin/stdout of a child process. The client (`crates/enclaveapp-bridge/src/client.rs`) discovers the bridge only from a fixed-path list under `/mnt/c/Program Files/<app>/` and `/mnt/c/ProgramData/<app>/`. Replacing the binary at those paths requires Windows admin rights. The `which`-based PATH fallback was removed — a user-writable `$PATH` entry on the WSL side could otherwise substitute a malicious bridge binary. Request/response size is capped at 64 KB, the child is reaped via `BridgeSession::Drop`, and reads are bounded. Before spawn, `require_bridge_is_authenticode_signed` optionally parses the PE header's security data directory and refuses to spawn a binary with no Authenticode signature block — **but only when this crate was compiled with `ENCLAVEAPP_BRIDGE_REQUIRE_SIGNED=1`**. In the current default release posture (unsigned binaries), the check is compiled out and any PE at a trusted admin path is spawned. The check has no runtime bypass. See "Bridge protocol surface" above for the full rationale and residual-risk accounting.

**Linux TPM backend:** `AccessPolicy` is stored in key metadata and displayed to the user, but the Linux TPM backend does not consult it at runtime. TPM child keys are created with empty authorization (`Context::create` is invoked with no `auth_value`), so neither signing nor decryption requires any user interaction:

- `LinuxTpmSigner::sign` (`crates/enclaveapp-linux-tpm/src/sign.rs`) signs every request without prompting.
- `LinuxTpmEncryptor::decrypt` (`crates/enclaveapp-linux-tpm/src/encrypt.rs`) calls `Context::ecdh_z_gen` without an HMAC/auth session, so ECIES decryption is also silent.

A key created with `AccessPolicy::BiometricOnly` on Linux TPM provides no biometric gate — it behaves identically to `AccessPolicy::None` at runtime, for both signing and decryption. Applications that require enforced user presence on Linux should not rely on this backend to supply it.

**Keyring backend:** Exists for Linux without TPM. Strictly weaker than hardware backends. Any same-user process can access the keyring. No biometric enforcement. As with the Linux TPM backend, `AccessPolicy` is stored in metadata but is not consulted at sign or decrypt time — `SoftwareSigner::sign` and `SoftwareEncryptor::decrypt` operate on the loaded private key without user interaction regardless of the recorded policy. The keyring must be running; if not, the app errors rather than falling back to plaintext.
