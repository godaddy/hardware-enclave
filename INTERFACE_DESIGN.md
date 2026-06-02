# enclave Interface Design

**Status:** Implemented in `crates/enclave/`. Published at `enclave` on crates.io.

This document records the design decisions behind the `enclave` crate's public API.
For usage documentation see `crates/enclave/README.md`. For the application delivery
tier patterns see `crates/enclave/DELIVERY_TIERS.md`.

---

## Motivation

The `libenclaveapp` internal crates accumulated rough edges making FFI bindings painful:
opaque `Box<dyn Trait>`, platform types leaking through, two error hierarchies, `serde_json::Value`
in public types, and `sign_with_presence()` silently ignoring presence params on non-macOS.

`enclave` is the clean public facade. All internal crates remain intact for existing Rust consumers.

---

## Crate structure

```
crates/enclave/
  src/
    signing.rs           SignerHandle
    encryption.rs        EncryptorHandle
    auth.rs              AuthHandle + AuthCapabilities
    memory/              SecureBuffer, LockedBuffer, MemoryEnclave, TieredPool, PoolSlot
    integrity.rs         TamperEvidentHandle, IntegrityMode, VerifyOutcome
    exec.rs              SecureProcess, TempSecretFile  (delivery tiers 2 & 3)
    credential.rs        CredentialState, LifecyclePolicy  (delivery tier 4)
    capabilities.rs      SecurityCapabilities, is_binary_signed, has_keychain_entitlement
    config.rs            EnclaveConfig + PlatformConfig escape hatches
    factory.rs           create_signer, create_encryptor, create_auth, create_tamper_evident
    error.rs             unified Error
    types.rs             KeyInfo, AccessPolicy, BackendKind, PresenceMode, ...
crates/enclaveapp-*/     internal implementation (unchanged, not published via FFI)
```

---

## Interface 1 — Signing (`SignerHandle`)

Multi-key. Every method takes a `label` parameter.

```rust
pub struct SignerHandle { /* wraps AppSigningBackend */ }

impl SignerHandle {
    pub fn generate_key(&self, label: &str, policy: AccessPolicy) -> Result<Vec<u8>>;
    pub fn public_key(&self, label: &str) -> Result<Vec<u8>>;
    pub fn sign(&self, label: &str, data: &[u8]) -> Result<Vec<u8>>;
    pub fn sign_with_presence(&self, label: &str, data: &[u8], opts: &PresenceOptions)
        -> Result<Vec<u8>>;   // Strict + no biometric → Err(PresenceNotAvailable)
    pub fn presence_available(&self) -> bool;
    pub fn list_keys(&self) -> Result<Vec<KeyInfo>>;
    pub fn delete_key(&self, label: &str) -> Result<()>;
    pub fn key_exists(&self, label: &str) -> Result<bool>;
    pub fn rename_key(&self, old: &str, new: &str) -> Result<()>;
    pub fn evict_presence_cache(&self, label: &str);
    pub fn backend_kind(&self) -> BackendKind;
}
```

---

## Interface 2 — Encryption (`EncryptorHandle`)

Multi-key. `decrypt` returns `Zeroizing<Vec<u8>>`.

```rust
pub struct EncryptorHandle { /* wraps AppEncryptionStorage + BridgeEncryptorWrapper for WSL */ }

impl EncryptorHandle {
    pub fn generate_key(&self, label: &str, policy: AccessPolicy) -> Result<Vec<u8>>;
    pub fn public_key(&self, label: &str) -> Result<Vec<u8>>;
    pub fn encrypt(&self, label: &str, plaintext: &[u8]) -> Result<Vec<u8>>;
    pub fn decrypt(&self, label: &str, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>>;
    pub fn list_keys(&self) -> Result<Vec<KeyInfo>>;
    pub fn delete_key(&self, label: &str) -> Result<()>;
    pub fn key_exists(&self, label: &str) -> Result<bool>;
    pub fn rename_key(&self, old: &str, new: &str) -> Result<()>;
    pub fn backend_kind(&self) -> BackendKind;
}
```

ECIES wire format: `[0x01][65B pubkey][12B nonce][ciphertext][16B GCM tag]`

---

## Interface 3 — Auth (`AuthHandle`)

Decoupled from key operations. Standalone presence check and cache eviction.

```rust
pub struct AuthHandle {
    // Windows: owns a HelloGate (per-handle verification cache)
}

impl AuthHandle {
    pub fn capabilities(&self) -> AuthCapabilities;
    pub fn request_presence(&self, reason: &str) -> Result<()>;
        // macOS: LAContext.evaluatePolicy(.deviceOwnerAuthentication) — fires Touch ID
        // Windows: UserConsentVerifier + password fallback
        // Linux: Err(PresenceNotAvailable)
    pub fn evict_presence_cache(&self);
    pub fn backend_kind(&self) -> BackendKind;
}

pub struct AuthCapabilities {
    pub biometric_available: bool,   // runtime check on Windows via UserConsentVerifier
    pub password_available: bool,
    pub presence_caching: bool,      // true only on macOS (LAContext TTL)
    pub authenticator_name: Option<String>,
}
```

---

## Interface 4 — Protected Memory

### `SecureBuffer`

Guard pages (PROT_NONE) + mlock + random canaries. State: Mutable → Frozen → Mutable → Dead.
Canaries verified on `destroy()`. Canary corruption logged at `error!` and panics in debug builds.

### `LockedBuffer`

`Arc<Mutex<SecureBuffer>>` with a global registry for shutdown cleanup.

```rust
pub struct LockedBuffer(Arc<Mutex<SecureBuffer>>);

impl LockedBuffer {
    pub fn new(size: usize) -> Result<Self>;
    pub fn random(size: usize) -> Result<Self>;
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self>;
    pub fn freeze(&self) -> Result<()>;   pub fn melt(&self) -> Result<()>;
    pub fn scramble(&self) -> Result<()>; pub fn wipe(&self);
    pub fn bytes_zeroizing(&self) -> Zeroizing<Vec<u8>>;
    pub fn size(&self) -> usize;
}

pub fn zeroize_all_registered_at_shutdown();
```

### `MemoryEnclave`

AES-256-GCM sealed secret. Plaintext in locked slab slots only. Hot cache avoids
decryption on repeated `open()`. Coffer key XOR-split in slab slots 0+1.
Nonce: 12 fresh OsRng bytes per seal (fork-safe).

```rust
impl MemoryEnclave {
    pub fn seal(plaintext: &[u8]) -> Result<Self>;
    pub fn seal_buffer(buf: &mut SecureBuffer) -> Result<Self>;
    pub fn seal_slot(slot: &PoolSlot) -> Result<Self>;
    pub fn open(&self) -> Result<PoolSlot>;   // hot-cache fast path
    pub fn plaintext_len(&self) -> usize;
    pub fn id(&self) -> u64;
}
```

### `TieredPool` / `PoolSlot`

Single mlock'd page per tier. `PoolSlot` is `Send` but not `Sync`. Only acquire via
module-level functions — `PoolSlot::drop` returns to `global_pool()`, not a local instance.

```rust
init_pool(TieredPoolConfig { tier_sizes: vec![32, 64, 128] })?;

pub fn pool_acquire(size: usize) -> Result<PoolSlot>;
pub fn pool_release(slot: PoolSlot);
pub fn coffer_view() -> Result<PoolSlot>;

pub struct TieredPool {
    pub fn new(config: TieredPoolConfig) -> Result<Self>;
    pub(crate) fn acquire(&self, size: usize) -> Result<PoolSlot>;
    pub(crate) fn coffer_view(&self) -> Result<PoolSlot>;
    pub fn max_slab_slot_size(&self) -> usize;
    pub fn tier_count(&self) -> usize;
    pub fn tier_slot_size(&self, i: usize) -> Option<usize>;
}
```

---

## Interface 5 — Tamper-Evident Files (`TamperEvidentHandle`)

Two modes chosen at construction:

```rust
pub enum IntegrityMode {
    Sidecar,      // default: .hmac sidecar authoritative. 1 secure-store entry/app.
    TrustAnchor,  // per-file tag in platform secure store (Keychain/DPAPI/Secret Service).
                  // Use for low-volume, high-value files only (one entry per file).
}

// Default: Sidecar mode.
let h = create_tamper_evident("myapp")?;
// TrustAnchor mode:
let h = create_tamper_evident("myapp")?.with_trust_anchor();

impl TamperEvidentHandle {
    pub fn with_trust_anchor(self) -> Self;
    pub fn mode(&self) -> IntegrityMode;
    pub fn write(&self, path: &Path, content: &[u8]) -> Result<()>;
    pub fn read(&self, path: &Path) -> Result<Vec<u8>>;  // Err(TamperDetected) on mismatch
    pub fn verify(&self, path: &Path) -> Result<VerifyOutcome>;
    pub fn migrate(&self, path: &Path) -> Result<()>;
    pub fn remove_integrity_data(&self, path: &Path) -> Result<()>;
    pub fn app_name(&self) -> &str;
}
```

`path_to_label()` derives a 64-char hex label (SHA-256 of path bytes) for the secure store key.

---

## Binary identity and capabilities

```rust
pub fn is_binary_signed() -> bool;
pub fn has_keychain_entitlement(group: &str) -> bool;  // codesign check, cached per-group
pub fn security_capabilities(app_name: &str) -> SecurityCapabilities;

pub struct SecurityCapabilities {
    pub binary_signed: bool,
    pub backend: BackendKind,
    pub effective_keychain_group: Option<String>,
    pub code_signature_binding: bool,
    pub keychain_user_presence: bool,
    pub hardware_presence: bool,
    pub presence_caching: bool,
    pub effective_app_name: String,
    pub downgraded_features: Vec<String>,
    pub recommended_access_policy: AccessPolicy,
}
```

---

## Unified error type

```rust
#[non_exhaustive]
pub enum Error {
    NotAvailable, KeyNotFound { label }, DuplicateLabel { label }, InvalidLabel { reason },
    SignFailed { detail }, EncryptFailed { detail }, DecryptFailed { detail },
    AuthDenied { label }, AuthRequired { label, detail }, UserCancelled { label },
    KeyOperation { operation, detail },
    TamperDetected { path },
    RequiresSigning { feature },      // factory: impossible config for unsigned binary
    PolicyNotSupported { policy },    // generate_key: backend can't enforce policy
    PresenceNotAvailable,             // sign_with_presence(Strict) + no biometric
    NotImplemented { feature },       // API stub
    PolicyMismatch { detail },
    Config(String), Io(io::Error), Memory(String),
}
```

---

## Decisions

1. **Crate name:** `enclave` — free on crates.io. Repo renamed `godaddy/enclave`.

2. **LockedBuffer registry:** Included — matters when FFI callers may not cleanly drop handles.

3. **Enclave/Coffer layer:** Implemented (not deferred). `MemoryEnclave` + Coffer in slab slots 0/1.

4. **AccessPolicy on Linux:** `generate_key(BiometricOnly)` → `Error::PolicyNotSupported`.

5. **`sign_with_presence(Strict)` on unsupported platform:** `Error::PresenceNotAvailable`. No silent fallback.

6. **EncryptorHandle multi-key:** Implemented via `AppEncryptionStorage::encryptor()` + `BridgeEncryptorWrapper` for WSL bridge.

7. **TamperEvidentHandle dual-mode:** `IntegrityMode::Sidecar` (default, scales to any file count) vs `TrustAnchor` (per-file in platform secure store). Builder: `.with_trust_anchor()`.

8. **Nonce scheme:** Full 12-byte OsRng nonce per seal. Counter+prefix scheme was fork-unsafe.

9. **`StorageError` and `enclaveapp_core::Error`:** Both `#[non_exhaustive]`. `From` impls have `_` fallback arms.

10. **`EncryptorHandle::decrypt` return:** `Zeroizing<Vec<u8>>` — zeroization visible at the type level.

---

## Migration plan

**Phase 1 — Complete.** `crates/enclave/` with all six interfaces, 148 tests, CI/CD.

**Phase 2 — Next.** Port consuming apps (`awsenc`, `sshenc`, `sso-jwt`, `npmenc`) from
`enclaveapp-*` to `enclave::*` app by app. Internal crates not removed until all done.

**Phase 3 — After migration.** Add `crates/enclave-ffi/` with `extern "C"` wrappers.
Rename internal `enclaveapp-*` crates to `enclave-*` in the same PR that drops the old surface.
