# enclave

Hardware-backed key management and in-process memory protection for
macOS (Secure Enclave), Windows (TPM 2.0), and Linux (TPM 2.0 / keyring).

---

## What this is

`enclave` is two things in one crate:

**Hardware key management** — ECDSA P-256 signing and ECIES P-256 encryption backed by the
platform hardware security module. Private keys never leave the hardware. User-presence
enforcement (Touch ID, Windows Hello) is built in and composable.

**In-process memory protection** — guard-paged mlock'd buffers, AES-256-GCM in-memory sealed
secrets, and a tiered pool of locked memory slots. Ported from
[asherah-ffi](https://github.com/godaddy/asherah-ffi). These components can be used
independently of the HSM layer, and compose with it: decrypted key material from the HSM
can be held in sealed or guard-paged memory with no swap exposure.

---

## Platform support

| | macOS | Windows | Linux | WSL2 |
|--|:---:|:---:|:---:|:---:|
| Signing / Encryption | Secure Enclave | TPM 2.0 | TPM 2.0 / keyring | Bridge → Windows TPM |
| Touch ID / Windows Hello | ✅ | ✅ | — | — |
| Guard-page buffers | ✅ | ✅ | ✅ | ✅ |
| mlock'd / no-swap | ✅ | ✅ | ✅ | ✅ |
| In-memory AES-GCM sealing | ✅ | ✅ | ✅ | ✅ |
| Tamper-evident files | ✅ | ✅ | ✅ | ✅ |

---

## Memory protection

The in-process memory subsystem is the most differentiated part of this crate. It can be used
without the HSM layer.

### `SecureBuffer` — guard-paged, mlock'd allocation

A page-guarded, mlock'd buffer for short-lived secret material. Guard pages on both sides
trigger SIGSEGV on overflow/underflow. Random canaries are verified on `destroy()`. The inner
region is zeroized before unmapping.

```rust
use enclave::SecureBuffer;

let key_material = [0u8; 32]; // your 32-byte secret
let mut buf = SecureBuffer::new(32)?;
buf.bytes().copy_from_slice(&key_material);
buf.freeze()?;       // PROT_READ — prevents accidental mutation
// ... use buf.as_slice() ...
buf.destroy()?;      // verifies canaries, zeroizes, unmaps
// or just drop — same effect, logged at error! if canaries are corrupt
```

State transitions: `Mutable` → `freeze()` → `Frozen` → `melt()` → `Mutable` → `destroy()` → `Dead`.

### `LockedBuffer` — Arc-wrapped, thread-safe

An `Arc<Mutex<SecureBuffer>>` for sharing secret material across threads, with a
global registry for shutdown cleanup.

```rust
use enclave::{LockedBuffer, zeroize_all_registered_at_shutdown};
use zeroize::Zeroizing;

let buf = LockedBuffer::random(32)?;              // OsRng-filled
let copy: Zeroizing<Vec<u8>> = buf.bytes_zeroizing();
buf.wipe();                                        // explicit zero (also happens on drop)
// At process shutdown:
zeroize_all_registered_at_shutdown();
```

### `MemoryEnclave` — AES-256-GCM in-memory sealed secret

Seals plaintext under the process-global Coffer key (stored XOR-split in two locked slab
slots; neither half alone reveals the key). The plaintext lives only in the locked slab while
open — never on the regular heap. A hot cache avoids decryption on repeated `open()` calls.

```rust
use enclave::MemoryEnclave;

let sealed = MemoryEnclave::seal(b"ephemeral secret")?;

// Cold path: AES-256-GCM decrypt into a locked PoolSlot.
// Hot path: copy from slab cache — no crypto.
let slot = sealed.open()?;
assert_eq!(&slot.as_slice()[..16], b"ephemeral secret");
// slot drops → zeroed immediately
// sealed drops → hot-cache entry evicted and zeroed
```

Crypto properties: nonce is 12 fresh OsRng bytes per seal (fork-safe). AES-256-GCM
authentication: any bit flip in ciphertext or tag → `Err(DecryptFailed)`. Key schedule
zeroized via `aes-gcm`'s `ZeroizeOnDrop` feature.

### Pool and tiered slab

The pool backs `MemoryEnclave::open()` and is available directly for any secret-sized
allocation. The default global pool has one 32-byte tier (one mlock'd page, ~126 usable
slots). Acquisitions larger than the tier's slot size fall back to a standalone
`SecureBuffer`.

```rust
use enclave::{pool_acquire, pool_release, coffer_view, init_pool, TieredPoolConfig};

// Optional: configure tiers before first use.
init_pool(TieredPoolConfig { tier_sizes: vec![32, 64, 128] })?;

let mut slot = pool_acquire(32)?;   // slab-backed (mlock'd single page)
slot.bytes().copy_from_slice(&key); // write secret
drop(slot);                          // → zeroed, returned to free list, Condvar notified

// Get the Coffer master key for direct AES-GCM use.
let key_slot = coffer_view()?;
// ... use key_slot.as_slice() as AES-256 key ...
drop(key_slot);                      // → zeroed, slot returned
```

---

## Hardware key management

### Creating handles

```rust
use enclave::{create_signer, create_encryptor, EnclaveConfig, AccessPolicy};

// App name gets `-unsigned` appended automatically for unsigned binaries,
// preventing dev key namespace collisions with production keys.
let config = EnclaveConfig::new("myapp", "default-key");
let signer  = create_signer(&config)?;
let encryptor = create_encryptor(&config)?;
```

### Signing (ECDSA P-256)

`SignerHandle` is multi-key: every method takes a `label` parameter.

```rust
// Generate a hardware-backed P-256 signing key.
let pubkey: Vec<u8> = signer.generate_key("ssh-key", AccessPolicy::Any)?;

// Sign — returns DER-encoded ECDSA signature.
let sig = signer.sign("ssh-key", message)?;

// Sign with Touch ID (Strict → Err(PresenceNotAvailable) if no biometric).
let sig = signer.sign_with_presence("ssh-key", message, &PresenceOptions::strict("SSH auth"))?;

// Key management.
signer.list_keys()?;
signer.key_exists("ssh-key")?;
signer.delete_key("ssh-key")?;
signer.rename_key("ssh-key", "github-key")?;
```

### Encryption (ECIES P-256)

`EncryptorHandle` is multi-key. `decrypt` returns `Zeroizing<Vec<u8>>`.

```rust
encryptor.generate_key("cache-key", AccessPolicy::None)?;

let ciphertext = encryptor.encrypt("cache-key", b"secret credential")?;
let plaintext  = encryptor.decrypt("cache-key", &ciphertext)?;
// plaintext: Zeroizing<Vec<u8>> — zeroed when dropped

encryptor.list_keys()?;
encryptor.delete_key("cache-key")?;
```

Wire format (ECIES): `[0x01 version][65B ephemeral pubkey][12B nonce][ciphertext][16B GCM tag]`

### User presence (Touch ID / Windows Hello)

`AuthHandle` gives a standalone presence check and cache eviction, decoupled from specific
key operations.

```rust
use enclave::create_auth;

let auth = create_auth(&config)?;
let caps = auth.capabilities();
// caps: { biometric_available, password_available, presence_caching, authenticator_name }

// Prompt synchronously — blocks until user responds.
auth.request_presence("Authorize credential access")?;

// Force re-authentication for subsequent sign_with_presence calls.
auth.evict_presence_cache();
```

On macOS: `LAContext.evaluatePolicy(.deviceOwnerAuthentication)`.  
On Windows: `UserConsentVerifier.RequestVerificationAsync` with Hello → password fallback.  
On Linux: returns `Err(PresenceNotAvailable)`.

---

## Hardware security keys (FIDO2 / WebAuthn)

`SecurityKeyHandle` manages FIDO2 platform authenticator credentials backed by
the Windows Hello TPM (Windows native) or the Windows TPM via a JSON-RPC bridge
(WSL2). Returns `NotAvailable` on macOS and non-WSL Linux.

```rust
use enclave::{create_security_key, EnclaveConfig};

let config = EnclaveConfig::new("myapp", "default");
let sk = create_security_key(&config);

if sk.is_available() {
    // Fires a Windows Hello gesture; creates a TPM-bound FIDO2 credential.
    let info = sk.generate("ssh-key", Some("user@host"))?;

    // sign() also fires Hello. Returns the full FIDO2 assertion.
    let sig = sk.sign("ssh-key", data_to_sign)?;
    // sig.signature_der — DER ECDSA P-256
    // sig.flags         — User Present / User Verified bits
    // sig.counter       — monotonic TPM counter
}
```

`SecurityKeySignature` contains everything needed to build an
`sk-ecdsa-sha2-nistp256@openssh.com` SSH signature wire format.

---

## Tamper-evident files

HMAC-SHA-256 protected files. The per-app HMAC key lives in the platform secure store
(Keychain / DPAPI / Secret Service); it never appears on disk.

Two modes — pick based on the number of files you need to protect:

```rust
use enclave::{create_tamper_evident, IntegrityMode};

// Sidecar mode (default): one secure-store entry per app.
// Scales to any file count. The .hmac sidecar is authoritative.
let handle = create_tamper_evident("myapp")?;

// TrustAnchor mode: one secure-store entry per file in addition to the per-app key.
// The platform secure store is authoritative — deleting the sidecar cannot bypass verification.
// Use for low-volume, high-value files only.
let handle = create_tamper_evident("myapp")?.with_trust_anchor();

handle.write(&path, content)?;

match handle.verify(&path)? {
    VerifyOutcome::Match          => { /* content unchanged */ }
    VerifyOutcome::Tamper         => { /* reject */ }
    VerifyOutcome::Legacy         => { handle.migrate(&path)?; } // bootstrap
    VerifyOutcome::StoreUnavailable => { /* fail-open */ }
    VerifyOutcome::NotFound       => { /* file absent */ }
}

// read() returns content or Err(TamperDetected).
let content = handle.read(&path)?;
```

---

## Binary identity

Unsigned binaries (e.g. `cargo build`) work fully — they automatically use a `-unsigned`
app name to avoid colliding with production keys. The library never silently degrades; it
returns `Error::RequiresSigning` when a config option requires an entitlement the binary
doesn't have.

```rust
use enclave::{is_binary_signed, has_keychain_entitlement, security_capabilities};

is_binary_signed()                              // path heuristic + codesign check on macOS
has_keychain_entitlement("TEAM.bundle.id")      // checks actual codesign entitlements
security_capabilities("myapp")                  // full posture: backend, entitlement, policy rec
```

---

## Configuration

```rust
EnclaveConfig {
    app_name: "myapp".into(),
    default_key_label: "main".into(),
    access_policy: None,              // auto: None for signed, Any for unsigned
    keys_dir: None,                   // default: ~/.config/myapp/keys/
    platform: PlatformConfig::MacOs(MacOsConfig {
        wrapping_key_user_presence: true,
        keychain_access_group: Some("TEAM.com.example.myapp".into()),
        wrapping_key_cache_ttl: Duration::from_secs(300),
        ..MacOsConfig::default()
    }),
}
```

---

## Security properties

| Property | Mechanism |
|----------|-----------|
| No plaintext keys on disk | HSM keeps private keys in hardware; software backends encrypt under keyring |
| No swap exposure | `mlock` on `SecureBuffer`, `LockedBuffer`, and slab pages |
| Overflow detection | Guard pages (`PROT_NONE`) + random canaries verified on destroy |
| Zeroization | All secret-bearing types zero on drop: `SecureBuffer`, `PoolSlot`, slab hot-cache entries |
| AES-GCM authentication | Any ciphertext modification → `Err(DecryptFailed)` |
| Coffer key splitting | `left XOR SHA-256(right)` — neither half reveals the key |
| Process hardening | `RLIMIT_CORE=0`, `PR_SET_DUMPABLE=0` (Linux), strict handle checks (Windows) |
| Dev/prod isolation | `-unsigned` suffix prevents dev keys from touching production key stores |
| No silent downgrades | Factory errors at construction time, not first use |

---

## Error handling

`enclave::Error` is `#[non_exhaustive]` — match with a `_` fallback arm.

Notable variants:
- `TamperDetected` — file HMAC mismatch
- `RequiresSigning { feature }` — config requires a code-signed binary
- `PolicyNotSupported { policy }` — backend cannot enforce the requested `AccessPolicy`
- `PresenceNotAvailable` — `sign_with_presence(Strict, ...)` on a platform without biometric
- `NotImplemented { feature }` — API stub (see individual method docs)

---

## Running the examples

Each example runs with real hardware or with a software mock for CI/development:

```bash
# Memory protection (no hardware required)
cargo run --example memory_protection

# Tamper-evident files (no hardware required)
cargo run --example integrity

# Signing with hardware (Touch ID / TPM)
cargo run --example signing

# Signing with software mock (no hardware, CI-safe)
ENCLAVE_MOCK=1 cargo run --example signing

# Encryption with software mock
ENCLAVE_MOCK=1 cargo run --example encryption

# Run all CI-safe examples via cargo test
ENCLAVE_MOCK=1 cargo test --test examples_ci
```

---

## License

MIT — Copyright 2026 Jay Gowdy
