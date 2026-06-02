# enclave

Hardware-backed signing and encryption for Rust — macOS Secure Enclave,
Windows TPM 2.0, Linux TPM 2.0 / keyring.

Private keys never leave the hardware. Touch ID and Windows Hello are built in.

---

## What you can build with this

- **SSH key management** — hardware-backed P-256 keys, signed with Touch ID,
  compatible with `ssh-agent` and `sk-ecdsa-sha2-nistp256@openssh.com`
- **Credential caching** — encrypt API tokens and passwords under the TPM;
  they survive process restart but cannot be stolen without hardware access
- **Code signing / git commit signing** — hardware-enforced key storage with
  optional biometric gate per operation
- **Secret storage with integrity checks** — tamper-evident config files backed
  by HMAC in the platform secure store (Keychain / DPAPI / Secret Service)
- **In-process memory protection** — guard-paged, mlock'd buffers and
  AES-256-GCM in-memory sealed secrets for long-lived processes that handle
  sensitive material

---

## Platform support

| | macOS | Windows | Linux | WSL2 |
|--|:---:|:---:|:---:|:---:|
| Signing (ECDSA P-256) | Secure Enclave | TPM 2.0 | TPM 2.0 / keyring | Bridge → Windows TPM |
| Encryption (ECIES P-256) | Secure Enclave | TPM 2.0 | TPM 2.0 / keyring | Bridge → Windows TPM |
| FIDO2 hardware security keys | — | ✅ WebAuthn | — | Bridge → Windows |
| Touch ID / Windows Hello | ✅ | ✅ | — | — |
| Tamper-evident files | ✅ | ✅ | ✅ | ✅ |
| Guard-page / mlock'd buffers | ✅ | ✅ | ✅ | ✅ |

---

## Signing

Generate a P-256 key in the hardware, sign data, get a DER-encoded ECDSA
signature back. Works identically on macOS (Secure Enclave), Windows (TPM),
and Linux (TPM or keyring).

```rust
use enclave::{create_signer, EnclaveConfig, AccessPolicy};

let config = EnclaveConfig::new("myapp", "signing-key");
let signer = create_signer(&config)?;

// Creates the key the first time; opens it on subsequent calls.
signer.generate_key("signing-key", AccessPolicy::Any)?;

// Returns a DER-encoded ECDSA P-256 signature.
let sig: Vec<u8> = signer.sign("signing-key", data)?;
```

### With user presence (Touch ID / Windows Hello)

```rust
use enclave::PresenceOptions;

// Strict: prompt on every call. Cached: reuse within TTL (macOS only).
let sig = signer.sign_with_presence(
    "signing-key",
    data,
    &PresenceOptions::cached("SSH authentication", 14400), // 4-hour TTL
)?;
```

### Key lifecycle

```rust
let pubkey: Vec<u8> = signer.public_key("signing-key")?;  // uncompressed SEC1
let keys:   Vec<KeyInfo> = signer.list_keys()?;
signer.rename_key("signing-key", "github-key")?;
signer.delete_key("github-key")?;
```

---

## Encryption

ECIES P-256 encryption under a hardware-backed key. Encrypted data survives
process restart; it can only be decrypted on the same machine by the same user.

```rust
use enclave::{create_encryptor, EnclaveConfig, AccessPolicy};

let config = EnclaveConfig::new("myapp", "cache-key");
let enc = create_encryptor(&config)?;

enc.generate_key("cache-key", AccessPolicy::None)?;

let ciphertext: Vec<u8> = enc.encrypt("cache-key", b"my-api-token")?;

// Returns Zeroizing<Vec<u8>> — wiped from memory on drop.
let plaintext = enc.decrypt("cache-key", &ciphertext)?;
```

The ECIES wire format is:
`[0x01 version][65B ephemeral pubkey][12B nonce][ciphertext][16B GCM tag]`

---

## FIDO2 hardware security keys (Windows / WSL2)

Generate TPM-bound FIDO2 credentials and produce `sk-ecdsa-sha2-nistp256@openssh.com`
SSH signatures with hardware-enforced Windows Hello confirmation.

```rust
use enclave::{create_security_key, EnclaveConfig};

let sk = create_security_key(&EnclaveConfig::new("myapp", "default"));

if sk.is_available() {
    let info = sk.generate("github-key", Some("user@host"))?;
    // info.credential_id, info.rp_id, info.public_key

    let sig = sk.sign("github-key", ssh_session_data)?;
    // sig.signature_der — raw ECDSA P-256
    // sig.flags         — User Present / User Verified bits
    // sig.counter       — monotonic TPM counter
}
```

Only available on Windows native and WSL2 (via bridge to Windows TPM).
Returns `Err(NotAvailable)` on macOS and native Linux.

---

## Tamper-evident files

HMAC-SHA-256 protection for config files, key metadata, and any file where you
need to detect undetected modification. The HMAC key lives in the platform
secure store; files on disk remain plaintext with a `.hmac` sidecar.

```rust
use enclave::{create_tamper_evident, VerifyOutcome};

let handle = create_tamper_evident("myapp")?;

handle.write(&path, config_bytes)?;

match handle.verify(&path)? {
    VerifyOutcome::Match   => { /* file is intact */ }
    VerifyOutcome::Tamper  => { /* reject — file was modified externally */ }
    VerifyOutcome::Legacy  => { handle.migrate(&path)?; /* bootstrap existing file */ }
    _                      => {}
}

// read() verifies and returns content in one step.
let content: Vec<u8> = handle.read(&path)?;
```

For high-security files, `.with_trust_anchor()` stores the HMAC in the platform
secure store — deleting the sidecar cannot bypass verification.

**For tests and CI** (no Keychain/DPAPI access, no prompts):

```rust
use enclave::create_tamper_evident_ephemeral;

let handle = create_tamper_evident_ephemeral("myapp");
```

---

## User presence

Acquire a standalone presence confirmation decoupled from any specific key
operation, or evict the cached presence token to force re-authentication.

```rust
use enclave::create_auth;

let auth = create_auth(&config)?;
let caps = auth.capabilities();
// caps.biometric_available, caps.presence_caching, caps.authenticator_name

auth.request_presence("Authorizing SSH key access")?;
auth.evict_presence_cache(); // force re-auth on the next operation
```

---

## In-process memory protection

Protect secret material that lives in the process for extended periods —
session tokens, decrypted keys, cached credentials. Ported from
[asherah-ffi](https://github.com/godaddy/asherah-ffi).

### Guard-paged buffers

Pages flanking the secret region are set to `PROT_NONE`; overflows trigger
SIGSEGV. Random canaries are verified on `destroy()`. The region is mlock'd
(no swap) and zeroized before unmapping.

```rust
use enclave::SecureBuffer;

let mut buf = SecureBuffer::new(32)?;
buf.bytes().copy_from_slice(&key_material);
buf.freeze()?;        // PROT_READ — no accidental mutation
// ... use buf.as_slice() ...
buf.destroy()?;       // zeroizes, verifies canaries, unmaps
```

### AES-256-GCM in-memory sealed secrets

Secrets live as ciphertext on the heap and are only decrypted briefly when you
call `open()`. The plaintext is returned in a guard-paged, mlock'd slot — not
the regular heap — and is zeroed when the slot drops.

```rust
use enclave::MemoryEnclave;

let sealed = MemoryEnclave::seal(b"session-token-xyz")?;

let slot = sealed.open()?;
// use slot.as_slice() — plaintext is here
// slot drops → plaintext zeroed immediately
```

### Thread-safe shared buffers

```rust
use enclave::{LockedBuffer, zeroize_all_registered_at_shutdown};

let buf = LockedBuffer::from_bytes(b"shared-secret")?;
let copy = buf.bytes_zeroizing(); // Zeroizing<Vec<u8>>

// At process shutdown, zero all registered buffers:
zeroize_all_registered_at_shutdown();
```

---

## Configuration

```rust
use enclave::{EnclaveConfig, PlatformConfig};

let config = EnclaveConfig::new("myapp", "default-key");
// -unsigned is appended to app_name automatically for unsigned binaries,
// preventing dev key collisions with production keys.
```

**macOS: Touch ID gate on the wrapping key (requires entitlement):**

```rust
use enclave::{PlatformConfig, MacOsConfig};
use std::time::Duration;

PlatformConfig::MacOs(MacOsConfig {
    wrapping_key_user_presence: true,
    keychain_access_group: Some("TEAM.com.example.myapp".into()),
    wrapping_key_cache_ttl: Duration::from_secs(14400),
    ..MacOsConfig::default()
})
```

### Signed vs unsigned binaries

Development builds (`cargo build`) are unsigned. `enclave` appends `-unsigned`
to your app name automatically, preventing dev keys from ever touching
production key storage. Production signed builds get full Keychain ACL binding
(macOS), meaning only your binary can access its own keys.

---

## Security properties

| Property | Mechanism |
|----------|-----------|
| Keys never leave hardware | SE / TPM only performs private-key operations |
| No swap exposure | `mlock` + `MADV_DONTDUMP` on all secret pages |
| Buffer overflow detection | `PROT_NONE` guard pages + random canaries |
| Zeroization | All secret-bearing types wipe memory on drop |
| Ciphertext integrity | AES-256-GCM authentication (`MemoryEnclave`) |
| Metadata integrity | HMAC-SHA-256 verified against platform secure store |
| Dev/prod isolation | `-unsigned` suffix on unsigned binary app names |

See [THREAT_MODEL.md](THREAT_MODEL.md) for the full threat model, limitations,
and residual risks.

---

## Building applications that wrap third-party tools

If you're building an application that wraps a CLI tool and needs to inject
secrets into it (via environment variables, temp files, or an agent protocol),
see [DELIVERY_TIERS.md](DELIVERY_TIERS.md) for the four integration patterns
and guidance on when to use each.

---

## Examples

```bash
# No hardware required — always works
cargo run --example memory_protection
cargo run --example integrity

# Software mock (CI-safe, no prompts, no hardware)
ENCLAVE_MOCK=1 cargo run --example signing
ENCLAVE_MOCK=1 cargo run --example encryption

# Real hardware (prompts Touch ID / Windows Hello)
cargo run --example signing
cargo run --example encryption

# Run all CI-safe examples via cargo test
ENCLAVE_MOCK=1 cargo test --test examples_ci
```

---

## License

MIT — Copyright 2026 Jay Gowdy
