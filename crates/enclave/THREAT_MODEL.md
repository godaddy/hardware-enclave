# Threat Model

This document describes the threats the `enclave` crate defends against,
the threats it does not defend against, and the residual risks that
consuming applications must address.

---

## What enclave protects

### Hardware key protection

Private keys for signing (ECDSA P-256) and encryption (ECIES P-256) never
leave the hardware security module — macOS Secure Enclave, Windows TPM 2.0,
or Linux TPM 2.0. The hardware enforces:

- **Extraction resistance.** An attacker who reads the process memory, the
  disk, or the keychain cannot recover the private key material.
- **Platform binding.** Keys are bound to the device. Copying the key
  store to another machine does not enable signing or decryption.
- **Access policy enforcement.** On macOS, `AccessPolicy::Any` or
  `BiometricOnly` requires hardware-mediated biometric or passcode
  authentication. The Secure Enclave Processor enforces this — there is no
  user-mode bypass.

### In-process memory protection

The memory protection subsystem defends against **same-process heap scraping**:

- **Guard pages** (`SecureBuffer`). `PROT_NONE` pages on both sides of a
  secret buffer cause SIGSEGV on overflow/underflow. Random canaries are
  verified on `destroy()`.
- **mlock.** Secret pages are pinned in RAM and excluded from core dumps
  (`madvise(MADV_DONTDUMP)` on Linux, `MADV_NOCORE` on BSD).
- **AES-256-GCM sealing** (`MemoryEnclave`). Decrypted secrets exist in
  plaintext only briefly during `open()` — between that call and the
  `PoolSlot::drop`. The rest of the time they are AES-256-GCM ciphertext
  on the heap.
- **Coffer key splitting.** The master encryption key is never stored whole.
  It is split as `left XOR SHA-256(right)` across two mlock'd slab slots;
  neither half alone reveals the key.
- **Zeroization.** All secret-bearing types zero their memory on drop.

### Tamper-evident metadata

`TamperEvidentHandle` protects configuration and key metadata files from
undetected modification:

- **Sidecar mode** (default). HMAC-SHA-256 of the file content is stored in
  a `.hmac` sidecar. Modification of either the file or the sidecar is
  detected on next `verify()`.
- **TrustAnchor mode.** Per-file HMAC tag stored in the platform secure
  store (Keychain/DPAPI/Secret Service). Deleting the sidecar does not
  bypass verification.

---

## What enclave does NOT protect

### Same-UID attacker with code execution

An attacker running as the same user with arbitrary code execution in the
process can:

- Read live memory directly after `open()` returns the plaintext.
- Invoke `sign()` or `decrypt()` using the legitimate handle objects in memory.
- Hook function calls to intercept return values.

This is the universal limitation of user-mode security. The hardware
provides extraction resistance against **passive** attackers (file theft,
memory snapshot, cold-boot) but not against an **active** attacker with code
execution.

**Mitigation.** `harden_process()` sets `RLIMIT_CORE=0`, `PR_SET_DUMPABLE=0`
(Linux), and Windows strict handle / image-load mitigations. This raises the
bar for common attack tooling but is not a hard cryptographic boundary.

### Key metadata and label exposure

Key labels, creation timestamps, and access policies are stored in `.meta`
files. An attacker who can read the key directory knows what keys exist and
when they were created, even if they cannot extract the private key material.

### Availability attacks

An attacker who can delete key files or the key directory can cause
`sign()` and `decrypt()` to fail. `TamperEvidentHandle` detects modification
but does not prevent deletion.

### Cross-tenant isolation

`enclave` does not enforce isolation between different applications running
as the same user. Two applications using the same `app_name` share a key
namespace. Use unique, unguessable app names and the `-unsigned` suffix
applied automatically for development builds.

### Post-quantum security

All cryptographic primitives use ECDSA/ECDH P-256, which is not
post-quantum secure. The credentials protected by this library (cached
tokens, SSH keys, session secrets) are typically short-lived, which limits
the value of a "harvest now, decrypt later" attack. Post-quantum algorithm
support will be added when hardware security modules provide it.

---

## Residual risks

| Risk | Mitigation required |
|------|---------------------|
| Plaintext window after `open()` | Use `PoolSlot` only within the narrowest possible scope. Do not store the result in long-lived data structures. |
| Core dump before `harden_process()` runs | Call `harden_process()` (called automatically by `TieredPool::new()`) or call it explicitly at the top of `main()`. |
| Swap exposure of non-pool memory | Use `SecureBuffer` or `LockedBuffer` for any secret-containing allocation that lives outside the pool. |
| Metadata leakage | Run key directories with 0o700 permissions. |
| App name collision | Use globally unique app names. The `-unsigned` suffix prevents dev/prod collision. |

---

## Security contact

Report vulnerabilities to the GoDaddy security team at
security@godaddy.com or via https://hackerone.com/godaddy.
