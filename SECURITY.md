# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in the Enclave crate, report it privately.

**Do not open a public GitHub issue for security vulnerabilities.**

Email: Report via GitHub's private vulnerability reporting feature on the
[enclave repository](https://github.com/godaddy/enclave/security/advisories/new),
or contact the maintainer directly.

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if you have one)

You will receive an acknowledgment within 72 hours. A fix will be developed
and released as quickly as possible, with credit given to the reporter
(unless anonymity is requested).

## Supported Versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |

Only the latest release receives security fixes.

## Security Model Summary

enclave provides hardware-backed key management via the Secure Enclave
(macOS), TPM 2.0 (Windows/Linux), and a keyring fallback:

- **Private keys never leave the hardware.** Secure Enclave and TPM keys are
  non-exportable. The keyring backend encrypts keys via the system keyring
  (D-Bus Secret Service) -- it does not provide hardware isolation.
- **ECDSA P-256 signing and ECIES encryption.** Both operations are performed
  inside the hardware security module. Only public keys are exported.
- **ECIES ciphertext is authenticated.** AES-GCM provides both confidentiality
  and integrity. Tampering with ciphertext causes decryption failure.
- **Platform-specific trust boundaries.** Each backend (CryptoKit, CNG,
  Linux TPM, software) has different security properties documented in
  [THREAT_MODEL.md](THREAT_MODEL.md).

### What enclave does NOT protect against

- Root/admin compromise (root can bypass all software protections)
- Kernel exploits on any platform
- Physical attacks on the Secure Enclave or TPM hardware
- Side-channel attacks against the hardware security module
- Keyring backend key theft (the keyring backend is not hardware-isolated)

See [THREAT_MODEL.md](THREAT_MODEL.md) for a detailed analysis.

## Dependencies

enclave uses a conservative set of dependencies. Key external crates:

- `p256`, `ecdsa`: Elliptic curve operations (keyring backend)
- `aes-gcm`: Authenticated encryption (keyring backend ECIES)
- `sha2`: Hash functions
- `serde`, `toml`: Configuration serialization
- `zeroize`: Secure memory wiping. Applied selectively — see the zeroize-coverage note in [THREAT_MODEL.md](THREAT_MODEL.md)

All dependencies are published on crates.io and are widely used in the
Rust ecosystem.
