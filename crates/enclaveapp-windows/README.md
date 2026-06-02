# enclaveapp-windows

Windows TPM 2.0 backend for enclave, using CNG (NCrypt/BCrypt).

Keys are generated inside the TPM via the Microsoft Platform Crypto Provider and never leave the hardware. CNG persists keys internally by name -- no private key files on disk.

## Features

- **`signing`** -- `TpmSigner` implementing `EnclaveSigner` (ECDSA P-256 via `NCryptSignHash`)
- **`encryption`** -- `TpmEncryptor` implementing `EnclaveEncryptor` (ECIES via ECDH + AES-GCM)

```toml
enclaveapp-windows = { version = "0.1", features = ["signing"] }
```

## How it works

### Signing

1. `NCryptCreatePersistedKey` creates an ECDSA P-256 key in the TPM
2. Keys are named `<app_name>-<label>` (e.g., `sshenc-default`)
3. On sign: SHA-256 hash of the data, then `NCryptSignHash` produces a P1363 signature (r||s), which is converted to DER

### Encryption

1. `NCryptCreatePersistedKey` creates an ECDH P-256 key in the TPM
2. On encrypt: BCrypt generates an ephemeral ECDH key pair, `BCryptSecretAgreement` derives a shared secret, HASH KDF produces an AES-256 key, BCrypt AES-GCM encrypts
3. On decrypt: `NCryptSecretAgreement` uses the TPM-bound private key with the ephemeral public key from the ciphertext

### Windows Hello

When `AccessPolicy` is not `None`, the key is created with `NCRYPT_UI_POLICY_PROPERTY` requiring user authentication before key use. If the UI policy cannot be applied, key creation fails rather than silently falling back to an unprotected key.

## Cross-platform modules

The `convert` module contains pure-Rust helpers that compile on all platforms:

- `p1363_to_der` / `der_to_p1363` -- signature format conversion
- `eccpublic_blob_to_sec1` / `sec1_to_eccpublic_blob` -- public key format conversion
- `key_name` -- CNG key naming convention

These are useful for testing and for other crates that need to work with these formats.

## Custom key storage

Metadata and cached public keys are stored on disk. By default in `%APPDATA%\<app_name>\keys\`. Override with `with_keys_dir`:

```rust
let signer = TpmSigner::with_keys_dir("sshenc", PathBuf::from(r"C:\Users\user\.sshenc\keys"));
```

On non-Windows platforms, the crate compiles as an empty stub.
