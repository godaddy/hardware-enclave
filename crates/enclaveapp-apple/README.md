# enclaveapp-apple

macOS Secure Enclave backend for enclave, using CryptoKit via a Swift bridge.

Keys are generated inside the Secure Enclave and never leave it. The private key material is non-exportable and device-bound. Only an opaque `dataRepresentation` handle is persisted to disk for reloading.

## Features

- **`signing`** -- `SecureEnclaveSigner` implementing `EnclaveSigner` (ECDSA P-256)
- **`encryption`** -- `SecureEnclaveEncryptor` implementing `EnclaveEncryptor` (ECIES)

Enable one or both in your `Cargo.toml`:

```toml
enclaveapp-apple = { version = "0.1", features = ["signing"] }
```

## How it works

### Signing (sshenc)

1. `SecureEnclave.P256.Signing.PrivateKey` is created in the SE
2. The `dataRepresentation` is saved as a `.handle` file
3. On sign, the handle is loaded and `key.signature(for: data)` is called
4. CryptoKit hashes with SHA-256 internally and returns a DER-encoded ECDSA signature

### Encryption (awsenc, sso-jwt)

1. `SecureEnclave.P256.KeyAgreement.PrivateKey` is created in the SE
2. On encrypt: an ephemeral P256 key pair is generated in software, ECDH derives a shared secret with the SE key's public key, X9.63 KDF produces an AES-256 key, AES-GCM encrypts the plaintext
3. On decrypt: the SE private key performs ECDH with the ephemeral public key from the ciphertext, same KDF, AES-GCM decrypts

### Access control

All key types support optional user presence requirements:

| Policy | macOS behavior |
|---|---|
| `None` | No authentication required |
| `Any` | Touch ID or device password |
| `BiometricOnly` | Touch ID only |
| `PasswordOnly` | Device password only |

## Build

Requires Xcode (for `swiftc`). The `build.rs` compiles `swift/bridge.swift` into a static library and links CryptoKit, Security, and LocalAuthentication frameworks.

On non-macOS platforms, the crate compiles as an empty stub.

## Custom key storage

By default, keys are stored in `~/.config/<app_name>/keys/`. For backward compatibility with existing key locations, use `with_keys_dir`:

```rust
let signer = SecureEnclaveSigner::with_keys_dir("sshenc", PathBuf::from("/home/user/.sshenc/keys"));
```
