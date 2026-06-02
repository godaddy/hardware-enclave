# enclaveapp-test-support

Mock implementations of all enclave traits for testing without hardware.

## Usage

```rust
use enclaveapp_test_support::MockKeyBackend;
use enclaveapp_core::{EnclaveKeyManager, EnclaveSigner, EnclaveEncryptor, KeyType, AccessPolicy};

let backend = MockKeyBackend::new();

// Generate a signing key
let pub_key = backend.generate("test-key", KeyType::Signing, AccessPolicy::None)?;
assert_eq!(pub_key.len(), 65);

// Sign data
let sig = backend.sign("test-key", b"hello world")?;
assert!(sig[0] == 0x30); // DER SEQUENCE

// Generate an encryption key
backend.generate("enc-key", KeyType::Encryption, AccessPolicy::None)?;

// Encrypt/decrypt roundtrip
let ciphertext = backend.encrypt("enc-key", b"secret")?;
let plaintext = backend.decrypt("enc-key", &ciphertext)?;
assert_eq!(plaintext, b"secret");
```

## Behavior

- **Deterministic**: the same label always produces the same public key
- **In-memory**: no files, no hardware, no side effects
- **Thread-safe**: `Mutex`-protected internal state
- **Type-enforced**: signing keys reject encrypt/decrypt, encryption keys reject sign
- **Duplicate detection**: generating the same label twice returns `DuplicateLabel`
- **Mock crypto**: XOR-based encryption and fake DER signatures -- tests control flow, not cryptographic correctness

## Implements

- `EnclaveKeyManager` -- generate, public_key, list_keys, delete_key, is_available
- `EnclaveSigner` -- sign (produces minimal DER-encoded fake signatures)
- `EnclaveEncryptor` -- encrypt/decrypt (XOR with deterministic seed)
