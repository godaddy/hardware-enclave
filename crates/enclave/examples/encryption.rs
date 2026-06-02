// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Demonstrates encryption key lifecycle and ECIES encrypt/decrypt.
//!
//! Run with real hardware:
//!
//! ```text
//! cargo run --example encryption
//! ```
//!
//! Run with software mock (CI-safe, no hardware required):
//!
//! ```text
//! ENCLAVE_MOCK=1 cargo run --example encryption
//! ```
//!
//! When `ENCLAVE_MOCK=1` is set, the example uses the
//! `enclaveapp-test-software` backend with a temporary directory — no
//! Secure Enclave, TPM, or system keyring is accessed.

#![allow(clippy::print_stdout)]
#![allow(clippy::unwrap_used)]

use enclaveapp_core::traits::{EnclaveEncryptor, EnclaveKeyManager};
use enclaveapp_core::types::{AccessPolicy, KeyType};
use enclaveapp_test_software::SoftwareEncryptor;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    let mock_mode = std::env::var("ENCLAVE_MOCK").as_deref() == Ok("1");

    if mock_mode {
        run_with_mock()
    } else {
        run_with_hardware()
    }
}

// ── Mock path ────────────────────────────────────────────────────────────────

fn run_with_mock() -> Result<(), Box<dyn std::error::Error>> {
    println!("[mock] Using software backend (no hardware required)");

    let tmp = tempfile::TempDir::new()?;
    let enc = SoftwareEncryptor::with_keys_dir("example-encryption", tmp.path().to_path_buf());

    // 1. Generate an encryption key.
    let pubkey = enc.generate("example-enc-key", KeyType::Encryption, AccessPolicy::None)?;
    println!(
        "[mock] Generated key. Public key ({} bytes): {}...",
        pubkey.len(),
        bytes_to_hex(&pubkey[..8])
    );

    // 2. Encrypt a secret credential.
    let plaintext = b"my secret credential";
    let ciphertext = enc.encrypt("example-enc-key", plaintext)?;
    println!(
        "[mock] Encrypted {} bytes → {} bytes ciphertext.",
        plaintext.len(),
        ciphertext.len()
    );

    // 3. Verify the ECIES ciphertext format.
    // Wire format: [0x01 version][65B pubkey][12B nonce][ciphertext][16B tag]
    assert_eq!(ciphertext[0], 0x01, "ECIES version byte must be 0x01");
    assert_eq!(
        ciphertext[1], 0x04,
        "Ephemeral pubkey must start with 0x04 (uncompressed)"
    );
    let expected_len = 1 + 65 + 12 + plaintext.len() + 16;
    assert_eq!(
        ciphertext.len(),
        expected_len,
        "Ciphertext length mismatch: expected {expected_len}, got {}",
        ciphertext.len()
    );
    println!("[mock] Ciphertext format validated (ECIES wire format correct).");

    // 4. Decrypt — returns Zeroizing<Vec<u8>>.
    let decrypted = enc.decrypt("example-enc-key", &ciphertext)?;
    assert_eq!(
        decrypted.as_slice(),
        plaintext,
        "Decrypt/encrypt roundtrip mismatch"
    );
    println!(
        "[mock] Decrypt roundtrip verified: {:?}",
        std::str::from_utf8(&decrypted)?
    );

    // 5. list_keys.
    let keys = enc.list_keys()?;
    assert_eq!(keys.len(), 1, "expected 1 key, found {}", keys.len());
    println!("[mock] list_keys() -> {:?}", keys);

    // 6. Encrypt different data to demonstrate freshness (new ephemeral key each time).
    let ct2 = enc.encrypt("example-enc-key", plaintext)?;
    assert_ne!(
        ciphertext, ct2,
        "Each encryption must produce different ciphertext"
    );
    println!("[mock] Fresh encryption produces different ciphertext (ephemeral ECDH key).");

    // 7. delete_key.
    enc.delete_key("example-enc-key")?;
    println!("[mock] Deleted key.");

    // 8. Confirm key is gone.
    let exists = enc.key_exists("example-enc-key")?;
    assert!(!exists, "key should not exist after deletion");
    println!("[mock] key_exists() after deletion -> {exists}");

    println!("[mock] Encryption example complete.");
    Ok(())
}

// ── Hardware path ─────────────────────────────────────────────────────────────

fn run_with_hardware() -> Result<(), Box<dyn std::error::Error>> {
    use enclave::{create_encryptor, AccessPolicy, EnclaveConfig};

    println!("[hardware] Using platform HSM backend.");

    let config = EnclaveConfig::new("enclave-example", "example-enc-key");
    let enc = create_encryptor(&config)?;

    // Clean up any leftover key from a previous run.
    if enc.key_exists("example-enc-key")? {
        println!("[hardware] Removing leftover key from previous run.");
        enc.delete_key("example-enc-key")?;
    }

    // 1. Generate a hardware-backed P-256 encryption key.
    let pubkey = enc.generate_key("example-enc-key", AccessPolicy::None)?;
    println!(
        "[hardware] Generated key. Public key ({} bytes): {}...",
        pubkey.len(),
        bytes_to_hex(&pubkey[..8])
    );

    // 2. Encrypt a secret credential.
    let plaintext = b"my secret credential";
    let ciphertext = enc.encrypt("example-enc-key", plaintext)?;
    println!(
        "[hardware] Encrypted {} bytes → {} bytes ciphertext.",
        plaintext.len(),
        ciphertext.len()
    );

    // 3. Verify ECIES format.
    assert_eq!(ciphertext[0], 0x01, "ECIES version byte must be 0x01");
    println!("[hardware] Ciphertext format validated.");

    // 4. Decrypt.
    let decrypted = enc.decrypt("example-enc-key", &ciphertext)?;
    assert_eq!(decrypted.as_slice(), plaintext);
    println!("[hardware] Decrypt roundtrip verified.");

    // 5. list_keys.
    let keys = enc.list_keys()?;
    println!("[hardware] list_keys() -> {} key(s)", keys.len());

    // 6. delete_key.
    enc.delete_key("example-enc-key")?;
    println!("[hardware] Deleted key.");

    assert!(!enc.key_exists("example-enc-key")?);
    println!("[hardware] Encryption example complete.");

    Ok(())
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
