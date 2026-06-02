// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Demonstrates signing key lifecycle and ECDSA P-256 signing.
//!
//! Run with real hardware:
//!
//! ```text
//! cargo run --example signing
//! ```
//!
//! Run with software mock (CI-safe, no hardware required):
//!
//! ```text
//! ENCLAVE_MOCK=1 cargo run --example signing
//! ```
//!
//! When `ENCLAVE_MOCK=1` is set, the example uses the
//! `enclaveapp-test-software` backend with a temporary directory — no
//! Secure Enclave, TPM, or system keyring is accessed.

#![allow(clippy::print_stdout)]
#![allow(clippy::unwrap_used)]

use enclaveapp_core::traits::{EnclaveKeyManager, EnclaveSigner};
use enclaveapp_core::types::{AccessPolicy, KeyType};
use enclaveapp_test_software::SoftwareSigner;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing for readable output.
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
    let signer = SoftwareSigner::with_keys_dir("example-signing", tmp.path().to_path_buf());

    // 1. Generate a signing key.
    let pubkey = signer.generate("example-signing-key", KeyType::Signing, AccessPolicy::None)?;
    println!(
        "[mock] Generated key. Public key ({} bytes): {}...",
        pubkey.len(),
        bytes_to_hex(&pubkey[..8])
    );

    // 2. Sign some data.
    let message = b"hello from the signing example";
    let sig = signer.sign("example-signing-key", message)?;
    println!(
        "[mock] Signature ({} bytes): {}...",
        sig.len(),
        bytes_to_hex(&sig[..8])
    );

    // 3. Verify the signature is valid DER (starts with 0x30 SEQUENCE tag).
    assert_eq!(
        sig[0], 0x30,
        "DER ECDSA signature must start with SEQUENCE tag 0x30"
    );
    assert!(
        (68..=73).contains(&sig.len()),
        "DER P-256 signature should be 68-73 bytes, got {}",
        sig.len()
    );
    println!(
        "[mock] Signature format validated (DER SEQUENCE, {} bytes).",
        sig.len()
    );

    // 4. Verify the signature with the p256 crate.
    verify_signature(&pubkey, message, &sig)?;
    println!("[mock] Signature cryptographically verified.");

    // 5. list_keys — should show one key.
    let keys = signer.list_keys()?;
    assert_eq!(keys.len(), 1, "expected 1 key, found {}", keys.len());
    println!("[mock] list_keys() -> {:?}", keys);

    // 6. key_exists — true before deletion.
    let exists = signer.key_exists("example-signing-key")?;
    assert!(exists, "key should exist before deletion");

    // 7. delete_key.
    signer.delete_key("example-signing-key")?;
    println!("[mock] Deleted key.");

    // 8. key_exists — false after deletion.
    let exists_after = signer.key_exists("example-signing-key")?;
    assert!(!exists_after, "key should not exist after deletion");
    println!("[mock] key_exists() after deletion -> {exists_after}");

    println!("[mock] Signing example complete.");
    Ok(())
}

// ── Hardware path ─────────────────────────────────────────────────────────────

fn run_with_hardware() -> Result<(), Box<dyn std::error::Error>> {
    use enclave::{create_signer, AccessPolicy, EnclaveConfig};

    println!("[hardware] Using platform HSM backend.");

    let config = EnclaveConfig::new("enclave-example", "example-signing-key");
    let signer = create_signer(&config)?;

    // Clean up any leftover key from a previous run.
    if signer.key_exists("example-signing-key")? {
        println!("[hardware] Removing leftover key from previous run.");
        signer.delete_key("example-signing-key")?;
    }

    // 1. Generate a hardware-backed P-256 signing key.
    let pubkey = signer.generate_key("example-signing-key", AccessPolicy::None)?;
    println!(
        "[hardware] Generated key. Public key ({} bytes): {}...",
        pubkey.len(),
        bytes_to_hex(&pubkey[..8])
    );

    // 2. Sign data.
    let message = b"hello from the signing example";
    let sig = signer.sign("example-signing-key", message)?;
    println!(
        "[hardware] Signature ({} bytes): {}...",
        sig.len(),
        bytes_to_hex(&sig[..8])
    );

    // 3. Verify the DER format.
    assert_eq!(
        sig[0], 0x30,
        "DER ECDSA signature must start with SEQUENCE tag 0x30"
    );
    println!("[hardware] Signature format validated.");

    // 4. Verify cryptographically.
    verify_signature(&pubkey, message, &sig)?;
    println!("[hardware] Signature cryptographically verified.");

    // 5. list_keys.
    let keys = signer.list_keys()?;
    println!("[hardware] list_keys() -> {} key(s)", keys.len());
    assert!(!keys.is_empty(), "at least one key should exist");

    // 6. key_exists.
    assert!(signer.key_exists("example-signing-key")?);

    // 7. delete_key.
    signer.delete_key("example-signing-key")?;
    println!("[hardware] Deleted key.");

    // 8. key_exists — false after deletion.
    assert!(!signer.key_exists("example-signing-key")?);
    println!("[hardware] Signing example complete.");

    Ok(())
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn verify_signature(
    pub_bytes: &[u8],
    message: &[u8],
    sig_bytes: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    use p256::ecdsa::{signature::Verifier, DerSignature, VerifyingKey};
    let point = p256::EncodedPoint::from_bytes(pub_bytes)
        .map_err(|e| format!("invalid public key point: {e}"))?;
    let vk = VerifyingKey::from_encoded_point(&point)
        .map_err(|e| format!("invalid verifying key: {e}"))?;
    let sig =
        DerSignature::from_bytes(sig_bytes).map_err(|e| format!("invalid DER signature: {e}"))?;
    vk.verify(message, &sig)
        .map_err(|e| format!("signature verification failed: {e}").into())
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
