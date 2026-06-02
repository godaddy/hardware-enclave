// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Demonstrates tamper-evident file protection.
//!
//! **Default mode** — uses an ephemeral in-memory HMAC key. Zero interactive
//! prompts. No Keychain / DPAPI / D-Bus access. Safe for CI and examples.
//!
//! **Interactive mode** (`ENCLAVE_INTERACTIVE=1`) — uses the real platform
//! secure store. On macOS, an unsigned binary will show a login-keychain
//! password prompt (not Touch ID). On a signed binary with the correct
//! entitlements, this would use biometrics instead.
//!
//! ```text
//! # Default (no prompts, CI-safe):
//! cargo run --example integrity
//!
//! # Interactive (real Keychain/DPAPI — requires explicit consent):
//! ENCLAVE_INTERACTIVE=1 cargo run --example integrity
//! ```
//!
//! The example covers:
//! - Sidecar mode: write → verify Match → corrupt → detect Tamper
//! - Protecting a directory of multiple files
//! - `VerifyOutcome` variants: Match, Tamper, Legacy, NotFound
//! - `migrate()` to bootstrap HMAC protection on pre-existing files
//! - Cleanup: all files are in `TempDir`s, removed automatically on exit

#![allow(clippy::print_stdout)]
#![allow(clippy::unwrap_used)]

use enclave::{create_tamper_evident, create_tamper_evident_ephemeral, VerifyOutcome};

/// Returns `true` when running in interactive mode with real hardware.
///
/// Interactive mode requires `ENCLAVE_INTERACTIVE=1` and will show platform
/// secure-store prompts. Only set this when you have explicitly consented to
/// interactive prompts.
fn interactive() -> bool {
    std::env::var("ENCLAVE_INTERACTIVE").is_ok()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    if interactive() {
        println!("Mode: INTERACTIVE (real platform secure store — prompts may appear)");
        println!("Note: unsigned binaries will show a password prompt on macOS.");
        println!("      Signed binaries with keychain-access-groups use biometrics.");
    } else {
        println!("Mode: EPHEMERAL (in-memory key, no platform secure store, no prompts)");
        println!("      Set ENCLAVE_INTERACTIVE=1 to test with real Keychain/DPAPI.");
    }

    println!("\n=== Sidecar mode: single file ===");
    demo_single_file()?;

    println!("\n=== Sidecar mode: directory of files ===");
    demo_directory()?;

    println!("\n=== Legacy file migration ===");
    demo_migration()?;

    if interactive() {
        println!("\n=== TrustAnchor mode (low-volume, high-value file) ===");
        demo_trust_anchor()?;
    } else {
        println!("\n=== TrustAnchor mode: skipped in ephemeral mode ===");
        println!("    (TrustAnchor stores per-file tags in the platform secure store)");
    }

    println!("\nIntegrity example complete.");
    Ok(())
}

// ── Shared constructor ────────────────────────────────────────────────────────

fn make_handle(app: &str) -> Result<enclave::TamperEvidentHandle, Box<dyn std::error::Error>> {
    if interactive() {
        Ok(create_tamper_evident(app)?)
    } else {
        Ok(create_tamper_evident_ephemeral(app))
    }
}

// ── Single file ───────────────────────────────────────────────────────────────

fn demo_single_file() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = tempfile::TempDir::new()?;
    let path = tmp.path().join("config.toml");
    let content = b"[app]\nname = \"myapp\"\n";

    let handle = make_handle("integrity-example")?;

    // Write: atomically writes the file and updates the HMAC sidecar.
    handle.write(&path, content)?;
    println!("  Written: {}", path.display());

    // Verify: content matches the sidecar HMAC.
    match handle.verify(&path)? {
        VerifyOutcome::Match => println!("  Verify: Match ✓"),
        VerifyOutcome::StoreUnavailable => println!("  Verify: StoreUnavailable (ephemeral key)"),
        other => println!("  Verify: unexpected outcome {other:?}"),
    }

    // Read: verify + return content in one call.
    let read_back = handle.read(&path)?;
    assert_eq!(read_back, content);
    println!("  Read: roundtrip verified ✓");

    // Tamper: overwrite file directly, bypassing the API.
    std::fs::write(&path, b"[app]\nname = \"attacker\"\n")?;
    println!("  Tampered: file overwritten externally");

    match handle.verify(&path)? {
        VerifyOutcome::Tamper => println!("  Verify: Tamper detected ✓"),
        VerifyOutcome::StoreUnavailable => {
            println!("  Verify: StoreUnavailable (expected in ephemeral mode with TrustAnchor)");
        }
        other => println!("  Verify: {other:?}"),
    }

    // NotFound.
    let missing = tmp.path().join("nonexistent.toml");
    assert_eq!(handle.verify(&missing)?, VerifyOutcome::NotFound);
    println!("  NotFound: missing file detected ✓");

    // Remove integrity data (sidecar).
    handle.remove_integrity_data(&path)?;

    // TempDir drops here → all files cleaned up automatically.
    Ok(())
}

// ── Directory of files ────────────────────────────────────────────────────────

fn demo_directory() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = tempfile::TempDir::new()?;
    let handle = make_handle("integrity-example-dir")?;

    // Write 10 config files.
    for i in 0..10_u32 {
        let path = tmp.path().join(format!("config-{i:02}.toml"));
        handle.write(&path, format!("value = {i}").as_bytes())?;
    }
    println!("  Written: 10 config files");

    // Verify all — all should Match.
    let mut matches = 0_u32;
    for i in 0..10_u32 {
        let path = tmp.path().join(format!("config-{i:02}.toml"));
        match handle.verify(&path)? {
            VerifyOutcome::Match | VerifyOutcome::StoreUnavailable => matches += 1,
            other => println!("  Unexpected: config-{i:02}.toml → {other:?}"),
        }
    }
    println!("  All {matches}/10 files verified ✓");

    // Corrupt one file.
    let victim = tmp.path().join("config-05.toml");
    std::fs::write(&victim, b"value = 999")?;

    let mut tampers = 0_u32;
    for i in 0..10_u32 {
        let path = tmp.path().join(format!("config-{i:02}.toml"));
        if handle.verify(&path)? == VerifyOutcome::Tamper {
            tampers += 1;
        }
    }
    assert_eq!(tampers, 1, "exactly one file should be tampered");
    println!("  Tamper in config-05.toml detected, {tampers}/10 tampered ✓");

    Ok(())
}

// ── Migration ─────────────────────────────────────────────────────────────────

fn demo_migration() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = tempfile::TempDir::new()?;
    let path = tmp.path().join("legacy.toml");
    let content = b"[legacy]\nformat = 1\n";

    // Write the file WITHOUT using the integrity API (pre-existing file).
    std::fs::write(&path, content)?;
    println!("  Pre-existing file written without integrity API");

    let handle = make_handle("integrity-example-legacy")?;

    // Verify without sidecar → Legacy.
    assert_eq!(handle.verify(&path)?, VerifyOutcome::Legacy);
    println!("  Verify: Legacy (no sidecar yet) ✓");

    // Bootstrap: compute HMAC and write sidecar.
    handle.migrate(&path)?;
    println!("  Migrate: sidecar written");

    // Now verify → Match.
    match handle.verify(&path)? {
        VerifyOutcome::Match => println!("  Verify after migrate: Match ✓"),
        VerifyOutcome::StoreUnavailable => {
            println!("  Verify after migrate: StoreUnavailable (ephemeral, sidecar mode)")
        }
        other => println!("  Verify after migrate: {other:?}"),
    }

    Ok(())
}

// ── TrustAnchor (interactive only) ───────────────────────────────────────────

fn demo_trust_anchor() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = tempfile::TempDir::new()?;
    let path = tmp.path().join("secret.json");
    let content = br#"{"api_key":"sk-test-12345"}"#;

    // TrustAnchor stores a per-file tag in the platform secure store.
    // For an unsigned binary on macOS, this will request the login keychain password.
    // Use this mode only for low-volume, high-value files.
    let handle = create_tamper_evident("integrity-trust-anchor")?.with_trust_anchor();

    println!(
        "  Mode: {:?} (per-file tag in platform secure store)",
        handle.mode()
    );

    handle.write(&path, content)?;

    // Delete the sidecar — should NOT bypass verification in TrustAnchor mode.
    let sidecar = {
        let mut s = path.as_os_str().to_owned();
        s.push(".hmac");
        std::path::PathBuf::from(s)
    };
    if sidecar.exists() {
        std::fs::remove_file(&sidecar)?;
        println!("  Sidecar deleted — trust anchor in secure store still authoritative");
    }

    match handle.verify(&path)? {
        VerifyOutcome::Match => println!("  Verify: Match (sidecar deletion did not bypass) ✓"),
        VerifyOutcome::Legacy => println!("  Verify: Legacy (no trust anchor in store yet)"),
        other => println!("  Verify: {other:?}"),
    }

    // Cleanup: remove the trust anchor from the secure store.
    handle.remove_integrity_data(&path)?;
    println!("  Trust anchor removed from platform secure store ✓");

    Ok(())
}
