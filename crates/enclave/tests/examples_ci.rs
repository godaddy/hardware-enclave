// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! CI harness: compiles and runs each example in non-interactive mode to
//! verify they work correctly without hardware, without Keychain access,
//! and without any interactive prompts.
//!
//! **Non-interactive examples (always run in CI):**
//! - `memory_protection` — guard-paged buffers, sealed secrets (no hardware needed)
//! - `integrity` — tamper-evident files with ephemeral in-memory HMAC key
//! - `signing` with `ENCLAVE_MOCK=1` — software P-256 backend
//! - `encryption` with `ENCLAVE_MOCK=1` — software P-256 backend
//!
//! **Interactive examples (never run automatically):**
//! - Same examples with `ENCLAVE_INTERACTIVE=1` — touch real Keychain/DPAPI/Hello
//! - `signing` / `encryption` without `ENCLAVE_MOCK` — real HSM
//!
//! Interactive tests require explicit opt-in and are run manually on developer
//! machines where hardware and biometric prompts are available.
//!
//! # Rules enforced by this harness
//!
//! 1. Never set `ENCLAVE_INTERACTIVE`. If an example tries to touch the
//!    platform secure store (Keychain, DPAPI, D-Bus Secret Service) without
//!    this being set, that is a bug in the example.
//!
//! 2. Never enumerate all secrets and filter later. Examples must access
//!    only specifically named secrets (keyed by app_name + label).
//!
//! 3. Never cross-access another binary's secure storage. The `-unsigned`
//!    suffix applied automatically to unsigned binaries prevents collisions
//!    with signed production keys.

#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
#![allow(clippy::print_stderr)]

use std::process::Command;

/// Run an example with the given environment additions.
/// Never sets ENCLAVE_INTERACTIVE.
fn run_example_with_env(name: &str, extra_env: &[(&str, &str)]) -> bool {
    let mut cmd = Command::new(env!("CARGO"));
    cmd.args(["run", "--example", name, "--quiet"])
        // Clean logging — avoid tracing noise that looks like failures.
        .env("RUST_LOG", "warn")
        // Explicitly UNSET ENCLAVE_INTERACTIVE to ensure no interactive prompts fire.
        .env_remove("ENCLAVE_INTERACTIVE")
        .current_dir(env!("CARGO_MANIFEST_DIR"));

    for (k, v) in extra_env {
        cmd.env(k, v);
    }

    let output = cmd
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn cargo run --example {name}: {e}"));

    if !output.status.success() {
        eprintln!(
            "example '{name}' failed (exit {:?}):\nstdout:\n{}\nstderr:\n{}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    output.status.success()
}

// ── Non-interactive CI tests ──────────────────────────────────────────────────

#[test]
fn example_memory_protection() {
    // Memory protection never requires hardware or platform secure store.
    assert!(
        run_example_with_env("memory_protection", &[]),
        "memory_protection example failed"
    );
}

#[test]
fn example_integrity_ephemeral() {
    // integrity example uses create_tamper_evident_ephemeral() by default:
    // random in-memory HMAC key, no Keychain/DPAPI/D-Bus, no interactive prompts.
    assert!(
        run_example_with_env("integrity", &[]),
        "integrity example (ephemeral mode) failed"
    );
}

#[test]
fn example_signing_mock() {
    // ENCLAVE_MOCK=1 causes the signing example to use the software P-256 backend
    // (enclaveapp-test-software) via a TempDir. No Keychain access, no HSM.
    assert!(
        run_example_with_env("signing", &[("ENCLAVE_MOCK", "1")]),
        "signing example (mock mode) failed"
    );
}

#[test]
fn example_encryption_mock() {
    // ENCLAVE_MOCK=1 causes the encryption example to use the software P-256 backend.
    assert!(
        run_example_with_env("encryption", &[("ENCLAVE_MOCK", "1")]),
        "encryption example (mock mode) failed"
    );
}

// ── Interactive tests (not run automatically) ─────────────────────────────────
//
// These tests are IGNORED by default. Run them explicitly with:
//   ENCLAVE_INTERACTIVE=1 cargo test --test examples_ci -- --ignored
//
// They will show biometric prompts on machines with Touch ID / Windows Hello,
// or password prompts on unsigned macOS binaries without entitlements.
//
// Each interactive test cleans up its own Keychain/DPAPI entries on exit.

#[test]
#[ignore = "requires real hardware and interactive prompts (ENCLAVE_INTERACTIVE=1)"]
fn example_integrity_interactive() {
    // Tests the real Keychain/DPAPI path including TrustAnchor mode.
    // On macOS, an unsigned binary will show a password prompt.
    // A signed binary with keychain-access-groups would use Touch ID.
    assert!(
        run_example_with_env("integrity", &[("ENCLAVE_INTERACTIVE", "1")]),
        "integrity example (interactive mode) failed"
    );
}

#[test]
#[ignore = "requires real hardware and interactive prompts (ENCLAVE_INTERACTIVE=1)"]
fn example_signing_real_hardware() {
    // Tests signing against the real Secure Enclave / TPM.
    // May prompt for Touch ID or Windows Hello.
    assert!(
        run_example_with_env("signing", &[]),
        "signing example (real hardware) failed"
    );
}

#[test]
#[ignore = "requires real hardware and interactive prompts (ENCLAVE_INTERACTIVE=1)"]
fn example_encryption_real_hardware() {
    assert!(
        run_example_with_env("encryption", &[]),
        "encryption example (real hardware) failed"
    );
}
