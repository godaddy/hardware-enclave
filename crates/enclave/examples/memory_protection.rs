// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Demonstrates the in-process memory protection subsystem.
//!
//! This example requires no hardware and runs on all platforms:
//!
//! ```text
//! cargo run --example memory_protection
//! ```
//!
//! Covers:
//! - `SecureBuffer` — guard-paged, mlock'd allocation
//! - `LockedBuffer` — Arc-wrapped, thread-safe locked memory
//! - `MemoryEnclave` — AES-256-GCM in-memory sealed secret
//! - Pool: `pool_acquire` / `pool_release` / `coffer_view`

#![allow(clippy::print_stdout)]
#![allow(clippy::unwrap_used)]

use enclave::{coffer_view, pool_acquire, pool_release, LockedBuffer, MemoryEnclave, SecureBuffer};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    println!("=== SecureBuffer ===");
    demo_secure_buffer()?;

    println!("\n=== LockedBuffer ===");
    demo_locked_buffer()?;

    println!("\n=== MemoryEnclave ===");
    demo_memory_enclave()?;

    println!("\n=== Pool (pool_acquire / coffer_view) ===");
    demo_pool()?;

    println!("\nMemory protection example complete.");
    Ok(())
}

fn demo_secure_buffer() -> Result<(), Box<dyn std::error::Error>> {
    // Allocate a 32-byte guard-paged, mlock'd buffer.
    let key_material = [0xAB_u8; 32];
    let mut buf = SecureBuffer::new(32)?;
    println!("  Allocated SecureBuffer (32 bytes, state=Mutable).");

    // Write a secret into it.
    buf.bytes().copy_from_slice(&key_material);
    println!("  Wrote secret data.");

    // Freeze — makes the buffer read-only (PROT_READ).
    buf.freeze()?;
    println!("  Frozen (read-only).");
    assert_eq!(buf.as_slice(), &key_material);
    println!("  Read back: {}...", bytes_to_hex(&buf.as_slice()[..4]));

    // Melt — re-enables writes.
    buf.melt()?;
    buf.bytes().fill(0xFF);
    println!("  Melted and overwrote with 0xFF.");

    // Explicit destroy — verifies guard-page canaries, zeroizes, unmaps.
    buf.destroy()?;
    println!("  Destroyed (canaries verified, memory zeroized and unmapped).");

    Ok(())
}

fn demo_locked_buffer() -> Result<(), Box<dyn std::error::Error>> {
    let secret = b"locked secret value";

    // Create from bytes — copies into locked memory.
    let buf = LockedBuffer::from_bytes(secret.as_ref())?;
    println!("  Created LockedBuffer from bytes ({} bytes).", buf.size());

    // Get a Zeroizing copy — a heap allocation that zeroes itself on drop.
    {
        let copy = buf.bytes_zeroizing();
        assert_eq!(copy.as_slice(), secret.as_ref());
        println!("  bytes_zeroizing() returned correct data.");
        // `copy` dropped here — its heap allocation is zeroed.
    }

    // Random buffer.
    let rand_buf = LockedBuffer::random(32)?;
    let rand_bytes = rand_buf.bytes_zeroizing();
    assert_eq!(rand_bytes.len(), 32);
    println!(
        "  LockedBuffer::random(32) produced {} non-zero bytes.",
        rand_bytes.iter().filter(|&&b| b != 0).count()
    );

    // Explicit wipe.
    buf.wipe();
    let wiped = buf.bytes_zeroizing();
    assert!(wiped.iter().all(|&b| b == 0), "wipe() must zero the buffer");
    println!("  wipe() zeroed the buffer.");

    Ok(())
}

fn demo_memory_enclave() -> Result<(), Box<dyn std::error::Error>> {
    let session_token = b"my session token 1234";

    // Seal plaintext under the process-global Coffer key (AES-256-GCM).
    let sealed = MemoryEnclave::seal(session_token)?;
    println!(
        "  Sealed {} bytes. MemoryEnclave id={}.",
        session_token.len(),
        sealed.id()
    );

    // Cold path: AES-256-GCM decrypt into a locked PoolSlot.
    {
        let slot = sealed.open()?;
        assert_eq!(
            &slot.as_slice()[..session_token.len()],
            session_token,
            "Seal/open roundtrip mismatch"
        );
        println!("  open() (cold path) → plaintext verified.");
        // slot drops here → zeroed immediately.
    }

    // Hot path: second open() copies from the slab cache (no crypto).
    {
        let slot = sealed.open()?;
        assert_eq!(&slot.as_slice()[..session_token.len()], session_token);
        println!("  open() (hot cache path) → plaintext verified.");
    }

    // Two seals of the same plaintext produce different ciphertexts (random nonces).
    let sealed2 = MemoryEnclave::seal(session_token)?;
    assert_ne!(
        sealed.id(),
        sealed2.id(),
        "Each seal must produce a distinct ID"
    );
    println!(
        "  Two seals of the same data produce distinct IDs ({} vs {}).",
        sealed.id(),
        sealed2.id()
    );

    // Drop sealed → hot cache evicted.
    drop(sealed);
    drop(sealed2);
    println!("  Dropped MemoryEnclave values — hot cache evicted.");

    Ok(())
}

fn demo_pool() -> Result<(), Box<dyn std::error::Error>> {
    // Acquire a 32-byte slab-backed slot.
    let mut slot = pool_acquire(32)?;
    println!("  pool_acquire(32) → PoolSlot ({} bytes).", slot.size());

    // Write a secret into it.
    slot.bytes().fill(0xCC);
    println!("  Wrote 0xCC into slot.");

    // Manual release (normally just drop).
    pool_release(slot);
    println!("  pool_release() returned slot to pool (slot zeroed).");

    // coffer_view — the master AES-256 key for direct use.
    {
        let key_slot = coffer_view()?;
        assert_eq!(key_slot.size(), 32, "Coffer key must be 32 bytes (AES-256)");
        println!("  coffer_view() → 32-byte AES-256 master key slot acquired.");
        // key_slot drops here — slot returned to pool.
    }
    println!("  coffer_view dropped — key slot returned to pool.");

    // Larger allocation falls back to a standalone SecureBuffer (not slab-backed).
    let big_slot = pool_acquire(8192)?;
    println!(
        "  pool_acquire(8192) → PoolSlot ({} bytes, standalone SecureBuffer).",
        big_slot.size()
    );
    drop(big_slot);
    println!("  Large slot dropped — SecureBuffer destroyed.");

    Ok(())
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
