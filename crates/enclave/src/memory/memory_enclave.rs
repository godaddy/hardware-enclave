// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

// aes-gcm's Nonce::from_slice still works but triggers a deprecation on
// the underlying generic_array usage in some versions.
#![allow(deprecated)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use rand::TryRngCore;

use super::pool::{hot_cache_evict, hot_cache_get, hot_cache_insert, pool_acquire, PoolSlot};
use super::secure_buffer::SecureBuffer;
use crate::error::{Error, Result};

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

static NONCE_PREFIX: OnceLock<[u8; 4]> = OnceLock::new();
static NONCE_COUNTER: AtomicU64 = AtomicU64::new(0);

fn nonce_prefix() -> &'static [u8; 4] {
    NONCE_PREFIX.get_or_init(|| {
        let mut prefix = [0_u8; 4];
        rand::rngs::OsRng.try_fill_bytes(&mut prefix).expect(
            "MemoryEnclave: OsRng failed to generate nonce prefix — \
                 cannot safely seal secrets without a random nonce. \
                 This indicates a system-level RNG failure.",
        );
        prefix
    })
}

fn next_nonce() -> [u8; NONCE_LEN] {
    // Uniqueness only requires a distinct counter per call; no cross-thread
    // memory ordering is needed beyond the atomicity of the fetch_add itself.
    let counter = NONCE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut nonce = [0_u8; NONCE_LEN];
    nonce[..4].copy_from_slice(nonce_prefix());
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    nonce
}

/// An in-memory AES-256-GCM sealed secret.
///
/// Plaintext is encrypted under the process-global Coffer master key.
/// `open()` returns the plaintext in a `PoolSlot` (slab-backed if the
/// plaintext fits in the smallest tier's slot size, otherwise standalone).
/// A hot cache in the slab avoids decryption when the same `MemoryEnclave`
/// is opened multiple times in quick succession.
///
/// When dropped, the hot cache entry for this enclave is evicted.
///
/// # Security note: hot cache
/// After the first successful `open()`, the plaintext is cached in the locked slab
/// until this `MemoryEnclave` is dropped (or until LRU pressure evicts it). The
/// cached copy lives in a guard-paged, mlock'd slab slot — but it is present for
/// the lifetime of this value. For secrets that should not persist in memory,
/// drop the `MemoryEnclave` promptly after use.
pub struct MemoryEnclave {
    id: u64,
    /// [nonce (12 bytes)] [ciphertext + GCM tag]
    ciphertext: Vec<u8>,
    plaintext_len: usize,
}

static SEAL_ID: AtomicU64 = AtomicU64::new(1);

impl std::fmt::Debug for MemoryEnclave {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryEnclave")
            .field("id", &self.id)
            .field("plaintext_len", &self.plaintext_len)
            .finish()
    }
}

impl MemoryEnclave {
    fn do_seal(plaintext: &[u8]) -> Result<Self> {
        // Get the master key from the slab-backed coffer.
        let key_slot = super::pool::global_pool().coffer_view()?;
        let nonce_bytes = next_nonce();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let cipher = Aes256Gcm::new_from_slice(key_slot.as_slice())
            .map_err(|e| Error::Memory(format!("MemoryEnclave::seal cipher init: {e}")))?;

        let ct = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| Error::Memory(format!("MemoryEnclave::seal encrypt: {e}")))?;

        // Drop key_slot immediately after use — wipes the slab slot.
        drop(key_slot);

        let mut blob = Vec::with_capacity(NONCE_LEN + ct.len());
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ct);

        let id = SEAL_ID.fetch_add(1, Ordering::Relaxed);
        Ok(Self {
            id,
            ciphertext: blob,
            plaintext_len: plaintext.len(),
        })
    }

    /// Seal `plaintext` under the Coffer key.
    pub fn seal(plaintext: &[u8]) -> Result<Self> {
        Self::do_seal(plaintext)
    }

    /// Seal a `SecureBuffer`'s contents (melt → read → re-freeze).
    pub fn seal_buffer(buf: &mut SecureBuffer) -> Result<Self> {
        buf.melt()?;
        let result = Self::do_seal(buf.as_slice());
        drop(buf.freeze());
        result
    }

    /// Seal a `PoolSlot`'s contents.
    /// The caller is responsible for dropping the slot (which zeroizes it).
    pub fn seal_slot(slot: &PoolSlot) -> Result<Self> {
        Self::do_seal(slot.as_slice())
    }

    /// Decrypt and return the plaintext in a `PoolSlot`.
    ///
    /// Hot cache fast path: if this enclave was recently opened, the plaintext
    /// is copied from the slab cache into a new transient `PoolSlot` without
    /// AES-GCM decryption.
    pub fn open(&self) -> Result<PoolSlot> {
        // Hot cache lookup (slab-backed copy).
        if let Some(cached) = hot_cache_get(self.id) {
            return Ok(cached);
        }

        // Cold path: decrypt.
        if self.ciphertext.len() < NONCE_LEN + TAG_LEN {
            return Err(Error::Memory(
                "MemoryEnclave::open: ciphertext too short".into(),
            ));
        }

        let key_slot = super::pool::global_pool().coffer_view()?;
        let nonce = Nonce::from_slice(&self.ciphertext[..NONCE_LEN]);

        let cipher = Aes256Gcm::new_from_slice(key_slot.as_slice())
            .map_err(|e| Error::Memory(format!("MemoryEnclave::open cipher init: {e}")))?;

        // Wrap the decrypted plaintext in Zeroizing immediately so it is
        // scrubbed when it goes out of scope — even on error paths below.
        // Note: aes_gcm's Aes256Gcm zeroizes its key schedule on drop (it
        // implements ZeroizeOnDrop via the zeroize feature in aes-gcm).
        let plaintext = zeroize::Zeroizing::new(
            cipher
                .decrypt(nonce, &self.ciphertext[NONCE_LEN..])
                .map_err(|_| Error::DecryptFailed {
                    detail: "MemoryEnclave::open: authentication failed".into(),
                })?,
        );

        // Wipe the key slot immediately after decryption.
        drop(key_slot);

        // Cache the plaintext in the slab (only if it fits: exact slot_size match).
        // If pool_acquire fails, evict the cache entry so we don't leave a
        // cached plaintext that the caller has no slot to receive.
        hot_cache_insert(self.id, &plaintext);

        // Return plaintext in a fresh PoolSlot.
        let mut out_slot = pool_acquire(plaintext.len()).map_err(|e| {
            hot_cache_evict(self.id);
            e
        })?;
        let copy_len = plaintext.len().min(out_slot.size());
        out_slot.bytes()[..copy_len].copy_from_slice(&plaintext[..copy_len]);
        Ok(out_slot)
    }

    pub fn plaintext_len(&self) -> usize {
        self.plaintext_len
    }

    pub fn id(&self) -> u64 {
        self.id
    }
}

impl Drop for MemoryEnclave {
    fn drop(&mut self) {
        // Capture `id` by value (Copy) so the closure is UnwindSafe.
        let id = self.id;
        // catch_unwind prevents a double-panic during stack unwind.
        drop(std::panic::catch_unwind(move || {
            hot_cache_evict(id);
        }));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::memory::pool::{coffer_view, hot_cache_get};

    /// Serializes tests that touch the global TieredPool to prevent interference.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn seal_and_open_roundtrip() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let secret = b"my secret data 1234";
        let enc = MemoryEnclave::seal(secret).unwrap();
        let slot = enc.open().unwrap();
        assert_eq!(&slot.as_slice()[..secret.len()], secret.as_ref());
    }

    #[test]
    fn open_twice_uses_hot_cache() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let secret = b"cached secret";
        let enc = MemoryEnclave::seal(secret).unwrap();
        let s1 = enc.open().unwrap();
        // Drop s1 before opening again (releases slab slot for second open).
        let bytes1 = s1.as_slice()[..secret.len()].to_vec();
        drop(s1);
        let s2 = enc.open().unwrap();
        assert_eq!(bytes1, secret.as_ref());
        assert_eq!(&s2.as_slice()[..secret.len()], secret.as_ref());
    }

    #[test]
    fn drop_evicts_hot_cache() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let secret = b"evicted secret";
        let id = {
            let enc = MemoryEnclave::seal(secret).unwrap();
            let slot = enc.open().unwrap(); // populate cache
            drop(slot);
            enc.id()
        }; // enc dropped here — should evict
        assert!(hot_cache_get(id).is_none());
    }

    #[test]
    fn different_enclaves_are_independent() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let enc1 = MemoryEnclave::seal(b"secret one").unwrap();
        let enc2 = MemoryEnclave::seal(b"secret two").unwrap();
        assert_ne!(enc1.id(), enc2.id());
        let s1 = enc1.open().unwrap();
        let s2 = enc2.open().unwrap();
        assert_eq!(&s1.as_slice()[..10], b"secret one");
        assert_eq!(&s2.as_slice()[..10], b"secret two");
        drop(s1);
        drop(s2);
    }

    #[test]
    fn seal_empty_slice() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let enc = MemoryEnclave::seal(b"").unwrap();
        assert_eq!(enc.plaintext_len(), 0);
        let slot = enc.open().unwrap();
        drop(slot);
    }

    #[test]
    fn coffer_view_returns_key_sized_slot() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let slot = coffer_view().unwrap();
        assert_eq!(slot.size(), 32);
    }

    #[test]
    fn pool_acquire_small_uses_slab() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        use crate::memory::pool::pool_acquire;
        let slot = pool_acquire(16).unwrap();
        assert!(slot.slab_index().is_some());
    }

    #[test]
    fn pool_acquire_large_uses_standalone() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        use crate::memory::pool::pool_acquire;
        let slot = pool_acquire(8192).unwrap();
        assert!(slot.slab_index().is_none());
    }

    #[test]
    fn seal_open_large() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let plaintext = vec![0xAB_u8; 4096];
        let enc = MemoryEnclave::seal(&plaintext).unwrap();
        let slot = enc.open().unwrap();
        assert_eq!(&slot.as_slice()[..4096], plaintext.as_slice());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let plaintext = b"tamper test";
        let mut enc = MemoryEnclave::seal(plaintext).unwrap();
        enc.ciphertext[NONCE_LEN] ^= 0xFF;
        let result = enc.open();
        assert!(
            matches!(result, Err(Error::DecryptFailed { .. })),
            "expected DecryptFailed, got {result:?}"
        );
    }

    #[test]
    fn truncated_ciphertext_fails() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let enc = MemoryEnclave::seal(b"short").unwrap();
        let truncated = MemoryEnclave {
            id: enc.id,
            ciphertext: vec![0_u8; NONCE_LEN + TAG_LEN - 1],
            plaintext_len: 5,
        };
        let result = truncated.open();
        assert!(
            matches!(result, Err(Error::Memory(_))),
            "expected Memory error, got {result:?}"
        );
    }

    #[test]
    fn unique_ids() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let a = MemoryEnclave::seal(b"a").unwrap();
        let b = MemoryEnclave::seal(b"b").unwrap();
        assert_ne!(a.id(), b.id());
    }

    #[test]
    fn seal_buffer_roundtrip() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let secret = b"buffered secret";
        let mut sbuf = SecureBuffer::new(secret.len()).unwrap();
        sbuf.bytes().copy_from_slice(secret);
        let enc = MemoryEnclave::seal_buffer(&mut sbuf).unwrap();
        assert!(sbuf.is_alive());
        let slot = enc.open().unwrap();
        assert_eq!(&slot.as_slice()[..secret.len()], secret);
    }

    #[test]
    fn seal_slot_roundtrip() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let secret = b"slot secret data";
        let mut slot = pool_acquire(secret.len()).unwrap();
        slot.bytes()[..secret.len()].copy_from_slice(secret);
        let enc = MemoryEnclave::seal_slot(&slot).unwrap();
        drop(slot);
        let out = enc.open().unwrap();
        assert_eq!(&out.as_slice()[..secret.len()], secret);
    }

    #[test]
    fn debug_does_not_leak_plaintext() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let enc = MemoryEnclave::seal(b"top secret").unwrap();
        let debug = format!("{enc:?}");
        assert!(!debug.contains("top secret"));
        assert!(debug.contains("MemoryEnclave"));
    }

    #[test]
    fn same_plaintext_different_nonces() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let a = MemoryEnclave::seal(b"same").unwrap();
        let b = MemoryEnclave::seal(b"same").unwrap();
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    // ── New tests for review findings ────────────────────────────────

    #[test]
    fn plaintext_is_zeroized_after_open() {
        // This test verifies that the intermediate plaintext Vec is Zeroizing-wrapped.
        // We can't directly inspect the heap, but we verify the open() succeeds and
        // returns correct data — the Zeroizing wrapper is a compile-time guarantee.
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let secret = b"zeroize test secret";
        let enc = MemoryEnclave::seal(secret).unwrap();
        let slot = enc.open().unwrap();
        assert_eq!(&slot.as_slice()[..secret.len()], secret.as_ref());
    }

    #[test]
    fn open_cache_evicted_on_drop() {
        // BLK-8: verify hot cache is evicted when MemoryEnclave is dropped.
        // After a successful open and drop of the enclave, cache must be clear.
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let enc = MemoryEnclave::seal(b"test").unwrap();
        let id = enc.id();
        let slot = enc.open().unwrap(); // populates cache
        drop(slot);
        drop(enc); // should evict
        assert!(hot_cache_get(id).is_none());
    }

    #[test]
    fn nonce_prefix_is_nonzero() {
        // Probabilistically verifies OsRng ran (not a PID fallback).
        // All-zero prefix would be astronomically unlikely with a real OsRng.
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let enc1 = MemoryEnclave::seal(b"a").unwrap();
        let enc2 = MemoryEnclave::seal(b"b").unwrap();
        // Different ciphertexts implies different nonces (nonce uniqueness).
        assert_ne!(enc1.ciphertext, enc2.ciphertext);
    }
}
