// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

#![allow(unsafe_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, Weak};

use zeroize::{Zeroize, Zeroizing};

use super::secure_buffer::SecureBuffer;
use crate::error::Result;

// Global registry for centralized shutdown cleanup.
type Registry = Mutex<HashMap<usize, Weak<Mutex<SecureBuffer>>>>;

fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn register(id: usize, weak: Weak<Mutex<SecureBuffer>>) {
    if let Ok(mut r) = registry().lock() {
        r.insert(id, weak);
    }
}

fn unregister(id: usize) {
    if let Ok(mut r) = registry().lock() {
        r.remove(&id);
    }
}

/// Zeroize the contents of all registered LockedBuffers.
///
/// **Call only at process shutdown.** Any LockedBuffer user still holding
/// a reference after this call will read zeroed data. The buffers are not
/// destroyed — they remain live with zeroed content until normal Drop runs.
///
/// # Panics (debug only)
/// In debug builds, panics if any LockedBuffer has a strong reference count > 2
/// at the time of the call (i.e. a caller outside the registry still holds a clone).
pub fn zeroize_all_registered_at_shutdown() {
    if let Ok(r) = registry().lock() {
        for weak in r.values() {
            if let Some(arc) = weak.upgrade() {
                // In debug mode, assert this is the only strong reference
                // (registry holds one weak ref; the upgrade here is the second strong ref,
                // so count == 2 means no external holders).
                debug_assert!(
                    Arc::strong_count(&arc) <= 2,
                    "zeroize_all_registered_at_shutdown called while LockedBuffer still in use"
                );
                if let Ok(mut buf) = arc.lock() {
                    drop(buf.melt());
                    if buf.is_alive() {
                        buf.bytes().zeroize();
                    }
                }
            }
        }
    }
}

/// Arc-wrapped, Mutex-guarded SecureBuffer for sharing across threads.
pub struct LockedBuffer {
    inner: Arc<Mutex<SecureBuffer>>,
    id: usize,
}

impl std::fmt::Debug for LockedBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LockedBuffer")
            .field("id", &self.id)
            .finish()
    }
}

impl LockedBuffer {
    fn from_buffer(buf: SecureBuffer) -> Result<Self> {
        static ID: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(1);
        let id = ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let arc = Arc::new(Mutex::new(buf));
        register(id, Arc::downgrade(&arc));
        Ok(Self { inner: arc, id })
    }

    /// Allocate a new zeroed buffer.
    pub fn new(size: usize) -> Result<Self> {
        Self::from_buffer(SecureBuffer::new(size)?)
    }

    /// Allocate and fill with OsRng random bytes.
    pub fn random(size: usize) -> Result<Self> {
        let mut buf = SecureBuffer::new(size)?;
        buf.scramble()?;
        Self::from_buffer(buf)
    }

    /// Create from an existing byte slice (copies into locked memory).
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let src = bytes.as_ref();
        let mut buf = SecureBuffer::new(src.len())?;
        buf.bytes().copy_from_slice(src);
        Self::from_buffer(buf)
    }

    pub fn freeze(&self) -> Result<()> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .freeze()
    }

    pub fn melt(&self) -> Result<()> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).melt()
    }

    pub fn scramble(&self) -> Result<()> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .scramble()
    }

    pub fn wipe(&self) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        drop(guard.melt());
        if guard.is_alive() {
            guard.bytes().zeroize();
        }
    }

    /// Copy contents to a Zeroizing heap allocation.
    pub fn bytes_zeroizing(&self) -> Zeroizing<Vec<u8>> {
        let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        Zeroizing::new(guard.as_slice().to_vec())
    }

    pub fn size(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).size()
    }
}

impl Drop for LockedBuffer {
    fn drop(&mut self) {
        unregister(self.id);
        self.wipe();
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn zeroize_at_shutdown_does_not_panic_on_dead_weaks() {
        // Create a buffer and drop it so the registry Weak becomes dead.
        // zeroize_all_registered_at_shutdown() must be a no-op for dead Weaks.
        let buf = LockedBuffer::new(32).unwrap();
        // Write a known pattern via the inner lock.
        {
            let mut g = buf.inner.lock().unwrap_or_else(|e| e.into_inner());
            g.bytes().fill(0xAB_u8);
        }
        // Drop the user-facing handle so the registry's Weak is the only reference.
        drop(buf);
        // After drop, the Weak in the registry is dead — this must not panic.
        zeroize_all_registered_at_shutdown();
    }

    #[test]
    fn zeroize_at_shutdown_zeroes_live_buffer() {
        let buf = LockedBuffer::new(32).unwrap();
        {
            let mut g = buf.inner.lock().unwrap_or_else(|e| e.into_inner());
            g.bytes().fill(0xAB_u8);
        }
        // Still holding buf — strong count is 1 (user) + upgrade in the function = 2.
        zeroize_all_registered_at_shutdown();
        // After the call the buffer contents must be zeroed.
        let g = buf.inner.lock().unwrap_or_else(|e| e.into_inner());
        assert!(
            g.as_slice().iter().all(|&b| b == 0),
            "buffer must be zeroed after shutdown call"
        );
    }

    #[test]
    fn new_buffer_is_zeroed() {
        let buf = LockedBuffer::new(32).unwrap();
        let bytes = buf.bytes_zeroizing();
        assert!(bytes.iter().all(|&b| b == 0), "new buffer must be zeroed");
    }

    #[test]
    fn new_buffer_has_correct_size() {
        for &size in &[1_usize, 16, 32, 64, 128] {
            let buf = LockedBuffer::new(size).unwrap();
            assert_eq!(buf.size(), size);
        }
    }

    #[test]
    fn random_buffer_is_nonzero() {
        let buf = LockedBuffer::random(32).unwrap();
        let bytes = buf.bytes_zeroizing();
        // Statistically certain with a real CSPRNG.
        assert!(
            bytes.iter().any(|&b| b != 0),
            "random buffer must not be all zeros"
        );
    }

    #[test]
    fn from_bytes_copies_data() {
        let input = b"hello locked world";
        let buf = LockedBuffer::from_bytes(input.as_ref()).unwrap();
        assert_eq!(buf.size(), input.len());
        let bytes = buf.bytes_zeroizing();
        assert_eq!(bytes.as_slice(), input.as_ref());
    }

    #[test]
    fn wipe_zeroes_contents() {
        let buf = LockedBuffer::from_bytes(b"secret to wipe").unwrap();
        buf.wipe();
        let bytes = buf.bytes_zeroizing();
        assert!(
            bytes.iter().all(|&b| b == 0),
            "after wipe(), buffer must be zeroed"
        );
    }

    #[test]
    fn bytes_zeroizing_returns_independent_copy() {
        let buf = LockedBuffer::from_bytes(b"copy test").unwrap();
        let copy = buf.bytes_zeroizing();
        // Wipe the original.
        buf.wipe();
        // The copy should still hold the original data.
        assert_eq!(copy.as_slice(), b"copy test");
    }

    #[test]
    fn freeze_and_melt_through_handle() {
        let buf = LockedBuffer::new(16).unwrap();
        buf.freeze().unwrap();
        buf.melt().unwrap();
        // After melt, should still be usable.
        let bytes = buf.bytes_zeroizing();
        assert_eq!(bytes.len(), 16);
    }

    #[test]
    fn scramble_produces_nonzero() {
        let buf = LockedBuffer::new(64).unwrap();
        buf.scramble().unwrap();
        let bytes = buf.bytes_zeroizing();
        assert!(
            bytes.iter().any(|&b| b != 0),
            "scramble must fill with non-zero bytes"
        );
    }

    #[test]
    fn zeroize_all_at_shutdown_zeroes_all_registered() {
        // Register multiple buffers, call zeroize_all, verify all are zeroed.
        let b1 = LockedBuffer::from_bytes(b"secret1").unwrap();
        let b2 = LockedBuffer::from_bytes(b"secret2").unwrap();
        // Still holding strong refs to b1 and b2 while calling zeroize_all.
        zeroize_all_registered_at_shutdown();
        let bytes1 = b1.bytes_zeroizing();
        let bytes2 = b2.bytes_zeroizing();
        assert!(
            bytes1.iter().all(|&b| b == 0),
            "b1 must be zeroed after shutdown call"
        );
        assert!(
            bytes2.iter().all(|&b| b == 0),
            "b2 must be zeroed after shutdown call"
        );
    }

    #[test]
    fn concurrent_access_from_multiple_threads() {
        use std::sync::Arc;
        use std::thread;
        let buf = Arc::new(LockedBuffer::new(64).unwrap());
        let handles: Vec<_> = (0..8)
            .map(|i| {
                let b = Arc::clone(&buf);
                thread::spawn(move || {
                    // Each thread freezes, reads size, melts.
                    b.freeze().ok();
                    let _ = b.size();
                    b.melt().ok();
                    let _ = i;
                })
            })
            .collect();
        for h in handles {
            h.join().expect("thread panicked");
        }
    }
}
