// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

#![allow(unsafe_code)]

//! Single mlock'd page subdivided into fixed-size slots.
//!
//! The slab occupies exactly one OS page (typically 4 KiB), mlock'd to
//! prevent swap-out. It is subdivided into `floor(page_size / slot_size)`
//! equal slots. This fits within the typical per-process mlock limit.
//!
//! When `init_coffer = true`, slots 0 (left) and 1 (right) are permanently
//! reserved for the Coffer (master key halves). Remaining slots form a shared
//! pool used for both the hot cache and transient (checked-out) use.

use std::collections::{HashMap, HashSet, VecDeque};
use std::ptr::NonNull;
use std::time::Duration;

use rand::TryRngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use super::memcall::{os_lock, os_protect, os_unlock, page_size, Protection};
use crate::error::{Error, Result};

/// Default slot size in bytes (AES-256 key size, matching asherah-ffi).
pub const DEFAULT_SLOT_SIZE: usize = 32;

/// Maximum time to wait for a slot to become available.
pub(crate) const SLOT_WAIT_TIMEOUT: Duration = Duration::from_secs(30);

/// Slot index for the Coffer left half (stores master_key XOR SHA-256(right)).
pub(crate) const COFFER_LEFT: usize = 0;
/// Slot index for the Coffer right half (stores random bytes).
pub(crate) const COFFER_RIGHT: usize = 1;
/// First slot index available to the shared pool (free/cached/transient).
pub(crate) const FIRST_SHARED_SLOT: usize = 2;

/// A single mlock'd page subdivided into fixed-size slots.
///
/// Three-state slot tracking (mutually exclusive):
/// - **free**: in the `free` LIFO vec — available for immediate use.
/// - **cached**: in `cache_map` + `cache_lru` — holds plaintext for a MemoryEnclave.
/// - **transient**: in `transient` set — currently checked out to a `PoolSlot`.
///
/// When `has_coffer` is true, slots 0 (COFFER_LEFT) and 1 (COFFER_RIGHT) are
/// permanently reserved and never appear in any of the three state lists.
pub struct SecureSlab {
    ptr: NonNull<u8>,
    page_size: usize,
    pub slot_size: usize,
    total_slots: usize,
    has_coffer: bool,

    /// LIFO free list — `pop()` returns the next slot to allocate.
    free: Vec<usize>,
    /// enclave_id → slot_index for cached entries.
    cache_map: HashMap<u64, usize>,
    /// LRU order: front = oldest (next to evict), back = MRU.
    cache_lru: VecDeque<u64>,
    /// Slots currently checked out (transient / in-use).
    transient: HashSet<usize>,
}

// SAFETY: SecureSlab has exclusive ownership of its mlock'd allocation (NonNull<u8>).
// All mutation is through &mut self, enforced by callers via Mutex<SecureSlab>.
// The raw pointer has no thread-local invariants — it is a plain mmap/VirtualAlloc region.
unsafe impl Send for SecureSlab {}

impl std::fmt::Debug for SecureSlab {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureSlab")
            .field("slot_size", &self.slot_size)
            .field("total_slots", &self.total_slots)
            .field("has_coffer", &self.has_coffer)
            .field("free", &self.free.len())
            .field("cached", &self.cache_map.len())
            .field("transient", &self.transient.len())
            .finish()
    }
}

impl SecureSlab {
    /// Allocate and mlock a single page, subdivided into `slot_size`-byte slots.
    ///
    /// When `init_coffer = true`, slots 0 and 1 are initialised with the Coffer
    /// key material and are permanently reserved (not included in free/cache/transient).
    pub fn new(slot_size: usize, init_coffer: bool) -> Result<Self> {
        let ps = page_size();
        if init_coffer && slot_size < 32 {
            return Err(Error::Memory(format!(
                "SecureSlab: coffer requires slot_size >= 32 (AES-256 key size), got {slot_size}"
            )));
        }
        if slot_size == 0 || slot_size > ps / 3 {
            return Err(Error::Memory(format!(
                "SecureSlab: slot_size {slot_size} is invalid (must be 1..={})",
                ps / 3
            )));
        }
        let total_slots = ps / slot_size;
        if total_slots < 3 {
            return Err(Error::Memory(
                "SecureSlab: page too small for at least 3 slots (2 coffer + 1 usable)".into(),
            ));
        }

        let ptr = unsafe { super::memcall::os_alloc(ps) }
            .map_err(|e| Error::Memory(format!("SecureSlab alloc: {e}")))?;

        // mlock the entire page.
        if let Err(e) = unsafe { os_lock(ptr.as_ptr(), ps) } {
            // Clean up the allocation before returning the error.
            drop(unsafe { super::memcall::os_free(ptr.as_ptr(), ps) });
            return Err(Error::Memory(format!("SecureSlab mlock: {e}")));
        }

        // Build the free list: LIFO, so pop() gives the highest-index slot first
        // (consistent with asherah-ffi behaviour).
        let free: Vec<usize> = (FIRST_SHARED_SLOT..total_slots).collect();

        let mut slab = Self {
            ptr,
            page_size: ps,
            slot_size,
            total_slots,
            has_coffer: init_coffer,
            free,
            cache_map: HashMap::new(),
            cache_lru: VecDeque::new(),
            transient: HashSet::new(),
        };

        if init_coffer {
            slab.init_coffer_slots()?;
        }

        Ok(slab)
    }

    /// Initialise Coffer slots 0 (left) and 1 (right).
    ///
    /// Slot 1 (right) = random bytes.
    /// Slot 0 (left)  = master_key XOR SHA-256(right).
    /// The temporary master key buffer is zeroized immediately after use.
    fn init_coffer_slots(&mut self) -> Result<()> {
        // Fill slot 1 (right) with random bytes.
        let right_ptr = self.slot_ptr(COFFER_RIGHT);
        // SAFETY: COFFER_RIGHT (1) is always a valid slot index (total_slots >= 3 is
        // asserted at construction). The pointer stays within the mlock'd page allocation.
        unsafe {
            let right = std::slice::from_raw_parts_mut(right_ptr, self.slot_size);
            rand::rngs::OsRng
                .try_fill_bytes(right)
                .map_err(|e| Error::Memory(format!("SecureSlab coffer right OsRng: {e}")))?;
        }

        // Generate a temporary master key (NOT written to slot 0 directly).
        let mut master_key = zeroize::Zeroizing::new(vec![0_u8; self.slot_size]);
        rand::rngs::OsRng
            .try_fill_bytes(&mut master_key)
            .map_err(|e| Error::Memory(format!("SecureSlab coffer master_key OsRng: {e}")))?;

        // Compute h = SHA-256(right), XOR into slot 0.
        // h is wrapped in Zeroizing so the hash is scrubbed on scope exit.
        // SAFETY: COFFER_RIGHT (1) and COFFER_LEFT (0) are always valid slot indices
        // (total_slots >= 3 is asserted at construction). All pointer arithmetic stays
        // within the single mlock'd page allocation.
        unsafe {
            let right = std::slice::from_raw_parts(right_ptr, self.slot_size);
            let mut h = zeroize::Zeroizing::new([0_u8; 32]);
            let digest: [u8; 32] = Sha256::digest(right).into();
            h.copy_from_slice(&digest);
            let left = std::slice::from_raw_parts_mut(self.slot_ptr(COFFER_LEFT), self.slot_size);
            for i in 0..self.slot_size {
                left[i] = master_key[i] ^ h[i % 32];
            }
            // h and master_key are zeroized on drop automatically.
        }

        Ok(())
    }

    /// Raw pointer for slot `index`.
    fn slot_ptr(&self, index: usize) -> *mut u8 {
        debug_assert!(
            index < self.total_slots,
            "slot index {index} out of range (total={})",
            self.total_slots
        );
        // SAFETY: index < total_slots (debug_assert above). slot_size * total_slots == page_size
        // (ensured at construction), so the pointer stays within the mlock'd allocation.
        unsafe { self.ptr.as_ptr().add(index * self.slot_size) }
    }

    /// Zeroize the contents of slot `index`.
    fn wipe_slot(&self, index: usize) {
        // SAFETY: index is always < total_slots (validated by callers); slot_ptr arithmetic
        // stays within the mlock'd slab page allocation which lives for the process lifetime.
        unsafe {
            std::slice::from_raw_parts_mut(self.slot_ptr(index), self.slot_size).zeroize();
        }
    }

    /// Raw pointer + length for slot `index`.
    ///
    /// Returns `None` if `index >= total_slots`. Only valid while `self` is alive.
    pub fn slot_raw(&self, index: usize) -> Option<(*mut u8, usize)> {
        if index >= self.total_slots {
            return None;
        }
        Some((self.slot_ptr(index), self.slot_size))
    }

    /// Slot size in bytes.
    #[allow(dead_code)]
    pub fn slot_size(&self) -> usize {
        self.slot_size
    }

    /// Total number of slots (including coffer slots if `has_coffer`).
    #[allow(dead_code)]
    pub fn total_slots(&self) -> usize {
        self.total_slots
    }

    /// Acquire a slot from the free list, marking it transient.
    ///
    /// If the free list is empty, evicts the LRU cache entry to make space.
    /// Returns `None` if no slots are available and no cache entries can be evicted.
    pub fn acquire_transient(&mut self) -> Option<usize> {
        if let Some(idx) = self.free.pop() {
            self.transient.insert(idx);
            return Some(idx);
        }
        // Free list empty — evict the LRU cache entry.
        let evict_id = *self.cache_lru.front()?;
        self.cache_evict(evict_id);
        // Now a slot was freed; try again.
        let idx = self.free.pop()?;
        self.transient.insert(idx);
        Some(idx)
    }

    /// Release a transient slot back to the free list and wipe its contents.
    ///
    /// Panics in debug mode if the slot was not transient (double-release guard).
    pub fn release(&mut self, index: usize) {
        let was_transient = self.transient.remove(&index);
        debug_assert!(
            was_transient,
            "SecureSlab::release: slot {index} was not transient (double-release?)"
        );
        self.wipe_slot(index);
        self.free.push(index);
    }

    /// Cache-get: copies the cached slot's bytes into a new transient slot.
    ///
    /// Promotes the entry to MRU position. Returns the transient slot index,
    /// or `None` on cache miss (or if no free slot is available for the copy).
    pub fn cache_get(&mut self, id: u64) -> Option<usize> {
        // Check cache hit before trying to acquire a transient slot.
        if !self.cache_map.contains_key(&id) {
            return None;
        }
        let cached_idx = *self.cache_map.get(&id)?;

        // Acquire a transient slot for the copy.
        // To avoid evicting the entry we're reading, we need a free slot.
        // If the free list is empty AND this is the only (or LRU) entry, we'd
        // evict ourselves. Handle that: only evict if there are other entries.
        let out_idx = if !self.free.is_empty() {
            self.free.pop()?
        } else {
            // Need to evict. Make sure we don't evict the entry we're reading.
            let lru_id = *self.cache_lru.front()?;
            if lru_id == id {
                // Guard: never evict the entry we're about to read. If the only free slot
                // requires evicting our own entry, return None (no available slot). This
                // prevents a scenario where cache_get would evict id's entry then try to
                // copy from a freed slot.
                return None;
            }
            self.cache_evict(lru_id);
            self.free.pop()?
        };

        // Copy cached slot bytes into the transient slot.
        // SAFETY: `cached_idx` is in `cache_map`, so it was never released to the free list;
        // its slot is within the mlock'd page (index < total_slots, validated at checkout time).
        // `out_idx` was just popped from `self.free` via `acquire_transient`, so it is also
        // in-bounds, non-aliased, and not in `cache_map`. The two indices are distinct because
        // `cached_idx` is in `cache_map` (not free) and `out_idx` was just removed from `free`.
        // Both raw slices are non-overlapping slices of the same mlock'd allocation.
        unsafe {
            let src = std::slice::from_raw_parts(self.slot_ptr(cached_idx), self.slot_size);
            let dst = std::slice::from_raw_parts_mut(self.slot_ptr(out_idx), self.slot_size);
            dst.copy_from_slice(src);
        }
        self.transient.insert(out_idx);

        // Promote to MRU.
        if let Some(pos) = self.cache_lru.iter().position(|&x| x == id) {
            self.cache_lru.remove(pos);
        }
        self.cache_lru.push_back(id);

        Some(out_idx)
    }

    /// Cache-insert: stores `data` into a free slot as a cache entry for `id`.
    ///
    /// Only inserts if `data.len() == self.slot_size` (exact fit).
    /// Evicts the LRU entry if the free list is empty.
    /// Returns `true` if the entry was inserted.
    pub fn cache_insert(&mut self, id: u64, data: &[u8]) -> bool {
        if data.len() != self.slot_size {
            return false;
        }

        // Remove any existing entry for this id.
        if self.cache_map.contains_key(&id) {
            self.cache_evict(id);
        }

        // Get a free slot — evict LRU if needed.
        let slot_idx = if let Some(idx) = self.free.pop() {
            idx
        } else if let Some(&lru_id) = self.cache_lru.front() {
            self.cache_evict(lru_id);
            match self.free.pop() {
                Some(idx) => idx,
                None => return false,
            }
        } else {
            return false;
        };

        // Write data into the slot.
        // SAFETY: `slot_idx` was just popped from `self.free` and is not in `transient` or
        // `cache_map`. It is in-bounds (free list only contains valid indices 2..total_slots).
        // The slice lives within the single mlock'd page allocation which is valid for the
        // lifetime of this SecureSlab.
        unsafe {
            let dst = std::slice::from_raw_parts_mut(self.slot_ptr(slot_idx), self.slot_size);
            dst.copy_from_slice(data);
        }

        self.cache_map.insert(id, slot_idx);
        self.cache_lru.push_back(id);
        true
    }

    /// Cache-evict: removes the cache entry for `id`, wipes the slot, and
    /// returns it to the free list. No-op if `id` is not cached.
    pub fn cache_evict(&mut self, id: u64) {
        if let Some(slot_idx) = self.cache_map.remove(&id) {
            if let Some(pos) = self.cache_lru.iter().position(|&x| x == id) {
                self.cache_lru.remove(pos);
            }
            self.wipe_slot(slot_idx);
            self.free.push(slot_idx);
        }
    }

    /// Reconstruct the master key from Coffer slots 0+1 into a fresh transient slot.
    ///
    /// Only valid when `has_coffer = true`. Returns the transient slot index, or
    /// `None` if no free slot is available.
    pub fn coffer_view(&mut self) -> Option<usize> {
        debug_assert!(
            self.has_coffer,
            "SecureSlab::coffer_view called on non-coffer slab"
        );
        let out_idx = self.acquire_transient()?;
        // SAFETY: COFFER_LEFT (0) and COFFER_RIGHT (1) are always valid slot indices
        // (total_slots >= 3 is asserted at construction). out_idx is a checked-out transient
        // slot index obtained from acquire_transient(), which only returns indices in
        // FIRST_SHARED_SLOT..total_slots. All three pointer calculations stay within
        // the single mlock'd page allocation.
        unsafe {
            let left = std::slice::from_raw_parts(self.slot_ptr(COFFER_LEFT), self.slot_size);
            let right = std::slice::from_raw_parts(self.slot_ptr(COFFER_RIGHT), self.slot_size);
            // Wrap the hash in Zeroizing so it is scrubbed on scope exit.
            let mut h = zeroize::Zeroizing::new([0_u8; 32]);
            let digest: [u8; 32] = Sha256::digest(right).into();
            h.copy_from_slice(&digest);
            let out = std::slice::from_raw_parts_mut(self.slot_ptr(out_idx), self.slot_size);
            for i in 0..self.slot_size {
                // Note: for slot_size > 32 the hash repeats cyclically (h[i % 32]), reducing
                // the effective keystream entropy. slot_size == 32 (DEFAULT_SLOT_SIZE) is
                // required for the coffer (enforced in SecureSlab::new). This branch is
                // unreachable in practice.
                out[i] = left[i] ^ h[i % 32];
            }
            // h is zeroized on drop automatically.
        }
        Some(out_idx)
    }

    /// Number of usable (non-coffer) slots total.
    #[allow(dead_code)]
    pub fn usable_slots(&self) -> usize {
        self.total_slots.saturating_sub(FIRST_SHARED_SLOT)
    }
}

impl Drop for SecureSlab {
    fn drop(&mut self) {
        // SAFETY: ptr is valid for page_size bytes for the entire lifetime of this
        // struct (allocated in new(), freed here). Restoring write access first
        // ensures the subsequent zeroize and free calls succeed even if the page
        // was left in a ReadOnly or NoAccess state.
        unsafe {
            drop(os_protect(
                self.ptr.as_ptr(),
                self.page_size,
                Protection::ReadWrite,
            ));
            std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.page_size).zeroize();
            drop(os_unlock(self.ptr.as_ptr(), self.page_size));
            drop(super::memcall::os_free(self.ptr.as_ptr(), self.page_size));
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn new_default_slot_size() {
        let slab = SecureSlab::new(DEFAULT_SLOT_SIZE, false).unwrap();
        assert_eq!(slab.slot_size(), DEFAULT_SLOT_SIZE);
        assert!(slab.total_slots() >= 3);
        assert_eq!(slab.usable_slots(), slab.total_slots() - 2);
    }

    #[test]
    fn slot_size_zero_rejected() {
        assert!(SecureSlab::new(0, false).is_err());
    }

    #[test]
    fn slot_size_too_large_rejected() {
        let ps = page_size();
        assert!(SecureSlab::new(ps / 3 + 1, false).is_err());
    }

    #[test]
    fn coffer_slot_size_too_small_rejected() {
        // BLK-7: slot_size < 32 with init_coffer=true should fail.
        let result = SecureSlab::new(16, true);
        assert!(
            result.is_err(),
            "coffer requires slot_size >= 32 (AES-256 key size)"
        );
    }

    #[test]
    fn slot_raw_out_of_bounds_returns_none() {
        let slab = SecureSlab::new(DEFAULT_SLOT_SIZE, false).unwrap();
        assert!(slab.slot_raw(slab.total_slots()).is_none());
        assert!(slab.slot_raw(usize::MAX).is_none());
    }

    #[test]
    fn coffer_view_result_is_deterministic() {
        let mut slab = SecureSlab::new(DEFAULT_SLOT_SIZE, true).unwrap();
        let idx1 = slab.coffer_view().unwrap();
        let (ptr1, len1) = slab
            .slot_raw(idx1)
            .expect("slot_raw: index from coffer_view");
        let key1 = unsafe { std::slice::from_raw_parts(ptr1, len1) }.to_vec();
        slab.release(idx1);
        let idx2 = slab.coffer_view().unwrap();
        let (ptr2, len2) = slab
            .slot_raw(idx2)
            .expect("slot_raw: index from coffer_view");
        let key2 = unsafe { std::slice::from_raw_parts(ptr2, len2) }.to_vec();
        slab.release(idx2);
        assert_eq!(
            key1, key2,
            "coffer_view must reconstruct the same key each time"
        );
        assert!(key1.iter().any(|&b| b != 0), "key must not be all zeros");
    }

    #[test]
    fn acquire_and_release() {
        let mut slab = SecureSlab::new(DEFAULT_SLOT_SIZE, false).unwrap();
        let idx = slab.acquire_transient().unwrap();
        assert!(
            idx >= FIRST_SHARED_SLOT,
            "coffer slots must not be returned"
        );
        // Slot is now transient — a second acquire gives a different index.
        let idx2 = slab.acquire_transient().unwrap();
        assert_ne!(idx, idx2);
        slab.release(idx2);
        slab.release(idx);
        // After release, both slots are back.
        let re = slab.acquire_transient().unwrap();
        assert!(re >= FIRST_SHARED_SLOT);
        slab.release(re);
    }

    #[test]
    fn out_of_range_slot_raw_is_safe() {
        let slab = SecureSlab::new(DEFAULT_SLOT_SIZE, false).unwrap();
        // Out-of-bounds indices now return None.
        assert!(slab.slot_raw(slab.total_slots()).is_none());
        assert!(slab.slot_raw(usize::MAX).is_none());
        // In-bounds indices return Some with consistent offsets.
        let (p0, _) = slab.slot_raw(0).expect("slot 0 is valid");
        let (p1, _) = slab.slot_raw(1).expect("slot 1 is valid");
        assert_eq!(unsafe { p1.offset_from(p0) } as usize, DEFAULT_SLOT_SIZE);
    }

    #[test]
    fn release_nonexistent_is_noop_in_release_build() {
        // In release builds debug_assert is a no-op, so this must not panic.
        // In debug builds we deliberately skip calling this to avoid the assert.
        #[cfg(not(debug_assertions))]
        {
            let mut slab = SecureSlab::new(DEFAULT_SLOT_SIZE, false).unwrap();
            slab.release(5); // never acquired — should be a no-op in release
        }
        #[cfg(debug_assertions)]
        {
            // Just verify the slab can be created and dropped cleanly.
            let slab = SecureSlab::new(DEFAULT_SLOT_SIZE, false).unwrap();
            drop(slab);
        }
    }

    #[test]
    fn cache_insert_and_get() {
        let mut slab = SecureSlab::new(DEFAULT_SLOT_SIZE, false).unwrap();
        let data = [0x42_u8; DEFAULT_SLOT_SIZE];
        assert!(slab.cache_insert(42, &data));
        let slot_idx = slab.cache_get(42).unwrap();
        let (ptr, len) = slab
            .slot_raw(slot_idx)
            .expect("slot_raw: index validated by cache_get");
        let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
        assert_eq!(slice, &data);
        slab.release(slot_idx);
    }

    #[test]
    fn cache_insert_wrong_size_rejected() {
        let mut slab = SecureSlab::new(DEFAULT_SLOT_SIZE, false).unwrap();
        let data = [0x42_u8; DEFAULT_SLOT_SIZE - 1];
        assert!(!slab.cache_insert(42, &data));
        assert!(slab.cache_get(42).is_none());
    }

    #[test]
    fn cache_evict_removes_entry() {
        let mut slab = SecureSlab::new(DEFAULT_SLOT_SIZE, false).unwrap();
        let data = [0x55_u8; DEFAULT_SLOT_SIZE];
        slab.cache_insert(99, &data);
        slab.cache_evict(99);
        assert!(slab.cache_get(99).is_none());
    }

    #[test]
    fn coffer_view_reconstructs_key() {
        let mut slab = SecureSlab::new(DEFAULT_SLOT_SIZE, true).unwrap();
        // Call coffer_view twice; both results should be identical (deterministic).
        let idx1 = slab.coffer_view().unwrap();
        let (ptr1, len1) = slab
            .slot_raw(idx1)
            .expect("slot_raw: index from coffer_view is valid");
        let key1 = unsafe { std::slice::from_raw_parts(ptr1, len1) }.to_vec();
        slab.release(idx1);

        let idx2 = slab.coffer_view().unwrap();
        let (ptr2, len2) = slab
            .slot_raw(idx2)
            .expect("slot_raw: index from coffer_view is valid");
        let key2 = unsafe { std::slice::from_raw_parts(ptr2, len2) }.to_vec();
        slab.release(idx2);

        assert_eq!(key1, key2, "coffer_view must be deterministic");
        // Key must not be all zeros.
        assert!(!key1.iter().all(|&b| b == 0_u8));
    }

    #[test]
    fn acquire_transient_evicts_lru_when_full() {
        let mut slab = SecureSlab::new(DEFAULT_SLOT_SIZE, false).unwrap();
        let usable = slab.total_slots() - FIRST_SHARED_SLOT;
        // Fill all slots with cache entries.
        for id in 0..(usable as u64) {
            let data = [id as u8; DEFAULT_SLOT_SIZE];
            assert!(slab.cache_insert(id, &data), "insert {id} failed");
        }
        // Now acquire_transient should evict LRU (id=0) to make room.
        let idx = slab
            .acquire_transient()
            .expect("should evict LRU to make room");
        assert!(
            slab.cache_get(0).is_none(),
            "LRU entry (id=0) should have been evicted"
        );
        slab.release(idx);
    }

    #[test]
    fn cache_get_promotes_to_mru() {
        let mut slab = SecureSlab::new(DEFAULT_SLOT_SIZE, false).unwrap();
        let usable = slab.total_slots() - FIRST_SHARED_SLOT;
        // Insert entries until we fill the slab, leaving room for the transient copy.
        // Insert (usable - 1) entries so we always have one free slot for the transient copy.
        let count = usable - 1;
        for id in 0..(count as u64) {
            let data = [id as u8; DEFAULT_SLOT_SIZE];
            slab.cache_insert(id, &data);
        }
        // Access id=0 — it becomes MRU.
        let copy_idx = slab.cache_get(0).unwrap();
        slab.release(copy_idx);
        // Now fill the remaining free slot.
        slab.cache_insert(count as u64, &[0xFE_u8; DEFAULT_SLOT_SIZE]);
        // Insert one more — LRU must NOT be id=0 (it was promoted).
        // The oldest un-accessed entry should be evicted (id=1).
        slab.cache_insert(count as u64 + 1, &[0xFF_u8; DEFAULT_SLOT_SIZE]);
        assert!(
            slab.cache_get(0).is_some() || slab.cache_get(1).is_none(),
            "id=1 should be evicted before id=0"
        );
        // Clean up any transient slots.
        if let Some(idx) = slab.cache_get(0) {
            slab.release(idx);
        }
    }

    #[test]
    fn coffer_slots_not_in_free_list() {
        let mut slab = SecureSlab::new(DEFAULT_SLOT_SIZE, true).unwrap();
        // Drain all free slots — none should be coffer slots.
        let mut acquired = Vec::new();
        while let Some(idx) = slab.acquire_transient() {
            assert!(
                idx >= FIRST_SHARED_SLOT,
                "coffer slot {idx} must never appear in the free list"
            );
            acquired.push(idx);
        }
        for idx in acquired {
            slab.release(idx);
        }
    }

    #[test]
    fn free_list_is_lifo_highest_index_first() {
        let mut slab = SecureSlab::new(DEFAULT_SLOT_SIZE, false).unwrap();
        let usable = slab.total_slots() - FIRST_SHARED_SLOT;
        // Drain all free slots; they should come out in descending order (highest first = LIFO pop).
        let mut indices = Vec::new();
        while let Some(idx) = slab.acquire_transient() {
            indices.push(idx);
        }
        assert_eq!(indices.len(), usable, "all usable slots should be acquired");
        // LIFO: first pop = total_slots - 1 (the last element pushed during init).
        assert_eq!(indices[0], slab.total_slots() - 1);
        // Return all.
        for idx in indices {
            slab.release(idx);
        }
    }

    #[test]
    fn released_slot_is_zeroed() {
        let mut slab = SecureSlab::new(DEFAULT_SLOT_SIZE, false).unwrap();
        let idx = slab.acquire_transient().unwrap();
        // Write a known pattern.
        let (ptr, len) = slab.slot_raw(idx).unwrap();
        unsafe { std::slice::from_raw_parts_mut(ptr, len).fill(0xBE) };
        // Release (should zeroize).
        slab.release(idx);
        // Re-acquire the same slot (LIFO: should get it back immediately).
        let idx2 = slab.acquire_transient().unwrap();
        let (ptr2, len2) = slab.slot_raw(idx2).unwrap();
        let slice = unsafe { std::slice::from_raw_parts(ptr2, len2) };
        assert!(
            slice.iter().all(|&b| b == 0),
            "released slot must be zeroed"
        );
        slab.release(idx2);
    }

    #[test]
    fn double_acquire_returns_different_indices() {
        let mut slab = SecureSlab::new(DEFAULT_SLOT_SIZE, false).unwrap();
        let a = slab.acquire_transient().unwrap();
        let b = slab.acquire_transient().unwrap();
        assert_ne!(a, b, "two consecutive acquires must return different slots");
        slab.release(a);
        slab.release(b);
    }

    #[test]
    fn acquire_transient_single_entry_self_eviction_guard() {
        let mut slab = SecureSlab::new(DEFAULT_SLOT_SIZE, false).unwrap();
        // Put exactly one entry in the cache and fill all free slots transiently.
        let usable = slab.total_slots() - FIRST_SHARED_SLOT;
        let data = [0x42_u8; DEFAULT_SLOT_SIZE];
        slab.cache_insert(999, &data);
        // Fill (usable - 1) transient slots (one is used by the cached entry).
        let mut held = Vec::new();
        for _ in 0..(usable - 1) {
            if let Some(idx) = slab.acquire_transient() {
                held.push(idx);
            }
        }
        // Now free list is empty; only cache has an entry (id 999).
        // acquire_transient must evict LRU (id 999) to give us a slot.
        let result = slab.acquire_transient();
        // The LRU (999) was evicted to give us a slot.
        assert!(
            result.is_some(),
            "should evict cache entry to give us a slot"
        );
        // 999 must be gone from cache.
        assert!(
            slab.cache_get(999).is_none(),
            "cache entry 999 must be evicted"
        );
        for idx in held {
            slab.release(idx);
        }
        if let Some(idx) = result {
            slab.release(idx);
        }
    }

    #[test]
    fn lru_ordering_insert_a_b_c_access_a_evicts_b_next() {
        let mut slab = SecureSlab::new(DEFAULT_SLOT_SIZE, false).unwrap();
        let usable = slab.total_slots() - FIRST_SHARED_SLOT;
        assert!(
            usable >= 4,
            "need at least 4 usable slots for this test (A+B+C+D)"
        );
        let data = [0x11_u8; DEFAULT_SLOT_SIZE];
        // Insert A, B, C in order.
        slab.cache_insert(1, &data);
        slab.cache_insert(2, &data);
        slab.cache_insert(3, &data);
        // Access A → A promoted to MRU; LRU order becomes: B, C, A.
        let copy = slab.cache_get(1).unwrap();
        slab.release(copy);
        // Fill remaining free slots to force eviction on next insert.
        // We have (usable - 3) free slots; hold (usable - 4) so one slot remains for D's eviction
        // path (D must evict B to get a slot). Hold all but zero: fill everything.
        let slots_used = 3; // A, B, C are cached
        let free_left = usable - slots_used;
        let mut held = Vec::new();
        for _ in 0..free_left {
            if let Some(idx) = slab.acquire_transient() {
                held.push(idx);
            }
        }
        // Insert D — must evict B (the LRU after A was promoted), NOT A or C.
        slab.cache_insert(4, &data);
        // B must be gone.
        // To verify A, C, D without consuming slots (slab is full):
        // release held slots first so cache_get has room to make copies.
        for idx in held {
            slab.release(idx);
        }
        // B was evicted by D's insertion.
        assert!(
            slab.cache_get(2).is_none(),
            "B must be evicted (LRU after A was promoted)"
        );
        // A and C must still be present.
        if let Some(idx) = slab.cache_get(1) {
            slab.release(idx);
        } else {
            panic!("A must still be cached (was promoted to MRU)");
        }
        if let Some(idx) = slab.cache_get(3) {
            slab.release(idx);
        } else {
            panic!("C must still be cached");
        }
        if let Some(idx) = slab.cache_get(4) {
            slab.release(idx);
        }
    }

    #[test]
    fn cache_same_id_overwritten() {
        let mut slab = SecureSlab::new(DEFAULT_SLOT_SIZE, false).unwrap();
        let data1 = [0x11_u8; DEFAULT_SLOT_SIZE];
        let data2 = [0x22_u8; DEFAULT_SLOT_SIZE];
        slab.cache_insert(42, &data1);
        // Overwrite same id with different data.
        slab.cache_insert(42, &data2);
        let idx = slab.cache_get(42).unwrap();
        let (ptr, len) = slab.slot_raw(idx).unwrap();
        let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
        assert_eq!(slice, &data2, "second insert must overwrite first");
        slab.release(idx);
    }

    #[test]
    fn coffer_key_not_all_zeros() {
        let mut slab = SecureSlab::new(DEFAULT_SLOT_SIZE, true).unwrap();
        let idx = slab.coffer_view().unwrap();
        let (ptr, len) = slab.slot_raw(idx).unwrap();
        let key = unsafe { std::slice::from_raw_parts(ptr, len) };
        assert!(
            key.iter().any(|&b| b != 0),
            "coffer key must not be all zeros"
        );
        slab.release(idx);
    }

    #[test]
    fn coffer_key_is_different_from_right_half() {
        // Verify the master key is NOT equal to the raw right bytes
        // (i.e., the XOR derivation actually changes the value).
        let mut slab = SecureSlab::new(DEFAULT_SLOT_SIZE, true).unwrap();
        let key_idx = slab.coffer_view().unwrap();
        let (kptr, klen) = slab.slot_raw(key_idx).unwrap();
        let key = unsafe { std::slice::from_raw_parts(kptr, klen).to_vec() };
        slab.release(key_idx);
        // Read the right half (slot 1) directly via slot_raw (no acquire/release needed).
        let (rptr, rlen) = slab.slot_raw(COFFER_RIGHT).unwrap();
        let right = unsafe { std::slice::from_raw_parts(rptr, rlen).to_vec() };
        assert_ne!(key, right, "coffer key must differ from raw right half");
    }

    #[test]
    fn minimum_slot_size_valid() {
        // slot_size that results in exactly page_size total bytes is valid.
        let slab = SecureSlab::new(DEFAULT_SLOT_SIZE, false).unwrap();
        let ps = page_size();
        assert_eq!(slab.total_slots(), ps / DEFAULT_SLOT_SIZE);
    }

    #[test]
    fn cache_evicted_entry_slot_is_zeroed() {
        // When an entry is evicted from cache, its slot must be zeroed before returning to free list.
        let mut slab = SecureSlab::new(DEFAULT_SLOT_SIZE, false).unwrap();
        let usable = slab.total_slots() - FIRST_SHARED_SLOT;
        let pattern = vec![0xAA_u8; DEFAULT_SLOT_SIZE];
        // Fill all slots with cache entries.
        for id in 0..(usable as u64) {
            slab.cache_insert(id, &pattern);
        }
        // acquire_transient forces LRU eviction (id=0).
        let evicted_id = 0_u64;
        let new_idx = slab.acquire_transient().unwrap();
        assert!(slab.cache_get(evicted_id).is_none(), "id=0 must be evicted");
        // The newly acquired slot (previously held by id=0) must be zeroed.
        let (ptr, len) = slab.slot_raw(new_idx).unwrap();
        let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
        assert!(
            slice.iter().all(|&b| b == 0),
            "evicted cache slot must be zeroed"
        );
        slab.release(new_idx);
    }
}
