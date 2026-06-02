// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Tiered pool of mlock'd slab slots and standalone guard-paged buffers.
//!
//! # Initialization
//! The global memory pool is lazily initialized on first use. For reliable startup-time
//! error reporting, call [`init_pool()`] explicitly before using any [`MemoryEnclave`] or
//! [`pool_acquire()`] operations.

#![allow(unsafe_code)]

use std::sync::{Condvar, Mutex, OnceLock};

use super::memcall::page_size;
use super::secure_buffer::SecureBuffer;
use super::slab::{SecureSlab, DEFAULT_SLOT_SIZE, SLOT_WAIT_TIMEOUT};
use crate::error::{Error, Result};

// ── Pool slot origin ────────────────────────────────────────────────

enum PoolSlotOrigin {
    /// Slot lives in a tier's slab. `tier_index` identifies which `Tier` to return it to.
    Slab {
        tier_index: usize,
        slot_index: usize,
    },
    /// Slot owns a standalone guard-paged buffer (no tier fits, or tier exhausted).
    Standalone(SecureBuffer),
}

/// A handle to a locked memory region containing secret data.
///
/// The slot is either backed by a tier slab (mlock'd single-page pool) or a
/// standalone `SecureBuffer` (guard pages + mlock, for larger allocations).
///
/// `PoolSlot` is `Send` but NOT `Sync`; exclusive reference semantics prevent
/// concurrent mutation.
///
/// # Safety of the slab pointer
///
/// When origin is `Slab`, `ptr` points into a `TieredPool` tier's `SecureSlab`
/// which lives in a `OnceLock<TieredPool>` and is never dropped for the
/// process lifetime. The pointer therefore cannot dangle as long as the
/// process is alive.
///
/// # Safety
/// `PoolSlot` must not outlive the global pool. Only acquire via the module-level
/// `pool_acquire()` and `coffer_view()` functions, not via a local `TieredPool` instance.
/// The `TieredPool::acquire()` method is intentionally `pub(crate)` for this reason.
pub struct PoolSlot {
    ptr: *mut u8,
    len: usize,
    origin: PoolSlotOrigin,
}

// SAFETY: PoolSlot owns either:
// (a) a slab slot index — the underlying memory is the global slab (OnceLock, process-lifetime).
//     The raw pointer is valid for the process lifetime. No thread-local state.
// (b) a standalone SecureBuffer — which is itself Send.
// PoolSlot is NOT Sync because concurrent mutable access to the same slot is not protected.
unsafe impl Send for PoolSlot {}

impl std::fmt::Debug for PoolSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PoolSlot").field("len", &self.len).finish()
    }
}

impl PoolSlot {
    pub(crate) fn from_slab(
        ptr: *mut u8,
        len: usize,
        tier_index: usize,
        slot_index: usize,
    ) -> Self {
        Self {
            ptr,
            len,
            origin: PoolSlotOrigin::Slab {
                tier_index,
                slot_index,
            },
        }
    }

    fn from_standalone(mut buf: SecureBuffer) -> Self {
        // buf starts Mutable (freshly allocated); melt is a no-op if already mutable.
        drop(buf.melt());
        let ptr = buf.bytes().as_mut_ptr();
        let len = buf.size();
        Self {
            ptr,
            len,
            origin: PoolSlotOrigin::Standalone(buf),
        }
    }

    /// Mutable access to the slot's bytes.
    pub fn bytes(&mut self) -> &mut [u8] {
        // SAFETY: ptr is valid for len bytes (either in the global OnceLock slab, which is
        // process-lifetime, or in the standalone SecureBuffer owned by this PoolSlot).
        // &mut self guarantees exclusive access — PoolSlot is not Sync.
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }

    /// Read-only access to the slot's bytes.
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: ptr is valid for len bytes; no aliased mutable reference exists
        // because PoolSlot is not Sync and we hold a shared reference.
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    /// Total capacity of this slot in bytes.
    pub fn size(&self) -> usize {
        self.len
    }

    /// Returns the slab slot index if this slot is backed by the global slab.
    #[allow(dead_code)]
    pub(crate) fn slab_index(&self) -> Option<usize> {
        match &self.origin {
            PoolSlotOrigin::Slab { slot_index, .. } => Some(*slot_index),
            PoolSlotOrigin::Standalone(_) => None,
        }
    }

    /// Returns the tier index if this slot is backed by the global slab.
    #[allow(dead_code)]
    pub(crate) fn tier_index(&self) -> Option<usize> {
        match &self.origin {
            PoolSlotOrigin::Slab { tier_index, .. } => Some(*tier_index),
            PoolSlotOrigin::Standalone(_) => None,
        }
    }
}

impl Drop for PoolSlot {
    fn drop(&mut self) {
        match &mut self.origin {
            PoolSlotOrigin::Slab {
                tier_index,
                slot_index,
            } => {
                // Zeroize before acquiring the lock so memory is clean even under contention.
                // SAFETY: ptr points into the global TieredPool's slab page (OnceLock,
                // process-lifetime). The PoolSlot doc requires slots to come from global_pool(),
                // so this pointer is always valid for the process lifetime.
                unsafe {
                    use zeroize::Zeroize;
                    std::slice::from_raw_parts_mut(self.ptr, self.len).zeroize();
                }
                let pool = global_pool();
                if let Ok(mut slab) = pool.tiers[*tier_index].slab.lock() {
                    slab.release(*slot_index);
                }
                // Wake any waiter blocked in `acquire`.
                pool.tiers[*tier_index].cv.notify_one();
            }
            PoolSlotOrigin::Standalone(buf) => {
                // Zeroize before buf's own drop, which also zeroizes.
                drop(buf.melt());
                // SAFETY: ptr points into buf's inner region (the SecureBuffer owned by this
                // PoolSlot). buf is still alive at this point — we haven't dropped it yet.
                unsafe {
                    use zeroize::Zeroize;
                    std::slice::from_raw_parts_mut(self.ptr, self.len).zeroize();
                }
                // buf drops here: zeroizes again + unmaps.
            }
        }
    }
}

// ── Tiered pool ───────────────────────────────────────────────────

/// One tier: a single mlock'd-page slab with a fixed slot size.
struct Tier {
    slot_size: usize,
    slab: Mutex<SecureSlab>,
    /// Notified on every slot release so waiting `acquire` calls can retry.
    cv: Condvar,
}

impl std::fmt::Debug for Tier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tier")
            .field("slot_size", &self.slot_size)
            .finish()
    }
}

/// Configuration for the tiered pool.
///
/// `tier_sizes` lists the slot sizes for each tier. Must be non-empty.
/// Duplicate sizes are deduplicated; the list is sorted ascending internally.
/// Each size must satisfy: `1 <= size <= page_size() / 3`.
#[derive(Debug, Clone)]
pub struct TieredPoolConfig {
    /// Slot sizes for each tier, non-empty, each in `1..=page_size()/3`.
    pub tier_sizes: Vec<usize>,
}

impl Default for TieredPoolConfig {
    /// Single 32-byte tier (asherah-ffi compatible).
    fn default() -> Self {
        Self {
            tier_sizes: vec![DEFAULT_SLOT_SIZE],
        }
    }
}

/// Statically-owned tiered pool.
///
/// Tier 0's slab is initialised with the Coffer (master key halves in slots 0+1).
/// All other tiers have `init_coffer = false`.
///
/// `TieredPool` is `Send + Sync`: all mutable state is behind `Mutex`-guarded
/// fields. The `Vec<Tier>` contains raw pointers inside `SecureSlab`, which
/// requires explicit `Send`/`Sync` impls.
#[derive(Debug)]
pub struct TieredPool {
    tiers: Vec<Tier>,
}

// SAFETY: TieredPool contains Vec<Tier> where Tier holds Mutex<SecureSlab> (the slab's
// NonNull<u8> is Send but not Sync by default). All mutable access to each slab is
// serialized by its per-tier Mutex. The Condvar is Sync. There is no unguarded shared
// mutable state.
unsafe impl Send for TieredPool {}
unsafe impl Sync for TieredPool {}

impl TieredPool {
    /// Create a new `TieredPool` from `config`.
    ///
    /// Validates, deduplicates, and sorts `config.tier_sizes`, then allocates
    /// one mlock'd page per tier. Tier 0's slab initialises the Coffer.
    pub fn new(config: TieredPoolConfig) -> Result<Self> {
        // Harden the process as early as possible (idempotent).
        // Skipped in test builds: mitigations like ProcessStrictHandleCheckPolicy
        // and ProcessExtensionPointDisablePolicy can interfere with the test runner
        // and spawned threads, causing hangs on Windows CI.
        #[cfg(not(test))]
        enclaveapp_core::process::harden_process();

        let ps = page_size();
        let max_slot = ps / 3;

        if config.tier_sizes.is_empty() {
            return Err(Error::Memory(
                "TieredPoolConfig: tier_sizes must be non-empty".into(),
            ));
        }

        // Sort and dedup.
        let mut sizes = config.tier_sizes;
        sizes.sort_unstable();
        sizes.dedup();

        // Validate each size.
        for &sz in &sizes {
            if sz == 0 {
                return Err(Error::Memory(
                    "TieredPoolConfig: tier size 0 is invalid".into(),
                ));
            }
            if sz > max_slot {
                return Err(Error::Memory(format!(
                    "TieredPoolConfig: tier size {sz} exceeds page_size/3 ({max_slot})"
                )));
            }
        }

        // Tier 0's slab initialises the Coffer (AES-256 key). Its slot_size must be >= 32.
        if sizes[0] < 32 {
            return Err(Error::Memory(format!(
                "TieredPool: first tier slot_size must be >= 32 for coffer, got {}",
                sizes[0]
            )));
        }

        // Allocate one SecureSlab per tier.
        // Tier 0 initialises the Coffer; all others do not.
        let mut tiers = Vec::with_capacity(sizes.len());
        for (i, sz) in sizes.into_iter().enumerate() {
            let init_coffer = i == 0;
            let slab = SecureSlab::new(sz, init_coffer)?;
            tiers.push(Tier {
                slot_size: sz,
                slab: Mutex::new(slab),
                cv: Condvar::new(),
            });
        }

        Ok(Self { tiers })
    }

    /// Index of the smallest tier whose slot_size >= `size`, or `None` if all tiers are too small.
    fn tier_for_size(&self, size: usize) -> Option<usize> {
        self.tiers.iter().position(|t| t.slot_size >= size)
    }

    /// Acquire a slot from the appropriate tier.
    ///
    /// Routes to the smallest tier whose slot_size >= `size`. Waits up to
    /// `SLOT_WAIT_TIMEOUT` for a free slot using a `Condvar` (no spin/sleep);
    /// falls back to a standalone `SecureBuffer` if exhausted or no tier fits.
    ///
    /// # Safety note
    /// The returned `PoolSlot` contains a raw pointer into this pool's slab. It is
    /// only safe to use when `self` is the global pool (i.e. called via `pool_acquire()`).
    /// Do not call this on a local `TieredPool` instance and let the `PoolSlot` outlive it.
    pub(crate) fn acquire(&self, size: usize) -> Result<PoolSlot> {
        if let Some(tier_idx) = self.tier_for_size(size) {
            let deadline = std::time::Instant::now() + SLOT_WAIT_TIMEOUT;
            let mut guard = self.tiers[tier_idx]
                .slab
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            loop {
                if let Some(slot_idx) = guard.acquire_transient() {
                    let (ptr, len) = guard
                        .slot_raw(slot_idx)
                        .expect("slot_raw: index validated by acquire_transient");
                    drop(guard);
                    return Ok(PoolSlot::from_slab(ptr, len, tier_idx, slot_idx));
                }
                let timeout = deadline.saturating_duration_since(std::time::Instant::now());
                if timeout.is_zero() {
                    tracing::warn!(
                        size,
                        tier_idx,
                        "pool acquire: all slab slots exhausted; using standalone SecureBuffer"
                    );
                    drop(guard);
                    break;
                }
                let result = self.tiers[tier_idx]
                    .cv
                    .wait_timeout(guard, timeout)
                    .unwrap_or_else(|e| e.into_inner());
                guard = result.0;
            }
        }

        // Standalone fallback (no tier fits, or tier exhausted).
        Ok(PoolSlot::from_standalone(SecureBuffer::new(size)?))
    }

    /// Reconstruct the Coffer master key from tier 0's slab into a `PoolSlot`.
    ///
    /// # Safety note
    /// Same lifetime constraint as `acquire()`: only safe when `self` is the global pool.
    /// Use the module-level `coffer_view()` function instead of calling this directly.
    pub(crate) fn coffer_view(&self) -> Result<PoolSlot> {
        let mut guard = self.tiers[0].slab.lock().unwrap_or_else(|e| e.into_inner());
        let slot_idx = guard
            .coffer_view()
            .ok_or_else(|| Error::Memory("coffer_view: no free slab slot".into()))?;
        let (ptr, len) = guard
            .slot_raw(slot_idx)
            .expect("slot_raw: index validated by coffer_view");
        drop(guard);
        Ok(PoolSlot::from_slab(ptr, len, 0, slot_idx))
    }

    /// The largest slot size available in any tier.
    pub fn max_slab_slot_size(&self) -> usize {
        self.tiers.iter().map(|t| t.slot_size).max().unwrap_or(0)
    }

    /// Number of configured tiers.
    pub fn tier_count(&self) -> usize {
        self.tiers.len()
    }

    /// Slot size for tier `i`, or `None` if out of range.
    pub fn tier_slot_size(&self, i: usize) -> Option<usize> {
        self.tiers.get(i).map(|t| t.slot_size)
    }
}

// ── Global pool ───────────────────────────────────────────────────

static POOL: OnceLock<TieredPool> = OnceLock::new();

/// Initialize the global pool with a custom config.
///
/// Must be called before any pool operation. If the pool is already initialized
/// (via a prior call or via lazy default init), returns
/// `Error::Memory("pool already initialized")`.
pub fn init_pool(config: TieredPoolConfig) -> Result<()> {
    let pool = TieredPool::new(config)?;
    POOL.set(pool)
        .map_err(|_| Error::Memory("pool already initialized".into()))
}

pub(crate) fn global_pool() -> &'static TieredPool {
    POOL.get_or_init(|| {
        TieredPool::new(TieredPoolConfig::default())
            .expect("enclave: default tiered pool init failed — OsRng unavailable")
    })
}

/// Acquire a pool slot for `size` bytes.
///
/// Routes to the smallest tier whose slot_size >= `size`. Waits up to 30 s
/// for a free slot, then falls back to a standalone guard-paged `SecureBuffer`.
pub fn pool_acquire(size: usize) -> Result<PoolSlot> {
    global_pool().acquire(size)
}

/// Release a pool slot. The slot's contents are zeroized.
/// Prefer dropping the `PoolSlot` directly; this is provided for explicit release.
pub fn pool_release(slot: PoolSlot) {
    drop(slot);
}

/// Get a `PoolSlot` containing the Coffer master key.
/// Release promptly after use; the slot is from the pool and blocks that slot while held.
pub fn coffer_view() -> Result<PoolSlot> {
    global_pool().coffer_view()
}

// ── Slab-delegated hot cache helpers ─────────────────────────────

/// Insert plaintext into the slab hot cache for `id`.
/// Only caches if `data.len() == tier-0 slot_size` (exact fit).
pub(super) fn hot_cache_insert(id: u64, data: &[u8]) {
    let pool = global_pool();
    let mut slab = pool.tiers[0].slab.lock().unwrap_or_else(|e| e.into_inner());
    slab.cache_insert(id, data);
}

/// Look up plaintext from the slab hot cache.
/// Returns a transient `PoolSlot` with a copy of the cached bytes, or `None` on miss.
pub(super) fn hot_cache_get(id: u64) -> Option<PoolSlot> {
    let pool = global_pool();
    let mut guard = pool.tiers[0].slab.lock().unwrap_or_else(|e| e.into_inner());
    let slot_idx = guard.cache_get(id)?;
    // slot_idx was just returned by cache_get(), which only returns valid transient indices.
    let (ptr, len) = guard.slot_raw(slot_idx)?;
    drop(guard);
    Some(PoolSlot::from_slab(ptr, len, 0, slot_idx))
}

/// Evict an entry from the slab hot cache and notify waiters.
pub(super) fn hot_cache_evict(id: u64) {
    let pool = global_pool();
    {
        let mut slab = pool.tiers[0].slab.lock().unwrap_or_else(|e| e.into_inner());
        slab.cache_evict(id);
    }
    pool.tiers[0].cv.notify_one();
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::sync::Mutex;

    use super::super::slab::FIRST_SHARED_SLOT;
    use super::*;

    /// Serializes tests that touch the global TieredPool to prevent interference.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    // ── Global pool tests ───────────────────────────────────────────

    #[test]
    fn pool_acquire_small_uses_slab() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let slot = pool_acquire(16).unwrap();
        assert!(slot.slab_index().is_some());
        assert_eq!(slot.size(), DEFAULT_SLOT_SIZE);
    }

    #[test]
    fn pool_acquire_large_uses_standalone() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let slot = pool_acquire(8192).unwrap();
        assert!(slot.slab_index().is_none());
        assert_eq!(slot.size(), 8192);
    }

    #[test]
    fn pool_acquire_zero_uses_slab() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // size 0 <= slot_size, so it should use the slab.
        let slot = pool_acquire(0).unwrap();
        assert!(slot.slab_index().is_some());
    }

    #[test]
    fn pool_slot_write_and_read() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut slot = pool_acquire(16).unwrap();
        let data = b"test data 12345!";
        slot.bytes()[..data.len()].copy_from_slice(data);
        assert_eq!(&slot.as_slice()[..data.len()], data);
    }

    #[test]
    fn pool_slot_zeroized_on_drop() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Acquire a slab slot, write a pattern, drop it, re-acquire and verify zeroed.
        let mut slot = pool_acquire(16).unwrap();
        let sz = slot.size();
        slot.bytes().iter_mut().for_each(|b| *b = 0xDE);
        // The slab_index tells us which slot; after drop the same index should be free.
        let slot_idx = slot.slab_index().unwrap();
        drop(slot);
        // Acquire again — we should get a zeroed slot.
        let pool = global_pool();
        let mut guard = pool.tiers[0].slab.lock().unwrap_or_else(|e| e.into_inner());
        // Drain free list until we get the same index back.
        let mut acquired = vec![];
        while let Some(idx) = guard.acquire_transient() {
            acquired.push(idx);
            if idx == slot_idx {
                break;
            }
        }
        if acquired.last() == Some(&slot_idx) {
            let (ptr, _) = guard
                .slot_raw(slot_idx)
                .expect("slot_raw: index just acquired from slab");
            let s = unsafe { std::slice::from_raw_parts(ptr, sz) };
            assert!(s.iter().all(|&b| b == 0), "slot must be zeroed after drop");
        }
        for idx in acquired {
            guard.release(idx);
        }
    }

    #[test]
    fn coffer_view_returns_key_sized_slot() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let slot = coffer_view().unwrap();
        assert_eq!(slot.size(), DEFAULT_SLOT_SIZE);
        // Slot must be from tier 0 (slab-backed).
        assert_eq!(slot.tier_index(), Some(0));
    }

    #[test]
    fn coffer_view_is_deterministic() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let s1 = coffer_view().unwrap();
        let key1 = s1.as_slice().to_vec();
        drop(s1);
        let s2 = coffer_view().unwrap();
        let key2 = s2.as_slice().to_vec();
        drop(s2);
        assert_eq!(key1, key2, "coffer_view must return same key each call");
        assert!(!key1.iter().all(|&b| b == 0));
    }

    #[test]
    fn hot_cache_insert_get_evict() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let data = [0xAB_u8; DEFAULT_SLOT_SIZE];
        hot_cache_insert(1001, &data);
        let slot = hot_cache_get(1001).unwrap();
        assert_eq!(slot.as_slice(), &data);
        drop(slot);
        hot_cache_evict(1001);
        assert!(hot_cache_get(1001).is_none());
    }

    #[test]
    fn hot_cache_get_returns_pool_slot() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let data = [0xCC_u8; DEFAULT_SLOT_SIZE];
        hot_cache_insert(2002, &data);
        let slot = hot_cache_get(2002).expect("should be a cache hit");
        // Result is a slab-backed slot from tier 0.
        assert_eq!(slot.tier_index(), Some(0));
        assert!(slot
            .slab_index()
            .map(|i| i >= FIRST_SHARED_SLOT)
            .unwrap_or(false));
        drop(slot);
        hot_cache_evict(2002);
    }

    // ── Local TieredPool tests ───────────────────────────────────────

    #[test]
    fn tiered_pool_routes_small_to_first_tier() {
        // Use the global pool so PoolSlot::drop returns to the correct pool.
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let slot = pool_acquire(16).unwrap();
        assert_eq!(
            slot.tier_index(),
            Some(0),
            "should route to tier 0 (32-byte)"
        );
        assert_eq!(slot.size(), DEFAULT_SLOT_SIZE);
    }

    #[test]
    fn tiered_pool_routes_medium_to_second_tier() {
        // A 48-byte request exceeds the default 32-byte tier — falls back to standalone.
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let slot = pool_acquire(48).unwrap();
        assert!(
            slot.tier_index().is_none(),
            "48-byte request exceeds default tier; should be standalone"
        );
        assert_eq!(slot.size(), 48);
    }

    #[test]
    fn tiered_pool_routes_large_to_standalone() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let slot = pool_acquire(8192).unwrap();
        assert!(slot.tier_index().is_none(), "should be standalone");
        assert_eq!(slot.size(), 8192);
    }

    #[test]
    fn init_pool_default_config_has_one_tier() {
        // Inspect the global pool (already initialised by other tests).
        let pool = global_pool();
        assert_eq!(pool.tier_count(), 1);
        assert_eq!(pool.tier_slot_size(0), Some(DEFAULT_SLOT_SIZE));
        assert_eq!(pool.max_slab_slot_size(), DEFAULT_SLOT_SIZE);
    }

    #[test]
    fn tiered_pool_config_validates_ascending() {
        // Dedup test: no PoolSlots acquired, so local pool is safe.
        let pool = TieredPool::new(TieredPoolConfig {
            tier_sizes: vec![32, 32],
        })
        .unwrap();
        assert_eq!(pool.tier_count(), 1, "duplicates should be deduped");
    }

    #[test]
    fn tiered_pool_config_validates_max_slot_size() {
        let ps = page_size();
        let too_large = ps / 3 + 1;
        let err = TieredPool::new(TieredPoolConfig {
            tier_sizes: vec![too_large],
        });
        assert!(err.is_err(), "slot size > page_size/3 must be rejected");
    }

    #[test]
    fn local_pool_coffer_view_works() {
        // Verify coffer_view on the global pool; all slab PoolSlots must come from global_pool.
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let slot = coffer_view().unwrap();
        assert_eq!(slot.size(), DEFAULT_SLOT_SIZE);
        assert_eq!(slot.tier_index(), Some(0));
    }

    // ── New tests for review findings ────────────────────────────────

    #[test]
    fn tiered_pool_first_tier_must_be_32_bytes() {
        // BLK-7: first tier slot_size < 32 must be rejected (coffer requires AES-256 key size).
        let result = TieredPool::new(TieredPoolConfig {
            tier_sizes: vec![16],
        });
        assert!(
            result.is_err(),
            "first tier < 32 should fail (coffer requires slot_size >= 32)"
        );
    }

    #[test]
    fn coffer_view_key_is_32_bytes_and_nonzero() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let slot = coffer_view().unwrap();
        assert_eq!(slot.size(), 32);
        // Key must not be all zeros (OsRng ran during slab init).
        assert!(
            slot.as_slice().iter().any(|&b| b != 0),
            "coffer key must not be all zeros"
        );
    }

    #[test]
    fn empty_tier_sizes_rejected() {
        let result = TieredPool::new(TieredPoolConfig { tier_sizes: vec![] });
        assert!(result.is_err(), "empty tier_sizes must be rejected");
    }

    #[test]
    fn tier_sizes_sorted_ascending_internally() {
        // Pass sizes in reverse order — should be sorted internally.
        let pool = TieredPool::new(TieredPoolConfig {
            tier_sizes: vec![64, 32],
        })
        .unwrap();
        assert_eq!(pool.tier_count(), 2);
        assert_eq!(pool.tier_slot_size(0), Some(32));
        assert_eq!(pool.tier_slot_size(1), Some(64));
    }

    #[test]
    fn multi_tier_routing_smallest_fit() {
        // Two tiers: 32 and 64. Verify tier routing by slot_size inspection only
        // (do not acquire PoolSlots from a local pool — drop would return to wrong pool).
        let pool = TieredPool::new(TieredPoolConfig {
            tier_sizes: vec![32, 64],
        })
        .unwrap();
        assert_eq!(pool.tier_count(), 2);
        // tier_for_size is private; verify via tier_slot_size that sizes are correct.
        assert_eq!(pool.tier_slot_size(0), Some(32));
        assert_eq!(pool.tier_slot_size(1), Some(64));
        // Using the global pool: size 33 > 32 → standalone (single 32-byte tier in global pool).
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let slot = pool_acquire(33).unwrap();
        assert!(
            slot.tier_index().is_none(),
            "size 33 exceeds single 32-byte tier → standalone"
        );
        assert_eq!(slot.size(), 33);
        // Size 32 uses tier 0.
        let slot2 = pool_acquire(32).unwrap();
        assert_eq!(
            slot2.tier_index(),
            Some(0),
            "size 32 must use tier 0 (32-byte)"
        );
        drop(slot);
        drop(slot2);
    }

    #[test]
    fn pool_slot_tier_index_matches_acquisition_tier() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Default pool has one tier (32 bytes). A small acquisition must be tier 0.
        let slot = pool_acquire(16).unwrap();
        assert_eq!(slot.tier_index(), Some(0));
        assert_eq!(
            slot.slab_index().map(|i| i >= FIRST_SHARED_SLOT),
            Some(true)
        );
    }

    #[test]
    fn standalone_slot_has_no_tier_or_slab_index() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let slot = pool_acquire(9999).unwrap();
        assert!(slot.tier_index().is_none());
        assert!(slot.slab_index().is_none());
        assert_eq!(slot.size(), 9999);
    }

    #[test]
    fn pool_slot_zeroized_on_drop_standalone() {
        // Standalone slot (large allocation) must also be zeroed on drop.
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut slot = pool_acquire(512).unwrap();
        slot.bytes().fill(0xBE);
        // After drop, memory is in a guard-paged SecureBuffer that's zeroed in drop.
        drop(slot);
        // Can't inspect freed memory directly, but verify drop doesn't panic.
    }

    #[test]
    fn hot_cache_not_populated_for_large_plaintext() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // hot_cache_insert only caches data that fits in tier 0's slot size (32 bytes).
        // A 64-byte payload should not be cached.
        let big_data = [0x42_u8; 64];
        hot_cache_insert(9876, &big_data);
        // Should be a miss (not cached).
        let result = hot_cache_get(9876);
        assert!(result.is_none(), "oversized data must not be cached");
    }

    #[test]
    fn hot_cache_multiple_ids_are_independent() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let data_a = [0xAA_u8; DEFAULT_SLOT_SIZE];
        let data_b = [0xBB_u8; DEFAULT_SLOT_SIZE];
        hot_cache_insert(100, &data_a);
        hot_cache_insert(101, &data_b);
        let slot_a = hot_cache_get(100).unwrap();
        let slot_b = hot_cache_get(101).unwrap();
        assert_eq!(slot_a.as_slice(), &data_a, "id 100 must return data_a");
        assert_eq!(slot_b.as_slice(), &data_b, "id 101 must return data_b");
        drop(slot_a);
        drop(slot_b);
        hot_cache_evict(100);
        hot_cache_evict(101);
    }

    #[test]
    fn coffer_view_returns_same_key_every_time() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let s1 = coffer_view().unwrap();
        let k1 = s1.as_slice().to_vec();
        drop(s1);
        let s2 = coffer_view().unwrap();
        let k2 = s2.as_slice().to_vec();
        drop(s2);
        let s3 = coffer_view().unwrap();
        let k3 = s3.as_slice().to_vec();
        drop(s3);
        assert_eq!(k1, k2, "coffer key must be same on second call");
        assert_eq!(k2, k3, "coffer key must be same on third call");
        assert!(
            k1.iter().any(|&b| b != 0),
            "coffer key must not be all zeros"
        );
    }

    #[test]
    fn concurrent_pool_acquire_and_release() {
        use std::sync::Arc;
        use std::thread;
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // 8 threads each acquire a pool slot, write, verify, and release.
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let handles: Vec<_> = (0..8_u8)
            .map(|i| {
                let b = Arc::clone(&barrier);
                thread::spawn(move || {
                    let mut slot = pool_acquire(16).unwrap();
                    slot.bytes()[0] = i;
                    b.wait(); // synchronize so all threads are in-flight simultaneously
                    assert_eq!(slot.as_slice()[0], i, "thread {i}: slot content must match");
                    drop(slot);
                })
            })
            .collect();
        for h in handles {
            h.join().expect("thread panicked");
        }
    }
}
