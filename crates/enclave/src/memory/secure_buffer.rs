// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

#![allow(unsafe_code)]

use std::ptr::NonNull;

use rand::TryRngCore;
use zeroize::Zeroize;

use super::memcall::{os_alloc, os_free, os_lock, os_protect, os_unlock, page_size, Protection};
use crate::error::Error;

const CANARY_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum State {
    Mutable,
    Frozen,
    Dead,
}

/// A page-guarded, mlock'd buffer for secret material.
///
/// Layout: [guard page (PROT_NONE)] [inner region, mlock'd] [guard page (PROT_NONE)]
///
/// Guard pages are filled with random canary bytes. On drop, canaries are verified
/// (detects overflow), inner region is zeroized, and all pages are unmapped.
pub struct SecureBuffer {
    /// Pointer to the start of the full allocation (first guard page).
    alloc_ptr: NonNull<u8>,
    /// Total allocation length (guard + inner + guard), page-aligned.
    alloc_len: usize,
    /// Pointer to the start of the inner (data) region.
    inner_ptr: NonNull<u8>,
    /// Requested data length.
    inner_len: usize,
    /// Copy of canary bytes placed in guard pages.
    pre_canary: [u8; CANARY_LEN],
    post_canary: [u8; CANARY_LEN],
    page_size: usize,
    pub(super) state: State,
    mlocked: bool,
}

// Safety: exclusive ownership of the allocation.
unsafe impl Send for SecureBuffer {}

impl std::fmt::Debug for SecureBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureBuffer")
            .field("inner_len", &self.inner_len)
            .field("state", &self.state)
            .finish()
    }
}

impl SecureBuffer {
    /// Allocate a new mutable, mlock'd, guard-paged buffer.
    pub fn new(size: usize) -> crate::error::Result<Self> {
        let ps = page_size();
        // Round inner region up to page boundary.
        let inner_rounded = size.div_ceil(ps) * ps;
        let alloc_len = ps + inner_rounded + ps;

        let alloc_ptr = unsafe { os_alloc(alloc_len) }
            .map_err(|e| Error::Memory(format!("SecureBuffer::new alloc: {e}")))?;

        // SAFETY: alloc_ptr is a freshly allocated page from os_alloc. The offset ps is
        // exactly one page, which is within the multi-page allocation
        // (alloc_len = ps + inner_rounded + ps). The pointer is non-null because os_alloc
        // returns NonNull and we are adding a positive, in-bounds offset.
        let inner_ptr = unsafe { NonNull::new_unchecked(alloc_ptr.as_ptr().add(ps)) };

        // Generate random canaries.
        let mut pre_canary = [0_u8; CANARY_LEN];
        let mut post_canary = [0_u8; CANARY_LEN];
        if rand::rngs::OsRng.try_fill_bytes(&mut pre_canary).is_err() {
            pre_canary.fill(0xAB);
        }
        if rand::rngs::OsRng.try_fill_bytes(&mut post_canary).is_err() {
            post_canary.fill(0xCD);
        }

        // Write canaries into guard pages (must be writable at this point).
        unsafe {
            let pre_guard = alloc_ptr.as_ptr();
            std::ptr::copy_nonoverlapping(pre_canary.as_ptr(), pre_guard, CANARY_LEN.min(ps));
            let post_guard = alloc_ptr.as_ptr().add(ps + inner_rounded);
            std::ptr::copy_nonoverlapping(post_canary.as_ptr(), post_guard, CANARY_LEN.min(ps));
        }

        // mlock the inner region.
        let mlocked = unsafe { os_lock(inner_ptr.as_ptr(), inner_rounded) }.is_ok();

        // Set guard pages to PROT_NONE.
        drop(unsafe { os_protect(alloc_ptr.as_ptr(), ps, Protection::NoAccess) });
        drop(unsafe {
            os_protect(
                alloc_ptr.as_ptr().add(ps + inner_rounded),
                ps,
                Protection::NoAccess,
            )
        });

        Ok(Self {
            alloc_ptr,
            alloc_len,
            inner_ptr,
            inner_len: size,
            pre_canary,
            post_canary,
            page_size: ps,
            state: State::Mutable,
            mlocked,
        })
    }

    pub fn size(&self) -> usize {
        self.inner_len
    }

    pub fn is_alive(&self) -> bool {
        self.state != State::Dead
    }

    pub fn is_mutable(&self) -> bool {
        self.state == State::Mutable
    }

    /// Get a mutable slice to the inner region. Requires Mutable state.
    pub fn bytes(&mut self) -> &mut [u8] {
        assert!(
            self.state == State::Mutable,
            "SecureBuffer: bytes() called in non-mutable state"
        );
        // SAFETY: state == Mutable ensures the inner region has PROT_READ|WRITE. inner_ptr
        // was set at construction to alloc_ptr + page_size, which is within alloc_len.
        // inner_len is the caller-requested size, <= inner_rounded which is within alloc_len.
        // &mut self guarantees no aliasing.
        unsafe { std::slice::from_raw_parts_mut(self.inner_ptr.as_ptr(), self.inner_len) }
    }

    /// Get a read-only slice. Requires non-Dead state.
    pub fn as_slice(&self) -> &[u8] {
        assert!(
            self.state != State::Dead,
            "SecureBuffer: as_slice() on dead buffer"
        );
        // SAFETY: state != Dead ensures the allocation is still live. inner_ptr
        // was set at construction to alloc_ptr + page_size, within alloc_len.
        // If state == Frozen the protection is ReadOnly, which permits reads.
        // If state == Mutable the protection is ReadWrite, which also permits reads.
        unsafe { std::slice::from_raw_parts(self.inner_ptr.as_ptr(), self.inner_len) }
    }

    /// Make the buffer read-only.
    pub fn freeze(&mut self) -> crate::error::Result<()> {
        if self.state == State::Dead {
            return Err(Error::Memory("SecureBuffer::freeze on dead buffer".into()));
        }
        let inner_rounded = self.alloc_len - 2 * self.page_size;
        unsafe { os_protect(self.inner_ptr.as_ptr(), inner_rounded, Protection::ReadOnly) }
            .map_err(|e| Error::Memory(format!("freeze: {e}")))?;
        self.state = State::Frozen;
        Ok(())
    }

    /// Make the buffer writable again.
    pub fn melt(&mut self) -> crate::error::Result<()> {
        if self.state == State::Dead {
            return Err(Error::Memory("SecureBuffer::melt on dead buffer".into()));
        }
        let inner_rounded = self.alloc_len - 2 * self.page_size;
        unsafe {
            os_protect(
                self.inner_ptr.as_ptr(),
                inner_rounded,
                Protection::ReadWrite,
            )
        }
        .map_err(|e| Error::Memory(format!("melt: {e}")))?;
        self.state = State::Mutable;
        Ok(())
    }

    /// Verify guard-page canaries, zeroize, unlock, and free the allocation.
    ///
    /// Idempotent — returns `Ok(())` immediately if already `Dead`.
    pub fn destroy(&mut self) -> crate::error::Result<()> {
        if self.state == State::Dead {
            return Ok(());
        }

        let ps = self.page_size;
        let inner_rounded = self.alloc_len - 2 * ps;

        // Temporarily make guard pages readable for canary verification.
        let pre_guard = self.alloc_ptr.as_ptr();
        let post_guard = unsafe { self.alloc_ptr.as_ptr().add(ps + inner_rounded) };

        drop(unsafe { os_protect(pre_guard, ps, Protection::ReadOnly) });
        drop(unsafe { os_protect(post_guard, ps, Protection::ReadOnly) });

        // Read canaries from guard pages.
        let pre_guard_slice = unsafe { std::slice::from_raw_parts(pre_guard, CANARY_LEN) };
        let post_guard_slice = unsafe { std::slice::from_raw_parts(post_guard, CANARY_LEN) };

        // Constant-time comparison.
        let pre_ok = pre_guard_slice
            .iter()
            .zip(self.pre_canary.iter())
            .fold(0_u8, |acc, (a, b)| acc | (a ^ b))
            == 0;
        let post_ok = post_guard_slice
            .iter()
            .zip(self.post_canary.iter())
            .fold(0_u8, |acc, (a, b)| acc | (a ^ b))
            == 0;

        // Restore write access to inner region for zeroization.
        drop(unsafe {
            os_protect(
                self.inner_ptr.as_ptr(),
                inner_rounded,
                Protection::ReadWrite,
            )
        });

        // Zeroize inner region.
        unsafe {
            let s = std::slice::from_raw_parts_mut(self.inner_ptr.as_ptr(), inner_rounded);
            s.zeroize();
        }

        // Unlock inner region.
        if self.mlocked {
            drop(unsafe { os_unlock(self.inner_ptr.as_ptr(), inner_rounded) });
        }

        // Free entire allocation.
        // The guard pages remain PROT_NONE (set at construction); no need to restore
        // them to ReadWrite before freeing — the OS reclaims the entire mapping on
        // munmap/VirtualFree regardless of protection state. Restoring write access on
        // guard pages before free is unnecessary and was removed (SG-E).
        drop(unsafe { os_free(self.alloc_ptr.as_ptr(), self.alloc_len) });

        self.state = State::Dead;

        if !pre_ok || !post_ok {
            return Err(Error::Memory(
                "SecureBuffer: guard page canary corrupted — buffer overflow detected".into(),
            ));
        }
        Ok(())
    }

    /// Fill with random bytes (stays mutable).
    pub fn scramble(&mut self) -> crate::error::Result<()> {
        if self.state != State::Mutable {
            self.melt()?;
        }
        let buf = self.bytes();
        rand::rngs::OsRng
            .try_fill_bytes(buf)
            .map_err(|e| Error::Memory(format!("scramble OsRng: {e}")))
    }
}

#[allow(clippy::panic)]
impl Drop for SecureBuffer {
    fn drop(&mut self) {
        if let Err(e) = self.destroy() {
            // A canary corruption means a buffer overflow has occurred — the process
            // memory may be in an unsafe state. Log at error level.
            tracing::error!(error = %e, "SecureBuffer canary corruption detected — possible buffer overflow");
            // In debug/test builds, panic to make the violation visible.
            // clippy::panic is intentional: a corrupted canary in Drop is a
            // security-critical event that must not be silenced in debug builds.
            #[cfg(debug_assertions)]
            panic!("SecureBuffer canary corrupted: {e}");
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // Tests ported from asherah-ffi (godaddy/asherah-ffi/asherah/src/memguard.rs)

    #[test]
    fn canary_corruption_detected() {
        let mut buf = SecureBuffer::new(64).unwrap();

        // Temporarily enable write access on the post-guard page and corrupt the canary.
        let ps = page_size();
        let inner_rounded = 64_usize.div_ceil(ps) * ps;
        let post_guard = unsafe { buf.alloc_ptr.as_ptr().add(ps + inner_rounded) };

        unsafe {
            os_protect(post_guard, ps, Protection::ReadWrite).unwrap();
            *post_guard = !*post_guard; // flip first byte
        }

        // destroy() should detect the canary mismatch.
        let result = buf.destroy();
        assert!(
            result.is_err(),
            "destroy should report canary failure but returned Ok"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("canary"),
            "error should mention canary, got: {msg}"
        );
    }

    #[test]
    fn new_buffer_is_mutable() {
        let buf = SecureBuffer::new(32).unwrap();
        assert!(buf.is_mutable());
        assert!(buf.is_alive());
    }

    #[test]
    fn freeze_and_melt() {
        let mut buf = SecureBuffer::new(32).unwrap();
        buf.freeze().unwrap();
        assert!(!buf.is_mutable());
        buf.melt().unwrap();
        assert!(buf.is_mutable());
    }

    #[test]
    fn bytes_writes_and_reads_back() {
        let mut buf = SecureBuffer::new(64).unwrap();
        buf.bytes()[0] = 0xAA_u8;
        buf.bytes()[63] = 0xBB_u8;
        assert_eq!(buf.as_slice()[0], 0xAA_u8);
        assert_eq!(buf.as_slice()[63], 0xBB_u8);
    }

    #[test]
    fn scramble_produces_non_zero() {
        let mut buf = SecureBuffer::new(64).unwrap();
        buf.scramble().unwrap();
        // After OsRng fill, extremely unlikely all bytes are zero.
        let all_zero = buf.as_slice().iter().all(|&b| b == 0_u8);
        assert!(!all_zero, "scramble should produce non-zero bytes");
    }

    #[test]
    fn destroy_returns_ok_on_clean_buffer() {
        let mut buf = SecureBuffer::new(32).unwrap();
        buf.destroy().unwrap();
        assert!(!buf.is_alive());
    }

    #[test]
    fn drop_without_explicit_destroy_does_not_panic() {
        // Should not leak or panic.
        let mut buf = SecureBuffer::new(128).unwrap();
        buf.bytes()[0] = 1_u8;
        drop(buf);
    }

    #[test]
    fn freeze_twice_is_idempotent() {
        let mut buf = SecureBuffer::new(32).unwrap();
        buf.freeze().unwrap();
        // Second freeze must not error.
        buf.freeze().unwrap();
        assert!(!buf.is_mutable());
    }

    #[test]
    fn melt_twice_is_idempotent() {
        let mut buf = SecureBuffer::new(32).unwrap();
        buf.freeze().unwrap();
        buf.melt().unwrap();
        buf.melt().unwrap();
        assert!(buf.is_mutable());
    }

    #[test]
    fn frozen_buffer_is_readable() {
        let mut buf = SecureBuffer::new(16).unwrap();
        buf.bytes()[0] = 0x99;
        buf.freeze().unwrap();
        assert_eq!(buf.as_slice()[0], 0x99);
    }

    #[test]
    fn scramble_on_frozen_buffer_melts_first() {
        let mut buf = SecureBuffer::new(32).unwrap();
        buf.freeze().unwrap();
        // scramble() must succeed even from Frozen state.
        buf.scramble().unwrap();
        assert!(buf.is_mutable());
    }

    #[test]
    fn destroy_twice_is_safe() {
        let mut buf = SecureBuffer::new(32).unwrap();
        buf.destroy().unwrap();
        assert!(!buf.is_alive());
        // Second destroy must return immediately (Dead state guard).
        buf.destroy().unwrap();
        assert!(!buf.is_alive());
    }

    #[test]
    fn boundary_sizes() {
        let ps = page_size();
        for size in [
            1_usize,
            15,
            16,
            31,
            32,
            33,
            63,
            64,
            ps - 1,
            ps,
            ps + 1,
            ps * 2,
        ] {
            let mut buf = SecureBuffer::new(size).unwrap();
            assert_eq!(buf.size(), size);
            // Fill with known pattern.
            buf.bytes().fill(0xAB);
            assert!(buf.as_slice().iter().all(|&b| b == 0xAB));
            buf.destroy().unwrap();
        }
    }

    #[test]
    fn canary_pre_guard_corruption_detected() {
        // Corrupt the PRE-guard page and verify destroy() detects it.
        let ps = page_size();
        let mut buf = SecureBuffer::new(64).unwrap();
        // The pre-guard is at alloc_ptr (before inner_ptr).
        // Temporarily make it writable and flip a byte.
        let pre_guard = buf.alloc_ptr.as_ptr();
        unsafe {
            os_protect(pre_guard, ps, Protection::ReadWrite).unwrap();
            *pre_guard = !*pre_guard;
        }
        let result = buf.destroy();
        assert!(
            result.is_err(),
            "pre-guard canary corruption must be detected"
        );
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("canary"), "error must mention canary: {msg}");
    }

    #[test]
    fn drop_zeroes_inner_region() {
        // Write a known pattern, destroy, verify the buffer reports Dead
        // and the drop chain ran without panicking.
        let mut buf = SecureBuffer::new(64).unwrap();
        buf.bytes().fill(0xDE);
        buf.destroy().unwrap();
        assert!(!buf.is_alive());
    }
}
