// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

#![allow(unsafe_code)]

use std::ptr::NonNull;

#[derive(Debug)]
pub enum MemError {
    Alloc(String),
    Lock(String),
    Unlock(String),
    Protect(String),
    Free(String),
}

impl std::fmt::Display for MemError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MemError::Alloc(s) => write!(f, "alloc: {s}"),
            MemError::Lock(s) => write!(f, "lock: {s}"),
            MemError::Unlock(s) => write!(f, "unlock: {s}"),
            MemError::Protect(s) => write!(f, "protect: {s}"),
            MemError::Free(s) => write!(f, "free: {s}"),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Protection {
    NoAccess,
    ReadOnly,
    ReadWrite,
}

#[cfg(unix)]
pub fn page_size() -> usize {
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
}

#[cfg(windows)]
pub fn page_size() -> usize {
    use windows::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
    unsafe {
        let mut info = SYSTEM_INFO::default();
        GetSystemInfo(&mut info);
        info.dwPageSize as usize
    }
}

#[cfg(not(any(unix, windows)))]
pub fn page_size() -> usize {
    4096
}

// ── Unix implementation ───────────────────────────────────────────────────────

#[cfg(unix)]
pub unsafe fn os_alloc(len: usize) -> Result<NonNull<u8>, MemError> {
    let ptr = libc::mmap(
        std::ptr::null_mut(),
        len,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANON,
        -1,
        0,
    );
    if ptr == libc::MAP_FAILED {
        return Err(MemError::Alloc(std::io::Error::last_os_error().to_string()));
    }
    Ok(NonNull::new(ptr.cast::<u8>()).expect("mmap returned null that is not MAP_FAILED"))
}

#[cfg(unix)]
pub unsafe fn os_lock(ptr: *mut u8, len: usize) -> Result<(), MemError> {
    // Best-effort: exclude from core dumps and zero in child processes after fork.
    #[cfg(target_os = "linux")]
    {
        let _ = libc::madvise(ptr.cast(), len, libc::MADV_DONTDUMP);
        let _ = libc::madvise(ptr.cast(), len, libc::MADV_WIPEONFORK);
    }
    // macOS: no MADV_NOCORE; use MADV_ZERO_WIRED_PAGES as a best-effort hint.
    #[cfg(target_os = "macos")]
    let _ = libc::madvise(ptr.cast(), len, libc::MADV_ZERO_WIRED_PAGES);

    if libc::mlock(ptr.cast(), len) != 0 {
        return Err(MemError::Lock(std::io::Error::last_os_error().to_string()));
    }
    Ok(())
}

#[cfg(unix)]
pub unsafe fn os_unlock(ptr: *mut u8, len: usize) -> Result<(), MemError> {
    if libc::munlock(ptr.cast(), len) != 0 {
        return Err(MemError::Unlock(
            std::io::Error::last_os_error().to_string(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
pub unsafe fn os_protect(ptr: *mut u8, len: usize, prot: Protection) -> Result<(), MemError> {
    let flags = match prot {
        Protection::NoAccess => libc::PROT_NONE,
        Protection::ReadOnly => libc::PROT_READ,
        Protection::ReadWrite => libc::PROT_READ | libc::PROT_WRITE,
    };
    if libc::mprotect(ptr.cast(), len, flags) != 0 {
        return Err(MemError::Protect(
            std::io::Error::last_os_error().to_string(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
pub unsafe fn os_free(ptr: *mut u8, len: usize) -> Result<(), MemError> {
    if libc::munmap(ptr.cast(), len) != 0 {
        return Err(MemError::Free(std::io::Error::last_os_error().to_string()));
    }
    Ok(())
}

// ── Windows implementation ────────────────────────────────────────────────────

#[cfg(windows)]
pub unsafe fn os_alloc(len: usize) -> Result<NonNull<u8>, MemError> {
    use windows::Win32::System::Memory::{VirtualAlloc, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};
    let ptr = VirtualAlloc(None, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    NonNull::new(ptr.cast::<u8>())
        .ok_or_else(|| MemError::Alloc(std::io::Error::last_os_error().to_string()))
}

#[cfg(windows)]
pub unsafe fn os_lock(ptr: *mut u8, len: usize) -> Result<(), MemError> {
    use windows::Win32::System::Memory::VirtualLock;
    VirtualLock(ptr.cast(), len).map_err(|e| MemError::Lock(e.to_string()))
}

#[cfg(windows)]
pub unsafe fn os_unlock(ptr: *mut u8, len: usize) -> Result<(), MemError> {
    use windows::Win32::System::Memory::VirtualUnlock;
    VirtualUnlock(ptr.cast(), len).map_err(|e| MemError::Unlock(e.to_string()))
}

#[cfg(windows)]
pub unsafe fn os_protect(ptr: *mut u8, len: usize, prot: Protection) -> Result<(), MemError> {
    use windows::Win32::System::Memory::{
        VirtualProtect, PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE,
    };
    let flags = match prot {
        Protection::NoAccess => PAGE_NOACCESS,
        Protection::ReadOnly => PAGE_READONLY,
        Protection::ReadWrite => PAGE_READWRITE,
    };
    let mut old = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
    VirtualProtect(ptr.cast(), len, flags, &mut old).map_err(|e| MemError::Protect(e.to_string()))
}

#[cfg(windows)]
pub unsafe fn os_free(ptr: *mut u8, len: usize) -> Result<(), MemError> {
    use windows::Win32::System::Memory::{VirtualFree, MEM_RELEASE};
    let _ = len;
    VirtualFree(ptr.cast(), 0, MEM_RELEASE).map_err(|e| MemError::Free(e.to_string()))
}

// ── Stub for other platforms ──────────────────────────────────────────────────

#[cfg(not(any(unix, windows)))]
pub unsafe fn os_alloc(len: usize) -> Result<NonNull<u8>, MemError> {
    use std::alloc::{alloc_zeroed, Layout};
    let layout = Layout::from_size_align(len, 1).map_err(|e| MemError::Alloc(e.to_string()))?;
    let ptr = alloc_zeroed(layout);
    NonNull::new(ptr).ok_or_else(|| MemError::Alloc("allocation failed".into()))
}

#[cfg(not(any(unix, windows)))]
pub unsafe fn os_lock(_ptr: *mut u8, _len: usize) -> Result<(), MemError> {
    Ok(())
}
#[cfg(not(any(unix, windows)))]
pub unsafe fn os_unlock(_ptr: *mut u8, _len: usize) -> Result<(), MemError> {
    Ok(())
}
#[cfg(not(any(unix, windows)))]
pub unsafe fn os_protect(_ptr: *mut u8, _len: usize, _prot: Protection) -> Result<(), MemError> {
    Ok(())
}
#[cfg(not(any(unix, windows)))]
pub unsafe fn os_free(ptr: *mut u8, len: usize) -> Result<(), MemError> {
    use std::alloc::{dealloc, Layout};
    let layout = Layout::from_size_align(len, 1).map_err(|e| MemError::Free(e.to_string()))?;
    dealloc(ptr, layout);
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // Tests ported from asherah-ffi (godaddy/asherah-ffi/asherah/src/memcall.rs)

    #[test]
    fn alloc_and_free_basic() {
        let len = 4096;
        let ptr = unsafe { os_alloc(len) }.unwrap();
        let slice = unsafe { std::slice::from_raw_parts(ptr.as_ptr(), len) };
        assert_eq!(slice.len(), len);
        assert!(unsafe { os_free(ptr.as_ptr(), len) }.is_ok());
    }

    #[test]
    fn read_write_basic() {
        let len = 64;
        let ptr = unsafe { os_alloc(len) }.unwrap();
        unsafe {
            *ptr.as_ptr() = 0xAA_u8;
        }
        unsafe {
            *ptr.as_ptr().add(63) = 0xBB_u8;
        }
        assert_eq!(unsafe { *ptr.as_ptr() }, 0xAA_u8);
        assert_eq!(unsafe { *ptr.as_ptr().add(63) }, 0xBB_u8);
        unsafe { os_free(ptr.as_ptr(), len) }.unwrap();
    }

    #[test]
    fn lock_and_unlock() {
        let len = page_size();
        let ptr = unsafe { os_alloc(len) }.unwrap();
        unsafe { os_lock(ptr.as_ptr(), len) }.unwrap();
        unsafe { os_unlock(ptr.as_ptr(), len) }.unwrap();
        unsafe { os_free(ptr.as_ptr(), len) }.unwrap();
    }

    #[test]
    fn protect_read_write() {
        let len = page_size();
        let ptr = unsafe { os_alloc(len) }.unwrap();
        unsafe { os_protect(ptr.as_ptr(), len, Protection::ReadOnly) }.unwrap();
        unsafe { os_protect(ptr.as_ptr(), len, Protection::ReadWrite) }.unwrap();
        unsafe {
            *ptr.as_ptr() = 42_u8;
        }
        assert_eq!(unsafe { *ptr.as_ptr() }, 42_u8);
        unsafe { os_free(ptr.as_ptr(), len) }.unwrap();
    }

    #[test]
    fn protect_no_access_and_restore() {
        let len = page_size();
        let ptr = unsafe { os_alloc(len) }.unwrap();
        unsafe { os_protect(ptr.as_ptr(), len, Protection::NoAccess) }.unwrap();
        // Restore so we can free
        unsafe { os_protect(ptr.as_ptr(), len, Protection::ReadWrite) }.unwrap();
        unsafe { os_free(ptr.as_ptr(), len) }.unwrap();
    }

    #[test]
    fn various_sizes_are_zero_initialized() {
        for &size in &[1_usize, 16, 256, 4096, 8192] {
            let ptr = unsafe { os_alloc(size) }.unwrap();
            let slice = unsafe { std::slice::from_raw_parts(ptr.as_ptr(), size) };
            assert!(
                slice.iter().all(|&b| b == 0_u8),
                "size {size}: not zero-initialized"
            );
            unsafe { os_free(ptr.as_ptr(), size) }.unwrap();
        }
    }

    #[test]
    fn protection_flags_are_distinct() {
        let na = format!("{:?}", Protection::NoAccess);
        let ro = format!("{:?}", Protection::ReadOnly);
        let rw = format!("{:?}", Protection::ReadWrite);
        assert_ne!(na, ro);
        assert_ne!(ro, rw);
        assert_ne!(na, rw);
    }

    #[test]
    fn harden_process_succeeds() {
        // Ported from asherah-ffi disable_core_dumps_succeeds.
        // Should not panic or error.
        crate::harden_process();
    }
}
