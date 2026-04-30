// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! NCrypt provider management and RAII handle wrapper.
//!
//! Keys are persisted in the **Microsoft Platform Crypto Provider**
//! (TPM 2.0). The Microsoft Passport / NGC KSP was investigated as
//! an alternative for Windows Hello routing but rejected:
//! `NCryptCreatePersistedKey` against `Microsoft Passport Key
//! Storage Provider` returns `NTE_INVALID_PARAMETER (0x80090027)` on
//! every algorithm / flag combination tried even on hosts where
//! Hello (PIN + biometric) is fully enrolled (`dsregcmd /status`
//! reports `NgcSet : YES`). The NCrypt path to NGC appears to be
//! reserved for system services / domain controllers; user-mode
//! callers are expected to go through `KeyCredentialManager` (WinRT)
//! or `WebAuthn`. Keeping keys in the Platform KSP and routing the
//! UI prompt through `Windows.Security.Credentials.UI.UserConsentVerifier`
//! delivers a Hello prompt deterministically on Hello-enrolled hosts
//! without requiring NGC-resident keys. See [`crate::hello`].

// This module wraps NCrypt C APIs which require unsafe FFI calls.
#![allow(unsafe_code, unused_qualifications, let_underscore_drop)]

use windows::core::PCWSTR;
use windows::Win32::Security::Cryptography::*;

/// The CNG provider name for TPM-backed keys.
pub const PLATFORM_PROVIDER: &str = "Microsoft Platform Crypto Provider";

/// RAII wrapper for NCrypt handles. Calls `NCryptFreeObject` on drop.
#[derive(Debug)]
pub struct NcryptHandle(pub NCRYPT_HANDLE);

// NCrypt handles are thread-safe opaque pointers.
unsafe impl Send for NcryptHandle {}
unsafe impl Sync for NcryptHandle {}

impl NcryptHandle {
    /// Re-interpret as a provider handle.
    pub fn as_prov(&self) -> NCRYPT_PROV_HANDLE {
        NCRYPT_PROV_HANDLE(self.0 .0)
    }

    /// Re-interpret as a key handle.
    pub fn as_key(&self) -> NCRYPT_KEY_HANDLE {
        NCRYPT_KEY_HANDLE(self.0 .0)
    }
}

impl Drop for NcryptHandle {
    fn drop(&mut self) {
        if self.0 .0 != 0 {
            unsafe {
                let _ = NCryptFreeObject(self.0);
            }
        }
    }
}

/// Open the TPM platform crypto provider.
pub fn open_provider() -> enclaveapp_core::Result<NcryptHandle> {
    let provider_name: Vec<u16> = PLATFORM_PROVIDER
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut handle = NCRYPT_PROV_HANDLE::default();
    unsafe {
        NCryptOpenStorageProvider(&mut handle, PCWSTR(provider_name.as_ptr()), 0).map_err(|e| {
            enclaveapp_core::Error::KeyOperation {
                operation: "open_provider".into(),
                detail: e.to_string(),
            }
        })?;
    }
    Ok(NcryptHandle(NCRYPT_HANDLE(handle.0)))
}

/// Check if the TPM platform crypto provider is available.
pub fn is_available() -> bool {
    open_provider().is_ok()
}
