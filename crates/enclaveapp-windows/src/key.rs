// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Key creation, opening, deletion, and enumeration shared between signing
//! and encryption modules.

// This module wraps NCrypt C APIs which require unsafe FFI calls.
// `mem_forget` is used intentionally in `delete_key` because NCryptDeleteKey
// takes ownership of the handle.
#![allow(
    unsafe_code,
    clippy::mem_forget,
    clippy::ptr_as_ptr,
    unused_qualifications,
    let_underscore_drop
)]

use crate::convert::key_name;
use crate::export::export_public_key;
use crate::provider::{open_provider, NcryptHandle};
use crate::ui_policy::set_ui_policy;
use enclaveapp_core::{AccessPolicy, Error, Result};
use windows::core::PCWSTR;
use windows::Win32::Security::Cryptography::*;

/// Create a new TPM-backed key with the given algorithm.
///
/// Returns the key handle and the 65-byte SEC1 uncompressed public key.
pub fn create_key(
    provider: &NcryptHandle,
    app_name: &str,
    label: &str,
    algorithm: &str,
    policy: AccessPolicy,
) -> Result<(NcryptHandle, Vec<u8>)> {
    let name = key_name(app_name, label);
    let name_wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let algo_wide: Vec<u16> = algorithm.encode_utf16().chain(std::iter::once(0)).collect();

    let mut key_handle = NCRYPT_KEY_HANDLE::default();
    unsafe {
        NCryptCreatePersistedKey(
            provider.as_prov(),
            &mut key_handle,
            PCWSTR(algo_wide.as_ptr()),
            PCWSTR(name_wide.as_ptr()),
            CERT_KEY_SPEC::default(),
            NCRYPT_FLAGS::default(),
        )
        .map_err(|e| Error::GenerateFailed {
            detail: format!("NCryptCreatePersistedKey: {e}"),
        })?;
    }
    let key = NcryptHandle(NCRYPT_HANDLE(key_handle.0));

    // Decide whether to set `NCRYPT_UI_PROTECT_KEY_FLAG` on the key.
    //
    // - `AccessPolicy::None`: never set, no prompt at any time.
    //
    // - With the `windows-hello-ui` feature on (default), probe
    //   Hello at keygen time:
    //
    //   - Hello *is* enrolled (PIN / face / fingerprint usable):
    //     skip the flag. The Rust-side `request_consent_for_policy`
    //     in `sign` / `decrypt` will fire Hello at use time
    //     deterministically, and we don't want the flag's CryptUI
    //     password protector firing on top at `NCryptFinalizeKey`.
    //     This is the ideal path: zero password dialogs, Hello
    //     prompt only at use time.
    //
    //   - Hello *not* enrolled: keep the flag so the TPM still
    //     gates use behind *some* UI — the legacy CryptUI password
    //     prompt. Worse UX than Hello but never silent signing,
    //     which the user explicitly preferred over no prompt at
    //     all.
    //
    // - Without the feature (`default-features = false`): set the
    //   flag whenever the policy demands presence. This preserves
    //   the pre-feature implementation as an "ifdef" path.
    if policy != AccessPolicy::None {
        #[cfg(feature = "windows-hello-ui")]
        let hello_available = crate::hello::is_hello_available();
        #[cfg(not(feature = "windows-hello-ui"))]
        let hello_available = false;
        if !hello_available {
            set_ui_policy(&key, policy)?;
        }
    }

    // Persist the key to the TPM.
    unsafe {
        NCryptFinalizeKey(key.as_key(), NCRYPT_FLAGS::default()).map_err(|e| {
            Error::GenerateFailed {
                detail: format!("NCryptFinalizeKey: {e}"),
            }
        })?;
    }

    let pub_key = export_public_key(&key)?;
    Ok((key, pub_key))
}

/// Open an existing TPM-backed key by application name and label.
pub fn open_key(provider: &NcryptHandle, app_name: &str, label: &str) -> Result<NcryptHandle> {
    let name = key_name(app_name, label);
    let name_wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let mut key_handle = NCRYPT_KEY_HANDLE::default();
    unsafe {
        NCryptOpenKey(
            provider.as_prov(),
            &mut key_handle,
            PCWSTR(name_wide.as_ptr()),
            CERT_KEY_SPEC::default(),
            NCRYPT_FLAGS::default(),
        )
        .map_err(|_| Error::KeyNotFound {
            label: label.to_string(),
        })?;
    }
    Ok(NcryptHandle(NCRYPT_HANDLE(key_handle.0)))
}

/// Delete a key from the TPM by application name and label.
pub fn delete_key(app_name: &str, label: &str) -> Result<()> {
    let provider = open_provider()?;
    let key = open_key(&provider, app_name, label)?;

    // NCryptDeleteKey takes ownership of the handle and frees it on success,
    // so we must NOT let the NcryptHandle drop call NCryptFreeObject again.
    let raw_handle = key.as_key();
    std::mem::forget(key);

    unsafe {
        NCryptDeleteKey(raw_handle, 0).map_err(|e| Error::KeyOperation {
            operation: "delete_key".into(),
            detail: format!("NCryptDeleteKey: {e}"),
        })?;
    }
    Ok(())
}

/// Enumerate all keys that match the given application name prefix.
///
/// Returns the label portion (with the `{app_name}-` prefix stripped).
pub fn enumerate_keys(provider: &NcryptHandle, app_name: &str) -> Result<Vec<String>> {
    let prefix = format!("{app_name}-");
    let mut labels = Vec::new();
    let mut enum_state: *mut std::ffi::c_void = std::ptr::null_mut();

    loop {
        let mut key_name: *mut NCryptKeyName = std::ptr::null_mut();
        let result = unsafe {
            NCryptEnumKeys(
                provider.as_prov(),
                PCWSTR::null(),
                &mut key_name,
                &mut enum_state,
                NCRYPT_FLAGS::default(),
            )
        };

        if result.is_err() {
            // NTE_NO_MORE_ITEMS or any other error ends enumeration.
            break;
        }

        if !key_name.is_null() {
            let key_info = unsafe { &*key_name };
            let name = unsafe { key_info.pszName.to_string() };
            if let Ok(name_str) = name {
                if let Some(stripped) = name_str.strip_prefix(&prefix) {
                    labels.push(stripped.to_string());
                }
            }
            unsafe {
                let _ = NCryptFreeBuffer(key_name as *mut _);
            }
        }
    }

    // Free the enumeration state buffer.
    if !enum_state.is_null() {
        unsafe {
            let _ = NCryptFreeBuffer(enum_state);
        }
    }

    labels.sort();
    Ok(labels)
}
