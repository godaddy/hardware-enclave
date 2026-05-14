// Copyright 2026 Jay Gowdy
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
    create_key_with_flags(provider, app_name, label, algorithm, policy, NCRYPT_FLAGS::default())
}

/// Like [`create_key`] but with `NCRYPT_SILENT_FLAG` set on
/// `NCryptCreatePersistedKey` and `NCryptFinalizeKey`. This tells the
/// KSP it MUST NOT surface its own UI; if it would need to, the call
/// fails with `NTE_SILENT_CONTEXT` (0x80090022). Use this from the
/// `prefer_windows_hello_ux` path where the application supplies
/// Hello UX via `UserConsentVerifier` instead of the legacy CryptUI
/// dialog -- failing closed is preferable to a surprise password
/// prompt from the KSP.
pub fn create_key_silent(
    provider: &NcryptHandle,
    app_name: &str,
    label: &str,
    algorithm: &str,
    policy: AccessPolicy,
) -> Result<(NcryptHandle, Vec<u8>)> {
    create_key_with_flags(provider, app_name, label, algorithm, policy, NCRYPT_SILENT_FLAG)
}

fn create_key_with_flags(
    provider: &NcryptHandle,
    app_name: &str,
    label: &str,
    algorithm: &str,
    policy: AccessPolicy,
    flags: NCRYPT_FLAGS,
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
            flags,
        )
        .map_err(|e| Error::GenerateFailed {
            detail: format!("NCryptCreatePersistedKey: {e}"),
        })?;
    }
    let key = NcryptHandle(NCRYPT_HANDLE(key_handle.0));

    // Set `NCRYPT_UI_PROTECT_KEY_FLAG` whenever a non-None access
    // policy is requested. The TPM enforces the UI gate per-sign:
    // on Hello-enrolled hosts the OS surfaces the legacy CryptUI
    // password protector dialog; on non-Hello hosts the same dialog.
    // Either way, the gate is hardware-enforced -- the TPM will not
    // release the key without the OS-mediated UI ack, and there is
    // no user-mode Boolean an attacker can hook.
    //
    // The previous design (pre-PR removing UserConsentVerifier) had
    // a Hello-availability probe here that dropped the flag when
    // Hello was enrolled, with a Rust-side `UserConsentVerifier`
    // call in `sign` / `decrypt` providing the prompt instead.
    // That gave a nicer Hello biometric UX but at the cost of a
    // soft consent gate -- the `Verified` Boolean was checked in
    // user-mode and hookable by an attacker with code execution as
    // the user. Apps that want hardware-enforced Hello biometric
    // UX use `enclaveapp-windows-webauthn` (TPM via NGC) instead.
    //
    // Apps that opt into `StorageConfig::prefer_windows_hello_ux`
    // pass `AccessPolicy::None` here and gate via the application-
    // level `hello_gate::HelloGate` -- see the file-on-disk threat
    // model in libenclaveapp's THREAT_MODEL.md.
    if policy != AccessPolicy::None {
        set_ui_policy(&key, policy)?;
    }

    // Persist the key to the TPM. Inherit `flags` so callers using
    // NCRYPT_SILENT_FLAG fail closed (NTE_SILENT_CONTEXT) rather than
    // let the KSP show its own dialog.
    unsafe {
        NCryptFinalizeKey(key.as_key(), flags).map_err(|e| {
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
    open_key_with_flags(provider, app_name, label, NCRYPT_FLAGS::default())
}

/// Like [`open_key`] but with `NCRYPT_SILENT_FLAG` set. See
/// [`create_key_silent`] for rationale.
pub fn open_key_silent(provider: &NcryptHandle, app_name: &str, label: &str) -> Result<NcryptHandle> {
    open_key_with_flags(provider, app_name, label, NCRYPT_SILENT_FLAG)
}

fn open_key_with_flags(
    provider: &NcryptHandle,
    app_name: &str,
    label: &str,
    flags: NCRYPT_FLAGS,
) -> Result<NcryptHandle> {
    let name = key_name(app_name, label);
    let name_wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let mut key_handle = NCRYPT_KEY_HANDLE::default();
    unsafe {
        NCryptOpenKey(
            provider.as_prov(),
            &mut key_handle,
            PCWSTR(name_wide.as_ptr()),
            CERT_KEY_SPEC::default(),
            flags,
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
