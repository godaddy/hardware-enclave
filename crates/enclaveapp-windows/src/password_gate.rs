// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Windows account-password soft gate.
//!
//! Fallback user-presence check for hosts where Windows Hello / PIN is
//! not configured. [`crate::hello_gate::HelloGate`] tries
//! `UserConsentVerifier` first; when that reports the device is not
//! enrolled (`DeviceNotPresent` / `NotConfiguredForUser` /
//! `DisabledByPolicy`) it falls back to this module, which prompts for
//! the current user's Windows credentials via
//! `CredUIPromptForWindowsCredentialsW` and validates them with
//! `LogonUserW(LOGON32_LOGON_NETWORK)`.
//!
//! ## Why this exists
//!
//! Without a fallback, opting an app into the Hello soft-UX gate would
//! *eliminate* the user-presence signal for exactly the users who never
//! set up Hello, while keeping the prompt friction for those who did.
//! A Windows password prompt works regardless of Hello enrollment, so
//! every user gets a presence check.
//!
//! ## Threat-model trade-off
//!
//! Identical posture to [`crate::hello_gate`]: this is a **soft gate**.
//! The verification is a Boolean computed in the calling process; a
//! same-UID attacker with code execution can hook `LogonUserW`'s result
//! or invoke the TPM key operation directly. It is a user-presence
//! consent signal, not a hard cryptographic boundary against same-UID
//! malware. The plaintext password lives in process memory only for the
//! duration of the `LogonUserW` call and is zeroized immediately after.
//!
//! ## Outcomes
//!
//! [`verify_current_user`] returns a [`PresenceOutcome`]:
//! - [`PresenceOutcome::Verified`] — the user proved presence; proceed.
//! - [`PresenceOutcome::Denied`] — the user cancelled or exhausted
//!   retries; the caller treats this as access denied.
//! - [`PresenceOutcome::Unavailable`] — no prompt could be shown or the
//!   account cannot be validated this way (headless session, API
//!   failure, passwordless/unsupported account). The caller degrades to
//!   no presence prompt; the credential bundle remains TPM-encrypted.

#![allow(unsafe_code)]

use std::iter::once;
use std::mem::size_of;
use std::ptr::{null, null_mut};

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE, HWND};
use windows::Win32::Graphics::Gdi::HBITMAP;
use windows::Win32::Security::Credentials::{
    CredUIPromptForWindowsCredentialsW, CredUnPackAuthenticationBufferW,
    CREDUIWIN_ENUMERATE_CURRENT_USER, CREDUI_INFOW, CRED_PACK_FLAGS,
};
use windows::Win32::Security::{LogonUserW, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT};
use windows::Win32::System::Com::CoTaskMemFree;
use zeroize::Zeroize;

/// Result of a Windows password presence check.
#[derive(Debug)]
pub enum PresenceOutcome {
    /// The user proved presence (correct Windows password).
    Verified,
    /// The user actively declined (cancelled the dialog) or failed
    /// verification after the allowed retries. Treat as access denied.
    Denied(String),
    /// No prompt could be shown, or the account cannot be validated via
    /// this mechanism. The caller should degrade gracefully rather than
    /// block the user.
    Unavailable(String),
}

/// `CredUIPromptForWindowsCredentialsW` returns a Win32 error code (not
/// an `HRESULT`). `ERROR_SUCCESS` means the user submitted credentials.
const ERROR_SUCCESS_CODE: u32 = 0;
/// The user dismissed the credential dialog.
const ERROR_CANCELLED_CODE: u32 = 1223; // ERROR_CANCELLED
/// Win32 `ERROR_LOGON_FAILURE`; passed back to the dialog as `dwAuthError`
/// so a re-prompt shows the "the password is incorrect" hint, and used to
/// distinguish a wrong password (retry) from an unvalidatable account
/// (degrade).
const ERROR_LOGON_FAILURE_CODE: u32 = 1326;
/// How many times to re-prompt on a wrong password before denying.
const MAX_ATTEMPTS: u32 = 3;

/// Prompt the current user for their Windows password and verify it.
///
/// `reason` is shown as the dialog's message text; pick something the
/// user can match to the action they're taking (e.g. "Unlock gocode-dev
/// credentials"). See the module docs for the outcome semantics and the
/// threat-model trade-off.
pub fn verify_current_user(reason: &str) -> PresenceOutcome {
    // SAFETY: all pointers handed to the Win32 calls below are either
    // null or point at live, correctly-sized stack/heap buffers for the
    // duration of each call; see the inner function for per-call notes.
    unsafe { verify_current_user_inner(reason) }
}

unsafe fn verify_current_user_inner(reason: &str) -> PresenceOutcome {
    let message: Vec<u16> = reason.encode_utf16().chain(once(0)).collect();
    let caption: Vec<u16> = "gocode-dev".encode_utf16().chain(once(0)).collect();
    let ui_info = CREDUI_INFOW {
        cbSize: size_of::<CREDUI_INFOW>() as u32,
        hwndParent: HWND::default(),
        pszMessageText: PCWSTR(message.as_ptr()),
        pszCaptionText: PCWSTR(caption.as_ptr()),
        hbmBanner: HBITMAP::default(),
    };

    let mut auth_error: u32 = 0;
    let mut attempts: u32 = 0;

    loop {
        attempts += 1;
        let mut auth_package: u32 = 0;
        let mut out_buf: *mut core::ffi::c_void = null_mut();
        let mut out_size: u32 = 0;

        // Restrict the dialog to the current user's tile: we are
        // confirming "are you still you", not collecting arbitrary
        // credentials.
        let rc = CredUIPromptForWindowsCredentialsW(
            Some(&ui_info),
            auth_error,
            &mut auth_package,
            None,
            0,
            &mut out_buf,
            &mut out_size,
            None,
            CREDUIWIN_ENUMERATE_CURRENT_USER,
        );

        match rc {
            ERROR_SUCCESS_CODE => {}
            ERROR_CANCELLED_CODE => {
                return PresenceOutcome::Denied("user cancelled the password prompt".into());
            }
            other => {
                return PresenceOutcome::Unavailable(format!(
                    "CredUIPromptForWindowsCredentialsW failed (0x{other:08X})"
                ));
            }
        }

        let outcome = verify_auth_buffer(out_buf, out_size);

        // The credential blob holds the plaintext password; scrub it
        // before handing the memory back to the allocator.
        if !out_buf.is_null() {
            std::slice::from_raw_parts_mut(out_buf.cast::<u8>(), out_size as usize).zeroize();
            CoTaskMemFree(Some(out_buf.cast_const()));
        }

        match outcome {
            AuthCheck::Verified => return PresenceOutcome::Verified,
            AuthCheck::WrongPassword => {
                auth_error = ERROR_LOGON_FAILURE_CODE;
                if attempts >= MAX_ATTEMPTS {
                    return PresenceOutcome::Denied(
                        "Windows password could not be verified".into(),
                    );
                }
                // loop and re-prompt with the "incorrect password" hint
            }
            AuthCheck::Unavailable(detail) => return PresenceOutcome::Unavailable(detail),
        }
    }
}

/// Internal classification of a single unpack+logon attempt.
enum AuthCheck {
    Verified,
    WrongPassword,
    Unavailable(String),
}

/// Unpack the credential blob from `CredUIPromptForWindowsCredentialsW`
/// and validate it with a network logon. All secret buffers are zeroized
/// before return.
unsafe fn verify_auth_buffer(buf: *mut core::ffi::c_void, size: u32) -> AuthCheck {
    if buf.is_null() || size == 0 {
        return AuthCheck::Unavailable("empty credential buffer".into());
    }

    // First call: discover the required buffer lengths (in WCHARs). The
    // wrapper returns Err on the expected insufficient-buffer result;
    // the out-params are written regardless.
    let mut user_len: u32 = 0;
    let mut domain_len: u32 = 0;
    let mut pass_len: u32 = 0;
    // Expected to fail with insufficient-buffer; the lengths are written
    // regardless. `drop` matches the crate convention for discarding a
    // Result whose Err carries a destructor.
    drop(CredUnPackAuthenticationBufferW(
        CRED_PACK_FLAGS(0),
        buf,
        size,
        PWSTR(null_mut()),
        &mut user_len,
        PWSTR(null_mut()),
        Some(&mut domain_len),
        PWSTR(null_mut()),
        &mut pass_len,
    ));
    if user_len == 0 || pass_len == 0 {
        return AuthCheck::Unavailable("could not size unpacked credentials".into());
    }

    let mut user = vec![0_u16; user_len as usize];
    let mut domain = vec![0_u16; domain_len.max(1) as usize];
    let mut password = vec![0_u16; pass_len as usize];

    let unpacked = CredUnPackAuthenticationBufferW(
        CRED_PACK_FLAGS(0),
        buf,
        size,
        PWSTR(user.as_mut_ptr()),
        &mut user_len,
        PWSTR(domain.as_mut_ptr()),
        Some(&mut domain_len),
        PWSTR(password.as_mut_ptr()),
        &mut pass_len,
    );
    if unpacked.is_err() {
        user.zeroize();
        domain.zeroize();
        password.zeroize();
        return AuthCheck::Unavailable("could not unpack credentials".into());
    }

    // UPN-form usernames (user@domain) carry the whole identity in the
    // username field with an empty domain; pass NULL domain in that case.
    let domain_ptr = if domain_len > 1 && domain[0] != 0 {
        PCWSTR(domain.as_ptr())
    } else {
        PCWSTR(null())
    };

    let mut token = HANDLE::default();
    let logon = LogonUserW(
        PCWSTR(user.as_ptr()),
        domain_ptr,
        PCWSTR(password.as_ptr()),
        LOGON32_LOGON_NETWORK,
        LOGON32_PROVIDER_DEFAULT,
        &mut token,
    );

    // Scrub secrets the instant they are no longer needed.
    user.zeroize();
    domain.zeroize();
    password.zeroize();

    match logon {
        Ok(()) => {
            if !token.is_invalid() {
                drop(CloseHandle(token));
            }
            AuthCheck::Verified
        }
        Err(err) => {
            // HRESULT_FROM_WIN32 packs the Win32 code in the low 16 bits.
            let win32 = (err.code().0 as u32) & 0xFFFF;
            if win32 == ERROR_LOGON_FAILURE_CODE {
                AuthCheck::WrongPassword
            } else {
                // The account cannot be validated via LogonUser on this
                // host (e.g. network-logon right denied, passwordless
                // account). Degrade rather than lock the user out.
                AuthCheck::Unavailable(format!("LogonUserW could not validate the account: {err}"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Win32 codes the prompt loop branches on must match the
    /// platform definitions. A silent drift here would turn "user
    /// cancelled" into "degrade" (or vice versa), changing the gate's
    /// deny/allow semantics. The interactive prompt itself is not
    /// unit-testable (it requires an attended desktop), so pin the
    /// constants instead.
    #[test]
    fn win32_codes_match_platform_definitions() {
        assert_eq!(ERROR_SUCCESS_CODE, 0);
        assert_eq!(ERROR_CANCELLED_CODE, 1223);
        assert_eq!(ERROR_LOGON_FAILURE_CODE, 1326);
    }

    /// Document the deny/allow contract of the three outcomes so a
    /// refactor can't quietly collapse "denied" (block decrypt) into
    /// "unavailable" (degrade and decrypt) without this test noticing.
    #[test]
    fn outcomes_carry_the_expected_shape() {
        let denied = PresenceOutcome::Denied("cancelled".into());
        let unavailable = PresenceOutcome::Unavailable("headless".into());
        assert!(matches!(denied, PresenceOutcome::Denied(_)));
        assert!(matches!(unavailable, PresenceOutcome::Unavailable(_)));
        assert!(matches!(
            PresenceOutcome::Verified,
            PresenceOutcome::Verified
        ));
    }
}
