// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Windows Hello UI gate.
//!
//! Wraps `Windows.Security.Credentials.UI.UserConsentVerifier`, the
//! WinRT API for surfacing a Hello prompt (face / fingerprint / PIN)
//! from any user-mode app. Used by [`crate::sign`] and
//! [`crate::encrypt`] to gate operations that the metadata's
//! `AccessPolicy` says require user presence — instead of relying
//! solely on `NCRYPT_UI_PROTECT_KEY_FLAG` which on some Windows
//! configurations surfaces as the legacy CryptUI password protector
//! rather than Hello.
//!
//! ## Routing precedence
//!
//! `UserConsentVerifier` itself doesn't expose a knob to force
//! biometric over PIN — the OS chooses based on its own policy and
//! recent-presence cache. On the developer host the prompt
//! consistently fires as Hello PIN; on hosts whose Hello policy
//! prefers biometric the same call surfaces face/fingerprint. Either
//! way the resulting credential is Hello, not the legacy CryptUI
//! password dialog.
//!
//! ## Code-signing
//!
//! `UserConsentVerifier` is in the WinRT public API surface and
//! accessible from any user-mode process. Probed on the developer
//! host with an unsigned `cargo build --release` binary —
//! `CheckAvailabilityAsync` returned `Available`,
//! `RequestVerificationAsync` returned `Verified` after the user
//! authenticated. No code-signing requirement.
//!
//! ## Defense-in-depth
//!
//! Calling this from Rust before the TPM operation does not, on its
//! own, hardware-enforce user presence — a malicious local-process
//! attacker who controls the binary could skip the call. That is why
//! [`crate::ui_policy::set_ui_policy`] is still applied to the key
//! at creation time when the access policy demands presence: the TPM
//! refuses to sign without *some* UI, even if the Rust-side gate is
//! bypassed. The Hello prompt this module produces is *additional* —
//! its purpose is to make sure that when the user does see a prompt,
//! it's Hello, not CryptUI.

#![cfg(feature = "windows-hello-ui")]
#![allow(unsafe_code, unused_qualifications)]

use enclaveapp_core::AccessPolicy;
use windows::core::HSTRING;
use windows::Security::Credentials::UI::{
    UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
};

/// Cheap synchronous probe for whether Hello is in a state that
/// will produce a real prompt right now. Used at keygen time to
/// decide whether to set `NCRYPT_UI_PROTECT_KEY_FLAG` on the
/// created key — when Hello is enrolled we skip the flag (the
/// Rust-side `request_consent_for_policy` will fire Hello at use
/// time), when Hello is missing we keep the flag so the user still
/// sees the legacy CryptUI password prompt instead of having a key
/// that signs silently.
///
/// Returns `true` only when `UserConsentVerifier::CheckAvailability`
/// reports `Available`. Any error or non-Available status (no PIN
/// enrolled, disabled by policy, biometric devices missing, etc.)
/// returns `false` so the caller falls through to the flag.
pub fn is_hello_available() -> bool {
    let Ok(op) = UserConsentVerifier::CheckAvailabilityAsync() else {
        return false;
    };
    matches!(op.get(), Ok(UserConsentVerifierAvailability::Available))
}

/// Outcome of a Hello prompt attempt that the caller can act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentOutcome {
    /// User authenticated (face / fingerprint / PIN — Windows
    /// chooses). Caller may proceed with the TPM operation.
    Verified,
    /// Hello isn't available on this host (no PIN / biometric
    /// enrolled, disabled by policy, missing biometric devices,
    /// etc.). Caller should fall through to the TPM-flag-only path
    /// — the hardware UI gate will prompt with whatever CryptUI
    /// chooses, which is the pre-feature behavior.
    NotAvailable,
    /// The user declined / cancelled / exhausted retries / device
    /// busy. Caller should refuse the operation; the user actively
    /// chose not to authorize this signature.
    Declined,
}

/// Synchronously invoke Hello if the caller's access policy demands
/// user presence. `prompt` is the message shown to the user
/// (typically "sshenc: signing for X" or similar — kept short, the
/// dialog truncates).
///
/// Returns `Ok(ConsentOutcome::Verified)` when the user authenticated
/// or when the access policy is `None` (no prompt was needed).
/// Surfaces `Declined` on user cancel and `NotAvailable` when Hello
/// itself is missing — the caller chooses whether that's a hard
/// failure or a soft fall-through.
pub fn request_consent_for_policy(
    policy: AccessPolicy,
    prompt: &str,
) -> enclaveapp_core::Result<ConsentOutcome> {
    if policy == AccessPolicy::None {
        return Ok(ConsentOutcome::Verified);
    }

    // Cheap availability probe so we don't wait on a UI thread that
    // never produces a dialog (Hello uninstalled / policy-disabled).
    let availability = match UserConsentVerifier::CheckAvailabilityAsync() {
        Ok(op) => op.get().map_err(|e| enclaveapp_core::Error::KeyOperation {
            operation: "hello_check_availability".into(),
            detail: e.to_string(),
        })?,
        Err(e) => {
            return Err(enclaveapp_core::Error::KeyOperation {
                operation: "hello_check_availability".into(),
                detail: e.to_string(),
            });
        }
    };
    if availability != UserConsentVerifierAvailability::Available {
        return Ok(ConsentOutcome::NotAvailable);
    }

    let message: HSTRING = prompt.into();
    let result = match UserConsentVerifier::RequestVerificationAsync(&message) {
        Ok(op) => op.get().map_err(|e| enclaveapp_core::Error::KeyOperation {
            operation: "hello_request_verification".into(),
            detail: e.to_string(),
        })?,
        Err(e) => {
            return Err(enclaveapp_core::Error::KeyOperation {
                operation: "hello_request_verification".into(),
                detail: e.to_string(),
            });
        }
    };
    Ok(match result {
        UserConsentVerificationResult::Verified => ConsentOutcome::Verified,
        // DeviceNotPresent / DisabledByPolicy / DeviceBusy collapse
        // to NotAvailable — same actionable category for the caller.
        UserConsentVerificationResult::DeviceNotPresent
        | UserConsentVerificationResult::DisabledByPolicy => ConsentOutcome::NotAvailable,
        // Canceled / RetriesExhausted / NotConfiguredForUser are
        // explicit user-side declines. Don't fall back; refuse.
        _ => ConsentOutcome::Declined,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn access_policy_none_short_circuits() {
        // Should not hit the WinRT API at all — no Hello UI fires
        // and the test runs cleanly even on hosts without Hello.
        let outcome = request_consent_for_policy(AccessPolicy::None, "should not appear").unwrap();
        assert_eq!(outcome, ConsentOutcome::Verified);
    }
}
