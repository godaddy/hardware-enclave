// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Windows Hello UI policy setup for TPM key operations.

// This module wraps NCrypt C APIs which require unsafe FFI calls.
#![allow(unsafe_code, trivial_casts, clippy::ptr_as_ptr, unused_qualifications)]

use crate::provider::NcryptHandle;
use enclaveapp_core::AccessPolicy;
use windows::core::PCWSTR;
use windows::Win32::Security::Cryptography::*;
use windows::Win32::Security::OBJECT_SECURITY_INFORMATION;

/// Expected in-memory size of `NCRYPT_UI_POLICY` as the Windows API
/// defines it — `DWORD dwVersion`, `DWORD dwFlags`, and three
/// `LPCWSTR` pointers. This mirrors the C declaration in
/// `ncrypt.h`:
/// ```c
/// typedef struct NCRYPT_UI_POLICY {
///     DWORD   dwVersion;
///     DWORD   dwFlags;
///     LPCWSTR pszCreationTitle;
///     LPCWSTR pszFriendlyName;
///     LPCWSTR pszDescription;
/// } NCRYPT_UI_POLICY;
/// ```
/// On 64-bit Windows: 4 + 4 + 8 + 8 + 8 = 32 bytes. The trailing
/// pointer alignment adds nothing on x64 (pointers are already
/// naturally aligned), so the struct lays out at exactly 32 bytes.
/// On 32-bit Windows: 4 + 4 + 4 + 4 + 4 = 20 bytes. We support both.
///
/// A silent `windows-rs` struct-layout change would change
/// `size_of::<NCRYPT_UI_POLICY>()`, which would desync from what
/// `NCryptSetProperty` / `NCryptGetProperty` expect via the `cbInput`
/// argument. The compile-time assertion below catches that at build
/// time rather than at runtime.
const EXPECTED_NCRYPT_UI_POLICY_SIZE: usize = if cfg!(target_pointer_width = "64") {
    32
} else {
    20
};

const _: () = assert!(
    std::mem::size_of::<NCRYPT_UI_POLICY>() == EXPECTED_NCRYPT_UI_POLICY_SIZE,
    "NCRYPT_UI_POLICY layout changed — NCryptSetProperty / NCryptGetProperty \
     cbInput values in this module will desync. Update the expected size \
     constant after auditing the new layout."
);

/// Set a Windows Hello UI policy on a key handle.
///
/// When the policy is anything other than `None`, the key is marked with
/// `NCRYPT_UI_PROTECT_KEY_FLAG` which causes Windows Hello to prompt the
/// user for authentication before the key can be used.
pub fn set_ui_policy(
    key_handle: &NcryptHandle,
    policy: AccessPolicy,
) -> enclaveapp_core::Result<()> {
    if policy == AccessPolicy::None {
        return Ok(());
    }

    let ui_policy = NCRYPT_UI_POLICY {
        dwVersion: 1,
        dwFlags: NCRYPT_UI_PROTECT_KEY_FLAG,
        pszCreationTitle: PCWSTR::null(),
        pszFriendlyName: PCWSTR::null(),
        pszDescription: PCWSTR::null(),
    };

    let prop_name: Vec<u16> = "UI Policy"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let result = unsafe {
        NCryptSetProperty(
            NCRYPT_HANDLE(key_handle.as_key().0),
            PCWSTR(prop_name.as_ptr()),
            std::slice::from_raw_parts(
                &ui_policy as *const _ as *const u8,
                std::mem::size_of::<NCRYPT_UI_POLICY>(),
            ),
            NCRYPT_FLAGS::default(),
        )
    };

    result.map_err(|e| enclaveapp_core::Error::KeyOperation {
        operation: "set_ui_policy".into(),
        detail: format!("NCryptSetProperty(UI Policy): {e}"),
    })
}

/// Read back the `NCRYPT_UI_POLICY` actually set on a CNG key and
/// assert that it matches the requested `AccessPolicy`.
///
/// Defends against a same-user attacker who pre-plants a TPM key with
/// the expected CNG name but without `NCRYPT_UI_PROTECT_KEY_FLAG`. If
/// the app were to open and sign with such a key, the Windows Hello
/// prompt would not fire and the intended presence check would be
/// bypassed. Re-verifying the flag before signing closes that gap.
///
/// Returns `Ok(())` if the key carries the correct `NCRYPT_UI_PROTECT_KEY_FLAG`
/// for the requested policy (or no flag when `expected == None`). Returns
/// an `Error::KeyOperation` if the policy does not match or the query
/// itself fails.
pub fn verify_ui_policy_matches(
    key_handle: &NcryptHandle,
    expected: AccessPolicy,
) -> enclaveapp_core::Result<()> {
    let prop_name: Vec<u16> = "UI Policy"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    // Two-call pattern. CNG's serialized form for `NCRYPT_UI_POLICY`
    // is the struct followed by the inline string contents that the
    // three `LPCWSTR` fields point to (length is variable and can
    // exceed `sizeof(NCRYPT_UI_POLICY)` even when the strings were
    // null at SET time, because CNG normalizes them). Passing a
    // fixed-size buffer fails with `NTE_BUFFER_TOO_SMALL (0x80090028)`
    // — the symptom in sshenc#180. First query the required size
    // with a null buffer, then allocate exactly that and read.
    let mut required: u32 = 0;
    let size_result = unsafe {
        NCryptGetProperty(
            NCRYPT_HANDLE(key_handle.as_key().0),
            PCWSTR(prop_name.as_ptr()),
            None,
            &mut required,
            OBJECT_SECURITY_INFORMATION(0),
        )
    };

    if let Err(e) = size_result {
        // SPC_E_NO_POLICY / NTE_NOT_FOUND surface as a missing policy
        // — translate to "no flag set" so the comparison below treats
        // it as AccessPolicy::None.
        if expected == AccessPolicy::None {
            return Ok(());
        }
        return Err(enclaveapp_core::Error::KeyOperation {
            operation: "verify_ui_policy".into(),
            detail: format!(
                "NCryptGetProperty(UI Policy) size query for key with expected policy \
                 {expected:?}: {e}",
            ),
        });
    }

    if (required as usize) < std::mem::size_of::<NCRYPT_UI_POLICY>() {
        return Err(enclaveapp_core::Error::KeyOperation {
            operation: "verify_ui_policy".into(),
            detail: format!(
                "NCryptGetProperty(UI Policy) reported a buffer size of {required} bytes, \
                 smaller than sizeof(NCRYPT_UI_POLICY)={}",
                std::mem::size_of::<NCRYPT_UI_POLICY>()
            ),
        });
    }

    let mut buf = vec![0_u8; required as usize];
    let mut actual_size = required;
    let result = unsafe {
        NCryptGetProperty(
            NCRYPT_HANDLE(key_handle.as_key().0),
            PCWSTR(prop_name.as_ptr()),
            Some(&mut buf),
            &mut actual_size,
            OBJECT_SECURITY_INFORMATION(0),
        )
    };

    if let Err(e) = result {
        if expected == AccessPolicy::None {
            return Ok(());
        }
        return Err(enclaveapp_core::Error::KeyOperation {
            operation: "verify_ui_policy".into(),
            detail: format!(
                "NCryptGetProperty(UI Policy) for key with expected policy {expected:?}: {e}",
            ),
        });
    }

    // We only need `dwFlags`; ignore the trailing inline strings and
    // their pointers, which point into the local buffer (not stable
    // outside this scope).
    //
    // SAFETY: `buf` is at least `sizeof(NCRYPT_UI_POLICY)` bytes (we
    // checked `required` above) and CNG just wrote a valid
    // `NCRYPT_UI_POLICY` into the prefix. Reading a `u32`-sized
    // `dwFlags` field from a properly-sized buffer is sound.
    let actual_flags = unsafe { (*(buf.as_ptr() as *const NCRYPT_UI_POLICY)).dwFlags };

    let has_protect_flag =
        (actual_flags & NCRYPT_UI_PROTECT_KEY_FLAG) == NCRYPT_UI_PROTECT_KEY_FLAG;
    let expected_protect_flag = expected != AccessPolicy::None;

    if has_protect_flag == expected_protect_flag {
        return Ok(());
    }
    let detail = if expected_protect_flag {
        format!("key is missing NCRYPT_UI_PROTECT_KEY_FLAG but metadata expects {expected:?}")
    } else {
        "key has NCRYPT_UI_PROTECT_KEY_FLAG set but metadata expects AccessPolicy::None".into()
    };
    Err(enclaveapp_core::Error::KeyOperation {
        operation: "verify_ui_policy".into(),
        detail,
    })
}

#[cfg(test)]
mod tests {
    //! Integration tests against a real Microsoft Platform Crypto
    //! Provider key. Each test creates a TPM-backed P-256 key with a
    //! unique label, runs the verify, and deletes the key on the way
    //! out — including on panic, via a drop guard.
    //!
    //! The whole module is `#[ignore]`'d because it requires:
    //! - A real TPM 2.0 the user can write to.
    //! - GitHub-hosted `windows-latest` runners don't expose one to
    //!   user processes, so CI wouldn't pass these. They're meant for
    //!   the developer's matrix-test laptop.
    //!
    //! Run with:
    //! ```sh
    //! cargo test -p enclaveapp-windows ui_policy -- --ignored
    //! ```
    //!
    //! These cover the regression behind sshenc#180: a key created
    //! with `AccessPolicy::Any` has its UI policy round-trip via
    //! `verify_ui_policy_matches`. The pre-fix version failed with
    //! `NTE_BUFFER_TOO_SMALL` because CNG returns the
    //! `NCRYPT_UI_POLICY` struct followed by inline strings whose
    //! total size exceeds the bare `sizeof(NCRYPT_UI_POLICY)`.
    use super::*;
    use crate::key::{create_key, delete_key};
    use crate::provider::open_provider;

    const TEST_APP: &str = "enclaveapp_test_ui_policy";
    const ECDSA_P256: &str = "ECDSA_P256";

    /// RAII guard that deletes a TPM key on drop, regardless of test
    /// outcome. Every test that calls `create_key` must hold one of
    /// these so a panicking assertion doesn't leave a stranded key in
    /// the user's TPM-backed CNG store.
    struct KeyGuard {
        label: String,
    }

    impl Drop for KeyGuard {
        fn drop(&mut self) {
            // Best-effort delete; ignore errors so a failed cleanup
            // doesn't shadow the real test failure. `let _ =` would
            // trip the workspace's `let-underscore-drop` lint, so
            // bind to a named ignore instead.
            let _r = delete_key(TEST_APP, &self.label);
        }
    }

    /// Generate a per-test label so parallel `cargo test` runs don't
    /// collide on the same CNG key name.
    fn unique_label(prefix: &str) -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("{prefix}-{}-{nanos}", std::process::id())
    }

    #[test]
    #[ignore = "requires a real TPM 2.0; run on the matrix-test laptop"]
    fn verify_round_trips_for_presence_required_key() {
        let provider = open_provider().expect("open_provider");
        let label = unique_label("any");
        let _guard = KeyGuard {
            label: label.clone(),
        };

        let (_key, _pub_key) =
            create_key(&provider, TEST_APP, &label, ECDSA_P256, AccessPolicy::Any)
                .expect("create_key with AccessPolicy::Any");

        let key = crate::key::open_key(&provider, TEST_APP, &label).expect("open_key");
        verify_ui_policy_matches(&key, AccessPolicy::Any)
            .expect("verify_ui_policy_matches(Any) on a presence-required key must succeed");
    }

    #[test]
    #[ignore = "requires a real TPM 2.0; run on the matrix-test laptop"]
    fn verify_round_trips_for_no_presence_key() {
        let provider = open_provider().expect("open_provider");
        let label = unique_label("none");
        let _guard = KeyGuard {
            label: label.clone(),
        };

        let (_key, _pub_key) =
            create_key(&provider, TEST_APP, &label, ECDSA_P256, AccessPolicy::None)
                .expect("create_key with AccessPolicy::None");

        let key = crate::key::open_key(&provider, TEST_APP, &label).expect("open_key");
        verify_ui_policy_matches(&key, AccessPolicy::None)
            .expect("verify_ui_policy_matches(None) on a no-presence key must succeed");
    }

    #[test]
    #[ignore = "requires a real TPM 2.0; run on the matrix-test laptop"]
    fn verify_rejects_planted_key_missing_protect_flag() {
        // Security-critical contract: if a key without
        // NCRYPT_UI_PROTECT_KEY_FLAG is opened with metadata that
        // claims a presence policy, the verify must fail. This is
        // the sole defense against a same-user attacker who pre-
        // plants a TPM key under the expected CNG name without the
        // flag.
        let provider = open_provider().expect("open_provider");
        let label = unique_label("plant");
        let _guard = KeyGuard {
            label: label.clone(),
        };

        let (_key, _pub_key) =
            create_key(&provider, TEST_APP, &label, ECDSA_P256, AccessPolicy::None)
                .expect("create_key with AccessPolicy::None");

        let key = crate::key::open_key(&provider, TEST_APP, &label).expect("open_key");
        let err = verify_ui_policy_matches(&key, AccessPolicy::Any)
            .expect_err("verify_ui_policy_matches(Any) against a None-policy key must fail");
        assert!(
            err.to_string()
                .contains("missing NCRYPT_UI_PROTECT_KEY_FLAG"),
            "error message should name the missing-flag mismatch, got: {err}"
        );
    }

    #[test]
    #[ignore = "requires a real TPM 2.0; run on the matrix-test laptop"]
    fn verify_rejects_extra_protect_flag() {
        let provider = open_provider().expect("open_provider");
        let label = unique_label("extra");
        let _guard = KeyGuard {
            label: label.clone(),
        };

        let (_key, _pub_key) =
            create_key(&provider, TEST_APP, &label, ECDSA_P256, AccessPolicy::Any)
                .expect("create_key with AccessPolicy::Any");

        let key = crate::key::open_key(&provider, TEST_APP, &label).expect("open_key");
        let err = verify_ui_policy_matches(&key, AccessPolicy::None)
            .expect_err("verify_ui_policy_matches(None) against an Any-policy key must fail");
        assert!(
            err.to_string()
                .contains("NCRYPT_UI_PROTECT_KEY_FLAG set but metadata expects"),
            "error message should name the extra-flag mismatch, got: {err}"
        );
    }
}
