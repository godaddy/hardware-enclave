// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Win32 WebAuthn FFI wrapper. All `unsafe` is contained here; the
//! public API surface in `lib.rs` is safe Rust.
//!
//! ## clientDataJSON brittleness note
//!
//! Win32 WebAuthn.dll documents `pbClientDataJSON` as bytes-of-JSON
//! plus an explicit `pwszHashAlgId` -- it does not validate that the
//! bytes parse as JSON. We exploit this contract: `client_data` is
//! the raw SSH sign payload, and webauthn.dll computes
//! `SHA-256(client_data)` and signs `authenticator_data || that_hash`.
//! The OpenSSH SK verifier reconstructs the same shape from
//! `SHA-256(data)` where `data` is the SSH session-binding bytes.
//!
//! If a future Windows update tightens this and starts requiring
//! that `pbClientDataJSON` actually be valid JSON, every existing
//! sshenc Hello user breaks. The integration test in
//! `tests/wire_format_roundtrip.rs` asserts the WebAuthn-produced
//! signature verifies via `ssh-keygen -Y verify`, so any such drift
//! is caught at CI time rather than silently in production.

use ciborium::Value as CborValue;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use windows::core::PCWSTR;
use windows::Win32::Foundation::HWND;
use windows::Win32::Networking::WindowsWebServices::*;
use windows::Win32::System::Console::GetConsoleWindow;
use windows::Win32::UI::WindowsAndMessaging::{
    GetDesktopWindow, GetForegroundWindow, IsWindowVisible,
};

use crate::{Result, WebAuthnAssertion, WebAuthnCredential, WebAuthnError};

/// Parameters for `make_credential`.
#[derive(Debug, Clone)]
pub struct MakeCredentialParams<'params> {
    /// Relying-Party identifier. We pin it to a stable string per
    /// app (`"sshenc"`, `"awsenc"`, etc.) so credentials don't
    /// collide across enclave apps on the same host.
    pub rp_id: &'params str,
    /// Human-readable RP name surfaced in the Hello prompt.
    pub rp_name: &'params str,
    /// Per-user opaque identifier the OS scopes credentials by.
    /// We use the SSH key label (or a hash of it) here.
    pub user_id: &'params [u8],
    /// Username surfaced in the Hello prompt and in `passkey` UI.
    pub user_name: &'params str,
    /// Display name surfaced in the Hello prompt.
    pub user_display_name: &'params str,
    /// Hello prompt timeout. Hard upper bound is whatever the OS
    /// applies; pick something the user can realistically respond
    /// to (60s is the WebAuthn convention).
    pub timeout_ms: u32,
    /// HWND to parent the prompt to. `None` -> auto-pick from
    /// `GetConsoleWindow`/`GetForegroundWindow`/`GetDesktopWindow`
    /// in that order. CLI binaries should pass `None`; the agent
    /// (where there is no console) should pass an explicit handle
    /// from a foreground helper.
    pub hwnd: Option<isize>,
}

/// Parameters for `get_assertion`.
#[derive(Debug, Clone)]
pub struct GetAssertionParams<'params> {
    /// Must match the `rp_id` used at make-credential time.
    pub rp_id: &'params str,
    /// `credential_id` returned from a prior `make_credential` for
    /// the user we're signing as.
    pub credential_id: &'params [u8],
    /// Raw bytes the SSH side wants signed. Will be SHA-256'd by
    /// webauthn.dll and that hash will be concatenated with
    /// `authenticator_data` and ECDSA-signed.
    pub client_data: &'params [u8],
    pub timeout_ms: u32,
    pub hwnd: Option<isize>,
}

/// Remove a previously-registered platform credential from the
/// user's passkey list. Best-effort -- if the credential is
/// already gone (user pruned it via Settings -> Passkeys) this
/// returns an error we generally want to ignore.
pub fn delete_platform_credential(credential_id: &[u8]) -> Result<()> {
    #[allow(unsafe_code)]
    unsafe {
        WebAuthNDeletePlatformCredential(credential_id).map_err(map_webauthn_error)
    }
}

/// Probe whether the Hello platform authenticator is reachable on
/// this host. Cheap check (no UI). Use to decide at install/keygen
/// time whether to recommend the SK key path.
pub fn is_platform_authenticator_available() -> bool {
    #[allow(unsafe_code)]
    unsafe {
        match WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable() {
            Ok(b) => b.as_bool(),
            Err(_) => false,
        }
    }
}

/// Create a new TPM-backed credential. Triggers a one-time Hello
/// "save your passkey" / consent prompt; the user's gesture proves
/// presence and the resulting credential is sealed by the TPM.
pub fn make_credential(params: MakeCredentialParams<'_>) -> Result<WebAuthnCredential> {
    let rp_id_w = to_wide(params.rp_id);
    let rp_name_w = to_wide(params.rp_name);
    let user_name_w = to_wide(params.user_name);
    let user_display_w = to_wide(params.user_display_name);

    let mut user_id_buf: Vec<u8> = params.user_id.to_vec();
    let mut client_data_json = canonical_make_client_data();

    #[allow(unsafe_code)]
    let result = unsafe {
        let hwnd = pick_hwnd(params.hwnd);

        let rp = WEBAUTHN_RP_ENTITY_INFORMATION {
            dwVersion: WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION,
            pwszId: PCWSTR(rp_id_w.as_ptr()),
            pwszName: PCWSTR(rp_name_w.as_ptr()),
            pwszIcon: PCWSTR::null(),
        };

        let user = WEBAUTHN_USER_ENTITY_INFORMATION {
            dwVersion: WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
            cbId: u32::try_from(user_id_buf.len())
                .map_err(|_| WebAuthnError::InvalidResponse("user_id too long".into()))?,
            pbId: user_id_buf.as_mut_ptr(),
            pwszName: PCWSTR(user_name_w.as_ptr()),
            pwszIcon: PCWSTR::null(),
            pwszDisplayName: PCWSTR(user_display_w.as_ptr()),
        };

        let mut cose_param = WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
            dwVersion: 1,
            pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
            lAlg: WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256,
        };
        let cose_params = WEBAUTHN_COSE_CREDENTIAL_PARAMETERS {
            cCredentialParameters: 1,
            pCredentialParameters: &mut cose_param,
        };

        let client_data = WEBAUTHN_CLIENT_DATA {
            dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
            cbClientDataJSON: u32::try_from(client_data_json.len())
                .map_err(|_| WebAuthnError::InvalidResponse("client_data_json too long".into()))?,
            pbClientDataJSON: client_data_json.as_mut_ptr(),
            pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
        };

        let opts = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS {
            dwVersion: WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_1,
            dwTimeoutMilliseconds: params.timeout_ms,
            dwAuthenticatorAttachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM,
            dwUserVerificationRequirement: WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
            dwAttestationConveyancePreference: WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            bRequireResidentKey: false.into(),
            bPreferResidentKey: false.into(),
            ..Default::default()
        };

        let opts_ptr: *const WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS = &opts;
        WebAuthNAuthenticatorMakeCredential(
            hwnd,
            &rp,
            &user,
            &cose_params,
            &client_data,
            Some(opts_ptr),
        )
    };

    let attestation_ptr = result.map_err(map_webauthn_error)?;

    // SAFETY: Win32 returned a non-null attestation pointer on Ok.
    // We deref once, copy fields out, and free on the way out.
    #[allow(unsafe_code)]
    let credential = unsafe {
        let att = &*attestation_ptr;
        let credential_id = slice_from_raw(att.pbCredentialId, att.cbCredentialId).to_vec();
        let authenticator_data =
            slice_from_raw(att.pbAuthenticatorData, att.cbAuthenticatorData).to_vec();
        let resident = att.bResidentKey.as_bool();

        WebAuthNFreeCredentialAttestation(Some(attestation_ptr));

        let (x, y) = parse_pubkey_from_authenticator_data(&authenticator_data)?;
        WebAuthnCredential {
            credential_id,
            public_key_x: x,
            public_key_y: y,
            authenticator_data,
            resident,
        }
    };

    Ok(credential)
}

/// Sign `client_data` with a previously-created credential. Fires
/// a Hello prompt; on user verification the TPM returns a DER
/// ECDSA signature over `authenticator_data || SHA-256(client_data)`.
pub fn get_assertion(params: GetAssertionParams<'_>) -> Result<WebAuthnAssertion> {
    let rp_id_w = to_wide(params.rp_id);
    let mut credential_id_buf: Vec<u8> = params.credential_id.to_vec();
    let mut client_data_buf: Vec<u8> = params.client_data.to_vec();

    #[allow(unsafe_code)]
    let result = unsafe {
        let hwnd = pick_hwnd(params.hwnd);

        // Use the V1 `CredentialList` field (a `WEBAUTHN_CREDENTIALS`
        // of plain `WEBAUTHN_CREDENTIAL`) and explicitly null
        // `pAllowCredentialList`. This matches the
        // `tavrez/openssh-sk-winhello` working pattern. With the V4
        // `pAllowCredentialList` field the platform on some Win11
        // builds enumerates discoverable credentials more
        // aggressively for the chooser; with V1 + a single-entry
        // CredentialList scoped to a unique-per-key RP, the chooser
        // collapses to a single-entry "OK" interstitial instead of
        // a multi-credential picker.
        let mut allow_cred = WEBAUTHN_CREDENTIAL {
            dwVersion: 1,
            cbId: u32::try_from(credential_id_buf.len())
                .map_err(|_| WebAuthnError::InvalidResponse("credential_id too long".into()))?,
            pbId: credential_id_buf.as_mut_ptr(),
            pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
        };
        let allow_list = WEBAUTHN_CREDENTIALS {
            cCredentials: 1,
            pCredentials: &mut allow_cred,
        };

        let client_data = WEBAUTHN_CLIENT_DATA {
            dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
            cbClientDataJSON: u32::try_from(client_data_buf.len())
                .map_err(|_| WebAuthnError::InvalidResponse("client_data too long".into()))?,
            pbClientDataJSON: client_data_buf.as_mut_ptr(),
            pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
        };

        let opts = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS {
            dwVersion: 1,
            dwTimeoutMilliseconds: params.timeout_ms,
            CredentialList: allow_list,
            dwAuthenticatorAttachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM,
            dwUserVerificationRequirement: WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
            pAllowCredentialList: std::ptr::null_mut(),
            ..Default::default()
        };

        let opts_ptr: *const WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS = &opts;
        WebAuthNAuthenticatorGetAssertion(
            hwnd,
            PCWSTR(rp_id_w.as_ptr()),
            &client_data,
            Some(opts_ptr),
        )
    };

    let assertion_ptr = result.map_err(map_webauthn_error)?;

    #[allow(unsafe_code)]
    let assertion = unsafe {
        let asn = &*assertion_ptr;
        let authenticator_data =
            slice_from_raw(asn.pbAuthenticatorData, asn.cbAuthenticatorData).to_vec();
        let signature_der = slice_from_raw(asn.pbSignature, asn.cbSignature).to_vec();
        WebAuthNFreeAssertion(assertion_ptr);

        if authenticator_data.len() < 37 {
            return Err(WebAuthnError::InvalidResponse(format!(
                "authenticator_data too short: {} bytes",
                authenticator_data.len()
            )));
        }
        let flags = authenticator_data[32];
        let counter = u32::from_be_bytes([
            authenticator_data[33],
            authenticator_data[34],
            authenticator_data[35],
            authenticator_data[36],
        ]);
        WebAuthnAssertion {
            signature_der,
            authenticator_data,
            flags,
            counter,
        }
    };

    Ok(assertion)
}

// ---- internals ---------------------------------------------------

fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[allow(unsafe_code)]
/// Pick an HWND to parent the Hello dialog to.
///
/// Probes (in order): caller-provided HWND, console window,
/// foreground window, desktop. Each candidate is required to be
/// **visible** (`IsWindowVisible`) — if the chosen parent is
/// hidden, Hello renders the dialog parented to a non-displayable
/// window, the user can't respond to it, and
/// `WebAuthNAuthenticatorMakeCredential` / `…GetAssertion` block
/// indefinitely (the dwTimeoutMilliseconds field doesn't trip
/// once the user has interacted with the dialog at all). Field-
/// observed when a sshenc matrix run was launched from
/// `Start-Process -WindowStyle Hidden`: GetConsoleWindow() returned
/// the hidden parent's HWND, the first dialog squeaked through to
/// foreground but every subsequent prompt landed on the hidden
/// parent and the keygen process hung forever.
///
/// The desktop fallback is always visible, so we always have a
/// usable HWND. A caller-provided HWND that fails the visibility
/// check is swapped for the next candidate rather than respected
/// blindly — the caller's intent ("parent the dialog HERE")
/// presumes the parent is displayable; honoring an invisible HWND
/// just hangs the dialog.
unsafe fn pick_hwnd(provided: Option<isize>) -> HWND {
    let candidates: [HWND; 4] = [
        provided
            .map(|raw| HWND(raw as *mut _))
            .unwrap_or(HWND(std::ptr::null_mut())),
        GetConsoleWindow(),
        GetForegroundWindow(),
        GetDesktopWindow(),
    ];
    for candidate in candidates {
        if !candidate.0.is_null() && IsWindowVisible(candidate).as_bool() {
            return candidate;
        }
    }
    // Should be unreachable: GetDesktopWindow is always non-null
    // and visible. Fall through to it anyway in case Win32 returns
    // something unexpected.
    GetDesktopWindow()
}

#[allow(unsafe_code)]
unsafe fn slice_from_raw<'params>(ptr: *const u8, len: u32) -> &'params [u8] {
    if ptr.is_null() || len == 0 {
        return &[];
    }
    std::slice::from_raw_parts(ptr, len as usize)
}

fn map_webauthn_error(e: windows::core::Error) -> WebAuthnError {
    let hr = e.code();
    // 0x80090028 NTE_USER_CANCELLED
    if hr.0 as u32 == 0x80090028 {
        return WebAuthnError::UserCanceled;
    }
    // 0x800704C7 ERROR_CANCELLED (WinRT cancellation)
    if hr.0 as u32 == 0x800704C7 {
        return WebAuthnError::UserCanceled;
    }
    // 0x80004004 E_ABORT (WebAuthn cancellation)
    if hr.0 as u32 == 0x80004004 {
        return WebAuthnError::UserCanceled;
    }
    // 0x800705B4 ERROR_TIMEOUT
    if hr.0 as u32 == 0x800705B4 {
        return WebAuthnError::Timeout;
    }
    let name = lookup_error_name(hr);
    WebAuthnError::Backend {
        hr: hr.0 as u32,
        name,
    }
}

#[allow(unsafe_code)]
fn lookup_error_name(hr: windows::core::HRESULT) -> String {
    unsafe {
        let pw = WebAuthNGetErrorName(hr);
        if pw.0.is_null() {
            return String::from("(unnamed)");
        }
        let mut len = 0_usize;
        while *pw.0.add(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(pw.0, len);
        String::from_utf16_lossy(slice)
    }
}

/// At make-credential time we don't carry an SSH-side payload,
/// so we synthesize a minimal but well-formed JSON envelope. This
/// is the only place we put real JSON in `pbClientDataJSON` -- at
/// sign time we put the raw SSH bytes per the SK protocol.
fn canonical_make_client_data() -> Vec<u8> {
    br#"{"type":"webauthn.create","challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","origin":"sshenc:keygen"}"#.to_vec()
}

/// Parse the ECDSA P-256 public key out of `authenticator_data`.
///
/// Layout per FIDO2 / W3C WebAuthn:
/// ```text
///   bytes  0..32  rpIdHash
///   byte   32     flags
///   bytes  33..37 signCount (u32 BE)
///   bytes  37..   attestedCredentialData (only when AT flag set):
///                 16 bytes aaguid
///                 2 bytes  credentialIdLength (u16 BE)
///                 N bytes  credentialId
///                 M bytes  credentialPublicKey (COSE_Key CBOR map)
/// ```
///
/// The COSE_Key map for ECDSA P-256 (kty=2, alg=-7) contains
/// `-2 (x)` and `-3 (y)` -- each a 32-byte byte string. We
/// CBOR-decode rather than offset-hardcode (which is what the
/// `tavrez/openssh-sk-winhello` plugin does -- works today, breaks
/// quietly if Microsoft ever reorders fields).
fn parse_pubkey_from_authenticator_data(authenticator_data: &[u8]) -> Result<([u8; 32], [u8; 32])> {
    if authenticator_data.len() < 37 {
        return Err(WebAuthnError::InvalidResponse(format!(
            "authenticator_data too short for header: {} bytes",
            authenticator_data.len()
        )));
    }
    let flags = authenticator_data[32];
    if flags & 0x40 == 0 {
        return Err(WebAuthnError::InvalidResponse(
            "AT flag not set in authenticator_data; cannot extract pubkey".into(),
        ));
    }

    let attested_start = 37;
    if authenticator_data.len() < attested_start + 18 {
        return Err(WebAuthnError::InvalidResponse(
            "authenticator_data too short for attested credential header".into(),
        ));
    }
    // skip 16-byte AAGUID
    let cred_len_off = attested_start + 16;
    let cred_id_len = u16::from_be_bytes([
        authenticator_data[cred_len_off],
        authenticator_data[cred_len_off + 1],
    ]) as usize;
    let cose_start = cred_len_off + 2 + cred_id_len;
    if authenticator_data.len() < cose_start {
        return Err(WebAuthnError::InvalidResponse(
            "authenticator_data too short for COSE_Key blob".into(),
        ));
    }
    let cose_bytes = &authenticator_data[cose_start..];

    let cose_value: CborValue = ciborium::from_reader(cose_bytes)
        .map_err(|e| WebAuthnError::InvalidResponse(format!("COSE CBOR parse failed: {e}")))?;
    let map = match cose_value {
        CborValue::Map(m) => m,
        _ => {
            return Err(WebAuthnError::InvalidResponse(
                "COSE_Key value is not a CBOR map".into(),
            ))
        }
    };

    let mut x: Option<[u8; 32]> = None;
    let mut y: Option<[u8; 32]> = None;
    for (k, v) in map.iter() {
        let k_int = match k {
            CborValue::Integer(i) => i128::from(*i),
            _ => continue,
        };
        let v_bytes = match v {
            CborValue::Bytes(b) => b.as_slice(),
            _ => continue,
        };
        if k_int == -2 && v_bytes.len() == 32 {
            let mut buf = [0_u8; 32];
            buf.copy_from_slice(v_bytes);
            x = Some(buf);
        } else if k_int == -3 && v_bytes.len() == 32 {
            let mut buf = [0_u8; 32];
            buf.copy_from_slice(v_bytes);
            y = Some(buf);
        }
    }

    match (x, y) {
        (Some(x), Some(y)) => Ok((x, y)),
        _ => Err(WebAuthnError::InvalidResponse(
            "COSE_Key missing -2/-3 (x/y) byte strings".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal authenticator_data with a synthetic
    /// COSE_Key payload to exercise the parser without hardware.
    fn synth_authenticator_data(x: &[u8; 32], y: &[u8; 32]) -> Vec<u8> {
        let mut cose_bytes = Vec::new();
        let cose = CborValue::Map(vec![
            (CborValue::Integer(1.into()), CborValue::Integer(2.into())), // kty=EC2
            (
                CborValue::Integer(3.into()),
                CborValue::Integer((-7_i32).into()),
            ), // alg=ES256
            (
                CborValue::Integer((-1_i32).into()),
                CborValue::Integer(1.into()),
            ), // crv=P-256
            (
                CborValue::Integer((-2_i32).into()),
                CborValue::Bytes(x.to_vec()),
            ),
            (
                CborValue::Integer((-3_i32).into()),
                CborValue::Bytes(y.to_vec()),
            ),
        ]);
        ciborium::into_writer(&cose, &mut cose_bytes).expect("cbor encode");

        let mut ad = Vec::new();
        ad.extend_from_slice(&[0_u8; 32]); // rpIdHash
        ad.push(0x45); // flags: UP|UV|AT
        ad.extend_from_slice(&0_u32.to_be_bytes()); // counter
        ad.extend_from_slice(&[0_u8; 16]); // aaguid
        ad.extend_from_slice(&16_u16.to_be_bytes()); // credentialIdLength
        ad.extend_from_slice(&[0_u8; 16]); // credentialId
        ad.extend_from_slice(&cose_bytes);
        ad
    }

    #[test]
    fn parses_ecdsa_p256_pubkey() {
        let mut x = [0_u8; 32];
        let mut y = [0_u8; 32];
        for i in 0..32 {
            x[i] = i as u8;
            y[i] = (i + 32) as u8;
        }
        let ad = synth_authenticator_data(&x, &y);
        let (got_x, got_y) = parse_pubkey_from_authenticator_data(&ad).expect("parse ok");
        assert_eq!(got_x, x);
        assert_eq!(got_y, y);
    }

    #[test]
    fn rejects_truncated_authenticator_data() {
        let short = vec![0_u8; 36];
        assert!(parse_pubkey_from_authenticator_data(&short).is_err());
    }

    #[test]
    fn rejects_missing_at_flag() {
        let mut ad = vec![0_u8; 64];
        ad[32] = 0x05; // UP|UV but not AT
        assert!(parse_pubkey_from_authenticator_data(&ad).is_err());
    }
}
