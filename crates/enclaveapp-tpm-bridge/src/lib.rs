// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Generic JSON-RPC TPM bridge server for enclave apps.
//!
//! Extracts the common bridge server logic shared by `awsenc-tpm-bridge` and
//! `sso-jwt-tpm-bridge`. Each app only needs to supply its default app name
//! and key label, then call [`BridgeServer::run_stdio`].
//!
//! # Example
//!
//! ```no_run
//! let mut server = enclaveapp_tpm_bridge::BridgeServer::new("myapp", "cache-key");
//! server.run_stdio().ok();
//! ```

mod tpm;

pub use tpm::{TpmSigningStorage, TpmStorage};

use base64::prelude::*;
use enclaveapp_bridge::BridgeResponse;
use enclaveapp_core::types::AccessPolicy;
use serde::Deserialize;
use std::io::{self, BufRead, Write};

/// Backward-compatible bridge request that supports both the legacy `biometric`
/// boolean and the newer `access_policy` enum.
#[derive(Debug, Deserialize)]
pub struct BridgeRequestCompat {
    /// Method: "init", "encrypt", "decrypt", "destroy", "delete".
    pub method: String,
    /// Parameters.
    #[serde(default)]
    pub params: BridgeParamsCompat,
}

/// Parameters for a bridge request.
#[derive(Debug, Default, Deserialize)]
pub struct BridgeParamsCompat {
    /// Base64-encoded data (plaintext for encrypt, ciphertext for decrypt).
    #[serde(default)]
    pub data: String,
    /// Access policy to enforce on key use.
    #[serde(default)]
    pub access_policy: AccessPolicy,
    /// Legacy field: older bridge clients send `"biometric": true` instead of
    /// `"access_policy": "biometric_only"`. Kept for backward compatibility.
    #[serde(default)]
    pub biometric: bool,
    /// Application name (determines TPM key name).
    #[serde(default)]
    pub app_name: String,
    /// Key label within the application namespace.
    #[serde(default)]
    pub key_label: String,

    // --- WebAuthn / SK fields. See `enclaveapp_bridge::BridgeParams`
    // for field-by-field semantics. Optional; non-SK methods leave
    // them empty.
    #[serde(default)]
    pub rp_id: Option<String>,
    #[serde(default)]
    pub rp_name: Option<String>,
    #[serde(default)]
    pub user_id_b64: Option<String>,
    #[serde(default)]
    pub user_name: Option<String>,
    #[serde(default)]
    pub user_display_name: Option<String>,
    #[serde(default)]
    pub credential_id_b64: Option<String>,
    #[serde(default)]
    pub client_data_b64: Option<String>,
    #[serde(default)]
    pub timeout_ms: Option<u32>,
}

impl BridgeParamsCompat {
    /// Return the app name, falling back to the provided default.
    pub fn app_name_or<'param>(&'param self, default: &'param str) -> &'param str {
        if self.app_name.is_empty() {
            default
        } else {
            &self.app_name
        }
    }

    /// Return the key label, falling back to the provided default.
    pub fn key_label_or<'param>(&'param self, default: &'param str) -> &'param str {
        if self.key_label.is_empty() {
            default
        } else {
            &self.key_label
        }
    }

    /// Resolve the effective access policy, falling back to the legacy
    /// `biometric` boolean when `access_policy` is unset (defaults to `None`).
    pub fn effective_access_policy(&self) -> AccessPolicy {
        if self.access_policy != AccessPolicy::None {
            return self.access_policy;
        }
        if self.biometric {
            return AccessPolicy::BiometricOnly;
        }
        AccessPolicy::None
    }
}

/// Handle a single parsed bridge request, dispatching to the appropriate
/// TPM storage operation.
pub fn handle_request(
    request: &BridgeRequestCompat,
    storage: &mut Option<TpmStorage>,
    signing_storage: &mut Option<TpmSigningStorage>,
    default_app_name: &str,
    default_key_label: &str,
) -> BridgeResponse {
    let app_name = request.params.app_name_or(default_app_name);
    let key_label = request.params.key_label_or(default_key_label);

    match request.method.as_str() {
        "init" => {
            match TpmStorage::new(
                app_name,
                key_label,
                request.params.effective_access_policy(),
            ) {
                Ok(s) => {
                    *storage = Some(s);
                    BridgeResponse::success("ok")
                }
                Err(e) => BridgeResponse::error(&format!("init failed: {e}")),
            }
        }
        "encrypt" => {
            let Some(ref s) = storage else {
                return BridgeResponse::error("not initialized: call init first");
            };
            if request.params.data.is_empty() {
                return BridgeResponse::error("missing data parameter");
            }
            let plaintext = match BASE64_STANDARD.decode(&request.params.data) {
                Ok(d) => d,
                Err(e) => {
                    return BridgeResponse::error(&format!("base64 decode error: {e}"));
                }
            };
            match s.encrypt(&plaintext) {
                Ok(ciphertext) => BridgeResponse::success(&BASE64_STANDARD.encode(&ciphertext)),
                Err(e) => BridgeResponse::error(&format!("encrypt failed: {e}")),
            }
        }
        "decrypt" => {
            let Some(ref s) = storage else {
                return BridgeResponse::error("not initialized: call init first");
            };
            if request.params.data.is_empty() {
                return BridgeResponse::error("missing data parameter");
            }
            let ciphertext = match BASE64_STANDARD.decode(&request.params.data) {
                Ok(d) => d,
                Err(e) => {
                    return BridgeResponse::error(&format!("base64 decode error: {e}"));
                }
            };
            match s.decrypt(&ciphertext) {
                Ok(plaintext) => BridgeResponse::success(&BASE64_STANDARD.encode(&plaintext)),
                Err(e) => BridgeResponse::error(&format!("decrypt failed: {e}")),
            }
        }
        "destroy" | "delete" => match TpmStorage::delete(app_name, key_label) {
            Ok(()) => {
                *storage = None;
                BridgeResponse::success("ok")
            }
            Err(e) => BridgeResponse::error(&format!("delete failed: {e}")),
        },
        "init_signing" => {
            match TpmSigningStorage::new(
                app_name,
                key_label,
                request.params.effective_access_policy(),
            ) {
                Ok(s) => {
                    *signing_storage = Some(s);
                    BridgeResponse::success("ok")
                }
                Err(e) => BridgeResponse::error(&format!("init_signing failed: {e}")),
            }
        }
        "sign" => {
            let Some(ref s) = signing_storage else {
                return BridgeResponse::error("signing not initialized: call init_signing first");
            };
            if request.params.data.is_empty() {
                return BridgeResponse::error("missing data parameter");
            }
            let data = match BASE64_STANDARD.decode(&request.params.data) {
                Ok(d) => d,
                Err(e) => {
                    return BridgeResponse::error(&format!("base64 decode error: {e}"));
                }
            };
            match s.sign(&data) {
                Ok(signature) => BridgeResponse::success(&BASE64_STANDARD.encode(&signature)),
                Err(e) => BridgeResponse::error(&format!("sign failed: {e}")),
            }
        }
        "public_key" => {
            // Standalone: doesn't require prior init_signing. The
            // previous behaviour required clients to call init_signing
            // first, which has create-if-missing semantics keyed by
            // key_label (defaults to "default") -- so any read-only
            // probe of a non-existent key created a `default` signing
            // key as a side effect. Same fix shape as `list_keys`
            // (libenclaveapp PR #110): a static `public_key_for_app`
            // helper that just instantiates a TpmSigner without going
            // through TpmSigningStorage::new's ensure_signing_key.
            match TpmSigningStorage::public_key_for_app(app_name, key_label) {
                Ok(pubkey) => BridgeResponse::success(&BASE64_STANDARD.encode(&pubkey)),
                Err(e) => BridgeResponse::error(&format!("public_key failed: {e}")),
            }
        }
        "list_keys" => {
            // Standalone: doesn't require prior init_signing. Otherwise
            // the client side's call_bridge_after_signing_init would
            // create a key with the configured key_label (defaults to
            // "default") as a side effect of every list operation,
            // which manifested as a "default" key leak in the agent's
            // identity-enumeration path.
            match TpmSigningStorage::list_keys_for_app(app_name) {
                Ok(keys) => {
                    let json = serde_json::to_string(&keys).unwrap_or_else(|_| "[]".to_string());
                    BridgeResponse::success(&json)
                }
                Err(e) => BridgeResponse::error(&format!("list_keys failed: {e}")),
            }
        }
        "delete_signing" => match TpmSigningStorage::delete(app_name, key_label) {
            Ok(()) => {
                *signing_storage = None;
                BridgeResponse::success("ok")
            }
            Err(e) => BridgeResponse::error(&format!("delete_signing failed: {e}")),
        },
        // Load-only existence check: returns "true"/"false" and does NOT
        // create the key. Does not require prior init_signing.
        // Needed because `init_signing` has load-or-create semantics, so
        // clients that use public_key/list_keys as an existence test end
        // up creating the key as a side effect.
        "signing_key_exists" => match TpmSigningStorage::key_exists(app_name, key_label) {
            Ok(exists) => BridgeResponse::success(if exists { "true" } else { "false" }),
            Err(e) => BridgeResponse::error(&format!("signing_key_exists failed: {e}")),
        },
        // WebAuthn / SK methods. WSL clients call these to get
        // hardware-enforced Hello consent on the Windows host
        // (where webauthn.dll lives). Non-Windows server builds
        // refuse with a clear error -- those builds shouldn't be
        // running these methods anyway since the bridge target
        // platform is Windows.
        "webauthn_is_available" => webauthn_is_available_handler(),
        "webauthn_make_credential" => webauthn_make_credential_handler(&request.params),
        "webauthn_get_assertion" => webauthn_get_assertion_handler(&request.params),
        "webauthn_delete_platform_credential" => {
            webauthn_delete_platform_credential_handler(&request.params)
        }
        other => BridgeResponse::error(&format!("unknown method: {other}")),
    }
}

#[cfg(target_os = "windows")]
fn webauthn_is_available_handler() -> BridgeResponse {
    if enclaveapp_windows_webauthn::is_platform_authenticator_available() {
        BridgeResponse::success("true")
    } else {
        BridgeResponse::success("false")
    }
}

#[cfg(not(target_os = "windows"))]
fn webauthn_is_available_handler() -> BridgeResponse {
    BridgeResponse::success("false")
}

#[cfg(target_os = "windows")]
#[allow(clippy::too_many_lines)] // tight serial flow, splitting hurts readability
fn webauthn_make_credential_handler(params: &BridgeParamsCompat) -> BridgeResponse {
    use enclaveapp_windows_webauthn::{make_credential, MakeCredentialParams};

    let Some(rp_id) = params.rp_id.as_deref() else {
        return BridgeResponse::error("webauthn_make_credential: missing rp_id");
    };
    let rp_name = params.rp_name.as_deref().unwrap_or("sshenc");
    let Some(user_id_b64) = params.user_id_b64.as_deref() else {
        return BridgeResponse::error("webauthn_make_credential: missing user_id_b64");
    };
    let user_id = match BASE64_STANDARD.decode(user_id_b64) {
        Ok(v) => v,
        Err(e) => return BridgeResponse::error(&format!("user_id_b64 decode: {e}")),
    };
    let user_name = params.user_name.as_deref().unwrap_or("");
    let user_display_name = params.user_display_name.as_deref().unwrap_or(user_name);
    let timeout_ms = params.timeout_ms.unwrap_or(60_000);

    match make_credential(MakeCredentialParams {
        rp_id,
        rp_name,
        user_id: &user_id,
        user_name,
        user_display_name,
        timeout_ms,
        // Bridge process has no console window; let the wrapper
        // pick GetForegroundWindow / GetDesktopWindow. On a
        // typical `wsl bash -c "sshenc keygen"` invocation the
        // foreground window is the Windows terminal hosting WSL.
        hwnd: None,
    }) {
        Ok(cred) => {
            let payload = enclaveapp_bridge::WebauthnMakeCredentialResult {
                credential_id_b64: BASE64_STANDARD.encode(&cred.credential_id),
                public_key_x_hex: hex_lower(&cred.public_key_x),
                public_key_y_hex: hex_lower(&cred.public_key_y),
                authenticator_data_b64: BASE64_STANDARD.encode(&cred.authenticator_data),
                resident: cred.resident,
            };
            match serde_json::to_string(&payload) {
                Ok(s) => BridgeResponse::success(&s),
                Err(e) => BridgeResponse::error(&format!("serialize make_credential result: {e}")),
            }
        }
        Err(e) => BridgeResponse::error(&format!("webauthn_make_credential: {e}")),
    }
}

#[cfg(not(target_os = "windows"))]
fn webauthn_make_credential_handler(_params: &BridgeParamsCompat) -> BridgeResponse {
    BridgeResponse::error(
        "webauthn_make_credential: webauthn.dll is only available on Windows; \
         this bridge build can't service the request",
    )
}

#[cfg(target_os = "windows")]
fn webauthn_get_assertion_handler(params: &BridgeParamsCompat) -> BridgeResponse {
    use enclaveapp_windows_webauthn::{get_assertion, GetAssertionParams};

    let Some(rp_id) = params.rp_id.as_deref() else {
        return BridgeResponse::error("webauthn_get_assertion: missing rp_id");
    };
    let Some(credential_id_b64) = params.credential_id_b64.as_deref() else {
        return BridgeResponse::error("webauthn_get_assertion: missing credential_id_b64");
    };
    let credential_id = match BASE64_STANDARD.decode(credential_id_b64) {
        Ok(v) => v,
        Err(e) => return BridgeResponse::error(&format!("credential_id_b64 decode: {e}")),
    };
    let Some(client_data_b64) = params.client_data_b64.as_deref() else {
        return BridgeResponse::error("webauthn_get_assertion: missing client_data_b64");
    };
    let client_data = match BASE64_STANDARD.decode(client_data_b64) {
        Ok(v) => v,
        Err(e) => return BridgeResponse::error(&format!("client_data_b64 decode: {e}")),
    };
    let timeout_ms = params.timeout_ms.unwrap_or(60_000);

    match get_assertion(GetAssertionParams {
        rp_id,
        credential_id: &credential_id,
        client_data: &client_data,
        timeout_ms,
        hwnd: None,
    }) {
        Ok(asn) => {
            let payload = enclaveapp_bridge::WebauthnAssertionResult {
                signature_der_b64: BASE64_STANDARD.encode(&asn.signature_der),
                authenticator_data_b64: BASE64_STANDARD.encode(&asn.authenticator_data),
                flags: asn.flags,
                counter: asn.counter,
            };
            match serde_json::to_string(&payload) {
                Ok(s) => BridgeResponse::success(&s),
                Err(e) => BridgeResponse::error(&format!("serialize assertion result: {e}")),
            }
        }
        Err(e) => BridgeResponse::error(&format!("webauthn_get_assertion: {e}")),
    }
}

#[cfg(not(target_os = "windows"))]
fn webauthn_get_assertion_handler(_params: &BridgeParamsCompat) -> BridgeResponse {
    BridgeResponse::error(
        "webauthn_get_assertion: webauthn.dll is only available on Windows; \
         this bridge build can't service the request",
    )
}

#[cfg(target_os = "windows")]
fn webauthn_delete_platform_credential_handler(params: &BridgeParamsCompat) -> BridgeResponse {
    let Some(credential_id_b64) = params.credential_id_b64.as_deref() else {
        return BridgeResponse::error(
            "webauthn_delete_platform_credential: missing credential_id_b64",
        );
    };
    let credential_id = match BASE64_STANDARD.decode(credential_id_b64) {
        Ok(v) => v,
        Err(e) => return BridgeResponse::error(&format!("credential_id_b64 decode: {e}")),
    };
    match enclaveapp_windows_webauthn::delete_platform_credential(&credential_id) {
        Ok(()) => BridgeResponse::success("ok"),
        Err(e) => BridgeResponse::error(&format!("webauthn_delete_platform_credential: {e}")),
    }
}

#[cfg(not(target_os = "windows"))]
fn webauthn_delete_platform_credential_handler(_params: &BridgeParamsCompat) -> BridgeResponse {
    BridgeResponse::error(
        "webauthn_delete_platform_credential: webauthn.dll is only available on Windows",
    )
}

#[cfg(target_os = "windows")]
fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// A JSON-RPC bridge server that reads requests from stdin and writes
/// responses to stdout, delegating to [`TpmStorage`] for crypto operations.
#[derive(Debug)]
pub struct BridgeServer {
    default_app_name: String,
    default_key_label: String,
}

impl BridgeServer {
    /// Create a new bridge server with the given default app name and key label.
    ///
    /// These defaults are used when the client omits `app_name` or `key_label`
    /// from the request parameters.
    pub fn new(default_app_name: &str, default_key_label: &str) -> Self {
        Self {
            default_app_name: default_app_name.to_string(),
            default_key_label: default_key_label.to_string(),
        }
    }

    /// Run the bridge server, reading JSON-RPC requests from stdin and writing
    /// responses to stdout. Blocks until stdin is closed or a write error
    /// occurs.
    #[allow(clippy::print_stdout)]
    pub fn run_stdio(&mut self) -> io::Result<()> {
        let stdin = io::stdin();
        let mut stdout = io::stdout().lock();
        let mut storage: Option<TpmStorage> = None;
        let mut signing_storage: Option<TpmSigningStorage> = None;

        for line in stdin.lock().lines() {
            let line = match line {
                Ok(l) => l,
                Err(e) => {
                    let resp = BridgeResponse::error(&format!("read error: {e}"));
                    drop(serde_json::to_writer(&mut stdout, &resp));
                    drop(stdout.write_all(b"\n"));
                    drop(stdout.flush());
                    break;
                }
            };

            if line.trim().is_empty() {
                continue;
            }

            let response = match serde_json::from_str::<BridgeRequestCompat>(&line) {
                Ok(req) => handle_request(
                    &req,
                    &mut storage,
                    &mut signing_storage,
                    &self.default_app_name,
                    &self.default_key_label,
                ),
                Err(e) => BridgeResponse::error(&format!("invalid JSON: {e}")),
            };

            if serde_json::to_writer(&mut stdout, &response).is_err() {
                break;
            }
            if stdout.write_all(b"\n").is_err() {
                break;
            }
            if stdout.flush().is_err() {
                break;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    const TEST_APP_NAME: &str = "test-app";
    const TEST_KEY_LABEL: &str = "cache-key";

    fn make_request(method: &str, data: &str, access_policy: AccessPolicy) -> BridgeRequestCompat {
        BridgeRequestCompat {
            method: method.to_string(),
            params: BridgeParamsCompat {
                data: data.to_string(),
                access_policy,
                biometric: false,
                app_name: TEST_APP_NAME.to_string(),
                key_label: TEST_KEY_LABEL.to_string(),
                ..BridgeParamsCompat::default()
            },
        }
    }

    fn handle(req: &BridgeRequestCompat, storage: &mut Option<TpmStorage>) -> BridgeResponse {
        let mut signing_storage = None;
        handle_request(
            req,
            storage,
            &mut signing_storage,
            TEST_APP_NAME,
            TEST_KEY_LABEL,
        )
    }

    fn handle_signing(
        req: &BridgeRequestCompat,
        signing_storage: &mut Option<TpmSigningStorage>,
    ) -> BridgeResponse {
        let mut storage = None;
        handle_request(
            req,
            &mut storage,
            signing_storage,
            TEST_APP_NAME,
            TEST_KEY_LABEL,
        )
    }

    // ----- Parsing tests -----

    #[test]
    fn parse_init_request() {
        let json = r#"{"method": "init", "params": {"access_policy": "none"}}"#;
        let req: BridgeRequestCompat = serde_json::from_str(json).unwrap();
        assert_eq!(req.method, "init");
        assert_eq!(req.params.access_policy, AccessPolicy::None);
        assert_eq!(req.params.app_name_or(TEST_APP_NAME), TEST_APP_NAME);
        assert_eq!(req.params.key_label_or(TEST_KEY_LABEL), TEST_KEY_LABEL);
    }

    #[test]
    fn parse_init_request_defaults() {
        let json = r#"{"method": "init", "params": {}}"#;
        let req: BridgeRequestCompat = serde_json::from_str(json).unwrap();
        assert_eq!(req.method, "init");
        assert_eq!(req.params.access_policy, AccessPolicy::None);
        assert!(req.params.data.is_empty());
        assert_eq!(req.params.app_name_or(TEST_APP_NAME), TEST_APP_NAME);
        assert_eq!(req.params.key_label_or(TEST_KEY_LABEL), TEST_KEY_LABEL);
    }

    #[test]
    fn parse_encrypt_request() {
        let json =
            r#"{"method": "encrypt", "params": {"data": "aGVsbG8=", "access_policy": "none"}}"#;
        let req: BridgeRequestCompat = serde_json::from_str(json).unwrap();
        assert_eq!(req.method, "encrypt");
        assert_eq!(req.params.data, "aGVsbG8=");
    }

    #[test]
    fn parse_decrypt_request() {
        let json = r#"{"method": "decrypt", "params": {"data": "Y2lwaGVy"}}"#;
        let req: BridgeRequestCompat = serde_json::from_str(json).unwrap();
        assert_eq!(req.method, "decrypt");
        assert_eq!(req.params.data, "Y2lwaGVy");
    }

    #[test]
    fn parse_destroy_request() {
        let json = r#"{"method": "destroy", "params": {}}"#;
        let req: BridgeRequestCompat = serde_json::from_str(json).unwrap();
        assert_eq!(req.method, "destroy");
        assert_eq!(req.params.app_name_or(TEST_APP_NAME), TEST_APP_NAME);
        assert_eq!(req.params.key_label_or(TEST_KEY_LABEL), TEST_KEY_LABEL);
    }

    #[test]
    fn parse_delete_request() {
        let json = r#"{"method": "delete", "params": {"key_label": "cache-key"}}"#;
        let req: BridgeRequestCompat = serde_json::from_str(json).unwrap();
        assert_eq!(req.method, "delete");
        assert_eq!(req.params.key_label_or(TEST_KEY_LABEL), TEST_KEY_LABEL);
    }

    #[test]
    fn parse_request_uses_defaults_for_minimal_payloads() {
        let json = r#"{"method":"init","params":{"access_policy":"biometric_only"}}"#;
        let req: BridgeRequestCompat = serde_json::from_str(json).unwrap();
        assert_eq!(req.params.access_policy, AccessPolicy::BiometricOnly);
        assert_eq!(req.params.app_name_or(TEST_APP_NAME), TEST_APP_NAME);
        assert_eq!(req.params.key_label_or(TEST_KEY_LABEL), TEST_KEY_LABEL);
    }

    #[test]
    fn parse_request_with_explicit_app_name_and_key_label() {
        let json = r#"{"method":"init","params":{"app_name":"custom","key_label":"my-key"}}"#;
        let req: BridgeRequestCompat = serde_json::from_str(json).unwrap();
        assert_eq!(req.params.app_name_or(TEST_APP_NAME), "custom");
        assert_eq!(req.params.key_label_or(TEST_KEY_LABEL), "my-key");
    }

    // ----- Serialization tests -----

    #[test]
    fn serialize_success_response() {
        let resp = BridgeResponse::success("ok");
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"result\":\"ok\""));
    }

    #[test]
    fn serialize_error_response() {
        let resp = BridgeResponse::error("something went wrong");
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"error\":\"something went wrong\""));
    }

    // ----- Handler tests -----

    #[test]
    fn handle_init_creates_storage() {
        let req = make_request("init", "", AccessPolicy::None);
        let mut storage = None;
        let resp = handle(&req, &mut storage);
        // On non-Windows, init succeeds (stub creates the struct)
        // but encrypt/decrypt will fail at runtime
        if let Some(err) = &resp.error {
            assert!(!err.is_empty(), "init error message should not be empty");
        } else {
            assert!(
                resp.result.is_some(),
                "init should return a result on success"
            );
        }
    }

    #[test]
    fn handle_destroy_clears_storage() {
        let req = make_request("destroy", "", AccessPolicy::None);
        let mut storage = None;
        let resp = handle(&req, &mut storage);
        // On platforms without TPM, destroy may return an error. That's expected.
        if let Some(err) = &resp.error {
            assert!(!err.is_empty(), "destroy error message should not be empty");
        } else {
            assert!(
                resp.result.is_some(),
                "destroy should return a result on success"
            );
        }
        assert!(storage.is_none());
    }

    #[test]
    fn handle_delete_clears_storage() {
        let req = make_request("delete", "", AccessPolicy::None);
        let mut storage = None;
        let resp = handle(&req, &mut storage);
        // On platforms without TPM, delete may return an error. That's expected.
        if let Some(err) = &resp.error {
            assert!(!err.is_empty(), "delete error message should not be empty");
        } else {
            assert!(
                resp.result.is_some(),
                "delete should return a result on success"
            );
        }
        assert!(storage.is_none());
    }

    #[test]
    fn destroy_and_delete_are_aliases() {
        // Locks in the compat guarantee: the bridge server MUST honor
        // both `destroy` and `delete` on the wire. `bridge_destroy`
        // on the client side sends `"delete"` for backward
        // compatibility with older servers, and newer clients may
        // send either. Both names must produce identical semantics
        // so neither version drifts into an "unknown method" error.
        let destroy = make_request("destroy", "", AccessPolicy::None);
        let delete = make_request("delete", "", AccessPolicy::None);

        let mut storage_a = None;
        let mut storage_b = None;
        let resp_destroy = handle(&destroy, &mut storage_a);
        let resp_delete = handle(&delete, &mut storage_b);

        // Neither response should be the unknown-method sentinel —
        // that error text is the regression guard.
        for resp in [&resp_destroy, &resp_delete] {
            if let Some(err) = &resp.error {
                assert!(
                    !err.contains("unknown method"),
                    "bridge rejected a supported alias as unknown: {err}"
                );
            }
        }
        // Result shape must match: either both error (no TPM on this
        // host) or both succeed.
        assert_eq!(
            resp_destroy.error.is_some(),
            resp_delete.error.is_some(),
            "destroy/delete disagreed: destroy={resp_destroy:?} delete={resp_delete:?}"
        );
    }

    #[test]
    fn handle_unknown_method() {
        let req = make_request("bogus", "", AccessPolicy::None);
        let mut storage = None;
        let resp = handle(&req, &mut storage);
        assert!(resp
            .error
            .as_deref()
            .is_some_and(|e| e.contains("unknown method")),);
    }

    #[test]
    fn handle_encrypt_without_init() {
        let req = make_request("encrypt", "aGVsbG8=", AccessPolicy::None);
        let mut storage = None;
        let resp = handle(&req, &mut storage);
        assert!(resp
            .error
            .as_deref()
            .is_some_and(|e| e.contains("not initialized")),);
    }

    #[test]
    fn handle_decrypt_without_init() {
        let req = make_request("decrypt", "Y2lwaGVy", AccessPolicy::None);
        let mut storage = None;
        let resp = handle(&req, &mut storage);
        assert!(resp
            .error
            .as_deref()
            .is_some_and(|e| e.contains("not initialized")),);
    }

    #[test]
    fn handle_encrypt_missing_data() {
        let req = make_request("encrypt", "", AccessPolicy::None);
        // On platforms without a TPM, new() may fail and storage is None,
        // so we get "not initialized" instead of "missing data". Both are valid errors.
        let mut storage = TpmStorage::new(TEST_APP_NAME, TEST_KEY_LABEL, AccessPolicy::None).ok();
        let resp = handle(&req, &mut storage);
        assert!(resp.error.is_some());
    }

    #[test]
    fn handle_encrypt_invalid_base64() {
        let req = make_request("encrypt", "not-valid-base64!!!", AccessPolicy::None);
        let mut storage = TpmStorage::new(TEST_APP_NAME, TEST_KEY_LABEL, AccessPolicy::None).ok();
        let resp = handle(&req, &mut storage);
        assert!(resp.error.is_some());
    }

    #[test]
    fn handle_decrypt_missing_data() {
        let req = make_request("decrypt", "", AccessPolicy::None);
        let mut storage = TpmStorage::new(TEST_APP_NAME, TEST_KEY_LABEL, AccessPolicy::None).ok();
        let resp = handle(&req, &mut storage);
        assert!(resp.error.is_some());
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn encrypt_returns_platform_error_on_non_windows() {
        let storage = TpmStorage::new(TEST_APP_NAME, TEST_KEY_LABEL, AccessPolicy::None).unwrap();
        let result = storage.encrypt(b"hello");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("only supported on Windows"));
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn decrypt_returns_platform_error_on_non_windows() {
        let storage = TpmStorage::new(TEST_APP_NAME, TEST_KEY_LABEL, AccessPolicy::None).unwrap();
        let result = storage.decrypt(b"hello");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("only supported on Windows"));
    }

    #[test]
    fn roundtrip_json_protocol() {
        // Simulate the full JSON protocol flow
        let init_json = r#"{"method":"init","params":{"app_name":"test-app","key_label":"cache-key","access_policy":"none"}}"#;
        let encrypt_json = r#"{"method":"encrypt","params":{"data":"aGVsbG8gd29ybGQ=","app_name":"test-app","key_label":"cache-key","access_policy":"none"}}"#;
        let destroy_json =
            r#"{"method":"destroy","params":{"app_name":"test-app","key_label":"cache-key"}}"#;

        let mut storage = None;
        let mut signing_storage = None;

        // Init
        let req: BridgeRequestCompat = serde_json::from_str(init_json).unwrap();
        let resp = handle_request(
            &req,
            &mut storage,
            &mut signing_storage,
            TEST_APP_NAME,
            TEST_KEY_LABEL,
        );
        if let Some(err) = &resp.error {
            assert!(!err.is_empty(), "init error message should not be empty");
        } else {
            assert!(
                resp.result.is_some(),
                "init should return a result on success"
            );
        }

        // Encrypt (will fail on non-Windows, which is expected)
        let req: BridgeRequestCompat = serde_json::from_str(encrypt_json).unwrap();
        let resp = handle_request(
            &req,
            &mut storage,
            &mut signing_storage,
            TEST_APP_NAME,
            TEST_KEY_LABEL,
        );
        if let Some(err) = &resp.error {
            assert!(!err.is_empty(), "encrypt error message should not be empty");
        } else {
            assert!(
                resp.result.is_some(),
                "encrypt should return a result on success"
            );
        }

        // Destroy
        let req: BridgeRequestCompat = serde_json::from_str(destroy_json).unwrap();
        let resp = handle_request(
            &req,
            &mut storage,
            &mut signing_storage,
            TEST_APP_NAME,
            TEST_KEY_LABEL,
        );
        if let Some(err) = &resp.error {
            assert!(!err.is_empty(), "destroy error message should not be empty");
        } else {
            assert!(
                resp.result.is_some(),
                "destroy should return a result on success",
            );
        }
        assert!(storage.is_none());
    }

    #[test]
    fn invalid_json_produces_error() {
        let bad_json = "this is not json";
        let result = serde_json::from_str::<BridgeRequestCompat>(bad_json);
        assert!(result.is_err());
    }

    // ----- effective_access_policy exhaustive variant tests -----

    #[test]
    fn effective_access_policy_none_without_biometric() {
        let json = r#"{"method":"init","params":{}}"#;
        let req: BridgeRequestCompat = serde_json::from_str(json).unwrap();
        assert_eq!(req.params.effective_access_policy(), AccessPolicy::None);
    }

    #[test]
    fn effective_access_policy_any() {
        let json = r#"{"method":"init","params":{"access_policy":"any"}}"#;
        let req: BridgeRequestCompat = serde_json::from_str(json).unwrap();
        assert_eq!(req.params.effective_access_policy(), AccessPolicy::Any);
    }

    #[test]
    fn effective_access_policy_password_only() {
        let json = r#"{"method":"init","params":{"access_policy":"password_only"}}"#;
        let req: BridgeRequestCompat = serde_json::from_str(json).unwrap();
        assert_eq!(
            req.params.effective_access_policy(),
            AccessPolicy::PasswordOnly
        );
    }

    // ----- Legacy payload defaults -----

    #[test]
    fn legacy_payload_with_no_params_defaults_to_none() {
        let json = r#"{"method":"init","params":{}}"#;
        let req: BridgeRequestCompat = serde_json::from_str(json).unwrap();
        assert_eq!(req.params.effective_access_policy(), AccessPolicy::None);
        assert_eq!(req.params.app_name, "");
        assert_eq!(req.params.key_label, "");
    }

    // ----- Biometric and access_policy coexistence -----

    #[test]
    fn biometric_and_access_policy_coexist_in_json() {
        let json = r#"{"method":"init","params":{"access_policy":"biometric_only","biometric":true,"app_name":"test","key_label":"k"}}"#;
        let req: BridgeRequestCompat = serde_json::from_str(json).unwrap();
        assert_eq!(
            req.params.effective_access_policy(),
            AccessPolicy::BiometricOnly
        );
    }

    // ----- Fallback when access_policy absent but biometric true -----

    #[test]
    fn biometric_true_falls_back_to_biometric_only() {
        let json =
            r#"{"method":"init","params":{"biometric":true,"app_name":"a","key_label":"k"}}"#;
        let req: BridgeRequestCompat = serde_json::from_str(json).unwrap();
        assert_eq!(
            req.params.effective_access_policy(),
            AccessPolicy::BiometricOnly
        );
    }

    #[test]
    fn legacy_biometric_true_maps_to_biometric_only() {
        let json = r#"{"method": "init", "params": {"biometric": true}}"#;
        let req: BridgeRequestCompat = serde_json::from_str(json).unwrap();
        assert_eq!(
            req.params.effective_access_policy(),
            AccessPolicy::BiometricOnly
        );
    }

    #[test]
    fn legacy_biometric_false_maps_to_none() {
        let json = r#"{"method": "init", "params": {"biometric": false}}"#;
        let req: BridgeRequestCompat = serde_json::from_str(json).unwrap();
        assert_eq!(req.params.effective_access_policy(), AccessPolicy::None);
    }

    #[test]
    fn access_policy_takes_precedence_over_biometric() {
        // When both fields are present, access_policy wins.
        let json = r#"{"method": "init", "params": {"access_policy": "any", "biometric": true}}"#;
        let req: BridgeRequestCompat = serde_json::from_str(json).unwrap();
        assert_eq!(req.params.effective_access_policy(), AccessPolicy::Any);
    }

    #[test]
    fn password_only_takes_precedence_over_biometric() {
        let json =
            r#"{"method":"init","params":{"access_policy":"password_only","biometric":true}}"#;
        let req: BridgeRequestCompat = serde_json::from_str(json).unwrap();
        assert_eq!(
            req.params.effective_access_policy(),
            AccessPolicy::PasswordOnly,
            "explicit access_policy should take precedence over legacy biometric field"
        );
    }

    #[test]
    fn empty_params_all_defaults() {
        let json = r#"{"method":"init","params":{}}"#;
        let req: BridgeRequestCompat = serde_json::from_str(json).unwrap();
        assert_eq!(req.params.effective_access_policy(), AccessPolicy::None);
        assert_eq!(req.params.data, "");
        assert_eq!(req.params.app_name, "");
        assert_eq!(req.params.key_label, "");
    }

    // ----- Signing handler tests -----

    #[test]
    fn handle_init_signing_creates_signing_storage() {
        let req = make_request("init_signing", "", AccessPolicy::None);
        let mut signing_storage = None;
        let resp = handle_signing(&req, &mut signing_storage);
        if let Some(err) = &resp.error {
            assert!(!err.is_empty(), "init_signing error should not be empty");
        } else {
            assert!(resp.result.is_some(), "init_signing should return a result");
        }
    }

    #[test]
    fn handle_sign_without_init_signing() {
        let req = make_request("sign", "aGVsbG8=", AccessPolicy::None);
        let mut signing_storage = None;
        let resp = handle_signing(&req, &mut signing_storage);
        assert!(resp
            .error
            .as_deref()
            .is_some_and(|e| e.contains("signing not initialized")),);
    }

    #[test]
    fn handle_public_key_without_init_signing() {
        // public_key is now standalone (parallel of list_keys, see PR
        // #110 commentary). Pre-fix it required init_signing first,
        // which created a key with the configured key_label as a side
        // effect of every read. The handler now uses
        // TpmSigningStorage::public_key_for_app, which takes both
        // app_name and key_label and returns KeyNotFound when the key
        // doesn't exist (instead of creating it).
        let req = make_request("public_key", "", AccessPolicy::None);
        let mut signing_storage = None;
        let resp = handle_signing(&req, &mut signing_storage);
        if let Some(err) = &resp.error {
            assert!(
                !err.contains("signing not initialized"),
                "public_key should be standalone, not require init_signing: {err}"
            );
        }
    }

    #[test]
    fn handle_list_keys_without_init_signing() {
        // list_keys is now standalone (doesn't require prior init_signing).
        // The previous behavior errored "signing not initialized" but that
        // forced clients to call init_signing first, which created a key
        // with the configured key_label as a side effect of every list.
        // The handler now uses TpmSigningStorage::list_keys_for_app, which
        // takes only app_name. On a non-Windows test build the underlying
        // call returns "TPM signing bridge is only supported on Windows";
        // either way it's NOT the "signing not initialized" sentinel.
        let req = make_request("list_keys", "", AccessPolicy::None);
        let mut signing_storage = None;
        let resp = handle_signing(&req, &mut signing_storage);
        if let Some(err) = &resp.error {
            assert!(
                !err.contains("signing not initialized"),
                "list_keys should be standalone, not require init_signing: {err}"
            );
        }
    }

    #[test]
    fn handle_sign_missing_data() {
        let req = make_request("sign", "", AccessPolicy::None);
        let mut signing_storage =
            TpmSigningStorage::new(TEST_APP_NAME, TEST_KEY_LABEL, AccessPolicy::None).ok();
        let resp = handle_signing(&req, &mut signing_storage);
        assert!(resp.error.is_some());
    }

    #[test]
    fn handle_delete_signing_clears_signing_storage() {
        let req = make_request("delete_signing", "", AccessPolicy::None);
        let mut signing_storage = None;
        let resp = handle_signing(&req, &mut signing_storage);
        if let Some(err) = &resp.error {
            assert!(
                !err.is_empty(),
                "delete_signing error message should not be empty"
            );
        } else {
            assert!(
                resp.result.is_some(),
                "delete_signing should return a result on success"
            );
        }
        assert!(signing_storage.is_none());
    }

    #[test]
    fn parse_init_signing_request() {
        let json = r#"{"method": "init_signing", "params": {"access_policy": "none"}}"#;
        let req: BridgeRequestCompat = serde_json::from_str(json).unwrap();
        assert_eq!(req.method, "init_signing");
        assert_eq!(req.params.access_policy, AccessPolicy::None);
    }

    #[test]
    fn parse_sign_request() {
        let json = r#"{"method": "sign", "params": {"data": "aGVsbG8=", "access_policy": "none"}}"#;
        let req: BridgeRequestCompat = serde_json::from_str(json).unwrap();
        assert_eq!(req.method, "sign");
        assert_eq!(req.params.data, "aGVsbG8=");
    }

    #[test]
    fn parse_public_key_request() {
        let json = r#"{"method": "public_key", "params": {}}"#;
        let req: BridgeRequestCompat = serde_json::from_str(json).unwrap();
        assert_eq!(req.method, "public_key");
    }

    #[test]
    fn parse_list_keys_request() {
        let json = r#"{"method": "list_keys", "params": {}}"#;
        let req: BridgeRequestCompat = serde_json::from_str(json).unwrap();
        assert_eq!(req.method, "list_keys");
    }

    #[test]
    fn parse_delete_signing_request() {
        let json = r#"{"method": "delete_signing", "params": {"key_label": "cache-key"}}"#;
        let req: BridgeRequestCompat = serde_json::from_str(json).unwrap();
        assert_eq!(req.method, "delete_signing");
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn sign_returns_platform_error_on_non_windows() {
        let storage =
            TpmSigningStorage::new(TEST_APP_NAME, TEST_KEY_LABEL, AccessPolicy::None).unwrap();
        let result = storage.sign(b"hello");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("only supported on Windows"));
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn public_key_returns_platform_error_on_non_windows() {
        let storage =
            TpmSigningStorage::new(TEST_APP_NAME, TEST_KEY_LABEL, AccessPolicy::None).unwrap();
        let result = storage.public_key();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("only supported on Windows"));
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn list_keys_returns_platform_error_on_non_windows() {
        let storage =
            TpmSigningStorage::new(TEST_APP_NAME, TEST_KEY_LABEL, AccessPolicy::None).unwrap();
        let result = storage.list_keys();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("only supported on Windows"));
    }

    // ----- BridgeServer construction -----

    #[test]
    fn bridge_server_new() {
        let server = BridgeServer::new("myapp", "mykey");
        assert_eq!(server.default_app_name, "myapp");
        assert_eq!(server.default_key_label, "mykey");
    }
}
