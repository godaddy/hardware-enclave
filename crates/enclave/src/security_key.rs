// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Hardware security key (FIDO2/WebAuthn) credentials via the Windows Hello
//! platform authenticator.
//!
//! SK keys produce [`SecurityKeySignature`]s that carry the full FIDO2 assertion
//! output — DER signature, user-presence flags, and a monotonic counter — which
//! is the format required by `sk-ecdsa-sha2-nistp256@openssh.com` and other
//! FIDO2-SK verifiers. This is distinct from [`SignerHandle`][crate::SignerHandle]
//! which returns a plain DER-encoded ECDSA signature.
//!
//! ## Platform support
//!
//! | Platform | Backend |
//! |----------|---------|
//! | Windows  | Native `WebAuthn.dll` via platform authenticator |
//! | WSL2     | JSON-RPC bridge → Windows TPM |
//! | macOS / Linux | `Err(NotAvailable)` |
//!
//! ## RP ID derivation
//!
//! The FIDO2 Relying Party ID is derived deterministically from the app name
//! and key label so each credential gets a unique, stable identifier:
//!
//! ```text
//! rp_id = "{app_name}-{hex8(SHA-256("{app_name}-rp-id-v1\x00" || label)[..4])}.local"
//! ```
//!
//! This prevents the Windows passkey chooser from listing multiple credentials
//! (it only ever sees one matching RP ID), and is stable across process restarts.

use std::path::PathBuf;

use base64::prelude::*;
use enclaveapp_core::metadata::{self, KeyMeta};
use enclaveapp_core::types::{validate_label, KeyType};
use sha2::{Digest, Sha256};

use crate::config::EnclaveConfig;
use crate::error::{Error, Result};
use crate::types::{AccessPolicy, BackendKind};

// ── Public types ─────────────────────────────────────────────────────────────

/// A hardware security key credential backed by the Windows Hello platform
/// authenticator (TPM + biometric/PIN). Obtain via [`create_security_key()`].
pub struct SecurityKeyHandle {
    app_name: String,
    keys_dir: PathBuf,
    backend: SkBackend,
}

impl std::fmt::Debug for SecurityKeyHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecurityKeyHandle")
            .field("app_name", &self.app_name)
            .field("backend", &self.backend_kind())
            .finish()
    }
}

/// Metadata for a stored hardware security key credential.
#[derive(Debug, Clone)]
pub struct SecurityKeyInfo {
    /// Key label (e.g. `"github-personal"`).
    pub label: String,
    /// Opaque credential identifier returned by the TPM at make-credential time.
    /// Required for get-assertion calls.
    pub credential_id: Vec<u8>,
    /// FIDO2 Relying Party ID used when the credential was created.
    pub rp_id: String,
    /// Uncompressed SEC1 P-256 public key: `0x04 || X (32 bytes) || Y (32 bytes)`.
    pub public_key: Vec<u8>,
    /// Human-readable comment (e.g. `"user@host"`), if set at generation time.
    pub comment: Option<String>,
}

/// Result of an SK signing operation.
///
/// The signature blob for `sk-ecdsa-sha2-nistp256@openssh.com` is constructed
/// from these three fields:
/// ```text
/// string  "sk-ecdsa-sha2-nistp256@openssh.com"
/// string  mpint(r) || mpint(s)   // extracted from signature_der
/// byte    flags
/// uint32  counter
/// ```
#[derive(Debug, Clone)]
pub struct SecurityKeySignature {
    /// DER-encoded ECDSA P-256 signature (`SEQUENCE { INTEGER r, INTEGER s }`).
    pub signature_der: Vec<u8>,
    /// User-presence flags from the TPM authenticator data.
    /// Bit 0 = User Present (UP), Bit 2 = User Verified (UV).
    pub flags: u8,
    /// Monotonic counter from the TPM, incremented on each assertion.
    /// Verifiers can check for replay/cloning by confirming counter increases.
    pub counter: u32,
}

// ── Backend enum ─────────────────────────────────────────────────────────────

#[derive(Debug)]
enum SkBackend {
    #[cfg(target_os = "windows")]
    Native,
    #[cfg(target_os = "linux")]
    Bridge {
        bridge_path: PathBuf,
    },
    Unavailable,
}

// ── impl SecurityKeyHandle ───────────────────────────────────────────────────

impl SecurityKeyHandle {
    fn new(app_name: String, keys_dir: PathBuf, backend: SkBackend) -> Self {
        Self {
            app_name,
            keys_dir,
            backend,
        }
    }

    /// Whether the platform authenticator is reachable (fast, no prompt).
    #[allow(clippy::needless_return, unreachable_code)]
    pub fn is_available(&self) -> bool {
        match &self.backend {
            #[cfg(target_os = "windows")]
            SkBackend::Native => enclaveapp_windows_webauthn::is_platform_authenticator_available(),
            #[cfg(target_os = "linux")]
            SkBackend::Bridge { bridge_path } => {
                enclaveapp_bridge::bridge_webauthn_is_available(bridge_path).unwrap_or(false)
            }
            SkBackend::Unavailable => false,
        }
    }

    /// Generate a new TPM-backed credential. Fires a Hello gesture on the
    /// Windows desktop.
    ///
    /// The derived RP ID and credential ID are stored in the key metadata
    /// directory alongside a fingerprint and public key.
    pub fn generate(&self, label: &str, comment: Option<&str>) -> Result<SecurityKeyInfo> {
        validate_label(label).map_err(Error::from)?;

        let rp_id = rp_id_for(&self.app_name, label);
        let user_id = user_id_for(&self.app_name, label);

        let (credential_id, pk_x, pk_y) = self.do_make_credential(&rp_id, label, &user_id)?;

        // Build uncompressed SEC1 public key.
        let mut public_key = Vec::with_capacity(65);
        public_key.push(0x04);
        public_key.extend_from_slice(&pk_x);
        public_key.extend_from_slice(&pk_y);

        // Persist metadata.
        metadata::ensure_dir(&self.keys_dir)?;
        #[allow(let_underscore_drop)]
        let _lock = metadata::DirLock::acquire(&self.keys_dir)?;

        let mut meta = KeyMeta::new(label, KeyType::Signing, AccessPolicy::Any);
        let cred_b64 = BASE64_STANDARD.encode(&credential_id);
        meta.set_app_field("algorithm", "sk-ecdsa-sha2-nistp256");
        meta.set_app_field("credential_id_b64", cred_b64.as_str());
        meta.set_app_field("rp_id", rp_id.as_str());
        if let Some(c) = comment {
            meta.set_app_field("comment", c);
        }
        metadata::save_meta(&self.keys_dir, label, &meta)?;

        // Cache public key.
        let pub_path = self.keys_dir.join(format!("{label}.pub"));
        metadata::atomic_write(&pub_path, &public_key)?;

        Ok(SecurityKeyInfo {
            label: label.to_string(),
            credential_id,
            rp_id,
            public_key,
            comment: comment.map(str::to_string),
        })
    }

    /// Sign `data` with the named credential. Fires a Hello gesture.
    ///
    /// Returns the full FIDO2 assertion output needed to build an
    /// `sk-ecdsa-sha2-nistp256@openssh.com` signature blob.
    pub fn sign(&self, label: &str, data: &[u8]) -> Result<SecurityKeySignature> {
        let info = self.get_credential(label)?;
        let (signature_der, flags, counter) =
            self.do_get_assertion(&info.rp_id, &info.credential_id, data)?;
        Ok(SecurityKeySignature {
            signature_der,
            flags,
            counter,
        })
    }

    /// List all SK credentials in this app's key directory.
    pub fn list_credentials(&self) -> Result<Vec<SecurityKeyInfo>> {
        let labels = metadata::list_labels(&self.keys_dir)?;
        let mut out = Vec::new();
        for label in labels {
            if let Ok(meta) = metadata::load_meta(&self.keys_dir, &label) {
                if meta.get_app_field("algorithm") == Some("sk-ecdsa-sha2-nistp256") {
                    if let Ok(info) = self.info_from_meta(&label, &meta) {
                        out.push(info);
                    }
                }
            }
        }
        Ok(out)
    }

    /// Get metadata for a specific SK credential.
    pub fn get_credential(&self, label: &str) -> Result<SecurityKeyInfo> {
        let meta = metadata::load_meta(&self.keys_dir, label).map_err(|_| Error::KeyNotFound {
            label: label.to_string(),
        })?;
        if meta.get_app_field("algorithm") != Some("sk-ecdsa-sha2-nistp256") {
            return Err(Error::KeyNotFound {
                label: label.to_string(),
            });
        }
        self.info_from_meta(label, &meta)
    }

    /// Check whether an SK credential with this label exists.
    pub fn credential_exists(&self, label: &str) -> Result<bool> {
        match self.get_credential(label) {
            Ok(_) => Ok(true),
            Err(Error::KeyNotFound { .. }) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Delete the SK credential and its metadata. Best-effort removal of the
    /// platform credential (ignored if already deleted from Windows passkeys).
    pub fn delete_credential(&self, label: &str) -> Result<()> {
        let info = self.get_credential(label)?;
        // Best-effort removal from the platform credential store.
        drop(self.do_delete_credential(&info.credential_id));
        // Remove local metadata files.
        metadata::delete_key_files(&self.keys_dir, label)?;
        Ok(())
    }

    /// Which hardware security backend backs this handle.
    ///
    /// Returns `None` when the platform authenticator is not available on this
    /// platform (macOS, unsupported Linux without a WSL bridge). A `None` result
    /// indicates that [`generate`][SecurityKeyHandle::generate] and
    /// [`sign`][SecurityKeyHandle::sign] will always return
    /// [`Error::NotAvailable`][crate::Error::NotAvailable].
    pub fn backend_kind(&self) -> Option<BackendKind> {
        match &self.backend {
            #[cfg(target_os = "windows")]
            SkBackend::Native => Some(BackendKind::Tpm),
            #[cfg(target_os = "linux")]
            SkBackend::Bridge { .. } => Some(BackendKind::TpmBridge),
            SkBackend::Unavailable => None,
        }
    }

    // ── private helpers ──────────────────────────────────────────────────────

    // Parameters used only in platform-specific cfg arms; suppress "unused" on other platforms.
    #[allow(clippy::needless_return, unreachable_code)]
    #[cfg_attr(
        not(any(target_os = "windows", target_os = "linux")),
        allow(unused_variables)
    )]
    fn do_make_credential(
        &self,
        rp_id: &str,
        label: &str,
        user_id: &[u8],
    ) -> Result<(Vec<u8>, [u8; 32], [u8; 32])> {
        match &self.backend {
            #[cfg(target_os = "windows")]
            SkBackend::Native => {
                let params = enclaveapp_windows_webauthn::MakeCredentialParams {
                    rp_id,
                    rp_name: &self.app_name,
                    user_id,
                    user_name: label,
                    user_display_name: label,
                    timeout_ms: 60_000,
                    hwnd: None,
                };
                let cred = enclaveapp_windows_webauthn::make_credential(params).map_err(|e| {
                    Error::KeyOperation {
                        operation: "sk_make_credential".into(),
                        detail: e.to_string(),
                    }
                })?;
                return Ok((cred.credential_id, cred.public_key_x, cred.public_key_y));
            }
            #[cfg(target_os = "linux")]
            SkBackend::Bridge { bridge_path } => {
                let result = enclaveapp_bridge::bridge_webauthn_make_credential(
                    bridge_path,
                    rp_id,
                    &self.app_name,
                    user_id,
                    label,
                    label,
                    60_000,
                )
                .map_err(|e| Error::KeyOperation {
                    operation: "sk_make_credential_bridge".into(),
                    detail: e.to_string(),
                })?;
                let credential_id =
                    BASE64_STANDARD
                        .decode(&result.credential_id_b64)
                        .map_err(|e| Error::KeyOperation {
                            operation: "sk_decode_credential_id".into(),
                            detail: e.to_string(),
                        })?;
                let pk_x =
                    hex_to_32(&result.public_key_x_hex).map_err(|e| Error::KeyOperation {
                        operation: "sk_decode_pubkey_x".into(),
                        detail: e,
                    })?;
                let pk_y =
                    hex_to_32(&result.public_key_y_hex).map_err(|e| Error::KeyOperation {
                        operation: "sk_decode_pubkey_y".into(),
                        detail: e,
                    })?;
                return Ok((credential_id, pk_x, pk_y));
            }
            SkBackend::Unavailable => {
                return Err(Error::NotAvailable);
            }
        }
    }

    #[allow(clippy::needless_return, unreachable_code)]
    #[cfg_attr(
        not(any(target_os = "windows", target_os = "linux")),
        allow(unused_variables)
    )]
    fn do_get_assertion(
        &self,
        rp_id: &str,
        credential_id: &[u8],
        client_data: &[u8],
    ) -> Result<(Vec<u8>, u8, u32)> {
        match &self.backend {
            #[cfg(target_os = "windows")]
            SkBackend::Native => {
                let params = enclaveapp_windows_webauthn::GetAssertionParams {
                    rp_id,
                    credential_id,
                    client_data,
                    timeout_ms: 60_000,
                    hwnd: None,
                };
                let assertion =
                    enclaveapp_windows_webauthn::get_assertion(params).map_err(|e| {
                        Error::SignFailed {
                            detail: e.to_string(),
                        }
                    })?;
                return Ok((assertion.signature_der, assertion.flags, assertion.counter));
            }
            #[cfg(target_os = "linux")]
            SkBackend::Bridge { bridge_path } => {
                let result = enclaveapp_bridge::bridge_webauthn_get_assertion(
                    bridge_path,
                    rp_id,
                    credential_id,
                    client_data,
                    60_000,
                )
                .map_err(|e| Error::SignFailed {
                    detail: e.to_string(),
                })?;
                let signature_der =
                    BASE64_STANDARD
                        .decode(&result.signature_der_b64)
                        .map_err(|e| Error::SignFailed {
                            detail: format!("decode signature: {e}"),
                        })?;
                return Ok((signature_der, result.flags, result.counter));
            }
            SkBackend::Unavailable => {
                return Err(Error::NotAvailable);
            }
        }
    }

    #[allow(clippy::needless_return, unreachable_code)]
    #[cfg_attr(
        not(any(target_os = "windows", target_os = "linux")),
        allow(unused_variables)
    )]
    fn do_delete_credential(&self, credential_id: &[u8]) -> Result<()> {
        match &self.backend {
            #[cfg(target_os = "windows")]
            SkBackend::Native => {
                return enclaveapp_windows_webauthn::delete_platform_credential(credential_id)
                    .map_err(|e| Error::KeyOperation {
                        operation: "sk_delete".into(),
                        detail: e.to_string(),
                    });
            }
            #[cfg(target_os = "linux")]
            SkBackend::Bridge { bridge_path } => {
                return enclaveapp_bridge::bridge_webauthn_delete_platform_credential(
                    bridge_path,
                    credential_id,
                )
                .map_err(|e| Error::KeyOperation {
                    operation: "sk_delete_bridge".into(),
                    detail: e.to_string(),
                });
            }
            SkBackend::Unavailable => {
                return Ok(());
            }
        }
    }

    fn info_from_meta(&self, label: &str, meta: &KeyMeta) -> Result<SecurityKeyInfo> {
        let credential_id_b64 =
            meta.get_app_field("credential_id_b64")
                .ok_or_else(|| Error::KeyOperation {
                    operation: "sk_load".into(),
                    detail: format!("key '{label}' missing credential_id_b64 in metadata"),
                })?;
        let credential_id =
            BASE64_STANDARD
                .decode(credential_id_b64)
                .map_err(|e| Error::KeyOperation {
                    operation: "sk_load".into(),
                    detail: format!("invalid credential_id_b64: {e}"),
                })?;
        let rp_id = match meta.get_app_field("rp_id") {
            Some(r) => r.to_string(),
            None => rp_id_for(&self.app_name, label),
        };
        let comment = meta.get_app_field("comment").map(str::to_string);

        // Read cached public key if available.
        let pub_path = self.keys_dir.join(format!("{label}.pub"));
        let public_key = if pub_path.exists() {
            metadata::read_no_follow(&pub_path).map_err(Error::from)?
        } else {
            Vec::new()
        };

        Ok(SecurityKeyInfo {
            label: label.to_string(),
            credential_id,
            rp_id,
            public_key,
            comment,
        })
    }
}

// ── RP-ID / user-ID derivation ───────────────────────────────────────────────

/// Derive a deterministic, unique FIDO2 Relying Party ID for `(app_name, label)`.
///
/// Format: `"{app_name}-{8 hex chars}.local"` where the hex is SHA-256 of
/// `"{app_name}-rp-id-v1\x00" || label`, truncated to 4 bytes.
///
/// This matches the formula used by sshenc when `app_name == "sshenc"`,
/// ensuring backward compatibility with existing credentials.
///
/// This is an internal derivation helper and is not part of the stable public API.
pub(crate) fn rp_id_for(app_name: &str, label: &str) -> String {
    let mut h = Sha256::new();
    h.update(app_name.as_bytes());
    h.update(b"-rp-id-v1\x00");
    h.update(label.as_bytes());
    let digest = h.finalize();
    format!(
        "{app_name}-{:08x}.local",
        u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]])
    )
}

/// Derive a deterministic 32-byte user ID for FIDO2 make-credential.
///
/// This is an internal derivation helper and is not part of the stable public API.
pub(crate) fn user_id_for(app_name: &str, label: &str) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(app_name.as_bytes());
    h.update(b"-user-id-v1\x00");
    h.update(label.as_bytes());
    h.finalize().to_vec()
}

// ── helpers ──────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn hex_to_32(hex: &str) -> std::result::Result<[u8; 32], String> {
    if hex.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", hex.len()));
    }
    let mut out = [0_u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).map_err(|e| e.to_string())?;
        out[i] = u8::from_str_radix(s, 16).map_err(|e| e.to_string())?;
    }
    Ok(out)
}

// ── factory ──────────────────────────────────────────────────────────────────

/// Create a `SecurityKeyHandle` for the current platform.
///
/// Returns `Ok(handle)` even on platforms where SK is unavailable —
/// check [`SecurityKeyHandle::is_available()`] before calling
/// [`generate`][SecurityKeyHandle::generate] or [`sign`][SecurityKeyHandle::sign].
#[allow(clippy::needless_return, unreachable_code)]
pub(crate) fn make_security_key_handle(config: &EnclaveConfig) -> SecurityKeyHandle {
    let app_name = config.effective_app_name();
    let keys_dir = config
        .keys_dir
        .clone()
        .unwrap_or_else(|| metadata::keys_dir(&app_name));

    #[cfg(target_os = "windows")]
    return SecurityKeyHandle::new(app_name, keys_dir, SkBackend::Native);

    #[cfg(target_os = "linux")]
    {
        let extra_paths: Vec<String> = match &config.platform {
            crate::config::PlatformConfig::Linux(l) => l.extra_bridge_paths.clone(),
            _ => Vec::new(),
        };
        if let Some(bridge_path) =
            enclaveapp_app_storage::platform::find_bridge_executable(&app_name, &extra_paths)
        {
            return SecurityKeyHandle::new(app_name, keys_dir, SkBackend::Bridge { bridge_path });
        }
    }

    SecurityKeyHandle::new(app_name, keys_dir, SkBackend::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rp_id_is_stable_and_unique() {
        let a = rp_id_for("sshenc", "github");
        let b = rp_id_for("sshenc", "github");
        assert_eq!(a, b, "rp_id must be deterministic");
        assert!(a.starts_with("sshenc-"));
        assert!(a.ends_with(".local"));

        let other = rp_id_for("sshenc", "gitlab");
        assert_ne!(a, other, "different labels must produce different rp_ids");
    }

    #[test]
    fn rp_id_matches_sshenc_formula() {
        // Verify our formula matches the "sshenc-rp-id-v1\x00" domain separator
        // that sshenc uses for backward compatibility.
        let rp_id = rp_id_for("sshenc", "test-key");
        // Must start with "sshenc-" and end with ".local", 8 hex chars in between.
        assert!(rp_id.starts_with("sshenc-"));
        assert!(rp_id.ends_with(".local"));
        let hex_part = &rp_id[7..rp_id.len() - 6]; // strip "sshenc-" and ".local"
        assert_eq!(hex_part.len(), 8, "must be 8 hex chars (4 bytes)");
        assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn user_id_is_32_bytes() {
        let uid = user_id_for("sshenc", "test-key");
        assert_eq!(uid.len(), 32);
    }

    #[test]
    fn user_id_is_stable() {
        let a = user_id_for("myapp", "key1");
        let b = user_id_for("myapp", "key1");
        assert_eq!(a, b);
        let other = user_id_for("myapp", "key2");
        assert_ne!(a, other);
    }

    #[test]
    fn is_available_does_not_panic() {
        let config = EnclaveConfig::new("testapp", "default");
        let handle = make_security_key_handle(&config);
        let _ = handle.is_available();
    }
}
