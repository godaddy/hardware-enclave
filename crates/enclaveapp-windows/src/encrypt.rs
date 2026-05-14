// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! `TpmEncryptor` — ECDH P-256 / ECIES encryption backend using the Windows TPM.

// This module wraps BCrypt/NCrypt C APIs which require unsafe FFI calls.
// The Windows crate's type conversions trigger trivial_casts and ptr_as_ptr
// for API-required pointer casts that cannot be simplified.
#![allow(
    unsafe_code,
    trivial_casts,
    clippy::ptr_as_ptr,
    unused_qualifications,
    let_underscore_drop
)]
//!
//! ## ECIES Wire Format
//!
//! ```text
//! [0x01] [65-byte ephemeral pubkey] [12-byte nonce] [ciphertext] [16-byte GCM tag]
//! ```
//!
//! ## Encryption flow
//!
//! 1. Load the stored public key for the label.
//! 2. Generate an ephemeral ECDH P-256 key pair via `BCryptGenerateKeyPair`.
//! 3. Import the stored public key as a BCrypt key.
//! 4. `BCryptSecretAgreement` between the ephemeral private key and the stored
//!    public key.
//! 5. `BCryptDeriveKey` (HASH KDF with SHA-256) to produce a 32-byte AES key.
//! 6. AES-256-GCM encrypt with a random 12-byte nonce.
//! 7. Assemble the output.
//!
//! Decryption uses `NCryptSecretAgreement` (the TPM private key never leaves
//! the hardware) and otherwise mirrors the process.

use crate::convert::{eccpublic_blob_to_sec1, sec1_to_eccpublic_blob};
use crate::key;
use crate::provider;
use crate::state;
use enclaveapp_core::metadata;
use enclaveapp_core::traits::{EnclaveEncryptor, EnclaveKeyManager};
use enclaveapp_core::types::validate_label;
use enclaveapp_core::{AccessPolicy, Error, KeyType, Result};
use std::ffi::c_void;
use std::ptr;
use windows::core::PCWSTR;
use windows::Win32::Security::Cryptography::*;

/// ECDH P-256 algorithm identifier for CNG.
const ECDH_P256_ALGORITHM: &str = "ECDH_P256";

/// BCRYPT_ECDH_PUBLIC_P256_MAGIC (`ECK1`).
const BCRYPT_ECDH_PUBLIC_P256_MAGIC: u32 = 0x314B_4345;

/// Version byte prefixed to the ECIES ciphertext envelope.
const ECIES_VERSION: u8 = 0x01;

/// AES-GCM nonce size in bytes.
const GCM_NONCE_SIZE: usize = 12;
/// AES-GCM authentication tag size in bytes.
const GCM_TAG_SIZE: usize = 16;

/// Minimum ciphertext length: version(1) + ephemeral pub(65) + nonce(12) + tag(16).
const MIN_CIPHERTEXT_LEN: usize = 1 + 65 + GCM_NONCE_SIZE + GCM_TAG_SIZE;

/// Windows TPM-backed ECDH P-256 encryptor (ECIES).
#[derive(Debug)]
pub struct TpmEncryptor {
    app_name: String,
    keys_dir_override: Option<std::path::PathBuf>,
    /// When `Some`, this encryptor surfaces a Windows Hello biometric/PIN
    /// prompt before each `decrypt` call (skipping it when the cache is
    /// fresh). The key is created without `NCRYPT_UI_PROTECT_KEY_FLAG` so
    /// the legacy CryptUI password dialog never fires.
    ///
    /// **Threat-model trade-off**: the gate is enforced at the app level
    /// via the `Verified` boolean returned by `UserConsentVerifier`. A
    /// same-UID attacker with code execution inside the host process can
    /// hook the result and bypass the gate. See [`crate::hello_gate`]
    /// for the full documentation.
    hello_gate: Option<std::sync::Arc<crate::hello_gate::HelloGate>>,
    /// Cache TTL for the Hello gate. `Duration::ZERO` disables caching
    /// (prompt on every call). Ignored when `hello_gate` is `None`.
    hello_cache_ttl: std::time::Duration,
    /// Message shown in the Hello prompt. Defaults to a generic string;
    /// callers can override via [`TpmEncryptor::with_hello_prompt`].
    hello_prompt: String,
}

impl TpmEncryptor {
    /// Create a new encryptor for the given application.
    pub fn new(app_name: &str) -> Self {
        TpmEncryptor {
            app_name: app_name.to_string(),
            keys_dir_override: None,
            hello_gate: None,
            hello_cache_ttl: std::time::Duration::ZERO,
            hello_prompt: default_hello_prompt(app_name),
        }
    }

    /// Create an encryptor with a custom keys directory path.
    pub fn with_keys_dir(app_name: &str, keys_dir: std::path::PathBuf) -> Self {
        TpmEncryptor {
            app_name: app_name.to_string(),
            keys_dir_override: Some(keys_dir),
            hello_gate: None,
            hello_cache_ttl: std::time::Duration::ZERO,
            hello_prompt: default_hello_prompt(app_name),
        }
    }

    /// Enable the Windows Hello soft-gate on this encryptor. When set,
    /// keys are created without `NCRYPT_UI_PROTECT_KEY_FLAG` (so the
    /// CryptUI password dialog never fires) and every `decrypt` call is
    /// gated by [`crate::hello_gate::HelloGate::ensure_verified`] with
    /// the supplied `cache_ttl`. See [`crate::hello_gate`] for the
    /// documented threat-model trade-off.
    #[must_use]
    pub fn with_hello_gate(
        mut self,
        gate: std::sync::Arc<crate::hello_gate::HelloGate>,
        cache_ttl: std::time::Duration,
    ) -> Self {
        self.hello_gate = Some(gate);
        self.hello_cache_ttl = cache_ttl;
        self
    }

    /// Override the message shown in the Hello prompt. No effect when
    /// the Hello gate is not enabled.
    #[must_use]
    pub fn with_hello_prompt(mut self, prompt: impl Into<String>) -> Self {
        self.hello_prompt = prompt.into();
        self
    }

    /// True if the Hello soft-gate is enabled on this encryptor.
    pub fn hello_gate_enabled(&self) -> bool {
        self.hello_gate.is_some()
    }

    fn keys_dir(&self) -> std::path::PathBuf {
        self.keys_dir_override
            .clone()
            .unwrap_or_else(|| metadata::keys_dir(&self.app_name))
    }

    /// If the Hello gate is enabled, ensure the user has been verified
    /// within `hello_cache_ttl`. Returns `Ok(())` immediately when the
    /// gate is not enabled.
    fn ensure_hello_verified(&self, label: &str) -> Result<()> {
        let Some(gate) = self.hello_gate.as_ref() else {
            return Ok(());
        };
        let scope = format!("{}:{}", self.app_name, label);
        gate.ensure_verified(&scope, &self.hello_prompt, self.hello_cache_ttl)
    }
}

fn default_hello_prompt(app_name: &str) -> String {
    format!("Unlock {app_name} credentials")
}

impl EnclaveKeyManager for TpmEncryptor {
    fn generate(&self, label: &str, key_type: KeyType, policy: AccessPolicy) -> Result<Vec<u8>> {
        validate_label(label)?;
        if key_type != KeyType::Encryption {
            return Err(Error::KeyOperation {
                operation: "generate".into(),
                detail: "TpmEncryptor only supports encryption keys".into(),
            });
        }

        let dir = self.keys_dir();
        let provider = provider::open_provider()?;
        let state = state::KeyMaterialState::acquire(&dir)?;
        let silent = self.hello_gate_enabled();
        state.ensure_label_available(label, || {
            let open_result = if silent {
                key::open_key_silent(&provider, &self.app_name, label)
            } else {
                key::open_key(&provider, &self.app_name, label)
            };
            match open_result {
                Ok(_key) => Ok(state::AuthoritativeKeyState::Present),
                Err(Error::KeyNotFound { .. }) => Ok(state::AuthoritativeKeyState::Missing),
                Err(error) => Err(error),
            }
        })?;
        // When the Hello soft-gate is enabled, use the silent KSP path:
        // the KSP must not surface its own legacy CryptUI dialog --
        // we'll surface Hello via UserConsentVerifier ourselves. If
        // the KSP would need UI it returns NTE_SILENT_CONTEXT, which
        // we let bubble up as a hard failure rather than fall back
        // to a surprise password prompt.
        let (_key_handle, pub_key) = if silent {
            key::create_key_silent(
                &provider,
                &self.app_name,
                label,
                ECDH_P256_ALGORITHM,
                policy,
            )?
        } else {
            key::create_key(
                &provider,
                &self.app_name,
                label,
                ECDH_P256_ALGORITHM,
                policy,
            )?
        };

        state.persist_generated_key(label, key_type, policy, &pub_key, || {
            key::delete_key(&self.app_name, label)
        })?;

        // Layer the HMAC sidecar on top of the persisted meta.
        // Best-effort: failures here don't fail the keygen.
        if let Ok(Some(hmac_key)) = crate::meta_hmac::load_or_create(&self.app_name) {
            let meta = enclaveapp_core::KeyMeta::new(label, key_type, policy);
            if let Err(e) = enclaveapp_core::metadata::save_meta_with_hmac(
                state.dir(),
                label,
                &meta,
                hmac_key.as_slice(),
            ) {
                tracing::warn!(
                    label = label,
                    error = %e,
                    "post-persist meta-HMAC sidecar write failed; \
                     next load's auto-migrate will retry"
                );
            }
        }

        Ok(pub_key)
    }

    fn public_key(&self, label: &str) -> Result<Vec<u8>> {
        validate_label(label)?;
        let dir = self.keys_dir();
        let state = state::KeyMaterialState::acquire(&dir)?;
        let provider = provider::open_provider()?;
        let key_handle = key::open_key(&provider, &self.app_name, label)?;
        let pub_key = crate::export::export_public_key(&key_handle)?;
        metadata::sync_pub_key(state.dir(), label, &pub_key)
    }

    fn list_keys(&self) -> Result<Vec<String>> {
        let provider = provider::open_provider()?;
        key::enumerate_keys(&provider, &self.app_name)
    }

    fn delete_key(&self, label: &str) -> Result<()> {
        validate_label(label)?;
        let dir = self.keys_dir();
        let state = state::KeyMaterialState::acquire(&dir)?;
        state.reconcile_deleted_key(label, || match key::delete_key(&self.app_name, label) {
            Ok(()) => Ok(state::AuthoritativeKeyState::Present),
            Err(Error::KeyNotFound { .. }) => Ok(state::AuthoritativeKeyState::Missing),
            Err(error) => Err(error),
        })
    }

    fn is_available(&self) -> bool {
        provider::is_available()
    }
}

impl EnclaveEncryptor for TpmEncryptor {
    fn encrypt(&self, label: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        validate_label(label)?;

        // 1. Load the stored public key (SEC1 uncompressed).
        let stored_pub = self.public_key(label)?;

        unsafe { ecies_encrypt(&stored_pub, plaintext) }
    }

    fn decrypt(&self, label: &str, ciphertext: &[u8]) -> Result<Vec<u8>> {
        validate_label(label)?;

        if ciphertext.len() < MIN_CIPHERTEXT_LEN {
            return Err(Error::DecryptFailed {
                detail: format!(
                    "ciphertext too short: {} < {MIN_CIPHERTEXT_LEN}",
                    ciphertext.len()
                ),
            });
        }
        if ciphertext[0] != ECIES_VERSION {
            return Err(Error::DecryptFailed {
                detail: format!("unsupported ECIES version: 0x{:02x}", ciphertext[0]),
            });
        }

        let ephemeral_pub = &ciphertext[1..66];
        let nonce = &ciphertext[66..66 + GCM_NONCE_SIZE];
        let ct_and_tag = &ciphertext[66 + GCM_NONCE_SIZE..];
        if ct_and_tag.len() < GCM_TAG_SIZE {
            return Err(Error::DecryptFailed {
                detail: "ciphertext too short for tag".into(),
            });
        }
        let ct = &ct_and_tag[..ct_and_tag.len() - GCM_TAG_SIZE];
        let tag = &ct_and_tag[ct_and_tag.len() - GCM_TAG_SIZE..];

        let provider = provider::open_provider()?;
        // When the Hello soft-gate is configured, open the key with
        // NCRYPT_SILENT_FLAG so the KSP cannot surface a legacy
        // dialog if its policy state is somehow inconsistent with our
        // expectation. The Hello prompt fires below via
        // `ensure_hello_verified` -- that is the only UI we permit.
        let key_handle = if self.hello_gate.is_some() {
            key::open_key_silent(&provider, &self.app_name, label)?
        } else {
            key::open_key(&provider, &self.app_name, label)?
        };

        // Re-verify the key's NCRYPT_UI_POLICY matches metadata's
        // AccessPolicy before decrypt. Catches an attacker-planted
        // key that has the expected CNG name but a different (or
        // missing) UI flag -- without this check the library might
        // decrypt through a key that has no hardware-enforced UI
        // gate.
        //
        // When the Hello soft-gate is enabled, the key is intentionally
        // created with no `NCRYPT_UI_PROTECT_KEY_FLAG` (so the legacy
        // CryptUI password dialog never fires) and the on-disk
        // AccessPolicy is recorded as `None`. The application-level
        // [`HelloGate`] enforces user presence instead — see the
        // threat-model documentation in [`crate::hello_gate`] and on
        // [`enclaveapp_app_storage::StorageConfig::prefer_windows_hello_ux`].
        let dir = self.keys_dir();
        let expected_policy = match metadata::load_meta(&dir, label) {
            Ok(meta) => meta.access_policy,
            Err(Error::KeyNotFound { .. }) => AccessPolicy::None,
            Err(err) => return Err(err),
        };
        crate::ui_policy::verify_ui_policy_matches(&key_handle, expected_policy)?;

        // Hello soft-gate: fire the biometric/PIN prompt (or use the
        // cached verification) before invoking the TPM private-key
        // operation. No-op when the gate is not configured.
        self.ensure_hello_verified(label)?;

        unsafe { ecies_decrypt(&key_handle, ephemeral_pub, nonce, ct, tag) }
    }
}

// ─── Low-level ECIES helpers (unsafe, Windows-only) ─────────────

/// Encode a Rust `&str` as a null-terminated UTF-16 vector.
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// ECIES encrypt: ephemeral ECDH + AES-256-GCM.
///
/// # Safety
/// Calls raw Win32 BCrypt APIs.
unsafe fn ecies_encrypt(stored_pub_sec1: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let ecdh_alg_name = to_wide(ECDH_P256_ALGORITHM);
    let eccpub_blob_type = to_wide("ECCPUBLICBLOB");

    // Open BCrypt ECDH provider.
    let mut ecdh_alg = BCRYPT_ALG_HANDLE::default();
    BCryptOpenAlgorithmProvider(
        &mut ecdh_alg,
        PCWSTR(ecdh_alg_name.as_ptr()),
        None,
        Default::default(),
    )
    .ok()
    .map_err(|e| Error::EncryptFailed {
        detail: format!("BCryptOpenAlgorithmProvider(ECDH): {e}"),
    })?;

    // Generate ephemeral key pair.
    let mut ephemeral_key = BCRYPT_KEY_HANDLE::default();
    BCryptGenerateKeyPair(ecdh_alg, &mut ephemeral_key, 256, 0)
        .ok()
        .map_err(|e| {
            let _ = BCryptCloseAlgorithmProvider(ecdh_alg, 0).ok();
            Error::EncryptFailed {
                detail: format!("BCryptGenerateKeyPair: {e}"),
            }
        })?;
    BCryptFinalizeKeyPair(ephemeral_key, 0).ok().map_err(|e| {
        let _ = BCryptDestroyKey(ephemeral_key).ok();
        let _ = BCryptCloseAlgorithmProvider(ecdh_alg, 0).ok();
        Error::EncryptFailed {
            detail: format!("BCryptFinalizeKeyPair: {e}"),
        }
    })?;

    // Export ephemeral public key as SEC1 for the output envelope.
    let eph_pub_sec1 = {
        let mut sz: u32 = 0;
        BCryptExportKey(
            ephemeral_key,
            BCRYPT_KEY_HANDLE::default(),
            PCWSTR(eccpub_blob_type.as_ptr()),
            None,
            &mut sz,
            0,
        )
        .ok()
        .map_err(|e| Error::EncryptFailed {
            detail: format!("BCryptExportKey eph size: {e}"),
        })?;
        let mut blob = vec![0_u8; sz as usize];
        BCryptExportKey(
            ephemeral_key,
            BCRYPT_KEY_HANDLE::default(),
            PCWSTR(eccpub_blob_type.as_ptr()),
            Some(&mut blob),
            &mut sz,
            0,
        )
        .ok()
        .map_err(|e| Error::EncryptFailed {
            detail: format!("BCryptExportKey eph: {e}"),
        })?;
        blob.truncate(sz as usize);
        eccpublic_blob_to_sec1(&blob)?
    };

    // Import stored public key into BCrypt.
    let stored_blob = sec1_to_eccpublic_blob(stored_pub_sec1, BCRYPT_ECDH_PUBLIC_P256_MAGIC)?;
    let mut stored_key = BCRYPT_KEY_HANDLE::default();
    BCryptImportKeyPair(
        ecdh_alg,
        BCRYPT_KEY_HANDLE::default(),
        PCWSTR(eccpub_blob_type.as_ptr()),
        &mut stored_key,
        &stored_blob,
        0,
    )
    .ok()
    .map_err(|e| Error::EncryptFailed {
        detail: format!("BCryptImportKeyPair: {e}"),
    })?;

    // ECDH: ephemeral private + stored public → shared secret.
    let mut secret = BCRYPT_SECRET_HANDLE::default();
    BCryptSecretAgreement(ephemeral_key, stored_key, &mut secret, 0)
        .ok()
        .map_err(|e| Error::EncryptFailed {
            detail: format!("BCryptSecretAgreement: {e}"),
        })?;

    // Derive 32-byte AES key via HASH KDF (SHA-256).
    // We must explicitly specify SHA-256; the HASH KDF defaults to SHA-1,
    // which produces only 20 bytes — too short for AES-256-GCM.
    let kdf_name = to_wide("HASH");
    let mut sha256_alg = to_wide("SHA256");
    let mut kdf_buffer = BCryptBuffer {
        cbBuffer: (sha256_alg.len() * std::mem::size_of::<u16>()) as u32,
        BufferType: KDF_HASH_ALGORITHM,
        pvBuffer: sha256_alg.as_mut_ptr() as *mut c_void,
    };
    let kdf_params = BCryptBufferDesc {
        ulVersion: BCRYPTBUFFER_VERSION,
        cBuffers: 1,
        pBuffers: &mut kdf_buffer,
    };
    let mut derived_key = vec![0_u8; 32];
    let mut derived_len: u32 = 0;
    BCryptDeriveKey(
        secret,
        PCWSTR(kdf_name.as_ptr()),
        Some(&kdf_params),
        Some(&mut derived_key),
        &mut derived_len,
        0,
    )
    .ok()
    .map_err(|e| Error::EncryptFailed {
        detail: format!("BCryptDeriveKey: {e}"),
    })?;
    derived_key.truncate(derived_len as usize);

    // Cleanup ECDH handles.
    let _ = BCryptDestroySecret(secret).ok();
    let _ = BCryptDestroyKey(stored_key).ok();
    let _ = BCryptDestroyKey(ephemeral_key).ok();
    let _ = BCryptCloseAlgorithmProvider(ecdh_alg, 0).ok();

    // AES-256-GCM encrypt.
    let (nonce, tag, ct) = aes_gcm_encrypt(&derived_key, plaintext)?;

    // Assemble: [version] [ephemeral pub] [nonce] [ciphertext] [tag]
    let mut output = Vec::with_capacity(1 + 65 + GCM_NONCE_SIZE + ct.len() + GCM_TAG_SIZE);
    output.push(ECIES_VERSION);
    output.extend_from_slice(&eph_pub_sec1);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ct);
    output.extend_from_slice(&tag);
    Ok(output)
}

/// ECIES decrypt using an NCrypt TPM key handle.
///
/// # Safety
/// Calls raw Win32 BCrypt/NCrypt APIs.
unsafe fn ecies_decrypt(
    tpm_key: &provider::NcryptHandle,
    ephemeral_pub_sec1: &[u8],
    nonce: &[u8],
    ct: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>> {
    let eccpub_blob_type = to_wide("ECCPUBLICBLOB");

    // Import ephemeral public key via the Platform Crypto Provider — the
    // same provider that holds the TPM private key. NCryptSecretAgreement
    // requires both handles to come from the same provider.
    let platform_prov = provider::open_provider()?;

    let eph_blob = sec1_to_eccpublic_blob(ephemeral_pub_sec1, BCRYPT_ECDH_PUBLIC_P256_MAGIC)?;
    let mut eph_key = NCRYPT_KEY_HANDLE::default();
    NCryptImportKey(
        platform_prov.as_prov(),
        NCRYPT_KEY_HANDLE::default(),
        PCWSTR(eccpub_blob_type.as_ptr()),
        None,
        &mut eph_key,
        &eph_blob,
        NCRYPT_FLAGS::default(),
    )
    .map_err(|e| Error::DecryptFailed {
        detail: format!("NCryptImportKey(eph): {e}"),
    })?;

    // NCryptSecretAgreement: TPM private key + ephemeral public key.
    let mut secret = NCRYPT_SECRET_HANDLE::default();
    NCryptSecretAgreement(
        tpm_key.as_key(),
        eph_key,
        &mut secret,
        NCRYPT_FLAGS::default(),
    )
    .map_err(|e| Error::DecryptFailed {
        detail: format!("NCryptSecretAgreement: {e}"),
    })?;

    // Derive 32-byte AES key via HASH KDF (SHA-256).
    // We must explicitly specify SHA-256; the HASH KDF defaults to SHA-1,
    // which produces only 20 bytes — too short for AES-256-GCM.
    let kdf_name = to_wide("HASH");
    let mut sha256_alg = to_wide("SHA256");
    let mut kdf_buffer = BCryptBuffer {
        cbBuffer: (sha256_alg.len() * std::mem::size_of::<u16>()) as u32,
        BufferType: KDF_HASH_ALGORITHM,
        pvBuffer: sha256_alg.as_mut_ptr() as *mut c_void,
    };
    let kdf_params = BCryptBufferDesc {
        ulVersion: BCRYPTBUFFER_VERSION,
        cBuffers: 1,
        pBuffers: &mut kdf_buffer,
    };
    let mut derived_key = vec![0_u8; 32];
    let mut derived_len: u32 = 0;
    NCryptDeriveKey(
        secret,
        PCWSTR(kdf_name.as_ptr()),
        Some(&kdf_params),
        Some(&mut derived_key),
        &mut derived_len,
        0_u32,
    )
    .map_err(|e| Error::DecryptFailed {
        detail: format!("NCryptDeriveKey: {e}"),
    })?;
    derived_key.truncate(derived_len as usize);

    drop(NCryptFreeObject(NCRYPT_HANDLE(secret.0)));
    drop(NCryptFreeObject(NCRYPT_HANDLE(eph_key.0)));
    // platform_prov is freed by NcryptHandle Drop

    // AES-256-GCM decrypt.
    aes_gcm_decrypt(&derived_key, nonce, ct, tag)
}

// ─── AES-256-GCM via BCrypt ────────────────────────────────────

/// AES-256-GCM encrypt. Returns `(nonce, tag, ciphertext)`.
///
/// # Safety
/// Calls raw Win32 BCrypt APIs.
unsafe fn aes_gcm_encrypt(
    key_bytes: &[u8],
    plaintext: &[u8],
) -> Result<([u8; GCM_NONCE_SIZE], [u8; GCM_TAG_SIZE], Vec<u8>)> {
    let aes_alg_name = to_wide("AES");
    let chain_mode_prop = to_wide("ChainingMode");
    let gcm_mode = to_wide("ChainingModeGCM");

    let mut aes_alg = BCRYPT_ALG_HANDLE::default();
    BCryptOpenAlgorithmProvider(
        &mut aes_alg,
        PCWSTR(aes_alg_name.as_ptr()),
        None,
        Default::default(),
    )
    .ok()
    .map_err(|e| Error::EncryptFailed {
        detail: format!("BCryptOpenAlgorithmProvider(AES): {e}"),
    })?;

    BCryptSetProperty(
        aes_alg.into(),
        PCWSTR(chain_mode_prop.as_ptr()),
        std::slice::from_raw_parts(gcm_mode.as_ptr() as *const u8, gcm_mode.len() * 2),
        0,
    )
    .ok()
    .map_err(|e| Error::EncryptFailed {
        detail: format!("BCryptSetProperty(GCM): {e}"),
    })?;

    let mut aes_key = BCRYPT_KEY_HANDLE::default();
    BCryptGenerateSymmetricKey(aes_alg, &mut aes_key, None, key_bytes, 0)
        .ok()
        .map_err(|e| Error::EncryptFailed {
            detail: format!("BCryptGenerateSymmetricKey: {e}"),
        })?;

    // Random nonce.
    let mut nonce = [0_u8; GCM_NONCE_SIZE];
    BCryptGenRandom(
        BCRYPT_ALG_HANDLE::default(),
        &mut nonce,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG,
    )
    .ok()
    .map_err(|e| Error::EncryptFailed {
        detail: format!("BCryptGenRandom: {e}"),
    })?;

    let mut tag = [0_u8; GCM_TAG_SIZE];
    let auth_info = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
        cbSize: std::mem::size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
        dwInfoVersion: 1, // BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION
        pbNonce: nonce.as_mut_ptr(),
        cbNonce: GCM_NONCE_SIZE as u32,
        pbAuthData: ptr::null_mut(),
        cbAuthData: 0,
        pbTag: tag.as_mut_ptr(),
        cbTag: GCM_TAG_SIZE as u32,
        pbMacContext: ptr::null_mut(),
        cbMacContext: 0,
        cbAAD: 0,
        cbData: 0,
        dwFlags: 0,
    };

    let mut ciphertext = vec![0_u8; plaintext.len()];
    let mut ct_len: u32 = 0;
    BCryptEncrypt(
        aes_key,
        Some(plaintext),
        Some(&auth_info as *const _ as *const _),
        None,
        Some(&mut ciphertext),
        &mut ct_len,
        BCRYPT_FLAGS::default(),
    )
    .ok()
    .map_err(|e| Error::EncryptFailed {
        detail: format!("BCryptEncrypt(AES-GCM): {e}"),
    })?;
    ciphertext.truncate(ct_len as usize);

    let _ = BCryptDestroyKey(aes_key).ok();
    let _ = BCryptCloseAlgorithmProvider(aes_alg, 0).ok();

    Ok((nonce, tag, ciphertext))
}

/// AES-256-GCM decrypt.
///
/// # Safety
/// Calls raw Win32 BCrypt APIs.
unsafe fn aes_gcm_decrypt(
    key_bytes: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>> {
    let aes_alg_name = to_wide("AES");
    let chain_mode_prop = to_wide("ChainingMode");
    let gcm_mode = to_wide("ChainingModeGCM");

    let mut aes_alg = BCRYPT_ALG_HANDLE::default();
    BCryptOpenAlgorithmProvider(
        &mut aes_alg,
        PCWSTR(aes_alg_name.as_ptr()),
        None,
        Default::default(),
    )
    .ok()
    .map_err(|e| Error::DecryptFailed {
        detail: format!("BCryptOpenAlgorithmProvider(AES): {e}"),
    })?;

    BCryptSetProperty(
        aes_alg.into(),
        PCWSTR(chain_mode_prop.as_ptr()),
        std::slice::from_raw_parts(gcm_mode.as_ptr() as *const u8, gcm_mode.len() * 2),
        0,
    )
    .ok()
    .map_err(|e| Error::DecryptFailed {
        detail: format!("BCryptSetProperty(GCM): {e}"),
    })?;

    let mut aes_key = BCRYPT_KEY_HANDLE::default();
    BCryptGenerateSymmetricKey(aes_alg, &mut aes_key, None, key_bytes, 0)
        .ok()
        .map_err(|e| Error::DecryptFailed {
            detail: format!("BCryptGenerateSymmetricKey: {e}"),
        })?;

    let mut nonce_copy = [0_u8; GCM_NONCE_SIZE];
    nonce_copy[..nonce.len()].copy_from_slice(nonce);
    let mut tag_copy = [0_u8; GCM_TAG_SIZE];
    tag_copy[..tag.len()].copy_from_slice(tag);

    let auth_info = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
        cbSize: std::mem::size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
        dwInfoVersion: 1,
        pbNonce: nonce_copy.as_mut_ptr(),
        cbNonce: GCM_NONCE_SIZE as u32,
        pbAuthData: ptr::null_mut(),
        cbAuthData: 0,
        pbTag: tag_copy.as_mut_ptr(),
        cbTag: GCM_TAG_SIZE as u32,
        pbMacContext: ptr::null_mut(),
        cbMacContext: 0,
        cbAAD: 0,
        cbData: 0,
        dwFlags: 0,
    };

    let mut plaintext = vec![0_u8; ciphertext.len()];
    let mut pt_len: u32 = 0;
    BCryptDecrypt(
        aes_key,
        Some(ciphertext),
        Some(&auth_info as *const _ as *const _),
        None,
        Some(&mut plaintext),
        &mut pt_len,
        BCRYPT_FLAGS::default(),
    )
    .ok()
    .map_err(|e| Error::DecryptFailed {
        detail: format!("BCryptDecrypt(AES-GCM): {e}"),
    })?;
    plaintext.truncate(pt_len as usize);

    let _ = BCryptDestroyKey(aes_key).ok();
    let _ = BCryptCloseAlgorithmProvider(aes_alg, 0).ok();

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify AES-256-GCM encrypt/decrypt roundtrip with a known 32-byte key.
    /// This exercises the symmetric crypto path independently of ECDH.
    #[test]
    fn aes_gcm_roundtrip_32byte_key() {
        let key = [0x42_u8; 32]; // 32-byte key for AES-256
        let plaintext = b"the quick brown fox jumps over the lazy dog";

        let (nonce, tag, ciphertext) =
            unsafe { aes_gcm_encrypt(&key, plaintext) }.expect("AES-GCM encrypt failed");

        assert_eq!(ciphertext.len(), plaintext.len());

        let recovered = unsafe { aes_gcm_decrypt(&key, &nonce, &ciphertext, &tag) }
            .expect("AES-GCM decrypt failed");

        assert_eq!(recovered, plaintext);
    }

    /// Verify AES-GCM rejects tampered ciphertext (tag mismatch).
    #[test]
    fn aes_gcm_tampered_ciphertext_fails() {
        let key = [0xAB_u8; 32];
        let plaintext = b"sensitive data";

        let (nonce, tag, mut ciphertext) =
            unsafe { aes_gcm_encrypt(&key, plaintext) }.expect("encrypt failed");

        // Flip a byte in the ciphertext.
        if !ciphertext.is_empty() {
            ciphertext[0] ^= 0xFF;
        }

        let result = unsafe { aes_gcm_decrypt(&key, &nonce, &ciphertext, &tag) };
        assert!(
            result.is_err(),
            "tampered ciphertext should fail decryption"
        );
    }

    /// Verify AES-GCM roundtrip with empty plaintext.
    #[test]
    fn aes_gcm_empty_plaintext() {
        let key = [0x01_u8; 32];
        let plaintext = b"";

        let (nonce, tag, ciphertext) =
            unsafe { aes_gcm_encrypt(&key, plaintext) }.expect("encrypt failed");

        assert!(ciphertext.is_empty());

        let recovered =
            unsafe { aes_gcm_decrypt(&key, &nonce, &ciphertext, &tag) }.expect("decrypt failed");

        assert!(recovered.is_empty());
    }

    /// Full ECIES encrypt/decrypt roundtrip using BCrypt (software ECDH).
    /// This tests the KDF SHA-256 fix end-to-end: `ecies_encrypt` derives a
    /// 32-byte key via HASH/SHA-256, and we verify via `aes_gcm_decrypt` that
    /// the derived key is the correct length.
    #[test]
    fn ecies_encrypt_produces_valid_envelope() {
        // Generate an ECDH P-256 key pair via BCrypt for testing.
        let ecdh_alg_name = to_wide(ECDH_P256_ALGORITHM);
        let eccpub_blob_type = to_wide("ECCPUBLICBLOB");

        unsafe {
            let mut ecdh_alg = BCRYPT_ALG_HANDLE::default();
            BCryptOpenAlgorithmProvider(
                &mut ecdh_alg,
                PCWSTR(ecdh_alg_name.as_ptr()),
                None,
                Default::default(),
            )
            .ok()
            .expect("open ECDH provider");

            let mut key = BCRYPT_KEY_HANDLE::default();
            BCryptGenerateKeyPair(ecdh_alg, &mut key, 256, 0)
                .ok()
                .expect("generate key pair");
            BCryptFinalizeKeyPair(key, 0)
                .ok()
                .expect("finalize key pair");

            // Export public key as SEC1.
            let mut sz: u32 = 0;
            BCryptExportKey(
                key,
                BCRYPT_KEY_HANDLE::default(),
                PCWSTR(eccpub_blob_type.as_ptr()),
                None,
                &mut sz,
                0,
            )
            .ok()
            .expect("export size");
            let mut blob = vec![0_u8; sz as usize];
            BCryptExportKey(
                key,
                BCRYPT_KEY_HANDLE::default(),
                PCWSTR(eccpub_blob_type.as_ptr()),
                Some(&mut blob),
                &mut sz,
                0,
            )
            .ok()
            .expect("export key");
            blob.truncate(sz as usize);

            let pub_sec1 = crate::convert::eccpublic_blob_to_sec1(&blob).expect("convert to SEC1");

            // Encrypt with ecies_encrypt — this will fail pre-fix because
            // BCryptDeriveKey produces 20 bytes (SHA-1) instead of 32 (SHA-256).
            let plaintext = b"ecies roundtrip test payload";
            let envelope = ecies_encrypt(&pub_sec1, plaintext)
                .expect("ecies_encrypt should succeed with SHA-256 KDF");

            // Verify envelope structure.
            assert!(envelope.len() >= MIN_CIPHERTEXT_LEN);
            assert_eq!(envelope[0], ECIES_VERSION);
            // The ephemeral public key (65 bytes) starts at offset 1.
            assert_eq!(envelope[1], 0x04, "SEC1 uncompressed prefix");

            let _ = BCryptDestroyKey(key).ok();
            let _ = BCryptCloseAlgorithmProvider(ecdh_alg, 0).ok();
        }
    }

    /// Full TPM-backed ECIES encrypt/decrypt roundtrip.
    /// Skips if no TPM is available (CI without hardware).
    #[test]
    fn ecies_tpm_roundtrip() {
        use enclaveapp_core::traits::{EnclaveEncryptor, EnclaveKeyManager};

        let enc = TpmEncryptor::new("roundtrip-test");
        if !enc.is_available() {
            return;
        }

        let label = "rt-key";
        let _ = enc.delete_key(label);

        enc.generate(label, KeyType::Encryption, AccessPolicy::None)
            .expect("generate");

        let plaintext = b"ECIES roundtrip proof - encrypt then decrypt";
        let ciphertext = enc.encrypt(label, plaintext).expect("encrypt");
        assert!(ciphertext.len() > plaintext.len());
        assert_eq!(ciphertext[0], ECIES_VERSION);

        let recovered = enc.decrypt(label, &ciphertext).expect("decrypt");
        assert_eq!(recovered, plaintext);

        let _ = enc.delete_key(label);
    }
}
