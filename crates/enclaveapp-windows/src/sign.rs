// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! `TpmSigner` — ECDSA P-256 signing backend using the Windows TPM.

// This module wraps NCrypt C APIs which require unsafe FFI calls.
#![allow(unsafe_code, unused_qualifications, let_underscore_drop)]

use crate::convert::p1363_to_der;
use crate::export::export_public_key;
use crate::key;
use crate::provider;
use crate::state;
use enclaveapp_core::metadata;
use enclaveapp_core::traits::{EnclaveKeyManager, EnclaveSigner};
use enclaveapp_core::types::validate_label;
use enclaveapp_core::{AccessPolicy, Error, KeyMeta, KeyType, Result};
use sha2::{Digest, Sha256};
use windows::Win32::Security::Cryptography::*;

/// ECDSA P-256 algorithm identifier for CNG.
const ECDSA_P256_ALGORITHM: &str = "ECDSA_P256";

/// Windows TPM-backed ECDSA P-256 signer.
#[derive(Debug)]
pub struct TpmSigner {
    app_name: String,
    keys_dir_override: Option<std::path::PathBuf>,
}

impl TpmSigner {
    /// Create a new signer for the given application.
    pub fn new(app_name: &str) -> Self {
        TpmSigner {
            app_name: app_name.to_string(),
            keys_dir_override: None,
        }
    }

    /// Create a signer with a custom keys directory path.
    pub fn with_keys_dir(app_name: &str, keys_dir: std::path::PathBuf) -> Self {
        TpmSigner {
            app_name: app_name.to_string(),
            keys_dir_override: Some(keys_dir),
        }
    }

    fn keys_dir(&self) -> std::path::PathBuf {
        self.keys_dir_override
            .clone()
            .unwrap_or_else(|| metadata::keys_dir(&self.app_name))
    }
}

impl EnclaveKeyManager for TpmSigner {
    fn generate(&self, label: &str, key_type: KeyType, policy: AccessPolicy) -> Result<Vec<u8>> {
        validate_label(label)?;
        if key_type != KeyType::Signing {
            return Err(Error::KeyOperation {
                operation: "generate".into(),
                detail: "TpmSigner only supports signing keys".into(),
            });
        }

        let dir = self.keys_dir();
        let provider = provider::open_provider()?;
        let state = state::KeyMaterialState::acquire(&dir)?;
        state.ensure_label_available(label, || {
            match key::open_key(&provider, &self.app_name, label) {
                Ok(_key) => Ok(state::AuthoritativeKeyState::Present),
                Err(Error::KeyNotFound { .. }) => Ok(state::AuthoritativeKeyState::Missing),
                Err(error) => Err(error),
            }
        })?;
        let (_key_handle, pub_key) = key::create_key(
            &provider,
            &self.app_name,
            label,
            ECDSA_P256_ALGORITHM,
            policy,
        )?;

        state.persist_generated_key(label, key_type, policy, &pub_key, || {
            key::delete_key(&self.app_name, label)
        })?;

        // Layer the HMAC sidecar on top of the persisted meta. Same
        // best-effort posture as the macOS path: a DPAPI failure
        // here doesn't fail keygen, the next strict-mode load will
        // hit the migration path. Cached after first call.
        if let Ok(Some(hmac_key)) = crate::meta_hmac::load_or_create(&self.app_name) {
            let meta = KeyMeta::new(label, key_type, policy);
            if let Err(e) =
                metadata::save_meta_with_hmac(state.dir(), label, &meta, hmac_key.as_slice())
            {
                tracing::warn!(
                    label = label,
                    error = %e,
                    "post-persist meta-HMAC sidecar write failed; \
                     will be picked up by the next load's auto-migrate"
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
        let pub_key = export_public_key(&key_handle)?;
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

    fn rename_key(&self, old_label: &str, new_label: &str) -> Result<()> {
        // Windows CNG persisted keys are immutable by name: renaming the
        // CNG container requires exporting (not possible for
        // hardware-bound keys) and re-importing under a new name. A
        // consistent rename is therefore not achievable on this backend.
        // Callers (e.g. sshenc's `default` promotion) already gate this
        // operation off on Windows.
        let _ = (old_label, new_label);
        Err(Error::KeyOperation {
            operation: "rename_key".into(),
            detail: "renaming is not supported on the Windows TPM backend: \
                     CNG keys are immutable by name. Create a new key with \
                     the desired label and migrate authorized_keys instead."
                .into(),
        })
    }

    fn is_available(&self) -> bool {
        provider::is_available()
    }
}

impl EnclaveSigner for TpmSigner {
    fn sign(&self, label: &str, data: &[u8]) -> Result<Vec<u8>> {
        validate_label(label)?;
        let provider = provider::open_provider()?;
        let key_handle = key::open_key(&provider, &self.app_name, label)?;

        // Re-verify the key's NCRYPT_UI_POLICY matches the metadata's
        // AccessPolicy before signing. Without this check, a same-user
        // attacker who pre-planted a TPM key with the expected CNG
        // name (but without UI_PROTECT_KEY_FLAG) could get sshenc to
        // sign without triggering a UI prompt — the hardware enforces
        // the policy that's actually set on the key, not what the app
        // thinks was set.
        //
        // With the `windows-hello-ui` feature on, `key::create_key`
        // skips the flag *only* when Hello was enrolled at keygen
        // time. So a key without the flag is the expected
        // configuration on a Hello host — we verify it explicitly
        // below: if Hello is no longer available now, refuse the
        // signature rather than falling through to silent TPM use.
        let dir = self.keys_dir();
        let expected_policy = match metadata::load_meta(&dir, label) {
            Ok(meta) => meta.access_policy,
            Err(Error::KeyNotFound { .. }) => AccessPolicy::None,
            Err(err) => return Err(err),
        };
        // Verify the on-disk metadata's access policy matches the
        // TPM key's actual `NCRYPT_UI_POLICY` flag. Catches an
        // attacker-planted key that has the expected CNG name but
        // a different (or missing) UI flag -- without this check
        // the agent might sign through a key that has no
        // hardware-enforced UI gate. The hardware itself fires the
        // CryptUI password dialog at the TPM call below if the
        // flag is set; we don't issue any user-mode prompts here.
        crate::ui_policy::verify_ui_policy_matches(&key_handle, expected_policy)?;

        // Pre-hash with SHA-256.
        let digest = Sha256::digest(data);

        // Query signature size.
        let mut sig_size: u32 = 0;
        unsafe {
            NCryptSignHash(
                key_handle.as_key(),
                None,
                &digest,
                None,
                &mut sig_size,
                NCRYPT_FLAGS::default(),
            )
            .map_err(|e| Error::SignFailed {
                detail: format!("NCryptSignHash size query: {e}"),
            })?;
        }

        // Produce the P1363 signature.
        let mut sig = vec![0_u8; sig_size as usize];
        unsafe {
            NCryptSignHash(
                key_handle.as_key(),
                None,
                &digest,
                Some(&mut sig),
                &mut sig_size,
                NCRYPT_FLAGS::default(),
            )
            .map_err(|e| Error::SignFailed {
                detail: format!("NCryptSignHash: {e}"),
            })?;
        }
        sig.truncate(sig_size as usize);

        // CNG returns P1363 (r || s); convert to DER.
        Ok(p1363_to_der(&sig))
    }
}
