// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Secure Enclave encryption backend (ECIES: ECDH + AES-GCM).

use crate::ffi;
use crate::keychain::{self, KeychainConfig};
use crate::lacontext;
use enclaveapp_core::traits::{EnclaveEncryptor, EnclaveKeyManager};
use enclaveapp_core::types::{validate_label, AccessPolicy, KeyType};
use enclaveapp_core::{Error, Result};
use zeroize::Zeroizing;

/// ECIES ciphertext overhead: version(1) + ephemeral_pub(65) + nonce(12) + tag(16)
const ECIES_OVERHEAD: usize = 1 + 65 + 12 + 16;

/// ECIES encryption backend using the macOS Secure Enclave.
#[derive(Debug)]
pub struct SecureEnclaveEncryptor {
    config: KeychainConfig,
}

impl SecureEnclaveEncryptor {
    pub fn new(app_name: &str) -> Self {
        SecureEnclaveEncryptor {
            config: KeychainConfig::new(app_name),
        }
    }

    /// Create an encryptor with a custom keys directory path.
    pub fn with_keys_dir(app_name: &str, keys_dir: std::path::PathBuf) -> Self {
        SecureEnclaveEncryptor {
            config: KeychainConfig::with_keys_dir(app_name, keys_dir),
        }
    }

    /// Create an encryptor from a pre-built `KeychainConfig`. Use this
    /// to supply non-default `wrapping_key_user_presence` /
    /// `wrapping_key_cache_ttl` settings.
    pub fn with_config(config: KeychainConfig) -> Self {
        SecureEnclaveEncryptor { config }
    }

    /// Load the Secure Enclave handle using the same reusable
    /// `LAContext` registry as signing. Returning the token with the
    /// handle lets the caller pass that same authenticated context into
    /// CryptoKit for the SE operation, so one prompt covers both the
    /// wrapping-key load and the hardware decrypt.
    fn load_handle(&self, label: &str) -> Result<(Zeroizing<Vec<u8>>, u64)> {
        let reason = format!("{}: decrypt ({})", self.config.app_name, label);
        let token = lacontext::acquire(
            &self.config.app_name,
            label,
            self.config.wrapping_key_cache_ttl.as_secs(),
            &reason,
        )
        .map(|h| h.token())
        .unwrap_or(0);
        Ok((
            keychain::load_handle_with_context(&self.config, label, token)?,
            token,
        ))
    }
}

impl EnclaveKeyManager for SecureEnclaveEncryptor {
    fn generate(&self, label: &str, key_type: KeyType, policy: AccessPolicy) -> Result<Vec<u8>> {
        validate_label(label)?;

        if key_type != KeyType::Encryption {
            return Err(Error::KeyOperation {
                operation: "generate".into(),
                detail: "SecureEnclaveEncryptor only supports encryption keys".into(),
            });
        }

        keychain::generate_and_save_key(&self.config, label, key_type, policy)
    }

    fn public_key(&self, label: &str) -> Result<Vec<u8>> {
        validate_label(label)?;
        keychain::load_pub_key(&self.config, label, KeyType::Encryption)
    }

    fn list_keys(&self) -> Result<Vec<String>> {
        keychain::list_labels(&self.config)
    }

    fn delete_key(&self, label: &str) -> Result<()> {
        validate_label(label)?;
        keychain::delete_key(&self.config, label)
    }

    fn is_available(&self) -> bool {
        keychain::is_available()
    }
}

impl EnclaveEncryptor for SecureEnclaveEncryptor {
    #[allow(unsafe_code)] // FFI call to CryptoKit Swift bridge
    fn encrypt(&self, label: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        validate_label(label)?;
        let (data_rep, _token) = self.load_handle(label)?;

        let output_capacity = plaintext.len() + ECIES_OVERHEAD;
        let mut ciphertext = vec![0_u8; output_capacity];
        let mut ciphertext_len = output_capacity as i32;

        let rc = unsafe {
            ffi::enclaveapp_se_encrypt(
                data_rep.as_ptr(),
                data_rep.len() as i32,
                plaintext.as_ptr(),
                plaintext.len() as i32,
                ciphertext.as_mut_ptr(),
                &mut ciphertext_len,
            )
        };

        if rc != 0 {
            return Err(Error::EncryptFailed {
                detail: format!("FFI returned error code {rc}"),
            });
        }

        ciphertext.truncate(ciphertext_len as usize);
        Ok(ciphertext)
    }

    #[allow(unsafe_code)] // FFI call to CryptoKit Swift bridge
    fn decrypt(&self, label: &str, ciphertext: &[u8]) -> Result<Vec<u8>> {
        validate_label(label)?;
        if ciphertext.len() < ECIES_OVERHEAD {
            return Err(Error::DecryptFailed {
                detail: "ciphertext too short".into(),
            });
        }

        let (data_rep, token) = self.load_handle(label)?;

        let max_plaintext = ciphertext.len();
        let mut plaintext = vec![0_u8; max_plaintext];
        let mut plaintext_len = max_plaintext as i32;

        let rc = unsafe {
            ffi::enclaveapp_se_decrypt(
                data_rep.as_ptr(),
                data_rep.len() as i32,
                ciphertext.as_ptr(),
                ciphertext.len() as i32,
                plaintext.as_mut_ptr(),
                &mut plaintext_len,
                token,
            )
        };

        if rc != 0 {
            return Err(Error::DecryptFailed {
                detail: format!("FFI returned error code {rc}"),
            });
        }

        plaintext.truncate(plaintext_len as usize);
        Ok(plaintext)
    }
}
