// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! `LinuxTpmSigner` -- ECDSA P-256 signing backend using Linux TPM 2.0.

#![allow(unused_qualifications, let_underscore_drop)]

use crate::tpm::{self, TpmConfig};
use enclaveapp_core::metadata::{self, DirLock};
use enclaveapp_core::traits::{EnclaveKeyManager, EnclaveSigner};
use enclaveapp_core::types::validate_label;
use enclaveapp_core::{AccessPolicy, Error, KeyType, Result};
use sha2::{Digest as _, Sha256};
use tss_esapi::structures::{
    Digest as TpmDigest, Public, Signature as TpmSignature, SignatureScheme,
};
use tss_esapi::traits::{Marshall, UnMarshall};

/// Linux TPM 2.0-backed ECDSA P-256 signer.
#[derive(Debug)]
pub struct LinuxTpmSigner {
    config: TpmConfig,
}

impl LinuxTpmSigner {
    /// Create a new signer for the given application.
    pub fn new(app_name: &str) -> Self {
        Self {
            config: TpmConfig::new(app_name),
        }
    }

    /// Create a signer with a custom keys directory path.
    pub fn with_keys_dir(app_name: &str, keys_dir: std::path::PathBuf) -> Self {
        Self {
            config: TpmConfig::with_keys_dir(app_name, keys_dir),
        }
    }

    /// Load a child key into the TPM and return its handle along with the context.
    fn load_key(&self, label: &str) -> Result<(tss_esapi::Context, tss_esapi::handles::KeyHandle)> {
        let dir = self.config.keys_dir();
        let (pub_blob, priv_blob) = tpm::load_key_blobs(&dir, label)?;

        let mut ctx = tpm::open_context()?;
        let primary_handle = tpm::create_primary(&mut ctx)?;

        let private = tss_esapi::structures::Private::try_from(priv_blob).map_err(|e| {
            Error::KeyOperation {
                operation: "load_private".into(),
                detail: e.to_string(),
            }
        })?;
        let public = Public::unmarshall(&pub_blob).map_err(|e| Error::KeyOperation {
            operation: "load_public".into(),
            detail: e.to_string(),
        })?;

        let key_handle =
            ctx.load(primary_handle, private, public)
                .map_err(|e| Error::KeyOperation {
                    operation: "load_key".into(),
                    detail: e.to_string(),
                })?;

        Ok((ctx, key_handle))
    }
}

impl EnclaveKeyManager for LinuxTpmSigner {
    fn generate(&self, label: &str, key_type: KeyType, policy: AccessPolicy) -> Result<Vec<u8>> {
        validate_label(label)?;
        if key_type != KeyType::Signing {
            return Err(Error::KeyOperation {
                operation: "generate".into(),
                detail: "LinuxTpmSigner only supports signing keys".into(),
            });
        }

        let dir = self.config.keys_dir();
        metadata::ensure_dir(&dir)?;
        let _lock = DirLock::acquire(&dir)?;

        tpm::ensure_label_available(&dir, label)?;

        let mut ctx = tpm::open_context()?;
        let primary_handle = tpm::create_primary(&mut ctx)?;
        let template = tpm::signing_key_template()?;

        let result = ctx
            .create(primary_handle, template, None, None, None, None)
            .map_err(|e| Error::GenerateFailed {
                detail: format!("TPM create: {e}"),
            })?;

        // Extract the public key as SEC1 uncompressed point
        let pub_key = tpm::extract_public_key(&result.out_public)?;

        // Serialize and save TPM blobs
        let pub_blob = result
            .out_public
            .marshall()
            .map_err(|e| Error::KeyOperation {
                operation: "marshall_public".into(),
                detail: e.to_string(),
            })?;
        let priv_blob: Vec<u8> = result.out_private.to_vec();
        tpm::persist_generated_key(
            &dir, label, key_type, policy, &pub_key, &pub_blob, &priv_blob,
        )?;

        // Layer the HMAC sidecar on top of the persisted meta.
        // Best-effort: a Secret Service failure here doesn't fail
        // keygen — the next strict-mode load runs the migration
        // step. Same threshold as the keyring backend's HMAC path.
        if let Some(hmac_key) = enclaveapp_keyring::meta_hmac_key(&self.config.app_name) {
            let meta = enclaveapp_core::KeyMeta::new(label, key_type, policy);
            if let Err(e) = enclaveapp_core::metadata::save_meta_with_hmac(
                &dir,
                label,
                &meta,
                hmac_key.as_slice(),
            ) {
                tracing::warn!(
                    label = label,
                    error = %e,
                    "linux-tpm: post-persist meta-HMAC sidecar write failed; \
                     next load's auto-migrate will retry"
                );
            }
        }

        Ok(pub_key)
    }

    fn public_key(&self, label: &str) -> Result<Vec<u8>> {
        validate_label(label)?;
        let dir = self.config.keys_dir();
        tpm::load_public_key(&dir, label)
    }

    fn list_keys(&self) -> Result<Vec<String>> {
        tpm::list_labels(&self.config.keys_dir())
    }

    fn rename_key(&self, old_label: &str, new_label: &str) -> Result<()> {
        validate_label(old_label)?;
        validate_label(new_label)?;
        if old_label == new_label {
            return Ok(());
        }
        let dir = self.config.keys_dir();
        if !dir.exists() {
            return Err(Error::KeyNotFound {
                label: old_label.to_string(),
            });
        }
        let _lock = DirLock::acquire(&dir)?;
        tpm::rename_key_blobs(&dir, old_label, new_label)?;
        // Linux TPM-backed keys do not write a `.meta.hmac` sidecar
        // on this branch (the strict-mode HMAC discipline ships only
        // on the keyring/software backend). Pass `None` for the
        // hmac_key.
        if let Err(error) = metadata::rename_key_files(&dir, old_label, new_label, None) {
            // Roll the blob rename back so state stays consistent.
            drop(tpm::rename_key_blobs(&dir, new_label, old_label));
            return Err(error);
        }
        Ok(())
    }

    fn delete_key(&self, label: &str) -> Result<()> {
        validate_label(label)?;
        let dir = self.config.keys_dir();
        if !dir.exists() {
            return Err(Error::KeyNotFound {
                label: label.to_string(),
            });
        }
        let _lock = DirLock::acquire(&dir)?;
        let blob_existed = tpm::key_blobs_exist(&dir, label)?;
        let metadata_existed = metadata::key_files_exist(&dir, label)?;
        if !blob_existed && !metadata_existed {
            return Err(Error::KeyNotFound {
                label: label.to_string(),
            });
        }
        match tpm::delete_key_blobs(&dir, label) {
            Ok(()) => {}
            Err(Error::KeyNotFound { .. }) if metadata_existed => {}
            Err(err) => return Err(err),
        }
        match metadata::delete_key_files(&dir, label) {
            Ok(()) => Ok(()),
            Err(Error::KeyNotFound { .. }) if blob_existed => Ok(()),
            Err(err) => Err(err),
        }
    }

    fn is_available(&self) -> bool {
        tpm::is_available()
    }
}

impl EnclaveSigner for LinuxTpmSigner {
    fn sign(&self, label: &str, data: &[u8]) -> Result<Vec<u8>> {
        // AccessPolicy is stored in key metadata but is not enforced here.
        // The TPM key uses empty authorization; no user prompt occurs regardless
        // of the policy recorded at generation time.
        validate_label(label)?;
        let (mut ctx, key_handle) = self.load_key(label)?;

        // Pre-hash with SHA-256 (TPM takes a digest, not raw data)
        let hash = Sha256::digest(data);
        let digest = TpmDigest::try_from(hash.as_slice()).map_err(|e| Error::SignFailed {
            detail: format!("digest conversion: {e}"),
        })?;

        // Sign with the TPM -- unrestricted key needs a null hierarchy ticket
        let ticket = tss_esapi::structures::HashcheckTicket::try_from(
            tss_esapi::tss2_esys::TPMT_TK_HASHCHECK {
                tag: tss_esapi::constants::tss::TPM2_ST_HASHCHECK,
                hierarchy: tss_esapi::constants::tss::TPM2_RH_NULL,
                digest: Default::default(),
            },
        )
        .map_err(|e| Error::SignFailed {
            detail: format!("ticket: {e}"),
        })?;
        let signature = ctx
            .sign(key_handle, digest, SignatureScheme::Null, ticket)
            .map_err(|e| Error::SignFailed {
                detail: format!("TPM sign: {e}"),
            })?;

        // Convert TPM signature to DER-encoded ECDSA signature
        tpm_signature_to_der(&signature)
    }
}

/// Convert a TPM ECDSA signature to DER-encoded format.
fn tpm_signature_to_der(sig: &TpmSignature) -> Result<Vec<u8>> {
    match sig {
        TpmSignature::EcDsa(ecc_sig) => {
            let r_bytes = ecc_sig.signature_r().value();
            let s_bytes = ecc_sig.signature_s().value();

            // Encode as DER SEQUENCE { INTEGER r, INTEGER s }
            let r_der = encode_der_integer(r_bytes);
            let s_der = encode_der_integer(s_bytes);

            let inner_len = r_der.len() + s_der.len();
            let mut der = Vec::with_capacity(2 + inner_len);
            der.push(0x30); // SEQUENCE tag
            encode_der_length(&mut der, inner_len);
            der.extend_from_slice(&r_der);
            der.extend_from_slice(&s_der);
            Ok(der)
        }
        _ => Err(Error::SignFailed {
            detail: "unexpected signature type from TPM (expected ECDSA)".into(),
        }),
    }
}

/// Encode a big-endian unsigned integer as DER INTEGER.
fn encode_der_integer(bytes: &[u8]) -> Vec<u8> {
    // Strip leading zeros but keep at least one byte
    let mut start = 0;
    while start < bytes.len() - 1 && bytes[start] == 0 {
        start += 1;
    }
    let significant = &bytes[start..];

    // If the high bit is set, prepend a 0x00 byte (positive integer)
    let needs_pad = significant[0] & 0x80 != 0;
    let len = significant.len() + usize::from(needs_pad);

    let mut out = Vec::with_capacity(2 + len);
    out.push(0x02); // INTEGER tag
    encode_der_length(&mut out, len);
    if needs_pad {
        out.push(0x00);
    }
    out.extend_from_slice(significant);
    out
}

/// Encode a DER length field.
fn encode_der_length(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use enclaveapp_core::KeyMeta;

    #[test]
    fn encode_der_integer_no_padding() {
        let bytes = [0x01, 0x02, 0x03];
        let der = encode_der_integer(&bytes);
        assert_eq!(der, vec![0x02, 0x03, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn encode_der_integer_with_high_bit_padding() {
        let bytes = [0x80, 0x01];
        let der = encode_der_integer(&bytes);
        assert_eq!(der, vec![0x02, 0x03, 0x00, 0x80, 0x01]);
    }

    #[test]
    fn encode_der_integer_strips_leading_zeros() {
        let bytes = [0x00, 0x00, 0x42];
        let der = encode_der_integer(&bytes);
        assert_eq!(der, vec![0x02, 0x01, 0x42]);
    }

    #[test]
    fn encode_der_integer_single_zero() {
        let bytes = [0x00];
        let der = encode_der_integer(&bytes);
        assert_eq!(der, vec![0x02, 0x01, 0x00]);
    }

    #[test]
    fn tpm_signer_rejects_encryption_key_type() {
        // This test doesn't need a TPM -- it validates the key_type check
        let signer = LinuxTpmSigner::with_keys_dir(
            "test",
            std::env::temp_dir().join("enclaveapp-tpm-test-reject"),
        );
        let err = signer
            .generate("test", KeyType::Encryption, AccessPolicy::None)
            .unwrap_err();
        match err {
            Error::KeyOperation { .. } => {}
            other => panic!("expected KeyOperation, got: {other}"),
        }
    }

    #[test]
    fn generate_rejects_duplicate_metadata_without_blob() {
        let dir = std::env::temp_dir().join(format!(
            "enclaveapp-tpm-test-sign-dup-{}",
            std::process::id()
        ));
        drop(std::fs::remove_dir_all(&dir));
        std::fs::create_dir_all(&dir).unwrap();

        let signer = LinuxTpmSigner::with_keys_dir("test", dir.clone());
        let meta = KeyMeta::new("stray-sign", KeyType::Signing, AccessPolicy::None);
        metadata::save_meta(&dir, "stray-sign", &meta).unwrap();

        let err = signer
            .generate("stray-sign", KeyType::Signing, AccessPolicy::None)
            .unwrap_err();
        match err {
            Error::DuplicateLabel { label } => assert_eq!(label, "stray-sign"),
            other => panic!("expected DuplicateLabel, got: {other}"),
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }

    // Integration tests that require actual TPM hardware.
    // Run with: ENCLAVEAPP_TEST_TPM=1 cargo test -p enclaveapp-linux-tpm --features signing
    #[test]
    fn tpm_sign_roundtrip() {
        if std::env::var("ENCLAVEAPP_TEST_TPM").is_err() {
            eprintln!("skipping TPM test (set ENCLAVEAPP_TEST_TPM=1 to run)");
            return;
        }

        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("enclaveapp-tpm-sign-test-{pid}-{id}"));
        std::fs::create_dir_all(&dir).unwrap();

        let signer = LinuxTpmSigner::with_keys_dir("test", dir.clone());

        let pub_key = signer
            .generate("tpm-sign-test", KeyType::Signing, AccessPolicy::None)
            .unwrap();
        assert_eq!(pub_key.len(), 65);
        assert_eq!(pub_key[0], 0x04);

        let sig = signer.sign("tpm-sign-test", b"hello world").unwrap();
        // DER signature starts with SEQUENCE tag
        assert_eq!(sig[0], 0x30);

        let retrieved = signer.public_key("tpm-sign-test").unwrap();
        assert_eq!(retrieved, pub_key);

        let keys = signer.list_keys().unwrap();
        assert!(keys.contains(&"tpm-sign-test".to_string()));

        signer.delete_key("tpm-sign-test").unwrap();

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
