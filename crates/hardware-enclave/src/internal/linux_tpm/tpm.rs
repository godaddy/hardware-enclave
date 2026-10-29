// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Core TPM 2.0 operations shared between signing and encryption backends.
#![allow(
    dead_code,
    unused_imports,
    unused_qualifications,
    unreachable_patterns,
    let_underscore_drop
)]

use crate::internal::core::metadata;
use crate::internal::core::{AccessPolicy, Error, KeyMeta, KeyType, Result};
use std::path::{Path, PathBuf};
use tss_esapi::{
    attributes::ObjectAttributesBuilder,
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        ecc::EccCurve,
        resource_handles::Hierarchy,
    },
    structures::{
        EccPoint, EccScheme, HashScheme, KeyDerivationFunctionScheme, Public, PublicBuilder,
        PublicEccParametersBuilder, SymmetricDefinitionObject,
    },
    tcti_ldr::{DeviceConfig, TctiNameConf},
    traits::UnMarshall,
    Context,
};

/// Try to open a TPM context.
pub fn open_context() -> Result<Context> {
    // Try kernel resource manager first (/dev/tpmrm0)
    let device_path = std::path::Path::new("/dev/tpmrm0");
    if device_path.exists() {
        let tcti = TctiNameConf::Device("/dev/tpmrm0".parse::<DeviceConfig>().map_err(|e| {
            Error::KeyOperation {
                operation: "parse_device_config".into(),
                detail: e.to_string(),
            }
        })?);
        return Context::new(tcti).map_err(|e| Error::KeyOperation {
            operation: "open_tpm".into(),
            detail: format!("device TCTI: {e}"),
        });
    }

    // Try tpm2-abrmd
    let tcti = TctiNameConf::Tabrmd(Default::default());
    Context::new(tcti).map_err(|e| Error::KeyOperation {
        operation: "open_tpm".into(),
        detail: format!("no TPM available (tried /dev/tpmrm0 and tpm2-abrmd): {e}"),
    })
}

pub fn is_available() -> bool {
    open_context().is_ok()
}

/// Build the primary ECC storage key template.
///
/// Uses ECC P-256 as a restricted decryption key under the owner hierarchy.
/// The template is deterministic so the same primary is recreated every time.
pub fn primary_key_template() -> Result<Public> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(true)
        .with_restricted(true)
        .build()
        .map_err(|e| Error::KeyOperation {
            operation: "primary_template".into(),
            detail: e.to_string(),
        })?;

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_ecc_parameters(
            PublicEccParametersBuilder::new_restricted_decryption_key(
                SymmetricDefinitionObject::AES_128_CFB,
                EccCurve::NistP256,
            )
            .build()
            .map_err(|e| Error::KeyOperation {
                operation: "primary_params".into(),
                detail: e.to_string(),
            })?,
        )
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .map_err(|e| Error::KeyOperation {
            operation: "primary_build".into(),
            detail: e.to_string(),
        })
}

/// Create the primary storage key. Returns its handle.
pub fn create_primary(ctx: &mut Context) -> Result<tss_esapi::handles::KeyHandle> {
    let template = primary_key_template()?;
    let result = ctx.execute_with_nullauth_session(|ctx| {ctx
        .create_primary(Hierarchy::Owner, template, None, None, None, None)
    })
        .map_err(|e| Error::KeyOperation {
            operation: "create_primary".into(),
            detail: e.to_string(),
        })?;
    Ok(result.key_handle)
}

/// Build a child ECDSA P-256 signing key template (unrestricted).
pub fn signing_key_template() -> Result<Public> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_sign_encrypt(true)
        .build()
        .map_err(|e| Error::KeyOperation {
            operation: "signing_template".into(),
            detail: e.to_string(),
        })?;

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_ecc_parameters(
            PublicEccParametersBuilder::new_unrestricted_signing_key(
                EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)),
                EccCurve::NistP256,
            )
            .build()
            .map_err(|e| Error::KeyOperation {
                operation: "signing_params".into(),
                detail: e.to_string(),
            })?,
        )
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .map_err(|e| Error::KeyOperation {
            operation: "signing_build".into(),
            detail: e.to_string(),
        })
}

/// Build a child ECDH P-256 key template for encryption (unrestricted decryption).
pub fn encryption_key_template() -> Result<Public> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(true)
        .build()
        .map_err(|e| Error::KeyOperation {
            operation: "encryption_template".into(),
            detail: e.to_string(),
        })?;

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_ecc_parameters(
            PublicEccParametersBuilder::new()
                .with_ecc_scheme(EccScheme::EcDh(HashScheme::new(HashingAlgorithm::Sha256)))
                .with_curve(EccCurve::NistP256)
                .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
                .with_is_decryption_key(true)
                .build()
                .map_err(|e| Error::KeyOperation {
                    operation: "encryption_params".into(),
                    detail: e.to_string(),
                })?,
        )
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .map_err(|e| Error::KeyOperation {
            operation: "encryption_build".into(),
            detail: e.to_string(),
        })
}

/// Extract 65-byte SEC1 uncompressed public key from a TPM ECC public structure.
pub fn extract_public_key(public: &Public) -> Result<Vec<u8>> {
    match public {
        Public::Ecc { unique, .. } => {
            let x = unique.x().value();
            let y = unique.y().value();
            let mut point = Vec::with_capacity(65);
            point.push(0x04);
            // Pad to 32 bytes each (P-256 coordinates are 32 bytes)
            let x_pad = 32usize.saturating_sub(x.len());
            point.extend(std::iter::repeat(0u8).take(x_pad));
            point.extend_from_slice(x);
            let y_pad = 32usize.saturating_sub(y.len());
            point.extend(std::iter::repeat(0u8).take(y_pad));
            point.extend_from_slice(y);
            Ok(point)
        }
        _ => Err(Error::KeyOperation {
            operation: "extract_public_key".into(),
            detail: "not an ECC key".into(),
        }),
    }
}

/// Configuration for the Linux TPM backend.
#[derive(Debug)]
pub struct TpmConfig {
    pub app_name: String,
    pub keys_dir_override: Option<PathBuf>,
}

impl TpmConfig {
    pub fn new(app_name: &str) -> Self {
        Self {
            app_name: app_name.to_string(),
            keys_dir_override: None,
        }
    }

    pub fn with_keys_dir(app_name: &str, keys_dir: PathBuf) -> Self {
        Self {
            app_name: app_name.to_string(),
            keys_dir_override: Some(keys_dir),
        }
    }

    pub fn keys_dir(&self) -> PathBuf {
        self.keys_dir_override
            .clone()
            .unwrap_or_else(|| metadata::keys_dir(&self.app_name))
    }
}

const TPM_BLOB_EXTENSIONS: [&str; 2] = ["tpm_pub", "tpm_priv"];

fn blob_path(dir: &Path, label: &str, extension: &str) -> Result<PathBuf> {
    crate::internal::core::types::validate_label(label)?;
    Ok(dir.join(format!("{label}.{extension}")))
}

fn blob_paths(dir: &Path, label: &str) -> Result<[PathBuf; 2]> {
    Ok([
        blob_path(dir, label, TPM_BLOB_EXTENSIONS[0])?,
        blob_path(dir, label, TPM_BLOB_EXTENSIONS[1])?,
    ])
}

pub fn key_artifacts_exist(dir: &Path, label: &str) -> Result<bool> {
    Ok(key_blobs_exist(dir, label)? || metadata::key_files_exist(dir, label)?)
}

pub fn ensure_label_available(dir: &Path, label: &str) -> Result<()> {
    if key_artifacts_exist(dir, label)? {
        return Err(Error::DuplicateLabel {
            label: label.to_string(),
        });
    }
    Ok(())
}

/// Save TPM key blobs (public + private) to disk.
/// The private blob is TPM-encrypted -- useless without the same physical TPM.
pub fn save_key_blobs(
    dir: &Path,
    label: &str,
    public_blob: &[u8],
    private_blob: &[u8],
) -> Result<()> {
    let [pub_path, priv_path] = blob_paths(dir, label)?;
    metadata::atomic_write(&pub_path, public_blob)?;
    if let Err(error) = write_private_blob(&priv_path, private_blob) {
        cleanup_blob_files(&[pub_path, priv_path])?;
        return Err(error);
    }
    Ok(())
}

/// Persist a newly generated TPM key and its cached metadata/public-key artifacts.
///
/// If any cached artifact write fails after the TPM blobs are persisted, all newly
/// written files for the label are removed so callers do not observe a partially
/// created key after a failed generate operation.
pub fn persist_generated_key(
    dir: &Path,
    label: &str,
    key_type: KeyType,
    policy: AccessPolicy,
    public_key: &[u8],
    public_blob: &[u8],
    private_blob: &[u8],
) -> Result<()> {
    save_key_blobs(dir, label, public_blob, private_blob)?;

    if let Err(error) = persist_cached_key_artifacts(dir, label, key_type, policy, public_key) {
        cleanup_generated_key_artifacts(dir, label)?;
        return Err(error);
    }

    Ok(())
}

/// Load TPM key blobs from disk.
pub fn load_key_blobs(dir: &Path, label: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    let [pub_path, priv_path] = blob_paths(dir, label)?;
    if !pub_path.exists() || !priv_path.exists() {
        return Err(Error::KeyNotFound {
            label: label.to_string(),
        });
    }
    let public_blob = metadata::read_no_follow(&pub_path)?;
    let private_blob = metadata::read_no_follow(&priv_path)?;
    Ok((public_blob, private_blob))
}

/// Load the public key for a TPM-backed label, requiring backing TPM blobs to exist.
///
/// A cached `.pub` file is only trusted after the TPM blobs are confirmed present.
/// If the cache is missing, the public key is derived from the TPM public blob and
/// written back for subsequent lookups.
pub fn load_public_key(dir: &Path, label: &str) -> Result<Vec<u8>> {
    let (public_blob, _) = load_key_blobs(dir, label)?;
    let public = Public::unmarshall(&public_blob).map_err(|e| Error::KeyOperation {
        operation: "load_public".into(),
        detail: e.to_string(),
    })?;
    let public_key = extract_public_key(&public)?;
    metadata::sync_pub_key(dir, label, &public_key)
}

pub fn list_labels(dir: &Path) -> Result<Vec<String>> {
    metadata::list_labels_for_extensions(dir, &["meta", "tpm_pub", "tpm_priv"])
}

/// Delete TPM key blob files.
pub fn delete_key_blobs(dir: &Path, label: &str) -> Result<()> {
    let [pub_path, priv_path] = blob_paths(dir, label)?;
    if !pub_path.exists() && !priv_path.exists() {
        return Err(Error::KeyNotFound {
            label: label.to_string(),
        });
    }
    for path in [pub_path, priv_path] {
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
    }
    Ok(())
}

pub fn key_blobs_exist(dir: &Path, label: &str) -> Result<bool> {
    let [pub_path, priv_path] = blob_paths(dir, label)?;
    Ok(pub_path.exists() || priv_path.exists())
}

/// Rename the `.tpm_pub` / `.tpm_priv` blob files associated with a key.
/// Does not touch metadata — callers combine with `metadata::rename_key_files`.
pub fn rename_key_blobs(dir: &Path, old_label: &str, new_label: &str) -> Result<()> {
    let [old_pub, old_priv] = blob_paths(dir, old_label)?;
    let [new_pub, new_priv] = blob_paths(dir, new_label)?;
    if new_pub.exists() || new_priv.exists() {
        return Err(Error::DuplicateLabel {
            label: new_label.to_string(),
        });
    }
    if !old_pub.exists() && !old_priv.exists() {
        return Err(Error::KeyNotFound {
            label: old_label.to_string(),
        });
    }
    let mut renamed: Vec<(PathBuf, PathBuf)> = Vec::new();
    for (old, new) in [(old_pub, new_pub), (old_priv, new_priv)] {
        if old.exists() {
            if let Err(err) = std::fs::rename(&old, &new) {
                // Roll back prior renames to keep the old label complete.
                for (backed_old, backed_new) in renamed.iter().rev() {
                    drop(std::fs::rename(backed_new, backed_old));
                }
                return Err(err.into());
            }
            renamed.push((old, new));
        }
    }
    Ok(())
}

fn persist_cached_key_artifacts(
    dir: &Path,
    label: &str,
    key_type: KeyType,
    policy: AccessPolicy,
    public_key: &[u8],
) -> Result<()> {
    metadata::save_pub_key(dir, label, public_key)?;
    let meta = KeyMeta::new(label, key_type, policy);
    metadata::save_meta(dir, label, &meta)
}

fn cleanup_generated_key_artifacts(dir: &Path, label: &str) -> Result<()> {
    let [pub_blob_path, priv_blob_path] = blob_paths(dir, label)?;
    let cached_pub = dir.join(format!("{label}.pub"));
    let meta = dir.join(format!("{label}.meta"));

    cleanup_blob_files(&[pub_blob_path, priv_blob_path, cached_pub, meta])?;

    Ok(())
}

fn write_private_blob(path: &Path, private_blob: &[u8]) -> Result<()> {
    metadata::atomic_write(path, private_blob)?;
    metadata::restrict_file_permissions(path)?;
    Ok(())
}

fn cleanup_blob_files(paths: &[PathBuf]) -> Result<()> {
    for path in paths {
        if path.is_file() {
            std::fs::remove_file(path)?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_dir() -> PathBuf {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("enclaveapp-tpm-test-{pid}-{id}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn tpm_config_new_sets_app_name() {
        let config = TpmConfig::new("sshenc");
        assert_eq!(config.app_name, "sshenc");
        assert!(config.keys_dir_override.is_none());
    }

    #[test]
    fn tpm_config_with_keys_dir_overrides_path() {
        let custom = PathBuf::from("/tmp/custom-tpm-keys");
        let config = TpmConfig::with_keys_dir("sshenc", custom.clone());
        assert_eq!(config.app_name, "sshenc");
        assert_eq!(config.keys_dir_override, Some(custom.clone()));
        assert_eq!(config.keys_dir(), custom);
    }

    #[test]
    fn tpm_config_keys_dir_returns_default_when_no_override() {
        let config = TpmConfig::new("test-app");
        let expected = metadata::keys_dir("test-app");
        assert_eq!(config.keys_dir(), expected);
    }

    #[test]
    fn save_load_key_blobs_roundtrip() {
        let dir = test_dir();
        let pub_blob = b"fake-tpm-public-blob-data";
        let priv_blob = b"fake-tpm-private-blob-data";
        save_key_blobs(&dir, "mykey", pub_blob, priv_blob).unwrap();

        let (loaded_pub, loaded_priv) = load_key_blobs(&dir, "mykey").unwrap();
        assert_eq!(loaded_pub, pub_blob);
        assert_eq!(loaded_priv, priv_blob);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn delete_key_blobs_removes_files() {
        let dir = test_dir();
        save_key_blobs(&dir, "delme", b"pub", b"priv").unwrap();
        assert!(dir.join("delme.tpm_pub").exists());
        assert!(dir.join("delme.tpm_priv").exists());

        delete_key_blobs(&dir, "delme").unwrap();
        assert!(!dir.join("delme.tpm_pub").exists());
        assert!(!dir.join("delme.tpm_priv").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_key_blobs_missing_returns_key_not_found() {
        let dir = test_dir();
        let err = load_key_blobs(&dir, "nonexistent").unwrap_err();
        match err {
            Error::KeyNotFound { label } => assert_eq!(label, "nonexistent"),
            other => panic!("expected KeyNotFound, got: {other}"),
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn delete_key_blobs_missing_returns_key_not_found() {
        let dir = test_dir();
        let err = delete_key_blobs(&dir, "nonexistent").unwrap_err();
        match err {
            Error::KeyNotFound { label } => assert_eq!(label, "nonexistent"),
            other => panic!("expected KeyNotFound, got: {other}"),
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn blob_helpers_reject_invalid_labels() {
        let dir = test_dir();
        assert!(save_key_blobs(&dir, "../bad", b"pub", b"priv").is_err());
        assert!(load_key_blobs(&dir, "../bad").is_err());
        assert!(delete_key_blobs(&dir, "../bad").is_err());
        assert!(key_blobs_exist(&dir, "../bad").is_err());
        assert!(ensure_label_available(&dir, "../bad").is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn persist_generated_key_cleans_up_on_cached_metadata_failure() {
        let dir = test_dir();
        std::fs::create_dir(dir.join("partial.meta")).unwrap();

        let err = persist_generated_key(
            &dir,
            "partial",
            KeyType::Encryption,
            AccessPolicy::None,
            &[0x04; 65],
            b"public-blob",
            b"private-blob",
        )
        .unwrap_err();

        assert!(matches!(err, Error::Io(_)));
        assert!(!dir.join("partial.tpm_pub").exists());
        assert!(!dir.join("partial.tpm_priv").exists());
        assert!(!dir.join("partial.pub").exists());
        assert!(dir.join("partial.meta").is_dir());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_public_key_rejects_stale_cache_without_tpm_blobs() {
        let dir = test_dir();
        metadata::save_pub_key(&dir, "orphaned", &[0x04; 65]).unwrap();

        let err = load_public_key(&dir, "orphaned").unwrap_err();
        match err {
            Error::KeyNotFound { label } => assert_eq!(label, "orphaned"),
            other => panic!("expected KeyNotFound, got: {other}"),
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_public_key_rejects_stale_cache_when_blob_is_invalid() {
        let dir = test_dir();
        save_key_blobs(&dir, "cached", b"ignored-public-blob", b"private-blob").unwrap();
        let cached = vec![0x04; 65];
        metadata::save_pub_key(&dir, "cached", &cached).unwrap();

        let err = load_public_key(&dir, "cached").unwrap_err();
        assert!(matches!(err, Error::KeyOperation { .. }));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn list_labels_includes_labels_from_tpm_blobs_without_metadata() {
        let dir = test_dir();
        std::fs::write(dir.join("alpha.tpm_pub"), b"pub").unwrap();
        std::fs::write(dir.join("alpha.tpm_priv"), b"priv").unwrap();
        std::fs::write(dir.join("beta.meta"), b"{}").unwrap();

        assert_eq!(list_labels(&dir).unwrap(), vec!["alpha", "beta"]);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn save_key_blobs_rolls_back_when_private_blob_write_fails() {
        let dir = test_dir();
        std::fs::create_dir(dir.join("partial.tpm_priv")).unwrap();

        let err = save_key_blobs(&dir, "partial", b"public-blob", b"private-blob").unwrap_err();
        assert!(matches!(err, Error::Io(_)));
        assert!(!dir.join("partial.tpm_pub").exists());
        assert!(dir.join("partial.tpm_priv").is_dir());

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
