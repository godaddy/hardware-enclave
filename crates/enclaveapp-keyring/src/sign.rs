// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Software ECDSA P-256 signing backend.

use crate::key_storage::{self, SoftwareConfig};
use crate::{meta_migration_marker, meta_tag};
use enclaveapp_core::traits::{EnclaveKeyManager, EnclaveSigner};
use enclaveapp_core::types::{validate_label, AccessPolicy, KeyType};
use enclaveapp_core::{Error, Result};

/// Software-based ECDSA P-256 signer.
///
/// Private keys are stored as files on disk (not hardware-backed).
#[derive(Debug)]
pub struct SoftwareSigner {
    config: SoftwareConfig,
}

impl SoftwareSigner {
    pub fn new(app_name: &str) -> Self {
        Self {
            config: SoftwareConfig::new(app_name),
        }
    }

    pub fn with_keys_dir(app_name: &str, keys_dir: std::path::PathBuf) -> Self {
        Self {
            config: SoftwareConfig::with_keys_dir(app_name, keys_dir),
        }
    }

    /// Disable keyring-based key encryption (for testing or environments
    /// without a keyring daemon).
    ///
    /// When the `keyring-storage` feature is not enabled this is a no-op
    /// because keyring support is already absent.
    pub fn without_keyring(mut self) -> Self {
        self.config.use_keyring = false;
        self
    }
}

impl EnclaveKeyManager for SoftwareSigner {
    fn generate(&self, label: &str, key_type: KeyType, policy: AccessPolicy) -> Result<Vec<u8>> {
        validate_label(label)?;
        if key_type != KeyType::Signing {
            return Err(Error::KeyOperation {
                operation: "generate".into(),
                detail: "SoftwareSigner only supports signing keys".into(),
            });
        }
        let pub_key = key_storage::generate_and_save(&self.config, label, key_type, policy)?;

        // Stamp the per-key meta-integrity tag against the meta we
        // just wrote. `generate_and_save` already wrote
        // `<label>.meta` (with `app_specific = null`) and the
        // `.meta.hmac` sidecar; the higher sshenc layer will
        // re-stamp after appending its `app_specific` fields, so
        // this inline stamp serves the simpler awsenc / sso-jwt
        // callers (which don't have a SshencBackend overlay) and as
        // a fallback for the sshenc layer if the re-stamp fails.
        // Best-effort: a Secret Service hiccup leaves the user in
        // the legacy_meta state, recoverable via `migrate-meta`.
        //
        // Skip when `use_keyring=false` (test mode) — Secret Service
        // is not reachable in that configuration; see the parallel
        // gating in `ensure_meta_integrity`.
        if self.config.use_keyring {
            if let Ok(Some(hk)) = key_storage::meta_hmac_key_existing(&self.config.app_name) {
                let dir = self.config.keys_dir();
                if let Err(e) =
                    meta_tag::stamp_from_disk(&self.config.app_name, label, &dir, hk.as_slice())
                {
                    tracing::warn!(
                        label = label,
                        error = %e,
                        "post-keygen meta-tag stamp failed; key persisted without trust-anchor tag. \
                         Run `<app> migrate-meta` once the Secret Service is reachable."
                    );
                }
            }
        }

        Ok(pub_key)
    }

    fn public_key(&self, label: &str) -> Result<Vec<u8>> {
        validate_label(label)?;
        key_storage::load_public_key(&self.config, label)
    }

    fn list_keys(&self) -> Result<Vec<String>> {
        key_storage::list_labels(&self.config)
    }

    fn delete_key(&self, label: &str) -> Result<()> {
        validate_label(label)?;
        key_storage::delete_key(&self.config, label)
    }

    fn rename_key(&self, old_label: &str, new_label: &str) -> Result<()> {
        key_storage::rename_key(&self.config, old_label, new_label)
    }

    fn is_available(&self) -> bool {
        true
    }
}

/// Run the per-op meta-integrity check against the Secret-Service-
/// stored tag. Returns `Ok(())` on a clean verify, on a missing meta
/// file (`NoMeta` — caller's key-not-found flow handles it
/// downstream), and on `KeychainUnavailable` (fail-open; the
/// secret-key load below will produce its own clearer error if the
/// underlying store is truly broken).
///
/// Returns `Err` on **tamper** (Secret Service tag exists but
/// doesn't match the on-disk meta) and on **legacy** (no tag — pre-
/// migration key or attacker-induced state). Error messages mirror
/// the macOS / Windows wording so the user-facing UX is identical
/// across platforms.
///
/// **Linux specifics:** the keyring backend doesn't enforce
/// `AccessPolicy` at sign time, so the meta-integrity tag is the
/// ONLY defense against a same-UID attacker rewriting policy fields
/// in `.meta`. macOS / Windows have hardware-enforced policy bits
/// at the chip layer that catch some bypasses even if the trust
/// anchor is defeated; on Linux the trust anchor is the whole
/// defense for these fields.
///
/// `use_keyring` mirrors `SoftwareConfig::use_keyring`. When false
/// (the `without_keyring()` test mode) we skip the Secret Service
/// fetch entirely — the existing tests use that flag to avoid
/// keyring round-trips, and `keyring::Entry::get_secret()` would
/// otherwise BLOCK waiting for D-Bus session bus that test runners
/// don't have. Production callers always have it true.
fn ensure_meta_integrity(
    app_name: &str,
    label: &str,
    dir: &std::path::Path,
    use_keyring: bool,
) -> Result<()> {
    // CRITICAL: do not touch the Secret Service unless an on-disk
    // `.meta` actually exists. Without this guard, every synthetic
    // call site (test binary, fresh-install probe) would call into
    // `meta_hmac_key_existing` — which is a D-Bus round-trip even
    // on a fresh install with no entry, surfacing as a needless
    // ~50ms latency on every operation.
    let meta_path = dir.join(format!("{label}.meta"));
    if !meta_path.exists() {
        return Ok(());
    }

    // Honor `use_keyring=false` — without this guard, tests that
    // construct `SoftwareSigner::without_keyring()` to avoid Secret
    // Service interactions would hang here on `get_secret()`'s
    // D-Bus connect (the keyring crate blocks until session bus is
    // reachable). Production sshenc never sets this to false.
    if !use_keyring {
        return Ok(());
    }

    // Read-only meta-HMAC key fetch. The meta-HMAC key is created
    // on first keygen via `meta_hmac_key`; we use the read-only
    // `_existing` companion here so a verify can never trigger a
    // Secret Service write (which on a locked keyring would prompt
    // the user to unlock or fail silently).
    let hmac_key = match key_storage::meta_hmac_key_existing(app_name) {
        Ok(Some(k)) => k,
        Ok(None) | Err(_) => return Ok(()),
    };

    match meta_tag::verify(app_name, label, dir, hmac_key.as_slice())? {
        meta_tag::VerifyOutcome::Match
        | meta_tag::VerifyOutcome::NoMeta
        | meta_tag::VerifyOutcome::KeychainUnavailable => Ok(()),
        meta_tag::VerifyOutcome::Tamper => Err(Error::KeyOperation {
            operation: "meta_tag_verify".into(),
            detail: format!(
                "key '{label}': metadata integrity check failed. The on-disk meta \
                 does not match the keychain-stored tag — meta may have been \
                 tampered with. Refusing to proceed. Regenerate the key to restore \
                 a known-good state."
            ),
        }),
        meta_tag::VerifyOutcome::Legacy => {
            // Strong-tamper variant when the migrate-meta marker is
            // already set; gentle one-time-cutover variant otherwise.
            // Treat any Secret Service failure on the marker check
            // as "marker not set" so the gentle message wins on a
            // flaky-store host.
            let marker_set = meta_migration_marker::is_set(app_name).unwrap_or(false);
            if marker_set {
                Err(Error::KeyOperation {
                    operation: "meta_tag_legacy_post_migration".into(),
                    detail: format!(
                        "key '{label}' has no integrity tag, but `{app_name} migrate-meta` \
                         has already completed on this install. This is a strong tamper \
                         signal — legitimate operation should not produce a missing tag \
                         after the marker is set. Recommended: regenerate the affected \
                         key with `{app_name} keygen`. Do NOT run migrate-meta again \
                         unless you can independently explain why this key's tag is \
                         missing (e.g., manual restore from a backup of an unrelated \
                         machine), in which case pass \
                         `--force-rerun-i-understand` to override."
                    ),
                })
            } else {
                Err(Error::KeyOperation {
                    operation: "meta_tag_legacy".into(),
                    detail: format!(
                        "key '{label}' has no integrity tag. This is the one-time \
                         migration required by upgrading to a build that introduces meta \
                         integrity tags, and is not something future upgrades will repeat. \
                         Before migrating, verify the key's current policy looks correct: \
                         `{app_name} inspect {label}`. To migrate: `{app_name} \
                         migrate-meta`."
                    ),
                })
            }
        }
    }
}

impl EnclaveSigner for SoftwareSigner {
    fn sign(&self, label: &str, data: &[u8]) -> Result<Vec<u8>> {
        use p256::ecdsa::{signature::Signer, SigningKey};

        validate_label(label)?;

        // Per-op trust-anchor check before loading the private key
        // and producing a signature. On the keyring backend this is
        // the ONLY enforcement of the policy fields recorded in the
        // meta — `AccessPolicy` is not enforced at sign time on this
        // backend, so a same-UID attacker with `.meta` write access
        // could otherwise change `presence_mode` / `access_policy`
        // freely. The trust anchor catches that.
        let dir = self.config.keys_dir();
        ensure_meta_integrity(&self.config.app_name, label, &dir, self.config.use_keyring)?;

        let secret = key_storage::load_secret_key(&self.config, label)?;
        let signing_key = SigningKey::from(&secret);

        let signature: p256::ecdsa::DerSignature = signing_key.sign(data);
        Ok(signature.as_bytes().to_vec())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_dir() -> PathBuf {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("enclaveapp-sw-sign-test-{pid}-{id}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn generate_and_sign_produces_valid_der() {
        let dir = test_dir();
        let signer = SoftwareSigner::with_keys_dir("test", dir.clone()).without_keyring();

        signer
            .generate("sign-key", KeyType::Signing, AccessPolicy::None)
            .unwrap();
        let sig = signer.sign("sign-key", b"hello world").unwrap();

        // DER signature starts with SEQUENCE tag 0x30
        assert_eq!(sig[0], 0x30);
        // Typical P-256 DER signature is 70-72 bytes
        assert!(
            sig.len() >= 68 && sig.len() <= 73,
            "sig len = {}",
            sig.len()
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn sign_produces_different_output_for_different_data() {
        let dir = test_dir();
        let signer = SoftwareSigner::with_keys_dir("test", dir.clone()).without_keyring();

        signer
            .generate("diff-data", KeyType::Signing, AccessPolicy::None)
            .unwrap();
        let sig1 = signer.sign("diff-data", b"data one").unwrap();
        let sig2 = signer.sign("diff-data", b"data two").unwrap();
        assert_ne!(sig1, sig2);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn sign_fails_for_nonexistent_key() {
        let dir = test_dir();
        let signer = SoftwareSigner::with_keys_dir("test", dir.clone()).without_keyring();

        let err = signer.sign("ghost", b"data").unwrap_err();
        match err {
            Error::KeyNotFound { label } => assert_eq!(label, "ghost"),
            other => panic!("expected KeyNotFound, got: {other}"),
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn generate_rejects_encryption_key_type() {
        let dir = test_dir();
        let signer = SoftwareSigner::with_keys_dir("test", dir.clone()).without_keyring();

        let err = signer
            .generate("enc-key", KeyType::Encryption, AccessPolicy::None)
            .unwrap_err();
        match err {
            Error::KeyOperation { .. } => {}
            other => panic!("expected KeyOperation, got: {other}"),
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn public_key_matches_generated() {
        let dir = test_dir();
        let signer = SoftwareSigner::with_keys_dir("test", dir.clone()).without_keyring();

        let generated = signer
            .generate("pk-test", KeyType::Signing, AccessPolicy::None)
            .unwrap();
        let retrieved = signer.public_key("pk-test").unwrap();
        assert_eq!(generated, retrieved);
        assert_eq!(retrieved.len(), 65);
        assert_eq!(retrieved[0], 0x04);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn list_and_delete_lifecycle() {
        let dir = test_dir();
        let signer = SoftwareSigner::with_keys_dir("test", dir.clone()).without_keyring();

        assert!(signer.list_keys().unwrap().is_empty());

        signer
            .generate("key-a", KeyType::Signing, AccessPolicy::None)
            .unwrap();
        signer
            .generate("key-b", KeyType::Signing, AccessPolicy::None)
            .unwrap();
        assert_eq!(signer.list_keys().unwrap(), vec!["key-a", "key-b"]);

        signer.delete_key("key-a").unwrap();
        assert_eq!(signer.list_keys().unwrap(), vec!["key-b"]);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn is_available_returns_true() {
        let dir = test_dir();
        let signer = SoftwareSigner::with_keys_dir("test", dir.clone()).without_keyring();
        assert!(signer.is_available());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn software_signer_rejects_invalid_labels_across_operations() {
        let dir = test_dir();
        let signer = SoftwareSigner::with_keys_dir("test", dir.clone()).without_keyring();

        let err = signer.public_key("../escape").unwrap_err();
        assert!(matches!(err, Error::InvalidLabel { .. }));

        let err = signer.delete_key("../escape").unwrap_err();
        assert!(matches!(err, Error::InvalidLabel { .. }));

        let err = signer.sign("../escape", b"payload").unwrap_err();
        assert!(matches!(err, Error::InvalidLabel { .. }));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn signature_can_be_verified_with_public_key() {
        use p256::ecdsa::{signature::Verifier, VerifyingKey};

        let dir = test_dir();
        let signer = SoftwareSigner::with_keys_dir("test", dir.clone()).without_keyring();

        let pub_bytes = signer
            .generate("verify-test", KeyType::Signing, AccessPolicy::None)
            .unwrap();
        let data = b"test message for verification";
        let sig_bytes = signer.sign("verify-test", data).unwrap();

        // Reconstruct the verifying key from the public key bytes
        let point = p256::EncodedPoint::from_bytes(&pub_bytes).unwrap();
        let verifying_key = VerifyingKey::from_encoded_point(&point).unwrap();
        let signature = p256::ecdsa::DerSignature::from_bytes(&sig_bytes).unwrap();
        verifying_key.verify(data, &signature).unwrap();

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn generate_returns_valid_65_byte_pubkey() {
        let dir = test_dir();
        let signer = SoftwareSigner::with_keys_dir("test", dir.clone()).without_keyring();

        let pub_bytes = signer
            .generate("gen-pubkey", KeyType::Signing, AccessPolicy::None)
            .unwrap();
        assert_eq!(pub_bytes.len(), 65);
        assert_eq!(pub_bytes[0], 0x04, "SEC1 uncompressed point prefix");

        // Verify it's a valid P-256 point
        let pk = p256::PublicKey::from_sec1_bytes(&pub_bytes);
        assert!(pk.is_ok(), "must be a valid P-256 point");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn sign_is_deterministic_for_same_key_and_data() {
        let dir = test_dir();
        let signer = SoftwareSigner::with_keys_dir("test", dir.clone()).without_keyring();

        signer
            .generate("det-key", KeyType::Signing, AccessPolicy::None)
            .unwrap();

        // RFC 6979 deterministic signatures: same key + same data = same signature
        let sig1 = signer.sign("det-key", b"deterministic data").unwrap();
        let sig2 = signer.sign("det-key", b"deterministic data").unwrap();
        assert_eq!(sig1, sig2, "RFC 6979 signatures should be deterministic");

        // Different data should produce different signatures
        let sig3 = signer.sign("det-key", b"different data").unwrap();
        assert_ne!(sig1, sig3);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn list_keys_after_generate_includes_label() {
        let dir = test_dir();
        let signer = SoftwareSigner::with_keys_dir("test", dir.clone()).without_keyring();

        signer
            .generate("listed-key", KeyType::Signing, AccessPolicy::None)
            .unwrap();

        let keys = signer.list_keys().unwrap();
        assert!(
            keys.contains(&"listed-key".to_string()),
            "list_keys should include the generated label"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn delete_key_then_sign_returns_key_not_found() {
        let dir = test_dir();
        let signer = SoftwareSigner::with_keys_dir("test", dir.clone()).without_keyring();

        signer
            .generate("del-then-sign", KeyType::Signing, AccessPolicy::None)
            .unwrap();

        // Sign succeeds before deletion
        signer.sign("del-then-sign", b"data").unwrap();

        // Delete the key
        signer.delete_key("del-then-sign").unwrap();

        // Sign should now fail
        let err = signer.sign("del-then-sign", b"data").unwrap_err();
        match err {
            Error::KeyNotFound { label } => assert_eq!(label, "del-then-sign"),
            other => panic!("expected KeyNotFound, got: {other}"),
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn with_keys_dir_uses_custom_directory() {
        let dir = test_dir();
        let signer = SoftwareSigner::with_keys_dir("test", dir.clone()).without_keyring();

        signer
            .generate("custom-dir-key", KeyType::Signing, AccessPolicy::None)
            .unwrap();

        // Key files should be in our custom directory
        assert!(dir.join("custom-dir-key.key").exists());
        assert!(dir.join("custom-dir-key.pub").exists());
        assert!(dir.join("custom-dir-key.meta").exists());

        // Should NOT be in the default directory
        let default_dir = enclaveapp_core::metadata::keys_dir("test");
        assert!(!default_dir.join("custom-dir-key.key").exists());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn generate_with_invalid_label_returns_error() {
        let dir = test_dir();
        let signer = SoftwareSigner::with_keys_dir("test", dir.clone()).without_keyring();

        // Empty label
        let err = signer
            .generate("", KeyType::Signing, AccessPolicy::None)
            .unwrap_err();
        match err {
            Error::InvalidLabel { .. } => {}
            other => panic!("expected InvalidLabel for empty label, got: {other}"),
        }

        // Label with special characters
        let err = signer
            .generate("bad/label", KeyType::Signing, AccessPolicy::None)
            .unwrap_err();
        match err {
            Error::InvalidLabel { .. } => {}
            other => panic!("expected InvalidLabel for label with slash, got: {other}"),
        }

        // Label with spaces
        let err = signer
            .generate("bad label", KeyType::Signing, AccessPolicy::None)
            .unwrap_err();
        match err {
            Error::InvalidLabel { .. } => {}
            other => panic!("expected InvalidLabel for label with space, got: {other}"),
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
