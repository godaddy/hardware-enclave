// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The hardware security module is absent, not enrolled, or unreachable.
    #[error("hardware security module not available")]
    NotAvailable,
    /// No key with the given label exists in this app's key store.
    #[error("key not found: {label}")]
    KeyNotFound { label: String },
    /// A key with this label already exists.
    #[error("duplicate key label: {label}")]
    DuplicateLabel { label: String },
    /// The label is syntactically invalid (empty, too long, or contains illegal characters).
    #[error("invalid key label: {reason}")]
    InvalidLabel { reason: String },
    /// The signing operation failed.
    #[error("signing failed: {detail}")]
    SignFailed { detail: String },
    /// The encryption operation failed.
    #[error("encryption failed: {detail}")]
    EncryptFailed { detail: String },
    /// The decryption operation failed; the ciphertext may be corrupt or have been tampered with.
    #[error("decryption failed: {detail}")]
    DecryptFailed { detail: String },
    /// The OS keychain / TPM ACL has a Deny entry for this binary.
    #[error("authentication denied for '{label}'")]
    AuthDenied { label: String },
    /// User authentication is required but the device is locked or no GUI session is available.
    #[error("authentication required for '{label}': {detail}")]
    AuthRequired { label: String, detail: String },
    /// The user dismissed the biometric or PIN prompt.
    #[error("user cancelled authentication for '{label}'")]
    UserCancelled { label: String },
    /// A lower-level key operation failed.
    #[error("key operation failed — {operation}: {detail}")]
    KeyOperation { operation: String, detail: String },
    /// File HMAC mismatch — the file has been modified outside the API.
    #[error("tamper detected: {path}")]
    TamperDetected { path: String },
    /// Returned from factory construction (not first use) when a config option
    /// requires a code-signed binary with the named entitlement/feature.
    ///
    /// The requested configuration requires a code-signed binary with a specific entitlement.
    #[error("feature '{feature}' requires a code-signed binary")]
    RequiresSigning { feature: String },
    /// The backend cannot enforce the requested `AccessPolicy` (e.g. `BiometricOnly` on Linux).
    ///
    /// Returned from `generate_key()` when the backend cannot enforce the
    /// requested `AccessPolicy` (e.g. `BiometricOnly` on Linux keyring/TPM).
    #[error("access policy '{policy}' is not supported by the current backend")]
    PolicyNotSupported { policy: String },
    /// `sign_with_presence(Strict, ...)` was called on a platform without biometric support.
    ///
    /// Returned from `sign_with_presence()` when `PresenceMode::Strict` is
    /// requested but the platform has no user-presence support.
    #[error("user presence is not available on this platform")]
    PresenceNotAvailable,
    /// This API is not yet fully implemented on this platform. Check the `feature` string.
    #[error("not implemented: {feature}")]
    NotImplemented { feature: String },
    /// The key's stored access policy does not match. Regenerate the key.
    ///
    /// This typically indicates the key was generated with a different policy
    /// and should be regenerated.
    #[error("access policy mismatch: {detail}")]
    PolicyMismatch { detail: String },
    /// A configuration value is invalid.
    #[error("config error: {0}")]
    Config(String),
    /// An I/O error occurred.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// An in-process memory protection operation failed (guard-page allocation, mlock, etc.).
    #[error("memory error: {0}")]
    Memory(String),
}

/// Shorthand `Result` type for this crate.
pub type Result<T> = std::result::Result<T, Error>;

impl From<enclaveapp_core::Error> for Error {
    fn from(e: enclaveapp_core::Error) -> Self {
        use enclaveapp_core::Error as CE;
        match e {
            CE::NotAvailable => Error::NotAvailable,
            CE::KeyNotFound { label } => Error::KeyNotFound { label },
            CE::DuplicateLabel { label } => Error::DuplicateLabel { label },
            CE::InvalidLabel { reason } => Error::InvalidLabel { reason },
            CE::SignFailed { detail } => Error::SignFailed { detail },
            CE::EncryptFailed { detail } => Error::EncryptFailed { detail },
            CE::DecryptFailed { detail } => Error::DecryptFailed { detail },
            CE::KeychainAuthDenied { label } => Error::AuthDenied { label },
            CE::KeychainInteractionRequired { label } => Error::AuthRequired {
                label,
                detail: "screen may be locked; unlock and retry".into(),
            },
            CE::KeychainNoWindowServer { label } => Error::AuthRequired {
                label,
                detail: "no GUI session; restart agent via launchd".into(),
            },
            CE::UserCancelled { label } => Error::UserCancelled { label },
            CE::KeyOperation { operation, detail } => Error::KeyOperation { operation, detail },
            CE::GenerateFailed { detail } => Error::KeyOperation {
                operation: "generate".into(),
                detail,
            },
            CE::Config(s) | CE::Serialization(s) => Error::Config(s),
            CE::Io(e) => Error::Io(e),
            // non_exhaustive fallback — add explicit arms for new enclaveapp_core::Error
            // variants as they are introduced
            other => Error::KeyOperation {
                operation: "unknown".into(),
                detail: other.to_string(),
            },
        }
    }
}

impl From<enclaveapp_app_storage::StorageError> for Error {
    fn from(e: enclaveapp_app_storage::StorageError) -> Self {
        use enclaveapp_app_storage::StorageError as SE;
        match e {
            SE::NotAvailable => Error::NotAvailable,
            SE::EncryptionFailed(s) => Error::EncryptFailed { detail: s },
            SE::DecryptionFailed(s) => Error::DecryptFailed { detail: s },
            SE::SigningFailed(s) => Error::SignFailed { detail: s },
            SE::KeyInitFailed(s) => Error::KeyOperation {
                operation: "init".into(),
                detail: s,
            },
            SE::KeyNotFound(s) => Error::KeyNotFound { label: s },
            SE::PolicyMismatch(s) => Error::PolicyMismatch { detail: s },
            SE::PlatformError(s) => Error::KeyOperation {
                operation: "platform".into(),
                detail: s,
            },
            // non_exhaustive fallback — add explicit arms for new StorageError
            // variants as they are introduced
            other => Error::KeyOperation {
                operation: "unknown".into(),
                detail: other.to_string(),
            },
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use enclaveapp_app_storage::StorageError;

    #[test]
    fn from_storage_error_policy_mismatch_preserves_detail() {
        let e: Error = StorageError::PolicyMismatch("None vs BiometricOnly".into()).into();
        match e {
            Error::PolicyMismatch { detail } => {
                assert!(detail.contains("BiometricOnly"));
            }
            other => panic!("expected PolicyMismatch, got {other:?}"),
        }
    }

    #[test]
    fn from_storage_error_all_variants_convert() {
        // Verify none of the conversions panic
        let variants: Vec<StorageError> = vec![
            StorageError::NotAvailable,
            StorageError::EncryptionFailed("e".into()),
            StorageError::DecryptionFailed("d".into()),
            StorageError::SigningFailed("s".into()),
            StorageError::KeyInitFailed("k".into()),
            StorageError::KeyNotFound("n".into()),
            StorageError::PolicyMismatch("p".into()),
            StorageError::PlatformError("pl".into()),
        ];
        for v in variants {
            drop(Error::from(v));
        }
    }
}
