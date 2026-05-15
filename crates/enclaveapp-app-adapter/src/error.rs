use thiserror::Error;

#[derive(Debug, Error)]
pub enum AdapterError {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("unable to determine configuration directory")]
    MissingConfigDir,

    #[error("unable to determine home directory")]
    MissingHomeDir,

    #[error("program not found: {0}")]
    ProgramNotFound(String),

    #[error("shell resolution for `{command}` returned an unsupported result: {raw}")]
    UnsupportedShellResolution { command: String, raw: String },

    #[error("command -v failed for `{command}`: {stderr}")]
    CommandVFailed { command: String, stderr: String },

    #[error("no supported integration type was provided")]
    NoSupportedIntegration,

    #[error("storage error: {0}")]
    Storage(String),

    #[error("missing secret for binding `{0}`")]
    MissingSecret(String),

    #[error("configuration override is required for this integration mode")]
    MissingConfigOverride,

    #[error("application `{app}` does not support integration type `{integration}`")]
    UnsupportedIntegration { app: String, integration: String },

    #[error("no available prepared integration candidate matched the application support matrix")]
    NoAvailableIntegrationCandidate,
}

impl From<enclaveapp_app_storage::StorageError> for AdapterError {
    fn from(value: enclaveapp_app_storage::StorageError) -> Self {
        Self::Storage(value.to_string())
    }
}

pub type Result<T> = std::result::Result<T, AdapterError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_variants_display_nonempty_messages() {
        let variants: Vec<AdapterError> = vec![
            AdapterError::Io(std::io::Error::other("io")),
            AdapterError::Json(
                serde_json::from_str::<()>("bad").expect_err("intentionally bad JSON"),
            ),
            AdapterError::MissingConfigDir,
            AdapterError::MissingHomeDir,
            AdapterError::ProgramNotFound("prog".into()),
            AdapterError::UnsupportedShellResolution {
                command: "cmd".into(),
                raw: "raw".into(),
            },
            AdapterError::CommandVFailed {
                command: "cmd".into(),
                stderr: "err".into(),
            },
            AdapterError::NoSupportedIntegration,
            AdapterError::Storage("details".into()),
            AdapterError::MissingSecret("binding".into()),
            AdapterError::MissingConfigOverride,
            AdapterError::UnsupportedIntegration {
                app: "app".into(),
                integration: "T1".into(),
            },
            AdapterError::NoAvailableIntegrationCandidate,
        ];
        for variant in &variants {
            let msg = variant.to_string();
            assert!(!msg.is_empty(), "Display for {variant:?} must not be empty");
        }
    }

    #[test]
    fn from_storage_error_produces_storage_variant() {
        use enclaveapp_app_storage::StorageError;
        let storage_err = StorageError::EncryptionFailed("test encryption error".into());
        let adapter_err = AdapterError::from(storage_err);
        assert!(matches!(adapter_err, AdapterError::Storage(_)));
        let msg = adapter_err.to_string();
        assert!(msg.contains("test encryption error"), "message: {msg}");
    }
}
