// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Error types for hardware key operations.

use thiserror::Error;

/// Core error type shared across enclaveapp crates.
#[derive(Debug, Error)]
pub enum Error {
    #[error("hardware security module not available")]
    NotAvailable,

    #[error("key generation failed: {detail}")]
    GenerateFailed { detail: String },

    #[error("key not found: {label}")]
    KeyNotFound { label: String },

    #[error("duplicate key label: {label}")]
    DuplicateLabel { label: String },

    #[error("invalid key label: {reason}")]
    InvalidLabel { reason: String },

    #[error("signing failed: {detail}")]
    SignFailed { detail: String },

    #[error("encryption failed: {detail}")]
    EncryptFailed { detail: String },

    #[error("decryption failed: {detail}")]
    DecryptFailed { detail: String },

    #[error("key operation failed: {operation}: {detail}")]
    KeyOperation { operation: String, detail: String },

    /// The OS keychain refused access because the binary's code-signing
    /// identity has a "Deny" ACL entry.  Recovery: open Keychain Access,
    /// find the entry under "Passwords" and change "Deny" to "Always Allow".
    #[error(
        "keychain access denied for '{label}': the OS refused this binary's \
         request (ACL set to Deny); open Keychain Access → Passwords and set \
         'Always Allow' for sshenc-agent"
    )]
    KeychainAuthDenied { label: String },

    /// The keychain item requires user presence but no authenticated LAContext
    /// was provided — usually because `evaluatePolicy` was cancelled (screen
    /// locked, biometric dismissed).  Transient: retry after unlocking.
    #[error(
        "keychain interaction required for '{label}': the item needs user \
         authentication but none was provided (screen may be locked); \
         unlock the screen and retry"
    )]
    KeychainInteractionRequired { label: String },

    /// The agent process has no window server connection, so Touch ID UI
    /// cannot be displayed.  This happens when the agent is started outside
    /// of launchd (e.g. `sshenc-agent &` in a shell).  Recovery: restart
    /// the agent via launchd so it inherits the user's GUI session.
    #[error(
        "no window server access for '{label}': Touch ID requires a GUI session; \
         restart the agent via launchd: \
         launchctl load ~/Library/LaunchAgents/com.godaddy.sshenc.agent.plist"
    )]
    KeychainNoWindowServer { label: String },

    /// The user explicitly cancelled a Touch ID / biometric prompt.  The
    /// LAContext (if any) is still valid and should NOT be evicted — evicting
    /// it forces a fresh prompt on retry with no gain.  This is transient and
    /// expected: the caller may retry the operation, which will re-prompt.
    #[error("user cancelled authentication for '{label}'")]
    UserCancelled { label: String },

    #[error("config error: {0}")]
    Config(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(String),
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Serialization(e.to_string())
    }
}

impl From<toml::de::Error> for Error {
    fn from(e: toml::de::Error) -> Self {
        Error::Serialization(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn display_not_available() {
        let e = Error::NotAvailable;
        assert!(e.to_string().contains("not available"));
    }

    #[test]
    fn display_generate_failed() {
        let e = Error::GenerateFailed {
            detail: "timeout".into(),
        };
        assert!(e.to_string().contains("timeout"));
    }

    #[test]
    fn display_key_not_found() {
        let e = Error::KeyNotFound {
            label: "mykey".into(),
        };
        assert!(e.to_string().contains("mykey"));
    }

    #[test]
    fn display_duplicate_label() {
        let e = Error::DuplicateLabel {
            label: "dup".into(),
        };
        assert!(e.to_string().contains("dup"));
    }

    #[test]
    fn display_invalid_label() {
        let e = Error::InvalidLabel {
            reason: "empty".into(),
        };
        assert!(e.to_string().contains("empty"));
    }

    #[test]
    fn display_sign_failed() {
        let e = Error::SignFailed {
            detail: "hw error".into(),
        };
        assert!(e.to_string().contains("hw error"));
    }

    #[test]
    fn display_encrypt_failed() {
        let e = Error::EncryptFailed {
            detail: "bad key".into(),
        };
        assert!(e.to_string().contains("bad key"));
    }

    #[test]
    fn display_decrypt_failed() {
        let e = Error::DecryptFailed {
            detail: "corrupt".into(),
        };
        assert!(e.to_string().contains("corrupt"));
    }

    #[test]
    fn display_key_operation() {
        let e = Error::KeyOperation {
            operation: "export".into(),
            detail: "not supported".into(),
        };
        let msg = e.to_string();
        assert!(msg.contains("export"));
        assert!(msg.contains("not supported"));
    }

    #[test]
    fn display_keychain_auth_denied() {
        let e = Error::KeychainAuthDenied {
            label: "mykey".into(),
        };
        let msg = e.to_string();
        assert!(msg.contains("mykey"), "message must name the label");
        assert!(
            msg.contains("denied") || msg.contains("Deny"),
            "message must mention denial"
        );
        assert!(
            msg.contains("Keychain Access") || msg.contains("Always Allow"),
            "message must include remediation guidance"
        );
    }

    #[test]
    fn display_keychain_interaction_required() {
        let e = Error::KeychainInteractionRequired {
            label: "mykey".into(),
        };
        let msg = e.to_string();
        assert!(msg.contains("mykey"), "message must name the label");
        assert!(
            msg.contains("interaction") || msg.contains("authentication"),
            "message must mention authentication"
        );
        assert!(
            msg.contains("locked") || msg.contains("unlock") || msg.contains("retry"),
            "message must include recovery guidance"
        );
    }

    #[test]
    fn display_keychain_no_window_server() {
        let e = Error::KeychainNoWindowServer {
            label: "mykey".into(),
        };
        let msg = e.to_string();
        assert!(msg.contains("mykey"), "message must name the label");
        assert!(
            msg.contains("window server") || msg.contains("GUI"),
            "message must mention window server"
        );
        assert!(
            msg.contains("launchctl") || msg.contains("launchd"),
            "message must include launchd remediation guidance"
        );
    }

    #[test]
    fn display_user_cancelled() {
        let e = Error::UserCancelled {
            label: "mykey".into(),
        };
        let msg = e.to_string();
        assert!(msg.contains("mykey"), "message must name the label");
        assert!(
            msg.contains("cancel") || msg.contains("cancelled"),
            "message must mention cancellation"
        );
    }

    #[test]
    fn display_config() {
        let e = Error::Config("missing field".into());
        assert!(e.to_string().contains("missing field"));
    }

    #[test]
    fn display_serialization() {
        let e = Error::Serialization("bad json".into());
        assert!(e.to_string().contains("bad json"));
    }

    #[test]
    fn from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let e: Error = io_err.into();
        match &e {
            Error::Io(_) => {}
            other => panic!("expected Error::Io, got: {other}"),
        }
        assert!(e.to_string().contains("file missing"));
    }

    #[test]
    fn from_serde_json_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("not json").unwrap_err();
        let e: Error = json_err.into();
        match &e {
            Error::Serialization(_) => {}
            other => panic!("expected Error::Serialization, got: {other}"),
        }
    }

    #[test]
    fn from_toml_de_error() {
        let toml_err = toml::from_str::<toml::Value>("= invalid").unwrap_err();
        let e: Error = toml_err.into();
        match &e {
            Error::Serialization(_) => {}
            other => panic!("expected Error::Serialization, got: {other}"),
        }
    }
}
