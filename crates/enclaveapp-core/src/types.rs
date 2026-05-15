// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Core types for hardware-backed key management.

use serde::{Deserialize, Serialize};

/// Key type determines what crypto operations are available.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyType {
    /// ECDSA P-256 signing key (SSH keys, git commit signing).
    #[default]
    Signing,
    /// ECDH P-256 key agreement key (ECIES encryption for credential caching).
    Encryption,
}

/// Access control policy for hardware key usage.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessPolicy {
    /// No user interaction required.
    #[default]
    None,
    /// Any user authentication (Touch ID, password, or PIN).
    Any,
    /// Biometric only (Touch ID / fingerprint).
    BiometricOnly,
    /// Password / PIN only.
    PasswordOnly,
}

/// User-presence prompt cadence for sign operations.
///
/// Orthogonal to [`AccessPolicy`]: `AccessPolicy` says *what* counts as
/// authentication (e.g. fingerprint vs. passcode); `PresenceMode` says *how
/// often* the user must reproduce it.
///
/// On macOS the choice is implemented by passing (or omitting) a long-lived
/// `LAContext` to CryptoKit's `SecureEnclave.P256.Signing.PrivateKey`.
///
/// Other platforms do not have an analogous cached-context concept and treat
/// all variants identically:
///
/// - **Windows TPM (CNG):** The hardware enforces `NCRYPT_UI_POLICY` per
///   sign, so every signature triggers a fresh Windows Hello prompt.
/// - **Linux TPM and software / keyring backends:** No gate at all.
///   `AccessPolicy` is stored in metadata but is not consulted at sign or
///   decrypt time, so all `PresenceMode` variants behave the same as
///   `PresenceMode::None`. See the "Linux TPM backend" section of
///   `THREAT_MODEL.md`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PresenceMode {
    /// User-presence prompt batched within a TTL window. The first sign
    /// after the cache is cold prompts; subsequent signs within the cache
    /// TTL reuse the same `LAContext` and are silent. This is the default
    /// for any new key created with user-presence enabled.
    #[default]
    Cached,
    /// User-presence prompt on every sign. The agent does not pass a
    /// long-lived `LAContext`, so the SEP enforces a fresh authentication
    /// per signature.
    Strict,
    /// No user-presence prompt. The key has `AccessPolicy::None` (or its
    /// platform equivalent) and signs silently regardless of cache state.
    None,
}

impl PresenceMode {
    /// Migration default for keys whose `.meta` predates `presence_mode`:
    /// historically, a key with any access policy other than `None`
    /// effectively had `Strict` semantics (one prompt per sign), and a
    /// key with `None` was silent. Use this when reading a legacy
    /// `.meta` file with no `presence_mode` field.
    pub fn migration_default(policy: AccessPolicy) -> Self {
        match policy {
            AccessPolicy::None => PresenceMode::None,
            _ => PresenceMode::Strict,
        }
    }
}

impl AccessPolicy {
    /// Convert to the integer used by the CryptoKit/CNG FFI layer.
    pub fn as_ffi_value(&self) -> i32 {
        match self {
            AccessPolicy::None => 0,
            AccessPolicy::Any => 1,
            AccessPolicy::BiometricOnly => 2,
            AccessPolicy::PasswordOnly => 3,
        }
    }

    /// Create from FFI integer value.
    pub fn from_ffi_value(val: i32) -> Self {
        match val {
            1 => AccessPolicy::Any,
            2 => AccessPolicy::BiometricOnly,
            3 => AccessPolicy::PasswordOnly,
            _ => AccessPolicy::None,
        }
    }
}

/// Validate a key label. Labels must be non-empty, ASCII alphanumeric plus
/// hyphens and underscores, and at most 64 characters.
pub fn validate_label(label: &str) -> crate::Result<()> {
    if label.is_empty() {
        return Err(crate::Error::InvalidLabel {
            reason: "label cannot be empty".into(),
        });
    }
    if label.len() > 64 {
        return Err(crate::Error::InvalidLabel {
            reason: "label cannot exceed 64 characters".into(),
        });
    }
    if !label
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(crate::Error::InvalidLabel {
            reason: "label must be ASCII alphanumeric, hyphens, or underscores".into(),
        });
    }
    Ok(())
}

/// Validate a 65-byte uncompressed P-256 SEC1 point (0x04 || X || Y).
pub fn validate_p256_point(bytes: &[u8]) -> crate::Result<()> {
    if bytes.len() != 65 {
        return Err(crate::Error::KeyOperation {
            operation: "validate_point".into(),
            detail: format!("expected 65 bytes, got {}", bytes.len()),
        });
    }
    if bytes[0] != 0x04 {
        return Err(crate::Error::KeyOperation {
            operation: "validate_point".into(),
            detail: format!(
                "expected uncompressed point prefix 0x04, got 0x{:02x}",
                bytes[0]
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn validate_label_valid() {
        assert!(validate_label("default").is_ok());
        assert!(validate_label("my-key").is_ok());
        assert!(validate_label("key_123").is_ok());
        assert!(validate_label("A").is_ok());
        // Max 64 chars
        let max_label = "a".repeat(64);
        assert!(validate_label(&max_label).is_ok());
    }

    #[test]
    fn validate_label_rejects_empty() {
        assert!(validate_label("").is_err());
    }

    #[test]
    fn validate_label_rejects_too_long() {
        let long_label = "a".repeat(65);
        assert!(validate_label(&long_label).is_err());
    }

    #[test]
    fn validate_label_rejects_spaces() {
        assert!(validate_label("my key").is_err());
    }

    #[test]
    fn validate_label_rejects_dots() {
        assert!(validate_label("my.key").is_err());
    }

    #[test]
    fn validate_label_rejects_slashes() {
        assert!(validate_label("my/key").is_err());
        assert!(validate_label("my\\key").is_err());
    }

    #[test]
    fn validate_label_rejects_unicode() {
        assert!(validate_label("caf\u{00e9}").is_err());
    }

    #[test]
    fn validate_p256_point_valid() {
        let mut point = vec![0x04];
        point.extend_from_slice(&[0xAA; 64]);
        assert!(validate_p256_point(&point).is_ok());
    }

    #[test]
    fn validate_p256_point_wrong_length_short() {
        let point = vec![0x04; 64];
        assert!(validate_p256_point(&point).is_err());
    }

    #[test]
    fn validate_p256_point_wrong_length_long() {
        let point = vec![0x04; 66];
        assert!(validate_p256_point(&point).is_err());
    }

    #[test]
    fn validate_p256_point_wrong_prefix_compressed() {
        let mut point = vec![0x02];
        point.extend_from_slice(&[0xAA; 64]);
        assert!(validate_p256_point(&point).is_err());
    }

    #[test]
    fn validate_p256_point_wrong_prefix_compressed_odd() {
        let mut point = vec![0x03];
        point.extend_from_slice(&[0xAA; 64]);
        assert!(validate_p256_point(&point).is_err());
    }

    #[test]
    fn access_policy_ffi_roundtrip() {
        let policies = [
            AccessPolicy::None,
            AccessPolicy::Any,
            AccessPolicy::BiometricOnly,
            AccessPolicy::PasswordOnly,
        ];
        for policy in &policies {
            let ffi = policy.as_ffi_value();
            let roundtripped = AccessPolicy::from_ffi_value(ffi);
            assert_eq!(*policy, roundtripped);
        }
    }

    #[test]
    fn access_policy_unknown_ffi_defaults_to_none() {
        assert_eq!(AccessPolicy::from_ffi_value(99), AccessPolicy::None);
        assert_eq!(AccessPolicy::from_ffi_value(-1), AccessPolicy::None);
    }

    #[test]
    fn access_policy_default_is_none() {
        assert_eq!(AccessPolicy::default(), AccessPolicy::None);
    }

    #[test]
    fn key_type_serde_roundtrip_signing() {
        let json = serde_json::to_string(&KeyType::Signing).unwrap();
        assert_eq!(json, "\"signing\"");
        let parsed: KeyType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, KeyType::Signing);
    }

    #[test]
    fn key_type_serde_roundtrip_encryption() {
        let json = serde_json::to_string(&KeyType::Encryption).unwrap();
        assert_eq!(json, "\"encryption\"");
        let parsed: KeyType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, KeyType::Encryption);
    }

    #[test]
    fn presence_mode_default_is_cached() {
        assert_eq!(PresenceMode::default(), PresenceMode::Cached);
    }

    #[test]
    fn presence_mode_migration_default_none_policy_gives_none() {
        assert_eq!(
            PresenceMode::migration_default(AccessPolicy::None),
            PresenceMode::None
        );
    }

    #[test]
    fn presence_mode_migration_default_any_policy_gives_strict() {
        assert_eq!(
            PresenceMode::migration_default(AccessPolicy::Any),
            PresenceMode::Strict
        );
    }

    #[test]
    fn presence_mode_migration_default_biometric_gives_strict() {
        assert_eq!(
            PresenceMode::migration_default(AccessPolicy::BiometricOnly),
            PresenceMode::Strict
        );
    }

    #[test]
    fn presence_mode_migration_default_password_gives_strict() {
        assert_eq!(
            PresenceMode::migration_default(AccessPolicy::PasswordOnly),
            PresenceMode::Strict
        );
    }

    #[test]
    fn presence_mode_serde_roundtrip_all_variants() {
        let variants = [
            PresenceMode::Cached,
            PresenceMode::Strict,
            PresenceMode::None,
        ];
        for mode in &variants {
            let json = serde_json::to_string(mode).unwrap();
            let parsed: PresenceMode = serde_json::from_str(&json).unwrap();
            assert_eq!(*mode, parsed);
        }
    }

    #[test]
    fn presence_mode_serde_wire_strings() {
        assert_eq!(
            serde_json::to_string(&PresenceMode::Cached).unwrap(),
            "\"cached\""
        );
        assert_eq!(
            serde_json::to_string(&PresenceMode::Strict).unwrap(),
            "\"strict\""
        );
        assert_eq!(
            serde_json::to_string(&PresenceMode::None).unwrap(),
            "\"none\""
        );
    }

    #[test]
    fn validate_p256_point_empty_input_is_error() {
        assert!(validate_p256_point(&[]).is_err());
    }

    #[test]
    fn validate_p256_point_exact_length_wrong_prefix() {
        let mut point = vec![0x00];
        point.extend_from_slice(&[0xBB; 64]);
        assert!(validate_p256_point(&point).is_err());
    }

    #[test]
    fn validate_label_exactly_64_chars_is_valid() {
        let label = "a".repeat(64);
        assert!(validate_label(&label).is_ok());
    }

    #[test]
    fn validate_label_65_chars_is_rejected() {
        let label = "a".repeat(65);
        let err = validate_label(&label).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("64") || msg.to_lowercase().contains("exceed"));
    }

    #[test]
    fn validate_label_hyphens_and_underscores_allowed() {
        assert!(validate_label("my-key_v2").is_ok());
        assert!(validate_label("---").is_ok());
        assert!(validate_label("___").is_ok());
    }

    #[test]
    fn access_policy_ffi_roundtrip_all_variants() {
        for policy in [
            AccessPolicy::None,
            AccessPolicy::Any,
            AccessPolicy::BiometricOnly,
            AccessPolicy::PasswordOnly,
        ] {
            assert_eq!(AccessPolicy::from_ffi_value(policy.as_ffi_value()), policy);
        }
    }
}
