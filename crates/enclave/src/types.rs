// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

pub use enclaveapp_app_storage::BackendKind;
pub use enclaveapp_core::types::{AccessPolicy, KeyType, PresenceMode};

/// Public projection of key metadata. Does not expose serde_json::Value.
#[derive(Debug, Clone)]
pub struct KeyInfo {
    pub label: String,
    pub key_type: KeyType,
    /// The key's access policy, if it could be determined.
    /// `None` means the policy was not available (e.g., metadata read failed or
    /// the backend does not expose policy metadata via `list_keys()`). Callers
    /// must check for `None` and not assume a default policy.
    pub access_policy: Option<AccessPolicy>,
    /// Uncompressed SEC1 public key (0x04 || X || Y, 65 bytes).
    pub public_key: Vec<u8>,
}

/// Options for sign_with_presence().
#[derive(Debug, Clone)]
pub struct PresenceOptions {
    pub mode: PresenceMode,
    /// How long a presence token may be reused (macOS LAContext TTL).
    pub cache_ttl_secs: u64,
    /// Human-readable reason shown in the OS prompt.
    pub reason: String,
}

impl PresenceOptions {
    pub fn strict(reason: impl Into<String>) -> Self {
        Self {
            mode: PresenceMode::Strict,
            cache_ttl_secs: 0,
            reason: reason.into(),
        }
    }

    pub fn cached(reason: impl Into<String>, ttl_secs: u64) -> Self {
        Self {
            mode: PresenceMode::Cached,
            cache_ttl_secs: ttl_secs,
            reason: reason.into(),
        }
    }
}
