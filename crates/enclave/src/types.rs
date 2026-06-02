// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

pub use enclaveapp_app_storage::BackendKind;
pub use enclaveapp_core::types::{AccessPolicy, KeyType, PresenceMode};

/// Public projection of key metadata. Does not expose serde_json::Value.
#[derive(Debug, Clone)]
pub struct KeyInfo {
    /// The key's label as passed to `generate_key()`.
    pub label: String,
    /// Whether this is a signing or encryption key.
    pub key_type: KeyType,
    /// The key's access policy, if determinable. `None` when metadata is unavailable.
    ///
    /// `None` means the policy was not available (e.g., metadata read failed or
    /// the backend does not expose policy metadata via `list_keys()`). Callers
    /// must check for `None` and not assume a default policy.
    pub access_policy: Option<AccessPolicy>,
    /// Uncompressed SEC1 P-256 public key: `0x04 || X (32 bytes) || Y (32 bytes)`.
    pub public_key: Vec<u8>,
}

/// Options controlling the user-presence prompt for [`SignerHandle::sign_with_presence`][crate::signing::SignerHandle::sign_with_presence].
///
/// The `mode` field determines whether a prompt fires; `cache_ttl_secs` controls
/// how long a successful authentication suppresses subsequent prompts (macOS only);
/// `reason` is the human-readable string shown in the biometric dialog.
#[derive(Debug, Clone)]
pub struct PresenceOptions {
    /// Controls when the biometric/PIN prompt fires.
    pub mode: PresenceMode,
    /// How long a successful authentication suppresses subsequent prompts.
    /// Effective only on macOS (LAContext TTL); ignored on other platforms.
    /// `0` means prompt on every call.
    pub cache_ttl_secs: u64,
    /// Human-readable reason shown in the Touch ID / Windows Hello dialog.
    pub reason: String,
}

impl PresenceOptions {
    /// Create options that always prompt (no caching). Equivalent to `PresenceMode::Strict`
    /// with `cache_ttl_secs = 0`.
    pub fn strict(reason: impl Into<String>) -> Self {
        Self {
            mode: PresenceMode::Strict,
            cache_ttl_secs: 0,
            reason: reason.into(),
        }
    }

    /// Create options that cache a successful authentication for `ttl_secs` seconds
    /// before prompting again. Uses `PresenceMode::Cached`.
    pub fn cached(reason: impl Into<String>, ttl_secs: u64) -> Self {
        Self {
            mode: PresenceMode::Cached,
            cache_ttl_secs: ttl_secs,
            reason: reason.into(),
        }
    }
}
