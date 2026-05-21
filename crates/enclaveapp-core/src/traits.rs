// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Core trait hierarchy for hardware-backed key management backends.

use crate::{AccessPolicy, KeyType, PresenceMode, Result};

/// Core key management operations. Every platform backend implements this.
pub trait EnclaveKeyManager: Send + Sync {
    /// Generate a new hardware-bound key.
    /// Returns the 65-byte uncompressed SEC1 public key (0x04 || X || Y).
    fn generate(&self, label: &str, key_type: KeyType, policy: AccessPolicy) -> Result<Vec<u8>>;

    /// Get the public key for an existing key.
    /// Returns the 65-byte uncompressed SEC1 public key.
    fn public_key(&self, label: &str) -> Result<Vec<u8>>;

    /// List all key labels managed by this application.
    fn list_keys(&self) -> Result<Vec<String>>;

    /// Delete a key and all associated metadata/files.
    fn delete_key(&self, label: &str) -> Result<()>;

    /// Check if the hardware security backend is available on this system.
    fn is_available(&self) -> bool;

    /// Check whether a key with this label exists, without creating it.
    ///
    /// Backends that route through the WSL bridge MUST override this —
    /// the default implementation calls `public_key`, which on the bridge
    /// has load-or-create semantics and would create the key as a
    /// side effect. Native backends return `KeyNotFound` from
    /// `public_key` for missing keys, so the default is safe there.
    fn key_exists(&self, label: &str) -> Result<bool> {
        match self.public_key(label) {
            Ok(_) => Ok(true),
            Err(crate::Error::KeyNotFound { .. }) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Rename a key from `old_label` to `new_label`, preserving all
    /// backend-specific state (hardware handles, keychain entries, etc.)
    /// and on-disk metadata. Fails if `new_label` already exists.
    ///
    /// Backends that store extra state keyed by the label (e.g. macOS
    /// keychain wrapping-key entries) MUST override this so the rename
    /// stays consistent. The default implementation only renames the
    /// on-disk metadata files and is correct for backends whose key
    /// material lives entirely on disk (software / keyring backends).
    fn rename_key(&self, old_label: &str, new_label: &str) -> Result<()> {
        let _ = (old_label, new_label);
        Err(crate::Error::KeyOperation {
            operation: "rename_key".into(),
            detail: "this backend does not implement rename_key; \
                     caller must implement the rename using the backend's \
                     native primitives"
                .into(),
        })
    }
}

/// ECDSA signing operations. Used by sshenc for SSH key signing.
pub trait EnclaveSigner: EnclaveKeyManager {
    /// Sign a message using the hardware-bound private key.
    ///
    /// On macOS (CryptoKit), the message is hashed internally with SHA-256.
    /// On Windows (CNG), the implementation pre-hashes with SHA-256 then calls NCryptSignHash.
    ///
    /// Returns a DER-encoded ECDSA signature.
    fn sign(&self, label: &str, data: &[u8]) -> Result<Vec<u8>>;

    /// Sign a message with explicit user-presence cadence.
    ///
    /// `mode` controls whether the underlying SEP / TPM prompt is batched
    /// within `cache_ttl_secs` (`PresenceMode::Cached`), required per sign
    /// (`PresenceMode::Strict`), or not required at all (`PresenceMode::None`).
    /// `cache_ttl_secs == 0` collapses `Cached` into `Strict`.
    ///
    /// `reason` is shown verbatim in the Touch ID / biometric dialog as the
    /// `localizedReason`. Callers should include context like the operation
    /// type and key label, e.g. `"sshenc: sign git commit (work-key)"`.
    ///
    /// The default impl ignores `mode`, `cache_ttl_secs`, and `reason` and
    /// falls back to [`sign`]. Only macOS overrides this; it batches Touch ID
    /// prompts within `cache_ttl_secs` when `PresenceMode::Cached`.
    ///
    /// Linux TPM and software backends keep the default. Neither enforces
    /// user presence at sign time — `AccessPolicy` is stored in key metadata
    /// but is not consulted during signing. Keys created with
    /// `AccessPolicy::Any` or `AccessPolicy::BiometricOnly` on Linux sign
    /// without any interactive prompt.
    fn sign_with_presence(
        &self,
        label: &str,
        data: &[u8],
        mode: PresenceMode,
        cache_ttl_secs: u64,
        reason: &str,
    ) -> Result<Vec<u8>> {
        let _ = (mode, cache_ttl_secs, reason);
        self.sign(label, data)
    }

    /// Evict cached wrapping key and LAContext for `label`, forcing the next
    /// operation to reload from the keychain with fresh authentication.
    fn evict_wrapping_key_cache(&self, _label: &str) {}
}

/// ECIES encryption operations. Used by awsenc and sso-jwt for credential caching.
pub trait EnclaveEncryptor: EnclaveKeyManager {
    /// Encrypt plaintext using the key's public key via ECIES.
    ///
    /// The implementation generates an ephemeral ECDH key pair, derives a
    /// shared secret with the stored key's public key, and encrypts with AES-GCM.
    ///
    /// Returns the ciphertext in the format:
    /// `[1-byte version 0x01] [65-byte ephemeral pubkey] [12-byte nonce] [ciphertext] [16-byte GCM tag]`
    fn encrypt(&self, label: &str, plaintext: &[u8]) -> Result<Vec<u8>>;

    /// Decrypt ciphertext using the hardware-bound private key.
    ///
    /// The implementation performs ECDH with the ephemeral public key from the
    /// ciphertext, derives the shared secret, and decrypts with AES-GCM.
    fn decrypt(&self, label: &str, ciphertext: &[u8]) -> Result<Vec<u8>>;
}
