// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

use crate::error::{Error, Result};
use crate::types::BackendKind;

/// Capabilities of the current platform's authentication subsystem.
#[derive(Debug, Clone)]
pub struct AuthCapabilities {
    /// Biometric authenticator available (Touch ID, Windows Hello fingerprint).
    pub biometric_available: bool,
    /// Password/PIN fallback available in the same auth flow.
    pub password_available: bool,
    /// Presence prompts can be cached across ops within a TTL (macOS LAContext only).
    pub presence_caching: bool,
    /// Human-readable authenticator name, if known.
    pub authenticator_name: Option<String>,
}

/// Handle to the platform authentication subsystem.
/// Obtained from `create_auth()`.
#[derive(Debug)]
pub struct AuthHandle {
    backend_kind: BackendKind,
}

impl AuthHandle {
    pub(crate) fn new(backend_kind: BackendKind) -> Self {
        Self { backend_kind }
    }

    pub fn capabilities(&self) -> AuthCapabilities {
        platform_auth_capabilities()
    }

    /// Request user-presence verification. Returns `Ok(())` if granted.
    /// `reason` is shown in the OS prompt.
    ///
    /// **Phase 2 stub.** Standalone presence acquisition (separate from
    /// per-operation `sign_with_presence`) requires LAContext/UserConsentVerifier
    /// integration not yet implemented. Returns `Error::NotImplemented` so that
    /// callers cannot silently treat this as a success.
    pub fn request_presence(&self, _reason: &str) -> Result<()> {
        if !self.capabilities().biometric_available {
            return Err(Error::PresenceNotAvailable);
        }
        // Standalone presence acquisition (separate from per-operation sign_with_presence)
        // requires LAContext/UserConsentVerifier integration, implemented in Phase 2.
        // Return a distinct error so callers cannot accidentally treat this as success.
        Err(Error::NotImplemented {
            feature:
                "standalone request_presence — use sign_with_presence for per-operation presence"
                    .into(),
        })
    }

    /// Evict any cached presence token.
    ///
    /// **Phase 2 stub.** This is a no-op until standalone LAContext/UserConsentVerifier
    /// integration is complete. Callers should not rely on this method for security enforcement.
    pub fn evict_presence_cache(&self) {}

    pub fn backend_kind(&self) -> BackendKind {
        self.backend_kind
    }
}

/// Standalone helper — no handle required.
#[allow(clippy::needless_return, unreachable_code)]
pub fn platform_auth_capabilities() -> AuthCapabilities {
    #[cfg(target_os = "macos")]
    let available = enclaveapp_apple::touch_id_available();

    #[cfg(target_os = "macos")]
    return AuthCapabilities {
        biometric_available: available,
        password_available: true,
        presence_caching: true,
        authenticator_name: Some("Touch ID".into()),
    };

    #[cfg(target_os = "windows")]
    return AuthCapabilities {
        biometric_available: true,
        password_available: true,
        presence_caching: false,
        authenticator_name: Some("Windows Hello".into()),
    };

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    AuthCapabilities {
        biometric_available: false,
        password_available: false,
        presence_caching: false,
        authenticator_name: None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::types::BackendKind;

    #[test]
    fn request_presence_returns_not_implemented_when_available() {
        // On macOS in test env, biometric_available may be false (no Touch ID in CI).
        // Either way, request_presence must NOT return Ok(()).
        let handle = AuthHandle::new(BackendKind::SecureEnclave);
        let result = handle.request_presence("test reason");
        // Must return an error — either PresenceNotAvailable or NotImplemented.
        // Must never return Ok(()) (which would be a false success).
        assert!(
            result.is_err(),
            "request_presence must not return Ok(()) — it is a stub"
        );
    }

    #[test]
    fn platform_auth_capabilities_does_not_panic() {
        let caps = platform_auth_capabilities();
        // Just verify it returns without panicking
        let _ = caps.biometric_available;
        let _ = caps.password_available;
        let _ = caps.presence_caching;
    }
}
