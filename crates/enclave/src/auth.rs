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
pub struct AuthHandle {
    backend_kind: BackendKind,
    /// Windows Hello verification cache. Each `AuthHandle` owns its own gate
    /// so that `evict_presence_cache()` only clears verifications acquired
    /// through this handle and does not affect other handles or the key
    /// sign/decrypt paths (which manage their own Hello state).
    #[cfg(target_os = "windows")]
    hello_gate: enclaveapp_windows::hello_gate::HelloGate,
}

impl std::fmt::Debug for AuthHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthHandle")
            .field("backend_kind", &self.backend_kind)
            .finish_non_exhaustive()
    }
}

impl AuthHandle {
    pub(crate) fn new(backend_kind: BackendKind) -> Self {
        Self {
            backend_kind,
            #[cfg(target_os = "windows")]
            hello_gate: enclaveapp_windows::hello_gate::HelloGate::new(),
        }
    }

    /// Return the platform's authentication capabilities. Equivalent to
    /// [`platform_auth_capabilities()`][crate::platform_auth_capabilities].
    pub fn capabilities(&self) -> AuthCapabilities {
        platform_auth_capabilities()
    }

    /// Request user-presence verification. Returns `Ok(())` if the user
    /// authenticated successfully.
    ///
    /// Platform behavior:
    /// - **macOS**: Fires the Touch ID / passcode dialog synchronously via
    ///   `LAContext.evaluatePolicy(.deviceOwnerAuthentication)`. Blocks until
    ///   the user responds. Returns `Err(PresenceNotAvailable)` if no
    ///   biometric or passcode is enrolled, or `Err(UserCancelled)` if the
    ///   user dismisses the prompt.
    /// - **Windows**: Calls `UserConsentVerifier.RequestVerificationAsync(reason)`.
    ///   Falls back to a password gate when Windows Hello is not enrolled.
    ///   Gracefully degrades to `Ok(())` on headless sessions where neither
    ///   Hello nor a verifiable password is available (credentials remain
    ///   TPM-encrypted regardless).
    /// - **Linux / other**: Always returns `Err(PresenceNotAvailable)`.
    #[allow(clippy::needless_return, unreachable_code)]
    pub fn request_presence(&self, reason: &str) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            return enclaveapp_apple::evaluate_presence(reason).map_err(|e| {
                use enclaveapp_core::Error as CE;
                match e {
                    CE::NotAvailable => Error::PresenceNotAvailable,
                    CE::UserCancelled { label } => Error::UserCancelled { label },
                    other => Error::from(other),
                }
            });
        }
        #[cfg(target_os = "windows")]
        {
            return self
                .hello_gate
                .ensure_verified("__standalone_presence__", reason, std::time::Duration::ZERO)
                .map_err(Error::from);
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            let _ = reason;
            return Err(Error::PresenceNotAvailable);
        }
    }

    /// Evict any cached presence token, forcing re-authentication on the
    /// next signing or decryption operation that uses a cached presence mode.
    ///
    /// Platform behavior:
    /// - **macOS**: Clears all cached `LAContext` handles from the global
    ///   registry. The next `sign_with_presence(Cached, ...)` call will fire
    ///   a fresh Touch ID prompt.
    /// - **Windows**: Clears all Windows Hello verifications cached in this
    ///   `AuthHandle`. The sign/decrypt paths manage their own `HelloGate`
    ///   state and are unaffected.
    /// - **Linux / other**: No-op.
    #[allow(clippy::needless_return, unreachable_code)]
    pub fn evict_presence_cache(&self) {
        #[cfg(target_os = "macos")]
        {
            enclaveapp_apple::evict_all_contexts();
            return;
        }
        #[cfg(target_os = "windows")]
        {
            self.hello_gate.invalidate_all();
            return;
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {}
    }

    /// Which hardware security backend this handle targets.
    pub fn backend_kind(&self) -> BackendKind {
        self.backend_kind
    }
}

/// Standalone helper — no handle required.
#[allow(clippy::needless_return, unreachable_code)]
pub fn platform_auth_capabilities() -> AuthCapabilities {
    #[cfg(target_os = "macos")]
    return AuthCapabilities {
        biometric_available: enclaveapp_apple::touch_id_available(),
        password_available: true,
        presence_caching: true,
        authenticator_name: Some("Touch ID".into()),
    };

    #[cfg(target_os = "windows")]
    return AuthCapabilities {
        // Checked at runtime via UserConsentVerifier::CheckAvailabilityAsync.
        biometric_available: enclaveapp_windows::hello_gate::is_available(),
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
    use crate::config::EnclaveConfig;
    use crate::factory::create_auth;

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn request_presence_never_panics() {
        // Skip on Windows entirely: request_presence() always requires a GUI prompt
        // (Hello or password dialog). Even when Hello is not enrolled, the Windows
        // fallback shows CredUIPromptForWindowsCredentialsW which blocks on headless CI.
        //
        // On macOS: skip if Touch ID is available (would block waiting for biometric).
        // On Linux: always safe — returns PresenceNotAvailable immediately.
        if platform_auth_capabilities().biometric_available {
            return;
        }
        let config = EnclaveConfig::new("testapp", "key");
        let handle = create_auth(&config).unwrap();
        drop(handle.request_presence("test reason"));
    }

    #[test]
    fn evict_presence_cache_never_panics() {
        let config = EnclaveConfig::new("testapp", "key");
        let handle = create_auth(&config).unwrap();
        handle.evict_presence_cache(); // Must not panic.
    }

    #[test]
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    fn request_presence_returns_not_available_on_linux() {
        let config = EnclaveConfig::new("testapp", "key");
        let handle = create_auth(&config).unwrap();
        let result = handle.request_presence("test");
        assert!(
            matches!(result, Err(Error::PresenceNotAvailable)),
            "Linux must return PresenceNotAvailable, got {result:?}"
        );
    }

    #[test]
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    fn evict_presence_cache_is_noop_on_linux() {
        let config = EnclaveConfig::new("testapp", "key");
        let handle = create_auth(&config).unwrap();
        handle.evict_presence_cache(); // Explicit no-op path; verify no panic.
                                       // Call twice to confirm idempotency.
        handle.evict_presence_cache();
    }

    #[test]
    fn platform_capabilities_does_not_panic() {
        let caps = platform_auth_capabilities();
        let _ = caps.biometric_available;
        let _ = caps.password_available;
        let _ = caps.presence_caching;
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn request_presence_returns_not_available_when_no_biometric() {
        // Skipped on Windows: request_presence always requires GUI interaction
        // (Hello or password dialog) — no fast-path error for missing biometrics.
        if platform_auth_capabilities().biometric_available {
            return;
        }
        let config = EnclaveConfig::new("testapp", "key");
        let handle = create_auth(&config).unwrap();
        let result = handle.request_presence("ci test");
        assert!(
            matches!(result, Err(Error::PresenceNotAvailable)),
            "platform without biometric must return PresenceNotAvailable, got {result:?}"
        );
    }
}
