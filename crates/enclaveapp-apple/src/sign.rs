// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Secure Enclave signing backend.

use crate::ffi;
use crate::keychain::{self, KeychainConfig};
use crate::lacontext;
use enclaveapp_core::traits::{EnclaveKeyManager, EnclaveSigner};
use enclaveapp_core::types::{validate_label, AccessPolicy, KeyType, PresenceMode};
use enclaveapp_core::{Error, Result};

fn should_evict_lacontext(e: &Error) -> bool {
    // Don't evict for errors where the LAContext is not the cause:
    //
    // - KeychainAuthDenied: the OS denies based on the binary's cdhash,
    //   not an expired/invalid LAContext. Evicting would just re-prompt
    //   Touch ID on every retry with no recovery possible.
    //
    // - KeychainInteractionRequired: no LAContext was provided at all
    //   (lacontext_token=0). Nothing is cached for this label, so evict
    //   is a no-op. The cause is typically a locked screen; when the user
    //   unlocks, the next acquire() will create a fresh context normally.
    //
    // - KeychainNoWindowServer: same as InteractionRequired — token was 0,
    //   nothing cached. The cause is the agent running outside launchd;
    //   evicting is a no-op and the fix is to restart via launchd.
    //
    // - UserCancelled: the user explicitly cancelled the Touch ID prompt.
    //   The LAContext is still valid and authenticated; evicting it forces
    //   a fresh Touch ID prompt on the next operation with no gain. The
    //   user may have cancelled due to being away from keyboard, on a call,
    //   etc. Keeping the LAContext alive allows the next operation to
    //   succeed silently when they return (within the cache TTL window).
    !matches!(
        e,
        Error::KeychainAuthDenied { .. }
            | Error::KeychainInteractionRequired { .. }
            | Error::KeychainNoWindowServer { .. }
            | Error::UserCancelled { .. }
    )
}

/// Returns `true` if Touch ID (or device passcode auth) is evaluable in
/// this process — meaning the process has a window server session and the
/// device has enrolled biometrics or a passcode set.
///
/// Returns `false` when:
/// - The process has no window server connection (started outside launchd).
/// - The device has no enrolled biometrics and no passcode.
///
/// Use this as a startup diagnostic to detect the "agent launched outside
/// launchd" misconfiguration before the first sign request fails.
#[allow(unsafe_code)]
pub fn touch_id_available() -> bool {
    unsafe { ffi::enclaveapp_se_touch_id_available() == 1 }
}

/// ECDSA P-256 signing backend using the macOS Secure Enclave.
#[derive(Debug)]
pub struct SecureEnclaveSigner {
    config: KeychainConfig,
}

impl SecureEnclaveSigner {
    pub fn new(app_name: &str) -> Self {
        SecureEnclaveSigner {
            config: KeychainConfig::new(app_name),
        }
    }

    /// Create a signer with a custom keys directory path.
    /// Use this for backward compatibility with existing key storage locations.
    pub fn with_keys_dir(app_name: &str, keys_dir: std::path::PathBuf) -> Self {
        SecureEnclaveSigner {
            config: KeychainConfig::with_keys_dir(app_name, keys_dir),
        }
    }

    /// Create a signer from a pre-built `KeychainConfig`. Use this to
    /// supply non-default `wrapping_key_user_presence` /
    /// `wrapping_key_cache_ttl` settings.
    pub fn with_config(config: KeychainConfig) -> Self {
        SecureEnclaveSigner { config }
    }

    /// Internal sign-with-token routine. `lacontext_token == 0` means
    /// "no reusable context; SEP enforces a prompt per sign." Non-zero
    /// is a token returned from the Swift LAContext registry.
    ///
    /// The same token is threaded into `keychain::load_handle_with_context`
    /// so the keychain decrypt of the wrapping-key entry reuses the
    /// LAContext's auth instead of issuing an independent prompt.
    /// Without this, a single sign produced two prompts on userPresence-
    /// protected wrapping keys: one for the keychain decrypt, one for
    /// the SE sign itself.
    #[allow(unsafe_code)] // FFI call to CryptoKit Swift bridge
    fn sign_inner(&self, label: &str, data: &[u8], lacontext_token: u64) -> Result<Vec<u8>> {
        validate_label(label)?;
        let data_rep = keychain::load_handle_with_context(&self.config, label, lacontext_token)?;

        let mut sig = vec![0_u8; 128]; // DER ECDSA P-256 sig is at most ~72 bytes
        let mut sig_len: i32 = 128;

        let rc = unsafe {
            ffi::enclaveapp_se_sign(
                data_rep.as_ptr(),
                data_rep.len() as i32,
                data.as_ptr(),
                data.len() as i32,
                sig.as_mut_ptr(),
                &mut sig_len,
                lacontext_token,
            )
        };

        if rc != 0 {
            return Err(match rc {
                16 => Error::UserCancelled {
                    // SE_ERR_USER_CANCEL: user cancelled the Touch ID prompt.
                    // The LAContext is still valid; don't evict it.
                    label: label.to_string(),
                },
                _ => {
                    let detail = match keychain::last_bridge_error() {
                        Some(msg) => format!("FFI returned error code {rc}: {msg}"),
                        None => format!("FFI returned error code {rc}"),
                    };
                    Error::SignFailed { detail }
                }
            });
        }

        sig.truncate(sig_len as usize);
        Ok(sig)
    }
}

impl EnclaveKeyManager for SecureEnclaveSigner {
    fn generate(&self, label: &str, key_type: KeyType, policy: AccessPolicy) -> Result<Vec<u8>> {
        validate_label(label)?;

        if key_type != KeyType::Signing {
            return Err(Error::KeyOperation {
                operation: "generate".into(),
                detail: "SecureEnclaveSigner only supports signing keys".into(),
            });
        }

        keychain::generate_and_save_key(&self.config, label, key_type, policy)
    }

    fn public_key(&self, label: &str) -> Result<Vec<u8>> {
        validate_label(label)?;
        keychain::load_pub_key(&self.config, label, KeyType::Signing)
    }

    fn list_keys(&self) -> Result<Vec<String>> {
        keychain::list_labels(&self.config)
    }

    fn delete_key(&self, label: &str) -> Result<()> {
        validate_label(label)?;
        keychain::delete_key(&self.config, label)
    }

    fn rename_key(&self, old_label: &str, new_label: &str) -> Result<()> {
        keychain::rename_key(&self.config, old_label, new_label)
    }

    fn is_available(&self) -> bool {
        keychain::is_available()
    }
}

impl EnclaveSigner for SecureEnclaveSigner {
    fn sign(&self, label: &str, data: &[u8]) -> Result<Vec<u8>> {
        // No reusable context — per-sign SEP prompt if the key has a
        // user-presence access control, silent otherwise. Preserves
        // pre-LAContext behaviour for callers that haven't migrated
        // to `sign_with_presence`.
        self.sign_inner(label, data, 0)
    }

    fn sign_with_presence(
        &self,
        label: &str,
        data: &[u8],
        mode: PresenceMode,
        cache_ttl_secs: u64,
        reason: &str,
    ) -> Result<Vec<u8>> {
        match mode {
            PresenceMode::Cached => {
                let token =
                    lacontext::acquire(&self.config.app_name, label, cache_ttl_secs, reason)
                        .map(|h| h.token())
                        .unwrap_or(0);
                let result = self.sign_inner(label, data, token);
                if let Err(ref e) = result {
                    if should_evict_lacontext(e) {
                        lacontext::evict(&self.config.app_name, label);
                    }
                }
                result
            }
            PresenceMode::Strict => {
                // Create a one-shot LAContext so the user sees a descriptive
                // reason string instead of the generic SE prompt. The handle
                // must stay alive across sign_inner; it's dropped on return.
                let handle = lacontext::create_once(reason);
                let token = handle.as_ref().map(|h| h.token()).unwrap_or(0);
                self.sign_inner(label, data, token)
            }
            PresenceMode::None => {
                // The SE key itself doesn't require user presence, but the
                // wrapping key always has `.userPresence` on macOS. Without a
                // LAContext the wrapping-key Touch ID fires with the system
                // default dialog — no custom reason string. Providing a
                // one-shot context costs nothing (the same Touch ID prompt
                // fires either way) but makes the dialog show the caller's
                // reason instead of a blank system prompt.
                let handle = lacontext::create_once(reason);
                let token = handle.as_ref().map(|h| h.token()).unwrap_or(0);
                self.sign_inner(label, data, token)
            }
        }
    }

    fn evict_wrapping_key_cache(&self, label: &str) {
        crate::keychain_wrap::cache_evict_for(&self.config.app_name, label);
    }
}
