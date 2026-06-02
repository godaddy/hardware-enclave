// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

#[cfg(target_os = "macos")]
use std::collections::HashMap;
#[cfg(target_os = "macos")]
use std::sync::{Mutex, OnceLock};

use crate::types::{AccessPolicy, BackendKind};

pub use enclaveapp_core::signing::is_binary_signed;

/// True iff the running binary has the named keychain-access-groups entitlement.
/// On macOS, runs `codesign -d --entitlements -` and checks for the group string.
/// On other platforms, always returns false.
///
/// The result is cached for the process lifetime. A binary that is re-signed while
/// running will not see the updated entitlement in the cache until the next process start.
pub fn has_keychain_entitlement(group: &str) -> bool {
    #[cfg(target_os = "macos")]
    {
        static CACHE: OnceLock<Mutex<HashMap<String, bool>>> = OnceLock::new();
        let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
        let mut guard = cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(&result) = guard.get(group) {
            return result;
        }
        let result = check_entitlement_macos(group);
        guard.insert(group.to_string(), result);
        result
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = group;
        false
    }
}

#[cfg(target_os = "macos")]
fn check_entitlement_macos(group: &str) -> bool {
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(_) => return false,
    };
    // Use absolute path to avoid PATH manipulation.
    // NOTE: `is_binary_signed()` in enclaveapp_core::signing also invokes
    // `codesign --verify` but in a different crate. That invocation should
    // similarly be updated to use an absolute path — tracked as a follow-up
    // in enclaveapp-core (out of scope here per constraint 4).
    let output = std::process::Command::new("/usr/bin/codesign")
        .args(["-d", "--entitlements", "-", "--xml"])
        .arg(&exe)
        .output();
    match output {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            let stderr = String::from_utf8_lossy(&o.stderr);
            stdout.contains(group) || stderr.contains(group)
        }
        Err(_) => false,
    }
}

/// Full description of the security tier available to the current binary on the current platform.
#[derive(Debug, Clone)]
pub struct SecurityCapabilities {
    /// Binary is code-signed. When false, app_name has `-unsigned` appended.
    pub binary_signed: bool,
    /// Hardware security backend detected.
    pub backend: BackendKind,
    /// Effective keychain access group, if any.
    pub effective_keychain_group: Option<String>,
    /// Keychain items are bound to this binary's code signature.
    pub code_signature_binding: bool,
    /// User-presence gates the keychain wrapping key.
    pub keychain_user_presence: bool,
    /// Platform can enforce user-presence at hardware/OS level.
    pub hardware_presence: bool,
    /// Presence prompts can be cached across operations within a TTL.
    pub presence_caching: bool,
    /// Effective app_name after -unsigned suffix applied (if applicable).
    pub effective_app_name: String,
    /// Features requested that were silently downgraded.
    pub downgraded_features: Vec<String>,
    /// Recommended AccessPolicy for new keys given the current security tier.
    pub recommended_access_policy: AccessPolicy,
}

/// Query capabilities without creating any handles.
pub fn security_capabilities(app_name: &str) -> SecurityCapabilities {
    let signed = is_binary_signed();
    let effective_app_name = enclaveapp_core::signing::ensure_safe_app_name(app_name);
    let backend = detect_backend();

    #[cfg(target_os = "macos")]
    let hardware_presence = enclaveapp_apple::touch_id_available();
    #[cfg(target_os = "windows")]
    let hardware_presence = true;
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let hardware_presence = false;

    let presence_caching = cfg!(target_os = "macos");

    let recommended_access_policy = if signed {
        AccessPolicy::None
    } else {
        AccessPolicy::Any
    };

    SecurityCapabilities {
        binary_signed: signed,
        backend,
        effective_keychain_group: None,
        code_signature_binding: false,
        keychain_user_presence: false,
        hardware_presence,
        presence_caching,
        effective_app_name,
        downgraded_features: Vec::new(),
        recommended_access_policy,
    }
}

#[allow(clippy::needless_return, unreachable_code)]
fn detect_backend() -> BackendKind {
    #[cfg(target_os = "macos")]
    {
        return BackendKind::SecureEnclave;
    }
    #[cfg(target_os = "windows")]
    {
        return BackendKind::Tpm;
    }
    #[cfg(target_os = "linux")]
    {
        if enclaveapp_wsl::is_wsl() {
            return BackendKind::TpmBridge;
        }
        return BackendKind::Keyring;
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    BackendKind::Keyring
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn is_binary_signed_returns_false_in_cargo_test() {
        // cargo test runs from /target/ so is_binary_signed() must return false.
        assert!(!is_binary_signed());
    }

    #[test]
    fn has_keychain_entitlement_returns_false_for_unknown_group() {
        // An unsigned test binary never has any keychain entitlement.
        assert!(!has_keychain_entitlement("com.example.nonexistent.group"));
    }

    #[test]
    fn security_capabilities_does_not_panic() {
        let caps = security_capabilities("testapp");
        assert!(!caps.effective_app_name.is_empty());
        // In test context, binary is unsigned → -unsigned suffix applied
        assert!(
            caps.effective_app_name.ends_with("-unsigned"),
            "unsigned binary should have -unsigned suffix, got: {}",
            caps.effective_app_name
        );
        assert!(!caps.binary_signed);
    }
}
