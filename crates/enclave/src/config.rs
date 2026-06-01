// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

use std::path::PathBuf;
use std::time::Duration;

use crate::types::AccessPolicy;
use enclaveapp_app_storage::{StorageConfig, WindowsSoftwareFallback};

/// Platform-specific escape hatches. Use PlatformConfig::Default for the common case.
#[derive(Debug, Clone, Default)]
pub enum PlatformConfig {
    #[default]
    Default,
    MacOs(MacOsConfig),
    Windows(WindowsConfig),
    Linux(LinuxConfig),
}

/// macOS-specific configuration overrides.
///
/// When using struct-update syntax (`..MacOsConfig::default()`), newly added
/// security-relevant fields will use their default values. Review the changelog
/// when updating the crate version to check for new fields.
#[derive(Debug, Clone)]
pub struct MacOsConfig {
    pub wrapping_key_user_presence: bool,
    pub wrapping_key_cache_ttl: Duration,
    /// `<TEAMID>.<group>` access group. Requires keychain-access-groups entitlement.
    pub keychain_access_group: Option<String>,
    /// Extra WSL bridge discovery paths.
    pub extra_bridge_paths: Vec<String>,
}

impl Default for MacOsConfig {
    fn default() -> Self {
        Self {
            wrapping_key_user_presence: false,
            wrapping_key_cache_ttl: Duration::ZERO,
            keychain_access_group: None,
            extra_bridge_paths: Vec::new(),
        }
    }
}

/// Windows-specific configuration overrides.
///
/// When using struct-update syntax (`..WindowsConfig::default()`), newly added
/// security-relevant fields will use their default values. Review the changelog
/// when updating the crate version to check for new fields.
#[derive(Debug, Clone)]
pub struct WindowsConfig {
    pub prefer_windows_hello_ux: bool,
    pub software_fallback: WindowsSoftwareFallback,
    pub dpapi_app_key: Option<[u8; 32]>,
}

impl Default for WindowsConfig {
    fn default() -> Self {
        Self {
            prefer_windows_hello_ux: false,
            software_fallback: WindowsSoftwareFallback::Disabled,
            dpapi_app_key: None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct LinuxConfig {
    pub force_keyring: bool,
    pub extra_bridge_paths: Vec<String>,
}

/// Configuration for all enclave handles created via factory functions.
#[derive(Debug, Clone)]
pub struct EnclaveConfig {
    /// Requested app identifier. The `-unsigned` suffix is applied automatically
    /// for unsigned binaries to prevent key namespace collisions.
    pub app_name: String,
    /// Default key label for factory-initialized keys.
    pub default_key_label: String,
    /// Default access policy for new keys. When None, the factory picks
    /// AccessPolicy::None for signed binaries and AccessPolicy::Any for unsigned.
    pub access_policy: Option<AccessPolicy>,
    /// Override key storage directory (default: platform default).
    pub keys_dir: Option<PathBuf>,
    /// Platform-specific overrides.
    pub platform: PlatformConfig,
}

impl EnclaveConfig {
    pub fn new(app_name: impl Into<String>, default_key_label: impl Into<String>) -> Self {
        Self {
            app_name: app_name.into(),
            default_key_label: default_key_label.into(),
            access_policy: None,
            keys_dir: None,
            platform: PlatformConfig::Default,
        }
    }

    /// Resolved effective app name (with -unsigned applied if needed).
    pub fn effective_app_name(&self) -> String {
        enclaveapp_core::signing::ensure_safe_app_name(&self.app_name)
    }

    /// Resolved access policy: explicit override, or signed->None / unsigned->Any.
    pub fn resolved_access_policy(&self) -> AccessPolicy {
        self.access_policy.unwrap_or_else(|| {
            if enclaveapp_core::signing::is_binary_signed() {
                AccessPolicy::None
            } else {
                AccessPolicy::Any
            }
        })
    }

    /// Build a StorageConfig for enclaveapp-app-storage.
    pub(crate) fn to_storage_config(&self) -> StorageConfig {
        let (
            wrapping_key_user_presence,
            wrapping_key_cache_ttl,
            keychain_access_group,
            extra_bridge_paths,
            force_keyring,
            prefer_windows_hello_ux,
            windows_software_fallback,
            dpapi_app_key,
        ) = match &self.platform {
            PlatformConfig::MacOs(m) => (
                m.wrapping_key_user_presence,
                m.wrapping_key_cache_ttl,
                m.keychain_access_group.clone(),
                m.extra_bridge_paths.clone(),
                false,
                false,
                WindowsSoftwareFallback::Disabled,
                None,
            ),
            PlatformConfig::Windows(w) => (
                false,
                Duration::ZERO,
                None,
                Vec::new(),
                false,
                w.prefer_windows_hello_ux,
                w.software_fallback,
                w.dpapi_app_key,
            ),
            PlatformConfig::Linux(l) => (
                false,
                Duration::ZERO,
                None,
                l.extra_bridge_paths.clone(),
                l.force_keyring,
                false,
                WindowsSoftwareFallback::Disabled,
                None,
            ),
            PlatformConfig::Default => (
                false,
                Duration::ZERO,
                None,
                Vec::new(),
                false,
                false,
                WindowsSoftwareFallback::Disabled,
                None,
            ),
        };

        StorageConfig {
            app_name: self.effective_app_name(),
            key_label: self.default_key_label.clone(),
            access_policy: self.resolved_access_policy(),
            extra_bridge_paths,
            keys_dir: self.keys_dir.clone(),
            force_keyring,
            wrapping_key_user_presence,
            wrapping_key_cache_ttl,
            keychain_access_group,
            prefer_windows_hello_ux,
            windows_software_fallback,
            dpapi_app_key,
        }
    }
}
