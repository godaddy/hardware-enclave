// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Hardware-backed key management for macOS Secure Enclave, Windows TPM 2.0,
//! and Linux TPM/keyring.
//!
//! # Quick start
//!
//! ```no_run
//! use enclave::{EnclaveConfig, create_signer, AccessPolicy};
//!
//! let config = EnclaveConfig::new("myapp", "default");
//! let signer = create_signer(&config)?;
//! let pubkey = signer.generate_key("default", AccessPolicy::Any)?;
//! let sig = signer.sign("default", b"hello world")?;
//! # Ok::<(), enclave::Error>(())
//! ```

pub mod auth;
pub mod capabilities;
pub mod config;
pub mod credential;
pub mod encryption;
pub mod error;
pub mod exec;
pub mod factory;
pub mod integrity;
pub mod memory;
pub mod signing;
pub mod types;

// Top-level re-exports for ergonomic use.
pub use auth::{platform_auth_capabilities, AuthCapabilities, AuthHandle};
pub use capabilities::{
    has_keychain_entitlement, is_binary_signed, security_capabilities, SecurityCapabilities,
};
pub use config::{EnclaveConfig, LinuxConfig, MacOsConfig, PlatformConfig, WindowsConfig};
pub use credential::{classify_credential, CredentialState, LifecyclePolicy};
pub use encryption::EncryptorHandle;
pub use error::{Error, Result};
pub use exec::{IntegrationType, SecureProcess, TempSecretFile};
pub use factory::{create_auth, create_encryptor, create_signer, create_tamper_evident};
pub use integrity::{TamperEvidentHandle, VerifyOutcome};
pub use memory::{
    coffer_view, init_pool, pool_acquire, pool_release, LockedBuffer, MemoryEnclave, PoolSlot,
    SecureBuffer, TieredPool, TieredPoolConfig,
};
pub use signing::SignerHandle;
pub use types::{AccessPolicy, BackendKind, KeyInfo, KeyType, PresenceMode, PresenceOptions};
