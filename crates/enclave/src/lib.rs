// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Hardware-backed key management and in-process memory protection.
//!
//! The `enclave` crate provides two distinct capabilities:
//!
//! **Hardware key management** — ECDSA P-256 signing and ECIES P-256 encryption
//! backed by the platform hardware security module (macOS Secure Enclave,
//! Windows TPM 2.0, Linux TPM 2.0 / keyring). Keys never leave the hardware.
//! User-presence enforcement (Touch ID, Windows Hello) is built in.
//!
//! **In-process memory protection** — guard-paged, mlock'd buffers
//! ([`SecureBuffer`]), Arc-wrapped thread-safe secret storage ([`LockedBuffer`]),
//! AES-256-GCM in-memory sealed secrets ([`MemoryEnclave`]), and a tiered pool
//! of locked memory slots ([`pool_acquire`]). Ported from
//! [asherah-ffi](https://github.com/godaddy/asherah-ffi), these components
//! defend against heap-scraping attacks on long-lived processes.
//!
//! Both capabilities compose: decrypted key material returned from the HSM layer
//! can be placed directly into a [`SecureBuffer`] or [`MemoryEnclave`].
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
//!
//! # Memory pool initialization
//! The global memory pool is lazily initialized on first use. For reliable startup-time
//! error reporting, call [`init_pool()`] explicitly before using any [`MemoryEnclave`] or
//! [`pool_acquire()`] operations.

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
pub mod security_key;
pub mod signing;
pub mod types;

// Top-level re-exports for ergonomic use.
pub use auth::{platform_auth_capabilities, AuthCapabilities, AuthHandle};
pub use capabilities::{
    has_keychain_entitlement, is_binary_signed, security_capabilities, SecurityCapabilities,
};
pub use config::{
    EnclaveConfig, LinuxConfig, MacOsConfig, PlatformConfig, WindowsConfig, WindowsSoftwareFallback,
};
pub use credential::{classify_credential, CredentialState, LifecyclePolicy};
pub use encryption::EncryptorHandle;
pub use error::{Error, Result};
pub use exec::{IntegrationType, SecureProcess, TempSecretFile};
pub use factory::{
    create_auth, create_encryptor, create_security_key, create_signer, create_tamper_evident,
    create_tamper_evident_ephemeral,
};
pub use integrity::{IntegrityMode, TamperEvidentHandle, VerifyOutcome};
pub use memory::{
    coffer_view, init_pool, pool_acquire, pool_release, zeroize_all_registered_at_shutdown,
    LockedBuffer, MemoryEnclave, PoolSlot, SecureBuffer, TieredPool, TieredPoolConfig,
};
pub use security_key::{SecurityKeyHandle, SecurityKeyInfo, SecurityKeySignature};
pub use signing::SignerHandle;
pub use types::{AccessPolicy, BackendKind, KeyInfo, KeyType, PresenceMode, PresenceOptions};
pub use zeroize::Zeroizing;
