// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Hardware-backed key management and in-process memory protection.
//!
//! This crate provides two independently usable capability sets:
//!
//! ## Memory protection (`features = ["memory"]`)
//!
//! Available with `default-features = false, features = ["memory"]` — no platform
//! HSM, no TPM, no Secure Enclave, no key storage. Only depends on `aes-gcm`,
//! `rand`, `zeroize`, `sha2`, `libc`, and `subtle`.
//!
//! - [`SecureBuffer`] — guard-paged, mlock'd buffer; memory never swaps to disk
//! - [`LockedBuffer`] — Arc-wrapped secret with global zeroize-on-shutdown registry
//! - [`MemoryEnclave`] — AES-256-GCM sealed in-memory secret with hot-cache tier
//! - [`TieredPool`] / [`pool_acquire`] — pool of locked memory slots for key material
//! - [`harden_process`] — disable core dumps, restrict ptrace, set no-new-privs
//!
//! ```no_run
//! use hardware_enclave::{harden_process, SecureBuffer, MemoryEnclave, init_pool};
//!
//! harden_process();
//! init_pool(hardware_enclave::TieredPoolConfig::default())?;
//! let buf = SecureBuffer::new(32)?; // 32 bytes, guard-paged
//! let enc = MemoryEnclave::seal(b"secret key material")?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## Hardware key management (`features = ["signing", "encryption"]`)
//!
//! ECDSA P-256 signing and ECIES P-256 encryption backed by the platform HSM
//! (macOS Secure Enclave, Windows TPM 2.0, Linux TPM 2.0 / keyring). Keys never
//! leave the hardware. User-presence enforcement (Touch ID, Windows Hello) built in.
//!
//! ```ignore
//! // Requires `features = ["signing"]` (included in the default feature set).
//! use hardware_enclave::{EnclaveConfig, create_signer, AccessPolicy};
//!
//! let config = EnclaveConfig::new("myapp", "default");
//! let signer = create_signer(&config)?;
//! let pubkey = signer.generate_key("default", AccessPolicy::Any)?;
//! let sig = signer.sign("default", b"hello world")?;
//! # Ok::<(), hardware_enclave::Error>(())
//! ```
//!
//! # Memory pool initialization
//! The global memory pool is lazily initialized on first use. For reliable startup-time
//! error reporting, call [`init_pool()`] explicitly before using any [`MemoryEnclave`] or
//! [`pool_acquire()`] operations.

// ── Internal platform backends — only compiled with key management features ──
#[cfg(any(feature = "signing", feature = "encryption"))]
pub(crate) mod internal;

// ── Always available: memory protection, error types, and process hardening ──
pub mod error;
pub mod hardening;
pub mod memory;

pub use error::{Error, Result};
pub use hardening::harden_process;
pub use memory::{
    coffer_view, init_pool, pool_acquire, pool_release, zeroize_all_registered_at_shutdown,
    LockedBuffer, MemoryEnclave, PoolSlot, SecureBuffer, TieredPool, TieredPoolConfig,
};
pub use zeroize::Zeroizing;

// ── Key management + platform utilities (signing or encryption) ──────────────
#[cfg(any(feature = "signing", feature = "encryption"))]
pub mod auth;
#[cfg(any(feature = "signing", feature = "encryption"))]
pub mod bridge_server;
#[cfg(any(feature = "signing", feature = "encryption"))]
pub mod capabilities;
#[cfg(any(feature = "signing", feature = "encryption"))]
pub mod config;
#[cfg(any(feature = "signing", feature = "encryption"))]
pub mod credential;
#[cfg(any(feature = "signing", feature = "encryption"))]
pub mod diagnostics;
#[cfg(any(feature = "signing", feature = "encryption"))]
pub mod encryption;
#[cfg(any(feature = "signing", feature = "encryption"))]
pub mod exec;
#[cfg(any(feature = "signing", feature = "encryption"))]
pub mod factory;
#[cfg(any(feature = "signing", feature = "encryption"))]
pub mod fs;
#[cfg(any(feature = "signing", feature = "encryption"))]
pub mod integrity;
#[cfg(any(feature = "signing", feature = "encryption"))]
pub mod process;
#[cfg(any(feature = "signing", feature = "encryption"))]
pub mod security_key;
#[cfg(any(feature = "signing", feature = "encryption"))]
pub mod shell;
#[cfg(any(feature = "signing", feature = "encryption"))]
pub mod signing;
#[cfg(any(feature = "signing", feature = "encryption"))]
pub mod types;
#[cfg(any(feature = "signing", feature = "encryption"))]
pub mod wsl;

#[cfg(any(feature = "signing", feature = "encryption"))]
pub use auth::{platform_auth_capabilities, AuthCapabilities, AuthHandle};
#[cfg(any(feature = "signing", feature = "encryption"))]
pub use capabilities::{
    has_keychain_entitlement, is_binary_signed, security_capabilities, SecurityCapabilities,
};
#[cfg(any(feature = "signing", feature = "encryption"))]
pub use config::{
    EnclaveConfig, LinuxConfig, MacOsConfig, PlatformConfig, WindowsConfig, WindowsSoftwareFallback,
};
#[cfg(any(feature = "signing", feature = "encryption"))]
pub use credential::{classify_credential, CredentialState, LifecyclePolicy};
#[cfg(feature = "encryption")]
pub use encryption::EncryptorHandle;
// Error and Result already re-exported unconditionally above.
#[cfg(any(feature = "signing", feature = "encryption"))]
pub use exec::{IntegrationType, SecureProcess, TempSecretFile};
#[cfg(any(feature = "signing", feature = "encryption"))]
pub use factory::{
    create_auth, create_encryptor, create_security_key, create_signer, create_tamper_evident,
    create_tamper_evident_ephemeral,
};
#[cfg(any(feature = "signing", feature = "encryption"))]
pub use integrity::{IntegrityMode, TamperEvidentHandle, VerifyOutcome};
#[cfg(any(feature = "signing", feature = "encryption"))]
pub use security_key::{SecurityKeyHandle, SecurityKeyInfo, SecurityKeySignature};
#[cfg(feature = "signing")]
pub use signing::SignerHandle;
#[cfg(any(feature = "signing", feature = "encryption"))]
pub use types::{AccessPolicy, BackendKind, KeyInfo, KeyType, PresenceMode, PresenceOptions};
