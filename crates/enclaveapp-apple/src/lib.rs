// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! enclave.
//!
//! Provides hardware-backed key management via CryptoKit Swift bridge:
//! - **Signing keys** (`SecureEnclave.P256.Signing.PrivateKey`) behind the `signing` feature
//! - **Encryption keys** (`SecureEnclave.P256.KeyAgreement.PrivateKey`) behind the `encryption` feature
//!
//! On non-macOS platforms, this crate compiles as an empty module.

#[cfg(target_os = "macos")]
mod ffi;
#[cfg(target_os = "macos")]
mod keychain;
#[cfg(target_os = "macos")]
mod keychain_wrap;
#[cfg(all(target_os = "macos", any(feature = "signing", feature = "encryption")))]
mod lacontext;
#[cfg(target_os = "macos")]
pub mod meta_hmac;
#[cfg(target_os = "macos")]
pub mod meta_migration_marker;
#[cfg(target_os = "macos")]
pub mod meta_tag;
#[cfg(target_os = "macos")]
pub mod signing;

#[cfg(all(target_os = "macos", feature = "encryption"))]
mod encrypt;
#[cfg(all(target_os = "macos", feature = "signing"))]
mod sign;

#[cfg(all(target_os = "macos", feature = "encryption"))]
pub use encrypt::SecureEnclaveEncryptor;
#[cfg(all(target_os = "macos", feature = "signing"))]
pub use sign::touch_id_available;
#[cfg(all(target_os = "macos", feature = "signing"))]
pub use sign::SecureEnclaveSigner;

// Export the keychain config so consumers can opt into
// wrapping-key user-presence and cache-TTL before constructing a signer.
#[cfg(target_os = "macos")]
pub use keychain::KeychainConfig;

// Standalone presence evaluation for enclave::AuthHandle.
#[cfg(all(target_os = "macos", any(feature = "signing", feature = "encryption")))]
pub use lacontext::{evaluate_presence, evict_all_contexts};
