// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

// The p256/elliptic-curve ecosystem uses deprecated generic-array APIs
// during the 0.14 -> 1.0 transition. Allow until upstream resolves this.
#![allow(deprecated)]

//! Software-only key backend for Linux systems without hardware security.
//!
//! Keys are standard P-256 key pairs stored as files on disk with restrictive
//! permissions. This provides the same API as the hardware backends but without
//! hardware protection -- private keys exist in memory and on disk.
//!
//! Use this as a fallback when:
//! - Running on Linux without WSL (WSL should use the TPM bridge instead)
//! - Hardware security is not available or not required

mod key_storage;
pub mod meta_migration_marker;
pub mod meta_tag;

#[cfg(feature = "signing")]
mod sign;

#[cfg(feature = "encryption")]
mod encrypt;

#[cfg(feature = "signing")]
pub use sign::SoftwareSigner;

#[cfg(feature = "encryption")]
pub use encrypt::SoftwareEncryptor;

pub use key_storage::{has_keyring_feature, is_available, meta_hmac_key, meta_hmac_key_existing};
