// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Windows TPM 2.0 backend for libenclaveapp via CNG (NCrypt/BCrypt).
//!
//! This crate provides hardware-backed key management using the Windows
//! Microsoft Platform Crypto Provider (TPM 2.0). It supports:
//!
//! - **Signing keys** (ECDSA P-256) via the `signing` feature
//! - **Encryption keys** (ECDH P-256 / ECIES) via the `encryption` feature
//!
//! On non-Windows platforms this crate compiles as empty.

#[cfg(target_os = "windows")]
mod export;
#[cfg(target_os = "windows")]
mod key;
#[cfg(target_os = "windows")]
pub mod meta_hmac;
#[cfg(target_os = "windows")]
mod provider;
#[cfg(target_os = "windows")]
pub mod ui_policy;

#[cfg(all(target_os = "windows", feature = "encryption"))]
mod encrypt;
#[cfg(all(target_os = "windows", feature = "signing"))]
mod sign;

#[cfg(all(target_os = "windows", feature = "encryption"))]
pub use encrypt::TpmEncryptor;
#[cfg(all(target_os = "windows", feature = "signing"))]
pub use sign::TpmSigner;

// Pure-logic helpers that compile on all platforms (for cross-platform tests).
// On non-Windows the Windows-gated consumers don't exist, so some items appear
// unused; they *are* used on the target platform.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
mod convert;
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
mod state;

pub use convert::{der_to_p1363, p1363_to_der};
