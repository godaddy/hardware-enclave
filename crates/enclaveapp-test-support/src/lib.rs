// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! enclave without hardware.
//!
//! Provides [`MockKeyBackend`] which implements all three core traits
//! (`EnclaveKeyManager`, `EnclaveSigner`, `EnclaveEncryptor`) using
//! deterministic in-memory operations.

mod mock;

pub use mock::*;
