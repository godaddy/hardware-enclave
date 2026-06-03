// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! JSON-RPC TPM bridge server for WSL2→Windows TPM routing.
//!
//! Windows binaries that serve the WSL2 TPM bridge instantiate [`BridgeServer`]
//! and call [`BridgeServer::run_stdio`]. The server reads JSON-RPC requests from
//! stdin and writes responses to stdout, handling signing, encryption, key
//! management, and key listing on behalf of WSL2 clients.
//!
//! # Usage
//!
//! ```ignore
//! // In the Windows tpm-bridge binary main():
//! use hardware_enclave::{harden_process, bridge_server::BridgeServer};
//!
//! harden_process();
//! let mut server = BridgeServer::new("my-app", "default-key");
//! server.run_stdio().expect("bridge server error");
//! ```

pub use crate::internal::tpm_bridge::{BridgeServer, TpmStorage};
