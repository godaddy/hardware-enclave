// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Page-guarded, mlock'd memory buffers for secret material.

mod locked_buffer;
mod memcall;
mod memory_enclave;
pub mod pool;
mod secure_buffer;
pub(crate) mod slab;

pub use locked_buffer::{zeroize_all_registered_at_shutdown, LockedBuffer};
pub use memory_enclave::MemoryEnclave;
pub use pool::{
    coffer_view, init_pool, pool_acquire, pool_release, PoolSlot, TieredPool, TieredPoolConfig,
};
pub use secure_buffer::SecureBuffer;

/// Zeroize all registered LockedBuffers. Call at shutdown.
///
/// Thin wrapper around [`zeroize_all_registered_at_shutdown`] for backward compatibility.
#[deprecated(
    since = "0.1.0",
    note = "use zeroize_all_registered_at_shutdown() instead"
)]
pub fn zeroize_all() {
    zeroize_all_registered_at_shutdown();
}
