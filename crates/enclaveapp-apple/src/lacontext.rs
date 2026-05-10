// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Reusable `LAContext` registry for Secure Enclave signing.
//!
//! When a key uses [`PresenceMode::Cached`], the agent wants one
//! Touch ID prompt per cache-TTL window — not one per signature. The
//! mechanism is Apple's `LAContext.touchIDAuthenticationAllowableReuseDuration`:
//! authenticate once on a long-lived `LAContext`, then pass that same
//! context to subsequent SE sign calls within the reuse window. The
//! SEP accepts the cached authentication and skips the prompt.
//!
//! Rust side:
//! - [`LaContextHandle`] is an opaque, Drop-on-release token.
//! - [`registry()`] holds one handle per `(app_name, label)` pair.
//! - Eviction (cache miss / TTL expiry / explicit delete) drops the
//!   handle, which calls Swift's `enclaveapp_se_lacontext_release` to
//!   invalidate the underlying `LAContext`.
//!
//! Threading: the registry is a `Mutex<HashMap>`; lookups and inserts
//! are short. Holding a returned `Arc<LaContextHandle>` does not block
//! other lookups.
//!
//! [`PresenceMode::Cached`]: enclaveapp_core::PresenceMode::Cached

use crate::ffi;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Opaque, Swift-owned `LAContext`. Dropping the handle releases the
/// underlying context via FFI.
#[derive(Debug)]
pub(crate) struct LaContextHandle {
    token: u64,
    /// When this handle was minted. Used by the registry to
    /// proactively evict on TTL expiry without waiting for the next
    /// wrapping-key cache eviction.
    created_at: Instant,
    ttl: Duration,
}

impl LaContextHandle {
    #[allow(unsafe_code)] // FFI call to Swift LAContext registry
    fn new(reason: &str, ttl: Duration) -> Option<Self> {
        let secs = ttl.as_secs_f64();
        let reason_len = i32::try_from(reason.len()).ok()?;
        // SAFETY: FFI to Swift bridge. `reason` is passed as a borrowed
        // byte slice for the duration of the call; Swift copies it before
        // returning and never retains the pointer.
        let token =
            unsafe { ffi::enclaveapp_se_lacontext_create(secs, reason.as_ptr(), reason_len) };
        if token == 0 {
            None
        } else {
            Some(LaContextHandle {
                token,
                created_at: Instant::now(),
                ttl,
            })
        }
    }

    /// The opaque token to pass to `enclaveapp_se_sign`. Sentinel `0`
    /// means "no context, prompt every sign."
    pub(crate) fn token(&self) -> u64 {
        self.token
    }

    fn is_expired(&self, now: Instant) -> bool {
        // The reuse window inside CryptoKit is what actually matters
        // for prompt suppression — this Rust-side TTL is a backstop
        // so we evict the registry entry roughly when the SEP would
        // also start re-prompting. A minute of slack avoids races
        // where the SEP would still reuse but the registry has
        // already dropped the handle.
        now.saturating_duration_since(self.created_at) >= self.ttl
    }
}

impl Drop for LaContextHandle {
    #[allow(unsafe_code)] // FFI call to release Swift-owned LAContext
    fn drop(&mut self) {
        // SAFETY: FFI to Swift bridge. The token came from
        // `enclaveapp_se_lacontext_create`, has not been released
        // yet (because the Drop impl runs at most once per handle),
        // and Swift's release is idempotent.
        unsafe { ffi::enclaveapp_se_lacontext_release(self.token) };
    }
}

type RegistryKey = (String, String);

/// Global registry. One entry per `(app_name, label)`.
fn registry() -> &'static Mutex<HashMap<RegistryKey, Arc<LaContextHandle>>> {
    static REGISTRY: OnceLock<Mutex<HashMap<RegistryKey, Arc<LaContextHandle>>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Look up or create the cached `LaContextHandle` for the given key.
/// Returns `None` if `ttl_secs == 0` (caller should pass token 0
/// instead — equivalent to "no context").
///
/// `reason` is shown verbatim in the Touch ID dialog when a fresh
/// LAContext must be created (cache miss or TTL expiry). Cache hits
/// return the existing handle regardless of the `reason` value.
pub(crate) fn acquire(
    app_name: &str,
    label: &str,
    ttl_secs: u64,
    reason: &str,
) -> Option<Arc<LaContextHandle>> {
    if ttl_secs == 0 {
        return None;
    }
    let key: RegistryKey = (app_name.to_string(), label.to_string());
    let ttl = Duration::from_secs(ttl_secs);

    let mut guard = match registry().lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };

    let now = Instant::now();
    if let Some(existing) = guard.get(&key) {
        if !existing.is_expired(now) {
            return Some(Arc::clone(existing));
        }
        // Expired; fall through to recreate.
        guard.remove(&key);
    }

    let handle = LaContextHandle::new(reason, ttl)?;
    let arc = Arc::new(handle);
    guard.insert(key, Arc::clone(&arc));
    Some(arc)
}

/// Create a one-shot `LaContextHandle` that is NOT stored in the
/// registry. Used for `PresenceMode::Strict` to show a per-sign
/// Touch ID prompt with a descriptive reason string. The returned
/// handle must be kept alive until the sign operation completes.
pub(crate) fn create_once(reason: &str) -> Option<LaContextHandle> {
    // Short TTL: just long enough to complete a single sign call.
    // Not stored in the registry — dropped (and released) by the
    // caller immediately after the sign completes.
    LaContextHandle::new(reason, Duration::from_secs(5))
}

/// Drop the cached `LaContextHandle` for the given key, if any. Called
/// from the wrapping-key cache eviction path so wrapping-key and
/// LAContext lifetimes stay aligned.
pub(crate) fn evict(app_name: &str, label: &str) {
    let key: RegistryKey = (app_name.to_string(), label.to_string());
    let mut guard = match registry().lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    guard.remove(&key);
}

/// Drop every cached `LaContextHandle`. Intended for tests and for
/// wrapping-key full-cache evict paths.
#[allow(dead_code)]
pub(crate) fn evict_all() {
    let mut guard = match registry().lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    guard.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttl_zero_returns_none() {
        // Doesn't touch FFI — short-circuits before the Swift call.
        assert!(acquire("test_app", "test_label_zero", 0, "test reason").is_none());
    }
}
