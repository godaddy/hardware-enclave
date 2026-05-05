// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! FFI declarations for the CryptoKit Swift bridge.
//!
//! All functions are declared regardless of feature flags since the Swift
//! bridge compiles all functions unconditionally.

// FFI extern block requires unsafe to declare. The actual unsafe usage is at
// call sites in keychain.rs, sign.rs, and encrypt.rs.
#[allow(unsafe_code, dead_code)]
extern "C" {
    pub fn enclaveapp_se_available() -> i32;

    // Signing key operations
    pub fn enclaveapp_se_generate_signing_key(
        pub_key_out: *mut u8,
        pub_key_len: *mut i32,
        data_rep_out: *mut u8,
        data_rep_len: *mut i32,
        auth_policy: i32,
    ) -> i32;

    pub fn enclaveapp_se_signing_public_key(
        data_rep: *const u8,
        data_rep_len: i32,
        pub_key_out: *mut u8,
        pub_key_len: *mut i32,
    ) -> i32;

    pub fn enclaveapp_se_sign(
        data_rep: *const u8,
        data_rep_len: i32,
        message: *const u8,
        message_len: i32,
        sig_out: *mut u8,
        sig_len: *mut i32,
        lacontext_token: u64,
    ) -> i32;

    /// Allocate a fresh `LAContext` with `touchIDAuthenticationAllowableReuseDuration`
    /// set to `ttl_secs` and register it in the Swift-side handle table. Returns
    /// the opaque token (always > 0) on success, or 0 on failure. Token 0 is a
    /// sentinel meaning "no context, prompt every sign."
    pub fn enclaveapp_se_lacontext_create(ttl_secs: f64) -> u64;

    /// Drop the `LAContext` referenced by `token`, invalidating any cached
    /// authentication. Idempotent; releasing token 0 is a no-op.
    pub fn enclaveapp_se_lacontext_release(token: u64);

    // Encryption key operations
    pub fn enclaveapp_se_generate_encryption_key(
        pub_key_out: *mut u8,
        pub_key_len: *mut i32,
        data_rep_out: *mut u8,
        data_rep_len: *mut i32,
        auth_policy: i32,
    ) -> i32;

    pub fn enclaveapp_se_encryption_public_key(
        data_rep: *const u8,
        data_rep_len: i32,
        pub_key_out: *mut u8,
        pub_key_len: *mut i32,
    ) -> i32;

    pub fn enclaveapp_se_delete_key(data_rep: *const u8, data_rep_len: i32) -> i32;

    pub fn enclaveapp_se_encrypt(
        data_rep: *const u8,
        data_rep_len: i32,
        plaintext: *const u8,
        plaintext_len: i32,
        ciphertext_out: *mut u8,
        ciphertext_len: *mut i32,
    ) -> i32;

    pub fn enclaveapp_se_decrypt(
        data_rep: *const u8,
        data_rep_len: i32,
        ciphertext: *const u8,
        ciphertext_len: i32,
        plaintext_out: *mut u8,
        plaintext_len: *mut i32,
    ) -> i32;

    // Keychain generic-password helpers (wrapping-key storage).
    //
    // Return codes:
    //   0   SE_OK
    //   4   SE_ERR_BUFFER_TOO_SMALL
    //   9   SE_ERR_KEYCHAIN_STORE
    //   10  SE_ERR_KEYCHAIN_LOAD
    //   11  SE_ERR_KEYCHAIN_DELETE
    //   12  SE_ERR_KEYCHAIN_NOT_FOUND
    // `access_group` (UTF-8 pointer) + `access_group_len`: when
    // non-null with len > 0, the bridge routes SecItemAdd through the
    // Data Protection keychain with `kSecAttrAccessGroup` set —
    // required for `.userPresence` ACL to install. Pass null / 0 to
    // use the legacy keychain (no userPresence support).
    pub fn enclaveapp_keychain_store(
        service: *const u8,
        service_len: i32,
        account: *const u8,
        account_len: i32,
        secret: *const u8,
        secret_len: i32,
        use_user_presence: i32,
        access_group: *const u8,
        access_group_len: i32,
    ) -> i32;

    // `access_group` (UTF-8 pointer) + `access_group_len`: when non-null
    // with len > 0, the bridge searches the Data Protection keychain
    // (filtered by `kSecAttrAccessGroup`) first and falls back to the
    // legacy keychain on NotFound. When null / 0, the legacy keychain
    // is queried directly. Required for binaries that store wrapping
    // keys via `enclaveapp_keychain_store` with an access group, so
    // load can find what store wrote.
    //
    // `lacontext_token`: when non-zero, the bridge passes the registered
    // LAContext via `kSecUseAuthenticationContext`. If that LAContext
    // has a recent successful `evaluatePolicy` (which is what the
    // sshenc agent's sign path arranges) the keychain reuses that auth
    // for `userPresence`-protected items, suppressing the per-call
    // biometric prompt. Token `0` is "no context, prompt independently."
    pub fn enclaveapp_keychain_load(
        service: *const u8,
        service_len: i32,
        account: *const u8,
        account_len: i32,
        secret_out: *mut u8,
        secret_len: *mut i32,
        access_group: *const u8,
        access_group_len: i32,
        lacontext_token: u64,
    ) -> i32;

    // `access_group` (UTF-8 pointer) + `access_group_len`: when non-null
    // with len > 0, the bridge sweeps both DP and legacy keychains so
    // the caller doesn't have to know which one a given item was
    // stored in. Required so a delete on an upgraded binary cleans up
    // both pre-upgrade (legacy) and post-upgrade (DP) entries for the
    // same service+account.
    pub fn enclaveapp_keychain_delete(
        service: *const u8,
        service_len: i32,
        account: *const u8,
        account_len: i32,
        access_group: *const u8,
        access_group_len: i32,
    ) -> i32;
}
