// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

// CryptoKit Secure Enclave bridge for enclaveapp.
//
// Exposes C functions callable from Rust for SE key lifecycle:
// - Check Secure Enclave availability
// - Generate signing and encryption keys
// - Extract public keys from data representations
// - Sign data (ECDSA P-256)
// - Encrypt/decrypt data (ECIES: ECDH + AES-GCM)
//
// Keys are persisted via CryptoKit's dataRepresentation, which is an opaque
// blob containing a handle to the SE key. The actual private key material
// never leaves the Secure Enclave.

import CoreGraphics
import CryptoKit
import Foundation
import LocalAuthentication
import Security

// MARK: - Result codes

let SE_OK: Int32 = 0
let SE_ERR_GENERATE: Int32 = 1
let SE_ERR_LOAD: Int32 = 2
let SE_ERR_SIGN: Int32 = 3
/// Returned **only** when a caller-supplied out-buffer is too small to
/// hold the result. The caller is expected to resize per the
/// `*_len.pointee` out-value and retry. It is a **contract error** to
/// use this code for any other failure mode — the Rust side loops on
/// it (expanding the buffer) and a misuse would turn a real error into
/// a retry storm. See `keychain.rs::generate_signing_with_retry` for
/// the retry discipline on the consumer side.
let SE_ERR_BUFFER_TOO_SMALL: Int32 = 4
let SE_ERR_NOT_AVAILABLE: Int32 = 5
let SE_ERR_ENCRYPT: Int32 = 6
let SE_ERR_DECRYPT: Int32 = 7
let SE_ERR_DELETE: Int32 = 8
let SE_ERR_KEYCHAIN_STORE: Int32 = 9
let SE_ERR_KEYCHAIN_LOAD: Int32 = 10
let SE_ERR_KEYCHAIN_DELETE: Int32 = 11
let SE_ERR_KEYCHAIN_NOT_FOUND: Int32 = 12
/// Returned when `SecItemCopyMatching` (or a store/delete) returns
/// `errSecAuthFailed` (-25293) — the OS has a "Deny" ACL decision cached
/// for this binary's code-signing identity.  Distinct from
/// `SE_ERR_KEYCHAIN_LOAD` so Rust can surface an actionable message
/// ("open Keychain Access and change Deny → Always Allow") rather than
/// the generic "keychain load error".
let SE_ERR_KEYCHAIN_AUTH_DENIED: Int32 = 13
/// Returned when `SecItemCopyMatching` returns `errSecInteractionRequired`
/// (-25308) — the item requires user presence but no authenticated LAContext
/// was provided.  This happens when `lacontext_token=0` is passed and the
/// keychain item was stored with `.userPresence` access control.  The screen
/// may be locked or biometric auth was cancelled; the caller should retry
/// after the user unlocks the screen.
let SE_ERR_KEYCHAIN_INTERACTION_REQUIRED: Int32 = 14
/// Returned when `SecItemCopyMatching` returns `errSecInteractionRequired`
/// and `CGSessionCopyCurrentDictionary()` returns nil — meaning the process
/// has no window server session at all.  Touch ID requires a window server
/// connection to display its prompt; background processes started outside of
/// launchd (e.g. `sshenc-agent &` in a shell) never get one.  Recovery:
/// restart the agent via launchd so it inherits the user's GUI session.
let SE_ERR_KEYCHAIN_NO_WINDOW_SERVER: Int32 = 15
/// Returned when the user explicitly cancels a Touch ID / biometric prompt
/// or when LocalAuthentication returns LAError.userCancel, .appCancel, or
/// .systemCancel.  The LAContext (if any) is still valid; evicting it would
/// force a fresh prompt on the next attempt with no gain.  The caller should
/// NOT evict the LAContext cache for this label.
let SE_ERR_USER_CANCEL: Int32 = 16

// MARK: - ECIES format constants

let ECIES_VERSION: UInt8 = 0x01
let ECIES_HEADER_SIZE = 1 + 65 + 12  // version + ephemeral pubkey + nonce
let ECIES_TAG_SIZE = 16

// MARK: - LAContext registry
//
// Keeps long-lived LAContext objects alive across multiple SE sign
// calls, keyed by an opaque `UInt64` token. The token is the only
// thing that crosses the FFI boundary; Rust never dereferences it.
//
// Lifetime is owned by Rust: every `enclaveapp_se_lacontext_create`
// must be paired with a matching `enclaveapp_se_lacontext_release`.
// Rust's drop / cache-eviction code path is responsible for that
// pairing — see `enclaveapp-apple::lacontext::LaContextHandle`.
//
// Token 0 is reserved as a sentinel for "no context, prompt every
// sign" — it must never appear in the registry.

private let lacontextLock = NSLock()
private var lacontextRegistry: [UInt64: LAContext] = [:]
private var lacontextNextToken: UInt64 = 0

/// Create a new LAContext with the given Touch ID reuse duration in
/// seconds, **explicitly authenticate it via `evaluatePolicy`**, and
/// register it under a fresh token. Returns the token (always > 0)
/// on success, or 0 if the user cancelled / authentication failed.
///
/// Why we authenticate up front instead of letting CryptoKit's
/// implicit SE prompt do it: with a `userPresence`-ACL'd SE key,
/// passing an unauthenticated LAContext to
/// `SecureEnclave.P256.Signing.PrivateKey(... authenticationContext:)`
/// does NOT make subsequent signs reuse a single authentication --
/// CryptoKit prompts on every sign, ignoring the reuse duration on
/// the LAContext. The reuse window only kicks in for signs that
/// follow an *explicit* `evaluatePolicy` on the LAContext. So we
/// prompt once here, mark the LAContext as authenticated, and from
/// then on the SE accepts signs from this LAContext silently for
/// `ttl_secs` -- which is the UX users actually expect ("I tap Touch
/// ID once and the agent handles the burst of signs in the next 5
/// minutes silently").
///
/// `ttl_secs == 0` collapses to "must re-auth every time" (no reuse
/// window). Apple caps the effective reuse at
/// `LATouchIDAuthenticationMaximumAllowableReuseDuration` (300s) for
/// Touch ID; values higher than that are silently clamped.
@_cdecl("enclaveapp_se_lacontext_create")
public func enclaveapp_se_lacontext_create(
    _ ttl_secs: Double,
    _ reason_ptr: UnsafePointer<UInt8>?,
    _ reason_len: Int32
) -> UInt64 {
    let ctx = LAContext()
    ctx.touchIDAuthenticationAllowableReuseDuration = max(0.0, ttl_secs)
    let reason: String
    if let ptr = reason_ptr, reason_len > 0 {
        reason = String(decoding: UnsafeBufferPointer(start: ptr, count: Int(reason_len)), as: UTF8.self)
    } else {
        reason = "Authenticate to use your Secure Enclave keys."
    }
    // Set localizedReason on the context so that implicit re-authentication
    // (e.g. when touchIDAuthenticationAllowableReuseDuration expires and
    // macOS re-prompts through a SecItem or SE key access) uses the same
    // descriptive string. Without this, implicit re-auth shows the generic
    // "[AppName] needs to authenticate to continue." default because macOS
    // reads ctx.localizedReason — not the evaluatePolicy localizedReason param.
    ctx.localizedReason = reason

    // `canEvaluatePolicy` rejects the call with an explicit error
    // before showing UI if the device has no enrolled biometrics /
    // passcode. Without this guard, `evaluatePolicy` on a freshly-
    // imaged Mac with no enrolled Touch ID throws an error that
    // surfaces as "create returned 0" with no diagnostic.
    var canEvalError: NSError?
    if !ctx.canEvaluatePolicy(.deviceOwnerAuthentication, error: &canEvalError) {
        FileHandle.standardError.write(
            ("enclaveapp: lacontext_create: device cannot evaluate "
             + ".deviceOwnerAuthentication policy: "
             + (canEvalError?.localizedDescription ?? "unknown") + "\n").data(using: .utf8)!
        )
        return 0
    }

    // Synchronously authenticate the LAContext. `evaluatePolicy` is
    // async; bridge to a synchronous return via a semaphore so the
    // C ABI caller (which expects a return value, not a callback)
    // gets a deterministic outcome.
    let semaphore = DispatchSemaphore(value: 0)
    var authed = false
    ctx.evaluatePolicy(
        .deviceOwnerAuthentication,
        localizedReason: reason
    ) { success, evalError in
        authed = success
        if !success, let err = evalError {
            // Errors that aren't "user cancelled" deserve a log line so
            // a user with a misconfigured biometric/passcode setup can
            // see *why* their LAContext keeps failing. User cancel is
            // expected and quiet.
            let nsErr = err as NSError
            if nsErr.code != LAError.userCancel.rawValue
                && nsErr.code != LAError.appCancel.rawValue
                && nsErr.code != LAError.systemCancel.rawValue
            {
                FileHandle.standardError.write(
                    ("enclaveapp: lacontext_create: evaluatePolicy failed: "
                     + nsErr.localizedDescription + "\n").data(using: .utf8)!
                )
            }
        }
        semaphore.signal()
    }
    semaphore.wait()

    if !authed {
        return 0
    }

    lacontextLock.lock()
    defer { lacontextLock.unlock() }
    lacontextNextToken &+= 1
    if lacontextNextToken == 0 { lacontextNextToken = 1 } // skip sentinel
    let token = lacontextNextToken
    lacontextRegistry[token] = ctx
    return token
}

/// Release the LAContext referenced by `token`. Idempotent — a
/// second release of the same token is a no-op. Releasing token 0
/// is a no-op.
@_cdecl("enclaveapp_se_lacontext_release")
public func enclaveapp_se_lacontext_release(_ token: UInt64) {
    if token == 0 { return }
    lacontextLock.lock()
    defer { lacontextLock.unlock() }
    if let ctx = lacontextRegistry.removeValue(forKey: token) {
        // `invalidate` clears any cached authentication so the LAContext
        // can't be reused after the Rust side has dropped it.
        ctx.invalidate()
    }
}

/// Look up the LAContext for `token`, or `nil` if not registered.
/// Caller must hold `lacontextLock` *only when reading the dict*; the
/// returned LAContext is fine to hand to CryptoKit without the lock,
/// because Rust's lifetime contract prevents concurrent release.
private func lacontextLookup(_ token: UInt64) -> LAContext? {
    if token == 0 { return nil }
    lacontextLock.lock()
    defer { lacontextLock.unlock() }
    return lacontextRegistry[token]
}

// MARK: - Helper: access control

func makeAccessControl(_ authPolicy: Int32) -> SecAccessControl? {
    var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
    switch authPolicy {
    case 1: flags.insert(.userPresence)
    case 2: flags.insert(.biometryAny)
    case 3: flags.insert(.devicePasscode)
    default: return nil
    }
    return SecAccessControlCreateWithFlags(
        nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, nil
    )
}

// MARK: - Helper: copy uncompressed public key

func copyUncompressedPubKey(
    _ rawPub: Data,
    _ pub_key_out: UnsafeMutablePointer<UInt8>,
    _ pub_key_len: UnsafeMutablePointer<Int32>
) -> Int32 {
    let uncompressedLen: Int32 = 65
    if pub_key_len.pointee < uncompressedLen {
        pub_key_len.pointee = uncompressedLen
        return SE_ERR_BUFFER_TOO_SMALL
    }
    pub_key_out[0] = 0x04
    rawPub.copyBytes(to: pub_key_out + 1, count: 64)
    pub_key_len.pointee = uncompressedLen
    return SE_OK
}

// MARK: - Helper: copy data representation

func copyDataRep(
    _ dataRep: Data,
    _ data_rep_out: UnsafeMutablePointer<UInt8>,
    _ data_rep_len: UnsafeMutablePointer<Int32>
) -> Int32 {
    let dataRepCount = Int32(dataRep.count)
    if data_rep_len.pointee < dataRepCount {
        data_rep_len.pointee = dataRepCount
        return SE_ERR_BUFFER_TOO_SMALL
    }
    dataRep.copyBytes(to: data_rep_out, count: dataRep.count)
    data_rep_len.pointee = dataRepCount
    return SE_OK
}

// MARK: - Check availability

@_cdecl("enclaveapp_se_available")
public func enclaveapp_se_available() -> Int32 {
    return SecureEnclave.isAvailable ? 1 : 0
}

/// Returns 1 if Touch ID (or device auth) is evaluable in this process,
/// 0 otherwise.  A return of 0 means one of:
///   - The process has no window server connection (started outside launchd).
///   - No biometrics enrolled and no device passcode set.
/// In either case, `lacontext_create` will return 0 and every sign with
/// a `.userPresence` key will get `errSecInteractionRequired`.
///
/// This is a startup diagnostic — call once after the agent initialises
/// and warn / auto-reload via launchd if the result is 0.
@_cdecl("enclaveapp_se_touch_id_available")
public func enclaveapp_se_touch_id_available() -> Int32 {
    // No window server session → Touch ID UI cannot be shown.
    guard CGSessionCopyCurrentDictionary() != nil else {
        return 0
    }
    let ctx = LAContext()
    var error: NSError?
    return ctx.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) ? 1 : 0
}

// MARK: - Signing key operations

/// Generate a new Secure Enclave P-256 signing key.
/// Returns the data representation (opaque blob for persistence) and raw public key.
///
/// - pub_key_out: buffer for 65-byte uncompressed public key (0x04 || X || Y)
/// - pub_key_len: in/out, must be >= 65
/// - data_rep_out: buffer for data representation
/// - data_rep_len: in/out, must be large enough (typically ~300 bytes)
/// - auth_policy: 0 = no auth, 1 = any, 2 = biometric only, 3 = password only
@_cdecl("enclaveapp_se_generate_signing_key")
public func enclaveapp_se_generate_signing_key(
    _ pub_key_out: UnsafeMutablePointer<UInt8>,
    _ pub_key_len: UnsafeMutablePointer<Int32>,
    _ data_rep_out: UnsafeMutablePointer<UInt8>,
    _ data_rep_len: UnsafeMutablePointer<Int32>,
    _ auth_policy: Int32
) -> Int32 {
    return traceDuration("se_generate_signing_key auth_policy=\(auth_policy)") {
        guard SecureEnclave.isAvailable else {
            return SE_ERR_NOT_AVAILABLE
        }

        do {
            let key: SecureEnclave.P256.Signing.PrivateKey
            if auth_policy != 0 {
                guard let accessControl = makeAccessControl(auth_policy) else {
                    return SE_ERR_GENERATE
                }
                key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: accessControl)
            } else {
                key = try SecureEnclave.P256.Signing.PrivateKey()
            }

            let rc = copyUncompressedPubKey(key.publicKey.rawRepresentation, pub_key_out, pub_key_len)
            if rc != SE_OK { return rc }

            return copyDataRep(key.dataRepresentation, data_rep_out, data_rep_len)
        } catch {
            return SE_ERR_GENERATE
        }
    }
}

/// Extract the public key from a signing key's persisted data representation.
@_cdecl("enclaveapp_se_signing_public_key")
public func enclaveapp_se_signing_public_key(
    _ data_rep: UnsafePointer<UInt8>,
    _ data_rep_len: Int32,
    _ pub_key_out: UnsafeMutablePointer<UInt8>,
    _ pub_key_len: UnsafeMutablePointer<Int32>
) -> Int32 {
    return traceDuration("se_signing_public_key") {
        do {
            let data = Data(bytes: data_rep, count: Int(data_rep_len))
            let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: data)
            return copyUncompressedPubKey(key.publicKey.rawRepresentation, pub_key_out, pub_key_len)
        } catch {
            return SE_ERR_LOAD
        }
    }
}

/// Sign a message using a signing key loaded from its data representation.
/// CryptoKit hashes the message with SHA-256 internally.
/// Returns a DER-encoded ECDSA signature.
@_cdecl("enclaveapp_se_sign")
public func enclaveapp_se_sign(
    _ data_rep: UnsafePointer<UInt8>,
    _ data_rep_len: Int32,
    _ message: UnsafePointer<UInt8>,
    _ message_len: Int32,
    _ sig_out: UnsafeMutablePointer<UInt8>,
    _ sig_len: UnsafeMutablePointer<Int32>,
    _ lacontext_token: UInt64
) -> Int32 {
    return traceDuration("se_sign message_len=\(message_len) ctx=\(lacontext_token)") {
        do {
            let keyData = Data(bytes: data_rep, count: Int(data_rep_len))
            let key: SecureEnclave.P256.Signing.PrivateKey
            if let ctx = lacontextLookup(lacontext_token) {
                // Reusable context path — first sign on a fresh ctx
                // prompts the user; subsequent signs within the
                // ctx's `touchIDAuthenticationAllowableReuseDuration`
                // window are silent.
                key = try SecureEnclave.P256.Signing.PrivateKey(
                    dataRepresentation: keyData,
                    authenticationContext: ctx
                )
            } else {
                // Strict path — fresh implicit context per sign,
                // SEP enforces a prompt every time the key has a
                // user-presence access control.
                key = try SecureEnclave.P256.Signing.PrivateKey(
                    dataRepresentation: keyData
                )
            }

            let msgData = Data(bytes: message, count: Int(message_len))
            let signature = try key.signature(for: msgData)

            let derSig = signature.derRepresentation
            let derCount = Int32(derSig.count)
            if sig_len.pointee < derCount {
                sig_len.pointee = derCount
                return SE_ERR_BUFFER_TOO_SMALL
            }
            derSig.copyBytes(to: sig_out, count: derSig.count)
            sig_len.pointee = derCount

            return SE_OK
        } catch {
            // Distinguish user-cancel from real errors so Rust doesn't
            // evict the LAContext cache when the user simply cancelled
            // the prompt. The LAContext is still valid — evicting it
            // forces a fresh Touch ID prompt on the next sign.
            let nsErr = error as NSError
            if nsErr.domain == LAErrorDomain {
                let laCode = nsErr.code
                if laCode == LAError.userCancel.rawValue
                    || laCode == LAError.appCancel.rawValue
                    || laCode == LAError.systemCancel.rawValue
                {
                    FileHandle.standardError.write(Data((
                        "enclaveapp: se_sign: user cancelled (LAError \(laCode))\n"
                    ).utf8))
                    return SE_ERR_USER_CANCEL
                }
                FileHandle.standardError.write(Data((
                    "enclaveapp: se_sign: LAError \(laCode): \(nsErr.localizedDescription)\n"
                ).utf8))
            } else {
                FileHandle.standardError.write(Data((
                    "enclaveapp: se_sign: \(nsErr.domain) \(nsErr.code): \(nsErr.localizedDescription)\n"
                ).utf8))
            }
            return SE_ERR_SIGN
        }
    }
}

// MARK: - Encryption key operations

/// Generate a new Secure Enclave P-256 key agreement key.
/// Returns the data representation and raw public key.
@_cdecl("enclaveapp_se_generate_encryption_key")
public func enclaveapp_se_generate_encryption_key(
    _ pub_key_out: UnsafeMutablePointer<UInt8>,
    _ pub_key_len: UnsafeMutablePointer<Int32>,
    _ data_rep_out: UnsafeMutablePointer<UInt8>,
    _ data_rep_len: UnsafeMutablePointer<Int32>,
    _ auth_policy: Int32
) -> Int32 {
    guard SecureEnclave.isAvailable else {
        return SE_ERR_NOT_AVAILABLE
    }

    do {
        let key: SecureEnclave.P256.KeyAgreement.PrivateKey
        if auth_policy != 0 {
            guard let accessControl = makeAccessControl(auth_policy) else {
                return SE_ERR_GENERATE
            }
            key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: accessControl)
        } else {
            key = try SecureEnclave.P256.KeyAgreement.PrivateKey()
        }

        let rc = copyUncompressedPubKey(key.publicKey.rawRepresentation, pub_key_out, pub_key_len)
        if rc != SE_OK { return rc }

        return copyDataRep(key.dataRepresentation, data_rep_out, data_rep_len)
    } catch {
        return SE_ERR_GENERATE
    }
}

/// Extract the public key from an encryption key's persisted data representation.
@_cdecl("enclaveapp_se_encryption_public_key")
public func enclaveapp_se_encryption_public_key(
    _ data_rep: UnsafePointer<UInt8>,
    _ data_rep_len: Int32,
    _ pub_key_out: UnsafeMutablePointer<UInt8>,
    _ pub_key_len: UnsafeMutablePointer<Int32>
) -> Int32 {
    do {
        let data = Data(bytes: data_rep, count: Int(data_rep_len))
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: data)
        return copyUncompressedPubKey(key.publicKey.rawRepresentation, pub_key_out, pub_key_len)
    } catch {
        return SE_ERR_LOAD
    }
}

/// Delete a Secure Enclave key referenced by its persistent data representation.
@_cdecl("enclaveapp_se_delete_key")
public func enclaveapp_se_delete_key(
    _ data_rep: UnsafePointer<UInt8>,
    _ data_rep_len: Int32
) -> Int32 {
    let keyRef = Data(bytes: data_rep, count: Int(data_rep_len))
    let query: [String: Any] = [kSecValuePersistentRef as String: keyRef]
    let status = SecItemDelete(query as CFDictionary)
    keychainTrace(
        "op=se_key_delete data_rep_len=\(data_rep_len) status=\(status)"
    )

    switch status {
    case errSecSuccess, errSecItemNotFound:
        return SE_OK
    default:
        return SE_ERR_DELETE
    }
}

/// ECIES encrypt using the SE key's public key.
///
/// 1. Load encryption key from data_rep to get its public key
/// 2. Generate ephemeral P256.KeyAgreement.PrivateKey (in software, NOT in SE)
/// 3. ECDH shared secret between ephemeral private key and SE key's public key
/// 4. Derive symmetric key via X9.63 KDF with ephemeral pubkey as sharedInfo
/// 5. AES-GCM seal
/// 6. Output: [0x01 version] [65-byte ephemeral pubkey] [12-byte nonce] [ciphertext] [16-byte tag]
@_cdecl("enclaveapp_se_encrypt")
public func enclaveapp_se_encrypt(
    _ data_rep: UnsafePointer<UInt8>,
    _ data_rep_len: Int32,
    _ plaintext: UnsafePointer<UInt8>,
    _ plaintext_len: Int32,
    _ ciphertext_out: UnsafeMutablePointer<UInt8>,
    _ ciphertext_len: UnsafeMutablePointer<Int32>
) -> Int32 {
    do {
        // Load SE key to get its public key
        let keyData = Data(bytes: data_rep, count: Int(data_rep_len))
        let seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: keyData)
        let sePubKey = seKey.publicKey

        // Generate ephemeral key pair (in software)
        let ephemeralKey = P256.KeyAgreement.PrivateKey()

        // ECDH: ephemeral private key + SE public key
        let sharedSecret = try ephemeralKey.sharedSecretFromKeyAgreement(with: sePubKey)

        // Derive symmetric key with ephemeral pubkey as sharedInfo
        let ephemeralPubRaw = ephemeralKey.publicKey.x963Representation
        let symKey = sharedSecret.x963DerivedSymmetricKey(
            using: SHA256.self,
            sharedInfo: ephemeralPubRaw,
            outputByteCount: 32
        )

        // AES-GCM seal
        let ptData = Data(bytes: plaintext, count: Int(plaintext_len))
        let sealedBox = try AES.GCM.seal(ptData, using: symKey)

        // Build output: version(1) + ephemeral_pub(65) + nonce(12) + ciphertext + tag(16)
        var output = Data()
        output.append(ECIES_VERSION)
        output.append(ephemeralPubRaw)  // 65 bytes (0x04 || x || y)
        output.append(contentsOf: sealedBox.nonce)
        output.append(sealedBox.ciphertext)
        output.append(sealedBox.tag)

        let outputCount = Int32(output.count)
        if ciphertext_len.pointee < outputCount {
            ciphertext_len.pointee = outputCount
            return SE_ERR_BUFFER_TOO_SMALL
        }
        output.copyBytes(to: ciphertext_out, count: output.count)
        ciphertext_len.pointee = outputCount

        return SE_OK
    } catch {
        return SE_ERR_ENCRYPT
    }
}

/// ECIES decrypt using the SE key's private key.
///
/// 1. Parse ciphertext: version(1) + ephemeral_pub(65) + nonce(12) + encrypted + tag(16)
/// 2. Reconstruct ephemeral public key
/// 3. ECDH: SE private key + ephemeral public key
/// 4. Derive same symmetric key
/// 5. AES-GCM open
@_cdecl("enclaveapp_se_decrypt")
public func enclaveapp_se_decrypt(
    _ data_rep: UnsafePointer<UInt8>,
    _ data_rep_len: Int32,
    _ ciphertext: UnsafePointer<UInt8>,
    _ ciphertext_len: Int32,
    _ plaintext_out: UnsafeMutablePointer<UInt8>,
    _ plaintext_len: UnsafeMutablePointer<Int32>,
    _ lacontext_token: UInt64
) -> Int32 {
    do {
        let ctLen = Int(ciphertext_len)
        let minLen = ECIES_HEADER_SIZE + ECIES_TAG_SIZE
        guard ctLen >= minLen else {
            return SE_ERR_DECRYPT
        }

        let ctData = Data(bytes: ciphertext, count: ctLen)

        // Parse version
        guard ctData[0] == ECIES_VERSION else {
            return SE_ERR_DECRYPT
        }

        // Parse ephemeral public key (65 bytes x963)
        let ephemeralPubRaw = ctData[1..<66]
        let ephemeralPubKey = try P256.KeyAgreement.PublicKey(x963Representation: ephemeralPubRaw)

        // Parse nonce (12 bytes)
        let nonce = try AES.GCM.Nonce(data: ctData[66..<78])

        // Parse ciphertext + tag
        let encryptedLen = ctLen - ECIES_HEADER_SIZE - ECIES_TAG_SIZE
        let encrypted = ctData[78..<(78 + encryptedLen)]
        let tag = ctData[(78 + encryptedLen)..<ctLen]

        // Load SE key and perform ECDH
        let keyData = Data(bytes: data_rep, count: Int(data_rep_len))
        let seKey: SecureEnclave.P256.KeyAgreement.PrivateKey
        if let ctx = lacontextLookup(lacontext_token) {
            seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                dataRepresentation: keyData,
                authenticationContext: ctx
            )
        } else {
            seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: keyData)
        }
        let sharedSecret = try seKey.sharedSecretFromKeyAgreement(with: ephemeralPubKey)

        // Derive same symmetric key with ephemeral pubkey as sharedInfo
        let symKey = sharedSecret.x963DerivedSymmetricKey(
            using: SHA256.self,
            sharedInfo: ephemeralPubRaw,
            outputByteCount: 32
        )

        // AES-GCM open
        let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: encrypted, tag: tag)
        let plaintext = try AES.GCM.open(sealedBox, using: symKey)

        let ptCount = Int32(plaintext.count)
        if plaintext_len.pointee < ptCount {
            plaintext_len.pointee = ptCount
            return SE_ERR_BUFFER_TOO_SMALL
        }
        plaintext.copyBytes(to: plaintext_out, count: plaintext.count)
        plaintext_len.pointee = ptCount

        return SE_OK
    } catch {
        return SE_ERR_DECRYPT
    }
}

// MARK: - Keychain helpers (generic-password wrapping keys)
//
// These helpers wrap the legacy (file-based) keychain's
// kSecClassGenericPassword items. Rust calls them to store, load, and
// delete the 32-byte AES wrapping key used to encrypt the SE
// dataRepresentation before it's written to `.handle` on disk.
//
// DO NOT set `kSecUseDataProtectionKeychain: true` — on unsigned builds
// (Homebrew, cargo build) the modern Data Protection keychain returns
// errSecMissingEntitlement (-34018). The legacy keychain accepts
// unsigned callers.
//
// Items are created with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`:
// the device must be unlocked to read them, and they do NOT sync via
// iCloud / migrate across devices.

/// Open the invoking user's login keychain by explicit path.
///
/// Security.framework's default-keychain lookup goes through
/// `CFPreferences`, which is keyed off the process's `$HOME`. A
/// caller that overrides `$HOME` (integration tests via `assert_cmd`,
/// `awsenc serve` invoked by the AWS CLI under a launchd sandbox,
/// cron, etc.) gets `errSecNoDefaultKeychain` back, at which point
/// `SecItemAdd` falls into a system-modal
/// "A keychain cannot be found to store '<account>'" alert.
///
/// We bypass that entirely: `getpwuid(getuid())` returns the real
/// user's home directory from the password database regardless of
/// `$HOME`, and `SecKeychainOpen` on
/// `~/Library/Keychains/login.keychain-db` produces a handle that
/// subsequent `SecItemAdd` / `SecItemCopyMatching` / `SecItemDelete`
/// calls use via `kSecUseKeychain` / `kSecMatchSearchList`. The
/// first-run "Always Allow" ACL prompt (a SecTrust decision driven
/// by the item op itself, not by default-keychain lookup) still
/// fires normally — unsigned-build UX is preserved.
///
/// `SecKeychainOpen` is deprecated alongside `SecKeychain` but is
/// still the only API that reaches the legacy file-based keychain;
/// the modern Data Protection keychain is unavailable on unsigned
/// builds (see the top-of-module comment).
// MARK: - Crypto-op timing and prompt-detection instrumentation
//
// Every FFI entrypoint below is wrapped with `traceDuration`, which
// measures the wall-clock time of the whole Apple call (including
// CryptoKit's internal `SecKeyCreateSignature` / `SecItemAdd` / …
// invocations). Two outputs come from that measurement:
//
// 1. **Always-on, shippable warning**: if an op takes longer than
//    the threshold (default 1000 ms, overridable via
//    `ENCLAVEAPP_SLOW_OP_THRESHOLD_MS`), write a one-line warning to
//    stderr. Human-visible password / Touch ID / passcode prompts
//    block for ≥1000 ms so any crossing of the threshold almost
//    certainly means a sheet appeared. Normal cold-cache or
//    cold-process starts are well under this.
// 2. **Opt-in verbose trace**: when `ENCLAVEAPP_KEYCHAIN_TRACE=1`
//    is set, write a line for every op (under the threshold or
//    above) and every inner `SecItem*` call with its OSStatus. Used
//    for exhaustive debugging.
//
// The warning branch is cheap and always compiled in; it's safe to
// ship. Users who never hit a prompt never see output.

private let slowCryptoOpThresholdMs: UInt64 = {
    if let raw = ProcessInfo.processInfo.environment["ENCLAVEAPP_SLOW_OP_THRESHOLD_MS"],
       let parsed = UInt64(raw) {
        return parsed
    }
    return 1000
}()

private let keychainTraceEnabled: Bool = {
    ProcessInfo.processInfo.environment["ENCLAVEAPP_KEYCHAIN_TRACE"] == "1"
}()

/// Emit a detail line (inner `SecItem*` OSStatus, etc.) when verbose
/// trace mode is on. No-op otherwise.
private func keychainTrace(_ line: @autoclosure () -> String) {
    guard keychainTraceEnabled else { return }
    FileHandle.standardError.write(Data(("keychain_trace: " + line() + "\n").utf8))
}

/// Measure the duration of `body`. On crossing the slow-op threshold
/// emit a shippable warning (suspected prompt); in verbose mode,
/// always emit a timing line for every call.
private func traceDuration<T>(_ op: String, _ body: () -> T) -> T {
    let start = DispatchTime.now()
    let result = body()
    let elapsed_ms =
        (DispatchTime.now().uptimeNanoseconds - start.uptimeNanoseconds) / 1_000_000

    if elapsed_ms >= slowCryptoOpThresholdMs {
        FileHandle.standardError.write(Data((
            "enclaveapp: crypto op '\(op)' took \(elapsed_ms)ms " +
            "(threshold=\(slowCryptoOpThresholdMs)ms) — likely triggered a " +
            "password / biometric prompt. Set ENCLAVEAPP_KEYCHAIN_TRACE=1 " +
            "for per-call detail.\n"
        ).utf8))
    } else if keychainTraceEnabled {
        FileHandle.standardError.write(Data(
            "keychain_trace: op=\(op) elapsed_ms=\(elapsed_ms)\n".utf8
        ))
    }
    return result
}

/// Return `true` when Security.framework can locate a default
/// keychain for this process. Query-only — it never prompts.
private func hasDefaultKeychain() -> Bool {
    var kc: SecKeychain?
    let status = SecKeychainCopyDefault(&kc)
    return status == errSecSuccess && kc != nil
}

/// Open the invoking user's login keychain by explicit absolute path
/// and try a silent empty-password unlock.
private func openLoginKeychain() -> SecKeychain? {
    guard let pw = getpwuid(getuid()) else {
        return nil
    }
    let home = String(cString: pw.pointee.pw_dir)
    // Modern macOS stores the login keychain as `.keychain-db`; older
    // installs may still have `.keychain`. Try both so migrated
    // systems aren't broken.
    let candidates = [
        "\(home)/Library/Keychains/login.keychain-db",
        "\(home)/Library/Keychains/login.keychain",
    ]
    for path in candidates {
        var kc: SecKeychain?
        if SecKeychainOpen(path, &kc) == errSecSuccess, let kc = kc {
            // Best-effort silent unlock with the empty password.
            // Interactive dev sessions are already unlocked (no-op);
            // headless contexts whose keychain is locked but has no
            // password get unlocked here. Any real-password failure
            // surfaces through the subsequent op.
            _ = SecKeychainUnlock(kc, 0, nil, true)
            return kc
        }
    }
    return nil
}

private func makeServiceData(_ service: UnsafePointer<UInt8>, _ len: Int32) -> Data {
    return Data(bytes: service, count: Int(len))
}

private func makeAccountString(_ account: UnsafePointer<UInt8>, _ len: Int32) -> String? {
    let bytes = Data(bytes: account, count: Int(len))
    return String(data: bytes, encoding: .utf8)
}

private func makeServiceString(_ service: UnsafePointer<UInt8>, _ len: Int32) -> String? {
    let bytes = Data(bytes: service, count: Int(len))
    return String(data: bytes, encoding: .utf8)
}

private func makeUtf8String(_ ptr: UnsafePointer<UInt8>, _ len: Int32) -> String? {
    let bytes = Data(bytes: ptr, count: Int(len))
    return String(data: bytes, encoding: .utf8)
}

/// Store (or replace) an opaque secret in the keychain as a generic
/// password. Any existing entry with the same service+account pair is
/// removed first, so the call is effectively an upsert.
///
/// When `use_user_presence` is non-zero the item is protected by a
/// `.userPresence` access-control flag (biometric-or-device-passcode)
/// instead of the default code-signature ACL. Accessing the item then
/// triggers a LocalAuthentication prompt instead of the legacy keychain
/// "Always Allow" dialog, and the authorization is tied to the user
/// rather than to a specific binary signature — so rebuilding an
/// unsigned binary no longer invalidates access.
@_cdecl("enclaveapp_keychain_store")
public func enclaveapp_keychain_store(
    _ service: UnsafePointer<UInt8>, _ service_len: Int32,
    _ account: UnsafePointer<UInt8>, _ account_len: Int32,
    _ secret: UnsafePointer<UInt8>, _ secret_len: Int32,
    _ use_user_presence: Int32,
    _ access_group: UnsafePointer<UInt8>?, _ access_group_len: Int32
) -> Int32 {
    return traceDuration("keychain_store userPresence=\(use_user_presence)") {
      guard let serviceStr = makeServiceString(service, service_len) else {
        return SE_ERR_KEYCHAIN_STORE
    }
    guard let accountStr = makeAccountString(account, account_len) else {
        return SE_ERR_KEYCHAIN_STORE
    }
    let secretData = Data(bytes: secret, count: Int(secret_len))

    // When the caller supplies a `keychain-access-groups`-style access
    // group string we route the op through the modern Data Protection
    // keychain (`kSecUseDataProtectionKeychain: true`). That keychain
    // accepts `kSecAttrAccessControl(.userPresence)` cleanly — the
    // legacy file-based keychain rejects the same attribute with
    // `errSecParam` (-50) — so this is the only path on which the
    // userPresence gate actually fires. The caller's binary must be
    // codesigned with a `keychain-access-groups` entitlement
    // containing the same group, otherwise SecItemAdd returns
    // `errSecMissingEntitlement` (-34018) and we fall through to the
    // legacy-keychain path below.
    let accessGroup: String? = {
        guard let ptr = access_group, access_group_len > 0 else { return nil }
        return makeUtf8String(ptr, access_group_len)
    }()
    let useDPKeychain = (accessGroup != nil)

    // Legacy-keychain path needs an explicit SecKeychain ref when no
    // default keychain is reachable (test contexts that override $HOME,
    // launchd sandboxes). The Data Protection path doesn't use
    // SecKeychain at all — accessGroup + access-control attribute
    // identify the item.
    let useExplicit = !useDPKeychain && !hasDefaultKeychain()
    let kc: SecKeychain? = useExplicit ? openLoginKeychain() : nil
    if useExplicit && kc == nil {
        return SE_ERR_KEYCHAIN_NOT_FOUND
    }

    var deleteQuery: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: serviceStr,
        kSecAttrAccount as String: accountStr,
    ]
    if useDPKeychain {
        deleteQuery[kSecUseDataProtectionKeychain as String] = true
        if let group = accessGroup {
            deleteQuery[kSecAttrAccessGroup as String] = group
        }
    }
    if let kc = kc { deleteQuery[kSecMatchSearchList as String] = [kc] }
    let predeleteStatus = SecItemDelete(deleteQuery as CFDictionary)
    keychainTrace(
        "op=store_predelete service=\(serviceStr) account=\(accountStr) status=\(predeleteStatus)"
    )

    var addQuery: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: serviceStr,
        kSecAttrAccount as String: accountStr,
        kSecValueData as String: secretData,
    ]
    if useDPKeychain {
        addQuery[kSecUseDataProtectionKeychain as String] = true
        if let group = accessGroup {
            addQuery[kSecAttrAccessGroup as String] = group
        }
    }
    if use_user_presence != 0 {
        // Bind access to user presence (Touch ID or device passcode)
        // via LocalAuthentication. `kSecAttrAccessControl` implies
        // accessibility, so `kSecAttrAccessible` must NOT also be set.
        var acError: Unmanaged<CFError>?
        guard let ac = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .userPresence,
            &acError
        ) else {
            acError?.release()
            return SE_ERR_KEYCHAIN_STORE
        }
        addQuery[kSecAttrAccessControl as String] = ac
    } else {
        addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    }
    if let kc = kc { addQuery[kSecUseKeychain as String] = kc }
    var status = SecItemAdd(addQuery as CFDictionary, nil)
    keychainTrace(
        "op=store_add service=\(serviceStr) account=\(accountStr) " +
        "userPresence=\(use_user_presence) dp=\(useDPKeychain) " +
        "group=\(accessGroup ?? "<nil>") status=\(status)"
    )

    // Two failure modes that share a fallback:
    //
    // 1. DP keychain + access group asked for, but the caller's binary
    //    isn't entitled — `errSecMissingEntitlement` (-34018). Drop
    //    DP/access-group flags and retry against the legacy keychain.
    //    UserPresence won't fire either way; the wrapping key still
    //    needs to land somewhere so the agent can sign.
    // 2. Legacy keychain + `.userPresence` ACL — `errSecParam` (-50).
    //    Drop the ACL and retry without it.
    //
    // Both fallbacks surface a stderr line so an operator who
    // configured user presence sees the downgrade explicitly.
    if useDPKeychain && status == errSecMissingEntitlement {
        FileHandle.standardError.write(Data((
            "enclaveapp: Data Protection keychain rejected access group " +
            "'\(accessGroup ?? "")' (OSStatus=\(status), errSecMissingEntitlement) — " +
            "binary lacks the matching keychain-access-groups entitlement. " +
            "Falling back to legacy keychain — userPresence gate won't fire " +
            "for this key.\n"
        ).utf8))
        addQuery.removeValue(forKey: kSecUseDataProtectionKeychain as String)
        addQuery.removeValue(forKey: kSecAttrAccessGroup as String)
        if use_user_presence != 0 {
            // Userpresence on legacy keychain is errSecParam → flatten now
            addQuery.removeValue(forKey: kSecAttrAccessControl as String)
            addQuery[kSecAttrAccessible as String] =
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        }
        // The DP-keychain initial path runs with `useExplicit = false`,
        // so we never opened a SecKeychain handle. If the default
        // keychain isn't reachable (typical of `$HOME`-overridden
        // contexts: e2e tests, launchd sandboxes, cron) the fallback
        // SecItemAdd will fall into a system-modal "A keychain cannot
        // be found to store '<account>'" dialog the user can't
        // dismiss. Pin the fallback to the explicit login-keychain
        // handle just like the non-DP path does.
        var fallback_kc: SecKeychain? = nil
        if !hasDefaultKeychain() {
            guard let kc_explicit = openLoginKeychain() else {
                keychainTrace(
                    "op=store_add_fallback_legacy_open_login_failed service=\(serviceStr) account=\(accountStr)"
                )
                return SE_ERR_KEYCHAIN_NOT_FOUND
            }
            fallback_kc = kc_explicit
            // The DP-side predelete didn't reach the legacy keychain.
            // If a stale legacy item exists under the same
            // service+account, SecItemAdd would return
            // errSecDuplicateItem; predelete to make the retry an
            // upsert.
            let legacyDeleteQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: serviceStr,
                kSecAttrAccount as String: accountStr,
                kSecMatchSearchList as String: [kc_explicit],
            ]
            let legacyPredelete = SecItemDelete(legacyDeleteQuery as CFDictionary)
            keychainTrace(
                "op=store_predelete_legacy service=\(serviceStr) account=\(accountStr) status=\(legacyPredelete)"
            )
            addQuery[kSecUseKeychain as String] = kc_explicit
        }
        let _ = fallback_kc
        status = SecItemAdd(addQuery as CFDictionary, nil)
        keychainTrace(
            "op=store_add_fallback_legacy service=\(serviceStr) account=\(accountStr) status=\(status)"
        )
    } else if use_user_presence != 0
        && (status == errSecMissingEntitlement || status == errSecParam)
    {
        FileHandle.standardError.write(Data((
            "enclaveapp: wrapping-key userPresence ACL rejected " +
            "(OSStatus=\(status)); falling back to non-userPresence storage — " +
            "userPresence gate won't fire for this key\n"
        ).utf8))
        addQuery.removeValue(forKey: kSecAttrAccessControl as String)
        addQuery[kSecAttrAccessible as String] =
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        status = SecItemAdd(addQuery as CFDictionary, nil)
        keychainTrace(
            "op=store_add_fallback service=\(serviceStr) account=\(accountStr) status=\(status)"
        )
    }

    return status == errSecSuccess ? SE_OK : SE_ERR_KEYCHAIN_STORE
    }
}

/// Load a previously-stored secret by service+account. Returns
/// `SE_ERR_KEYCHAIN_NOT_FOUND` if no entry exists.
///
/// `lacontext_token` plumbs an already-authenticated `LAContext` into
/// the keychain query via `kSecUseAuthenticationContext`. When the
/// stored item is `userPresence`-protected and the LAContext has a
/// recent successful `evaluatePolicy` (which is what
/// `enclaveapp_se_lacontext_create` does), `SecItemCopyMatching`
/// reuses that authentication and skips the biometric prompt -- so a
/// single user prompt covers both the wrapping-key keychain decrypt
/// and the subsequent SE sign. Token `0` is the sentinel for "no
/// context, prompt independently if the item is presence-protected".
@_cdecl("enclaveapp_keychain_load")
public func enclaveapp_keychain_load(
    _ service: UnsafePointer<UInt8>, _ service_len: Int32,
    _ account: UnsafePointer<UInt8>, _ account_len: Int32,
    _ secret_out: UnsafeMutablePointer<UInt8>, _ secret_len: UnsafeMutablePointer<Int32>,
    _ access_group: UnsafePointer<UInt8>?, _ access_group_len: Int32,
    _ lacontext_token: UInt64
) -> Int32 {
    return traceDuration("keychain_load") {
        guard let serviceStr = makeServiceString(service, service_len) else {
        return SE_ERR_KEYCHAIN_LOAD
    }
    guard let accountStr = makeAccountString(account, account_len) else {
        return SE_ERR_KEYCHAIN_LOAD
    }

    let accessGroup: String? = {
        guard let ptr = access_group, access_group_len > 0 else { return nil }
        return makeUtf8String(ptr, access_group_len)
    }()

    let authContext: LAContext? = lacontextLookup(lacontext_token)

    // Helper that performs a SecItemCopyMatching with the given keychain
    // routing options and copies the result into the caller's buffer.
    // Returns the SE_* result code (or `nil` on errSecItemNotFound,
    // letting the caller decide whether to retry on a different
    // keychain).
    func tryLoad(useDP: Bool, useExplicitLegacy: Bool) -> Int32? {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceStr,
            kSecAttrAccount as String: accountStr,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        if let ctx = authContext {
            query[kSecUseAuthenticationContext as String] = ctx
        }
        if useDP {
            query[kSecUseDataProtectionKeychain as String] = true
            if let group = accessGroup {
                query[kSecAttrAccessGroup as String] = group
            }
        } else if useExplicitLegacy {
            guard let kc = openLoginKeychain() else { return SE_ERR_KEYCHAIN_NOT_FOUND }
            query[kSecMatchSearchList as String] = [kc]
        }
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        keychainTrace(
            "op=load service=\(serviceStr) account=\(accountStr) " +
            "dp=\(useDP) group=\(accessGroup ?? "<nil>") status=\(status)"
        )
        if status == errSecItemNotFound {
            return nil
        }
        if status == errSecAuthFailed {
            return SE_ERR_KEYCHAIN_AUTH_DENIED
        }
        if status == errSecInteractionRequired {
            // Distinguish "no window server" (agent started outside launchd)
            // from "screen locked" (agent is fine, user needs to unlock).
            // CGSessionCopyCurrentDictionary() returns nil when the process
            // has no window server connection at all.
            if CGSessionCopyCurrentDictionary() == nil {
                return SE_ERR_KEYCHAIN_NO_WINDOW_SERVER
            }
            return SE_ERR_KEYCHAIN_INTERACTION_REQUIRED
        }
        if status == errSecUserCanceled {
            // User explicitly cancelled the keychain auth prompt. The
            // LAContext (if any) is still valid; evicting it would force
            // a fresh prompt on retry with no gain.
            FileHandle.standardError.write(Data((
                "enclaveapp: keychain_load: user cancelled (errSecUserCanceled)\n"
            ).utf8))
            return SE_ERR_USER_CANCEL
        }
        if status != errSecSuccess {
            FileHandle.standardError.write(Data((
                "enclaveapp: keychain_load: SecItemCopyMatching failed: " +
                "OSStatus \(status) service=\(serviceStr) account=\(accountStr)\n"
            ).utf8))
            return SE_ERR_KEYCHAIN_LOAD
        }
        guard let data = item as? Data else {
            return SE_ERR_KEYCHAIN_LOAD
        }
        let count = Int32(data.count)
        if secret_len.pointee < count {
            secret_len.pointee = count
            return SE_ERR_BUFFER_TOO_SMALL
        }
        data.copyBytes(to: secret_out, count: data.count)
        secret_len.pointee = count
        return SE_OK
    }

    // When the caller supplies an access group, try the Data Protection
    // keychain first — that's where `enclaveapp_keychain_store` puts
    // entitled-binary items. On NotFound, fall back to the legacy
    // keychain so wrapping-key items written by older binaries (or by
    // builds without the entitlement) remain reachable. The fallback
    // makes upgrades transparent: existing v<entitled> keys stored to
    // the legacy keychain still decrypt cleanly under the new binary.
    if accessGroup != nil {
        if let result = tryLoad(useDP: true, useExplicitLegacy: false) {
            return result
        }
        // DP miss → fall through to legacy.
    }
    let useExplicitLegacy = !hasDefaultKeychain()
    if let result = tryLoad(useDP: false, useExplicitLegacy: useExplicitLegacy) {
        return result
    }
    return SE_ERR_KEYCHAIN_NOT_FOUND
    }
}

/// Delete the generic-password entry for a service+account pair. It is
/// not an error if the entry does not exist — the caller treats that as
/// idempotent cleanup.
@_cdecl("enclaveapp_keychain_delete")
public func enclaveapp_keychain_delete(
    _ service: UnsafePointer<UInt8>, _ service_len: Int32,
    _ account: UnsafePointer<UInt8>, _ account_len: Int32,
    _ access_group: UnsafePointer<UInt8>?, _ access_group_len: Int32
) -> Int32 {
    return traceDuration("keychain_delete") {
        guard let serviceStr = makeServiceString(service, service_len) else {
            return SE_ERR_KEYCHAIN_DELETE
        }
        guard let accountStr = makeAccountString(account, account_len) else {
            return SE_ERR_KEYCHAIN_DELETE
        }

        let accessGroup: String? = {
            guard let ptr = access_group, access_group_len > 0 else { return nil }
            return makeUtf8String(ptr, access_group_len)
        }()

        // Helper that performs a SecItemDelete with the given keychain
        // routing options. Returns the OSStatus (success / NotFound /
        // error). Caller treats NotFound as a benign "already gone".
        func tryDelete(useDP: Bool, useExplicitLegacy: Bool) -> OSStatus {
            var query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: serviceStr,
                kSecAttrAccount as String: accountStr,
            ]
            if useDP {
                query[kSecUseDataProtectionKeychain as String] = true
                if let group = accessGroup {
                    query[kSecAttrAccessGroup as String] = group
                }
            } else if useExplicitLegacy {
                guard let kc = openLoginKeychain() else {
                    return errSecNoDefaultKeychain
                }
                query[kSecMatchSearchList as String] = [kc]
            }
            let status = SecItemDelete(query as CFDictionary)
            keychainTrace(
                "op=delete service=\(serviceStr) account=\(accountStr) " +
                "dp=\(useDP) group=\(accessGroup ?? "<nil>") status=\(status)"
            )
            return status
        }

        // When the caller supplies an access group, sweep both
        // keychains. Items written by an entitled binary live in the
        // DP keychain; items written by older / unentitled builds live
        // in the legacy keychain. We don't know which one a given
        // service+account was stored in, and the caller treats delete
        // as idempotent, so removing from both is safe and ensures we
        // don't leave stale entries behind on either side.
        var dpStatus: OSStatus = errSecItemNotFound
        if accessGroup != nil {
            dpStatus = tryDelete(useDP: true, useExplicitLegacy: false)
        }
        let legacyStatus = tryDelete(
            useDP: false,
            useExplicitLegacy: !hasDefaultKeychain()
        )

        // Success if either delete succeeded; otherwise both must be
        // NotFound (idempotent no-op) for us to claim success.
        if dpStatus == errSecSuccess || legacyStatus == errSecSuccess {
            return SE_OK
        }
        if (accessGroup == nil || dpStatus == errSecItemNotFound)
            && legacyStatus == errSecItemNotFound
        {
            return SE_OK
        }
        return SE_ERR_KEYCHAIN_DELETE
    }
}
