# AGENTS.md

Instructions for AI agents (Claude Code, Copilot, Cursor, etc.) working with the Enclave crate.

## Protection Class Safety Rules

**READ THIS BEFORE TOUCHING `bridge.swift`.**

The macOS Apple backend has two distinct protection class use sites that
**MUST use different values**. Getting this wrong forces every downstream
user to regenerate all Secure Enclave keys — there is no migration path
because the SE key access control is baked into the SEP at creation time.

### SE key access control (`makeAccessControl`)

```swift
// MUST be WhenUnlockedThisDeviceOnly
SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &error)
```

This is passed to `SecureEnclave.P256.Signing.PrivateKey(accessControl:)` at
key generation time. The protection class is **immutable** — once set, it
cannot be changed without deleting and regenerating the key.

`WhenUnlockedThisDeviceOnly` is required because CryptoKit's
`touchIDAuthenticationAllowableReuseDuration` (biometric caching) only works
with this protection class. With `AfterFirstUnlockThisDeviceOnly`, the SEP
ignores the LAContext's cached authentication and prompts Touch ID on every
single sign operation. This was discovered in PR #158 — the blanket protection
class change broke biometric caching entirely, requiring full key regeneration
for all affected users.

### Keychain wrapping key (`keychain_store`)

```swift
// MUST be AfterFirstUnlockThisDeviceOnly
SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, ...)
```

The wrapping key is stored as a `kSecClassGenericPassword` keychain item.
`AfterFirstUnlockThisDeviceOnly` keeps the keybag class key in memory from
first unlock until reboot, so background agents (like sshenc-agent) can
access wrapping keys after sleep/wake without requiring the screen to be
unlocked. `WhenUnlockedThisDeviceOnly` purges the class key on device
lock/sleep, causing `-25308 (errSecInteractionNotAllowed)` failures.

### Rules

1. **NEVER do a blanket find-and-replace of protection class constants.** These
   two sites have different requirements for different reasons.
2. **NEVER change `makeAccessControl`'s protection class** unless you have
   verified with Apple documentation that biometric caching
   (`touchIDAuthenticationAllowableReuseDuration`) works with the new class.
   The cost of getting this wrong is catastrophic — every user must regenerate
   all keys.
3. **Test biometric caching after any change to `bridge.swift`**: first sign
   should trigger Touch ID (~2-3s), second sign within the cache window should
   complete in <50ms. If every sign takes 2-3s, biometric caching is broken.
4. When changing keychain-related code, consider both sites independently and
   document which one you are changing and why.

## Build Safety (macOS)

See the consuming app's AGENTS.md (e.g., sshenc/AGENTS.md) for rules about
never running unsigned development builds as agents on macOS.

## Commits

Do not add Co-Authored-By lines for Claude Code in commit messages.
