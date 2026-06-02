# Design: `enclaveapp-app-storage`

**Status:** Implemented  
**Updated:** 2026-04-14

## Purpose

`enclaveapp-app-storage` is the shared application-facing storage layer inside `enclave`.

It exists so consuming applications do not each need their own copies of:

- platform detection
- WSL bridge discovery
- key bootstrap and key-exists checks
- access-policy mapping
- encrypt/decrypt and sign wrapper glue

## What it provides

Two primary entry points:

- `AppEncryptionStorage`
- `AppSigningBackend`

Both are configured with the same `StorageConfig`:

```rust
StorageConfig {
    app_name: "awsenc".into(),
    key_label: "cache-key".into(),
    access_policy: AccessPolicy::BiometricOnly,
    extra_bridge_paths: vec![],
    keys_dir: None,
}
```

The shared config keeps application-specific naming in the app, while the platform selection logic stays in one place.

## Current consumers

| Consumer | Current use |
|---|---|
| `awsenc` | encrypted credential cache |
| `sso-jwt` | encrypted token cache |
| `sshenc` | platform bootstrap for signing backend |
| `npmenc` | indirect encrypted secret storage through its adapter crate |

## Backend selection

The crate chooses the best available backend for the current environment:

| Environment | Backend |
|---|---|
| macOS | Secure Enclave |
| Windows | TPM 2.0 |
| WSL | Windows host bridge |
| Linux with TPM | TPM 2.0 |
| Linux without TPM | keyring |

For WSL, discovery is layered:

1. `enclaveapp_bridge::find_bridge(app_name)` for the generic `{app_name}-bridge.exe` path
2. auto-derived `{app_name}-tpm-bridge.exe` paths under `Program Files` and `ProgramData`
3. any app-specific absolute `extra_bridge_paths`

That lets the shared crate support both the generic bridge naming used by `enclaveapp-bridge` and the app-specific `*-tpm-bridge.exe` binaries used by derived projects.

## Why it exists

Before this crate, the same storage bootstrap logic was duplicated in:

- `awsenc`
- `sso-jwt`
- parts of `sshenc`

The duplication was not in the cryptography itself. It was in the surrounding application glue:

- create or locate the right key
- pick the right backend
- handle WSL paths
- pass the full access policy and key label through the bridge protocol
- convert backend errors into application-level errors

`enclaveapp-app-storage` centralizes that glue while leaving application-specific behavior in the consuming repos.

## Non-goals

This crate does not try to own:

- SSH-specific metadata, public-key files, or agent behavior from `sshenc`
- AWS or OAuth domain logic from `awsenc` and `sso-jwt`
- application-specific wrapper behavior from `npmenc`

It is a bootstrap and storage abstraction layer, not a full application framework.
