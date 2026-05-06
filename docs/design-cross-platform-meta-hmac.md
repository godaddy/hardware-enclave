# Design: Cross-platform `.meta` HMAC integrity

**Status:** Draft
**Updated:** 2026-05-06
**Branch:** `cross-platform-meta-hmac`
**Depends on:** `deep-review-fixes` branch (PR godaddy/libenclaveapp#119,
godaddy/sshenc#193) — adds `MetaIntegrityMode` and the strict-mode
load on the Linux keyring path.

## Background

The deep-review pass on the `deep-review-fixes` branch tightened
`metadata::load_meta_with_hmac` to refuse a missing
`<label>.meta.hmac` sidecar in production. That work was scoped
to the **Linux keyring/software backend on the encryption side**
(awsenc, sso-jwt) because that's the only backend that *writes*
the sidecar today, and the only call site that consumes it is
`enclaveapp-app-storage::encryption::ensure_key`.

The hardware-backed paths (macOS Secure Enclave, Windows CNG,
Linux TPM, WSL bridge) skipped the HMAC discipline entirely.
The original rationale was "the hardware enforces `AccessPolicy`
at sign/decrypt time, so a `.meta` lying about it can't relax
the actual hardware enforcement." That rationale only holds for
fields the hardware actually knows about. It doesn't hold for
fields the hardware has no opinion on, which turns out to be
most of `.meta`.

This document scopes the work to extend the HMAC sidecar
discipline to all platforms and all key types (signing and
encryption) so that every field in `.meta` is authenticated
against same-UID tampering wherever the threat applies.

## Threat surface that motivates this

A same-UID attacker on any platform can rewrite
`~/.config/<app>/keys/<label>.meta` (or `~/.sshenc/keys/...`,
or `%APPDATA%\<app>\keys\...`). The library uses the following
fields after read; each row describes what tampering buys.

| Field                        | Consumer                                             | Tamper impact                                                                                                                                                   | Severity |
| ---------------------------- | ---------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- |
| `app_specific.credential_id_b64` + `rp_id` | `sshenc-se::unified::sk_*`, `proxy::sk_keyinfo_from_meta` | Plant attacker-minted TPM credential ID. Agent calls `WebAuthNAuthenticatorGetAssertion` against attacker's credential; TPM signs. Combined with allowed_signers tamper, full key-substitution attack. | **Very high** |
| `app_specific.presence_mode` | `enclaveapp-apple::sign::sign_with_presence` | `Strict→Cached` flips macOS LAContext caching on; multiple signs go through one Touch ID prompt within the 4h cache TTL. | High |
| `access_policy`              | `sshenc list`/`inspect`, `PromptPolicy::KeyDefault`  | Hardware still enforces real ACL at sign, so direct bypass doesn't materialize. But UX trust corruption: user thinks key requires biometric, deploys it accordingly, and the actual key was created `None`. Self-correcting on macOS only when the SE ACL contradicts the meta and the agent doesn't acquire LAContext. | Medium |
| `app_specific.pub_file_path` | `gitenc --config` (writes `user.signingkey`); `sshenc inspect` | Repointing breaks `git verify-commit` (DoS); combined with allowed_signers tamper, supports author-attribution attacks. | Medium |
| `app_specific.git_email` / `git_name` | `gitenc --config`, allowed_signers entry generation | `user.email = attacker@evil.com` → user's commits show attacker as author in GitHub history. allowed_signers entry binds user's pub to attacker's email. | Medium |
| `algorithm`                  | SK vs CNG/SE dispatch                                | DoS — flipping `sk-ecdsa-sha2-nistp256` off makes SK signs route through wrong path and fail. | Low |
| `app_specific.comment`       | display + SSH key comment field in `.pub` blobs       | Display lie. Could embed misleading email in the SSH-key comment, but `gitenc` doesn't trust comment for principal binding. | Low |
| `key_type`                   | Signing vs Encryption code path                      | DoS. | Low |
| `label` (internal field)     | identity in some logs                                | Filename-vs-internal mismatch is easy to detect. | Low |
| `created`                    | display only                                         | None. | None |

Top of the list — the SK `credential_id_b64` substitution — is
the most consequential. It's a full key-substitution attack on
the SK/WebAuthn path, currently shipped as the **default** on
Hello-enrolled Windows hosts and reachable from WSL through the
TPM bridge.

## Design choice: HMAC sidecar everywhere

Two candidate designs are on the table. This document picks the
first; the rationale follows.

### Option A — HMAC sidecar everywhere (chosen)

Generalize the `<label>.meta.hmac` discipline to all platforms.
Each platform stores a per-app HMAC key in its native secure
store. `metadata::load_meta_with_hmac` already supports strict
mode; the work is per-backend HMAC key plumbing and wiring the
strict load into every backend's init path.

### Option B — Hardware re-verification

Read the hardware key's actual ACL at sign time and refuse to
proceed when `.meta` disagrees. The Windows legacy KSP path
already does this via `verify_ui_policy_matches`.

Option B is rejected because it can only authenticate **fields
the hardware knows about**. The hardware has no opinion on
`credential_id_b64`, `pub_file_path`, `git_email`, `git_name`,
or `comment`. Of those, `credential_id_b64` enables a full
key-substitution attack and the others enable
author-attribution attacks. Option B leaves all of them on the
table.

Option B *is* still useful as defense-in-depth for the fields
the hardware does know about (notably `presence_mode` on macOS
via SecAccessControl ACL introspection, and `access_policy`
versus the actual SE/CNG flag). It's compatible with Option A
and may be added as a follow-up. This design doesn't depend on
it.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ enclaveapp-app-storage                                      │
│                                                             │
│   trait MetaHmacKeyStore {                                  │
│       fn load_or_create(app: &str)                          │
│           -> Option<Zeroizing<Vec<u8>>>;                    │
│       fn delete(app: &str) -> Result<()>;                   │
│   }                                                         │
│                                                             │
│   #[cfg(target_os = "macos")] use enclaveapp_apple as store │
│   #[cfg(target_os = "windows")] use enclaveapp_windows ...  │
│   #[cfg(target_os = "linux")]  use enclaveapp_keyring ...   │
│                  + enclaveapp_linux_tpm (optional)          │
│                                                             │
│   AppEncryptionStorage::ensure_key  ──┐                     │
│   AppSigningBackend::ensure_key     ──┼──> strict load      │
│   AppSigningBackend::init_*         ──┘    + auto-migrate   │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│ enclaveapp-core::metadata                                   │
│                                                             │
│   load_meta_with_hmac(dir, label, key, RequireSidecar)      │
│   migrate_meta_to_hmac(dir, label, key)                     │
│   save_meta_with_hmac(dir, label, meta, key)                │
│   rename_key_files(.., Some(key))                           │
└─────────────────────────────────────────────────────────────┘
```

The HMAC primitive layer (`enclaveapp-core::metadata`) is
already complete from `deep-review-fixes`. This design adds:

1. A per-platform `MetaHmacKeyStore` implementation in each
   platform crate.
2. A trait/dispatch surface in `enclaveapp-app-storage` so
   call sites don't need per-platform `cfg` gates.
3. Strict-mode wiring at every `init` and `ensure_key` site,
   on both the encryption and signing sides.
4. Auto-migration on first load post-upgrade — same shape as
   the existing `encryption.rs::ensure_key` path.

## Per-backend HMAC key store

### macOS — legacy Keychain

Mirror what `enclaveapp-apple::keychain_wrap` already does for
wrapping keys. New module `enclaveapp-apple::meta_hmac`:

```rust
pub fn load_or_create(app_name: &str) -> Option<Zeroizing<Vec<u8>>>
```

Storage:

- Service: `format!("com.godaddy.{app}.meta-hmac")` — same
  namespace prefix as the wrapping keys, distinct service so
  the legacy Keychain ACL is a separate decision.
- Account: `__meta_hmac_key__` — matches the keyring
  convention.
- 32 random bytes from `SecRandomCopyBytes`.
- `kSecAttrAccessible = kSecAttrAccessibleAfterFirstUnlock` —
  reachable from agent at login without unlocking the
  keychain interactively.

ACL trade-off: the legacy Keychain ACL is bound to the
**creating binary's code signature**. Cross-binary access
(e.g. CLI reads what the agent created) fires an approval
sheet on unsigned dev builds. This is the same prompt class as
the wrapping keys today, and the same mitigation applies — the
HMAC key should be read **only** from `sshenc-agent`, never
from the CLI binaries. The CLI's `AgentProxyBackend` already
contains zero keychain calls; the HMAC verification belongs on
the agent side of the IPC boundary.

For signed release builds (Homebrew bottle, .app bundle), the
ACL is stable across rebuilds because the code signature is
stable.

### Windows — DPAPI

New module `enclaveapp-windows::meta_hmac`:

```rust
pub fn load_or_create(app_name: &str) -> Option<Zeroizing<Vec<u8>>>
```

Storage:

- 32 random bytes from `BCryptGenRandom`.
- DPAPI-encrypted via `CryptProtectData(CRYPTPROTECT_UI_FORBIDDEN)`
  — per-user, no admin, no UI, ties decrypt to the current
  Windows user account.
- Persisted file at
  `dirs::data_dir() / <app> / .meta-hmac.dpapi`. The blob is
  opaque — only the user's Windows credentials can decrypt it.

DPAPI binding survives package reinstalls and code-signature
changes; it does not survive a Windows user-profile reset.
Profile reset is treated the same as TPM reset: regenerate
keys.

Why a file rather than a CNG persisted symmetric key:
DPAPI-on-disk is one round trip per process start, no key
container lifetime to manage, atomic via temp+rename.
Persisted-key approach would also work but adds storage
provider lifecycle complexity for no security benefit on a
per-user threshold.

### Linux TPM — keyring fallback initially

The Linux TPM backend keeps using
`enclaveapp_keyring::meta_hmac_key` for now — same store as
the software/keyring backend. The HMAC key lives in the user's
Secret Service, alongside the KEK that the keyring backend
uses for its own key wrapping.

Rationale: the Linux TPM's actual private signing key is in
the TPM; we don't need to seal the HMAC key in the TPM as well
to match the threat model. The threshold for the HMAC key
matches the threshold for the user account itself.

Follow-up (out of scope here): TPM-sealed NV index for the
HMAC key, behind a feature flag. The seal would harden against
"attacker has Secret Service write but not TPM access" —
narrow but real.

### Linux software/keyring — already done

`enclaveapp_keyring::meta_hmac_key` exists and works. No
change.

## API surface

### New trait in `enclaveapp-app-storage::platform`

```rust
pub trait MetaHmacKeyStore {
    /// Load the per-app meta-HMAC key, generating and persisting
    /// one on first call. Returns `None` when the underlying secure
    /// store is unreachable — caller should treat this the same as
    /// keyring-unavailable on Linux today (refuse to proceed in
    /// production, accept in tests).
    fn load_or_create(app_name: &str) -> Option<Zeroizing<Vec<u8>>>;

    /// Remove the stored HMAC key. Used by `sshenc uninstall` and
    /// equivalents. Idempotent; missing-entry is success.
    fn delete(app_name: &str) -> Result<()>;
}
```

Per-platform impls live in their respective crates. The
dispatch happens in `enclaveapp-app-storage::platform`:

```rust
pub fn meta_hmac_key(app_name: &str) -> Option<Zeroizing<Vec<u8>>> {
    #[cfg(target_os = "macos")]
    { enclaveapp_apple::meta_hmac::load_or_create(app_name) }
    #[cfg(target_os = "windows")]
    { enclaveapp_windows::meta_hmac::load_or_create(app_name) }
    #[cfg(target_os = "linux")]
    { enclaveapp_keyring::meta_hmac_key(app_name) }
    // ... TPM-sealed variant follow-up
}
```

### Generalized strict-mode call sites

Today the strict load is invoked in exactly one place:

- `enclaveapp-app-storage::encryption::ensure_key`
  (Linux-gated)

This design adds it to every key-init path:

- `AppEncryptionStorage::ensure_key` — already has it on
  Linux; remove the `#[cfg(target_os = "linux")]` and use the
  cross-platform `meta_hmac_key`.
- `AppSigningBackend::init_macos` — new strict load before
  returning the SE backend.
- `AppSigningBackend::init_windows` — new strict load.
- `AppSigningBackend::init_linux` (TPM and keyring branches) —
  new strict load.
- `AppSigningBackend::init_wsl` — new strict load (the bridge
  keeps the meta on the Windows side; verification happens
  Windows-side via the bridge).

Per-sign re-verification is **not** part of this scope. Init-
time verification is the cheap and obvious win. Per-sign adds
HMAC compute cost on the hot path for marginal additional
defense (the only way init-time succeeds and per-sign would
catch tamper is if the attacker rewrites meta between init and
sign — which is a real but niche window). Revisit if a
specific threat or telemetry signal calls for it.

### `save_meta_with_hmac` becomes the default writer

Today, hardware backends call `save_meta` (no sidecar). After
this change, hardware backends call `save_meta_with_hmac` on
key creation and rename. `save_meta` stays around for tests
and explicit unauthenticated cases.

Affected sites (grepped):

- `enclaveapp-apple::keychain::save_key` (test path) →
  optional, can stay on `save_meta`.
- `enclaveapp-apple::keychain::generate_and_save_key` →
  switch to `save_meta_with_hmac`.
- `enclaveapp-windows::tpm::save_key_meta` → switch.
- `enclaveapp-linux-tpm::*` → switch.
- WSL bridge → bridge writes meta on the Windows side; switch
  the Windows-side writer.
- Keyring backend already does this.

### `rename_key_files` already takes `Option<&[u8]>`

The `deep-review-fixes` work added the parameter. Apple,
Windows, and TPM rename helpers currently pass `None`. After
this change they pass `Some(meta_hmac_key)`.

## Migration

Mirrors the existing B1 migration. On first
`load_meta_with_hmac` post-upgrade, a missing sidecar yields
`Error::KeyOperation { operation: "meta_hmac_missing", … }`.
The strict-mode call site catches that and runs
`migrate_meta_to_hmac`, logging a `warn!`. Subsequent loads
are strict.

For users with many existing keys (e.g. an sshenc setup with
several labels), the migration runs lazily on whichever key
the agent first loads after upgrade. `sshenc list` triggers it
for every key listed; `sshenc inspect` for the one inspected.
Within one session, all keys end up migrated.

The migration window is the same as B1: an attacker who
tampers `.meta` between upgrade and first load gets that
tamper blessed by the migration step. There is no oracle that
distinguishes legitimate-legacy from tampered. The `warn!`
log is the only signal. This is documented as residual risk
in the threat model.

## Threat-model updates

Two paragraphs change in `sshenc/THREAT_MODEL.md`:

1. **"Metadata File Tamper (`.meta`)"** — generalize the
   "Linux keyring" subsection to "all platforms"; update the
   residual-risk list to reflect that the macOS/Windows
   hardware backends now also have the HMAC sidecar.
2. **New "SK Credential Substitution" subsection** under the
   metadata-tamper threat — describe the
   `credential_id_b64`/`rp_id` attack and explicitly state
   that the HMAC sidecar closes it.

The "Cross-Binary Keychain ACL Prompt / Fatigue" threat gets
a residual-risk bullet noting that the meta-HMAC key on macOS
follows the same agent-only-reads invariant as the wrapping
key. No new prompt class.

## Backwards compatibility

- Existing `.meta` files (legacy, no sidecar) load fine via
  the auto-migration path on first run after upgrade.
- Keys created on the new code on a system where the
  HMAC-key store is unreachable (no Keychain on macOS, no
  DPAPI on Windows, no Secret Service on Linux): same
  behavior as Linux today — refuse to write the key. We do
  not silently fall back to unauthenticated meta in
  production.
- Test code that creates keys via `save_meta` directly
  continues to work; loading those via `RequireSidecar` will
  fail with `meta_hmac_missing`. Tests that need the legacy
  shape continue to use `AllowLegacyMissingSidecar`
  explicitly (existing tests already do).

## Testing plan

### Per-platform unit tests

- `enclaveapp-apple::meta_hmac` — load/create/delete
  roundtrip, behavior when keychain is locked.
- `enclaveapp-windows::meta_hmac` — load/create/delete,
  behavior when DPAPI is unavailable (rare; mainly profile-
  reset simulation).
- `enclaveapp-keyring` — already tested.

### Cross-process tests

- `sshenc-agent` creates key → `sshenc-agent` reads it → load
  succeeds. Same binary, no ACL prompt class.
- `sshenc` CLI does not call the meta-HMAC store directly
  (see ACL discussion above) — confirm by `cargo deny` or
  manual grep that the CLI binary doesn't link the platform
  HMAC module.

### Tamper tests (per platform)

- Generate key, edit `.meta` to flip
  `presence_mode: strict → cached`, run sign → expect
  `meta_hmac_verify` error before any sign.
- Generate SK key on Windows, edit `.meta` to substitute
  `credential_id_b64` from a different label, run sign →
  expect `meta_hmac_verify` error.
- Delete `.meta.hmac` sidecar, run sign → expect
  `meta_hmac_missing` followed by automatic migration on
  first load (existing test pattern from B1).

### Smoke tests on real hardware

These need a checkpoint in the rollout. Each platform's
matrix workflow gets one:

- macOS: keychain ACL behavior on rebuild — verify that the
  agent rebuild produces at most one approval sheet for the
  HMAC key (parity with the wrapping-key prompt count).
- Windows: DPAPI unprotect after Windows upgrade /
  user-profile copy.
- Linux TPM-present: fallback to keyring works; HMAC key
  lifecycle independent of TPM key lifecycle.

## Rollout

Phased PRs, each independently mergeable:

| PR  | Scope                                                              | Risk |
| --- | ------------------------------------------------------------------ | ---- |
| 1   | macOS HMAC store (`enclaveapp-apple::meta_hmac`) — no call sites yet | Low  |
| 2   | Windows HMAC store (`enclaveapp-windows::meta_hmac`) — no call sites | Low  |
| 3   | `MetaHmacKeyStore` trait + `enclaveapp-app-storage::platform` dispatch | Low  |
| 4   | Generalize encryption-side `ensure_key` to all platforms             | Medium |
| 5   | Generalize signing-side `init_*` to call strict-mode load            | Medium |
| 6   | Switch hardware backends from `save_meta` to `save_meta_with_hmac`   | Medium |
| 7   | Threat-model + design-doc updates                                    | Low  |

PRs 1–3 are pure additions (no existing call site changes) and
can land in any order. PR 4 + PR 5 are where behavior actually
changes; both need the per-platform smoke tests on real
hardware before merge.

PR 6 is the "make new keys carry sidecars" step. After PR 6
lands, freshly-created keys have sidecars from the start; old
keys auto-migrate on next load.

## Risks

- **Cross-binary Keychain ACL prompt class on macOS** — same
  threshold as the wrapping-key items. Mitigation: HMAC-store
  reads only from `sshenc-agent`. CLI never links it. Same
  invariant the wrapping-key code already maintains.
- **Migration window**: first load post-upgrade blesses
  whatever `.meta` is on disk. Identical to B1's window.
  Documented in threat model.
- **DPAPI profile-reset key loss on Windows** — equivalent to
  TPM key loss. Surfaces as `meta_hmac_missing`; user must
  regenerate keys. Same recovery flow as a hardware reset.
- **Keychain locked at agent start on macOS** —
  `kSecAttrAccessibleAfterFirstUnlock` covers this on
  reboot. Edge case: keychain explicitly locked by user,
  agent restarts; the HMAC store load returns `None`, and
  the strict path refuses to proceed. Surface a clear error.
- **TPM unavailable on a TPM-marker'd system** — the
  S4 sticky backend marker (also from `deep-review-fixes`)
  catches this and refuses init before we even reach the
  HMAC step. Composable.

## Out of scope

- TPM-sealed HMAC key on Linux TPM (follow-up; keyring
  fallback is acceptable for v1).
- Per-sign re-verification (cheap to add later if telemetry
  motivates it).
- Authenticating `.pub` and `.handle` files. `.pub` is
  already published to the world; `.handle` is hardware-
  attested via the keychain wrap or the TPM container.
- Asymmetric signature instead of HMAC. No security benefit
  for this use case; HMAC's symmetry is fine because the
  signer and verifier are the same library on the same host.
- A `<app> migrate-meta` CLI subcommand. The auto-migration
  on first load covers normal upgrade paths; explicit
  migration only matters when the user wants to verify a
  large set of legacy keys before relying on them. Revisit
  if the migration window risk gets pushback.

## Open questions

1. Should the macOS HMAC key live in the Data Protection
   keychain (with `kSecAttrAccessControl(.userPresence)`)
   instead of the legacy keychain? Pro: stronger ACL,
   biometric-gated read. Con: requires a `keychain-access-groups`
   entitlement, which today only the signed `.app` bundle
   carries. Suggested answer: legacy keychain for v1; revisit
   if the user-presence-on-HMAC is actually wanted.
2. Should the Windows DPAPI blob include
   `CRYPTPROTECT_LOCAL_MACHINE`? Pro: machine-bound rather
   than user-bound; survives user-profile-reset on a single
   device. Con: weakens the threshold (any local user can
   decrypt). Suggested answer: no — keep the per-user
   binding.
3. Do we run the strict-mode load on the **proxy** side
   (CLI's `AgentProxyBackend`) at all? The proxy's `keys_dir`
   is a cache of what the agent has, plus its own writes for
   things like `cache_key_artifacts_locally`. Suggested
   answer: no. Only the agent verifies. The proxy treats its
   keys_dir as a derived cache; the source of truth is what
   the agent serves over IPC.
4. Where does the `.backend` marker (S4) interact with the
   `.meta-hmac.dpapi` blob on Windows? Should we store both
   under the same `<app>` config dir? Suggested answer: yes,
   `~/.config/<app>/.backend` and
   `<data_dir>/<app>/.meta-hmac.dpapi` — different state
   classes, different lifecycle, no coupling needed.

## Concrete next step

Spike PR 1 (macOS `meta_hmac` module) on this branch. It's
self-contained, low-risk, and the work pattern (legacy
Keychain SecItemAdd/Copy mirroring `keychain_wrap`) is well-
trodden. Once PR 1 is in, PRs 2 and 3 follow the same shape;
PRs 4–6 are call-site sweeps with per-platform smoke tests.
