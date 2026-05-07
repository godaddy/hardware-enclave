# Design: meta-HMAC trust anchor — close the migration-attack window

**Status:** Draft, pre-implementation
**Date:** 2026-05-06
**Author:** Jay Gowdy
**Supersedes (in part):** `design-cross-platform-meta-hmac.md` §"Migration"
**Repos:** `libenclaveapp`, `sshenc`

## TL;DR

The shipped `verify_meta_integrity` blesses any `.meta` whose `.meta.hmac` sidecar is absent — it auto-migrates by computing a fresh HMAC over the on-disk meta and writing it as the new sidecar. A same-UID attacker who can edit `.meta` and `rm .meta.hmac` gets that tampered meta authenticated for them. The sidecar promise is null whenever this branch can fire.

This design closes the window with two moves:

1. **Keychain-attribute trust anchor (new keys).** At keygen, the expected meta-HMAC tag is stored as a custom attribute on the per-key wrapping-key Keychain item — same ACL boundary as the wrapping key itself. Tamper without our entitled binary is not possible. Sidecars become a derivable cache, not the root of trust.

2. **Explicit one-shot migration (legacy keys).** Existing keys that pre-date this change have no keychain-stored tag yet. The agent never auto-migrates them. The user runs `sshenc migrate-meta` once after upgrade. The subcommand prints fingerprints, requires explicit `yes`, and writes both the keychain attribute and the sidecar atomically.

After (1) and (2) ship, the agent's verify path has no migrate branch. Missing sidecar OR missing keychain tag is **always tamper**. The auto-migrate hole is gone.

## The flaw, explicitly

Today, `enclaveapp-app-storage::platform::verify_meta_integrity` does:

```text
load .meta from disk
  |
  +-- .meta.hmac present + matches  -> OK
  +-- .meta.hmac present + mismatch -> Err(KeyInitFailed)  // tamper detected
  +-- .meta.hmac missing            -> migrate_meta_to_hmac()  // SILENT BLESS
                                      writes a fresh sidecar over current .meta
```

The migrate branch was added so users upgrading from a pre-HMAC build don't get locked out. That's a real ergonomic concern. But the design conflates two distinct states: "this is a legacy key that has never been sidecar'd" and "this key was tampered with by removing its sidecar." From the agent's perspective on disk, those are indistinguishable.

Concrete attack:

1. Attacker has same UID as the agent, FS access to `~/.sshenc/keys/`.
2. Attacker edits `default.meta`: flips `presence_mode: strict → none`, or relaxes `access_policy`.
3. Attacker `rm default.meta.hmac`.
4. Next agent op (sign / list / inspect) → `verify_meta_integrity` hits the migrate branch → writes fresh `default.meta.hmac` over the tampered meta.
5. Tampered policy is now authenticated. The Touch ID prompt the user expected on every signature is gone. Subsequent ops sign silently.

The defense the prior design promised — "tamper without keychain access is caught" — does not hold in the presence of this branch.

## Threat model recap

We defend against:

- **Same-UID FS attacker:** can read/write any file in `~/.sshenc/`, `~/.ssh/`, `~/.config/sshenc/`. Cannot use our entitled signed binary's Keychain access (different code signature ⇒ different ACL identity).
- **Backup/restore drift:** user restores an old `.meta` from a Time Machine snapshot but not the matching `.meta.hmac`. This looks identical to the attacker case. Treating it as tamper is correct (user's own remediation: `sshenc migrate-meta` after they've inspected the restored state).

We do not defend against:

- **Root / kernel attacker:** can read the keychain directly and bypass the signed-binary ACL. Out of scope.
- **Same-binary attacker:** an attacker who has compromised the signed `sshenc-agent` binary itself. Out of scope (then they can sign anything they want anyway).

The prior design's claim "attacker without keychain access is caught" is the standard we want to actually meet for new keys, with no auto-migrate escape hatch.

## Design

### Component 1 — keychain-attribute trust anchor (new keys)

**On macOS today**, every sshenc key has a per-key Keychain item under service `com.godaddy.sshenc` with account `<label>` storing the wrapped handle blob. The item's ACL is bound to our signed bundle's code signature; cross-binary access fires the approval prompt. This is already our trust anchor for the wrapping key.

We extend that item to also carry the expected HMAC tag of the key's `.meta` JSON, in the Keychain item's `kSecAttrGeneric` attribute (8 bytes max in the C API, but `kSecAttrComment` or a custom-encoded blob inside the existing data field works for arbitrary length — implementation will pick whichever is cleanest).

Concretely:

- **At keygen** (`enclaveapp-apple/src/keychain.rs::generate_and_save_key`):
  - Compute meta JSON as today.
  - Compute `tag = HMAC-SHA256(meta_hmac_key, meta_json_bytes)`.
  - Write `<label>.meta` (atomic).
  - Write `<label>.meta.hmac` (atomic, hex-encoded tag) — derivable cache.
  - Persist the wrapping key + tag together to the Keychain in a single `SecItemAdd`. Tag lives in a stable attribute so subsequent `SecItemCopyMatching` returns it alongside the wrapped blob.

- **At per-op load** (`keychain.rs::load_handle_with_context` and friends):
  - Read the Keychain item once. Get back wrapped handle AND expected tag.
  - Recompute tag of on-disk `.meta`. Compare in constant time to the keychain tag.
    - Match → OK, proceed.
    - Mismatch → `Err(KeyOperation { operation: META_HMAC_VERIFY_OP, ... })`. Refuse to use the key.
  - If `<label>.meta.hmac` is missing on disk, write it from the keychain tag (cache rebuild). This is safe: the keychain tag is the authority, not the file.

- **What about Windows / Linux?** Symmetric: the per-key wrapping-key store on each platform gets the analogous attribute.
  - Windows CNG: use `NCryptSetProperty` on the persisted key handle with a custom property name. (NCrypt allows user-defined properties on persisted keys.)
  - Linux TPM: the `.handle` file on disk is already the per-key wrapping artifact; we extend it with a length-prefixed tag field. Format-versioned to allow future evolution.
  - Linux keyring: the kernel keyring entry for the wrapping key gets the tag in its description or a paired entry. Detail TBD in implementation.

The cross-platform invariant: **the trust anchor for `.meta` integrity is the per-key wrapping-key store, not a free-floating sidecar.** The sidecar exists only as a fast path / crash-resilience cache.

### Component 2 — explicit migration for legacy keys (`sshenc migrate-meta`)

Pre-existing keys (anything generated before Component 1 ships) have no keychain-stored tag. They cannot be safely auto-migrated by the agent because the agent cannot tell tamper from legacy.

We introduce a `sshenc migrate-meta` subcommand — user-driven, interactive by default, scriptable with `--yes`. Behavior:

1. Enumerate keys in `~/.sshenc/keys/`. For each:
   - Compute SHA-256 fingerprint of the current `.meta` JSON.
   - Read current policy fields (`presence_mode`, `access_policy`) for display.
2. Print a summary table:
   ```
   Migrating 3 keys to authenticated metadata. Verify these match what you expect:
     default              policy=strict  fingerprint=ab12…
     github-personal      policy=cached  fingerprint=cd34…
     test-key-a-151317-376 policy=none    fingerprint=ef56…
   Continue? [y/N]
   ```
3. On `y`: for each key, write the keychain-stored tag (Component 1's attribute) AND the on-disk sidecar atomically. If any keychain write fails, abort and report which keys are partially migrated; the command is rerunnable.
4. After all keys migrate, print "Done. Future tampering with .meta will be detected."

**Rationale for the prompt:**
- Human-in-the-loop confirmation is the only thing that distinguishes "I'm upgrading my own install" from "an attacker tampered with my .meta and is about to get me to sign their version." The user reading the fingerprints is the trust signal.
- One-time UX cost. No additional prompts on the steady-state path.
- `--yes` exists for CI / scripted installers, with the explicit understanding that those environments accept the risk.

**The agent never auto-migrates.** Period. After this design ships, the agent's `verify_meta_integrity` collapses to:

```text
read keychain item -> get wrapping blob + stored tag
read .meta from disk
  |
  +-- stored_tag matches HMAC(.meta)  -> OK; rebuild .meta.hmac sidecar if missing
  +-- stored_tag mismatch              -> Err(verify) // tamper
  +-- keychain item has no stored tag  -> Err(legacy_meta) // user must run migrate-meta
```

The legacy_meta error message points the user at `sshenc migrate-meta`.

### Component 3 — kill the existing auto-migrate branch

`enclaveapp-app-storage::platform::verify_meta_integrity` loses its migrate branch entirely:

- Missing sidecar AND missing keychain tag → `Err(StorageError::KeyInitFailed)` with detail pointing at `sshenc migrate-meta` (or, for awsenc/sso-jwt/npmenc, their equivalent).
- Missing sidecar AND keychain tag present → silently rebuild sidecar from keychain tag. No user-visible change. (This is the post-migrate steady state when something deletes the sidecar — the keychain tag is authoritative.)
- Sidecar present + mismatch → tamper, refuse.
- Sidecar present + matches keychain tag → OK.
- Sidecar present + matches HMAC of meta but no keychain tag → still legacy_meta error. The sidecar alone is not the trust anchor anymore.

`enclaveapp-core::metadata::migrate_meta_to_hmac` stays as a public helper but is no longer called from the agent's hot path. It becomes the building block for `sshenc migrate-meta` and similar tools in the other apps.

## What changes in the threat model doc

Today's threat model says "attacker without keychain access is caught for `.meta` tamper." That's currently aspirational on macOS and false in any branch where the auto-migrate path can fire.

Post-design, the threat model entry becomes:

- **For keys generated post-vN.N.N (Component 1 ships):** attacker without keychain access cannot tamper with `.meta` undetected. Mismatch is a hard error at every op.
- **For keys generated pre-vN.N.N:** until the user runs `sshenc migrate-meta`, the agent refuses to use them. The migration command requires interactive confirmation of fingerprints. Trust-on-first-use is explicit and one-shot.

## Out of scope

- **Cross-app migration UX.** awsenc / sso-jwt / npmenc each get their own `<app> migrate-meta` (or equivalent flag on an existing subcommand). Not part of this design — they have different lifecycle stories. We just provide the building block.
- **Backwards compat with existing `.meta.hmac` sidecars that have no keychain tag.** Treating them as legacy_meta is a deliberate choice: if a user already ran the old auto-migrate path, we do not retroactively bless those sidecars, because we cannot tell which were legitimate and which were attacker-induced. The migrate subcommand re-blesses them under the new model.
- **Hardware key attestation.** A future improvement would bind the meta tag to the SE / TPM key's attestation, removing the meta-HMAC key as a separate secret. Out of scope here.

## Rollout

| Step | Repo | Description |
| ---- | ---- | ----------- |
| 1 | libenclaveapp | Add keychain-attribute storage on all platforms. New keygen writes both attribute and sidecar. |
| 2 | libenclaveapp | Read path uses keychain attribute as authority. Sidecar becomes cache. |
| 3 | libenclaveapp | Remove `migrate_meta_to_hmac` call from `verify_meta_integrity`. Hard error on legacy state. |
| 4 | sshenc | Add `sshenc migrate-meta` subcommand with interactive fingerprint confirmation. |
| 5 | libenclaveapp + sshenc | Update threat model doc to reflect the new guarantees. |
| 6 | sshenc | Release notes call out the migrate-meta requirement for upgrading existing installs. |

Steps 1–3 ship as one libenclaveapp PR. Step 4 ships as the matching sshenc PR (depends on the libenclaveapp release tag bumping). Steps 5–6 are doc-only.

## Test plan

### Unit tests

- `verify_meta_integrity` returns `legacy_meta` error when keychain has no tag, regardless of sidecar state.
- `verify_meta_integrity` rebuilds sidecar from keychain tag when sidecar is deleted.
- `verify_meta_integrity` returns tamper error when keychain tag and on-disk meta disagree.
- New keygen writes keychain attribute and sidecar atomically; partial-failure leaves no half-state (transactional rollback already exists in `enclaveapp-core::backup`).

### Integration tests (per platform)

- macOS: sign on a freshly-generated key works; tamper `.meta`; sign returns tamper error; restore `.meta`; sign works again. Each step zero approval prompts on signed bundle.
- Windows: same suite against TPM-backed keys.
- Linux keyring: same suite.
- Linux TPM: same suite.

### End-to-end migration tests

- sshenc: pre-existing key with no keychain tag; `sshenc list` errors with legacy_meta message pointing at migrate-meta; `sshenc migrate-meta --yes` succeeds; subsequent `sshenc list` works; tamper detection holds afterward.
- sshenc: simulated attacker — generate key, drop sidecar, edit meta, run any agent op → must error, must NOT silently re-sign.

### Manual / observational

- Prompt audit: full keygen + sign + list + inspect cycle on signed bundle, count Touch ID prompts. Must equal current count (no regression).

## UX strings — locked

The user-facing language must frame `migrate-meta` as a **one-time
cutover for the version that introduces the keychain tag**, not as a
"run after every upgrade" routine. If users develop a reflex of
running `migrate-meta` after every release, the attack surface from
§"The flaw, explicitly" is restored — just with a user pressing Enter
instead of an automated path. The wording below is chosen to make that
reflex impossible.

Treat the version number `vX.Y.0` as a placeholder — the implementing
release substitutes its own version into the strings below.

### Agent `legacy_meta` error message

Printed when the agent encounters a key with no keychain tag (no
`migrate-marker` present in the keychain — i.e., this user has never
migrated):

```
Error: key 'github-personal' has no integrity tag.

This is a one-time migration required by the vX.Y.0 upgrade and is not
something future upgrades will repeat. If you have already run
`sshenc migrate-meta` on this machine, treat this as a tamper signal
— do not run it again. Regenerate the affected key instead.

Before migrating, verify the key's current policy looks correct:
    sshenc inspect github-personal

To migrate: sshenc migrate-meta
```

Stronger variant when `migrate-marker` IS present (user has already
migrated; this should never recur in legitimate use):

```
Error: key 'github-personal' has no integrity tag.

migrate-meta has already been run on this install, so this should not
have recurred. This is a strong tamper signal. Recommended: regenerate
this key. Do NOT run migrate-meta again unless you can independently
explain why this key's tag is missing (e.g., manual restore from
backup of an unrelated machine).

Audit log: ~/.sshenc/agent.err.log
```

### `sshenc migrate-meta` confirmation prompt

```
migrate-meta is the one-time fix for the vX.Y.0 upgrade. Once it
finishes successfully, you will not see this prompt again — future
upgrades will NOT ask you to run it. If this command is ever
suggested again later, it likely means someone has tampered with
your key metadata; regenerate affected keys instead of re-running.

Keys to migrate:
  default                policy=cached  fingerprint=ab12cd34ef56...
  github-personal        policy=cached  fingerprint=ff89aa11bb22...
  test-key-a-151317-376  POLICY=NONE !! fingerprint=cc33dd44ee55...
                         (no biometric required — verify this is
                         intentional before continuing)

Type 'yes' (full word) to migrate, or anything else to cancel.
> _
```

Policy-field highlighting: any key with `presence_mode: none` or
`access_policy: None` prints with the `POLICY=NONE !!` marker and the
explanatory parenthetical. Forces the user to look at the row.

### `sshenc inspect <label>` integrity line

Adds one line at top of existing output:

```
Integrity: OK
```

or

```
Integrity: LEGACY — run `sshenc migrate-meta` (one-time, vX.Y.0 cutover)
```

or (the screaming case after marker is set):

```
Integrity: TAMPER — keychain tag mismatch. Regenerate the key.
```

### `--yes` flag for CI

`sshenc migrate-meta --yes` exists for scripted environments
(unattended installers, CI fixtures). Prints the same warning block
to stderr but skips the interactive confirmation. The man page and
`--help` text call out that `--yes` bypasses the human-review step
that exists for security reasons.

A second-run attempt always requires `--force-rerun-i-understand`
even with `--yes`, so the marker-present strong warning cannot be
short-circuited by ambient automation.

## Open questions (implementation-time)

1. **Where in the keychain item does the tag live?** Settled:
   separate Keychain item per key under service
   `com.godaddy.<app>.meta-tag`, account = label. Cleaner abstraction
   than prepending a header to the wrapped blob; no FFI-boundary
   risk; same ACL pattern as the wrapping key. Item count grows by N
   (one per key) — acceptable tradeoff.
2. **Linux keyring / Linux TPM mechanics for the keychain-attr
   equivalent.** Out of scope for the macOS-first PR. Will mirror
   the per-key item pattern using each platform's secure store.
3. **Should `migrate-meta` show *what changed* in the policy
   fields?** Settled: yes for `presence_mode: none` /
   `access_policy: None`, no for arbitrary diffs (no baseline to
   diff against). The `POLICY=NONE !!` marker is the signal.
