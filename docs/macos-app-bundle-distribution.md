# macOS .app bundle distribution for libenclaveapp consumers

Status: planned — describes the cross-cutting work to enable the
Data Protection keychain (and therefore the wrapping-key
`.userPresence` ACL) for libenclaveapp consumers shipped via
Homebrew. As of 2026-04-27, only sshenc has a Developer ID signed
release pipeline; this doc captures the next step that brings the
full security model into reach.

## Why this matters

The libenclaveapp wrapping-key path stores a 32-byte AES key in the
macOS login keychain to encrypt SE-handle blobs at rest. The path
is meant to install a `kSecAttrAccessControl(.userPresence)` ACL on
that wrapping-key keychain item so a same-UID attacker who can read
the on-disk handle still has to satisfy a Touch ID / passcode prompt
to fetch the wrapping key.

That ACL only installs in macOS's Data Protection keychain — the
legacy file-based keychain rejects it with `errSecParam` -50. Routing
through the Data Protection keychain requires the calling binary to
claim a `keychain-access-groups` entitlement.

`keychain-access-groups` is a **restricted entitlement**. AMFI
(Apple Mobile File Integrity) refuses to launch any binary that
claims a restricted entitlement without a matching provisioning
profile:

```
amfid: Restricted entitlements not validated, bailing out.
       Error: "No matching profile found" (Code=-413)
```

Apple does not issue provisioning profiles for raw Mach-O CLI
binaries — they're issued for `.app` bundles distributed under
"Developer ID with Provisioning Profile" or via the Mac App Store.
The path forward, then, is to wrap each consumer's CLI binaries
inside a `.app` bundle, ship the bundle (with the embedded profile)
via Homebrew, and symlink the binaries from `Cellar` into
`/opt/homebrew/bin` so the user-facing CLI experience is unchanged.

This is the same pattern Adobe, JetBrains, 1Password, Docker
Desktop's CLI tools, and many others use for non-MAS distribution
with restricted entitlements. It is documented Apple-supported, not
a workaround.

## Naming

Per-consumer App IDs under a shared `com.godaddy.*` prefix:

| Consumer  | Bundle ID               | Keychain access group              |
| --------- | ----------------------- | ---------------------------------- |
| sshenc    | `com.godaddy.sshenc`    | `<TEAMID>.com.godaddy.sshenc`      |
| awsenc    | `com.godaddy.awsenc`    | `<TEAMID>.com.godaddy.awsenc`      |
| sso-jwt   | `com.godaddy.sso-jwt`   | `<TEAMID>.com.godaddy.sso-jwt`     |
| npmenc    | `com.godaddy.npmenc`    | `<TEAMID>.com.godaddy.npmenc`      |

For the GoDaddy team, `<TEAMID>` is `7UMADG39Z9`.

Per-app (not shared) so:

1. A compromised process from one consumer can't read another's
   wrapping-key items via SecItemCopyMatching — the OS enforces the
   group boundary.
2. Each consumer ships on its own release cadence; a shared profile
   would need cross-project coordination on every renewal.
3. Matches the existing namespacing in
   `enclaveapp-apple/src/keychain_wrap.rs` where the keychain service
   is `com.godaddy.<app_name>`.

libenclaveapp itself does not need an App ID — it's a library, doesn't
ship binaries.

## Per-consumer Apple developer portal setup

This is the only piece that has to happen by hand. ~5 minutes per
consumer. Do this once when adding `.app` bundle distribution to a
consumer; the resulting App ID + provisioning profile are good for
years.

**Prerequisites:** A "Developer ID Application" certificate already
in your team (see sshenc's `docs/macos-unsigned-ux.md` if you need
to set one up).

### Step 1 — register the App ID

1. Sign in to <https://developer.apple.com/account/resources/identifiers/list>
   under the team that owns the Developer ID cert.
2. Click **+** to add a new identifier.
3. Choose **App IDs** → **App** → Continue.
4. Description: `<consumer> — <one-line description>`
   (e.g. `sshenc — hardware-backed SSH key management`).
5. Bundle ID: **Explicit**, value `com.godaddy.<consumer>`
   (e.g. `com.godaddy.sshenc`).
6. Capabilities: leave everything unchecked. The Apple portal no
   longer surfaces Keychain Sharing as an explicit capability for
   App IDs; the team-prefix wildcard `<TEAMID>.*` in the Developer
   ID profile (issued in step 2) covers any `keychain-access-groups`
   claim with that prefix automatically.
7. Continue → Register.

### Step 2 — create the provisioning profile

1. Go to <https://developer.apple.com/account/resources/profiles/list>.
2. Click **+** to add a new profile.
3. Under **Distribution**, choose **Developer ID** → Continue.
4. Select the App ID from step 1 (`com.godaddy.<consumer>`)
   → Continue.
5. Select the **Developer ID Application** certificate → Continue.
6. Profile name: `<consumer> Developer ID profile`
   (e.g. `sshenc Developer ID profile`).
7. Generate → Download. The downloaded file is
   `<consumer>_Developer_ID_profile.provisionprofile` or similar.

Drop the file at
`~/.appstoreconnect/profiles/<consumer>.provisionprofile` and tell
the build pipeline maintainer the absolute path. The pipeline will
base64-encode it and stash it as the `MACOS_PROVISIONING_PROFILE`
GitHub secret on the consumer's repo.

### Step 3 — verify

```sh
security cms -D -i ~/.appstoreconnect/profiles/<consumer>.provisionprofile
```

Should print an XML plist whose `Entitlements` dict contains
`keychain-access-groups: ["<TEAMID>.com.godaddy.<consumer>"]`
and whose `TeamIdentifier` matches your team. If either is wrong, go
back and recreate.

## Pipeline mechanics (the libenclaveapp side)

The reusable release workflow gains:

**Inputs**

| Input                    | Purpose                                                                                                                         |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------- |
| `macos_bundle_id`        | e.g. `com.godaddy.sshenc`. Empty (default) skips the `.app` bundling path; binaries ship as a flat tarball as today.            |
| `macos_binaries`         | Space-separated list of binaries to include in the macOS `.app`. Empty defaults to `unix_binaries`. Use to drop Linux-only      |
|                          | binaries (e.g. tpm-bridge stdio servers) from the macOS tarball.                                                                |

**Secret**

| Secret                          | Purpose                                                                                                                  |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `MACOS_PROVISIONING_PROFILE`    | Base64-encoded `.provisionprofile` from the dev portal. Decoded into `<app>.app/Contents/embedded.provisionprofile`.     |

**Build steps** (added after `Sign release binaries (macOS)`,
before `Package (Unix)`):

1. Stage `macos_binaries` into `<app_name>.app/Contents/MacOS/`.
2. Generate `<app_name>.app/Contents/Info.plist` with the bundle ID
   from `macos_bundle_id`, version from the tag, and a one-line
   description.
3. Decode `MACOS_PROVISIONING_PROFILE` into
   `<app_name>.app/Contents/embedded.provisionprofile`.
4. Codesign the bundle: each binary inside `Contents/MacOS/` first
   with `--options runtime --timestamp --entitlements
   <entitlements>`, then sign the bundle as a whole. (Apple deprecated
   `--deep` — sign children explicitly, then the parent.)
5. Verify the bundle with `codesign --verify --strict --deep --verbose=2`.

**Notarization** moves to submitting the `.app` bundle directly
(notarytool natively accepts bundles), so we drop the
zip-of-binaries step that the current pipeline does.

**Packaging** on macOS becomes `tar czf <app>.tar.gz <app_name>.app`
instead of tarring loose binaries.

**Homebrew formula generation** for macOS gets a new shape:

```ruby
on_macos do
  prefix.install "<app_name>.app"
  bin.install_symlink "<app_name>.app/Contents/MacOS/<bin>" => "<bin>"
  # ...one symlink per binary in macos_binaries
end
```

Linux/Windows targets are untouched. Their tarballs and Scoop bucket
entries continue to ship loose binaries as today.

## Per-consumer integration

Each consumer's `release.yml` adds three things:

```yaml
with:
  macos_bundle_id: "com.godaddy.<consumer>"
  macos_binaries: "<consumer> <consumer>-foo <consumer>-bar"  # if differs from unix_binaries
secrets:
  MACOS_PROVISIONING_PROFILE: ${{ secrets.MACOS_PROVISIONING_PROFILE }}
```

The consumer's Rust code (one line in the place that builds the
`StorageConfig`) passes:

```rust
keychain_access_group: Some("7UMADG39Z9.com.godaddy.<consumer>".into()),
```

The consumer's entitlements plist (`installer/<consumer>.entitlements`)
declares the matching access group:

```xml
<key>keychain-access-groups</key>
<array>
    <string>7UMADG39Z9.com.godaddy.<consumer></string>
</array>
```

Each consumer also has to push its `MACOS_PROVISIONING_PROFILE`
secret to its own GitHub repo (`gh secret set MACOS_PROVISIONING_PROFILE
--repo godaddy/<consumer>`).

## Profile lifecycle

Developer ID provisioning profiles for distribution don't expire as
quickly as development profiles. Current Apple policy: **valid for
the lifetime of the Developer ID Application certificate**, which is
typically 5 years. Practically: set up once, refresh when the cert
gets near expiry. Add a CI cron that checks the embedded profile's
expiry date and warns 90 days out. (Future work; not blocking
initial rollout.)

If the team's Developer ID cert is rotated, the new cert has a new
serial number, and existing provisioning profiles bound to the old
cert will stop validating. Workflow: rotate cert → rotate profile
for each consumer → push new `MACOS_PROVISIONING_PROFILE` secret to
each consumer's repo. Same for the .p12 + password the existing
signing pipeline uses.

## Rollout order

1. **libenclaveapp PR** — pipeline changes (this doc + the workflow
   updates). Lands first.
2. **sshenc PR** — first consumer to opt in. Apple portal setup for
   `com.godaddy.sshenc`, secret upload, three-line `release.yml`
   change, Rust + entitlements changes. Tag-driven release verifies
   end-to-end.
3. **awsenc / sso-jwt / npmenc** — follow the same recipe once
   sshenc proves the pipeline. Each is ~3 file changes per repo plus
   the Apple portal step.

The libenclaveapp pipeline change is opt-in via `macos_bundle_id`,
so it doesn't disturb consumers that haven't migrated yet.
