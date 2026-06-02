# Windows & WSL Test Matrix

**Date:** 2026-04-16
**Versions:** awsenc v0.4.10 | sshenc v0.6.12 | sso-jwt v0.5.10 | npmenc/npxenc v0.1.0

## Environments

| ID | Environment | Binary Type | Notes |
|----|-------------|-------------|-------|
| PS | PowerShell | x86_64-pc-windows-msvc | Native Windows |
| CMD | Command Prompt | x86_64-pc-windows-msvc | Native Windows |
| GB | Git Bash (MINGW64) | x86_64-pc-windows-msvc | Native Windows |
| WU | WSL2 Ubuntu 24.04 | x86_64-unknown-linux-gnu | gnome-keyring 46.1 |
| WD | WSL2 Debian 13 | x86_64-unknown-linux-gnu | gnome-keyring 48.0 |
| WF | WSL2 Fedora 43 | x86_64-unknown-linux-gnu | gnome-keyring 48.0 |
| WA | WSL2 AlmaLinux 9.7 | x86_64-unknown-linux-gnu | gnome-keyring 40.0 |

## Results Summary

| Environment | Pass | Fail | Skip | Notes |
|-------------|------|------|------|-------|
| **PowerShell** | **29** | 0 | 0 | |
| **Command Prompt** | **29** | 0 | 0 | |
| **Git Bash** | **29** | 0 | 0 | |
| **WSL2 Ubuntu + keyring** | **30** | 0 | 4 | `--keyring` lifecycle passes |
| **WSL2 Debian + keyring** | **30** | 0 | 4 | `--keyring` lifecycle passes |
| **WSL2 Fedora + keyring** | **30** | 0 | 4 | `--keyring` lifecycle passes |
| **WSL2 AlmaLinux + keyring** | **30** | 0 | 4 | `--keyring` lifecycle passes |

The 4 skips on WSL are PowerShell shell-init and completions tests (not applicable on Linux).

---

## Detailed Test Results

### awsenc

| Test | PS | CMD | GB | WU | WD | WF | WA |
|------|:--:|:---:|:--:|:--:|:--:|:--:|:--:|
| `--version` (0.4.10) | P | P | P | P | P | P | P |
| `config` | P | P | P | P | P | P | P |
| `list` | P | P | P | P | P | P | P |
| `list --json` | P | P | P | P | P | P | P |
| `clear --all` | P | P | P | P | P | P | P |
| `shell-init bash` | P | P | P | P | P | P | P |
| `shell-init powershell` | P | P | P | S | S | S | S |
| `completions bash` | P | P | P | P | P | P | P |
| `completions powershell` | P | P | P | S | S | S | S |

### sshenc

| Test | PS | CMD | GB | WU | WD | WF | WA |
|------|:--:|:---:|:--:|:--:|:--:|:--:|:--:|
| `--version` (0.6.12) | P | P | P | P | P | P | P |
| `config path` | P | P | P | P | P | P | P |
| `config show` | P | P | P | P | P | P | P |
| `list` | P | P | P | P | P | P | P |
| `keygen` (TPM on Win, keyring on WSL) | P | P | P | P | P | P | P |
| `inspect` | P | P | P | P | P | P | P |
| `export-pub` | P | P | P | P | P | P | P |
| `export-pub --fingerprint` | P | P | P | P | P | P | P |
| `delete` | P | P | P | P | P | P | P |
| `completions bash` | P | P | P | P | P | P | P |
| `completions powershell` | P | P | P | S | S | S | S |
| `--keyring keygen` | - | - | - | P | P | P | P |
| `--keyring list` | - | - | - | P | P | P | P |
| `--keyring inspect` | - | - | - | P | P | P | P |
| `--keyring export-pub` | - | - | - | P | P | P | P |
| `--keyring delete` | - | - | - | P | P | P | P |

### npmenc / npxenc

| Test | PS | CMD | GB | WU | WD | WF | WA |
|------|:--:|:---:|:--:|:--:|:--:|:--:|:--:|
| `npmenc --version` (0.1.0) | P | P | P | P | P | P | P |
| `npxenc --version` (0.1.0) | P | P | P | P | P | P | P |
| `npmenc --help` | P | P | P | P | P | P | P |
| `npxenc --help` | P | P | P | P | P | P | P |

### sso-jwt

| Test | PS | CMD | GB | WU | WD | WF | WA |
|------|:--:|:---:|:--:|:--:|:--:|:--:|:--:|
| `--version` (0.5.10) | P | P | P | P | P | P | P |
| `--clear` | P | P | P | P | P | P | P |
| `shell-init bash` | P | P | P | P | P | P | P |
| `shell-init zsh` | P | P | P | P | P | P | P |
| `shell-init powershell` | P | P | P | S | S | S | S |

---

## WSL Keyring Setup

WSL2 distros require a system keyring (D-Bus Secret Service) for key storage. See [LINUX_SETUP.md](LINUX_SETUP.md) for full setup instructions.

### Packages Required

| Distro | Packages |
|--------|----------|
| Ubuntu 24.04 | `gnome-keyring dbus-x11 libsecret-tools libtss2-dev libdbus-1-dev` |
| Debian 13 | `gnome-keyring dbus-x11 libsecret-tools libtss2-dev libdbus-1-dev` |
| Fedora 43 | `gnome-keyring dbus-x11 libsecret tpm2-tss-devel dbus-devel` |
| AlmaLinux 9 | `gnome-keyring gnome-keyring-pam dbus-x11 libsecret pinentry tpm2-tss-devel dbus-devel` |

### Keyring Initialization

```bash
# Start D-Bus and gnome-keyring
export XDG_RUNTIME_DIR=/run/user/$(id -u)
mkdir -p $XDG_RUNTIME_DIR && chmod 700 $XDG_RUNTIME_DIR
eval $(dbus-launch --sh-syntax)
gnome-keyring-daemon --start --components=secrets

# Create default keyring (first time — triggers password dialog)
echo "probe" | secret-tool store --label="setup" app enclaveapp key setup
```

---

## Windows Installation

### Via Scoop

```powershell
scoop update awsenc sshenc sso-jwt
```

npmenc is not yet in Scoop — install from GitHub releases:

```powershell
# Download and extract to a directory in your PATH
Invoke-WebRequest -Uri "https://github.com/godaddy/npmenc/releases/latest/download/npmenc-x86_64-pc-windows-msvc.zip" -OutFile npmenc.zip
Expand-Archive npmenc.zip -DestinationPath "$env:LOCALAPPDATA\npmenc\bin"
```

### WSL Installation

Download `x86_64-unknown-linux-gnu` tarballs from GitHub releases:

```bash
for app in awsenc sshenc sso-jwt npmenc; do
  curl -sL "https://github.com/godaddy/$app/releases/latest/download/$app-x86_64-unknown-linux-gnu.tar.gz" | tar xz
done
sudo cp awsenc sshenc sshenc-agent sshenc-keygen gitenc sso-jwt npmenc npxenc /usr/local/bin/
```

### GLIBC Compatibility

GNU binaries require glibc 2.35+ (built on Ubuntu 22.04). Supported:

- Ubuntu 22.04+, Debian 12+, Fedora 36+, RHEL 10+

For RHEL 9 / AlmaLinux 9 (glibc 2.34), use the `x86_64-unknown-linux-musl` build. Note: musl builds do not include keyring support.

---

## Not Yet Tested (Require External Dependencies)

- **Okta authentication** — awsenc auth/serve/exec (requires Okta org + credentials)
- **OAuth device code flow** — sso-jwt token acquisition (requires OAuth server)
- **SSH connections** — sshenc ssh/agent (requires SSH target with registered key)
- **Git commit signing** — gitenc (requires git repo + configured identity)
- **Windows Hello / biometric** — access policy tests (requires interactive session)
- **WSL TPM bridge** — signing bridge not yet released; encryption bridge requires Okta/OAuth
- **npm registry auth** — npmenc install/uninstall (requires npm registry token)

---

## Test Automation

Tests are run via `run-matrix-tests.sh`:

```bash
# Windows (from Git Bash)
bash run-matrix-tests.sh "Git Bash"

# WSL with keyring
export USE_KEYRING=1
bash run-matrix-tests.sh "WSL2 Ubuntu"
```

## Resolved Issues

The following issues were found during testing and fixed:

1. **ECIES encrypt broken on Windows 11 build 26200** — `BCryptDeriveKey` HASH KDF defaulted to SHA-1 instead of SHA-256. Fixed in enclave#16.
2. **`sso-jwt shell-init powershell` not supported** — Fixed in sso-jwt#16.
3. **WSL signing path probed libtss2 before detecting WSL** — Caused noisy TCTI errors. Fixed in enclave#25.
4. **Musl builds stored keys as plaintext** — Fixed in enclave#25 (refuses without keyring).
5. **GNU binaries required glibc 2.39** — Pinned CI to ubuntu-22.04. Fixed in enclave#28.
6. **No `--keyring` flag for testing** — Added to all apps (sshenc#27, awsenc#23, sso-jwt#22).
7. **Signing bridge missing for WSL** — Added to bridge protocol (enclave#27).
8. **npmenc macOS test failures** — Temp dir path canonicalization (npmenc#8, #9).
