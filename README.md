# Enclave

Hardware-backed signing, encryption, and in-process memory protection for Rust.

Supports macOS (Secure Enclave), Windows (TPM 2.0), Linux (TPM 2.0 / keyring),
and WSL2. Private keys never leave the hardware. Touch ID and Windows Hello
are built in.

## Using the `enclave` crate

The [`enclave`](crates/enclave/) crate is the public API — hardware key management,
FIDO2 security keys, tamper-evident files, and guard-paged memory protection.

**→ [crates/enclave/README.md](crates/enclave/README.md) — start here**

```toml
[dependencies]
enclave = "0.1"
```

## Building wrapper applications

If you are building an application that wraps a third-party tool and injects
hardware-backed secrets into it, see the delivery tier guide:

**→ [crates/enclave/DELIVERY_TIERS.md](crates/enclave/DELIVERY_TIERS.md)**

Covers: SSH agent protocol, environment variable injection, temp file delivery,
and credential source patterns — with guidance on when to use each.

## Security

See [crates/enclave/THREAT_MODEL.md](crates/enclave/THREAT_MODEL.md) for the
full threat model, limitations, and residual risks.

Report vulnerabilities to security@godaddy.com or
[HackerOne](https://hackerone.com/godaddy).

## Workspace crates

The `enclave` crate is the public interface. The `enclaveapp-*` crates are
internal platform implementations.

| Crate | Role |
|---|---|
| **[enclave](crates/enclave/)** | Public API — the crate consumers import |
| [enclaveapp-app-storage](crates/enclaveapp-app-storage/) | Platform-detected signing / encryption |
| [enclaveapp-app-adapter](crates/enclaveapp-app-adapter/) | Secret delivery substrate |
| [enclaveapp-apple](crates/enclaveapp-apple/) | macOS Secure Enclave (CryptoKit Swift bridge) |
| [enclaveapp-windows](crates/enclaveapp-windows/) | Windows TPM 2.0 (CNG) |
| [enclaveapp-linux-tpm](crates/enclaveapp-linux-tpm/) | Linux TPM 2.0 (tss-esapi) |
| [enclaveapp-keyring](crates/enclaveapp-keyring/) | Linux keyring-encrypted P-256 keys |
| [enclaveapp-bridge](crates/enclaveapp-bridge/) | JSON-RPC bridge protocol + WSL client |
| [enclaveapp-tpm-bridge](crates/enclaveapp-tpm-bridge/) | Shared TPM bridge server |
| [enclaveapp-wsl](crates/enclaveapp-wsl/) | WSL detection, distro config |
| [enclaveapp-core](crates/enclaveapp-core/) | Traits, types, metadata, utilities |
| [enclaveapp-cache](crates/enclaveapp-cache/) | Shared binary cache format |

## Building

Requires Rust 1.75+. macOS builds require Xcode (Swift bridge compilation).

```bash
cargo build --workspace
cargo test --workspace
```

## License

MIT — Copyright 2026 Jay Gowdy
