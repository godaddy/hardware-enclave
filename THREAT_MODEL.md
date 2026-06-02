# Enclave Threat Model

By Jay Gowdy

## Review Metadata

| Field | Value |
|---|---|
| Status | NOT STARTED |
| Product Security Engineer | TBD |
| Contributors | Jay Gowdy |
| Jira tickets | TBD |
| Readiness Review | TBD |
| AWS account numbers | N/A. `enclave` is a Rust library and does not own AWS-hosted production infrastructure. |
| Incident Response Sharepoint Link | TBD |
| Cat | TBD |

## Abstract

This threat modeling document gives security considerations for
`enclave` based on the current architecture and implementation. It covers
security assumptions, security features built into the design, threats and
mitigations, external dependencies, and residual risks accepted by the
engineering team.

`enclave` is a shared Rust library for hardware-backed signing and
credential encryption. It is consumed by applications such as `sshenc`,
`gocode-dev`, `awsenc`, `sso-jwt`, and `npmenc`.

## Overview

`enclave` provides platform-neutral traits and adapters for P-256 signing,
ECIES-style encryption, platform key lifecycle, metadata persistence,
application storage bootstrap, WSL bridge communication, process hardening, and
app-adapter secret delivery patterns.

| Field | Value |
|---|---|
| Product State | In-Production |
| Application Prod URL | N/A. Library crate consumed by local applications. |
| Application Dev/Test URL | N/A. |
| Source Code | https://github.com/godaddy/enclave |
| Exposure | Internal/library code; not directly externally accessible. |
| Network zones deployed in | N/A. Runs inside consuming applications on developer workstations. |
| People/groups with access to production servers | N/A. No production servers are operated by this repository. |

## Security Guarantee

`enclave` aims to provide the following guarantees to consuming
applications:

- Hardware-backed P-256 private keys are non-exportable on supported Secure
  Enclave and TPM backends.
- Encrypted credential caches are unusable on another device when backed by
  hardware-resident keys.
- AES-256-GCM detects tampering with encrypted payloads.
- Metadata integrity protections detect policy-relevant `.meta` tampering where
  the platform cannot enforce policy independently.
- WSL bridge discovery avoids user-writable PATH lookup and bounds bridge
  request/response behavior.
- Unsafe FFI boundaries are kept narrow and validated with explicit contract
  checks.
- Consumers can apply process hardening before secret material is loaded into
  memory.

The library is used inside local CLI tools, agents, and credential helpers. It
does not by itself authenticate end users to GoDaddy services or operate a
network service.

Regulatory/legal requirements are inherited from consuming products.

Misuse that must be prevented or bounded:

- Export of hardware-backed private key material.
- Reuse of hardware-wrapped ciphertext on another machine.
- Silent policy downgrade by editing local metadata.
- Replacement of WSL bridge binaries through user-writable paths.
- Unbounded bridge response inflation or hung child processes.
- Accidental plaintext fallback in production secure storage.

## In-Scope

- P-256 signing keys and encryption keys managed by platform backends.
- ECIES encryption/decryption of credential caches.
- Metadata, handle, public-key, HMAC sidecar, and secure-store tag files.
- macOS Secure Enclave and Keychain wrapping behavior.
- Windows TPM/CNG and Windows WebAuthn/SK behavior.
- Linux TPM and keyring/software backend behavior.
- WSL bridge client/server protocol and discovery.
- App-storage backend selection.
- App-adapter delivery types and secret handling.
- Process hardening helpers, zeroization, and cache envelope protections.

## Out of Scope

- Security of applications that consume credentials after `enclave`
  returns them.
- Security of external identity providers, cloud providers, SSH servers,
  package registries, or application-specific APIs.
- Kernel, hypervisor, firmware, or root/admin compromise.
- Physical attacks on Secure Enclave, TPM chips, or side-channel attacks.
- Supply-chain compromise of Rust crates, compilers, platform SDKs, or system
  crypto libraries.
- Denial-of-service by deleting keys, corrupting metadata, killing agents, or
  exhausting local resources.
- User error in Type 4 credential-source consumers that print, export, or log
  returned credentials.

## Attack assumptions

The following assumptions relate to attackers and their available resources:

- A same-UID attacker may run code as the user and can access files, process
  environments, local IPC endpoints, and session keyrings available to that
  user.
- A root/admin attacker can replace binaries, attach debuggers, read process
  memory, bypass filesystem permissions, and directly access platform APIs.
- An offline attacker may copy disks, backups, profile directories, or encrypted
  cache files.
- A WSL attacker may control user-writable Linux paths and environment
  variables.
- A network attacker may observe or modify application-layer traffic handled by
  consuming apps, but `enclave` itself does not create network protocols.
- A supply-chain attacker may modify dependencies, bridge binaries, build tools,
  or consuming applications.

## Architectural Assumptions

- Consuming binaries call `enclaveapp_core::process::harden_process()` before
  loading secret material.
- Consuming applications choose the correct integration type for their threat
  model: helper tool, environment interpolation, temp materialized config, or
  credential source.
- The OS profile and secure storage belong to the intended local user.
- Hardware-backed platform APIs enforce non-exportability where the platform
  claims they do.
- Access policies are strongest on macOS Secure Enclave and Windows TPM/SK
  paths. Linux TPM and keyring backends do not provide equivalent biometric or
  user-presence enforcement.
- WSL bridge binaries are installed into fixed Windows admin-owned locations
  unless the user explicitly overrides the path.
- Unsigned Windows releases are an intentional product policy for canonical
  consumers; Authenticode bridge enforcement is available only for consumers
  that build with that requirement.

## Architectural Diagrams

Relevant diagrams are maintained under:

- Diagram folder: https://github.com/godaddy/enclave/tree/main/docs/diagrams

Key diagrams for review:

- Architecture diagram (PNG with embedded draw.io source): https://github.com/godaddy/enclave/blob/main/docs/diagrams/architecture.png
- Data flow diagram: https://github.com/godaddy/enclave/blob/main/docs/diagrams/data-flow-diagram.mmd
- Workspace context: https://github.com/godaddy/enclave/blob/main/docs/diagrams/workspace-context.mmd
- App-storage backend selection: https://github.com/godaddy/enclave/blob/main/docs/diagrams/app-storage-backend-selection.mmd
- Encryption flow: https://github.com/godaddy/enclave/blob/main/docs/diagrams/encryption-flow.mmd
- Signing flow: https://github.com/godaddy/enclave/blob/main/docs/diagrams/signing-flow.mmd
- Metadata trust boundary: https://github.com/godaddy/enclave/blob/main/docs/diagrams/metadata-trust-boundary.mmd
- WSL bridge flow: https://github.com/godaddy/enclave/blob/main/docs/diagrams/wsl-bridge-flow.mmd
- Adapter integration types: https://github.com/godaddy/enclave/blob/main/docs/diagrams/adapter-integration-types.mmd

Architecture guidance mapping:

| Question | Answer for `enclave` |
|---|---|
| Hosting location | Library code inside consuming local applications. No AWS account, region, VPC, subnet, AZ, or datacenter deployment is owned by this repo. |
| Major resources | Rust crates, platform backends, local metadata/key files, platform secure storage, optional WSL bridge child process. |
| Global / region / VPC resources | N/A for this repository. Consuming applications own any hosted infrastructure they call. |
| Ingress points | Library API calls from the consuming process; WSL bridge JSON-RPC over child process stdin/stdout. No network listener. |
| Egress points | Local platform APIs: Keychain, CNG/TPM, WebAuthn, Linux TPM, Secret Service/keyring, filesystem. No direct network egress. |
| Interface protection | OS process boundary, platform secure-storage ACLs, hardware non-exportability, fixed-path bridge discovery, metadata HMAC/trust anchors, bounded bridge IO. |
| AuthN/AuthZ methods | Local OS user/session identity, platform secure-storage policy, consuming-application authorization decisions. |
| Deployment architecture | Linked library / local helper model. No hot/hot, hot/warm, or autoscaled hosted service in this repo. |
| Expected traffic | Human developer or local tool invocation rates; operations are local secure-storage calls, not web request traffic. |

## Network ACLs

`enclave` is a library and does not expose inbound network services or
own network ACLs. WSL bridge communication is local stdio between a Linux client
process and a Windows bridge child process.

### INBOUND FLOWS

| ACL Type | Allow / Block | Source CIDR / hosts | Destination CIDR / hosts | Port(s) | Notes |
|---|---|---|---|---|---|
| Network | N/A | N/A | N/A | N/A | No inbound network listener is provided by this library. |
| Local IPC / stdio | Allow | Consuming app process | WSL bridge child process | N/A | JSON-RPC over child stdin/stdout for WSL TPM access. |

### OUTBOUND FLOWS

| ACL Type | Allow / Block | Source CIDR / hosts | Destination CIDR / hosts | Port(s) | Notes |
|---|---|---|---|---|---|
| Network | N/A | N/A | N/A | N/A | No outbound network calls are made by the library itself. |
| Platform API | Allow | Consuming process | Keychain, CNG/TPM, Secret Service, TPM device | N/A | Local OS/secure-hardware APIs used for signing, ECDH, key storage, and metadata tags. |

## Data Flow Diagram

Primary DFD: https://github.com/godaddy/enclave/blob/main/docs/diagrams/data-flow-diagram.mmd

Encryption DFD: https://github.com/godaddy/enclave/blob/main/docs/diagrams/encryption-flow.mmd

Signing DFD: https://github.com/godaddy/enclave/blob/main/docs/diagrams/signing-flow.mmd

Data processed or transmitted:

| Data type | Processed | Transmitted | Notes |
|---|---|---|---|
| P-256 private keys | Yes | No export on hardware backends | Created and used inside Secure Enclave/TPM where supported. |
| Key handles / blobs | Yes | Local disk only | May be opaque hardware references or wrapped software key material depending on backend. |
| Public keys | Yes | Returned to consumers | Not secret. |
| Credential plaintext | Yes | Returned to consuming app | Exists in process memory after decrypt. Consumer owns onward handling. |
| Credential ciphertext | Yes | Local disk by consuming app | AES-256-GCM envelope with backend-specific key protection. |
| Metadata | Yes | Local disk and secure-store tags | Includes labels, access policy, app-specific fields. |
| PII Data | No direct business PII by design | N/A | Consuming apps may encrypt tokens that contain user identity claims. |

## Critical Components

### `enclaveapp-core`

Type: library crate

Use case: Shared traits, errors, metadata helpers, binary discovery, process
hardening, and common crypto/data structures.

Input: Consumer requests, metadata files, platform results.

Output: Typed signing/encryption abstractions and hardened process behavior.

### `enclaveapp-app-storage`

Type: library crate

Use case: App-level bootstrap for encryption and signing backends.

Input: App name, key label, access policy, platform detection.

Output: Selected backend implementation for the current environment.

### Platform Backends

Type: library crates / platform FFI

Use case: Secure Enclave, Windows TPM/CNG, WebAuthn/SK, Linux TPM, keyring, and
test software implementations.

Input: Generate, sign, decrypt, delete, and metadata-integrity requests.

Output: Public keys, signatures, decrypted payloads, or platform errors.

### WSL Bridge

Type: local child process protocol

Use case: Allows WSL clients to delegate TPM operations to a Windows-hosted
bridge executable.

Input: JSON-RPC requests over stdio.

Output: JSON-RPC responses containing public keys, signatures, decrypt results,
or errors.

### App Adapter

Type: library crate

Use case: Delivers secrets to target applications through helper tools,
environment variables, temporary config, or credential-source APIs.

Input: Application secret material and launch configuration.

Output: Child process launch, redacted reads, or credential-source output.

## Trust Levels

| Name | Description | Trust details |
|---|---|---|
| Consuming application | Binary using `enclave` | Trusted to request appropriate backend, call process hardening early, and handle returned secrets correctly. |
| Same-UID process | Code running as the same OS user | Limited trust. Can access session resources and may call local APIs; active same-UID malware is not fully defeated. |
| Root/admin | Privileged local actor | Not trusted and out of scope for confidentiality of in-memory secrets. |
| Secure Enclave / TPM | Hardware security module | Trusted for non-exportability and hardware-backed operations. |
| OS keychain/keyring/Credential Manager | Platform secure storage | Trusted according to platform semantics; weaker than hardware for same-user boundaries. |
| WSL bridge binary | Windows child process serving WSL requests | Trusted if installed in fixed admin-owned path; replacement by Windows admin is out of scope. |
| Metadata files | Local disk sidecar state | Untrusted until verified by HMAC sidecar or secure-store trust anchor where implemented. |

## External Dependencies

| Name | Type | Use case |
|---|---|---|
| Apple CryptoKit / Security.framework | Platform API | Secure Enclave P-256 keys and Keychain wrapping/tag storage. |
| Windows CNG / TPM Platform Crypto Provider | Platform API | TPM-backed P-256 signing/encryption keys. |
| Windows WebAuthn / NGC | Platform API | Hardware-backed SK path and Hello UX. |
| Linux TPM / tss-esapi | Platform API/library | TPM-backed operations on Linux. |
| Secret Service / keyring | Platform service | Linux keyring-backed software key protection and metadata tags. |
| OS filesystem APIs | Platform API | Metadata, handle, cache, and sidecar persistence. |
| Rust crypto crates | Library dependencies | AES-GCM, HKDF/SHA-256, P-256 operations in software paths. |
| Windows bridge host environment | Local platform | WSL access to Windows TPM through fixed-path bridge executable. |

## APIs/Interfaces

| API Endpoint / Interface | Mutating | authN | authZ | External Facing |
|---|---|---|---|---|
| `SigningBackend::generate/sign/delete` | Yes | Local process identity | Consuming app policy and platform backend | No |
| `EncryptionStorage::encrypt/decrypt` | Yes | Local process identity | Platform secure storage access | No |
| Metadata read/write helpers | Yes | Local filesystem user | File permissions plus HMAC/trust-anchor checks | No |
| WSL bridge JSON-RPC | Yes | Child process relationship | Fixed path discovery and OS permissions | No |
| App-adapter launcher | Yes | Local process identity | Consuming app policy | No |
| Platform FFI calls | Yes | OS user/session | Platform-specific secure storage policy | No |

## Authentication / Authorization

`enclave` does not authenticate users to a web service. It relies on local
OS identity, platform secure-storage ACLs, hardware access policy, and consumer
application policy.

On macOS, Keychain ACL behavior can be tied to code-signing identity for stored
wrapping keys and metadata tags. On Windows, TPM/CNG and WebAuthn/SK paths
provide hardware-backed key use; signed Windows binaries are not required by the
canonical consumers. On Linux, keyring and TPM behavior depend on local session
and device access.

## Source Code

- Product repository: https://github.com/godaddy/enclave
- Design: https://github.com/godaddy/enclave/blob/main/DESIGN.md
- Diagrams: https://github.com/godaddy/enclave/tree/main/docs/diagrams

## Monitoring/Alerting

`enclave` is a local library and does not operate a central production
service with on-call alerting from this repository.

| Question | Answer |
|---|---|
| Active alerting to on-call? | N/A for the library. Consuming applications own service alerting. |
| OS security logs stored where? | Developer/user workstation OS policy. |
| Security relevant app logs stored where? | Consuming application logs. The library emits errors/warnings through consumer logging. |
| Retention | Determined by consuming application and workstation policy. |
| Centralized logging | N/A from this repository. |

## Where are secrets / client certs / credentials etc stored?

| Secret / credential | Storage location | Protection |
|---|---|---|
| Hardware private signing/encryption keys | Secure Enclave or TPM | Non-exportable on supported hardware backends. |
| macOS Secure Enclave handle | App key directory `.handle` file | AES-256-GCM wrapped under Keychain-held wrapping key. |
| Windows TPM key | Windows TPM/CNG key store | TPM-resident non-exportable key material. |
| Linux TPM key | Linux TPM state / key files | TPM-resident where supported; no biometric enforcement. |
| Linux keyring/software key | Encrypted local key file plus system keyring | Weaker than hardware; same-user keyring access remains a residual risk. |
| Credential ciphertext | Consuming app cache file | AES-256-GCM ECIES envelope; optional header/counter rollback protection in cache envelope users. |
| Credential plaintext | Consuming process memory | Must be handled by consumer; library zeroizes selected secret-bearing buffers. |
| Metadata HMAC tags | Keychain, Credential Manager, or Secret Service | Used to detect metadata tamper where implemented. |
| Client certificates | N/A | No client certificates are stored by the library. |

## Threats (To be filled out by Dev/Eng team and reviewed by Security)

| Threat ID | Threat Description | Affected Resource ID | Mitigated | Mitigation Details | Mitigation Verified |
|---|---|---|---|---|---|
| LEA-T01 | Attacker extracts hardware private key material. | Secure Enclave / TPM keys | Yes | Hardware-backed keys are non-exportable; APIs return signatures or ECDH results, not key bytes. | TBD |
| LEA-T02 | Stolen disk or copied profile decrypts credential caches on another device. | Credential ciphertext | Yes | Hardware ECIES key agreement requires original Secure Enclave/TPM key; ciphertext is device-bound on hardware backends. | TBD |
| LEA-T03 | Same-UID process requests signatures through a legitimate helper/agent. | Signing backends / consumers | Partially | User-presence policies can force Touch ID, Windows Hello/SK, or TPM UI where supported. Keys with `AccessPolicy::None` remain signable by same-user callers. | TBD |
| LEA-T04 | Root/admin reads process memory or replaces binaries. | All local secrets | No | Privileged local compromise is out of scope; hardware may still prevent key extraction but not key use or plaintext memory theft. | TBD |
| LEA-T05 | Metadata tamper downgrades access policy or deceives UI. | `.meta` files | Yes / Partially | HMAC sidecars and secure-store trust anchors detect tamper where implemented; macOS/Windows hardware enforce policy at key creation. Linux TPM/keyring limitations remain documented. | TBD |
| LEA-T06 | WSL bridge binary is planted through user-writable PATH. | WSL bridge | Yes | Bridge discovery uses fixed Windows paths; PATH fallback removed. | TBD |
| LEA-T07 | WSL bridge response inflation or hung child consumes resources. | WSL bridge client | Yes | Response size cap, read timeout, and kill-on-drop session lifecycle. | TBD |
| LEA-T08 | Unsigned Windows bridge replacement in admin-owned install path. | WSL bridge | No / Accepted | Canonical consumers deliberately do not Authenticode-sign Windows releases; replacement requires Windows admin. Build-time signed-bridge enforcement exists for consumers that opt in. | TBD |
| LEA-T09 | Unsafe Swift/Rust or Windows FFI contract drift causes memory corruption or incorrect behavior. | Platform FFI | Partially | Narrow FFI surface, buffer-size retry caps, layout assertions, and hard errors on contract violations. | TBD |
| LEA-T10 | Linux keyring backend exposes software private key to same-user session. | Linux keyring/software backend | No / Accepted | Documented weaker backend; errors rather than plaintext fallback when keyring unavailable. | TBD |
| LEA-T11 | Cache header tamper or rollback extends credential lifetime. | Credential cache envelope | Yes / Partially | Header hash binding and monotonic counter sidecar detect most edits/replays; attacker who can rewrite both cache and counter can replay only within server-side validity window. | TBD |
| LEA-T12 | Build-time tool shadowing injects malicious Swift object. | macOS build | Yes / Partially | Apple build script resolves `/usr/bin/xcrun` and Xcode-selected tools instead of PATH. General supply-chain compromise remains out of scope. | TBD |
