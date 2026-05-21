# libenclaveapp Diagrams

These diagrams are text-based Mermaid sources for the main `libenclaveapp`
architecture and flows. They are intended to be maintained with the code and
rendered by GitHub, Mermaid CLI, or other Mermaid-compatible tools.

The diagrams keep application-specific domain logic out of scope. Consuming
apps such as `sshenc`, `awsenc`, `sso-jwt`, `npmenc`, and `gocode-dev` are
shown only as examples of callers into the shared library.

## Files

- [`workspace-context.mmd`](workspace-context.mmd): crate boundaries and how
  consuming enclave apps depend on shared library layers.
- [`app-storage-backend-selection.mmd`](app-storage-backend-selection.mmd):
  `enclaveapp-app-storage` platform detection and backend dispatch.
- [`encryption-flow.mmd`](encryption-flow.mmd): application encrypt/decrypt
  lifecycle through `AppEncryptionStorage`.
- [`signing-flow.mmd`](signing-flow.mmd): application signing lifecycle through
  `AppSigningBackend`.
- [`adapter-integration-types.mmd`](adapter-integration-types.mmd): Type 1-4
  secret delivery strategies and their guardrail strength.
- [`wsl-bridge-flow.mmd`](wsl-bridge-flow.mmd): WSL client delegation to the
  Windows TPM bridge.
- [`metadata-trust-boundary.mmd`](metadata-trust-boundary.mmd): key artifacts,
  metadata, and platform trust anchors at a high level.

## Rendering

Example with Mermaid CLI:

```sh
mmdc -i docs/diagrams/workspace-context.mmd -o workspace-context.svg
```

