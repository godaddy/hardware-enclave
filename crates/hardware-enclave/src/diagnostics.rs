// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Platform diagnostics for troubleshooting hardware key management failures.
//!
//! On Windows, [`collect_vm_diagnostics`] gathers hypervisor-detection data used
//! to decide whether a DPAPI software fallback is appropriate when TPM 2.0 is
//! unavailable (e.g. in a VM without TPM passthrough).
//!
//! All items in this module require the `signing` or `encryption` feature.
//! The DPAPI/VM items additionally require Windows.

/// Hypervisor / VM detection results collected from CPUID, registry, and service
/// enumeration on Windows.
///
/// All fields are best-effort — missing data is `None` or an empty `Vec`.
#[cfg(all(
    any(feature = "signing", feature = "encryption"),
    target_os = "windows"
))]
pub use crate::internal::windows::dpapi_fallback::VmDiagnostics;

/// Collect VM/hypervisor diagnostics on Windows.
///
/// Reads CPUID hypervisor bit, Hyper-V and VMware registry keys, Windows service
/// names, and the display-adapter string to determine whether the host is a VM.
#[cfg(all(
    any(feature = "signing", feature = "encryption"),
    target_os = "windows"
))]
pub use crate::internal::windows::dpapi_fallback::collect_vm_diagnostics;

/// Decision returned by [`should_use_dpapi_after_tpm_failure`].
#[cfg(all(
    any(feature = "signing", feature = "encryption"),
    target_os = "windows"
))]
pub use crate::internal::windows::dpapi_fallback::FallbackDecision;

/// Decide whether a DPAPI software fallback is appropriate after a TPM failure.
///
/// Returns a [`FallbackDecision`] based on the error string and current
/// VM-detection diagnostics.
#[cfg(all(
    any(feature = "signing", feature = "encryption"),
    target_os = "windows"
))]
pub use crate::internal::windows::dpapi_fallback::should_use_dpapi_after_tpm_failure;

/// Human-readable description of the Windows secure storage backend.
///
/// Detects VM presence and Windows Hello availability once per process
/// (cached via [`std::sync::OnceLock`]) and returns the appropriate label:
///
/// - Non-VM, Hello/PIN configured: TPM 2.0 + Windows Hello gate
/// - Non-VM, no Hello: TPM 2.0 + password gate
/// - VM environment: ECIES P-256 + Windows Data Protection API (user-bound)
#[cfg(all(
    any(feature = "signing", feature = "encryption"),
    target_os = "windows"
))]
pub fn windows_backend_description() -> &'static str {
    use std::sync::OnceLock;

    static IS_VM: OnceLock<bool> = OnceLock::new();
    static HELLO_AVAILABLE: OnceLock<bool> = OnceLock::new();

    let is_vm = *IS_VM.get_or_init(|| collect_vm_diagnostics().vm_detected);
    if is_vm {
        return "✓ Windows ECIES P-256, Windows Data Protection API (user-bound)";
    }

    let hello = *HELLO_AVAILABLE.get_or_init(crate::internal::windows::hello_gate::is_available);
    if hello {
        "✓ Windows TPM 2.0 ECDH P-256 ECIES, Windows Hello gate"
    } else {
        "✓ Windows TPM 2.0 ECDH P-256 ECIES, password gate"
    }
}
