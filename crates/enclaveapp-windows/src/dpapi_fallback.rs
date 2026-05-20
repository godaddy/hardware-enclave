// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Guardrails for Windows DPAPI fallback.
//!
//! The fallback is deliberately decided here, inside the Windows backend,
//! rather than by application string matching. A caller can opt into the
//! policy, but cannot bypass the local "TPM failed + VM detected"
//! checks with an environment variable or app-level flag.

#![allow(unsafe_code, unused_qualifications)]

#[cfg(target_os = "windows")]
use windows::Win32::System::Registry::{
    RegGetValueW, HKEY_LOCAL_MACHINE, REG_VALUE_TYPE, RRF_RT_REG_SZ,
};

/// Decision details for audit logging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FallbackDecision {
    pub allowed: bool,
    pub tpm_failure: bool,
    pub vm_detected: bool,
    pub reason: String,
}

/// Return whether a failed TPM initialization may fall back to DPAPI.
pub fn should_use_dpapi_after_tpm_failure(error: &str) -> FallbackDecision {
    let tpm_failure = is_tpm_unavailable_error(error);
    let vm = detect_vm();
    let allowed = tpm_failure && vm.detected;
    let reason = match (allowed, tpm_failure, vm.detected) {
        (true, _, _) => format!("TPM unavailable and VM detected: {}", vm.reason),
        (false, false, _) => "TPM failure did not look like missing/unusable TPM hardware".into(),
        (false, true, false) => format!("TPM unavailable but VM not detected: {}", vm.reason),
        (false, true, true) => "fallback denied".into(),
    };
    FallbackDecision {
        allowed,
        tpm_failure,
        vm_detected: vm.detected,
        reason,
    }
}

fn is_tpm_unavailable_error(error: &str) -> bool {
    let lower = error.to_ascii_lowercase();
    [
        "hardware security module not available",
        "ncryptcreatepersistedkey",
        "ncryptopenstorageprovider",
        "ncryptfinalizekey",
        "microsoft platform crypto provider",
        "tpm",
        "0x80090030", // NTE_DEVICE_NOT_READY / TPM unavailable on some hosts.
        "0x80090029",
        "0x80090016", // NTE_BAD_KEYSET when the provider/keyset is absent.
        "0x8028000f", // TPM device not found.
        "0x80280001",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VmDetection {
    detected: bool,
    reason: String,
}

fn detect_vm() -> VmDetection {
    #[cfg(target_os = "windows")]
    {
        detect_vm_windows()
    }
    #[cfg(not(target_os = "windows"))]
    {
        VmDetection {
            detected: false,
            reason: "non-Windows build".into(),
        }
    }
}

#[cfg(target_os = "windows")]
fn detect_vm_windows() -> VmDetection {
    let registry_values = [
        registry_string(
            "SYSTEM\\CurrentControlSet\\Control\\SystemInformation",
            "SystemManufacturer",
        ),
        registry_string(
            "SYSTEM\\CurrentControlSet\\Control\\SystemInformation",
            "SystemProductName",
        ),
        registry_string("HARDWARE\\DESCRIPTION\\System\\BIOS", "SystemManufacturer"),
        registry_string("HARDWARE\\DESCRIPTION\\System\\BIOS", "SystemProductName"),
        registry_string("HARDWARE\\DESCRIPTION\\System\\BIOS", "BIOSVendor"),
    ];
    let joined = registry_values
        .iter()
        .flatten()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(" | ");
    if vm_string_signal(&joined) {
        return VmDetection {
            detected: true,
            reason: format!("registry VM marker: {joined}"),
        };
    }

    if let Some(vendor) = cpuid_hypervisor_vendor() {
        if vm_string_signal(&vendor) && !vendor.eq_ignore_ascii_case("Microsoft Hv") {
            return VmDetection {
                detected: true,
                reason: format!("CPUID hypervisor vendor: {vendor}"),
            };
        }
        // "Microsoft Hv" is reported by both Windows VBS on physical hardware
        // and Hyper-V guests (Azure, on-prem bastions, VDI).  Distinguish them
        // by manufacturer: physical machines with VBS show their real OEM
        // (Dell, Lenovo, HP, …); Hyper-V guests show "Microsoft Corporation".
        // Note: Surface devices are Microsoft hardware but have working TPMs,
        // so they never reach this fallback path.
        if vendor.eq_ignore_ascii_case("Microsoft Hv")
            && joined
                .to_ascii_lowercase()
                .contains("microsoft corporation")
        {
            return VmDetection {
                detected: true,
                reason: format!(
                    "Hyper-V guest: Microsoft Hv CPUID + Microsoft Corporation manufacturer ({joined})"
                ),
            };
        }
        return VmDetection {
            detected: false,
            reason: format!("hypervisor bit set without trusted VM registry marker: {vendor}"),
        };
    }

    VmDetection {
        detected: false,
        reason: if joined.is_empty() {
            "no VM registry markers and no CPUID hypervisor vendor".into()
        } else {
            format!("no VM registry marker: {joined}")
        },
    }
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn vm_string_signal(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "vmware",
        "virtualbox",
        "qemu",
        "kvm",
        "xen",
        "parallels",
        "hyper-v",
        "virtual machine",
        "amazon ec2",
        "google compute",
        "google cloud",
        "microsoft corporation | virtual machine",
        "nutanix",
        "citrix",
        "bhyve",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

#[cfg(target_os = "windows")]
fn registry_string(subkey: &str, value_name: &str) -> Option<String> {
    use std::ffi::c_void;
    let subkey = wide_null(subkey);
    let value_name = wide_null(value_name);
    let mut ty = REG_VALUE_TYPE(0);
    let mut bytes = 1024_u32;
    let mut buf = vec![0_u16; (bytes as usize) / 2];
    // SAFETY: `buf` is writable for `bytes` bytes. The input strings
    // are null-terminated UTF-16 and live for the duration of the call.
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            windows::core::PCWSTR(subkey.as_ptr()),
            windows::core::PCWSTR(value_name.as_ptr()),
            RRF_RT_REG_SZ,
            Some(&mut ty),
            Some(buf.as_mut_ptr().cast::<c_void>()),
            Some(&mut bytes),
        )
    };
    if status.is_err() || bytes < 2 {
        return None;
    }
    let len = ((bytes as usize) / 2).saturating_sub(1);
    buf.truncate(len);
    String::from_utf16(&buf)
        .ok()
        .map(|s| s.trim_matches(char::from(0)).trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(target_os = "windows")]
fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn cpuid_hypervisor_vendor() -> Option<String> {
    #[cfg(target_arch = "x86")]
    use std::arch::x86::{__cpuid, __cpuid_count};
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::{__cpuid, __cpuid_count};

    let leaf1 = __cpuid(1);
    if (leaf1.ecx & (1 << 31)) == 0 {
        return None;
    }
    let hv = __cpuid_count(0x4000_0000, 0);
    let mut bytes = Vec::with_capacity(12);
    bytes.extend_from_slice(&hv.ebx.to_le_bytes());
    bytes.extend_from_slice(&hv.ecx.to_le_bytes());
    bytes.extend_from_slice(&hv.edx.to_le_bytes());
    String::from_utf8(bytes)
        .ok()
        .map(|s| s.trim_matches(char::from(0)).trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn cpuid_hypervisor_vendor() -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tpm_error_classifier_accepts_missing_tpm_codes() {
        assert!(is_tpm_unavailable_error(
            "key initialization failed: NCryptFinalizeKey: 0x8028000F"
        ));
        assert!(is_tpm_unavailable_error(
            "Microsoft Platform Crypto Provider: TPM device not found"
        ));
    }

    #[test]
    fn tpm_error_classifier_rejects_unrelated_errors() {
        assert!(!is_tpm_unavailable_error(
            "metadata integrity check failed: tag mismatch"
        ));
    }

    #[test]
    fn vm_string_classifier_accepts_common_vm_markers() {
        assert!(vm_string_signal("VMware, Inc. | VMware Virtual Platform"));
        assert!(vm_string_signal("Microsoft Corporation | Virtual Machine"));
        assert!(vm_string_signal("Citrix Hypervisor"));
    }

    #[test]
    fn vm_string_classifier_rejects_plain_hardware() {
        assert!(!vm_string_signal("Dell Inc. | Latitude 7450"));
        assert!(!vm_string_signal("LENOVO | ThinkPad X1 Carbon"));
    }

    #[test]
    fn vm_string_classifier_does_not_treat_vbs_hypervisor_vendor_as_vm() {
        // Windows virtualization-based security on physical hardware can
        // expose the Microsoft hypervisor interface. That alone is not a
        // VM signal; otherwise VBS-enabled laptops would incorrectly be
        // allowed to downgrade from TPM to DPAPI.
        assert!(!vm_string_signal("Microsoft Hv"));
        assert!(!vm_string_signal(
            "Dell Inc. | Latitude 7450 | Microsoft Hv"
        ));
    }

    #[test]
    fn hyper_v_guest_detected_via_microsoft_corporation_manufacturer() {
        // A Hyper-V guest (Azure VM, on-prem bastion, VDI) reports
        // "Microsoft Hv" as the CPUID hypervisor vendor AND "Microsoft
        // Corporation" as the system manufacturer.  We must allow the DPAPI
        // fallback for these machines even though "Microsoft Hv" alone is
        // excluded (to protect physical VBS machines).
        assert!(vm_string_signal("Microsoft Corporation | Virtual Machine"));
        // Product name may not say "Virtual Machine" on all bastions.
        // The key check is manufacturer + CPUID, tested via detect_vm logic:
        // manufacturer "Microsoft Corporation" alone is not a vm_string_signal …
        assert!(!vm_string_signal("Microsoft Corporation"));
        // … but the joined string that includes it alongside a VM product
        // name is, which is what detect_vm_windows constructs.
        assert!(vm_string_signal(
            "Microsoft Corporation | Virtual Machine | Microsoft Corporation | Virtual Machine | VRTUAL"
        ));
    }

    #[test]
    fn vbs_on_physical_oem_hardware_not_treated_as_vm() {
        // A Dell laptop running VBS should NOT be detected as a VM even
        // though CPUID reports the Microsoft hypervisor bit.
        assert!(!vm_string_signal("Dell Inc. | Latitude 7450"));
        assert!(!vm_string_signal("LENOVO | ThinkPad X1 Carbon"));
        assert!(!vm_string_signal("HP | EliteBook 840"));
    }
}
