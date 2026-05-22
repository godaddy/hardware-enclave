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

/// Raw system information gathered during VM detection.
/// Exposed for diagnostic/audit logging by consuming applications.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmDiagnostics {
    pub vm_detected: bool,
    pub detection_reason: String,
    /// Raw registry values read during detection (label, value or None if absent).
    pub registry_values: Vec<(String, Option<String>)>,
    /// CPUID hypervisor vendor string, if the hypervisor bit is set.
    pub cpuid_hypervisor_vendor: Option<String>,
    /// Whether the Hyper-V guest integration services registry key exists.
    pub hyperv_guest_integration: bool,
    /// Architecture of the running process.
    pub arch: &'static str,
}

/// Return whether a failed TPM initialization may fall back to DPAPI.
pub fn should_use_dpapi_after_tpm_failure(error: &str) -> FallbackDecision {
    let tpm_failure = is_tpm_unavailable_error(error);
    let diag = collect_vm_diagnostics();
    let allowed = tpm_failure && diag.vm_detected;
    let reason = match (allowed, tpm_failure, diag.vm_detected) {
        (true, _, _) => format!("TPM unavailable and VM detected: {}", diag.detection_reason),
        (false, false, _) => "TPM failure did not look like missing/unusable TPM hardware".into(),
        (false, true, false) => {
            format!(
                "TPM unavailable but VM not detected: {}",
                diag.detection_reason
            )
        }
        (false, true, true) => "fallback denied".into(),
    };
    FallbackDecision {
        allowed,
        tpm_failure,
        vm_detected: diag.vm_detected,
        reason,
    }
}

/// Collect VM detection diagnostics without making a fallback decision.
/// Returns raw system information for diagnostic logging by consuming applications.
pub fn collect_vm_diagnostics() -> VmDiagnostics {
    #[cfg(target_os = "windows")]
    {
        collect_vm_diagnostics_windows()
    }
    #[cfg(not(target_os = "windows"))]
    {
        VmDiagnostics {
            vm_detected: false,
            detection_reason: "non-Windows build".into(),
            registry_values: vec![],
            cpuid_hypervisor_vendor: None,
            hyperv_guest_integration: false,
            arch: std::env::consts::ARCH,
        }
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

#[cfg(target_os = "windows")]
fn collect_vm_diagnostics_windows() -> VmDiagnostics {
    let registry_checks: Vec<(&str, &str, &str)> = vec![
        (
            "SystemInformation\\SystemManufacturer",
            "SYSTEM\\CurrentControlSet\\Control\\SystemInformation",
            "SystemManufacturer",
        ),
        (
            "SystemInformation\\SystemProductName",
            "SYSTEM\\CurrentControlSet\\Control\\SystemInformation",
            "SystemProductName",
        ),
        (
            "BIOS\\SystemManufacturer",
            "HARDWARE\\DESCRIPTION\\System\\BIOS",
            "SystemManufacturer",
        ),
        (
            "BIOS\\SystemProductName",
            "HARDWARE\\DESCRIPTION\\System\\BIOS",
            "SystemProductName",
        ),
        (
            "BIOS\\BIOSVendor",
            "HARDWARE\\DESCRIPTION\\System\\BIOS",
            "BIOSVendor",
        ),
        (
            "BIOS\\BIOSVersion",
            "HARDWARE\\DESCRIPTION\\System\\BIOS",
            "BIOSVersion",
        ),
        (
            "BIOS\\SystemVersion",
            "HARDWARE\\DESCRIPTION\\System\\BIOS",
            "SystemVersion",
        ),
        (
            "BIOS\\BaseBoardManufacturer",
            "HARDWARE\\DESCRIPTION\\System\\BIOS",
            "BaseBoardManufacturer",
        ),
        (
            "BIOS\\BaseBoardProduct",
            "HARDWARE\\DESCRIPTION\\System\\BIOS",
            "BaseBoardProduct",
        ),
        (
            "Disk\\Enum\\0",
            "SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum",
            "0",
        ),
        (
            "CentralProcessor\\ProcessorNameString",
            "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
            "ProcessorNameString",
        ),
        (
            "CentralProcessor\\VendorIdentifier",
            "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
            "VendorIdentifier",
        ),
    ];

    let registry_values: Vec<(String, Option<String>)> = registry_checks
        .iter()
        .map(|(label, subkey, value_name)| (label.to_string(), registry_string(subkey, value_name)))
        .collect();

    let hyperv_guest = hyperv_guest_parameters_exist();

    let cpuid_vendor = cpuid_hypervisor_vendor();

    // Build the joined string from identity-relevant registry values for vm_string_signal.
    // Use only the first 9 values (manufacturer/product/bios strings, not disk/processor).
    let identity_joined = registry_values
        .iter()
        .take(9)
        .filter_map(|(_, v)| v.as_deref())
        .collect::<Vec<_>>()
        .join(" | ");

    let disk_device = registry_values
        .iter()
        .find(|(label, _)| label == "Disk\\Enum\\0")
        .and_then(|(_, v)| v.as_deref());

    // --- Detection logic ---

    // 1. Registry identity strings (manufacturer, product, BIOS, baseboard)
    if vm_string_signal(&identity_joined) {
        return VmDiagnostics {
            vm_detected: true,
            detection_reason: format!("registry VM marker: {identity_joined}"),
            registry_values,
            cpuid_hypervisor_vendor: cpuid_vendor,
            hyperv_guest_integration: hyperv_guest,
            arch: std::env::consts::ARCH,
        };
    }

    // 2. Disk device name (virtual disk controllers)
    if let Some(disk) = disk_device {
        if vm_string_signal(disk) {
            return VmDiagnostics {
                vm_detected: true,
                detection_reason: format!("virtual disk device: {disk}"),
                registry_values,
                cpuid_hypervisor_vendor: cpuid_vendor,
                hyperv_guest_integration: hyperv_guest,
                arch: std::env::consts::ARCH,
            };
        }
    }

    // 3. CPUID hypervisor vendor
    if let Some(ref vendor) = cpuid_vendor {
        if vm_string_signal(vendor) && !vendor.eq_ignore_ascii_case("Microsoft Hv") {
            return VmDiagnostics {
                vm_detected: true,
                detection_reason: format!("CPUID hypervisor vendor: {vendor}"),
                registry_values,
                cpuid_hypervisor_vendor: cpuid_vendor,
                hyperv_guest_integration: hyperv_guest,
                arch: std::env::consts::ARCH,
            };
        }
        // "Microsoft Hv" — reported by both VBS on physical hardware and Hyper-V guests.
        if vendor.eq_ignore_ascii_case("Microsoft Hv") {
            // 4. Microsoft Hv + "Microsoft Corporation" manufacturer = Hyper-V guest
            if identity_joined
                .to_ascii_lowercase()
                .contains("microsoft corporation")
            {
                return VmDiagnostics {
                    vm_detected: true,
                    detection_reason: format!(
                        "Hyper-V guest: Microsoft Hv CPUID + Microsoft Corporation manufacturer ({identity_joined})"
                    ),
                    registry_values,
                    cpuid_hypervisor_vendor: cpuid_vendor,
                    hyperv_guest_integration: hyperv_guest,
                    arch: std::env::consts::ARCH,
                };
            }
            // 5. Microsoft Hv + Hyper-V guest integration services = VDI on Hyper-V
            //    (catches CyberArk, Citrix, etc. with non-standard manufacturer)
            if hyperv_guest {
                return VmDiagnostics {
                    vm_detected: true,
                    detection_reason: format!(
                        "Hyper-V VDI: Microsoft Hv CPUID + guest integration services present ({identity_joined})"
                    ),
                    registry_values,
                    cpuid_hypervisor_vendor: cpuid_vendor,
                    hyperv_guest_integration: hyperv_guest,
                    arch: std::env::consts::ARCH,
                };
            }
            return VmDiagnostics {
                vm_detected: false,
                detection_reason: format!(
                    "hypervisor bit set without VM indicators: {vendor} (manufacturer: {identity_joined})"
                ),
                registry_values,
                cpuid_hypervisor_vendor: cpuid_vendor,
                hyperv_guest_integration: hyperv_guest,
                arch: std::env::consts::ARCH,
            };
        }
    }

    // 6. No CPUID hypervisor, but check Hyper-V guest integration (ARM64 path)
    if hyperv_guest {
        return VmDiagnostics {
            vm_detected: true,
            detection_reason: format!(
                "Hyper-V guest integration services present without CPUID hypervisor ({identity_joined})"
            ),
            registry_values,
            cpuid_hypervisor_vendor: cpuid_vendor,
            hyperv_guest_integration: hyperv_guest,
            arch: std::env::consts::ARCH,
        };
    }

    VmDiagnostics {
        vm_detected: false,
        detection_reason: if identity_joined.is_empty() {
            "no VM registry markers, no CPUID hypervisor vendor, no Hyper-V guest integration"
                .into()
        } else {
            format!("no VM indicators detected: {identity_joined}")
        },
        registry_values,
        cpuid_hypervisor_vendor: cpuid_vendor,
        hyperv_guest_integration: hyperv_guest,
        arch: std::env::consts::ARCH,
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
        "cyberark",
        "seabios",
        "proxmox",
        "openstack",
        "oracle vm",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

/// Check whether the Hyper-V guest integration services registry key exists.
/// This key is present on all Hyper-V guests (Azure VMs, on-prem VDI, etc.)
/// but NOT on physical machines running VBS.
#[cfg(target_os = "windows")]
fn hyperv_guest_parameters_exist() -> bool {
    use windows::Win32::System::Registry::{RegCloseKey, RegOpenKeyExW, HKEY, KEY_READ};

    let subkey = wide_null("SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters");
    let mut hkey = HKEY::default();
    // SAFETY: Standard Win32 registry probe. We only open for read and
    // immediately close. The wide_null string is kept alive for the call.
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            windows::core::PCWSTR(subkey.as_ptr()),
            Some(0),
            KEY_READ,
            &mut hkey,
        )
    };
    if status.is_ok() {
        unsafe {
            let _ = RegCloseKey(hkey);
        }
        true
    } else {
        false
    }
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

    #[test]
    fn vm_string_classifier_accepts_new_signals() {
        assert!(vm_string_signal("CyberArk Ltd | CyberArk PSM"));
        assert!(vm_string_signal("SeaBIOS | pc-q35-8.1"));
        assert!(vm_string_signal("Proxmox Virtual Environment"));
        assert!(vm_string_signal("OpenStack Foundation"));
        assert!(vm_string_signal("Oracle VM VirtualBox"));
    }

    #[test]
    fn vm_string_classifier_rejects_raid_virtual_disk() {
        // RAID controllers expose "Virtual Disk" — must NOT match.
        assert!(!vm_string_signal("DELL | VIRTUAL DISK"));
        assert!(!vm_string_signal("HP SmartArray Virtual Disk"));
    }

    #[test]
    fn vm_string_classifier_rejects_seagate() {
        // "seabios" must not match "Seagate" (different prefix)
        assert!(!vm_string_signal("Seagate Barracuda"));
    }

    #[test]
    fn collect_vm_diagnostics_returns_valid_struct() {
        let diag = collect_vm_diagnostics();
        assert!(!diag.detection_reason.is_empty());
        assert!(!diag.arch.is_empty());
    }
}
