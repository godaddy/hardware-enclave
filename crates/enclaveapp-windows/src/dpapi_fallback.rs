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
    /// VM guest services found in the Windows service registry.
    pub guest_services_found: Vec<String>,
    /// Display adapter description from the GPU class registry.
    pub display_adapter: Option<String>,
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
            guest_services_found: vec![],
            display_adapter: None,
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
    let guest_services = detect_guest_services();
    let display_adapter = detect_display_adapter();

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

    let make_result = |vm_detected: bool, detection_reason: String| VmDiagnostics {
        vm_detected,
        detection_reason,
        registry_values: registry_values.clone(),
        cpuid_hypervisor_vendor: cpuid_vendor.clone(),
        hyperv_guest_integration: hyperv_guest,
        guest_services_found: guest_services.clone(),
        display_adapter: display_adapter.clone(),
        arch: std::env::consts::ARCH,
    };

    // --- Detection logic ---

    // 1. Registry identity strings (manufacturer, product, BIOS, baseboard)
    if vm_string_signal(&identity_joined) {
        return make_result(true, format!("registry VM marker: {identity_joined}"));
    }

    // 2. Disk device name (virtual disk controllers)
    if let Some(disk) = disk_device {
        if vm_string_signal(disk) {
            return make_result(true, format!("virtual disk device: {disk}"));
        }
    }

    // 3. VM guest services present (vmicheartbeat, VBoxGuest, vmci, etc.)
    if !guest_services.is_empty() {
        let svc_list = guest_services.join(", ");
        return make_result(true, format!("VM guest services installed: {svc_list}"));
    }

    // 4. Virtual display adapter
    if let Some(ref adapter) = display_adapter {
        if vm_display_signal(adapter) {
            return make_result(true, format!("virtual display adapter: {adapter}"));
        }
    }

    // 5. CPUID hypervisor vendor
    if let Some(ref vendor) = cpuid_vendor {
        if vm_string_signal(vendor) && !vendor.eq_ignore_ascii_case("Microsoft Hv") {
            return make_result(true, format!("CPUID hypervisor vendor: {vendor}"));
        }
        // "Microsoft Hv" — reported by both VBS on physical hardware and Hyper-V guests.
        if vendor.eq_ignore_ascii_case("Microsoft Hv") {
            // 6. Microsoft Hv + "Microsoft Corporation" manufacturer = Hyper-V guest
            if identity_joined
                .to_ascii_lowercase()
                .contains("microsoft corporation")
            {
                return make_result(
                    true,
                    format!(
                        "Hyper-V guest: Microsoft Hv CPUID + Microsoft Corporation manufacturer ({identity_joined})"
                    ),
                );
            }
            // 7. Microsoft Hv + Hyper-V guest integration services = VDI on Hyper-V
            if hyperv_guest {
                return make_result(
                    true,
                    format!(
                        "Hyper-V VDI: Microsoft Hv CPUID + guest integration services present ({identity_joined})"
                    ),
                );
            }
            return make_result(
                false,
                format!(
                    "hypervisor bit set without VM indicators: {vendor} (manufacturer: {identity_joined})"
                ),
            );
        }
    }

    // 8. No CPUID hypervisor, but check Hyper-V guest integration (ARM64 path)
    if hyperv_guest {
        return make_result(
            true,
            format!(
                "Hyper-V guest integration services present without CPUID hypervisor ({identity_joined})"
            ),
        );
    }

    make_result(
        false,
        if identity_joined.is_empty() {
            "no VM indicators detected (no registry markers, no CPUID hypervisor, no guest services, no virtual display)".into()
        } else {
            format!("no VM indicators detected: {identity_joined}")
        },
    )
}

/// Check for known VM guest service drivers in the Windows service registry.
/// These services are only installed by hypervisor guest tools — never on bare metal.
#[cfg(target_os = "windows")]
fn detect_guest_services() -> Vec<String> {
    use windows::Win32::System::Registry::{RegCloseKey, RegOpenKeyExW, HKEY, KEY_READ};

    const VM_SERVICES: &[(&str, &str)] = &[
        // Hyper-V guest integration
        ("vmicheartbeat", "Hyper-V Heartbeat"),
        ("vmicshutdown", "Hyper-V Shutdown"),
        ("vmickvpexchange", "Hyper-V KVP Exchange"),
        ("vmicguestinterface", "Hyper-V Guest Service Interface"),
        ("vmicvss", "Hyper-V VSS"),
        ("vmictimesync", "Hyper-V Time Sync"),
        // VMware Tools
        ("vmci", "VMware VMCI"),
        ("vmhgfs", "VMware Host-Guest Filesystem"),
        ("vmxnet", "VMware vmxnet"),
        ("vmxnet3", "VMware vmxnet3"),
        ("vmvss", "VMware VSS"),
        ("VMTools", "VMware Tools"),
        // VirtualBox Guest Additions
        ("VBoxGuest", "VirtualBox Guest"),
        ("VBoxSF", "VirtualBox Shared Folders"),
        ("VBoxMouse", "VirtualBox Mouse"),
        ("VBoxVideo", "VirtualBox Video"),
        // KVM/virtio (Red Hat)
        ("vioscsi", "virtio SCSI"),
        ("viostor", "virtio Storage"),
        ("netkvm", "virtio Network"),
        ("vioinput", "virtio Input"),
        ("vioser", "virtio Serial"),
        ("balloon", "virtio Balloon"),
        // QEMU Guest Agent
        ("QEMU-GA", "QEMU Guest Agent"),
        ("qemu-ga", "QEMU Guest Agent"),
        // Parallels
        ("prl_strg", "Parallels Storage"),
        ("prl_tg", "Parallels Tools Gate"),
        ("prl_eth", "Parallels Network"),
        // Xen
        ("xenevtchn", "Xen Event Channel"),
        ("xenvbd", "Xen Block Device"),
        ("xennet", "Xen Network"),
        ("xenvif", "Xen Virtual Interface"),
    ];

    let mut found = Vec::new();
    for (svc_name, label) in VM_SERVICES {
        let subkey = format!("SYSTEM\\CurrentControlSet\\Services\\{svc_name}");
        let subkey_wide = wide_null(&subkey);
        let mut hkey = HKEY::default();
        // SAFETY: Standard registry probe — open for read and immediately close.
        let status = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                windows::core::PCWSTR(subkey_wide.as_ptr()),
                Some(0),
                KEY_READ,
                &mut hkey,
            )
        };
        if status.is_ok() {
            unsafe {
                let _ = RegCloseKey(hkey);
            }
            found.push(format!("{svc_name} ({label})"));
        }
    }
    found
}

/// Read the primary display adapter description from the GPU class registry.
#[cfg(target_os = "windows")]
fn detect_display_adapter() -> Option<String> {
    // The display adapter class GUID is {4d36e968-e325-11ce-bfc1-08002be10318}.
    // Subkey \0000 is the primary adapter.
    registry_string(
        "SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000",
        "DriverDesc",
    )
}

/// Check if a display adapter description indicates a virtual GPU.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn vm_display_signal(adapter: &str) -> bool {
    let lower = adapter.to_ascii_lowercase();
    [
        "microsoft hyper-v video",
        "vmware svga",
        "vmware soda",
        "virtualbox graphics",
        "red hat qxl",
        "virtio gpu",
        "citrix indirect display",
        "parallels display",
        "qxl",
        "xen display",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
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
    fn vm_display_signal_detects_virtual_adapters() {
        assert!(vm_display_signal("Microsoft Hyper-V Video"));
        assert!(vm_display_signal("VMware SVGA 3D"));
        assert!(vm_display_signal("VirtualBox Graphics Adapter"));
        assert!(vm_display_signal("Red Hat QXL controller"));
        assert!(vm_display_signal("Citrix Indirect Display Adapter"));
    }

    #[test]
    fn vm_display_signal_rejects_real_gpus() {
        assert!(!vm_display_signal("NVIDIA GeForce RTX 4090"));
        assert!(!vm_display_signal("AMD Radeon RX 7900 XTX"));
        assert!(!vm_display_signal("Intel UHD Graphics 770"));
        assert!(!vm_display_signal("Intel Iris Xe Graphics"));
    }

    #[test]
    fn collect_vm_diagnostics_returns_valid_struct() {
        let diag = collect_vm_diagnostics();
        assert!(!diag.detection_reason.is_empty());
        assert!(!diag.arch.is_empty());
    }
}
