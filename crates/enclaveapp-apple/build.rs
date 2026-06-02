// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Build script for enclaveapp-apple.
//! Compiles the Swift CryptoKit bridge into a static library and links it.

// Build scripts are expected to panic on failure — that is the standard Cargo
// convention for communicating build errors.
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::match_same_arms,
    clippy::print_stdout
)]

use std::env;
use std::path::PathBuf;
use std::process::Command;

/// Absolute path to the system `xcrun` tool.
///
/// `xcrun` is part of Xcode Command Line Tools and lives at
/// `/usr/bin/xcrun` on all macOS installations. Invoking it by
/// absolute path (rather than bare `xcrun`, which walks `$PATH`)
/// removes a PATH-hijack vector from the build-machine trust
/// boundary — a shadowed `xcrun` earlier on `$PATH` can no longer
/// substitute a poisoned swiftc / ar into the static bridge object
/// that ends up linked into the binary. See
/// THREAT_MODEL.md "Build-time trust".
const XCRUN: &str = "/usr/bin/xcrun";

/// Resolve a toolchain tool by asking `xcrun --find`. The returned
/// absolute path bypasses `$PATH` and points at the tool inside the
/// active Xcode developer directory (`xcode-select -p`), which is a
/// system-managed path.
fn xcrun_find(tool: &str) -> PathBuf {
    let output = Command::new(XCRUN)
        .args(["--find", tool])
        .output()
        .unwrap_or_else(|e| panic!("failed to run {XCRUN} --find {tool}: {e}"));
    if !output.status.success() {
        panic!(
            "xcrun --find {tool} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let path = String::from_utf8(output.stdout)
        .unwrap_or_else(|e| panic!("invalid xcrun output for {tool}: {e}"))
        .trim()
        .to_string();
    PathBuf::from(path)
}

fn main() {
    // Only build Swift bridge on macOS
    if env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() != "macos" {
        return;
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let swift_src = "swift/bridge.swift";
    let lib_path = out_dir.join("libenclaveapp_se_bridge.a");

    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| "arm64".into());
    let swift_target = match target_arch.as_str() {
        "aarch64" => "arm64-apple-macos14.0",
        "x86_64" => "x86_64-apple-macos14.0",
        _ => "arm64-apple-macos14.0",
    };

    // Resolve all toolchain executables via the absolute `/usr/bin/xcrun`
    // rather than walking `$PATH`. The resolved `swiftc` and `ar` land
    // inside the active Xcode developer directory.
    let sdk_output = Command::new(XCRUN)
        .args(["--show-sdk-path", "--sdk", "macosx"])
        .output()
        .unwrap_or_else(|e| panic!("failed to run {XCRUN} --show-sdk-path: {e}"));
    let sdk_path = String::from_utf8(sdk_output.stdout)
        .unwrap_or_else(|e| panic!("invalid xcrun output: {e}"))
        .trim()
        .to_string();

    let swiftc = xcrun_find("swiftc");
    let ar = xcrun_find("ar");

    // Compile Swift to object file
    let obj_path = out_dir.join("enclaveapp_se_bridge.o");
    let status = Command::new(&swiftc)
        .args([
            "-emit-object",
            "-target",
            swift_target,
            "-sdk",
            &sdk_path,
            "-O",
            "-parse-as-library",
            "-o",
        ])
        .arg(&obj_path)
        .arg(swift_src)
        .status()
        .unwrap_or_else(|e| panic!("failed to run {}: {e}", swiftc.display()));

    if !status.success() {
        panic!("swiftc compilation failed");
    }

    // Create static library from object file
    let status = Command::new(&ar)
        .args(["rcs"])
        .arg(&lib_path)
        .arg(&obj_path)
        .status()
        .unwrap_or_else(|e| panic!("failed to run {}: {e}", ar.display()));

    if !status.success() {
        panic!("ar failed to create static library");
    }

    // Find the Swift runtime library path for linking
    let swift_lib_dir = format!("{sdk_path}/usr/lib/swift");

    // Toolchain's swift lib dir — derived from the resolved swiftc path,
    // which is itself a sibling of the toolchain's `lib/swift/macosx`.
    let toolchain_lib = swiftc
        .parent()
        .and_then(|p| p.parent())
        .unwrap_or_else(|| {
            panic!(
                "unexpected swiftc path structure (expected .../bin/swiftc): {}",
                swiftc.display()
            )
        })
        .join("lib")
        .join("swift")
        .join("macosx");

    // Link directives
    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=enclaveapp_se_bridge");
    println!("cargo:rustc-link-search=native={swift_lib_dir}");
    println!("cargo:rustc-link-search=native={}", toolchain_lib.display());
    println!("cargo:rustc-link-lib=dylib=swiftCore");
    println!("cargo:rustc-link-lib=dylib=swiftFoundation");
    println!("cargo:rustc-link-lib=framework=CryptoKit");
    println!("cargo:rustc-link-lib=framework=Security");
    println!("cargo:rustc-link-lib=framework=LocalAuthentication");

    println!("cargo:rerun-if-changed={swift_src}");
    println!("cargo:rerun-if-changed=build.rs");
}
