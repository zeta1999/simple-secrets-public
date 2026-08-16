---
name: simple-secrets-integration
description: Guides an autonomous AI agent through the process of adding the `simple-secrets` post-quantum library to an external Rust, Android, or iOS codebase. Use this skill when asked to incorporate secret management, Shamir sharing, or ML-KEM secure pairing into another project.
---

# `simple-secrets` Agent Integration Guide

This skill provides step-by-step instructions for integrating the `simple-secrets` crate into an external project. Follow these steps meticulously to ensure correct linking and platform compatibility.

## Step 1: Rust Workspace Integration

If integrating into a standard Rust application:

1. Locate the target `Cargo.toml`.
2. Inject the path dependency linking to the local `simple-secrets` folder:
   ```toml
   [dependencies]
   simple-secrets = { path = "/path/to/simple-secrets" }
   ```
3. In the application source, import the `SecretManager` via `use simple_secrets::core::manager::SecretManager;`.

## Step 2: Launching the Embedded TUI

If the user requests visual components, you can bypass manual window logic and instantly mount the `simple-secrets` TUI.
1. Invoke the main `launch_tui()` hook inside the target codebase's main thread:
   ```rust
   if let Err(e) = simple_secrets::ui::launch_tui() {
       eprintln!("TUI Error: {}", e);
   }
   ```
   > **Note**: This will seize control of standard I/O (stdout/stdin) utilizing `crossterm` and `ratatui`, ensure no other async thread attempts to write to stdout simultaneously.

## Step 3: FFI Compilation (Mobile Targets)

If the target project is an iOS or Android app, you must compile the `simple-secrets` crate natively.

**For Android**:
1. Run `cargo build --target aarch64-linux-android --release` within the `simple-secrets` repository.
2. Locate the resulting `libsimple_secrets.so`.
3. Move the `.so` file into the Android project's `app/src/main/jniLibs/arm64-v8a/` directory.
4. Implement a Java/Kotlin wrapper invoking `Java_com_simplesecrets_Library_init`.

**For iOS**:
1. Run `cargo build --target aarch64-apple-ios --release`.
2. Provide the `libsimple_secrets.a` or `.dylib` to the Xcode project configuration.
3. Call `simple_secrets_init()` inside `AppDelegate.swift` or an equivalent startup method via a Bridging Header.

## Step 4: Verification
Always compile the integrated target using `cargo check` (for Rust binaries) or the respective `ci.sh` scripts to guarantee there are no traits or platform flag misconfigurations.
