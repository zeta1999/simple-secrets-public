#!/usr/bin/env bash
#
# Local CI for simple-secrets (Linux + macOS).
#
# The host-native gates (format, lint, tests) are mandatory: any failure aborts
# the run. The mobile cross-compilation checks are best-effort smoke tests --
# they require an installed Rust target AND the corresponding platform toolchain
# (Android NDK / Xcode iOS SDK), neither of which is guaranteed on a dev box, so
# a missing toolchain is reported and skipped rather than failing CI.
set -euo pipefail

echo "Running CI for simple-secrets..."

echo "==> Checking formatting..."
cargo fmt -- --check

echo "==> Running clippy..."
cargo clippy --all-targets -- -D warnings

echo "==> Running tests..."
cargo test

# Returns 0 only if the rust target is installed.
target_installed() {
    rustup target list --installed | grep -qx "$1"
}

# Run `cargo check` for a cross target, but only if the host can actually link
# it. A failure here is reported as a warning and does NOT abort CI, because it
# usually means a missing SDK/NDK on this machine rather than broken code.
cross_check() {
    local label="$1" target="$2" tool="$3"
    echo "==> Checking ${label} target..."
    if ! target_installed "$target"; then
        echo "    Skipping ${label}: rust target '${target}' not installed."
        return 0
    fi
    if [ -n "$tool" ] && ! command -v "$tool" >/dev/null 2>&1; then
        echo "    Skipping ${label}: toolchain '${tool}' not found on PATH."
        return 0
    fi
    if cargo check --target "$target"; then
        echo "    ${label} check passed."
    else
        echo "    WARNING: ${label} cross-check failed (likely a missing SDK/NDK)." >&2
    fi
}

# iOS builds through the system clang shipped with Xcode's command line tools.
cross_check "iOS" "aarch64-apple-ios" ""
# Android needs the NDK's target clang for C dependencies.
cross_check "Android" "aarch64-linux-android" "aarch64-linux-android-clang"

# Lean formal model: a hard gate when the Lean toolchain is installed, skipped
# otherwise so the Rust CI still runs on machines without Lean.
echo "==> Building Lean model..."
if command -v lake >/dev/null 2>&1; then
    (cd lean && lake build)
    echo "    Lean model built."
else
    echo "    Skipping Lean model: 'lake' not found on PATH."
fi

echo "CI completed successfully!"
