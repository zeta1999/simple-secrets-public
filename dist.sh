#!/usr/bin/env bash
#
# Binary distribution builder for simple-secrets (Linux + macOS).
#
# Produces a self-contained release tarball under dist/ containing the
# optimized binary plus the end-user documentation, with a SHA-256 checksum
# for integrity verification. Mirrors the host-portable style of ci.sh: no
# external tools beyond cargo, rustc, tar, and the platform's sha256 utility.
#
# Usage:
#   ./dist.sh                 # build for the host target
#   ./dist.sh <target-triple> # cross-build (target must be installed via rustup)
set -euo pipefail

cd "$(dirname "$0")"

# ── Resolve version and target ───────────────────────────────────
# Version comes from the [package] section of Cargo.toml (first match).
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1)"
if [ -z "$VERSION" ]; then
    echo "dist: could not determine version from Cargo.toml" >&2
    exit 1
fi

# Target defaults to the host triple reported by rustc.
HOST_TARGET="$(rustc -vV | sed -n 's/^host: //p')"
TARGET="${1:-$HOST_TARGET}"

BIN_NAME="simple-secrets"
PKG_NAME="${BIN_NAME}-${VERSION}-${TARGET}"
STAGE_DIR="dist/${PKG_NAME}"

echo "==> Building ${BIN_NAME} ${VERSION} for ${TARGET} (release)..."
CARGO_ARGS=(build --release --bin "$BIN_NAME")
if [ "$TARGET" != "$HOST_TARGET" ]; then
    if ! rustup target list --installed | grep -qx "$TARGET"; then
        echo "dist: rust target '${TARGET}' is not installed (rustup target add ${TARGET})" >&2
        exit 1
    fi
    CARGO_ARGS+=(--target "$TARGET")
    BIN_PATH="target/${TARGET}/release/${BIN_NAME}"
else
    BIN_PATH="target/release/${BIN_NAME}"
fi
cargo "${CARGO_ARGS[@]}"

# ── Stage the bundle ─────────────────────────────────────────────
echo "==> Staging bundle in ${STAGE_DIR}..."
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR"
cp "$BIN_PATH" "$STAGE_DIR/"

# Always ship the user manual; ship any other top-level docs that exist.
cp USER_MANUAL.md "$STAGE_DIR/"
for doc in README.md LICENSE LICENSE.md SPECS.md; do
    [ -f "$doc" ] && cp "$doc" "$STAGE_DIR/"
done

# ── Archive + checksum ───────────────────────────────────────────
ARCHIVE="dist/${PKG_NAME}.tar.gz"
echo "==> Creating ${ARCHIVE}..."
tar -czf "$ARCHIVE" -C dist "$PKG_NAME"

echo "==> Writing checksum..."
if command -v sha256sum >/dev/null 2>&1; then
    (cd dist && sha256sum "${PKG_NAME}.tar.gz" > "${PKG_NAME}.tar.gz.sha256")
elif command -v shasum >/dev/null 2>&1; then
    (cd dist && shasum -a 256 "${PKG_NAME}.tar.gz" > "${PKG_NAME}.tar.gz.sha256")
else
    echo "    WARNING: no sha256 utility found; skipping checksum." >&2
fi

echo "dist: done -> ${ARCHIVE}"
