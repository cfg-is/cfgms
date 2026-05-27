#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jordan Ritz
#
# build-pkg.sh — Build a macOS .pkg installer for cfgms-steward.
#
# Prerequisites:
#   - Go toolchain (for building the binary when --binary-path is not supplied)
#   - Xcode Command Line Tools (pkgbuild + productbuild, always present on macOS)
#   - xcrun notarytool (Xcode 13+, for notarization)
#
# Code signing (optional):
#   Set APPLE_SIGNING_IDENTITY to a Developer ID Installer certificate name
#   (e.g. "Developer ID Installer: ACME Corp (XXXXXXXXXX)") to sign the pkg.
#   Without it the pkg is produced unsigned and a warning is printed.
#
# Notarization (optional):
#   Set APPLE_NOTARIZATION_PROFILE to a keychain profile created with:
#     xcrun notarytool store-credentials <profile-name> --apple-id ... --team-id ...
#   Notarization is skipped when the variable is absent or empty.
#
# Usage examples:
#   # Build amd64 pkg:
#   bash build/darwin/build-pkg.sh --arch amd64 --version v1.0.0
#
#   # Build arm64 pkg with signing:
#   APPLE_SIGNING_IDENTITY="Developer ID Installer: Acme (XXXXXXXXXX)" \
#     bash build/darwin/build-pkg.sh --arch arm64 --version v1.0.0
#
#   # Use a pre-built binary:
#   bash build/darwin/build-pkg.sh \
#     --arch amd64 \
#     --version v1.0.0 \
#     --binary-path ./bin/cfgms-steward-darwin-amd64

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# ── Defaults ──────────────────────────────────────────────────────────────────

ARCH="amd64"
VERSION="0.0.0"
BINARY_PATH=""
CONTROLLER_URL=""

# ── Argument parsing ──────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        --arch)          ARCH="$2";           shift 2 ;;
        --version)       VERSION="$2";        shift 2 ;;
        --binary-path)   BINARY_PATH="$2";    shift 2 ;;
        --controller-url) CONTROLLER_URL="$2"; shift 2 ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

# Strip leading 'v' from version for pkgbuild (requires N.N.N format).
PKG_VERSION="${VERSION#v}"
if ! [[ "$PKG_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9] ]]; then
    PKG_VERSION="0.0.0"
fi

echo "=== CFGMS Steward macOS .pkg Build ==="
echo "Version:        $VERSION"
echo "Pkg version:    $PKG_VERSION"
echo "ControllerURL:  ${CONTROLLER_URL:-(not set — generic build)}"
echo "Arch:           $ARCH"

# ── Step 1: Build the binary (when not pre-supplied) ─────────────────────────

if [[ -z "$BINARY_PATH" ]]; then
    echo ""
    echo "Building cfgms-steward binary for darwin/$ARCH..."

    BINARY_NAME="cfgms-steward-darwin-$ARCH"
    BINARY_PATH="$REPO_ROOT/bin/$BINARY_NAME"
    mkdir -p "$(dirname "$BINARY_PATH")"

    VERSION_FLAG="-X github.com/cfgis/cfgms/pkg/version.Version=$VERSION"
    if [[ -n "$CONTROLLER_URL" ]]; then
        LD_FLAGS="-s -w -X main.ControllerURL=$CONTROLLER_URL $VERSION_FLAG"
    else
        LD_FLAGS="-s -w $VERSION_FLAG"
    fi

    GOOS=darwin GOARCH="$ARCH" CGO_ENABLED=0 go build \
        -trimpath \
        -ldflags "$LD_FLAGS" \
        -o "$BINARY_PATH" \
        "$REPO_ROOT/cmd/steward"

    echo "  Binary: $BINARY_PATH"
else
    echo "Using pre-built binary: $BINARY_PATH"
    if [[ ! -f "$BINARY_PATH" ]]; then
        echo "ERROR: Binary not found: $BINARY_PATH" >&2
        exit 1
    fi
fi

# ── Step 2: Assemble the package payload ──────────────────────────────────────
# pkgbuild expects a directory tree that mirrors the target filesystem.

echo ""
echo "Assembling package payload..."

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

PAYLOAD_DIR="$WORK_DIR/payload"
SCRIPTS_DIR="$WORK_DIR/scripts"
mkdir -p "$PAYLOAD_DIR/usr/local/bin"
mkdir -p "$SCRIPTS_DIR"

# Install the binary into the payload tree.
cp "$BINARY_PATH" "$PAYLOAD_DIR/usr/local/bin/cfgms-steward"
chmod 755 "$PAYLOAD_DIR/usr/local/bin/cfgms-steward"

# Copy the postinstall script.
cp "$SCRIPT_DIR/scripts/postinstall" "$SCRIPTS_DIR/postinstall"
chmod 755 "$SCRIPTS_DIR/postinstall"

echo "  Payload: $PAYLOAD_DIR/usr/local/bin/cfgms-steward"
echo "  Scripts: $SCRIPTS_DIR/postinstall"

# ── Step 3: Build the component pkg with pkgbuild ─────────────────────────────

COMPONENT_PKG="$WORK_DIR/cfgms-steward.pkg"
OUTPUT_PKG="$REPO_ROOT/bin/cfgms-steward-darwin-$ARCH.pkg"
mkdir -p "$REPO_ROOT/bin"

echo ""
echo "Building component pkg..."

pkgbuild \
    --root "$PAYLOAD_DIR" \
    --scripts "$SCRIPTS_DIR" \
    --identifier "com.cfgms.steward" \
    --version "$PKG_VERSION" \
    --install-location "/" \
    "$COMPONENT_PKG"

echo "  Component pkg: $COMPONENT_PKG"

# ── Step 4: Wrap in a distribution pkg with productbuild ─────────────────────

echo ""
echo "Building distribution pkg..."

productbuild \
    --distribution "$SCRIPT_DIR/Distribution.xml" \
    --package-path "$WORK_DIR" \
    --version "$PKG_VERSION" \
    "$OUTPUT_PKG"

echo "  Distribution pkg: $OUTPUT_PKG"

# ── Step 5: Code signing (optional) ──────────────────────────────────────────

if [[ -n "${APPLE_SIGNING_IDENTITY:-}" ]]; then
    echo ""
    echo "Signing pkg with identity: $APPLE_SIGNING_IDENTITY"

    SIGNED_PKG="$WORK_DIR/cfgms-steward-darwin-$ARCH-signed.pkg"
    productsign \
        --sign "$APPLE_SIGNING_IDENTITY" \
        "$OUTPUT_PKG" \
        "$SIGNED_PKG"

    mv "$SIGNED_PKG" "$OUTPUT_PKG"
    echo "  Pkg signed."
else
    echo ""
    echo "WARNING: APPLE_SIGNING_IDENTITY not set — pkg is unsigned." >&2
    echo "         macOS Gatekeeper may block unsigned packages on non-MDM endpoints." >&2
    echo "         For production: set APPLE_SIGNING_IDENTITY to your Developer ID Installer certificate." >&2
fi

# ── Step 6: Notarization (optional) ──────────────────────────────────────────

if [[ -n "${APPLE_NOTARIZATION_PROFILE:-}" ]]; then
    echo ""
    echo "Submitting for notarization (profile: $APPLE_NOTARIZATION_PROFILE)..."

    xcrun notarytool submit "$OUTPUT_PKG" \
        --keychain-profile "$APPLE_NOTARIZATION_PROFILE" \
        --wait

    xcrun stapler staple "$OUTPUT_PKG"
    echo "  Pkg notarized and stapled."
else
    echo ""
    echo "WARNING: APPLE_NOTARIZATION_PROFILE not set — skipping notarization." >&2
    echo "         Notarized packages are required for distribution outside MDM on macOS 10.15+." >&2
fi

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "=== Build Complete ==="
echo "pkg: $OUTPUT_PKG"
echo ""
echo "Deploy via MDM (Jamf / Mosyle):"
echo "  1. Push steward-deploy.plist to /Library/Application Support/cfgms/steward-deploy.plist"
echo "     Plist keys: REGTOKEN (required), CA_FINGERPRINT, CA_CERT_PATH (optional)"
echo "  2. Deploy $(basename "$OUTPUT_PKG") as a managed package"
echo ""
echo "Deploy manually (testing):"
echo "  sudo installer -pkg $(basename "$OUTPUT_PKG") -target /"
