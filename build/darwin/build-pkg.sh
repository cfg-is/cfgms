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
# Code signing (required when CFGMS_RELEASE_BUILD=1):
#   Set APPLE_APPLICATION_SIGNING_IDENTITY to a Developer ID Application
#   certificate and APPLE_SIGNING_IDENTITY to a Developer ID Installer name
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
PUBLISHER_KEY=""
RELEASE_BUILD="${CFGMS_RELEASE_BUILD:-0}"

# ── Argument parsing ──────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        --arch)          ARCH="$2";           shift 2 ;;
        --version)       VERSION="$2";        shift 2 ;;
        --binary-path)   BINARY_PATH="$2";    shift 2 ;;
        --controller-url) CONTROLLER_URL="$2"; shift 2 ;;
        --publisher-key) PUBLISHER_KEY="$2";  shift 2 ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

if [[ "$RELEASE_BUILD" == 1 ]]; then
    if ! [[ "$VERSION" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-([0-9A-Za-z-]+)(\.[0-9A-Za-z-]+)*)?$ ]]; then
        echo "ERROR: CFGMS_RELEASE_BUILD requires a canonical v-prefixed semantic version." >&2
        exit 1
    fi
    if [[ "$VERSION" == *-* ]]; then
        IFS='.' read -r -a prerelease_parts <<< "${VERSION#*-}"
        for identifier in "${prerelease_parts[@]}"; do
            if [[ "$identifier" =~ ^[0-9]+$ && ${#identifier} -gt 1 && "$identifier" == 0* ]]; then
                echo "ERROR: numeric prerelease identifiers cannot have leading zeroes." >&2
                exit 1
            fi
        done
    fi
    for required in PUBLISHER_KEY APPLE_APPLICATION_SIGNING_IDENTITY APPLE_SIGNING_IDENTITY APPLE_NOTARIZATION_PROFILE; do
        if [[ -z "${!required:-}" ]]; then
            echo "ERROR: CFGMS_RELEASE_BUILD requires $required." >&2
            exit 1
        fi
    done
    KEY_HEX="$(printf '%s' "$PUBLISHER_KEY" | openssl base64 -d -A | od -An -tx1 | tr -d ' \n')"
    if [[ ${#KEY_HEX} -ne 64 || "$KEY_HEX" =~ ^0+$ ]]; then
        echo "ERROR: PUBLISHER_KEY must be a non-zero 32-byte Ed25519 public key." >&2
        exit 1
    fi
fi

# Strip the tag prefix and prerelease suffix for pkgbuild's numeric N.N.N
# receipt version. The full semantic version remains embedded in the binary
# and bound by the release signatures/attestations.
PKG_VERSION="${VERSION#v}"
PKG_VERSION="${PKG_VERSION%%-*}"
if ! [[ "$PKG_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    PKG_VERSION="0.0.0"
fi

echo "=== CFGMS Steward macOS .pkg Build ==="
echo "Version:        $VERSION"
echo "Pkg version:    $PKG_VERSION"
echo "ControllerURL:  ${CONTROLLER_URL:-(not set — generic build)}"
echo "PublisherKey:   ${PUBLISHER_KEY:+(set)}${PUBLISHER_KEY:-(not set — placeholder key)}"
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
        LD_FLAGS="-s -w -X main.ControllerURL=$CONTROLLER_URL -X main.SecurityProfile=public-beta $VERSION_FLAG"
    else
        LD_FLAGS="-s -w -X main.SecurityProfile=public-beta $VERSION_FLAG"
    fi
    if [[ -n "$PUBLISHER_KEY" ]]; then
        LD_FLAGS="$LD_FLAGS -X github.com/cfgis/cfgms/pkg/modules/trust.cfgmsPublisherPublicKey=$PUBLISHER_KEY"
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

# ── Step 1b: Build the launcher binary ───────────────────────────────────────
# The launcher must be bundled in the .pkg payload — Install() hard-fails when
# it is absent, so we always build it inline (not from a pre-existing artifact).

echo ""
echo "Building cfgms-steward-launcher binary for darwin/$ARCH..."

LAUNCHER_BUILD_DIR="$REPO_ROOT/bin/darwin-$ARCH"
LAUNCHER_BUILD_PATH="$LAUNCHER_BUILD_DIR/cfgms-steward-launcher"
mkdir -p "$LAUNCHER_BUILD_DIR"

LAUNCHER_LD_FLAGS="-s -w -X github.com/cfgis/cfgms/pkg/version.Version=$VERSION"

GOOS=darwin GOARCH="$ARCH" CGO_ENABLED=0 go build \
    -trimpath \
    -ldflags "$LAUNCHER_LD_FLAGS" \
    -o "$LAUNCHER_BUILD_PATH" \
    "$REPO_ROOT/cmd/cfgms-steward-launcher"

echo "  Launcher: $LAUNCHER_BUILD_PATH"

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

# Install the steward binary into the payload tree.
cp "$BINARY_PATH" "$PAYLOAD_DIR/usr/local/bin/cfgms-steward"
chmod 755 "$PAYLOAD_DIR/usr/local/bin/cfgms-steward"

# Install the launcher binary into the payload tree. This is required — Install()
# hard-fails when the launcher is absent, so we fail loudly here rather than
# producing a broken .pkg.
if [[ ! -f "$LAUNCHER_BUILD_PATH" ]]; then
    echo "ERROR: launcher binary not found after build: $LAUNCHER_BUILD_PATH" >&2
    exit 1
fi
cp "$LAUNCHER_BUILD_PATH" "$PAYLOAD_DIR/usr/local/bin/cfgms-launcher"
chmod 755 "$PAYLOAD_DIR/usr/local/bin/cfgms-launcher"
echo "  Launcher payload: $PAYLOAD_DIR/usr/local/bin/cfgms-launcher"

# Install stdlib module binaries into the payload tree.
STDLIB_MODULES=(
    cfgms-module-cert_trust
    cfgms-module-file
    cfgms-module-firewall
    cfgms-module-hostname
    cfgms-module-package
    cfgms-module-patch
    cfgms-module-script
    cfgms-module-service
    cfgms-module-time
    cfgms-module-user
)
MODULES_PAYLOAD_DIR="$PAYLOAD_DIR/usr/local/lib/cfgms/modules"
mkdir -p "$MODULES_PAYLOAD_DIR"
for module_bin in "${STDLIB_MODULES[@]}"; do
    src="$REPO_ROOT/bin/$module_bin-darwin-$ARCH"
    module_name="${module_bin#cfgms-module-}"
    if [[ ! -f "$src" ]]; then
        GOOS=darwin GOARCH="$ARCH" CGO_ENABLED=0 go build \
            -trimpath \
            -ldflags "$LAUNCHER_LD_FLAGS" \
            -o "$src" \
            "$REPO_ROOT/features/modules/stdlib/$module_name/cmd"
    fi
    if [[ -f "$src" ]]; then
        cp "$src" "$MODULES_PAYLOAD_DIR/$module_bin"
        chmod 755 "$MODULES_PAYLOAD_DIR/$module_bin"
        echo "  Module: $MODULES_PAYLOAD_DIR/$module_bin"
    elif [[ "$RELEASE_BUILD" == 1 ]]; then
        echo "ERROR: release module binary not found after build: $src" >&2
        exit 1
    else
        echo "  Warning: stdlib module binary not found: $src (skipping)" >&2
    fi
done

# The executable payload is signed before pkgbuild so Gatekeeper verifies the
# installed binaries as well as the outer installer package.
if [[ -n "${APPLE_APPLICATION_SIGNING_IDENTITY:-}" ]]; then
    echo ""
    echo "Signing executable payloads with: $APPLE_APPLICATION_SIGNING_IDENTITY"
    while IFS= read -r -d '' executable; do
        codesign --force --options runtime --timestamp \
            --sign "$APPLE_APPLICATION_SIGNING_IDENTITY" "$executable"
        codesign --verify --strict --verbose=2 "$executable"
    done < <(find "$PAYLOAD_DIR/usr/local" -type f -perm -0100 -print0)
elif [[ "$RELEASE_BUILD" == 1 ]]; then
    echo "ERROR: release executable payloads cannot be unsigned." >&2
    exit 1
else
    echo "WARNING: APPLE_APPLICATION_SIGNING_IDENTITY not set — payload binaries are unsigned." >&2
fi

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
    pkgutil --check-signature "$OUTPUT_PKG"
    echo "  Pkg signed and verified."
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
    xcrun stapler validate "$OUTPUT_PKG"
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
