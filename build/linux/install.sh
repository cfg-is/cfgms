#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# install.sh — Install cfgms-steward on Linux with CA trust bootstrap.
#
# Installs the bundled cfgms-steward binary, verifies the controller CA cert
# fingerprint (interactive prompt or --fingerprint flag for non-interactive
# use), and delegates to cfgms-steward install for cert placement and systemd
# service registration.
#
# Usage:
#   sudo bash install.sh --regtoken TOKEN [--fingerprint HEX] [--ca-cert PATH]
#
# Flags:
#   --regtoken TOKEN    Registration token (required)
#   --fingerprint HEX   CA cert SHA-256 fingerprint, lowercase hex no colons;
#                       skips interactive prompt
#   --ca-cert PATH      CA cert PEM path (default: ca.crt in script directory
#                       if present — matches the tar.gz bundle layout)
#
# Non-interactive example:
#   sudo bash install.sh --regtoken mytoken --fingerprint aabbcc1122...
#
# Interactive example:
#   sudo bash install.sh --regtoken mytoken
#   (Displays the fingerprint from ca.fingerprint, prompts for confirmation)
#
# Test isolation:
#   CFGMS_INSTALL_PREFIX=/tmp/test sudo bash install.sh ...
#   All write paths are prefixed; the binary is resolved from the prefix path
#   so tests can inject a mock cfgms-steward without root.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Argument parsing ──────────────────────────────────────────────────────────

REGTOKEN=""
FINGERPRINT=""
CA_CERT=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --regtoken)    REGTOKEN="$2";     shift 2 ;;
        --fingerprint) FINGERPRINT="$2";  shift 2 ;;
        --ca-cert)     CA_CERT="$2";      shift 2 ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

# ── Validation ────────────────────────────────────────────────────────────────

if [[ -z "$REGTOKEN" ]]; then
    echo "Usage: sudo bash install.sh --regtoken TOKEN [--fingerprint HEX] [--ca-cert PATH]" >&2
    echo "" >&2
    echo "  --regtoken TOKEN    Registration token (required)" >&2
    echo "  --fingerprint HEX   CA cert SHA-256 fingerprint for non-interactive install" >&2
    echo "  --ca-cert PATH      Path to CA cert PEM (default: ca.crt in script directory)" >&2
    exit 1
fi

# ── Locate CA cert ────────────────────────────────────────────────────────────

# Default: ca.crt in the same directory as this script (matches tar.gz layout).
if [[ -z "$CA_CERT" && -f "$SCRIPT_DIR/ca.crt" ]]; then
    CA_CERT="$SCRIPT_DIR/ca.crt"
fi

# ── Fingerprint verification ──────────────────────────────────────────────────

if [[ -n "$CA_CERT" ]]; then
    if [[ -n "$FINGERPRINT" ]]; then
        # Non-interactive: compute SHA-256 from the cert, normalize to lowercase
        # hex without colons, and compare to the caller-supplied value.
        COMPUTED="$(openssl x509 -noout -fingerprint -sha256 -in "$CA_CERT" 2>/dev/null \
            | sed 's/.*=//; s/://g' | tr '[:upper:]' '[:lower:]')"
        EXPECTED="$(echo "$FINGERPRINT" | tr '[:upper:]' '[:lower:]')"
        if [[ "$COMPUTED" != "$EXPECTED" ]]; then
            echo "Fingerprint mismatch:" >&2
            echo "  expected: $EXPECTED" >&2
            echo "  computed: $COMPUTED" >&2
            echo "Installation aborted. Verify the CA fingerprint before deploying." >&2
            exit 1
        fi
    else
        # Interactive: display the bundled fingerprint and prompt for confirmation.
        FP_FILE="$SCRIPT_DIR/ca.fingerprint"
        if [[ -f "$FP_FILE" ]]; then
            DISPLAYED_FP="$(cat "$FP_FILE")"
        else
            DISPLAYED_FP="$(openssl x509 -noout -fingerprint -sha256 -in "$CA_CERT" 2>/dev/null \
                | sed 's/.*=//; s/://g' | tr '[:upper:]' '[:lower:]')"
        fi
        echo ""
        echo "CA Certificate Fingerprint (SHA-256):"
        echo "  $DISPLAYED_FP"
        echo ""
        printf "Verify this fingerprint against your controller --init output. Continue? [y/N] "
        read -r ANSWER || ANSWER=""
        case "$ANSWER" in
            [yY]|[yY][eE][sS]) ;;
            *)
                echo "Installation aborted. Verify the CA fingerprint before deploying." >&2
                exit 1
                ;;
        esac
    fi
fi

# ── Locate cfgms-steward binary ───────────────────────────────────────────────

# Primary: bundle path (same directory as this script, matching tar.gz layout).
# Test-isolation fallback: CFGMS_INSTALL_PREFIX/usr/local/bin/cfgms-steward
# lets tests inject a mock binary without root access.
INSTALL_PREFIX="${CFGMS_INSTALL_PREFIX:-}"
if [[ -x "$SCRIPT_DIR/cfgms-steward" ]]; then
    STEWARD_BIN="$SCRIPT_DIR/cfgms-steward"
elif [[ -n "$INSTALL_PREFIX" && -x "$INSTALL_PREFIX/usr/local/bin/cfgms-steward" ]]; then
    STEWARD_BIN="$INSTALL_PREFIX/usr/local/bin/cfgms-steward"
else
    echo "Error: cfgms-steward binary not found in $SCRIPT_DIR" >&2
    exit 1
fi

# ── Build and run install command ─────────────────────────────────────────────

INSTALL_ARGS=(install --regtoken "$REGTOKEN")
if [[ -n "$CA_CERT" ]]; then
    INSTALL_ARGS+=(--ca-cert "$CA_CERT")
fi
if [[ -n "$FINGERPRINT" ]]; then
    INSTALL_ARGS+=(--fingerprint "$FINGERPRINT")
fi

echo "Installing CFGMS Steward..."
"$STEWARD_BIN" "${INSTALL_ARGS[@]}"
