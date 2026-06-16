#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# install_test.sh — Tests for build/linux/install.sh.
#
# Requires: openssl (for cert generation and fingerprint computation)
#
# Usage:
#   bash build/linux/install_test.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_SH="$SCRIPT_DIR/install.sh"

PASS=0
FAIL=0

pass() { echo "PASS: $1"; ((PASS++)) || true; }
fail() { echo "FAIL: $1"; ((FAIL++)) || true; }

# ── Generate a test CA cert ───────────────────────────────────────────────────

CERT_DIR="$(mktemp -d)"
trap 'rm -rf "$CERT_DIR"' EXIT

openssl req -x509 -newkey ed25519 \
    -keyout "$CERT_DIR/ca.key" \
    -out "$CERT_DIR/ca.crt" \
    -days 1 -noenc \
    -subj "/CN=test-ca" 2>/dev/null

# Correct fingerprint: lowercase hex, no colons (matches marker.go format).
CORRECT_FP="$(openssl x509 -noout -fingerprint -sha256 -in "$CERT_DIR/ca.crt" 2>/dev/null \
    | sed 's/.*=//; s/://g' | tr '[:upper:]' '[:lower:]')"

# ── Helpers ───────────────────────────────────────────────────────────────────

# make_install_dir populates a temp directory with install.sh and a mock
# cfgms-steward binary. The mock writes the --ca-cert file to the expected
# location under CFGMS_INSTALL_PREFIX so tests can verify cert placement.
make_install_dir() {
    local dir="$1"
    cp "$INSTALL_SH" "$dir/install.sh"
    chmod +x "$dir/install.sh"

    cat > "$dir/cfgms-steward" <<'MOCK'
#!/usr/bin/env bash
# Mock cfgms-steward: simulates cert placement under CFGMS_INSTALL_PREFIX.
CA_CERT_SRC=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        install)   shift ;;
        --ca-cert) CA_CERT_SRC="$2"; shift 2 ;;
        *)         shift ;;
    esac
done
if [[ -n "$CA_CERT_SRC" ]]; then
    PREFIX="${CFGMS_INSTALL_PREFIX:-}"
    DEST="${PREFIX}/etc/cfgms/controller-ca.crt"
    mkdir -p "$(dirname "$DEST")"
    cp "$CA_CERT_SRC" "$DEST"
fi
exit 0
MOCK
    chmod +x "$dir/cfgms-steward"
}

# run_install executes install.sh from DIR with CFGMS_INSTALL_PREFIX set to
# PREFIX. Additional positional arguments are forwarded to install.sh.
# After the call, LAST_EXIT and LAST_OUTPUT are set.
LAST_EXIT=0
LAST_OUTPUT=""
run_install() {
    local dir="$1"
    local prefix="${2:-}"
    shift 2
    LAST_EXIT=0
    LAST_OUTPUT="$(CFGMS_INSTALL_PREFIX="$prefix" bash "$dir/install.sh" "$@" 2>&1)" \
        || LAST_EXIT=$?
}

# ── Test 1: Missing --regtoken exits 1 with usage message ────────────────────

T1="$(mktemp -d)"
make_install_dir "$T1"

run_install "$T1" ""

if [[ $LAST_EXIT -eq 1 ]] && echo "$LAST_OUTPUT" | grep -qi "regtoken"; then
    pass "test1: missing --regtoken exits 1 with usage message"
else
    fail "test1: expected exit 1 and 'regtoken' in output (exit=$LAST_EXIT output='$LAST_OUTPUT')"
fi
rm -rf "$T1"

# ── Test 2: Fingerprint mismatch exits 1 and does not write the cert ─────────

T2="$(mktemp -d)"
T2_PREFIX="$(mktemp -d)"
make_install_dir "$T2"
cp "$CERT_DIR/ca.crt" "$T2/ca.crt"

WRONG_FP="0000000000000000000000000000000000000000000000000000000000000000"
run_install "$T2" "$T2_PREFIX" --regtoken "tok-test" --fingerprint "$WRONG_FP"

T2_CERT="$T2_PREFIX/etc/cfgms/controller-ca.crt"
if [[ $LAST_EXIT -eq 1 ]] && [[ ! -f "$T2_CERT" ]]; then
    pass "test2: fingerprint mismatch exits 1 and does not write the cert"
else
    fail "test2: expected exit 1 and no cert at $T2_CERT (exit=$LAST_EXIT cert_exists=$([ -f "$T2_CERT" ] && echo yes || echo no))"
fi
rm -rf "$T2" "$T2_PREFIX"

# ── Test 3: Correct fingerprint exits 0 and writes cert to prefixed path ─────

T3="$(mktemp -d)"
T3_PREFIX="$(mktemp -d)"
make_install_dir "$T3"
cp "$CERT_DIR/ca.crt" "$T3/ca.crt"

run_install "$T3" "$T3_PREFIX" --regtoken "tok-test" --fingerprint "$CORRECT_FP"

T3_CERT="$T3_PREFIX/etc/cfgms/controller-ca.crt"
if [[ $LAST_EXIT -eq 0 ]] && [[ -f "$T3_CERT" ]]; then
    pass "test3: correct fingerprint exits 0 and writes cert to prefixed path"
else
    fail "test3: expected exit 0 and cert at $T3_CERT (exit=$LAST_EXIT cert_exists=$([ -f "$T3_CERT" ] && echo yes || echo no))"
fi
rm -rf "$T3" "$T3_PREFIX"

# ── Test 4: Interactive mode with 'y' proceeds and exits 0 ───────────────────

T4="$(mktemp -d)"
T4_PREFIX="$(mktemp -d)"
make_install_dir "$T4"
cp "$CERT_DIR/ca.crt" "$T4/ca.crt"

LAST_EXIT=0
LAST_OUTPUT="$(echo "y" | CFGMS_INSTALL_PREFIX="$T4_PREFIX" bash "$T4/install.sh" \
    --regtoken "tok-test" 2>&1)" || LAST_EXIT=$?

if [[ $LAST_EXIT -eq 0 ]]; then
    pass "test4: interactive 'y' exits 0"
else
    fail "test4: expected exit 0 for interactive 'y' (exit=$LAST_EXIT output='$LAST_OUTPUT')"
fi
rm -rf "$T4" "$T4_PREFIX"

# ── Test 5: Interactive mode with 'N' exits 1 ────────────────────────────────

T5="$(mktemp -d)"
T5_PREFIX="$(mktemp -d)"
make_install_dir "$T5"
cp "$CERT_DIR/ca.crt" "$T5/ca.crt"

LAST_EXIT=0
LAST_OUTPUT="$(echo "N" | CFGMS_INSTALL_PREFIX="$T5_PREFIX" bash "$T5/install.sh" \
    --regtoken "tok-test" 2>&1)" || LAST_EXIT=$?

if [[ $LAST_EXIT -eq 1 ]] && echo "$LAST_OUTPUT" | grep -q "aborted"; then
    pass "test5: interactive 'N' exits 1 with abort message"
else
    fail "test5: expected exit 1 and 'aborted' message for 'N' (exit=$LAST_EXIT output='$LAST_OUTPUT')"
fi
rm -rf "$T5" "$T5_PREFIX"

# ── Test 6: Interactive mode with empty input exits 1 ────────────────────────

T6="$(mktemp -d)"
T6_PREFIX="$(mktemp -d)"
make_install_dir "$T6"
cp "$CERT_DIR/ca.crt" "$T6/ca.crt"

LAST_EXIT=0
LAST_OUTPUT="$(echo "" | CFGMS_INSTALL_PREFIX="$T6_PREFIX" bash "$T6/install.sh" \
    --regtoken "tok-test" 2>&1)" || LAST_EXIT=$?

if [[ $LAST_EXIT -eq 1 ]] && echo "$LAST_OUTPUT" | grep -q "aborted"; then
    pass "test6: interactive empty input exits 1 with abort message"
else
    fail "test6: expected exit 1 and 'aborted' message for empty input (exit=$LAST_EXIT output='$LAST_OUTPUT')"
fi
rm -rf "$T6" "$T6_PREFIX"

# ── Test 7: --ca-cert explicit path is used instead of ./ca.crt default ──────

T7="$(mktemp -d)"
T7_PREFIX="$(mktemp -d)"
make_install_dir "$T7"
# No ca.crt in $T7 — pass --ca-cert explicitly.

run_install "$T7" "$T7_PREFIX" \
    --regtoken "tok-test" \
    --fingerprint "$CORRECT_FP" \
    --ca-cert "$CERT_DIR/ca.crt"

T7_CERT="$T7_PREFIX/etc/cfgms/controller-ca.crt"
if [[ $LAST_EXIT -eq 0 ]] && [[ -f "$T7_CERT" ]]; then
    pass "test7: explicit --ca-cert path works and writes cert to prefixed path"
else
    fail "test7: expected exit 0 and cert at $T7_CERT (exit=$LAST_EXIT cert_exists=$([ -f "$T7_CERT" ] && echo yes || echo no))"
fi
rm -rf "$T7" "$T7_PREFIX"

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "Results: $PASS passed, $FAIL failed"

if [[ $FAIL -gt 0 ]]; then
    exit 1
fi
