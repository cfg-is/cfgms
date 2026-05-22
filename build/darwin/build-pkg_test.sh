#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jordan Ritz
#
# build-pkg_test.sh — Integration test for the macOS postinstall script.
#
# Tests that the postinstall script reads steward-deploy.plist correctly and
# passes the expected arguments to cfgms-steward install.
#
# This test is macOS-only (uses PlistBuddy). On other platforms it prints
# "skip: darwin only" and exits 0.
#
# Usage:
#   bash build/darwin/build-pkg_test.sh

[[ "$(uname)" == "Darwin" ]] || { echo "skip: darwin only"; exit 0; }

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POSTINSTALL="$SCRIPT_DIR/scripts/postinstall"

PASS=0
FAIL=0

pass() { echo "PASS: $1"; ((PASS++)) || true; }
fail() { echo "FAIL: $1"; ((FAIL++)) || true; }

# ── Helper: create a temp directory for each test case ───────────────────────

run_postinstall() {
    local plist_path="$1"
    local install_prefix="$2"
    shift 2

    CFGMS_DEPLOY_PLIST="$plist_path" \
    CFGMS_INSTALL_PREFIX="$install_prefix" \
    bash "$POSTINSTALL" "$@" 2>&1
}

write_plist() {
    local path="$1"
    local regtoken="$2"
    local fingerprint="${3:-}"
    local ca_cert_path="${4:-}"

    /usr/libexec/PlistBuddy -c "Clear dict" "$path" 2>/dev/null || true
    /usr/libexec/PlistBuddy -c "Add :REGTOKEN string $regtoken" "$path"
    if [[ -n "$fingerprint" ]]; then
        /usr/libexec/PlistBuddy -c "Add :CA_FINGERPRINT string $fingerprint" "$path"
    fi
    if [[ -n "$ca_cert_path" ]]; then
        /usr/libexec/PlistBuddy -c "Add :CA_CERT_PATH string $ca_cert_path" "$path"
    fi
}

# ── Test fixture: mock cfgms-steward binary ───────────────────────────────────
# The mock binary records all arguments to a file so tests can assert them.

make_mock_binary() {
    local dir="$1"
    local record_file="$dir/recorded-args"
    local binary="$dir/usr/local/bin/cfgms-steward"

    mkdir -p "$(dirname "$binary")"
    cat > "$binary" <<EOF
#!/bin/bash
echo "\$@" > "$record_file"
EOF
    chmod +x "$binary"
    echo "$record_file"
}

# ── Test 1: REGTOKEN only — calls install with --regtoken ────────────────────

T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

PLIST="$T/steward-deploy.plist"
write_plist "$PLIST" "tok-abc-123"
ARGS_FILE="$(make_mock_binary "$T")"

OUTPUT="$(run_postinstall "$PLIST" "$T")"
RECORDED="$(cat "$ARGS_FILE")"

if [[ "$RECORDED" == "install --regtoken tok-abc-123" ]]; then
    pass "test1: regtoken-only passes correct args"
else
    fail "test1: expected 'install --regtoken tok-abc-123', got '$RECORDED'"
fi

# ── Test 2: REGTOKEN + CA_FINGERPRINT — adds --fingerprint ──────────────────

T2=$(mktemp -d)

PLIST2="$T2/steward-deploy.plist"
write_plist "$PLIST2" "tok-xyz" "aabbcc1122"
ARGS_FILE2="$(make_mock_binary "$T2")"

run_postinstall "$PLIST2" "$T2" >/dev/null
RECORDED2="$(cat "$ARGS_FILE2")"

if [[ "$RECORDED2" == "install --regtoken tok-xyz --fingerprint aabbcc1122" ]]; then
    pass "test2: regtoken+fingerprint passes correct args"
else
    fail "test2: expected 'install --regtoken tok-xyz --fingerprint aabbcc1122', got '$RECORDED2'"
fi

rm -rf "$T2"

# ── Test 3: All fields — adds --ca-cert ──────────────────────────────────────

T3=$(mktemp -d)

PLIST3="$T3/steward-deploy.plist"
write_plist "$PLIST3" "tok-full" "ddeeff3344" "/etc/cfgms/controller-ca.crt"
ARGS_FILE3="$(make_mock_binary "$T3")"

run_postinstall "$PLIST3" "$T3" >/dev/null
RECORDED3="$(cat "$ARGS_FILE3")"

EXPECTED3="install --regtoken tok-full --fingerprint ddeeff3344 --ca-cert /etc/cfgms/controller-ca.crt"
if [[ "$RECORDED3" == "$EXPECTED3" ]]; then
    pass "test3: all fields passes correct args"
else
    fail "test3: expected '$EXPECTED3', got '$RECORDED3'"
fi

rm -rf "$T3"

# ── Test 4: Missing plist — exits non-zero with error message ────────────────

T4=$(mktemp -d)
make_mock_binary "$T4" >/dev/null

# Capture output separately: with pipefail, piping a failing command into grep
# would propagate the non-zero exit code even when grep succeeds.
T4_OUTPUT="$(run_postinstall "$T4/does-not-exist.plist" "$T4" 2>&1 || true)"
if echo "$T4_OUTPUT" | grep -q "not found"; then
    pass "test4: missing plist produces error message"
else
    fail "test4: expected 'not found' in output for missing plist (got: '$T4_OUTPUT')"
fi

rm -rf "$T4"

# ── Test 5: Empty REGTOKEN — exits non-zero with error message ───────────────

T5=$(mktemp -d)
PLIST5="$T5/steward-deploy.plist"

# Write a plist with no REGTOKEN key at all.
/usr/libexec/PlistBuddy -c "Clear dict" "$PLIST5" 2>/dev/null || true
/usr/libexec/PlistBuddy -c "Add :CA_FINGERPRINT string aabbcc" "$PLIST5"

make_mock_binary "$T5" >/dev/null

# Capture output separately: same pipefail reason as test 4.
T5_OUTPUT="$(run_postinstall "$PLIST5" "$T5" 2>&1 || true)"
if echo "$T5_OUTPUT" | grep -q "REGTOKEN"; then
    pass "test5: missing REGTOKEN produces error message"
else
    fail "test5: expected 'REGTOKEN' in output for missing token (got: '$T5_OUTPUT')"
fi

rm -rf "$T5"

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "Results: $PASS passed, $FAIL failed"

if [[ $FAIL -gt 0 ]]; then
    exit 1
fi
