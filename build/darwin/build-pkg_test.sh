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
while [[ \$# -gt 0 ]]; do
    if [[ "\$1" == "--regtoken-file" ]]; then
        echo "\$2" > "$dir/recorded-token-path"
        if [[ "\${MOCK_EXIT:-0}" == "0" ]]; then cp "\$2" "$dir/recorded-token"; fi
    fi
    shift
done
exit "\${MOCK_EXIT:-0}"
EOF
    chmod +x "$binary"
    echo "$record_file"
}

# ── Test 1: REGTOKEN only — calls install with --regtoken-file ────────────────────

T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

PLIST="$T/steward-deploy.plist"
write_plist "$PLIST" "tok-abc-123"
ARGS_FILE="$(make_mock_binary "$T")"

OUTPUT="$(run_postinstall "$PLIST" "$T")"
RECORDED="$(cat "$ARGS_FILE")"

TOKPATH1="$(cat "$T/recorded-token-path")"
if [[ "$RECORDED" == "install --regtoken-file $TOKPATH1" && "$RECORDED" != *tok-abc-123* \
    && "$(cat "$T/recorded-token")" == "tok-abc-123" ]]; then
    pass "test1: regtoken-only passes correct args"
else
    fail "test1: expected 'install --regtoken-file <path>' with token read from file, got '$RECORDED'"
fi

# ── Test 2: REGTOKEN + CA_FINGERPRINT — adds --fingerprint ──────────────────

T2=$(mktemp -d)

PLIST2="$T2/steward-deploy.plist"
write_plist "$PLIST2" "tok-xyz" "aabbcc1122"
ARGS_FILE2="$(make_mock_binary "$T2")"

run_postinstall "$PLIST2" "$T2" >/dev/null
RECORDED2="$(cat "$ARGS_FILE2")"

if [[ "$RECORDED2" == "install --regtoken-file $(cat "$T2/recorded-token-path") --fingerprint aabbcc1122" ]]; then
    pass "test2: regtoken+fingerprint passes correct args"
else
    fail "test2: expected 'install --regtoken-file <path> --fingerprint aabbcc1122', got '$RECORDED2'"
fi

rm -rf "$T2"

# ── Test 3: All fields — adds --controller-ca ──────────────────────────────────────

T3=$(mktemp -d)

PLIST3="$T3/steward-deploy.plist"
write_plist "$PLIST3" "tok-full" "ddeeff3344" "/etc/cfgms/controller-ca.crt"
ARGS_FILE3="$(make_mock_binary "$T3")"

run_postinstall "$PLIST3" "$T3" >/dev/null
RECORDED3="$(cat "$ARGS_FILE3")"

EXPECTED3="install --regtoken-file $(cat "$T3/recorded-token-path") --fingerprint ddeeff3344 --controller-ca /etc/cfgms/controller-ca.crt"
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

# ── Test 6: success consumes the token ───────────────────────────────────────

T6=$(mktemp -d)
PLIST6="$T6/steward-deploy.plist"
write_plist "$PLIST6" "tok-consume"
make_mock_binary "$T6" >/dev/null

run_postinstall "$PLIST6" "$T6" >/dev/null
TOKPATH6="$(cat "$T6/recorded-token-path")"
if [[ "$(cat "$T6/recorded-token")" == "tok-consume" ]] \
    && ! grep -q "REGTOKEN" "$PLIST6" \
    && ! /usr/libexec/PlistBuddy -c "Print :REGTOKEN" "$PLIST6" >/dev/null 2>&1 \
    && [[ ! -e "$TOKPATH6" && ! -e "$(dirname "$TOKPATH6")" ]]; then
    pass "test6: token passed by file, removed from plist, temp file gone"
else
    fail "test6: token not consumed correctly (path: $TOKPATH6)"
fi

rm -rf "$T6"

# ── Test 7: install failure keeps the plist and cleans the temp file ─────────

T7=$(mktemp -d)
PLIST7="$T7/steward-deploy.plist"
write_plist "$PLIST7" "tok-retry"
make_mock_binary "$T7" >/dev/null

T7_RC=0
MOCK_EXIT=3 run_postinstall "$PLIST7" "$T7" >/dev/null || T7_RC=$?
TOKPATH7="$(cat "$T7/recorded-token-path")"
if [[ $T7_RC -ne 0 ]] \
    && /usr/libexec/PlistBuddy -c "Print :REGTOKEN" "$PLIST7" >/dev/null 2>&1 \
    && [[ -n "$TOKPATH7" && ! -e "$TOKPATH7" && ! -e "$(dirname "$TOKPATH7")" ]]; then
    pass "test7: failed install exits non-zero, keeps REGTOKEN, removes temp file"
else
    fail "test7: rc=$T7_RC, plist/temp-file state wrong (path: $TOKPATH7)"
fi

rm -rf "$T7"

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "Results: $PASS passed, $FAIL failed"

if [[ $FAIL -gt 0 ]]; then
    exit 1
fi
