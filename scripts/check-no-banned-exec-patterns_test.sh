#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# Tests for scripts/check-no-banned-exec-patterns.sh (Issue #4343).
#
# Covers: the real windows-setup.ps1 and the two script templates pass today
# (the fix this story ships); each individual banned pattern is independently
# detected and named when planted in a fixture file; a comment merely
# mentioning a banned pattern does not self-trip the gate; and the gate fails
# closed (exit 2) when a named file is missing.
#
# Usage: bash scripts/check-no-banned-exec-patterns_test.sh

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECKER="$REPO_ROOT/scripts/check-no-banned-exec-patterns.sh"

PASS=0
FAIL=0

pass() {
    echo "  ✅ $1"
    PASS=$((PASS + 1))
}

fail() {
    echo "  ❌ $1"
    FAIL=$((FAIL + 1))
}

echo "🧪 scripts/check-no-banned-exec-patterns.sh"
echo "============================================"

# --- 1. The real files in the repo pass today (the fix this story ships) ---
out=$(bash "$CHECKER" 2>&1)
rc=$?
if [ "$rc" -eq 0 ]; then
    pass "real windows-setup.ps1 + templates pass (exit 0)"
else
    fail "real files should pass (rc=$rc): $out"
fi
case "$out" in
    OK:*) pass "reports OK on stdout" ;;
    *) fail "should report OK on stdout (got: $out)" ;;
esac

# --- 2. Each banned pattern is independently detected and named -------------
run_against_fixture() {
    local content="$1"
    local fixture
    fixture=$(mktemp)
    printf '%s\n' "$content" > "$fixture"
    CFGMS_TEST_CHECK_FILES="$fixture" bash "$CHECKER" >"${fixture}.out" 2>&1
    RC=$?
    STDOUT="$(cat "${fixture}.out")"
    rm -f "$fixture" "${fixture}.out"
}

BANNED_CASES=(
    "iex ((New-Object System.Net.WebClient).DownloadString('https://example.com/install.ps1'))"
    "Invoke-Expression \$cmd"
    'powershell -Command "Write-Host hi"'
    "certutil -decode file -EncodedCommand foo"
    "Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process"
    'bash -c "echo hi"'
    'eval "$cmd"'
    "python3 -c 'print(1)'"
)
for case_src in "${BANNED_CASES[@]}"; do
    run_against_fixture "$case_src"
    if [ "$RC" -eq 1 ]; then
        pass "rejects: ${case_src:0:40}..."
    else
        fail "should reject (rc=$RC): ${case_src} — stdout: $STDOUT"
    fi
done

# --- 3. A comment merely naming a banned pattern does not self-trip --------
run_against_fixture '# No banned pattern here: no iex, Invoke-Expression, eval, bash -c, python -c, -EncodedCommand, -ExecutionPolicy Bypass.
Write-Host "clean"'
if [ "$RC" -eq 0 ]; then
    pass "a comment naming banned patterns does not trip the gate"
else
    fail "comment-only mention should not trip the gate (rc=$RC): $STDOUT"
fi

# --- 4. A clean file with none of the patterns passes -----------------------
run_against_fixture 'Write-Host "hello"
& git status'
if [ "$RC" -eq 0 ]; then
    pass "a clean file passes"
else
    fail "clean file should pass (rc=$RC): $STDOUT"
fi

# --- 5. The gate fails closed when a named file is missing ------------------
CFGMS_TEST_CHECK_FILES="/nonexistent/does-not-exist.ps1" bash "$CHECKER" >/tmp/cnbep_missing.out 2>&1
RC=$?
if [ "$RC" -eq 2 ]; then
    pass "fails closed (exit 2) when a named file is missing"
else
    fail "missing file should exit 2 (rc=$RC): $(cat /tmp/cnbep_missing.out)"
fi
rm -f /tmp/cnbep_missing.out

echo ""
echo "Passed: $PASS  Failed: $FAIL"
[ "$FAIL" -eq 0 ] || exit 1
echo "✅ check-no-banned-exec-patterns.sh tests passed"
