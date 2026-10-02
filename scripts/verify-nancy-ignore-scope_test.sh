#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# verify-nancy-ignore-scope_test.sh — Tests for scripts/verify-nancy-ignore-scope.sh.
#
# The gate exists to give machine-checked evidence that .nancy-ignore can only
# ever suppress the exact CVE/OSS-Index IDs it lists — never a pattern that
# could catch a second, unrelated vulnerability (Issue #3366 AC3). These tests
# exercise it against the repo's real file plus synthetic fixtures covering the
# ways an entry could accidentally widen scope or silently drop coverage.
#
# Run: bash scripts/verify-nancy-ignore-scope_test.sh
# Exit codes: 0 = all tests passed, 1 = any test failed

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GATE="$REPO_ROOT/scripts/verify-nancy-ignore-scope.sh"

SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/cfgms-nancy-scope.XXXXXX")"
cleanup() { rm -rf "$SCRATCH"; }
trap cleanup EXIT INT TERM

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

PASS_COUNT=0
FAIL_COUNT=0

_pass() { echo -e "${GREEN}[PASS]${NC} $1"; PASS_COUNT=$((PASS_COUNT + 1)); }
_fail() { echo -e "${RED}[FAIL]${NC} $1"; FAIL_COUNT=$((FAIL_COUNT + 1)); }

# assert_pass NAME CONTENT — gate must exit 0 against CONTENT
assert_pass() {
    local name="$1" content="$2" file
    file="$SCRATCH/$name.ignore"
    printf '%s\n' "$content" >"$file"
    if bash "$GATE" "$file" >/dev/null 2>&1; then
        _pass "$name: accepted as expected"
    else
        _fail "$name: rejected but should have been accepted"
    fi
}

# assert_fail NAME CONTENT — gate must exit non-zero against CONTENT
assert_fail() {
    local name="$1" content="$2" file
    file="$SCRATCH/$name.ignore"
    printf '%s\n' "$content" >"$file"
    if bash "$GATE" "$file" >/dev/null 2>&1; then
        _fail "$name: accepted but should have been rejected"
    else
        _pass "$name: rejected as expected"
    fi
}

echo "=== verify-nancy-ignore-scope.sh test suite ==="
echo ""

# ---------------------------------------------------------------------------
# The gate must accept the repo's real suppression file as-is.
# ---------------------------------------------------------------------------
if bash "$GATE" "$REPO_ROOT/.nancy-ignore" >/dev/null 2>&1; then
    _pass "real .nancy-ignore: accepted"
else
    _fail "real .nancy-ignore: rejected — should be well-formed"
fi

# ---------------------------------------------------------------------------
# Well-formed shapes the gate must accept.
# ---------------------------------------------------------------------------
assert_pass "single-entry" "# comment
CVE-2026-56860 until=2026-11-15"

assert_pass "multi-entry-distinct-ids" "CVE-2020-00001 until=2026-11-15
CVE-2021-00002 until=2026-11-15"

assert_pass "trailing-inline-comment" "CVE-2026-56860 until=2026-11-15 # re-check quarterly"

assert_pass "empty-file" ""

assert_pass "comments-and-blanks-only" "# nothing suppressed right now

# still nothing"

# ---------------------------------------------------------------------------
# Shapes that must be rejected — each is a way scope could widen or silently
# drop coverage.
# ---------------------------------------------------------------------------
assert_fail "wildcard-star" "CVE-2026-56860 until=2026-11-15
CVE-9999-* until=2026-11-15"

assert_fail "wildcard-question" "CVE-202?-56860 until=2026-11-15"

assert_fail "missing-expiry" "CVE-2026-56860"

assert_fail "malformed-date-month" "CVE-2026-56860 until=2026-13-01"

assert_fail "malformed-date-format" "CVE-2026-56860 until=11-15-2026"

assert_fail "malformed-date-not-zero-padded" "CVE-2026-56860 until=2026-1-1"

assert_fail "duplicate-entry" "CVE-2026-56860 until=2026-11-15
CVE-2026-56860 until=2026-11-16"

# A malformed second entry must be caught explicitly: nancy v2.1.0 itself
# aborts parsing the rest of the file on a bad `until=` date (the error is
# swallowed by its caller), which would silently stop the FIRST entry from
# being honoured too. The gate must reject this before nancy ever sees it.
assert_fail "malformed-second-entry-would-shadow-first" "CVE-2026-56860 until=2026-11-15
CVE-2027-00001 until=not-a-date"

# ---------------------------------------------------------------------------
# The core scoping proof: a synthetic CVE not present in the file must never
# be reported as excluded, replicating nancy's `v.Cve == ex || v.ID == ex`
# equality check (internal/ossindex/types.go, maybeExclude, nancy v2.1.0).
# ---------------------------------------------------------------------------
output="$(bash "$GATE" "$REPO_ROOT/.nancy-ignore" 2>&1)"
if echo "$output" | grep -q "does not match any entry, so it would still fail the gate"; then
    _pass "scoping proof: synthetic unrelated CVE confirmed unmatched"
else
    _fail "scoping proof: expected output did not confirm the synthetic CVE was unmatched"
fi

# A file that (hypothetically) excluded everything would never reach this
# check in real nancy — but assert our synthetic probe ID itself is never
# accidentally listed as a real suppression by any fixture used above, or the
# proof above is vacuous.
if grep -rq "CVE-1970-00000-scope-probe" "$REPO_ROOT/.nancy-ignore" 2>/dev/null; then
    _fail "scoping proof: probe ID collides with a real suppression entry — test is not meaningful"
else
    _pass "scoping proof: probe ID is disjoint from real suppression entries"
fi

echo ""
echo "=== Results: $PASS_COUNT passed, $FAIL_COUNT failed ==="

if [ "$FAIL_COUNT" -gt 0 ]; then
    exit 1
fi
exit 0
