#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# install-cfg-test.sh — Integration tests for scripts/install-cfg.sh.
#
# Tests install to a temp prefix, verifies cfg runs, and re-installs
# idempotently. Does not require root. Requires a pre-built bin/cfg binary.
#
# Usage:
#   bash scripts/install-cfg-test.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
INSTALL_SCRIPT="$SCRIPT_DIR/install-cfg.sh"

PASS=0
FAIL=0

pass() { echo "PASS: $1"; ((PASS++)) || true; }
fail() { echo "FAIL: $1"; ((FAIL++)) || true; }

# ── Centralized cleanup ───────────────────────────────────────────────────────

# All temp dirs and backup paths registered here are cleaned up on EXIT.
CLEANUP_PATHS=()

cleanup() {
    local p
    for p in "${CLEANUP_PATHS[@]:-}"; do
        [[ -z "$p" ]] && continue
        rm -rf "$p" 2>/dev/null || true
    done
}

trap cleanup EXIT

# ── Preflight: ensure bin/cfg exists ─────────────────────────────────────────

if [[ ! -f "$REPO_ROOT/bin/cfg" ]]; then
    echo "Error: bin/cfg not found. Run 'make build-cli' before running this test." >&2
    exit 1
fi

# ── Test 1: Install to temp prefix, binary is executable and runs ─────────────

T1_PREFIX="$(mktemp -d)"
CLEANUP_PATHS+=("$T1_PREFIX")

EXIT_CODE=0
OUTPUT="$(bash "$INSTALL_SCRIPT" --prefix "$T1_PREFIX" 2>&1)" || EXIT_CODE=$?

if [[ $EXIT_CODE -eq 0 ]] && [[ -x "$T1_PREFIX/cfg" ]]; then
    pass "test1: install exits 0 and places executable cfg binary in prefix"
else
    fail "test1: expected exit 0 and executable $T1_PREFIX/cfg (exit=$EXIT_CODE output='$OUTPUT')"
fi

# cfg version must exit 0
VERSION_EXIT=0
VERSION_OUT="$("$T1_PREFIX/cfg" version 2>&1)" || VERSION_EXIT=$?

if [[ $VERSION_EXIT -eq 0 ]]; then
    pass "test1: $T1_PREFIX/cfg version exits 0"
else
    fail "test1: $T1_PREFIX/cfg version should exit 0 (exit=$VERSION_EXIT output='$VERSION_OUT')"
fi

# ── Test 2: Re-install over existing binary is idempotent (exits 0) ───────────

EXIT_CODE=0
OUTPUT="$(bash "$INSTALL_SCRIPT" --prefix "$T1_PREFIX" 2>&1)" || EXIT_CODE=$?

if [[ $EXIT_CODE -eq 0 ]] && [[ -x "$T1_PREFIX/cfg" ]]; then
    pass "test2: re-install exits 0 (idempotent)"
else
    fail "test2: re-install should exit 0 (exit=$EXIT_CODE output='$OUTPUT')"
fi

# cfg version must still work after re-install
VERSION_EXIT=0
VERSION_OUT="$("$T1_PREFIX/cfg" version 2>&1)" || VERSION_EXIT=$?

if [[ $VERSION_EXIT -eq 0 ]]; then
    pass "test2: cfg version exits 0 after re-install"
else
    fail "test2: cfg version should exit 0 after re-install (exit=$VERSION_EXIT output='$VERSION_OUT')"
fi

# ── Test 3: install creates prefix directory when absent ──────────────────────

T3_BASE="$(mktemp -d)"
CLEANUP_PATHS+=("$T3_BASE")
T3_PREFIX="$T3_BASE/nonexistent/subdir"

EXIT_CODE=0
OUTPUT="$(bash "$INSTALL_SCRIPT" --prefix "$T3_PREFIX" 2>&1)" || EXIT_CODE=$?

if [[ $EXIT_CODE -eq 0 ]] && [[ -x "$T3_PREFIX/cfg" ]]; then
    pass "test3: install creates absent prefix directory and installs binary"
else
    fail "test3: expected exit 0 and binary at $T3_PREFIX/cfg (exit=$EXIT_CODE output='$OUTPUT')"
fi

# ── Test 4: missing binary exits 1 with error message ────────────────────────

T4_PREFIX="$(mktemp -d)"
CLEANUP_PATHS+=("$T4_PREFIX")

ORIGINAL_BIN="$REPO_ROOT/bin/cfg"
BACKUP_BIN="$REPO_ROOT/bin/cfg.bak.$$"
CLEANUP_PATHS+=("$BACKUP_BIN")

# Move aside; restore is guaranteed by the EXIT trap registering BACKUP_BIN
# and by the explicit mv below (whichever fires first).
mv "$ORIGINAL_BIN" "$BACKUP_BIN"

EXIT_CODE=0
OUTPUT="$(bash "$INSTALL_SCRIPT" --prefix "$T4_PREFIX" 2>&1)" || EXIT_CODE=$?

# Restore immediately so subsequent tests work
mv "$BACKUP_BIN" "$ORIGINAL_BIN"
# Remove from cleanup so the EXIT trap does not try to rm the restored binary
CLEANUP_PATHS=("${CLEANUP_PATHS[@]/$BACKUP_BIN/}")

if [[ $EXIT_CODE -ne 0 ]] && echo "$OUTPUT" | grep -q "not found"; then
    pass "test4: missing bin/cfg exits non-zero with 'not found' message"
else
    fail "test4: expected non-zero exit and 'not found' in output (exit=$EXIT_CODE output='$OUTPUT')"
fi

# ── Test 5: unknown argument exits non-zero with error message ────────────────

EXIT_CODE=0
OUTPUT="$(bash "$INSTALL_SCRIPT" --unknown-flag 2>&1)" || EXIT_CODE=$?

if [[ $EXIT_CODE -ne 0 ]]; then
    pass "test5: unknown argument exits non-zero"
else
    fail "test5: expected non-zero exit for unknown argument (exit=$EXIT_CODE)"
fi

if echo "$OUTPUT" | grep -q "Unknown argument"; then
    pass "test5: unknown argument emits 'Unknown argument' error message"
else
    fail "test5: expected 'Unknown argument' in output (exit=$EXIT_CODE output='$OUTPUT')"
fi

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "Results: $PASS passed, $FAIL failed"

if [[ $FAIL -gt 0 ]]; then
    exit 1
fi
