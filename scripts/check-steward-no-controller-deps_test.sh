#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# Tests for scripts/check-steward-no-controller-deps.sh (Issue #5747).
#
# Builds throwaway Go modules whose cmd/steward main package imports (directly
# or transitively) a features/controller/... package and asserts the gate exits
# 1 naming it; asserts exit 0 for a clean fixture and for the real tree; and
# asserts the gate fails closed (exit 2) when the closure cannot be computed.
#
# Usage: bash scripts/check-steward-no-controller-deps_test.sh

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECKER="$REPO_ROOT/scripts/check-steward-no-controller-deps.sh"

PASS=0
FAIL=0
TMPDIRS=()
trap 'rm -rf "${TMPDIRS[@]}"' EXIT

pass() { echo "  ✅ $1"; PASS=$((PASS + 1)); }
fail() { echo "  ❌ $1"; FAIL=$((FAIL + 1)); }

# make_fixture <steward-import-path-or-empty> — creates a module "example.com/fix"
# with features/controller/batchjob, pkg/shared (which may import it) and a
# cmd/steward main package importing <arg> (a path under the module), and echoes its dir.
make_fixture() {
    local imp="$1" dir
    dir="$(mktemp -d)"
    TMPDIRS+=("$dir")
    mkdir -p "$dir/cmd/steward" "$dir/features/controller/batchjob" "$dir/pkg/shared" "$dir/pkg/leaf"
    printf 'module example.com/fix\n\ngo 1.21\n' > "$dir/go.mod"
    printf 'package batchjob\n\nconst X = 1\n' > "$dir/features/controller/batchjob/b.go"
    printf 'package leaf\n\nconst Y = 1\n' > "$dir/pkg/leaf/l.go"
    printf 'package shared\n\nimport _ "example.com/fix/features/controller/batchjob"\n' > "$dir/pkg/shared/s.go"
    local import_line=""
    [ -n "$imp" ] && import_line="import _ \"example.com/fix/$imp\""
    printf 'package main\n\n%s\n\nfunc main() {}\n' "$import_line" > "$dir/cmd/steward/main.go"
    printf '%s' "$dir"
}

run_checker() {
    local dir="$1"
    STDERR="$(bash "$CHECKER" "$dir" 2>&1 >/dev/null)"
    RC=$?
}

# Clean fixture
dir=$(make_fixture "pkg/leaf")
run_checker "$dir"
[ "$RC" -eq 0 ] && pass "clean fixture exits 0" || fail "clean fixture exited $RC: $STDERR"

# Direct import of a controller package
dir=$(make_fixture "features/controller/batchjob")
run_checker "$dir"
if [ "$RC" -eq 1 ] && grep -q "example.com/fix/features/controller/batchjob" <<<"$STDERR"; then
    pass "direct controller import exits 1 naming the package"
else
    fail "direct controller import: exit $RC, stderr: $STDERR"
fi
for os in linux windows darwin; do
    grep -q "GOOS=$os" <<<"$STDERR" && pass "offender reported for GOOS=$os" || fail "no report for GOOS=$os"
done

# Transitive import via pkg/
dir=$(make_fixture "pkg/shared")
run_checker "$dir"
if [ "$RC" -eq 1 ] && grep -q "example.com/fix/features/controller/batchjob" <<<"$STDERR"; then
    pass "transitive controller import exits 1 naming the package"
else
    fail "transitive controller import: exit $RC, stderr: $STDERR"
fi

# Fails closed when the closure cannot be computed
dir=$(make_fixture "pkg/does-not-exist")
run_checker "$dir"
[ "$RC" -eq 2 ] && pass "unresolvable steward closure fails closed (exit 2)" || fail "unresolvable closure exited $RC"

# Real tree
bash "$CHECKER" >/dev/null 2>&1
[ $? -eq 0 ] && pass "real tree exits 0" || fail "real tree failed the gate"

echo ""
echo "Passed: $PASS  Failed: $FAIL"
[ "$FAIL" -eq 0 ]
