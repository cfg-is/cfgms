#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# Tests for scripts/check-no-python-in-core.sh (Issue #4303, Epic #4296).
#
# Covers: a clean tree passes; a planted .py file under each of the six
# declared paths individually is rejected and named — at BOTH nesting depths,
# directly in the root (web/setup.py, test/conftest.py) and further down
# (pkg/storage/rogue.py), since a pathspec that only matches the nested shape
# leaves the likelier top-level placement unguarded; a .py file under an
# allowed tree (.claude/ or scripts/) is not flagged; and the gate fails
# closed (exit 2) outside a git work tree.
#
# Each case runs in a throwaway git repository so nothing touches the real tree.
#
# Usage: bash scripts/check-no-python-in-core_test.sh

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECKER="$REPO_ROOT/scripts/check-no-python-in-core.sh"

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

# make_repo creates a throwaway repo with a clean tree and echoes its path.
make_repo() {
    local dir
    dir="$(mktemp -d)"
    git -C "$dir" init --quiet
    git -C "$dir" config user.email "test@example.com"
    git -C "$dir" config user.name "test"
    mkdir -p "$dir/cmd/controller" "$dir/pkg/storage" "$dir/features/rbac" \
        "$dir/api/proto" "$dir/web/src" "$dir/test/integration" \
        "$dir/.claude/scripts" "$dir/scripts"
    echo "package main" > "$dir/cmd/controller/main.go"
    echo "placeholder" > "$dir/scripts/other.sh"
    git -C "$dir" add cmd pkg features api web test .claude scripts 2>/dev/null || true
    # The mkdir'd but empty dirs above have no committable content beyond
    # main.go/other.sh; add whatever landed, then commit.
    git -C "$dir" add -A
    git -C "$dir" commit --quiet -m "initial"
    printf '%s' "$dir"
}

# run_checker <repo> — runs the gate in <repo>, setting RC/STDOUT/STDERR.
run_checker() {
    local repo="$1" out err
    out="$(mktemp)"
    err="$(mktemp)"
    ( cd "$repo" && bash "$CHECKER" ) >"$out" 2>"$err"
    RC=$?
    STDOUT="$(cat "$out")"
    STDERR="$(cat "$err")"
    rm -f "$out" "$err"
}

echo "🧪 scripts/check-no-python-in-core.sh"
echo "======================================"

# --- 1. A clean tree passes -------------------------------------------------
repo="$(make_repo)"
run_checker "$repo"
if [ "$RC" -eq 0 ]; then
    pass "clean tree exits 0"
else
    fail "clean tree should exit 0 (rc=$RC, stderr: $STDERR)"
fi
case "$STDOUT" in
    OK:*) pass "clean tree reports OK on stdout" ;;
    *)    fail "clean tree should report OK on stdout (got: $STDOUT)" ;;
esac
rm -rf "$repo"

# --- 2. A planted .py file under each of the six declared paths is rejected -
# Each root is exercised at two depths: nested under a subdirectory, and
# directly in the root itself. The top-level cases are the ones a '**/'
# pathspec silently misses, and are the placement real Python tooling uses.
CORE_PATHS=(
    "cmd/controller/rogue.py"
    "pkg/storage/rogue.py"
    "features/rbac/rogue.py"
    "api/proto/rogue.py"
    "web/src/rogue.py"
    "test/integration/rogue.py"
    "cmd/rogue.py"
    "pkg/rogue.py"
    "features/rogue.py"
    "api/gen.py"
    "web/setup.py"
    "test/conftest.py"
)
for offender in "${CORE_PATHS[@]}"; do
    repo="$(make_repo)"
    mkdir -p "$repo/$(dirname "$offender")"
    printf '# rogue\n' > "$repo/$offender"
    git -C "$repo" add "$offender"
    git -C "$repo" commit --quiet -m "add $offender"
    run_checker "$repo"

    if [ "$RC" -eq 1 ]; then
        pass "rejects a .py file under '$offender' (exit 1)"
    else
        fail "'$offender' should exit 1 (rc=$RC, stdout: $STDOUT)"
    fi

    case "$STDERR" in
        *"$offender"*) pass "names the offending file for '$offender' on stderr" ;;
        *) fail "stderr should name $offender (got: $STDERR)" ;;
    esac
    rm -rf "$repo"
done

# --- 3. A .py file under an allowed tree (.claude/, scripts/) passes --------
repo="$(make_repo)"
printf '# fine\n' > "$repo/.claude/scripts/tool.py"
printf '# fine\n' > "$repo/scripts/tool.py"
git -C "$repo" add .claude/scripts/tool.py scripts/tool.py
git -C "$repo" commit --quiet -m "allowed python"
run_checker "$repo"
if [ "$RC" -eq 0 ]; then
    pass "ignores .py files under .claude/ and scripts/ (no false positive)"
else
    fail ".py under .claude/ and scripts/ should not trip the gate (rc=$RC, stderr: $STDERR)"
fi
rm -rf "$repo"

# --- 4. The gate fails closed when it cannot scan ---------------------------
nonrepo="$(mktemp -d)"
mkdir -p "$nonrepo/pkg"
printf '# rogue\n' > "$nonrepo/pkg/rogue.py"
run_checker "$nonrepo"
if [ "$RC" -eq 2 ]; then
    pass "fails closed (exit 2) outside a git work tree"
else
    fail "outside a git work tree the gate must fail closed with exit 2 (rc=$RC)"
fi
rm -rf "$nonrepo"

echo ""
echo "Passed: $PASS  Failed: $FAIL"
[ "$FAIL" -eq 0 ] || exit 1
echo "✅ check-no-python-in-core.sh tests passed"
