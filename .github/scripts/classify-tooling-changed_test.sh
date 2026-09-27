#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# Tests for .github/scripts/classify-tooling-changed.sh (Issue #4304, Epic
# #4296).
#
# The wrapper's own job is small -- validate its two reused/derived inputs,
# then delegate to scripts/lib/detect-tooling-changed.sh (whose own fixture
# suite, detect-tooling-changed_test.sh, covers the actual classification
# behavior). These tests cover the wrapper's fail-closed input handling and
# one successful delegation, using real throwaway git repositories (mktemp -d
# + git init, real commits, real `git diff`) so nothing touches the real tree
# and no case is mocked.
#
# Usage: bash .github/scripts/classify-tooling-changed_test.sh

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WRAPPER="$REPO_ROOT/.github/scripts/classify-tooling-changed.sh"
ALL_GROUPS="groups=core,security-review,claude-tooling,devinfra"

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

# make_repo creates a throwaway repo with the real detector script vendored
# in at its expected relative path, plus one committed baseline file, and
# echoes its path. Callers commit further changes on top and diff against the
# baseline commit.
make_repo() {
    local dir
    dir="$(mktemp -d)"
    git -C "$dir" init --quiet
    git -C "$dir" config user.email "test@example.com"
    git -C "$dir" config user.name "test"
    mkdir -p "$dir/scripts/lib" "$dir/pkg"
    cp "$REPO_ROOT/scripts/lib/detect-tooling-changed.sh" "$dir/scripts/lib/detect-tooling-changed.sh"
    chmod +x "$dir/scripts/lib/detect-tooling-changed.sh"
    echo "placeholder" > "$dir/pkg/placeholder.go"
    git -C "$dir" add pkg scripts
    git -C "$dir" commit --quiet -m "initial"
    printf '%s' "$dir"
}

commit_change() {
    local repo="$1" path="$2"
    mkdir -p "$(dirname "$repo/$path")"
    echo "change" > "$repo/$path"
    git -C "$repo" add "$path"
    git -C "$repo" commit --quiet -m "change $path"
}

# run_wrapper <changed-files-txt> <base-ref> <repo-root> -- sets RC/STDOUT.
run_wrapper() {
    local out
    out="$(mktemp)"
    bash "$WRAPPER" "$1" "$2" "$3" > "$out" 2>&1
    RC=$?
    STDOUT="$(cat "$out")"
    rm -f "$out"
}

last_line() {
    printf '%s\n' "$1" | tail -n 1
}

echo "🧪 .github/scripts/classify-tooling-changed.sh"
echo "==============================================="

# --- 1. missing changed-files argument resolves every group -----------------
repo="$(make_repo)"
base="$(git -C "$repo" rev-parse HEAD)"
run_wrapper "/nonexistent/changed_files.txt" "$base" "$repo"
line="$(last_line "$STDOUT")"
if [ "$RC" -eq 0 ] && [ "$line" = "$ALL_GROUPS" ]; then
    pass "missing changed-files list resolves every suite group (fail closed)"
else
    fail "missing changed-files list should resolve every group (rc=$RC, got: $line)"
fi
rm -rf "$repo"

# --- 2. empty changed-files list resolves every group ------------------------
repo="$(make_repo)"
base="$(git -C "$repo" rev-parse HEAD)"
empty_file="$(mktemp)"
: > "$empty_file"
run_wrapper "$empty_file" "$base" "$repo"
line="$(last_line "$STDOUT")"
if [ "$RC" -eq 0 ] && [ "$line" = "$ALL_GROUPS" ]; then
    pass "empty changed-files list resolves every suite group (fail closed)"
else
    fail "empty changed-files list should resolve every group (rc=$RC, got: $line)"
fi
rm -f "$empty_file"
rm -rf "$repo"

# --- 3. missing base ref resolves every group --------------------------------
repo="$(make_repo)"
files="$(mktemp)"
echo "pkg/storage/storage.go" > "$files"
run_wrapper "$files" "" "$repo"
line="$(last_line "$STDOUT")"
if [ "$RC" -eq 0 ] && [ "$line" = "$ALL_GROUPS" ]; then
    pass "missing base ref resolves every suite group (fail closed)"
else
    fail "missing base ref should resolve every group (rc=$RC, got: $line)"
fi
rm -f "$files"
rm -rf "$repo"

# --- 4. missing repo root resolves every group -------------------------------
files="$(mktemp)"
echo "pkg/storage/storage.go" > "$files"
run_wrapper "$files" "HEAD" "/nonexistent/repo/root/for-classify-tooling-test"
line="$(last_line "$STDOUT")"
if [ "$RC" -eq 0 ] && [ "$line" = "$ALL_GROUPS" ]; then
    pass "missing repo root resolves every suite group (fail closed)"
else
    fail "missing repo root should resolve every group (rc=$RC, got: $line)"
fi
rm -f "$files"

# --- 5. missing detector script resolves every group -------------------------
repo="$(mktemp -d)"
git -C "$repo" init --quiet
git -C "$repo" config user.email "test@example.com"
git -C "$repo" config user.name "test"
echo "placeholder" > "$repo/placeholder.go"
git -C "$repo" add placeholder.go
git -C "$repo" commit --quiet -m "initial"
base="$(git -C "$repo" rev-parse HEAD)"
files="$(mktemp)"
echo "pkg/storage/storage.go" > "$files"
run_wrapper "$files" "$base" "$repo"
line="$(last_line "$STDOUT")"
if [ "$RC" -eq 0 ] && [ "$line" = "$ALL_GROUPS" ]; then
    pass "missing detector script resolves every suite group (fail closed)"
else
    fail "missing detector script should resolve every group (rc=$RC, got: $line)"
fi
rm -f "$files"
rm -rf "$repo"

# --- 6. successful delegation: narrow diff resolves the narrow group --------
repo="$(make_repo)"
base="$(git -C "$repo" rev-parse HEAD)"
commit_change "$repo" ".claude/skills/security-review/notes.md"
files="$(mktemp)"
echo ".claude/skills/security-review/notes.md" > "$files"
run_wrapper "$files" "$base" "$repo"
line="$(last_line "$STDOUT")"
if [ "$RC" -eq 0 ] && [ "$line" = "groups=core,security-review" ]; then
    pass "successful delegation narrows to the group the diff actually touched"
else
    fail "successful delegation should narrow groups (rc=$RC, got: $line)"
fi
rm -f "$files"
rm -rf "$repo"

# --- 7. successful delegation: non-tooling diff resolves core only ----------
repo="$(make_repo)"
base="$(git -C "$repo" rev-parse HEAD)"
commit_change "$repo" "pkg/storage/storage.go"
files="$(mktemp)"
echo "pkg/storage/storage.go" > "$files"
run_wrapper "$files" "$base" "$repo"
line="$(last_line "$STDOUT")"
if [ "$RC" -eq 0 ] && [ "$line" = "groups=core" ]; then
    pass "successful delegation resolves groups=core only for a non-tooling diff"
else
    fail "successful delegation should resolve groups=core only (rc=$RC, got: $line)"
fi
rm -f "$files"
rm -rf "$repo"

echo ""
echo "Passed: $PASS  Failed: $FAIL"
[ "$FAIL" -eq 0 ] || exit 1
echo "✅ classify-tooling-changed.sh tests passed"
