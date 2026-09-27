#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# Tests for scripts/lib/detect-tooling-changed.sh (Issue #4302, Epic #4296).
#
# The gate decides which of the four suite groups (core, security-review,
# claude-tooling, devinfra) a diff must run, always including core, and fails
# closed to every group on any input defect. Every fixture is a throwaway git
# repository (mktemp -d + git init, real commits, real `git diff`) so nothing
# touches the real tree and no case is mocked.
#
# Usage: bash scripts/lib/detect-tooling-changed_test.sh

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DETECTOR="$REPO_ROOT/scripts/lib/detect-tooling-changed.sh"

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

# make_repo creates a throwaway repo with one committed baseline file and
# echoes its path. Callers commit further changes on top and diff against the
# baseline commit (captured separately via `git -C "$dir" rev-parse HEAD`).
make_repo() {
    local dir
    dir="$(mktemp -d)"
    git -C "$dir" init --quiet
    git -C "$dir" config user.email "test@example.com"
    git -C "$dir" config user.name "test"
    mkdir -p "$dir/scripts/lib" "$dir/pkg"
    echo "placeholder" > "$dir/pkg/placeholder.go"
    git -C "$dir" add pkg
    git -C "$dir" commit --quiet -m "initial"
    printf '%s' "$dir"
}

# run_detector <repo> <base-ref> -- runs the gate, setting RC/STDOUT.
run_detector() {
    local repo="$1" base_ref="$2" out
    out="$(mktemp)"
    ( cd "$repo" && bash "$DETECTOR" "$base_ref" ) > "$out" 2>&1
    RC=$?
    STDOUT="$(cat "$out")"
    rm -f "$out"
}

# last_line extracts the final `groups=...` line from detector stdout.
last_line() {
    printf '%s\n' "$1" | tail -n 1
}

# commit_change <repo> <path> -- writes a placeholder file at <path> (creating
# parent dirs) and commits it.
commit_change() {
    local repo="$1" path="$2"
    mkdir -p "$(dirname "$repo/$path")"
    echo "change" > "$repo/$path"
    git -C "$repo" add "$path"
    git -C "$repo" commit --quiet -m "change $path"
}

echo "🧪 scripts/lib/detect-tooling-changed.sh"
echo "========================================"

# --- 1. security-review tree only ------------------------------------------
repo="$(make_repo)"
base="$(git -C "$repo" rev-parse HEAD)"
commit_change "$repo" ".claude/skills/security-review/notes.md"
run_detector "$repo" "$base"
line="$(last_line "$STDOUT")"
if [ "$RC" -eq 0 ] && [ "$line" = "groups=core,security-review" ]; then
    pass "security-review tree change resolves groups=core,security-review only"
else
    fail "security-review tree change should resolve groups=core,security-review (rc=$RC, got: $line)"
fi
rm -rf "$repo"

# --- 2. claude-tooling tree only (excludes security-review) ----------------
repo="$(make_repo)"
base="$(git -C "$repo" rev-parse HEAD)"
commit_change "$repo" ".claude/agents/po.md"
run_detector "$repo" "$base"
line="$(last_line "$STDOUT")"
if [ "$RC" -eq 0 ] && [ "$line" = "groups=core,claude-tooling" ]; then
    pass "claude-tooling tree change resolves groups=core,claude-tooling only"
else
    fail "claude-tooling tree change should resolve groups=core,claude-tooling (rc=$RC, got: $line)"
fi
rm -rf "$repo"

# --- 3. security-review is excluded from claude-tooling --------------------
repo="$(make_repo)"
base="$(git -C "$repo" rev-parse HEAD)"
commit_change "$repo" ".claude/skills/security-review/harness.py"
run_detector "$repo" "$base"
line="$(last_line "$STDOUT")"
if [ "$RC" -eq 0 ] && [ "$line" = "groups=core,security-review" ]; then
    pass "security-review path does not also trigger claude-tooling"
else
    fail "security-review path must not trigger claude-tooling (rc=$RC, got: $line)"
fi
rm -rf "$repo"

# --- 4. devinfra tree only (.github/scripts/) -------------------------------
repo="$(make_repo)"
base="$(git -C "$repo" rev-parse HEAD)"
commit_change "$repo" ".github/scripts/some-gate.sh"
run_detector "$repo" "$base"
line="$(last_line "$STDOUT")"
if [ "$RC" -eq 0 ] && [ "$line" = "groups=core,devinfra" ]; then
    pass ".github/scripts/ change resolves groups=core,devinfra only"
else
    fail ".github/scripts/ change should resolve groups=core,devinfra (rc=$RC, got: $line)"
fi
rm -rf "$repo"

# --- 5. devinfra tree only (.devcontainer/) ---------------------------------
repo="$(make_repo)"
base="$(git -C "$repo" rev-parse HEAD)"
commit_change "$repo" ".devcontainer/devcontainer.json"
run_detector "$repo" "$base"
line="$(last_line "$STDOUT")"
if [ "$RC" -eq 0 ] && [ "$line" = "groups=core,devinfra" ]; then
    pass ".devcontainer/ change resolves groups=core,devinfra only"
else
    fail ".devcontainer/ change should resolve groups=core,devinfra (rc=$RC, got: $line)"
fi
rm -rf "$repo"

# --- 6. non-tooling trees only (pkg/, cmd/, features/, web/, api/) ----------
repo="$(make_repo)"
base="$(git -C "$repo" rev-parse HEAD)"
commit_change "$repo" "pkg/storage/storage.go"
commit_change "$repo" "cmd/steward/main.go"
commit_change "$repo" "features/controller/handler.go"
commit_change "$repo" "web/src/app.tsx"
commit_change "$repo" "api/proto/foo.proto"
run_detector "$repo" "$base"
line="$(last_line "$STDOUT")"
if [ "$RC" -eq 0 ] && [ "$line" = "groups=core" ]; then
    pass "pkg/cmd/features/web/api-only changes resolve groups=core only"
else
    fail "non-tooling trees should resolve groups=core only (rc=$RC, got: $line)"
fi
rm -rf "$repo"

# --- 7. gating machinery change forces every group (scripts/test-scripts.sh) ---
repo="$(make_repo)"
base="$(git -C "$repo" rev-parse HEAD)"
commit_change "$repo" "scripts/test-scripts.sh"
commit_change "$repo" "pkg/storage/storage.go"
run_detector "$repo" "$base"
line="$(last_line "$STDOUT")"
if [ "$RC" -eq 0 ] && [ "$line" = "groups=core,security-review,claude-tooling,devinfra" ]; then
    pass "scripts/test-scripts.sh change forces every suite group"
else
    fail "scripts/test-scripts.sh change should force every group (rc=$RC, got: $line)"
fi
rm -rf "$repo"

# --- 8. gating machinery change forces every group (Makefile) ---------------
repo="$(make_repo)"
base="$(git -C "$repo" rev-parse HEAD)"
commit_change "$repo" "Makefile"
run_detector "$repo" "$base"
line="$(last_line "$STDOUT")"
if [ "$RC" -eq 0 ] && [ "$line" = "groups=core,security-review,claude-tooling,devinfra" ]; then
    pass "Makefile change forces every suite group"
else
    fail "Makefile change should force every group (rc=$RC, got: $line)"
fi
rm -rf "$repo"

# --- 9. gating machinery change forces every group (test-suite.yml) --------
repo="$(make_repo)"
base="$(git -C "$repo" rev-parse HEAD)"
commit_change "$repo" ".github/workflows/test-suite.yml"
run_detector "$repo" "$base"
line="$(last_line "$STDOUT")"
if [ "$RC" -eq 0 ] && [ "$line" = "groups=core,security-review,claude-tooling,devinfra" ]; then
    pass ".github/workflows/test-suite.yml change forces every suite group"
else
    fail ".github/workflows/test-suite.yml change should force every group (rc=$RC, got: $line)"
fi
rm -rf "$repo"

# --- 10. mixed diff resolves the union --------------------------------------
repo="$(make_repo)"
base="$(git -C "$repo" rev-parse HEAD)"
commit_change "$repo" ".claude/skills/security-review/notes.md"
commit_change "$repo" ".claude/agents/po.md"
commit_change "$repo" ".github/scripts/some-gate.sh"
commit_change "$repo" "pkg/storage/storage.go"
run_detector "$repo" "$base"
line="$(last_line "$STDOUT")"
if [ "$RC" -eq 0 ] && [ "$line" = "groups=core,security-review,claude-tooling,devinfra" ]; then
    pass "mixed diff resolves the union of matched groups"
else
    fail "mixed diff should resolve the union of matched groups (rc=$RC, got: $line)"
fi
rm -rf "$repo"

# --- 11. missing/invalid base ref resolves every group ----------------------
repo="$(make_repo)"
run_detector "$repo" "this-ref-does-not-exist"
line="$(last_line "$STDOUT")"
if [ "$RC" -eq 0 ] && [ "$line" = "groups=core,security-review,claude-tooling,devinfra" ]; then
    pass "invalid base ref resolves every suite group (fail closed)"
else
    fail "invalid base ref should resolve every group (rc=$RC, got: $line)"
fi
rm -rf "$repo"

# --- 12. empty base ref argument resolves every group -----------------------
repo="$(make_repo)"
out="$(cd "$repo" && bash "$DETECTOR" "" 2>&1)"
rc=$?
line="$(printf '%s\n' "$out" | tail -n 1)"
if [ "$rc" -eq 0 ] && [ "$line" = "groups=core,security-review,claude-tooling,devinfra" ]; then
    pass "empty base ref resolves every suite group (fail closed)"
else
    fail "empty base ref should resolve every group (rc=$rc, got: $line)"
fi
rm -rf "$repo"

# --- 13. unreadable repo root resolves every group --------------------------
out="$(bash "$DETECTOR" "HEAD" "/nonexistent/repo/root/for-detect-tooling-test" 2>&1)"
rc=$?
line="$(printf '%s\n' "$out" | tail -n 1)"
if [ "$rc" -eq 0 ] && [ "$line" = "groups=core,security-review,claude-tooling,devinfra" ]; then
    pass "unreadable repo root resolves every suite group (fail closed)"
else
    fail "unreadable repo root should resolve every group (rc=$rc, got: $line)"
fi

# --- 14. no commits ahead of base ref, clean working tree -> core only -----
repo="$(make_repo)"
base="$(git -C "$repo" rev-parse HEAD)"
run_detector "$repo" "$base"
line="$(last_line "$STDOUT")"
if [ "$RC" -eq 0 ] && [ "$line" = "groups=core" ]; then
    pass "no commits ahead of base ref, clean tree, resolves groups=core only"
else
    fail "clean tree with no commits ahead should resolve groups=core only (rc=$RC, got: $line)"
fi
rm -rf "$repo"

# --- 15. no commits ahead of base ref, but working tree carries a change --
# Staged-but-uncommitted, not merely written to disk: `git diff <base-ref>`
# only sees a new path once it is in the index (plain `git diff`, unlike
# `git status`, never reports untracked files).
repo="$(make_repo)"
base="$(git -C "$repo" rev-parse HEAD)"
mkdir -p "$repo/.claude/agents"
echo "uncommitted" > "$repo/.claude/agents/po.md"
git -C "$repo" add ".claude/agents/po.md"
run_detector "$repo" "$base"
line="$(last_line "$STDOUT")"
if [ "$RC" -eq 0 ] && [ "$line" = "groups=core,claude-tooling" ]; then
    pass "uncommitted working-tree change is seen when HEAD has no commits ahead of base"
else
    fail "uncommitted working-tree change should be classified (rc=$RC, got: $line)"
fi
rm -rf "$repo"

echo ""
echo "Passed: $PASS  Failed: $FAIL"
[ "$FAIL" -eq 0 ] || exit 1
echo "✅ detect-tooling-changed.sh tests passed"
