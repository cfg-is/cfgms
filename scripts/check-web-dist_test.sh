#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# Tests for scripts/check-web-dist.sh (Issue #3043).
#
# The checker is the enforcement half of the web/dist placeholder rule, called by
# both the pre-commit hook and Frontend CI. A checker that silently stopped
# rejecting built output would leave the A6.3 review bypass open with a green
# check, so its rejection paths are tested here rather than assumed.
#
# Each case runs in a throwaway git repository so nothing touches the real tree.
#
# Usage: bash scripts/check-web-dist_test.sh

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECKER="$REPO_ROOT/scripts/check-web-dist.sh"

PLACEHOLDER='<!doctype html>
<!--
  CFGMS_DIST_PLACEHOLDER
  tracked placeholder, not a build
-->
<html lang="en"><head><title>CFGMS</title></head><body><div id="root"></div></body></html>'

BUILT_OUTPUT='<!doctype html>
<html lang="en"><head>
<script type="module" crossorigin src="/assets/index-Dx_A5HW-.js"></script>
<link rel="stylesheet" crossorigin href="/assets/index-B6kDu8Ni.css">
</head><body><div id="root"></div></body></html>'

PASS=0
FAIL=0

# make_repo creates a throwaway repo containing the tracked placeholder and
# echoes its path.
make_repo() {
    local dir
    dir="$(mktemp -d)"
    git -C "$dir" init --quiet
    git -C "$dir" config user.email "test@example.com"
    git -C "$dir" config user.name "test"
    mkdir -p "$dir/web/dist" "$dir/scripts"
    printf '%s\n' "$PLACEHOLDER" > "$dir/web/dist/index.html"
    printf 'dist/*\n!dist/index.html\n' > "$dir/web/.gitignore"
    git -C "$dir" add web/dist/index.html web/.gitignore
    git -C "$dir" commit --quiet -m "initial"
    printf '%s' "$dir"
}

# expect <want_rc> <description> <repo> [--staged]
expect() {
    local want_rc="$1" desc="$2" repo="$3" mode="${4:-}"
    local got_rc
    ( cd "$repo" && bash "$CHECKER" $mode ) >/dev/null 2>&1
    got_rc=$?
    if [ "$got_rc" -eq "$want_rc" ]; then
        echo "  ✅ $desc"
        PASS=$((PASS + 1))
    else
        echo "  ❌ $desc (want rc=$want_rc, got rc=$got_rc)"
        FAIL=$((FAIL + 1))
    fi
    rm -rf "$repo"
}

echo "🧪 scripts/check-web-dist.sh"
echo "============================"

# 1. The tracked placeholder alone is clean, in both modes.
repo="$(make_repo)"
expect 0 "accepts the tracked placeholder (committed mode)" "$repo"

repo="$(make_repo)"
expect 0 "accepts a commit that stages nothing under web/dist (staged mode)" "$repo" --staged

# 2. Built output staged over the placeholder is rejected.
repo="$(make_repo)"
printf '%s\n' "$BUILT_OUTPUT" > "$repo/web/dist/index.html"
git -C "$repo" add web/dist/index.html
expect 1 "rejects built output staged as the placeholder (staged mode)" "$repo" --staged

# 3. Built output already committed is rejected — this is the --no-verify path
#    that CI has to catch.
repo="$(make_repo)"
printf '%s\n' "$BUILT_OUTPUT" > "$repo/web/dist/index.html"
git -C "$repo" add web/dist/index.html
git -C "$repo" commit --quiet -m "bypassed the hook"
expect 1 "rejects built output already committed (committed mode)" "$repo"

# 4. Any other tracked file under web/dist/ is built output.
repo="$(make_repo)"
mkdir -p "$repo/web/dist/app/assets"
echo "// hashed asset" > "$repo/web/dist/app/assets/index-BP9FLgsC.js"
git -C "$repo" add -f web/dist/app/assets/index-BP9FLgsC.js
git -C "$repo" commit --quiet -m "committed an asset"
expect 1 "rejects extra tracked files under web/dist/" "$repo"

# 5. A missing placeholder breaks //go:embed all:dist — also a failure.
repo="$(make_repo)"
git -C "$repo" rm --quiet web/dist/index.html
git -C "$repo" commit --quiet -m "removed the placeholder"
expect 1 "rejects a missing placeholder" "$repo"

# 6. An unrelated commit must not be blocked by an unstaged local build.
#    Developers run npm run build constantly; only staged content is the hook's
#    business.
repo="$(make_repo)"
printf '%s\n' "$BUILT_OUTPUT" > "$repo/web/dist/index.html"   # dirty, NOT staged
echo "unrelated" > "$repo/scripts/other.sh"
git -C "$repo" add scripts/other.sh
expect 0 "ignores an unstaged dirty placeholder (staged mode)" "$repo" --staged

echo ""
echo "Passed: $PASS  Failed: $FAIL"
[ "$FAIL" -eq 0 ] || exit 1
echo "✅ check-web-dist.sh tests passed"
