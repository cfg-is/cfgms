#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# check-web-dist.sh — enforce the web/dist placeholder rule (Issue #3043)
#
# Real Vite output must never be committed: it bypasses source review (security
# A6.3) and, because every build produces different content hashes, any two web
# branches collide on the entry point. Vite writes to web/dist/app/, which
# web/.gitignore excludes wholesale, so the only tracked file under web/dist/ is
# the static placeholder web/dist/index.html.
#
# This script is the single implementation of that rule. It is called by the
# pre-commit hook (--staged, validating what is about to be committed) and by
# Frontend CI (default, validating what is committed) so the check survives
# --no-verify and containers with no hooks installed.
#
# Usage:
#   ./scripts/check-web-dist.sh            # validate committed/worktree content
#   ./scripts/check-web-dist.sh --staged   # validate staged content (pre-commit)
#
# Exit codes: 0 = clean, 1 = violation.

set -uo pipefail

MODE="committed"
if [ "${1:-}" = "--staged" ]; then
    MODE="staged"
fi

PLACEHOLDER_FILE="web/dist/index.html"
SENTINEL="CFGMS_DIST_PLACEHOLDER"

fail() {
    echo "❌ Built web output must never be committed (Issue #3043)"
    echo ""
    echo "$1"
    echo ""
    echo "Rule (web/.gitignore): Vite builds into web/dist/app/, which is ignored."
    echo "The only tracked file under web/dist/ is the static placeholder"
    echo "$PLACEHOLDER_FILE, which must carry the $SENTINEL sentinel and must"
    echo "never contain content-hashed asset references."
    echo ""
    if [ "$MODE" = "staged" ]; then
        echo "To unstage the built output and restore the placeholder:"
        echo "    git restore --staged web/dist/"
        echo "    git checkout -- $PLACEHOLDER_FILE"
    else
        echo "To restore the placeholder:"
        echo "    git checkout origin/develop -- $PLACEHOLDER_FILE"
        echo "    git rm --cached <any other tracked file under web/dist/>"
    fi
    exit 1
}

# --- 1. Only the placeholder may be tracked/staged under web/dist/ ------------
if [ "$MODE" = "staged" ]; then
    dist_paths=$(git diff --cached --name-only --diff-filter=ACM -- web/dist 2>/dev/null)
else
    dist_paths=$(git ls-files web/dist 2>/dev/null)
fi

unexpected=$(printf '%s\n' "$dist_paths" | grep -v '^$' | grep -vFx "$PLACEHOLDER_FILE")
if [ -n "$unexpected" ]; then
    fail "These files under web/dist/ are built output and must not be committed:
$(printf '%s\n' "$unexpected" | sed 's/^/    /')"
fi

# --- 2. The placeholder must still be the placeholder -------------------------
# In --staged mode, only validate content when the file is actually staged;
# an unrelated commit must not be blocked by a dirty worktree copy.
content=""
if [ "$MODE" = "staged" ]; then
    if printf '%s\n' "$dist_paths" | grep -qFx "$PLACEHOLDER_FILE"; then
        content=$(git show ":$PLACEHOLDER_FILE" 2>/dev/null)
    else
        exit 0
    fi
else
    if [ ! -f "$PLACEHOLDER_FILE" ]; then
        fail "$PLACEHOLDER_FILE is missing. It is required: //go:embed all:dist in
web/embed.go needs a file present for \`go build\` to work with no frontend build."
    fi
    content=$(cat "$PLACEHOLDER_FILE")
fi

if ! printf '%s' "$content" | grep -qF "$SENTINEL"; then
    fail "$PLACEHOLDER_FILE no longer carries the $SENTINEL sentinel — it looks like
real build output. The controller uses that sentinel to refuse to serve a
placeholder as if it were the application."
fi

if printf '%s' "$content" | grep -qE '(src|href)="/assets/'; then
    fail "$PLACEHOLDER_FILE contains content-hashed asset references (/assets/...),
which only a Vite build produces."
fi

echo "✅ web/dist placeholder intact (${MODE} content)"
exit 0
