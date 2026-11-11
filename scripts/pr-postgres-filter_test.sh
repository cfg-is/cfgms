#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# Tests for scripts/pr-postgres-filter.sh (Issue #6133).
#
# Covers: each trigger path yields postgres=true (including a nested file, a
# migration and a rename out of a trigger path); docs-only and unrelated pkg/
# files yield postgres=false (including look-alike prefixes); and every defect
# in the input (missing, unreadable, empty, blank-only list, unreadable
# --renamed list, no or unknown arguments) fails closed to postgres=true.
#
# Usage: bash scripts/pr-postgres-filter_test.sh

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FILTER="$REPO_ROOT/scripts/pr-postgres-filter.sh"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

PASS=0
FAIL=0

# expect <name> <expected-output> <filter args...>
expect() {
    local name="$1" want="$2" got
    shift 2
    got="$(bash "$FILTER" "$@" 2>/dev/null)"
    if [ "$got" = "$want" ]; then
        echo "  ✅ $name"
        PASS=$((PASS + 1))
    else
        echo "  ❌ $name: want '$want', got '$got'"
        FAIL=$((FAIL + 1))
    fi
}

# list <name> <line...> writes a changed-file list and echoes its path.
list() {
    local f="$work/$1.txt"
    shift
    printf '%s\n' "$@" > "$f"
    printf '%s' "$f"
}

echo "trigger paths -> postgres=true"
expect "database provider file" postgres=true \
    --files "$(list t1 pkg/storage/providers/database/provider.go)"
expect "database provider nested migration" postgres=true \
    --files "$(list t2 pkg/storage/providers/database/migrations/0042_add_x.sql)"
expect "storage interfaces file" postgres=true \
    --files "$(list t3 pkg/storage/interfaces/store.go)"
expect "schema-compat script" postgres=true \
    --files "$(list t4 scripts/check-schema-compat.sh)"
expect "schema-compat test script" postgres=true \
    --files "$(list t5 scripts/check-schema-compat_test.sh)"
expect "trigger file among unrelated files" postgres=true \
    --files "$(list t6 docs/README.md cmd/steward/main.go pkg/storage/providers/database/x_test.go)"
expect "rename out of a trigger path" postgres=true \
    --files "$(list t7 pkg/storage/providers/other/moved.go)" \
    --renamed "$(list t7r pkg/storage/providers/database/moved.go)"

echo "unrelated files -> postgres=false"
expect "docs only" postgres=false \
    --files "$(list f1 docs/architecture/storage-architecture.md README.md)"
expect "unrelated pkg file" postgres=false \
    --files "$(list f2 pkg/cert/manager.go)"
expect "sibling storage provider" postgres=false \
    --files "$(list f3 pkg/storage/providers/sqlite/store.go)"
expect "look-alike prefix databaseX" postgres=false \
    --files "$(list f4 pkg/storage/providers/databasex/a.go)"
expect "look-alike prefix interfaces2" postgres=false \
    --files "$(list f5 pkg/storage/interfaces2/a.go)"
expect "unrelated script" postgres=false \
    --files "$(list f6 scripts/check-no-python-in-core.sh)"
expect "path only mentioned mid-line" postgres=false \
    --files "$(list f7 docs/pkg/storage/interfaces/notes.md)"
expect "workflow-only change" postgres=false \
    --files "$(list f8 .github/workflows/cross-platform-build-pr.yml scripts/pr-postgres-filter.sh)"
expect "unrelated rename" postgres=false \
    --files "$(list f9 pkg/b/new.go)" --renamed "$(list f9r pkg/a/old.go)"

echo "fail closed -> postgres=true"
: > "$work/empty.txt"
printf '\n  \n\n' > "$work/blank.txt"
expect "empty list" postgres=true --files "$work/empty.txt"
expect "blank-only list" postgres=true --files "$work/blank.txt"
expect "missing list" postgres=true --files "$work/does-not-exist.txt"
expect "directory as list" postgres=true --files "$work"
expect "no arguments" postgres=true
expect "--files without value" postgres=true --files
expect "unknown argument" postgres=true --bogus "$work/empty.txt"
expect "unreadable --renamed list" postgres=true \
    --files "$(list u1 docs/a.md)" --renamed "$work/does-not-exist.txt"
if [ "$(id -u)" -ne 0 ]; then
    unreadable="$(list u2 pkg/cert/manager.go)"
    chmod 000 "$unreadable"
    expect "unreadable list (mode 000)" postgres=true --files "$unreadable"
    chmod 600 "$unreadable"
else
    # Root reads mode-000 files, so the case cannot be constructed.
    echo "  (skipped: unreadable-by-mode case needs a non-root user)"
fi

echo ""
echo "passed: $PASS, failed: $FAIL"
[ "$FAIL" -eq 0 ]
