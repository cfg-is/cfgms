#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# Tests for scripts/check-schema-compat.sh (Issue #6097, Epic #5978).
#
# Builds two `git worktree`s of the current commit as the base and head trees,
# patches them (the patches touch only those temporary trees, never the
# repository tree) and runs the real check against the real test Postgres:
#
#   1. a head that drops a column the base code reads      -> direction A FAIL, exit 1
#   2. a head that adds a nullable column                  -> both PASS, exit 0
#   3. a base without the keep-schema mode                 -> NOT RUN, exit 2
#   4. an unreachable database                             -> NOT RUN, exit 2
#   5. a base whose suite drops a table                    -> FAIL: suite rebuilt the schema
#   6. every database test skipped (-short)                -> NOT RUN, exit 2
#   7. a suite in which no store test passes               -> NOT RUN, exit 2
#   8. psql missing from PATH                              -> NOT RUN, exit 2
#
# Each run is narrowed with CFGMS_SCHEMA_COMPAT_TEST_RUN to the node registry and
# config store tests, because the check runs several times here.
#
# Needs psql, go, jq and git on PATH and the Postgres test service, with the
# CFGMS_TEST_DB_* variables exported (.env.test). Unlike the fixture-only suites
# under scripts/, it therefore runs in the postgres-integration job of
# .github/workflows/cross-platform-build.yml, not from scripts/test-scripts.sh.
# It fails, never skips, when its preconditions are missing.
#
# Usage: bash scripts/check-schema-compat_test.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECKER="$REPO_ROOT/scripts/check-schema-compat.sh"
PKG_REL="pkg/storage/providers/database"

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

for tool in psql go jq git; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "ERROR: $tool is required on PATH" >&2
        exit 1
    fi
done
if [[ -z "${CFGMS_TEST_DB_PASSWORD:-}" ]]; then
    echo "ERROR: CFGMS_TEST_DB_PASSWORD is not set (source .env.test with set -a)" >&2
    exit 1
fi

# The narrow suite: node registry and config store tests.
NARROW_RUN='TestDatabaseNodeRegistryStore_|TestDatabaseConfigStore_'

TMP="$(mktemp -d)"
BASE="$TMP/base"
HEAD="$TMP/head"
cleanup() {
    local wt
    for wt in "$BASE" "$HEAD"; do
        git -C "$REPO_ROOT" worktree remove --force "$wt" >/dev/null 2>&1 || true
    done
    git -C "$REPO_ROOT" worktree prune >/dev/null 2>&1 || true
    rm -rf "$TMP"
}
trap cleanup EXIT

git -C "$REPO_ROOT" worktree add --detach "$BASE" HEAD >/dev/null 2>&1
git -C "$REPO_ROOT" worktree add --detach "$HEAD" HEAD >/dev/null 2>&1

# restore_trees puts both worktrees back to the commit.
restore_trees() {
    local wt
    for wt in "$BASE" "$HEAD"; do
        git -C "$wt" checkout --quiet -- .
        git -C "$wt" clean --quiet -fd
    done
}

# insert_after_anchor <tree> <statement>: add a SQL statement to
# CreateNodeRegistryTable, after its last ALTER TABLE line. Fails the run when the
# anchor is gone, so a drifted anchor is loud rather than a silently unpatched pass.
ANCHOR='ADD COLUMN IF NOT EXISTS started_at TIMESTAMP WITH TIME ZONE;'
insert_after_anchor() {
    local tree="$1" statement="$2" file="$1/$PKG_REL/schemas.go"
    if [[ "$(grep -cF "$ANCHOR" "$file")" -ne 1 ]]; then
        echo "ERROR: patch anchor not found exactly once in $file" >&2
        exit 1
    fi
    awk -v anchor="$ANCHOR" -v add="$statement" \
        '{ print } index($0, anchor) { print "\t\t" add }' "$file" >"$file.patched"
    mv "$file.patched" "$file"
    if ! grep -qF "$statement" "$file"; then
        echo "ERROR: patch did not apply to $file" >&2
        exit 1
    fi
}

# run_check [VAR=value ...]: run the check on the two worktrees. Sets
# RC and OUT (stdout and stderr together).
RC=0
OUT=""
run_check() {
    RC=0
    OUT="$(env CFGMS_SCHEMA_COMPAT_TEST_RUN="$NARROW_RUN" "$@" \
        "$CHECKER" --base-dir "$BASE" --head-dir "$HEAD" 2>&1)" || RC=$?
}

expect_rc() {
    local want="$1" label="$2"
    if [[ "$RC" -eq "$want" ]]; then
        pass "$label: exit $want"
    else
        fail "$label: want exit $want, got $RC"
        echo "$OUT" | tail -n 30 | sed 's/^/      /'
    fi
}

expect_out() {
    local needle="$1" label="$2"
    if grep -qF -- "$needle" <<<"$OUT"; then
        pass "$label: prints '$needle'"
    else
        fail "$label: output lacks '$needle'"
        echo "$OUT" | tail -n 30 | sed 's/^/      /'
    fi
}

echo "🧪 scripts/check-schema-compat.sh"
echo "=================================="

# --- 1. breaking head: drops a column the base code reads ------------------
echo "case 1: head drops a column the base revision's stores read"
restore_trees
# `address` rather than `version`: the base code's own CreateNodeRegistryTable
# re-adds `version` with ADD COLUMN IF NOT EXISTS, which would mask the drop.
insert_after_anchor "$HEAD" 'ALTER TABLE cfgms_node_registry DROP COLUMN address;'
run_check
expect_rc 1 "breaking head"
expect_out "A (base code, head schema): FAIL" "breaking head"
expect_out "failing tests" "breaking head"

# --- 2. expand-only head: adds a nullable column ---------------------------
echo "case 2: head adds a nullable column"
restore_trees
insert_after_anchor "$HEAD" 'ALTER TABLE cfgms_node_registry ADD COLUMN IF NOT EXISTS compat_probe TEXT;'
run_check
expect_rc 0 "expand-only head"
expect_out "A (base code, head schema): PASS" "expand-only head"
expect_out "B (head code, base schema): PASS" "expand-only head"

# --- 3. base revision without keep-schema mode -----------------------------
echo "case 3: base revision lacks the keep-schema mode"
restore_trees
sed -i 's/"CFGMS_TEST_KEEP_SCHEMA"/"CFGMS_TEST_NO_SUCH_MODE"/' "$BASE/$PKG_REL"/*_test.go
if grep -qF '"CFGMS_TEST_KEEP_SCHEMA"' "$BASE/$PKG_REL"/*_test.go; then
    echo "ERROR: keep-schema patch did not apply" >&2
    exit 1
fi
run_check
expect_rc 2 "missing harness"
expect_out "NOT RUN: base revision lacks the compat harness" "missing harness"

# --- 4. unreachable database -----------------------------------------------
echo "case 4: the database is unreachable"
restore_trees
# Port 1 is never a Postgres server; this is the only value that differs.
run_check CFGMS_TEST_DB_PORT=1
expect_rc 2 "unreachable database"
expect_out "NOT RUN" "unreachable database"
expect_out "unreachable" "unreachable database"

# --- 5. a suite that drops a table -----------------------------------------
echo "case 5: a base test drops a table"
restore_trees
cat >"$BASE/$PKG_REL/zz_compat_selftest_drop_test.go" <<'GO'
package database

import "testing"

// TestCompatSelfTestDropsTable stands in for a test that rebuilds the schema.
func TestCompatSelfTestDropsTable(t *testing.T) {
	db := getTestDB(t)
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(`DROP TABLE IF EXISTS cfgms_node_registry`); err != nil {
		t.Fatal(err)
	}
}
GO
NARROW_SAVED="$NARROW_RUN"
NARROW_RUN="$NARROW_RUN|TestCompatSelfTestDropsTable"
run_check
NARROW_RUN="$NARROW_SAVED"
expect_rc 1 "schema-rebuilding suite"
expect_out "FAIL: suite rebuilt the schema" "schema-rebuilding suite"
expect_out "cfgms_node_registry" "schema-rebuilding suite"

# --- 6. every database test skipped ----------------------------------------
echo "case 6: -short skips every database test"
restore_trees
run_check GOFLAGS=-short
expect_rc 2 "all tests skipped"
expect_out "NOT RUN" "all tests skipped"
if grep -qE '^[AB] \(.*\): PASS' <<<"$OUT"; then
    fail "all tests skipped: a direction was reported PASS"
else
    pass "all tests skipped: no direction reported PASS"
fi

# --- 7. a suite in which no store test passes ------------------------------
echo "case 7: the suite selects only a test that never opens the database"
restore_trees
NARROW_SAVED="$NARROW_RUN"
NARROW_RUN='^TestDatabaseProvider_ClusterCapable_True$'
run_check
NARROW_RUN="$NARROW_SAVED"
expect_rc 2 "no store test passed"
expect_out "NOT RUN: no database store test passed" "no store test passed"

# --- 8. psql is not on PATH ------------------------------------------------
echo "case 8: psql is missing"
restore_trees
EMPTY_BIN="$TMP/empty-bin"
mkdir -p "$EMPTY_BIN"
RC=0
OUT="$(PATH="$EMPTY_BIN" "$BASH" "$CHECKER" --base-dir "$BASE" --head-dir "$HEAD" 2>&1)" || RC=$?
expect_rc 2 "psql missing"
expect_out "NOT RUN: required tool 'psql' is not on PATH" "psql missing"

echo
echo "Passed: $PASS  Failed: $FAIL"
if [[ "$FAIL" -ne 0 ]]; then
    exit 1
fi
