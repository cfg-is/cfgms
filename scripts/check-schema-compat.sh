#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# check-schema-compat.sh — prove both directions of the N / N-1 schema contract
# on the real database provider (Issue #6097, Epic #5978).
#
#   A (base code, head schema): the base revision's database test suite passes
#       against a schema that the head revision created.
#   B (head code, base schema): the head revision's database test suite passes
#       against a schema that the base revision created.
#
# Each direction resets the test database, materialises one revision's schema by
# running that revision's TestSchemaCompat_ApplyAllStores, then runs the other
# revision's package suite in keep-schema mode (CFGMS_TEST_KEEP_SCHEMA=1), where
# the test helpers truncate tables instead of dropping them. In direction B the
# head code also applies its own expansion on top of the base schema while its
# suite runs, which is the real upgrade path, so that run is not read-only.
#
# Usage:
#   scripts/check-schema-compat.sh [--base-dir DIR --head-dir DIR]
#
#   Without arguments the head is the working tree this script lives in and the
#   base is a throwaway `git worktree` of $CFGMS_SCHEMA_COMPAT_BASE_SHA (for a
#   merge_group the workflow passes github.event.merge_group.base_sha; for
#   workflow_dispatch the merge-base with origin/develop). The commit must be
#   present locally, so the checkout needs fetch-depth: 0.
#   --base-dir and --head-dir (both or neither) name two existing source trees
#   instead; scripts/check-schema-compat_test.sh uses them.
#
# Environment:
#   CFGMS_TEST_DB_PASSWORD         required; must be exported so go test sees it
#   CFGMS_TEST_DB_PORT             default 5432
#   CFGMS_TEST_DB_HOST             default localhost
#   CFGMS_TEST_DB_NAME             default cfgms_test
#   CFGMS_TEST_DB_USER             default cfgms_test
#   CFGMS_SCHEMA_COMPAT_BASE_SHA   base revision when --base-dir is not given
#   CFGMS_SCHEMA_COMPAT_TEST_RUN   `go test -run` regex for the two suite runs;
#                                  empty (default) runs the whole package suite
#   CFGMS_SCHEMA_COMPAT_SUITE_TIMEOUT  per suite run, default 15m
#   CFGMS_SCHEMA_COMPAT_APPLY_TIMEOUT  per apply run, default 5m
#
# The connection comes from the CFGMS_TEST_DB_* variables the Docker test
# services write to .env.test. The password reaches psql as PGPASSWORD in that
# one process's environment, never as an argument, and is never printed.
#
# Reset: the schema the test role's search_path resolves to (current_schema(),
# `public` unless the role's search_path says otherwise) is dropped with CASCADE
# and recreated, after checking the test role owns it.
#
# Output: one line per direction (PASS, FAIL or NOT RUN), then the failing test
# names. A run that proves nothing is NOT RUN, never PASS: a missing tool, an
# unreachable database, a base or head revision without the compat harness, an
# apply step that skipped, or a suite in which no store test passed or some test
# skipped because the database was unavailable.
#
# Exit codes:
#   0  both directions passed
#   1  a direction failed (a test failed, or the suite rebuilt the schema)
#   2  NOT RUN: the check could not prove anything and must not count as passed
#
# Tests: scripts/check-schema-compat_test.sh (needs the Postgres test service;
# it runs in the postgres-integration job, not in scripts/test-scripts.sh).

set -euo pipefail

readonly PKG_REL="pkg/storage/providers/database"
readonly RC_FAIL=1
readonly RC_NOT_RUN=2

# Everything below runs in the foreground; this script uses no background jobs.
WORK=""
CREATED_BASE_WORKTREE=""
HEAD_DIR=""
BASE_DIR=""

die_not_run() {
    echo "NOT RUN: $*"
    exit "$RC_NOT_RUN"
}

cleanup() {
    local rc=$?
    if [[ -n "$CREATED_BASE_WORKTREE" && -n "$HEAD_DIR" ]]; then
        git -C "$HEAD_DIR" worktree remove --force "$CREATED_BASE_WORKTREE" >/dev/null 2>&1 || true
        git -C "$HEAD_DIR" worktree prune >/dev/null 2>&1 || true
    fi
    if [[ -n "$WORK" ]]; then
        rm -rf "$WORK"
    fi
    return "$rc"
}
trap cleanup EXIT

usage() {
    echo "Usage: ${0##*/} [--base-dir DIR --head-dir DIR]" >&2
}

# --- arguments ---------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --base-dir)
            [[ $# -ge 2 ]] || { usage; exit "$RC_NOT_RUN"; }
            BASE_DIR="$2"
            shift 2
            ;;
        --head-dir)
            [[ $# -ge 2 ]] || { usage; exit "$RC_NOT_RUN"; }
            HEAD_DIR="$2"
            shift 2
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            usage
            exit "$RC_NOT_RUN"
            ;;
    esac
done
if [[ -n "$BASE_DIR" && -z "$HEAD_DIR" ]] || [[ -z "$BASE_DIR" && -n "$HEAD_DIR" ]]; then
    echo "ERROR: --base-dir and --head-dir must be given together" >&2
    usage
    exit "$RC_NOT_RUN"
fi

# --- required tools ----------------------------------------------------------
# command -v is a builtin, so this runs even when PATH holds none of the tools.
for tool in psql go jq git; do
    command -v "$tool" >/dev/null 2>&1 || die_not_run "required tool '$tool' is not on PATH"
done

# --- database connection -----------------------------------------------------
DB_HOST="${CFGMS_TEST_DB_HOST:-localhost}"
DB_PORT="${CFGMS_TEST_DB_PORT:-5432}"
DB_NAME="${CFGMS_TEST_DB_NAME:-cfgms_test}"
DB_USER="${CFGMS_TEST_DB_USER:-cfgms_test}"
[[ -n "${CFGMS_TEST_DB_PASSWORD:-}" ]] || die_not_run "CFGMS_TEST_DB_PASSWORD is not set (source .env.test with set -a)"

# psql_run runs psql against the test database. The password is passed in the
# environment of this one process only; NOTICEs (the CASCADE list of a reset) are
# muted.
psql_run() {
    PGPASSWORD="$CFGMS_TEST_DB_PASSWORD" PGOPTIONS='-c client_min_messages=warning' psql -X -q -w -v ON_ERROR_STOP=1 \
        -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" "$@"
}

psql_run -At -c 'SELECT 1' >/dev/null 2>&1 ||
    die_not_run "the test database is unreachable at ${DB_HOST}:${DB_PORT} (database ${DB_NAME}, user ${DB_USER})"

owner_ok="$(psql_run -At -c "SELECT pg_has_role(current_user, n.nspowner, 'MEMBER') FROM pg_namespace n WHERE n.nspname = current_schema()" 2>/dev/null || true)"
if [[ "$owner_ok" != "t" ]]; then
    echo "ERROR: the test role '${DB_USER}' does not own the current schema of database '${DB_NAME}', or the schema does not exist; refusing to reset it" >&2
    exit "$RC_NOT_RUN"
fi

# --- source trees ------------------------------------------------------------
WORK="$(mktemp -d)"

if [[ -z "$HEAD_DIR" ]]; then
    HEAD_DIR="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd)"
    base_sha="${CFGMS_SCHEMA_COMPAT_BASE_SHA:-}"
    [[ -n "$base_sha" ]] || die_not_run "CFGMS_SCHEMA_COMPAT_BASE_SHA is not set and --base-dir was not given"
    [[ "$base_sha" =~ ^[0-9a-fA-F]{7,64}$ ]] || die_not_run "CFGMS_SCHEMA_COMPAT_BASE_SHA is not a commit id"
    git -C "$HEAD_DIR" cat-file -e "${base_sha}^{commit}" 2>/dev/null ||
        die_not_run "base commit ${base_sha} is not present in this checkout (the job needs fetch-depth: 0)"
    BASE_DIR="$WORK/base"
    if ! git -C "$HEAD_DIR" worktree add --detach "$BASE_DIR" "$base_sha" >/dev/null 2>&1; then
        die_not_run "could not create a worktree of ${base_sha}"
    fi
    CREATED_BASE_WORKTREE="$BASE_DIR"
fi
for dir in "$BASE_DIR" "$HEAD_DIR"; do
    [[ -d "$dir/$PKG_REL" ]] || die_not_run "${dir} has no ${PKG_REL}"
done
BASE_DIR="$(cd "$BASE_DIR" && pwd)"
HEAD_DIR="$(cd "$HEAD_DIR" && pwd)"

# has_harness reports whether a tree carries the compat harness: keep-schema mode
# in the test helpers and the apply test. Matching the quoted string literal and
# the function declaration keeps a comment that merely names them from counting.
has_harness() {
    local pkg="$1/$PKG_REL"
    grep -qsF '"CFGMS_TEST_KEEP_SCHEMA"' "$pkg"/*_test.go &&
        grep -qsF '"CFGMS_SCHEMA_COMPAT_APPLY"' "$pkg"/*_test.go &&
        grep -qsE 'func TestSchemaCompat_ApplyAllStores\(' "$pkg"/*_test.go
}
has_harness "$BASE_DIR" || die_not_run "base revision lacks the compat harness"
has_harness "$HEAD_DIR" || die_not_run "head revision lacks the compat harness"

# --- database helpers --------------------------------------------------------
# reset_database drops and recreates the schema the test role works in, so the
# next apply step starts from nothing.
reset_database() {
    psql_run >/dev/null <<'SQL'
DO $$
DECLARE s text := current_schema();
BEGIN
    IF s IS NULL THEN
        RAISE EXCEPTION 'no current schema';
    END IF;
    EXECUTE format('DROP SCHEMA %I CASCADE', s);
    EXECUTE format('CREATE SCHEMA %I', s);
END
$$;
SQL
}

# fingerprint prints a sorted catalog fingerprint of the current schema: every
# table, every column, and every row-level-security policy name.
fingerprint() {
    psql_run -At -c "
        SELECT 'table ' || table_name FROM information_schema.tables
            WHERE table_schema = current_schema() AND table_type = 'BASE TABLE'
        UNION ALL
        SELECT 'column ' || table_name || '.' || column_name FROM information_schema.columns
            WHERE table_schema = current_schema()
        UNION ALL
        SELECT 'policy ' || tablename || '.' || policyname FROM pg_policies
            WHERE schemaname = current_schema()" | LC_ALL=C sort
}

# --- go test helpers ---------------------------------------------------------
SUITE_RUN="${CFGMS_SCHEMA_COMPAT_TEST_RUN:-}"
SUITE_TIMEOUT="${CFGMS_SCHEMA_COMPAT_SUITE_TIMEOUT:-15m}"
APPLY_TIMEOUT="${CFGMS_SCHEMA_COMPAT_APPLY_TIMEOUT:-5m}"

# test_events <json-file> <jq-filter>: apply a filter to the go test -json stream.
# Reading raw lines and parsing with fromjson? tolerates the non-JSON lines go
# test prints when the build fails.
test_events() {
    jq -Rr "fromjson? | $2" "$1"
}

# run_apply <tree> <out>: run the tree's apply test, which creates every store.
run_apply() {
    local tree="$1" out="$2" rc=0
    (
        cd "$tree"
        env -u CFGMS_TEST_KEEP_SCHEMA CFGMS_SCHEMA_COMPAT_APPLY=1 \
            go test -json -count=1 -tags=integration -timeout "$APPLY_TIMEOUT" \
            -run '^TestSchemaCompat_ApplyAllStores$' "./$PKG_REL/"
    ) >"$out" 2>"$out.stderr" || rc=$?
    return "$rc"
}

# run_suite <tree> <out>: run the tree's whole database package suite in
# keep-schema mode, or the subset CFGMS_SCHEMA_COMPAT_TEST_RUN selects.
run_suite() {
    local tree="$1" out="$2" rc=0
    local -a run_args=()
    if [[ -n "$SUITE_RUN" ]]; then
        run_args=(-run "$SUITE_RUN")
    fi
    (
        cd "$tree"
        env -u CFGMS_SCHEMA_COMPAT_APPLY CFGMS_TEST_KEEP_SCHEMA=1 \
            go test -json -count=1 -p 1 -tags=integration -timeout "$SUITE_TIMEOUT" \
            "${run_args[@]}" "./$PKG_REL/..."
    ) >"$out" 2>"$out.stderr" || rc=$?
    return "$rc"
}

# report_failures <label> <json-file>: name the failing tests, or the tail of the
# output when go test failed without naming one (a build error, timeout, panic).
report_failures() {
    local label="$1" file="$2" names
    names="$(test_events "$file" 'select(.Action == "fail" and (.Test // "") != "") | .Test' | LC_ALL=C sort -u)"
    if [[ -n "$names" ]]; then
        echo "  failing tests (${label}):"
        printf '%s\n' "$names" | sed 's/^/    /'
    else
        echo "  go test failed without naming a test (${label}); last lines of its output:"
        { test_events "$file" 'select(.Action == "output") | .Output | rtrimstr("\n")'; cat "$file.stderr"; } |
            tail -n 20 | sed 's/^/    /'
    fi
}

# --- one direction -----------------------------------------------------------
# Each direction sets DIR_RESULT (PASS, FAIL or NOT RUN).
DIR_RESULT=""

# run_direction <label> <apply-tree> <suite-tree>
run_direction() {
    local label="$1" apply_tree="$2" suite_tree="$3"
    local apply_out="$WORK/${label}-apply.json" suite_out="$WORK/${label}-suite.json"
    local before="$WORK/${label}-before.fp" after="$WORK/${label}-after.fp"
    local rc status

    DIR_RESULT="FAIL"

    if ! reset_database; then
        echo "  the database reset failed (${label})"
        DIR_RESULT="NOT RUN"
        return 0
    fi

    # Apply: materialise one revision's schema.
    rc=0
    run_apply "$apply_tree" "$apply_out" || rc=$?
    status="$(test_events "$apply_out" 'select(.Test == "TestSchemaCompat_ApplyAllStores" and (.Action == "pass" or .Action == "fail" or .Action == "skip")) | .Action' | tail -n 1)"
    case "$status" in
        pass) ;;
        skip)
            echo "NOT RUN: the apply step skipped (database unavailable or -short); nothing was applied (${label})"
            DIR_RESULT="NOT RUN"
            return 0
            ;;
        fail)
            echo "  the apply step failed (${label})"
            report_failures "apply ${label}" "$apply_out"
            return 0
            ;;
        *)
            if [[ "$rc" -eq 0 ]]; then
                echo "NOT RUN: TestSchemaCompat_ApplyAllStores did not run (${label})"
                DIR_RESULT="NOT RUN"
            else
                echo "  the apply step failed before reporting a result (${label})"
                report_failures "apply ${label}" "$apply_out"
            fi
            return 0
            ;;
    esac

    fingerprint >"$before" || {
        echo "NOT RUN: could not read the catalog after the apply step (${label})"
        DIR_RESULT="NOT RUN"
        return 0
    }

    # Suite: the other revision's tests against that schema.
    rc=0
    run_suite "$suite_tree" "$suite_out" || rc=$?

    fingerprint >"$after" || {
        echo "NOT RUN: could not read the catalog after the suite (${label})"
        DIR_RESULT="NOT RUN"
        return 0
    }

    local lost
    lost="$(LC_ALL=C comm -23 "$before" "$after")"
    if [[ -n "$lost" ]]; then
        echo "FAIL: suite rebuilt the schema (${label}); present after the apply step, gone after the suite:"
        printf '%s\n' "$lost" | sed 's/^/    /'
        if [[ "$rc" -ne 0 ]]; then
            report_failures "suite ${label}" "$suite_out"
        fi
        return 0
    fi

    if [[ "$rc" -ne 0 ]]; then
        report_failures "suite ${label}" "$suite_out"
        return 0
    fi

    # go test exited 0: make sure that is not a pile of skips.
    local db_skips store_passes
    db_skips="$(test_events "$suite_out" 'select(.Action == "output" and ((.Output // "") | test("PostgreSQL test database not|Skipping database tests in short mode"))) | .Test // "?"' | LC_ALL=C sort -u)"
    if [[ -n "$db_skips" ]]; then
        echo "NOT RUN: tests skipped because the database was unavailable (${label}):"
        printf '%s\n' "$db_skips" | sed 's/^/    /'
        DIR_RESULT="NOT RUN"
        return 0
    fi
    # A store test (TestDatabase<Name>Store_...) builds a store against the
    # database, so at least one passing means the suite did reach it.
    store_passes="$(test_events "$suite_out" 'select(.Action == "pass" and ((.Test // "") | test("^TestDatabase[A-Za-z]*Store_"))) | .Test' | wc -l)"
    if [[ "${store_passes// /}" -lt 1 ]]; then
        echo "NOT RUN: no database store test passed in the suite (${label}); the run proves nothing"
        DIR_RESULT="NOT RUN"
        return 0
    fi

    DIR_RESULT="PASS"
}

# --- run both directions -----------------------------------------------------
LABEL_A="A (base code, head schema)"
LABEL_B="B (head code, base schema)"

echo "check-schema-compat: base=${BASE_DIR} head=${HEAD_DIR}"
if [[ -n "$SUITE_RUN" ]]; then
    echo "check-schema-compat: suite narrowed to -run '${SUITE_RUN}'"
fi

# Each direction's detail lines are held back so the two result lines come first.
echo "check-schema-compat: running ${LABEL_A}" >&2
run_direction "A" "$HEAD_DIR" "$BASE_DIR" >"$WORK/A.detail"
result_a="$DIR_RESULT"
echo "check-schema-compat: running ${LABEL_B}" >&2
run_direction "B" "$BASE_DIR" "$HEAD_DIR" >"$WORK/B.detail"
result_b="$DIR_RESULT"

echo
echo "${LABEL_A}: ${result_a}"
echo "${LABEL_B}: ${result_b}"
cat "$WORK/A.detail" "$WORK/B.detail"

if [[ "$result_a" == "FAIL" || "$result_b" == "FAIL" ]]; then
    exit "$RC_FAIL"
fi
if [[ "$result_a" != "PASS" || "$result_b" != "PASS" ]]; then
    echo "NOT RUN: at least one direction proved nothing"
    exit "$RC_NOT_RUN"
fi
exit 0
