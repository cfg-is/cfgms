#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# pr-postgres-filter.sh — decide whether a pull request can affect the
# real-Postgres database provider tests that cross-platform-build-pr.yml runs
# in its `postgres-integration-pr` job (Issue #6133).
#
# Usage:
#   scripts/pr-postgres-filter.sh --files <changed-files> [--renamed <old-names>]
#
#   --files    one changed path per line, relative to the repository root
#   --renamed  optional: the pre-rename names of renamed files, one per line,
#              so a file moved OUT of a trigger path still triggers the job
#
# Output: exactly one line on stdout, `postgres=true` or `postgres=false`.
# Warnings go to stderr as `::warning::` workflow commands.
#
# THIS FILTER MUST FAIL CLOSED. `postgres=false` is printed only when the
# filter ran to completion over a non-empty list and no file matched. An
# unreadable, missing or empty list, an unreadable --renamed list, an unknown
# argument or any matching error resolves to `postgres=true`.
#
# Trigger paths:
#   pkg/storage/providers/database/**   the provider and its migrations
#   pkg/storage/interfaces/**           the contracts the provider implements
#   scripts/check-schema-compat*        the schema-compat tooling
#
# Tests: scripts/pr-postgres-filter_test.sh

set -uo pipefail

files_arg=""
renamed_arg=""

while [ "$#" -gt 0 ]; do
    case "$1" in
        --files)   files_arg="${2:-}"; shift 2 || break ;;
        --renamed) renamed_arg="${2:-}"; shift 2 || break ;;
        *) echo "::warning::pr-postgres-filter: unknown argument '$1' — running the Postgres job" >&2
           echo "postgres=true"; exit 0 ;;
    esac
done

fail_closed() {
    echo "::warning::pr-postgres-filter: $1 — running the Postgres job" >&2
    echo "postgres=true"
    exit 0
}

[ -n "$files_arg" ] || fail_closed "no --files argument"
[ -f "$files_arg" ] && [ -r "$files_arg" ] || fail_closed "changed-file list '$files_arg' is unreadable"
if [ -n "$renamed_arg" ]; then
    [ -f "$renamed_arg" ] && [ -r "$renamed_arg" ] || fail_closed "renamed-file list '$renamed_arg' is unreadable"
fi

# A list with no non-blank line is a listing defect, not "nothing changed".
grep -q '[^[:space:]]' "$files_arg"
status=$?
[ "$status" -ne 2 ] || fail_closed "cannot read changed-file list '$files_arg'"
[ "$status" -eq 0 ] || fail_closed "changed-file list '$files_arg' is empty"

inputs=("$files_arg")
[ -z "$renamed_arg" ] || inputs+=("$renamed_arg")

# Written to a file, not piped into `grep -q`: under pipefail a consumer that
# exits on its first match can SIGPIPE the producer.
work=$(mktemp -d) || fail_closed "cannot create a temporary directory"
trap 'rm -rf "$work"' EXIT

grep -E '^(pkg/storage/providers/database/|pkg/storage/interfaces/|scripts/check-schema-compat)' \
    "${inputs[@]}" > "$work/match.txt" 2>/dev/null
status=$?

case "$status" in
    0)
        echo "database provider path(s) changed — the Postgres job runs: $(head -5 "$work/match.txt" | tr '\n' ' ')" >&2
        echo "postgres=true"
        ;;
    1)
        echo "no changed file is under a database provider path — the Postgres job is skipped" >&2
        echo "postgres=false"
        ;;
    *)
        fail_closed "matching the changed files failed (grep exit ${status})"
        ;;
esac
