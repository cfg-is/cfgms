#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# check-gosec-load-length.sh — fail before gosec runs when a package's gosec
# file list is long enough that golang.org/x/tools/go/packages would split it
# into chunks (Issue #6270).
#
# gosec passes filepath.Join(<abs package dir>, <file>) for every non-test Go
# and cgo file of a package to packages.Load. packages.Load splits its
# patterns into chunks once their total length (len+1 per pattern) exceeds
# safeArgMax = 32767 - 16384 = 16383. Each chunk loads as its own
# command-line-arguments package and cannot see types declared in the other
# chunk, so gosec reports `undefined:` type errors instead of findings.
#
# This guard computes, per package in ./..., sum(len(<root>/<dir>/<file>) + 1)
# over non-test GoFiles and CgoFiles and fails when any package exceeds a
# threshold set below the hard limit, so the failure is a clear message at the
# time a package grows rather than a type error in gosec.
#
# Environment:
#   GOSEC_SCAN_ROOT       path gosec sees as the repo root (default: logical
#                         $PWD — never `pwd -P`, gosec uses the logical path)
#   GOSEC_LOAD_THRESHOLD  per-package limit in characters (default 15000)
#
# Usage (from the module root):
#   scripts/check-gosec-load-length.sh
#
# Exit codes:
#   0  every package is within the threshold
#   1  at least one package exceeds it (named on stderr)
#   2  the file lists could not be computed
#
# Tests: scripts/check-gosec-load-length_test.sh, run by scripts/test-scripts.sh.

set -euo pipefail

HARD_LIMIT=16383
THRESHOLD="${GOSEC_LOAD_THRESHOLD:-15000}"
ROOT="${GOSEC_SCAN_ROOT:-$PWD}"
ROOT="${ROOT%/}"

case "$THRESHOLD" in
    '' | *[!0-9]*)
        echo "ERROR: GOSEC_LOAD_THRESHOLD must be a non-negative integer (got '$THRESHOLD')" >&2
        exit 2
        ;;
esac

if ! module_path="$(go list -m 2>/dev/null)" || [ -z "$module_path" ]; then
    echo "ERROR: cannot determine the Go module path; gosec load length not verified" >&2
    exit 2
fi

# One "<import path> <file>" line per non-test Go/cgo file. .Dir is not used:
# under a symlinked scan root it is the resolved path, not the one gosec sees.
if ! listing="$(go list -f '{{$ip := .ImportPath}}{{range .GoFiles}}{{$ip}} {{.}}{{"\n"}}{{end}}{{range .CgoFiles}}{{$ip}} {{.}}{{"\n"}}{{end}}' ./... 2>/dev/null)"; then
    echo "ERROR: go list ./... failed; gosec load length not verified" >&2
    exit 2
fi

over="$(printf '%s\n' "$listing" | awk -v root="$ROOT" -v mod="$module_path" -v thr="$THRESHOLD" '
    NF == 2 && $2 !~ /_test\.go$/ {
        rel = substr($1, length(mod) + 1)   # "" for the root package, else "/sub/dir"
        total[$1] += length(root rel "/" $2) + 1
    }
    END {
        for (p in total) if (total[p] > thr) print total[p], p
    }' | sort -rn)"

if [ -n "$over" ]; then
    while read -r len pkg; do
        echo "ERROR: gosec load length for package $pkg is $len characters; threshold $THRESHOLD (hard limit $HARD_LIMIT)." >&2
        echo "       Past the hard limit golang.org/x/tools/go/packages splits the file list into chunks and gosec fails with 'undefined:' type errors." >&2
        echo "       Split the package (scan root: $ROOT)." >&2
    done <<<"$over"
    exit 1
fi

echo "gosec load length OK: every package is within $THRESHOLD characters (scan root $ROOT)"
