#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# check-docs-boundary.sh — verify that docs/ contains no private-deployment
# identifiers (Issue #3417, Epic #3412).
#
# docs/development/documentation-boundaries.md describes the convention this
# enforces. That document deliberately does NOT restate the denylist: this
# script is the single place the identifiers are written down, so the
# convention doc cannot itself reintroduce what the gate exists to keep out
# of the repository.
#
# Usage:
#   scripts/check-docs-boundary.sh                 # scan docs/
#   scripts/check-docs-boundary.sh --print-pattern # emit the denylist regex
#
# Exit codes:
#   0  no private-deployment identifiers in docs/
#   1  at least one match (offending files named on stderr)
#   2  the scan could not be performed (bad usage, not a git work tree, or
#      git grep failed) — the gate fails closed rather than reporting clean
#
# Tests: scripts/check-docs-boundary_test.sh, run by scripts/test-scripts.sh.

set -euo pipefail

# Single source of truth for the denylist. The test suite derives its fixtures
# from this pattern, so an identifier added here is covered automatically.
PATTERN='CFG-70-02|CFG-70-03|CFG-AB-02|CFG-C3-02|cfgms-ctrl-01|cfgms-ha-node2|cfgms-ha-node3|cfgms-lab-datasvc|cfgms_lab_ed25519|\bcfg-lab\b|lab\.cfg\.is|192\.168\.234\.'

case "${1:-}" in
    --print-pattern)
        printf '%s\n' "$PATTERN"
        exit 0
        ;;
    "")
        ;;
    *)
        echo "usage: $0 [--print-pattern]" >&2
        exit 2
        ;;
esac

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "ERROR: not inside a git work tree; docs/ boundary not verified" >&2
    exit 2
fi

# --untracked so that a brand-new docs file is scanned before it is ever
# staged: without it the gate reads clean on exactly the commit that
# introduces the identifier. Standard excludes still apply, so ignored files
# stay out of the scan.
set +e
matches=$(git grep --untracked -lE -e "$PATTERN" -- 'docs/')
grep_rc=$?
set -e

# git grep exits 0 when it matched, 1 when it did not, and >1 on error.
# Reporting an error as "clean" would fail the gate open — the precise
# failure mode this script exists to prevent.
if [ "$grep_rc" -gt 1 ]; then
    echo "ERROR: git grep failed (exit $grep_rc); docs/ boundary not verified" >&2
    exit 2
fi

if [ "$grep_rc" -eq 0 ] && [ -n "$matches" ]; then
    echo "ERROR: private-deployment identifiers found in docs/:" >&2
    echo "$matches" | sed 's/^/  /' >&2
    echo "" >&2
    echo "Locate the offending lines with:" >&2
    echo "  git grep -nE \"\$(scripts/check-docs-boundary.sh --print-pattern)\" -- 'docs/'" >&2
    echo "See: docs/development/documentation-boundaries.md" >&2
    exit 1
fi

echo "OK: no private-deployment identifiers in docs/"
