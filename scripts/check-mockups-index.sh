#!/bin/bash
# Structural-integrity check for the mockups index table (Issues #3042, #3166).
#
# docs/design/mockups/README.md is generated from per-mockup *.yaml sidecar
# files by scripts/generate-mockups-index.py (Issue #3166). This script is
# the backstop: it verifies the committed index has exactly one table header
# and no duplicate rows — the properties that matter regardless of how the
# file was produced.
#
# Generator freshness (committed README matches current *.yaml metadata) is
# verified separately by scripts/generate-mockups-index.py --check, which is
# exercised in scripts/test-scripts.sh.
#
# Exit code 0 = single header, no duplicate rows. 1 = violation found.
# Usage: ./scripts/check-mockups-index.sh [path-to-readme]

set -euo pipefail

README="${1:-docs/design/mockups/README.md}"

if [ ! -f "$README" ]; then
    echo "❌ $README not found"
    exit 1
fi

HEADER_COUNT=$(grep -cE '^\| *File *\| *What it is *\| *Status *\|' "$README") || true
if [ "$HEADER_COUNT" -ne 1 ]; then
    echo "❌ Expected exactly 1 table header row in $README, found $HEADER_COUNT"
    echo "   (a union-merge resolution may have duplicated the header)"
    exit 1
fi

ROW_KEYS=$(grep -E '^\| *\[`' "$README" | sed -E 's/^\| *\[`[^`]+`\]\(([^)]+)\).*/\1/')

if [ -z "$ROW_KEYS" ]; then
    echo "❌ No index rows found in $README — table may be malformed"
    exit 1
fi

DUPES=$(printf '%s\n' "$ROW_KEYS" | sort | uniq -d)
ROW_COUNT=$(printf '%s\n' "$ROW_KEYS" | wc -l | tr -d ' ')

if [ -n "$DUPES" ]; then
    echo "❌ Duplicate row(s) detected in $README — a merge left both sides of"
    echo "   a same-row edit in the table instead of one resolved version:"
    echo "$DUPES" | sed 's/^/     - /'
    exit 1
fi

echo "✅ $README: $ROW_COUNT unique row(s), single header row"
exit 0
