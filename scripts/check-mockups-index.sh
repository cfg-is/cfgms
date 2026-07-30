#!/bin/bash
# Structural-integrity check for the mockups index table (Issue #3042 AC4/AC5).
#
# docs/design/mockups/README.md carries `merge=union` in .gitattributes so
# concurrent PRs that each append a distinct row rebase without human
# intervention. `union` cannot distinguish "two additive rows" from "two
# edits of the same row" — both look like an add/add hunk to a line-based
# merge, and union keeps both sides either way. This script is the backstop:
# it fails loudly (nonzero exit, in CI) the moment a same-row edit slips
# through as a silent duplicate, instead of a human having to notice it in
# review.
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
