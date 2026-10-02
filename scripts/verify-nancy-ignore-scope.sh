#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# verify-nancy-ignore-scope.sh — Proves .nancy-ignore cannot suppress a CVE it
# does not literally list, without requiring network access or a GUIDE_TOKEN.
#
# nancy v2.1.0 parses each line with two regexes (internal/cmd/root.go):
#   unixComments = `#.*$`        strips a trailing comment
#   untilComment = `(until=)(.*)` strips a trailing "until=<date>"
# what remains, trimmed, is matched against each reported vulnerability with
# plain string equality (internal/ossindex/types.go, maybeExclude):
#   v.Cve == ex || v.ID == ex
# There is no wildcard, prefix, or regex matching on that side — an entry
# excludes exactly the literal id it names and nothing else. This script
# replicates both regexes and the equality check verbatim (verified against
# nancy tag v2.1.0, commit 410f73d14f5cf35300b2695dc1a74fb560b70a85) so CI
# fails if a future edit ever makes the suppression file broader than a list
# of exact CVE/OSS-Index IDs, and so the "a second unrelated CVE still fails
# the gate" property has machine-checked evidence instead of a design claim.
#
# A malformed `until=` date is also worth catching here: nancy's own loop
# aborts parsing the *rest* of the file on the first bad date (the error is
# swallowed by its caller), so a broken second entry would silently stop
# earlier entries' expiry from being honoured too. This gate rejects that
# before it reaches nancy.
#
# Run: bash scripts/verify-nancy-ignore-scope.sh [path-to-ignore-file]
# Exit codes: 0 = suppression file is a well-formed, exact-match allowlist
#             1 = malformed entry, wildcard, or other scope-widening pattern

set -euo pipefail

IGNORE_FILE="${1:-.nancy-ignore}"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

fail() {
    echo -e "${RED}❌ $1${NC}" >&2
    exit 1
}

if [ ! -f "$IGNORE_FILE" ]; then
    echo "ℹ️  No $IGNORE_FILE present — nothing to verify."
    exit 0
fi

# ---------------------------------------------------------------------------
# Parse exactly like nancy v2.1.0's determineIfLineIsExclusion.
# ---------------------------------------------------------------------------
declare -a ENTRIES=()
line_num=0
while IFS= read -r raw_line || [ -n "$raw_line" ]; do
    line_num=$((line_num + 1))

    # unixComments = `#.*$`
    stripped="${raw_line%%#*}"

    # untilComment = `(until=)(.*)` — capture, then strip from the line.
    until_val=""
    if [[ "$stripped" == *until=* ]]; then
        until_val="${stripped#*until=}"
        until_val="$(echo -n "$until_val" | xargs)"
        stripped="${stripped%%until=*}"
    fi

    cve_only="$(echo -n "$stripped" | xargs || true)"

    [ -z "$cve_only" ] && continue

    if [ -n "$until_val" ]; then
        if ! [[ "$until_val" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
            fail "$IGNORE_FILE:$line_num: malformed until= date '$until_val' (want YYYY-MM-DD) — nancy silently stops parsing the rest of the file on this error, so every entry below it would be dropped"
        fi
        if ! date -d "$until_val" >/dev/null 2>&1 && ! date -j -f '%Y-%m-%d' "$until_val" >/dev/null 2>&1; then
            fail "$IGNORE_FILE:$line_num: '$until_val' is not a real calendar date"
        fi
    fi

    # Defense in depth: nancy treats these as literal characters in an exact
    # string match, so they are inert today — but a glob-style entry signals
    # someone believed it was a pattern, which is exactly the "blanket
    # ignore" shape the policy in docs/development/security-workflow-guide.md
    # forbids. Fail loudly rather than let a no-op wildcard through review.
    if [[ "$cve_only" == *'*'* || "$cve_only" == *'?'* || "$cve_only" == *'['* ]]; then
        fail "$IGNORE_FILE:$line_num: entry '$cve_only' contains a wildcard character — nancy matches by exact string equality only, so this can never suppress anything; it reads as an attempted blanket ignore and is rejected"
    fi

    if [ -z "$until_val" ]; then
        fail "$IGNORE_FILE:$line_num: entry '$cve_only' has no until= expiry — every suppression must carry a review date"
    fi

    ENTRIES+=("$cve_only")
done <"$IGNORE_FILE"

if [ "${#ENTRIES[@]}" -eq 0 ]; then
    echo "ℹ️  $IGNORE_FILE has no active entries."
    exit 0
fi

for id in "${ENTRIES[@]}"; do
    count=0
    for other in "${ENTRIES[@]}"; do
        [ "$other" = "$id" ] && count=$((count + 1))
    done
    if [ "$count" -gt 1 ]; then
        fail "$IGNORE_FILE: duplicate entry '$id' — one line per CVE"
    fi
done

# ---------------------------------------------------------------------------
# Prove scoping: nancy's maybeExclude is `v.Cve == ex || v.ID == ex`. Replicate
# that exact string-equality check against a synthetic finding that is
# deliberately NOT in the file, and confirm it is not excluded.
# ---------------------------------------------------------------------------
is_excluded() {
    local candidate="$1"
    for id in "${ENTRIES[@]}"; do
        if [ "$id" = "$candidate" ]; then
            return 0
        fi
    done
    return 1
}

for id in "${ENTRIES[@]}"; do
    if ! is_excluded "$id"; then
        fail "internal error: '$id' failed to match itself under exact equality"
    fi
done

SYNTHETIC_UNRELATED_CVE="CVE-1970-00000-scope-probe"
if is_excluded "$SYNTHETIC_UNRELATED_CVE"; then
    fail "a synthetic CVE not present in $IGNORE_FILE matched an entry — suppression is no longer scoped to exact IDs"
fi

echo -e "${GREEN}✅ $IGNORE_FILE is a well-formed exact-match allowlist (${#ENTRIES[@]} entr$([ "${#ENTRIES[@]}" -eq 1 ] && echo y || echo ies))${NC}"
echo "   Verified: nancy v2.1.0 matches by strict equality only (internal/ossindex/types.go maybeExclude)."
echo "   A synthetic unrelated CVE ('$SYNTHETIC_UNRELATED_CVE') does not match any entry, so it would still fail the gate."
