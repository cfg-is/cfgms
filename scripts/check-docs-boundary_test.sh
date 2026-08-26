#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# Tests for scripts/check-docs-boundary.sh (Issue #3417, Epic #3412).
#
# The gate is the enforcement half of the documentation-boundary convention.
# Both of its failure modes are consequential: a false negative (mis-scoped
# regex, broken git grep invocation, scan silently failing open) lets a private
# deployment identifier into a world-readable repository with a green check,
# and a false positive blocks legitimate commits. Neither path is observable
# from the gate's normal "OK" output, so both are exercised here.
#
# Fixtures are derived from the gate's own denylist via --print-pattern, so
# this suite never restates the identifiers it is protecting — and an
# identifier added to the script is covered by these tests automatically.
#
# Each case runs in a throwaway git repository so nothing touches the real tree.
#
# Usage: bash scripts/check-docs-boundary_test.sh

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECKER="$REPO_ROOT/scripts/check-docs-boundary.sh"

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

# make_repo creates a throwaway repo with a clean docs/ tree and echoes its path.
make_repo() {
    local dir
    dir="$(mktemp -d)"
    git -C "$dir" init --quiet
    git -C "$dir" config user.email "test@example.com"
    git -C "$dir" config user.name "test"
    mkdir -p "$dir/docs/testing" "$dir/scripts"
    cat > "$dir/docs/testing/runbook.md" << 'EOF'
# Runbook

Nodes: ctrl-node-01, ctrl-node-02, ctrl-node-03
Hosts: HV-HOST-01, HV-HOST-02, HV-HOST-03
Domain: lab.example.com
Addresses: 192.0.2.10, 192.0.2.11 (RFC 5737)
SSH key: cfgms_ed25519
EOF
    echo "placeholder" > "$dir/scripts/other.sh"
    git -C "$dir" add docs scripts
    git -C "$dir" commit --quiet -m "initial"
    printf '%s' "$dir"
}

# run_checker <repo> — runs the gate in <repo>, setting RC/STDOUT/STDERR.
run_checker() {
    local repo="$1" out err
    out="$(mktemp)"
    err="$(mktemp)"
    ( cd "$repo" && bash "$CHECKER" ) >"$out" 2>"$err"
    RC=$?
    STDOUT="$(cat "$out")"
    STDERR="$(cat "$err")"
    rm -f "$out" "$err"
}

# sample_for_alt turns one alternative of the denylist regex into a literal
# string that must match it. Only the two metacharacter forms the denylist
# actually uses are handled; anything else is reported as a failure rather
# than silently skipped, so a future pattern shape cannot quietly lose coverage.
sample_for_alt() {
    local alt="$1"
    alt="${alt//\\b/}"
    alt="${alt//\\./.}"
    printf '%s' "$alt"
}

echo "🧪 scripts/check-docs-boundary.sh"
echo "================================="

# --- 0. The gate publishes its denylist as the single source of truth -------
PATTERN="$(bash "$CHECKER" --print-pattern)"
pattern_rc=$?
if [ "$pattern_rc" -eq 0 ] && [ -n "$PATTERN" ]; then
    pass "--print-pattern emits the denylist and exits 0"
else
    fail "--print-pattern should emit the denylist and exit 0 (rc=$pattern_rc)"
fi

# --- 1. A clean docs tree passes -------------------------------------------
repo="$(make_repo)"
run_checker "$repo"
if [ "$RC" -eq 0 ]; then
    pass "clean docs tree exits 0"
else
    fail "clean docs tree should exit 0 (rc=$RC, stderr: $STDERR)"
fi
case "$STDOUT" in
    OK:*) pass "clean docs tree reports OK on stdout" ;;
    *)    fail "clean docs tree should report OK on stdout (got: $STDOUT)" ;;
esac
rm -rf "$repo"

# --- 2. Every denylisted identifier is rejected, and the file is named ------
# Driven off the gate's own pattern: if an alternative is ever mis-scoped
# (wrong anchor, stray character class) this loop catches it.
IFS='|' read -r -a ALTS <<< "$PATTERN"
if [ "${#ALTS[@]}" -lt 2 ]; then
    fail "denylist should be an alternation of identifiers (got ${#ALTS[@]} entries)"
fi
for alt in "${ALTS[@]}"; do
    sample="$(sample_for_alt "$alt")"
    case "$sample" in
        *[\[\]\(\)\*\+\?\^\$\\]*)
            fail "denylist alternative '$alt' uses regex syntax sample_for_alt does not model — extend it"
            continue
            ;;
    esac

    repo="$(make_repo)"
    printf '# Leaked\n\nSee %s for details.\n' "$sample" > "$repo/docs/testing/leak.md"
    git -C "$repo" add docs/testing/leak.md
    git -C "$repo" commit --quiet -m "leak"
    run_checker "$repo"

    if [ "$RC" -eq 1 ]; then
        pass "rejects denylisted identifier '$alt' (exit 1)"
    else
        fail "denylisted identifier '$alt' should exit 1 (rc=$RC, stdout: $STDOUT)"
    fi

    case "$STDERR" in
        *docs/testing/leak.md*) pass "names the offending file for '$alt' on stderr" ;;
        *) fail "stderr should name docs/testing/leak.md for '$alt' (got: $STDERR)" ;;
    esac
    rm -rf "$repo"
done

# --- 3. An untracked docs file is scanned ----------------------------------
# Without --untracked the gate reads clean on exactly the commit that
# introduces a new document, which is when it matters most.
sample="$(sample_for_alt "${ALTS[0]}")"
repo="$(make_repo)"
printf '# New doc\n\n%s\n' "$sample" > "$repo/docs/testing/brand-new.md"   # never added
run_checker "$repo"
if [ "$RC" -eq 1 ]; then
    pass "rejects an untracked docs file carrying an identifier"
else
    fail "untracked docs file should exit 1 (rc=$RC, stdout: $STDOUT)"
fi
rm -rf "$repo"

# --- 4. The scan is scoped to docs/ ----------------------------------------
# A hit outside docs/ must not block a commit; the convention governs docs/.
repo="$(make_repo)"
printf '%s\n' "$sample" > "$repo/scripts/other.sh"
git -C "$repo" add scripts/other.sh
git -C "$repo" commit --quiet -m "outside docs"
run_checker "$repo"
if [ "$RC" -eq 0 ]; then
    pass "ignores an identifier outside docs/ (no false positive)"
else
    fail "identifier outside docs/ should not trip the gate (rc=$RC, stderr: $STDERR)"
fi
rm -rf "$repo"

# --- 5. Multiple offenders are all reported --------------------------------
repo="$(make_repo)"
printf '%s\n' "$sample" > "$repo/docs/testing/one.md"
printf '%s\n' "$sample" > "$repo/docs/testing/two.md"
git -C "$repo" add docs/testing/one.md docs/testing/two.md
git -C "$repo" commit --quiet -m "two leaks"
run_checker "$repo"
if [ "$RC" -eq 1 ] \
    && [[ "$STDERR" == *"docs/testing/one.md"* ]] \
    && [[ "$STDERR" == *"docs/testing/two.md"* ]]; then
    pass "reports every offending file, not just the first"
else
    fail "should report both offending files (rc=$RC, stderr: $STDERR)"
fi
rm -rf "$repo"

# --- 6. The gate fails closed when it cannot scan --------------------------
# A gate that cannot run must not report clean.
nonrepo="$(mktemp -d)"
mkdir -p "$nonrepo/docs"
printf '%s\n' "$sample" > "$nonrepo/docs/leak.md"
run_checker "$nonrepo"
if [ "$RC" -eq 2 ]; then
    pass "fails closed (exit 2) outside a git work tree"
else
    fail "outside a git work tree the gate must fail closed with exit 2 (rc=$RC)"
fi
rm -rf "$nonrepo"

# --- 7. Unknown arguments are a usage error, not a silent clean scan -------
out="$(bash "$CHECKER" --scan-everything 2>&1)"
rc=$?
if [ "$rc" -eq 2 ] && [[ "$out" == *usage* ]]; then
    pass "rejects unknown arguments with exit 2"
else
    fail "unknown argument should exit 2 with usage (rc=$rc, out: $out)"
fi

echo ""
echo "Passed: $PASS  Failed: $FAIL"
[ "$FAIL" -eq 0 ] || exit 1
echo "✅ check-docs-boundary.sh tests passed"
