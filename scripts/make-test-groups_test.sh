#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# Tests for the Makefile's local suite-group gating (Issue #4305, Epic #4296).
#
# `make test` asks scripts/lib/detect-tooling-changed.sh which script-suite
# groups the diff against the develop merge base touches and runs only those;
# test-commit, test-complete(-full) and test-agent-complete always run every
# group, exactly once. Every fixture is a throwaway git repository holding the
# real Makefile and the real detector, with a real origin/develop ref, real
# commits and a real `git merge-base` -- nothing is mocked.
#
# Invocations are counted with `make -n`. A dry run still executes every recipe
# line that contains $(MAKE) -- which is exactly the line in `test` that runs
# the detector and hands its answer to `$(MAKE) test-scripts` -- while every
# other line, including test-scripts' own `./scripts/test-scripts.sh ...` call,
# is only printed. So each printed test-scripts.sh line is one invocation that
# a real run would make, with the exact --group it would pass, and no Go test,
# linter or scanner runs.
#
# Usage: bash scripts/make-test-groups_test.sh

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ALL="core,security-review,claude-tooling,devinfra"

PASS=0
FAIL=0
FIXTURES=()

pass() {
    echo "  ✅ $1"
    PASS=$((PASS + 1))
}

fail() {
    echo "  ❌ $1"
    FAIL=$((FAIL + 1))
}

cleanup() {
    local d
    for d in "${FIXTURES[@]}"; do
        rm -rf "$d"
    done
}
trap cleanup EXIT

# make_repo [--no-origin] -- a throwaway repo holding the real Makefile and
# detector, committed as the develop baseline, with HEAD on a feature branch.
# Unless --no-origin is given, refs/remotes/origin/develop points at that
# baseline, so `git merge-base HEAD origin/develop` resolves exactly as it does
# in a real clone.
make_repo() {
    local dir
    dir="$(mktemp -d)"
    FIXTURES+=("$dir")
    git -C "$dir" init --quiet
    git -C "$dir" config user.email "test@example.com"
    git -C "$dir" config user.name "test"
    git -C "$dir" config core.autocrlf false
    mkdir -p "$dir/scripts/lib" "$dir/pkg"
    cp "$REPO_ROOT/Makefile" "$dir/Makefile"
    cp "$REPO_ROOT/scripts/lib/detect-tooling-changed.sh" "$dir/scripts/lib/"
    chmod +x "$dir/scripts/lib/detect-tooling-changed.sh"
    echo "package placeholder" > "$dir/pkg/placeholder.go"
    git -C "$dir" add Makefile scripts pkg
    git -C "$dir" commit --quiet -m "develop baseline"
    if [[ "${1:-}" != "--no-origin" ]]; then
        git -C "$dir" update-ref refs/remotes/origin/develop HEAD
    fi
    git -C "$dir" checkout --quiet -b feature
    printf '%s' "$dir"
}

# commit_change <repo> <path> -- writes a file at <path> and commits it.
commit_change() {
    local repo="$1" path="$2"
    mkdir -p "$(dirname "$repo/$path")"
    echo "change" > "$repo/$path"
    git -C "$repo" add "$path"
    git -C "$repo" commit --quiet -m "change $path"
}

# dry_run <repo> <target> [VAR=value...] -- `make -n <target>` in <repo>, with
# every variable this suite's own caller may have leaked removed: this file
# runs under `make test-scripts`, whose MAKEFLAGS carries the parent's
# CFGMS_TEST_SCRIPTS_GROUPS, and inheriting it would hide the auto-detection
# under test. Sets OUT (combined output) and INVOCATIONS (the printed
# test-scripts.sh lines, one per invocation a real run would make).
dry_run() {
    local repo="$1" target="$2"
    shift 2
    OUT="$(cd "$repo" && env -u MAKEFLAGS -u MFLAGS -u GNUMAKEFLAGS -u MAKELEVEL \
        -u CFGMS_TEST_SCRIPTS_GROUPS "$@" make -n --no-print-directory "$target" 2>&1)"
    INVOCATIONS="$(printf '%s\n' "$OUT" | grep -E '^\./scripts/test-scripts\.sh' || true)"
}

invocation_count() {
    if [[ -z "$INVOCATIONS" ]]; then
        echo 0
    else
        printf '%s\n' "$INVOCATIONS" | wc -l | tr -d ' '
    fi
}

# expect_single <label> <expected-groups-or-empty> -- exactly one test-scripts.sh
# invocation, passing `--group <expected>` (or no --group at all when empty).
expect_single() {
    local label="$1" want="$2" count
    count="$(invocation_count)"
    if [[ "$count" -ne 1 ]]; then
        fail "$label: expected exactly 1 test-scripts.sh invocation, got $count"
        printf '%s\n' "$OUT" | sed 's/^/      /' | tail -n 25
        return
    fi
    if [[ -z "$want" ]]; then
        if printf '%s\n' "$INVOCATIONS" | grep -q -- '--group'; then
            fail "$label: expected no --group (every group), got: $INVOCATIONS"
        else
            pass "$label: 1 invocation, no --group (every group)"
        fi
    elif printf '%s\n' "$INVOCATIONS" | grep -qE -- "--group ${want}( |$)"; then
        pass "$label: 1 invocation, --group $want"
    else
        fail "$label: expected --group $want, got: $INVOCATIONS"
    fi
}

# expect_reason <label> <regex> -- the one-line "which groups and why" banner.
expect_reason() {
    local label="$1" re="$2"
    if printf '%s\n' "$OUT" | grep -v '^[[:space:]]*echo' | grep -qE "test-scripts groups: ${re}"; then
        pass "$label: prints which groups were requested and why"
    else
        fail "$label: no 'test-scripts groups: ${re}' line in output"
        printf '%s\n' "$OUT" | grep 'test-scripts groups' | sed 's/^/      /'
    fi
}

echo "🧪 Makefile suite-group gating (make test / test-commit / test-complete)"
echo "========================================================================"

# --- 1. pkg/-only Go change -> core only -------------------------------------
repo="$(make_repo)"
commit_change "$repo" "pkg/feature/thing.go"
dry_run "$repo" test
expect_single "make test, pkg/-only diff" "core"
expect_reason "make test, pkg/-only diff" 'core \(vs develop merge base [0-9a-f]{8}: Matched suite groups: core\)'

# --- 2. security-review skill change -> core,security-review -----------------
repo="$(make_repo)"
commit_change "$repo" ".claude/skills/security-review/notes.md"
dry_run "$repo" test
expect_single "make test, security-review diff" "core,security-review"
expect_reason "make test, security-review diff" 'core,security-review \(vs develop merge base'

# --- 3. uncommitted working-tree change, no commits ahead -> classified -------
repo="$(make_repo)"
mkdir -p "$repo/.github/scripts"
echo "tracked" > "$repo/.github/scripts/tool.sh"
git -C "$repo" add .github/scripts/tool.sh
git -C "$repo" commit --quiet -m "add tool"
git -C "$repo" update-ref refs/remotes/origin/develop HEAD
echo "edited" > "$repo/.github/scripts/tool.sh"
dry_run "$repo" test
expect_single "make test, uncommitted devinfra edit" "core,devinfra"

# --- 4. no origin/develop merge base -> fail closed to every group ------------
repo="$(make_repo --no-origin)"
commit_change "$repo" "pkg/feature/thing.go"
dry_run "$repo" test
expect_single "make test, no origin/develop" "$ALL"
expect_reason "make test, no origin/develop" "${ALL} \\(no origin/develop merge base resolvable"

# --- 5. caller-set CFGMS_TEST_SCRIPTS_GROUPS is honored, not overridden -------
repo="$(make_repo)"
commit_change "$repo" "pkg/feature/thing.go"
dry_run "$repo" test CFGMS_TEST_SCRIPTS_GROUPS=devinfra
expect_single "make test, CFGMS_TEST_SCRIPTS_GROUPS=devinfra in env" "devinfra"
expect_reason "make test, CFGMS_TEST_SCRIPTS_GROUPS=devinfra in env" 'devinfra \(CFGMS_TEST_SCRIPTS_GROUPS set by the caller'

# --- 6. test-scripts directly -> every group, whatever the diff ---------------
repo="$(make_repo)"
commit_change "$repo" "pkg/feature/thing.go"
dry_run "$repo" test-scripts
expect_single "make test-scripts, pkg/-only diff" ""

# --- 7. the full-validation targets -> every group, exactly once --------------
# A pkg/-only diff (which alone would request core only) and a clean tree with
# zero changes both still get every group from each of these targets.
for scenario in pkg-only no-changes; do
    repo="$(make_repo)"
    [[ "$scenario" == pkg-only ]] && commit_change "$repo" "pkg/feature/thing.go"
    for target in test-commit test-complete test-complete-full test-agent-complete; do
        dry_run "$repo" "$target"
        expect_single "make $target, $scenario" "$ALL"
    done
done

echo ""
echo "Results: $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]]
