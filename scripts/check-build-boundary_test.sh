#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# Tests for scripts/check-build-boundary.sh (Issues #5747, #5887).
#
# Builds throwaway Go modules and asserts, for each of the three rules
# (cmd/steward -> features/controller, cmd/controller -> features/steward,
# pkg -> features/controller|features/steward), that a violation exits 1 naming
# the offending package; that a clean fixture and the real tree exit 0; and that
# each rule fails closed (exit 2) when its go list call fails.
#
# Usage: bash scripts/check-build-boundary_test.sh

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECKER="$REPO_ROOT/scripts/check-build-boundary.sh"
MOD="example.com/fix"

PASS=0
FAIL=0
TMPDIRS=()
trap 'rm -rf "${TMPDIRS[@]}"' EXIT

pass() { echo "  ✅ $1"; PASS=$((PASS + 1)); }
fail() { echo "  ❌ $1"; FAIL=$((FAIL + 1)); }

# write_file <dir> <relative-path> <content> — creates parent directories.
write_file() {
    mkdir -p "$(dirname "$1/$2")"
    printf '%s' "$3" > "$1/$2"
}

# make_fixture — creates a clean module "example.com/fix" with
# features/controller/batchjob, features/steward/runner, pkg/leaf, a cmd/steward
# and a cmd/controller main package that import nothing, a cmd/cfg main package,
# and echoes its dir. Callers then add the violating file.
make_fixture() {
    local dir
    dir="$(mktemp -d)"
    TMPDIRS+=("$dir")
    write_file "$dir" go.mod $'module example.com/fix\n\ngo 1.21\n'
    write_file "$dir" features/controller/batchjob/b.go $'package batchjob\n\nconst X = 1\n'
    write_file "$dir" features/steward/runner/r.go $'package runner\n\nconst X = 1\n'
    write_file "$dir" pkg/leaf/l.go $'package leaf\n\nconst Y = 1\n'
    write_file "$dir" cmd/steward/main.go $'package main\n\nfunc main() {}\n'
    write_file "$dir" cmd/controller/main.go $'package main\n\nfunc main() {}\n'
    write_file "$dir" cmd/cfg/main.go $'package main\n\nfunc main() {}\n'
    printf '%s' "$dir"
}

# main_importing <import-path-under-module> — main package source importing it.
main_importing() {
    printf 'package main\n\nimport _ "%s/%s"\n\nfunc main() {}\n' "$MOD" "$1"
}

run_checker() {
    STDERR="$(bash "$CHECKER" "$1" 2>&1 >/dev/null)"
    RC=$?
}

# expect_offender <label> <dir> <offending-package> [<import>]
expect_offender() {
    run_checker "$2"
    if [ "$RC" -eq 1 ] && grep -q "$3" <<<"$STDERR" && { [ -z "${4:-}" ] || grep -q "$4" <<<"$STDERR"; }; then
        pass "$1: exits 1 naming $3"
    else
        fail "$1: exit $RC, stderr: $STDERR"
    fi
}

# expect_exit <label> <dir> <code>
expect_exit() {
    run_checker "$2"
    [ "$RC" -eq "$3" ] && pass "$1: exits $3" || fail "$1: exit $RC (want $3), stderr: $STDERR"
}

echo "Clean fixture"
dir=$(make_fixture)
expect_exit "clean fixture" "$dir" 0

echo "Rule 1: cmd/steward -> features/controller"
dir=$(make_fixture)
write_file "$dir" cmd/steward/main.go "$(main_importing features/controller/batchjob)"
expect_offender "direct controller import" "$dir" "$MOD/features/controller/batchjob"
for os in linux windows darwin; do
    grep -q "GOOS=$os" <<<"$STDERR" && pass "rule 1 offender reported for GOOS=$os" || fail "rule 1: no report for GOOS=$os"
done
dir=$(make_fixture)
write_file "$dir" pkg/shared/s.go $'package shared\n\nimport _ "example.com/fix/features/controller/batchjob"\n'
write_file "$dir" cmd/steward/main.go "$(main_importing pkg/shared)"
expect_offender "transitive controller import" "$dir" "$MOD/features/controller/batchjob"
dir=$(make_fixture)
write_file "$dir" cmd/steward/main.go "$(main_importing pkg/does-not-exist)"
expect_exit "unresolvable steward closure fails closed" "$dir" 2

echo "Rule 2: cmd/controller -> features/steward"
dir=$(make_fixture)
write_file "$dir" cmd/controller/main.go "$(main_importing features/steward/runner)"
expect_offender "direct steward import" "$dir" "$MOD/features/steward/runner"
for os in linux windows; do
    grep -q "GOOS=$os" <<<"$STDERR" && pass "rule 2 offender reported for GOOS=$os" || fail "rule 2: no report for GOOS=$os"
done
dir=$(make_fixture)
write_file "$dir" pkg/shared/s.go $'package shared\n\nimport _ "example.com/fix/features/steward/runner"\n'
write_file "$dir" cmd/controller/main.go "$(main_importing pkg/shared)"
expect_offender "transitive steward import" "$dir" "$MOD/features/steward/runner"
dir=$(make_fixture)
write_file "$dir" cmd/controller/main.go "$(main_importing pkg/does-not-exist)"
expect_exit "unresolvable controller closure fails closed" "$dir" 2
dir=$(make_fixture)
write_file "$dir" cmd/steward/main.go "$(main_importing features/steward/runner)"
expect_exit "steward importing features/steward is allowed" "$dir" 0
dir=$(make_fixture)
write_file "$dir" cmd/controller/main.go "$(main_importing features/controller/batchjob)"
expect_exit "controller importing features/controller is allowed" "$dir" 0

echo "Rule 3: pkg -> features/controller | features/steward"
dir=$(make_fixture)
write_file "$dir" pkg/bad/b.go $'package bad\n\nimport _ "example.com/fix/features/controller/batchjob"\n'
expect_offender "production import of controller" "$dir" "$MOD/pkg/bad" "$MOD/features/controller/batchjob"
dir=$(make_fixture)
write_file "$dir" pkg/bad/b.go $'package bad\n\nimport _ "example.com/fix/features/steward/runner"\n'
expect_offender "production import of steward" "$dir" "$MOD/pkg/bad" "$MOD/features/steward/runner"
for os in linux windows darwin; do
    grep -q "GOOS=$os" <<<"$STDERR" && pass "rule 3 offender reported for GOOS=$os" || fail "rule 3: no report for GOOS=$os"
done
dir=$(make_fixture)
write_file "$dir" pkg/bad/b.go $'package bad\n'
write_file "$dir" pkg/bad/b_test.go $'package bad\n\nimport _ "example.com/fix/features/controller/batchjob"\n'
expect_offender "in-package test import" "$dir" "$MOD/pkg/bad" "$MOD/features/controller/batchjob"
dir=$(make_fixture)
write_file "$dir" pkg/bad/b.go $'package bad\n'
write_file "$dir" pkg/bad/b_test.go $'package bad_test\n\nimport _ "example.com/fix/features/steward/runner"\n'
expect_offender "external test import" "$dir" "$MOD/pkg/bad" "$MOD/features/steward/runner"
dir=$(make_fixture)
write_file "$dir" pkg/bad/b.go $'package bad\n'
write_file "$dir" pkg/bad/b_integration_test.go $'//go:build integration\n\npackage bad\n\nimport _ "example.com/fix/features/controller/batchjob"\n'
# Default-tag go list alone does not see the file; the gate must still catch it.
if [ -z "$(cd "$dir" && go list -f '{{join .TestImports " "}}' ./pkg/bad)" ]; then
    pass "integration fixture is invisible to a default-tag go list"
else
    fail "integration fixture unexpectedly visible to a default-tag go list"
fi
expect_offender "integration-tagged test import" "$dir" "$MOD/pkg/bad" "$MOD/features/controller/batchjob"
dir=$(make_fixture)
write_file "$dir" cmd/cfg/main.go "$(main_importing features/controller/batchjob)"
expect_exit "non-pkg package (cmd/cfg) importing a feature package" "$dir" 0
dir=$(make_fixture)
write_file "$dir" pkg/bad/b.go $'package bad\n\nimport _ "example.com/fix/pkg/does-not-exist"\n'
expect_exit "unresolvable pkg imports fail closed" "$dir" 2
dir=$(make_fixture)
write_file "$dir" pkg/bad/b.go $'package bad\n'
write_file "$dir" pkg/bad/b_integration.go $'//go:build integration\n\npackage bad\n\nimport _ "example.com/fix/pkg/does-not-exist"\n'
expect_exit "unresolvable integration-tagged pkg imports fail closed" "$dir" 2
dir=$(make_fixture)
write_file "$dir" pkg/featuresx/x.go $'package featuresx\n\nimport _ "example.com/fix/pkg/leaf"\n'
write_file "$dir" features/controllerx/c.go $'package controllerx\n'
write_file "$dir" pkg/neighbour/n.go $'package neighbour\n\nimport _ "example.com/fix/features/controllerx"\n'
expect_exit "path-boundary match: features/controllerx is not features/controller" "$dir" 0

echo "Real tree"
bash "$CHECKER" >/dev/null 2>&1
[ $? -eq 0 ] && pass "real tree exits 0" || fail "real tree failed the gate"

echo ""
echo "Passed: $PASS  Failed: $FAIL"
[ "$FAIL" -eq 0 ]
