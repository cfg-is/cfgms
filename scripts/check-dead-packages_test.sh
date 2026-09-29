#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# Tests for scripts/check-dead-packages.sh (Issue #4317).
#
# Each case builds a throwaway Go module (its own go.mod, so `go list`
# resolves entirely within the fixture, no network needed) and runs the
# checker against it. The central fixture is the shape called out in
# Issue #4317 as the one a naive implementation gets wrong:
#
#   cmd/app (main) --> live               (reachable)
#           `------> deadparent/livechild (reachable: a CHILD of an
#                                          unreachable package is not
#                                          itself unreachable)
#   deadparent                            (unreachable: has no importer
#                                          reachable from main, even though
#                                          its own child package does)
#   chaina <-- chainb <-- chainc          (unreachable: chainc is imported
#                                          by no main package; chainb only
#                                          by chainc; chaina only by chainb.
#                                          Every package in the chain HAS an
#                                          importer, so an implementation
#                                          that walks importers instead of
#                                          computing the closure from `main`
#                                          would wrongly call these reachable.)
#
# Usage: bash scripts/check-dead-packages_test.sh

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECKER="$REPO_ROOT/scripts/check-dead-packages.sh"

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

# make_fixture builds the chain/parent-child fixture module described above,
# plus a `live_test.go` that imports a package ONLY from a test file
# (testsupport), and echoes the module dir.
make_fixture() {
    local dir
    dir="$(mktemp -d)"

    cat >"$dir/go.mod" <<'EOF'
module fixture.test/app

go 1.21
EOF

    mkdir -p "$dir/cmd/app" "$dir/live" "$dir/deadparent/livechild" \
        "$dir/chaina" "$dir/chainb" "$dir/chainc" "$dir/testsupport"

    cat >"$dir/cmd/app/main.go" <<'EOF'
package main

import (
	_ "fixture.test/app/deadparent/livechild"
	_ "fixture.test/app/live"
)

func main() {}
EOF

    cat >"$dir/live/live.go" <<'EOF'
package live

func Live() {}
EOF

    cat >"$dir/live/live_test.go" <<'EOF'
package live

import (
	"testing"

	_ "fixture.test/app/testsupport"
)

func TestLive(t *testing.T) {}
EOF

    cat >"$dir/deadparent/deadparent.go" <<'EOF'
package deadparent

func DeadParent() {}
EOF

    cat >"$dir/deadparent/livechild/livechild.go" <<'EOF'
package livechild

func LiveChild() {}
EOF

    cat >"$dir/chaina/chaina.go" <<'EOF'
package chaina

func A() {}
EOF

    cat >"$dir/chainb/chainb.go" <<'EOF'
package chainb

import _ "fixture.test/app/chaina"

func B() {}
EOF

    cat >"$dir/chainc/chainc.go" <<'EOF'
package chainc

import _ "fixture.test/app/chainb"

func C() {}
EOF

    cat >"$dir/testsupport/testsupport.go" <<'EOF'
package testsupport

func Helper() {}
EOF

    printf '%s' "$dir"
}

# write_allowlist <file> <path...> — writes a minimal valid allowlist with
# one entry per path argument.
write_allowlist() {
    local file="$1"
    shift
    {
        echo "packages:"
        for p in "$@"; do
            echo "  - path: $p"
            echo "    reason: fixture test entry"
        done
    } >"$file"
}

# run_checker <dir> [allowlist] — runs the gate with cwd=<dir>, setting RC/STDOUT/STDERR.
run_checker() {
    local dir="$1" allowlist="${2:-}" out err
    out="$(mktemp)"
    err="$(mktemp)"
    ( cd "$dir" && bash "$CHECKER" ${allowlist:+"$allowlist"} ) >"$out" 2>"$err"
    RC=$?
    STDOUT="$(cat "$out")"
    STDERR="$(cat "$err")"
    rm -f "$out" "$err"
}

echo "🧪 scripts/check-dead-packages.sh"
echo "===================================="

# --- 1. A fully-connected module (no dead packages) passes with an empty ---
#        or absent allowlist.
repo="$(mktemp -d)"
cat >"$repo/go.mod" <<'EOF'
module fixture.test/clean

go 1.21
EOF
mkdir -p "$repo/cmd/app" "$repo/live"
cat >"$repo/cmd/app/main.go" <<'EOF'
package main

import _ "fixture.test/clean/live"

func main() {}
EOF
cat >"$repo/live/live.go" <<'EOF'
package live

func Live() {}
EOF
run_checker "$repo" "does-not-exist.yaml"
if [ "$RC" -eq 0 ]; then
    pass "fully-connected module exits 0 with no allowlist"
else
    fail "fully-connected module should exit 0 (rc=$RC, stdout: $STDOUT, stderr: $STDERR)"
fi
case "$STDOUT" in
    *"none"*) pass "fully-connected module reports no unreachable packages" ;;
    *) fail "expected 'none' reported for unreachable packages (got: $STDOUT)" ;;
esac
rm -rf "$repo"

# --- 2. The chain/parent-child fixture, no allowlist: reports exactly the ---
#        4 truly-dead packages, and crucially does NOT flag deadparent's
#        reachable child, and DOES flag every link of the chain.
repo="$(make_fixture)"
run_checker "$repo" "does-not-exist.yaml"
if [ "$RC" -eq 1 ]; then
    pass "chain/parent-child fixture exits 1 with no allowlist"
else
    fail "chain/parent-child fixture should exit 1 (rc=$RC, stdout: $STDOUT, stderr: $STDERR)"
fi
for want in "fixture.test/app/deadparent" "fixture.test/app/chaina" "fixture.test/app/chainb" "fixture.test/app/chainc"; do
    case "$STDERR" in
        *"$want"*) pass "reports $want as unreachable" ;;
        *) fail "expected $want reported as unreachable (stderr: $STDERR)" ;;
    esac
done
case "$STDOUT$STDERR" in
    *"deadparent/livechild"*) fail "must NOT report deadparent/livechild unreachable — a reachable child of an unreachable parent (stdout: $STDOUT, stderr: $STDERR)" ;;
    *) pass "does not report the reachable child deadparent/livechild" ;;
esac
case "$STDOUT$STDERR" in
    *"fixture.test/app/live"*) fail "must not report the reachable package 'live' as unreachable (stdout: $STDOUT, stderr: $STDERR)" ;;
    *) pass "does not report the reachable package 'live'" ;;
esac
rm -rf "$repo"

# --- 3. The same fixture, all 4 dead packages allowlisted: passes ----------
repo="$(make_fixture)"
write_allowlist "$repo/allow.yaml" \
    "deadparent" "chaina" "chainb" "chainc"
run_checker "$repo" "allow.yaml"
if [ "$RC" -eq 0 ]; then
    pass "chain/parent-child fixture exits 0 once all 4 dead packages are allowlisted"
else
    fail "should exit 0 once allowlisted (rc=$RC, stdout: $STDOUT, stderr: $STDERR)"
fi
rm -rf "$repo"

# --- 4. The same fixture, one dead package missing from the allowlist: ----
#        fails and names only the missing one.
repo="$(make_fixture)"
write_allowlist "$repo/allow.yaml" \
    "deadparent" "chaina" "chainb"
run_checker "$repo" "allow.yaml"
if [ "$RC" -eq 1 ]; then
    pass "fails when one dead package (chainc) is missing from the allowlist"
else
    fail "should exit 1 when chainc is missing from the allowlist (rc=$RC, stdout: $STDOUT, stderr: $STDERR)"
fi
case "$STDERR" in
    *"fixture.test/app/chainc"*) pass "names the missing package chainc" ;;
    *) fail "expected chainc named on stderr (got: $STDERR)" ;;
esac
case "$STDERR" in
    *"fixture.test/app/deadparent"*) fail "should not re-flag the already-allowlisted deadparent (stderr: $STDERR)" ;;
    *) pass "does not re-flag the already-allowlisted deadparent" ;;
esac
rm -rf "$repo"

# --- 5. A stale allowlist entry (a package that IS reachable) fails --------
repo="$(make_fixture)"
write_allowlist "$repo/allow.yaml" \
    "deadparent" "chaina" "chainb" "chainc" "live"
run_checker "$repo" "allow.yaml"
if [ "$RC" -eq 1 ]; then
    pass "fails when the allowlist contains a stale entry (live is reachable)"
else
    fail "should exit 1 on a stale allowlist entry (rc=$RC, stdout: $STDOUT, stderr: $STDERR)"
fi
case "$STDERR" in
    *"Stale"*"fixture.test/app/live"*) pass "names the stale entry 'live' and calls it out as stale" ;;
    *) fail "expected a stale-entry message naming 'live' (got: $STDERR)" ;;
esac
rm -rf "$repo"

# --- 6. A package reachable only from a _test.go file (testsupport) is ----
#        reported separately and does NOT require an allowlist entry.
repo="$(make_fixture)"
write_allowlist "$repo/allow.yaml" \
    "deadparent" "chaina" "chainb" "chainc"
run_checker "$repo" "allow.yaml"
if [ "$RC" -eq 0 ]; then
    pass "test-only-reachable package (testsupport) does not require an allowlist entry"
else
    fail "should exit 0 without allowlisting testsupport (rc=$RC, stdout: $STDOUT, stderr: $STDERR)"
fi
case "$STDOUT" in
    *"fixture.test/app/testsupport"*) pass "reports testsupport in the test-support bucket" ;;
    *) fail "expected testsupport reported in the test-support bucket (stdout: $STDOUT)" ;;
esac
rm -rf "$repo"

# --- 7. The gate fails closed when it cannot scan (no go.mod) --------------
nonmod="$(mktemp -d)"
mkdir -p "$nonmod/pkg"
run_checker "$nonmod" "allow.yaml"
if [ "$RC" -eq 2 ]; then
    pass "fails closed (exit 2) outside a Go module root"
else
    fail "outside a module root the gate must fail closed with exit 2 (rc=$RC, stdout: $STDOUT, stderr: $STDERR)"
fi
rm -rf "$nonmod"

# --- 8. A package under node_modules is vendored third-party content: it is --
#        never reported and never needs an allowlist entry (Issue #4389).
repo="$(make_fixture)"
mkdir -p "$repo/web/node_modules/flatted/golang/pkg/flatted"
cat >"$repo/web/node_modules/flatted/golang/pkg/flatted/flatted.go" <<'EOF'
package flatted

func Vendored() {}
EOF
write_allowlist "$repo/allow.yaml" \
    "deadparent" "chaina" "chainb" "chainc"
run_checker "$repo" "allow.yaml"
if [ "$RC" -eq 0 ]; then
    pass "vendored node_modules package does not require an allowlist entry"
else
    fail "node_modules package must not fail the gate (rc=$RC, stdout: $STDOUT, stderr: $STDERR)"
fi
case "$STDOUT$STDERR" in
    *node_modules*) fail "node_modules package must not be named in the output (stdout: $STDOUT)" ;;
    *) pass "vendored node_modules package is absent from every bucket" ;;
esac
rm -rf "$repo"

echo ""
echo "Passed: $PASS  Failed: $FAIL"
[ "$FAIL" -eq 0 ] || exit 1
echo "✅ check-dead-packages.sh tests passed"
