#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# check-build-boundary.sh — verify the steward / controller / pkg build boundary
# (Issues #5747, #5887).
#
# Stewards run on endpoints that may be compromised, so code that only the
# controller needs must not ship inside the steward binary, and the reverse
# holds for the controller. Code both sides need belongs under pkg/ or in a
# shared feature package. Three rules:
#
#   1. ./cmd/steward depends on no features/controller/... package
#      (GOOS linux, windows, darwin).
#   2. ./cmd/controller depends on no features/steward/... package
#      (GOOS linux, windows — the controller targets).
#   3. No package under ./pkg/... imports a features/controller/... or
#      features/steward/... package, production, in-package test and external
#      test files included (GOOS linux, windows, darwin). go list skips files
#      behind a build tag, so the check runs once with default tags and once
#      with -tags integration (the only non-platform tag used under pkg/) and
#      unions the two.
#
# Usage:
#   scripts/check-build-boundary.sh [module-dir]
#
# module-dir defaults to the repository root. Feature prefixes are
# <module path>/features/controller and <module path>/features/steward, matched
# on a path boundary (equal, or followed by a slash).
#
# Exit codes:
#   0  no rule is broken
#   1  at least one rule is broken (offenders named on stderr)
#   2  a dependency closure or package list could not be computed — the gate
#      fails closed
#
# Tests: scripts/check-build-boundary_test.sh, run by scripts/test-scripts.sh.

set -euo pipefail

MODULE_DIR="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
cd "$MODULE_DIR"

if ! module_path=$(go list -m 2>/dev/null) || [ -z "$module_path" ]; then
    echo "ERROR: could not determine the Go module path in $MODULE_DIR; build boundary not verified" >&2
    exit 2
fi
controller_prefix="$module_path/features/controller"
steward_prefix="$module_path/features/steward"

# under_prefix <prefix> — print the stdin lines whose last field equals the
# prefix or sits below it (path boundary, literal comparison).
under_prefix() {
    awk -v p="$1" '{ n = $NF; if (n == p || index(n, p "/") == 1) print }' | sort -u
}

failed=0

# check_closure <binary> <prefix> <label> <goos>... — rules 1 and 2.
check_closure() {
    local bin="$1" prefix="$2" label="$3" goos deps offenders
    shift 3
    for goos in "$@"; do
        if ! deps=$(GOOS="$goos" go list -deps "./cmd/$bin" 2>/dev/null); then
            echo "ERROR: 'GOOS=$goos go list -deps ./cmd/$bin' failed; $bin dependencies not verified" >&2
            exit 2
        fi
        offenders=$(printf '%s\n' "$deps" | under_prefix "$prefix")
        if [ -n "$offenders" ]; then
            echo "ERROR: ./cmd/$bin depends on $label package(s) on GOOS=$goos:" >&2
            printf '%s\n' "$offenders" | sed 's/^/  /' >&2
            failed=1
        fi
    done
}

check_closure steward "$controller_prefix" controller linux windows darwin
check_closure controller "$steward_prefix" steward linux windows

# Rule 3: one "<pkg> <import>" line per import of every package under ./pkg/...
import_template='{{$p := .ImportPath}}{{range .Imports}}{{$p}} {{.}}{{"\n"}}{{end}}{{range .TestImports}}{{$p}} {{.}}{{"\n"}}{{end}}{{range .XTestImports}}{{$p}} {{.}}{{"\n"}}{{end}}'

for goos in linux windows darwin; do
    imports=""
    for tags in "" "integration"; do
        if ! out=$(GOOS="$goos" go list -tags "$tags" -f "$import_template" ./pkg/... 2>/dev/null); then
            echo "ERROR: 'GOOS=$goos go list -tags \"$tags\" ./pkg/...' failed; pkg imports not verified" >&2
            exit 2
        fi
        imports+="$out"$'\n'
    done
    for prefix in "$controller_prefix" "$steward_prefix"; do
        offenders=$(printf '%s' "$imports" | under_prefix "$prefix")
        if [ -n "$offenders" ]; then
            echo "ERROR: pkg package(s) import ${prefix#"$module_path"/} package(s) on GOOS=$goos (package, import):" >&2
            printf '%s\n' "$offenders" | sed 's/^/  /' >&2
            failed=1
        fi
    done
done

if [ "$failed" -ne 0 ]; then
    exit 1
fi

echo "OK: build boundary holds (steward -> no features/controller, controller -> no features/steward, pkg -> no features/controller or features/steward)"
