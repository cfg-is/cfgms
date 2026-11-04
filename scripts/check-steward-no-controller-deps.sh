#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# check-steward-no-controller-deps.sh — verify that ./cmd/steward depends on no
# features/controller/... package on linux, windows or darwin (Issue #5747).
#
# Stewards run on endpoints that may be compromised, so code that only the
# controller needs must not ship inside the steward binary. Shared code that
# the steward needs belongs under pkg/.
#
# Usage:
#   scripts/check-steward-no-controller-deps.sh [module-dir]
#
# module-dir defaults to the repository root. The steward main package is
# ./cmd/steward within it; the controller prefix is <module path>/features/controller.
#
# Exit codes:
#   0  no features/controller/... package in the steward dependency closure
#   1  at least one match (offending packages named on stderr)
#   2  the dependency closure could not be computed — the gate fails closed
#
# Tests: scripts/check-steward-no-controller-deps_test.sh, run by scripts/test-scripts.sh.

set -euo pipefail

MODULE_DIR="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
cd "$MODULE_DIR"

if ! module_path=$(go list -m 2>/dev/null) || [ -z "$module_path" ]; then
    echo "ERROR: could not determine the Go module path in $MODULE_DIR; steward dependencies not verified" >&2
    exit 2
fi
prefix="$module_path/features/controller"

failed=0
for goos in linux windows darwin; do
    if ! deps=$(GOOS="$goos" go list -deps ./cmd/steward 2>/dev/null); then
        echo "ERROR: 'GOOS=$goos go list -deps ./cmd/steward' failed; steward dependencies not verified" >&2
        exit 2
    fi
    offenders=$(printf '%s\n' "$deps" | grep -E "^${prefix//./\\.}(/|$)" || true)
    if [ -n "$offenders" ]; then
        echo "ERROR: ./cmd/steward depends on controller package(s) on GOOS=$goos:" >&2
        printf '%s\n' "$offenders" | sed 's/^/  /' >&2
        failed=1
    fi
done

if [ "$failed" -ne 0 ]; then
    exit 1
fi

echo "OK: ./cmd/steward depends on no features/controller/... package (linux, windows, darwin)"
