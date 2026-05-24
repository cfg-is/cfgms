#!/usr/bin/env bash
# Log-injection linter wrapper.
#
# Thin shim over the Go AST linter in scripts/lint-log-injection/main.go.
# This file exists at the path named by Issue #1771's acceptance criteria;
# the analysis logic lives in the Go package so it can be invoked directly
# from `go run ./scripts/lint-log-injection` (the form used by the Makefile
# target and the pre-commit hook for speed).
#
# Args: file paths to lint. With no args, scans every Go file under
# features/**/api/ that isn't a *_test.go.
#
# Exit codes: 0 = clean, 1 = findings, 2 = parse/IO error.

set -euo pipefail

# Resolve the repo root from this script's location so the linter works
# regardless of the caller's CWD (pre-commit hook, Makefile, ad-hoc shell).
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/.." && pwd)"

cd "$repo_root"
exec go run ./scripts/lint-log-injection "$@"
