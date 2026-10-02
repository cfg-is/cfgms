#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# check-no-python-in-core.sh — verify that no tracked .py file exists under
# the core product / shipped path set (Issue #4303, Epic #4296).
#
# CFGMS's core product and shipped surfaces are Go (and, for web/, TypeScript)
# — a Python file under any of these trees is not a legitimate shipped
# artifact. Tracked Python belongs under .claude/ (agent tooling) or scripts/
# (dev tooling) instead. Unlike the raw-leader-primitive rule, there is no
# legitimate exception here, so no annotation escape hatch is provided.
#
# Usage:
#   scripts/check-no-python-in-core.sh
#
# Exit codes:
#   0  no .py file tracked under any of the six declared paths
#   1  at least one match (offending files named on stderr)
#   2  the scan could not be performed (not a git work tree, or git missing)
#      — the gate fails closed rather than reporting clean
#
# Tests: scripts/check-no-python-in-core_test.sh, run by scripts/test-scripts.sh.

set -euo pipefail

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "ERROR: not inside a git work tree; core product paths not verified" >&2
    exit 2
fi

# Single source of truth for the declared core-product/shipped path set.
#
# The patterns are '<root>/*.py', NOT '<root>/**/*.py'. Git's default
# (non-':(glob)') pathspec matching lets '*' cross '/', so '<root>/*.py' covers
# a file at any depth under <root> — including one placed directly in <root>.
# '<root>/**/*.py' requires the literal '/' after '**' and therefore silently
# misses top-level files such as web/setup.py, test/conftest.py or api/gen.py,
# which are exactly the shapes real Python tooling takes. Do not "fix" these
# back to '**/'; scripts/check-no-python-in-core_test.sh covers both depths.
set +e
matches=$(git ls-files -- 'cmd/*.py' 'pkg/*.py' 'features/*.py' 'api/*.py' 'web/*.py' 'test/*.py')
ls_files_rc=$?
set -e

if [ "$ls_files_rc" -ne 0 ]; then
    echo "ERROR: git ls-files failed (exit $ls_files_rc); core product paths not verified" >&2
    exit 2
fi

if [ -n "$matches" ]; then
    echo "ERROR: .py file(s) tracked under core product paths (cmd/, pkg/, features/, api/, web/, test/):" >&2
    echo "$matches" | sed 's/^/  /' >&2
    exit 1
fi

echo "OK: no .py file tracked under core product paths"
