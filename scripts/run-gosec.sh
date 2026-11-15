#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# run-gosec.sh — run gosec from the fixed short scan root /tmp/s (Issue #6270).
#
# gosec hands packages.Load the absolute path of every file in a package, and
# packages.Load splits the list into chunks past 16383 characters; a chunked
# package reports `undefined:` type errors instead of findings. The absolute
# path prefix is the only part we control, so the repository is scanned
# through a short symlink. os.Getwd honours the logical $PWD, so gosec's
# filepath.Abs returns /tmp/s/... paths. Literal /tmp, not $TMPDIR (long on
# macOS).
#
# The symlink, the cd, the guard and gosec run in this one shell process.
#
# Usage: scripts/run-gosec.sh <gosec arguments>
#
# Tests: scripts/check-gosec-load-length_test.sh, run by scripts/test-scripts.sh.

set -euo pipefail

SCAN_ROOT="/tmp/s"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"

ln -sfn "$REPO_ROOT" "$SCAN_ROOT"
cd "$SCAN_ROOT"

GOSEC_SCAN_ROOT="$SCAN_ROOT" bash scripts/check-gosec-load-length.sh

exec gosec "$@"
