#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# run-gosec.sh — run gosec from a private, short, per-run scan root (Issues #6270, #6276).
#
# gosec hands packages.Load the absolute path of every file in a package, and
# packages.Load splits the list into chunks past 16383 characters; a chunked
# package reports `undefined:` type errors instead of findings. The absolute
# path prefix is the only part we control, so the repository is scanned
# through a short symlink. os.Getwd honours the logical $PWD, so gosec's
# filepath.Abs returns /tmp/gXXXXXX/s/... paths. Literal /tmp, not $TMPDIR
# (long on macOS).
#
# The scan root is a fresh mktemp -d directory (mode 0700, owned by the caller)
# holding a one-character symlink to the checkout, so a path another local user
# pre-created in the shared /tmp is never followed and concurrent runs do not
# share a link. The link target is verified before the cd, and the directory is
# removed on exit. The symlink, the cd, the guard and gosec run in this one
# shell process; gosec's exit code is returned unchanged.
#
# Usage: scripts/run-gosec.sh <gosec arguments>
#
# Tests: scripts/check-gosec-load-length_test.sh, run by scripts/test-scripts.sh.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"

SCAN_DIR="$(mktemp -d /tmp/gXXXXXX)"
SCAN_ROOT="$SCAN_DIR/s"

cleanup() {
    rm -f "$SCAN_DIR/s"
    rmdir "$SCAN_DIR"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

ln -s "$REPO_ROOT" "$SCAN_ROOT"
if [ "$(readlink "$SCAN_ROOT")" != "$REPO_ROOT" ]; then
    echo "run-gosec.sh: scan root $SCAN_ROOT does not point at $REPO_ROOT" >&2
    exit 1
fi
cd "$SCAN_ROOT"

GOSEC_SCAN_ROOT="$SCAN_ROOT" bash "$REPO_ROOT/scripts/check-gosec-load-length.sh"

rc=0
gosec "$@" || rc=$?
exit "$rc"
