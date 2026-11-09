#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# macos-gate-rule.sh — decide whether one native macOS leg's result is
# acceptable to the PR-side Build Gate (Issue #5974).
#
# Usage:
#   scripts/macos-gate-rule.sh <changes_result> <macos_output> <leg_result>
#
#   changes_result  needs.changes.result of cross-platform-build-pr.yml
#   macos_output    needs.changes.outputs.macos (may be empty)
#   leg_result      needs.<macos leg>.result
#
# Exit codes:
#   0  the leg result is acceptable
#   1  it is not (the reason is on stderr)
#
# The macOS legs are skipped on a pull request that does not touch the macOS
# package closure (scripts/macos-pr-filter.sh). macOS does not run in the merge
# queue, so a skipped leg is only believable when `changes` succeeded AND its
# `macos` output is exactly `false`. An empty or unexpected output, a failed
# `changes` job, or a failed/cancelled leg is rejected. A leg that ran and
# succeeded is accepted whatever the output says.
#
# Tests: test_macos_gate_rule in scripts/test-scripts.sh.

set -euo pipefail

if [ "$#" -ne 3 ]; then
    echo "usage: $0 <changes_result> <macos_output> <leg_result>" >&2
    exit 1
fi

changes_result="$1"
macos_output="$2"
leg_result="$3"

case "$leg_result" in
    success)
        exit 0
        ;;
    skipped)
        if [ "$changes_result" != "success" ]; then
            echo "::error::macOS leg skipped but change detection did not succeed (result: ${changes_result:-<unset>})" >&2
            exit 1
        fi
        if [ "$macos_output" != "false" ]; then
            echo "::error::macOS leg skipped but the macos output is '${macos_output:-<unset>}', not 'false'" >&2
            exit 1
        fi
        exit 0
        ;;
    *)
        echo "::error::macOS leg result '${leg_result:-<unset>}' is not acceptable" >&2
        exit 1
        ;;
esac
