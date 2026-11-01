#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# check-no-banned-exec-patterns.sh — verify that dev/CI tooling carries none
# of CLAUDE.md's banned execution patterns (Issue #4343): iex,
# Invoke-Expression, powershell -Command "<string>", -EncodedCommand,
# -ExecutionPolicy Bypass, bash -c "<string>", eval, python -c.
#
# CLAUDE.md bans these patterns for modules and scripts that run on a managed
# endpoint: they compose a command string at runtime instead of execing an
# argument slice, which is exactly the shape that turns an attacker-controlled
# value into code. This gate holds the same rule for the files verified in
# Issue #4343's audit pass -- windows-setup.ps1 (a developer workstation setup
# script that used to pipe a remote installer into `iex`) and the two script
# templates under templates/scripts/ (intended to be copied as a starting
# point for new modules, so a banned pattern there propagates by design).
#
# Usage:
#   scripts/check-no-banned-exec-patterns.sh
#
# Exit codes:
#   0  none of the checked files contain a banned pattern
#   1  at least one match (offending file:line named on stderr)
#   2  a file this gate names was not found -- the check could not run
#
# Tests: scripts/check-no-banned-exec-patterns_test.sh, run by
# scripts/test-scripts.sh.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# CFGMS_TEST_CHECK_FILES lets the test suite point this gate at fixture files
# instead of the real repo tree, one per line. Unset in every real run, where
# the fixed set below applies.
if [[ -n "${CFGMS_TEST_CHECK_FILES:-}" ]]; then
    mapfile -t files <<<"${CFGMS_TEST_CHECK_FILES}"
else
    files=(
        "${REPO_ROOT}/windows-setup.ps1"
        "${REPO_ROOT}/templates/scripts/backup/config-backup.yaml"
        "${REPO_ROOT}/templates/scripts/system/log-rotation.yaml"
    )
fi

for f in "${files[@]}"; do
    if [[ ! -f "$f" ]]; then
        echo "ERROR: expected file not found: $f" >&2
        exit 2
    fi
done

# Each pattern is a grep -E regex, case-insensitive, matched against
# comment-stripped source (PowerShell '#'/YAML '#' comments — both files use
# '#' for line comments — are excluded so a comment that merely NAMES a
# banned pattern, e.g. explaining why one is absent, does not self-trip).
declare -a patterns=(
    '(^|[^a-zA-Z0-9_])iex([[:space:]]|\()'
    'invoke-expression'
    '-encodedcommand'
    '-executionpolicy[[:space:]]+bypass'
    'powershell(\.exe)?[[:space:]].*-command[[:space:]]+["'"'"']'
    'bash[[:space:]]+-c[[:space:]]+["'"'"']'
    '(^|[^a-zA-Z0-9_.])eval([[:space:]]|\()'
    'python[0-9.]*[[:space:]]+-c([[:space:]]|$)'
)

violations=0
for f in "${files[@]}"; do
    stripped=$(grep -vE '^[[:space:]]*#' "$f")
    for pat in "${patterns[@]}"; do
        hit=$(printf '%s\n' "$stripped" | grep -inE "$pat" || true)
        if [[ -n "$hit" ]]; then
            echo "ERROR: banned execution pattern in ${f#"$REPO_ROOT"/} (pattern: ${pat}):" >&2
            echo "$hit" | sed 's/^/  /' >&2
            violations=$((violations + 1))
        fi
    done
done

if [[ "$violations" -gt 0 ]]; then
    exit 1
fi

echo "OK: no banned execution pattern in windows-setup.ps1 or the script templates"
