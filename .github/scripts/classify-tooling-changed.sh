#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# Thin CI wrapper around scripts/lib/detect-tooling-changed.sh (Issue #4304,
# Epic #4296). The shared detector decides which of the four suite groups
# (core, security-review, claude-tooling, devinfra) a diff must run; this
# wrapper adapts that decision to the `changes` job's existing inputs so the
# job doesn't make a second GitHub API call to re-list the PR's files.
#
#   classify-tooling-changed.sh <changed-files.txt> <base-ref> [repo-root]
#
# <changed-files.txt> is the `changes` job's already-fetched PR file list
# (from `gh api .../pulls/{n}/files`, validated there against defects 1-3).
# It is reused only as a precondition check here -- proof that the earlier
# step actually produced a real file list -- not re-derived. The actual
# group classification is delegated entirely to the shared detector, which
# diffs <base-ref>...HEAD with git so both callers (this wrapper and local
# `make test`) run one classification algorithm instead of two.
#
# Prints reasoning, then exactly one final line: `groups=<csv>`. Always
# exits 0, matching classify-docs-only.sh and detect-tooling-changed.sh --
# the caller copies that line to $GITHUB_OUTPUT.
#
# THIS MUST FAIL CLOSED, identically to classify-docs-only.sh and
# detect-tooling-changed.sh: every defect here -- a missing or empty changed-
# files list, a missing base ref, a missing repo root, a missing or
# non-executable detector script -- resolves to every group. A needlessly run
# suite costs runner minutes; a wrongly skipped one ships untested tooling.
set -uo pipefail

ALL_GROUPS="groups=core,security-review,claude-tooling,devinfra"

changed_files="${1:-}"
base_ref="${2:-}"
root="${3:-.}"

fail_closed() {
  echo "::warning::$1 — assuming every suite group is affected"
  echo "$ALL_GROUPS"
  exit 0
}

[[ -n "$changed_files" && -f "$changed_files" ]] || fail_closed "no changed-files list given"
[[ -s "$changed_files" ]] || fail_closed "changed-files list is empty"
[[ -n "$base_ref" ]] || fail_closed "no base ref given"
[[ -d "$root" ]] || fail_closed "repo root ${root} is not a directory"

echo "Reusing changed-files list: $(wc -l < "$changed_files") file(s) (no re-fetch)"

detector="$root/scripts/lib/detect-tooling-changed.sh"
[[ -f "$detector" ]] || fail_closed "detector script ${detector} not found"
[[ -x "$detector" ]] || fail_closed "detector script ${detector} not executable"

echo "Delegating classification to ${detector} against base ref '${base_ref}'"

out="$(mktemp)"
trap 'rm -f "$out"' EXIT
rc=0
"$detector" "$base_ref" "$root" > "$out" 2>&1 || rc=$?

cat "$out"

if [[ "$rc" -ne 0 ]]; then
  fail_closed "detector exited ${rc}"
fi

verdict="$(tail -1 "$out")"
case "$verdict" in
  groups=*) echo "$verdict" ;;
  *) fail_closed "detector produced no groups= verdict" ;;
esac
