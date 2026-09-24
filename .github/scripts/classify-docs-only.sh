#!/usr/bin/env bash
# Decide whether a PR's changed files are documentation only.
#
#   classify-docs-only.sh <changed-files.txt> [repo-root]
#
# Prints the reasoning, then exactly one final line: `code=true` or
# `code=false`. Always exits 0 -- the caller copies that line to
# $GITHUB_OUTPUT. Used by test-suite.yml's `changes` job (Issue #4215).
#
# THIS MUST FAIL CLOSED. `code=false` skips the unit-test legs and posts a
# PASSING `unit-tests` context with zero tests run. Every defect -- a missing
# or empty input, a failed grep -- resolves to `code=true`. A needlessly run
# suite costs runner minutes; a wrongly skipped one ships untested code.
#
# "Documentation" is decided by path, but some documentation paths are read
# by code under test. `docs/security-review/methodology.md` is loaded by
# harness_runner.py at import time and has a size ceiling. PR #4201 changed
# only that file, was classified docs-only, skipped the legs, and left
# develop red for `unit-tests-scripts` until the next code PR ran them. So a
# doc path counts as CODE when any code tree references it by its full
# repo-relative path. That set is derived here on every run, never listed by
# hand, so a new harness input cannot slip past the gate.
set -uo pipefail

files="${1:-}"
root="${2:-.}"

fail_closed() {
  echo "::warning::$1 — assuming code changes and running the full suite"
  echo "code=true"
  exit 0
}

[[ -n "$files" && -f "$files" ]] || fail_closed "no changed-files list given"
[[ -s "$files" ]] || fail_closed "changed-files list is empty"
[[ -d "$root" ]] || fail_closed "repo root ${root} is not a directory"

# Paths treated as documentation. Mirrors the set this workflow's
# pull_request trigger used to paths-ignore.
DOC_RE='^(docs/|[^/]+\.md$|\.claude/.*\.md$|LICENSE$|\.gitignore$|\.editorconfig$)'

# Doc paths that code reads: every full `docs/...` or `.claude/....md` path
# named anywhere in the harness/script trees or in any Go file, kept only when
# the file really exists, so test fixtures such as `docs/x.md` drop out. Over-
# inclusion is the safe direction: a path merely mentioned in a comment makes
# its PRs run the suite, which costs minutes and ships nothing untested.
consumed="$(mktemp)"
refs="$(mktemp)"
trap 'rm -f "$consumed" "$refs"' EXIT
ref_re='(docs/[A-Za-z0-9_./-]+|\.claude/[A-Za-z0-9_./-]+\.md)'
: > "$refs"
for tree in .claude/scripts scripts .github/scripts; do
  [[ -d "$root/$tree" ]] || continue
  grep_status=0
  grep -rhoE "$ref_re" "$root/$tree" >> "$refs" 2>/dev/null || grep_status=$?
  # grep exits 1 when a tree has no match, which is not a defect; >1 is.
  [[ "$grep_status" -le 1 ]] || fail_closed "deriving code-consumed doc paths from ${tree} failed (grep exit ${grep_status})"
done
grep_status=0
grep -rhoE "$ref_re" --include='*.go' \
  --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=vendor "$root" >> "$refs" 2>/dev/null \
  || grep_status=$?
[[ "$grep_status" -le 1 ]] || fail_closed "deriving code-consumed doc paths from Go files failed (grep exit ${grep_status})"

sed 's/[.]*$//' "$refs" | sort -u | while IFS= read -r path; do
  [[ -f "$root/$path" ]] && echo "$path"
done > "$consumed"

echo "Doc paths read by code (treated as code): $(wc -l < "$consumed")"

non_doc="$(mktemp)"
trap 'rm -f "$consumed" "$refs" "$non_doc"' EXIT
grep_status=0
grep -vE "$DOC_RE" "$files" > "$non_doc" || grep_status=$?
[[ "$grep_status" -le 1 ]] || fail_closed "classifying changed files failed (grep exit ${grep_status})"

# Changed doc files that code reads.
grep -xFf "$consumed" "$files" >> "$non_doc" 2>/dev/null

if [[ -s "$non_doc" ]]; then
  echo "Code, or documentation read by code, changed — running the unit-test legs:"
  sort -u "$non_doc"
  echo "code=true"
else
  echo "All $(wc -l < "$files") changed file(s) are documentation that no code reads — legs will be skipped"
  echo "code=false"
fi
