#!/usr/bin/env bash
# Decide which suite groups (core, security-review, claude-tooling, devinfra)
# must run for a given diff (Issue #4302, Epic #4296).
#
#   detect-tooling-changed.sh <base-ref> [repo-root]
#
# Prints reasoning, then exactly one final line: `groups=<csv>`. `core` is
# always included. Always exits 0 -- this is a shared decision function for
# both CI gating and local `make test` gating, and neither caller should have
# to special-case a non-zero exit.
#
# THIS MUST FAIL CLOSED, identically to .github/scripts/classify-docs-only.sh:
# every input defect -- a missing base ref, a base ref that does not resolve,
# a failed `git diff` -- resolves to every group, never a partial or empty
# answer. A needlessly run suite costs runner minutes; a wrongly skipped one
# ships untested tooling.
#
# If the diff touches the gating machinery itself (scripts/test-scripts.sh,
# .github/workflows/test-suite.yml), every group runs immediately -- the
# mechanism that decides what to skip changed, so nothing else in the diff is
# trusted to be classifiable by it. The Makefile is NOT in this set (Issue
# #4424): it is a large shared file, and only two spots in it -- the
# test-scripts target forwarding CFGMS_TEST_SCRIPTS_GROUPS, and `make test`'s
# group auto-detection -- take part in this gating at all. A Makefile change
# that touches neither of those (the overwhelming majority: Go build/test
# targets) cannot affect which suite group any test belongs to, so it is
# classified like any other path -- `core` always, plus whichever other
# groups the rest of the diff selects on its own paths.
# scripts/test-scripts.sh's test_make_test_groups (core group) guards the one
# gating-relevant Makefile wiring directly, so a break there is still caught
# even though a Makefile change no longer forces every group by itself.
set -uo pipefail

ALL_GROUPS="groups=core,security-review,claude-tooling,devinfra"

base_ref="${1:-}"
root="${2:-.}"

fail_closed() {
  echo "::warning::$1 -- assuming every suite group is affected"
  echo "$ALL_GROUPS"
  exit 0
}

[[ -n "$base_ref" ]] || fail_closed "no base ref given"
[[ -d "$root" ]] || fail_closed "repo root ${root} is not a directory"

git -C "$root" rev-parse --is-inside-work-tree >/dev/null 2>&1 \
  || fail_closed "${root} is not inside a git work tree"

git -C "$root" rev-parse --verify --quiet "${base_ref}^{commit}" >/dev/null 2>&1 \
  || fail_closed "base ref '${base_ref}' does not resolve to a commit"

ahead_count="$(git -C "$root" rev-list --count "${base_ref}..HEAD" 2>/dev/null)" \
  || fail_closed "could not count commits ahead of '${base_ref}'"
[[ "$ahead_count" =~ ^[0-9]+$ ]] \
  || fail_closed "unexpected rev-list output counting commits ahead of '${base_ref}'"

changed="$(mktemp)"
trap 'rm -f "$changed"' EXIT

if [[ "$ahead_count" -gt 0 ]]; then
  echo "HEAD has ${ahead_count} commit(s) ahead of ${base_ref} -- diffing ${base_ref}...HEAD"
  git -C "$root" diff --name-only "${base_ref}...HEAD" > "$changed" \
    || fail_closed "git diff --name-only ${base_ref}...HEAD failed"
else
  echo "HEAD has no commits ahead of ${base_ref} -- diffing working tree against ${base_ref}"
  git -C "$root" diff --name-only "${base_ref}" > "$changed" \
    || fail_closed "git diff --name-only ${base_ref} (working tree) failed"
fi

echo "Changed file(s): $(wc -l < "$changed")"

# The gating machinery itself changed -- nothing else in this diff can be
# trusted to be classified honestly by the thing that just changed. Makefile
# is deliberately excluded -- see the header comment.
GATING_RE='^(scripts/test-scripts\.sh|\.github/workflows/test-suite\.yml)$'
grep_status=0
grep -qE "$GATING_RE" "$changed" || grep_status=$?
case "$grep_status" in
  0)
    echo "Gating machinery itself changed -- running every suite group"
    echo "$ALL_GROUPS"
    exit 0
    ;;
  1) ;; # no match, keep classifying
  *) fail_closed "matching gating-machinery paths failed (grep exit ${grep_status})" ;;
esac

groups="core"

# security-review: .claude/skills/security-review/**
grep_status=0
grep -qE '^\.claude/skills/security-review/' "$changed" || grep_status=$?
case "$grep_status" in
  0) groups="${groups},security-review" ;;
  1) ;;
  *) fail_closed "matching security-review paths failed (grep exit ${grep_status})" ;;
esac

# claude-tooling: .claude/** EXCLUDING .claude/skills/security-review/** --
# a plain grep exclude (not a lookahead) for portability.
claude_status=0
grep -E '^\.claude/' "$changed" > /dev/null || claude_status=$?
if [[ "$claude_status" -gt 1 ]]; then
  fail_closed "matching .claude/ paths failed (grep exit ${claude_status})"
elif [[ "$claude_status" -eq 0 ]]; then
  exclude_status=0
  grep -E '^\.claude/' "$changed" | grep -vqE '^\.claude/skills/security-review/' || exclude_status=$?
  case "$exclude_status" in
    0) groups="${groups},claude-tooling" ;;
    1) ;;
    *) fail_closed "excluding security-review paths from .claude/ match failed (grep exit ${exclude_status})" ;;
  esac
fi

# devinfra: .github/scripts/** or .devcontainer/**
grep_status=0
grep -qE '^(\.github/scripts/|\.devcontainer/)' "$changed" || grep_status=$?
case "$grep_status" in
  0) groups="${groups},devinfra" ;;
  1) ;;
  *) fail_closed "matching devinfra paths failed (grep exit ${grep_status})" ;;
esac

echo "Matched suite groups: ${groups}"
echo "groups=${groups}"
