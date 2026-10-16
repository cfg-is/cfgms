#!/usr/bin/env bash
# Tests for the PO merge-lane author-trust gate in po.md (Issue #5065).
#
# The session merges lane PRs without asking, so the lane must exclude PRs from
# untrusted external authors unless a maintainer released them. This test
# extracts the lane jq filter from po.md verbatim (drift guard) and runs it
# against a fixture preflight JSON, then checks Step 0 forbids `gh pr merge`.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
POMD="${REPO_ROOT}/.claude/agents/po.md"

[[ -f "$POMD" ]] || { printf 'FAIL: po.md not found at %s\n' "$POMD" >&2; exit 1; }
command -v jq >/dev/null || { printf 'FAIL: jq not installed\n' >&2; exit 1; }

fail=0
check() {  # check <desc> <actual> <expected>
  if [[ "$2" == "$3" ]]; then printf '  ok    %s\n' "$1"
  else printf '  FAIL  %s\n        want: %q\n        got:  %q\n' "$1" "$3" "$2"; fail=$((fail + 1)); fi
}

echo ""
echo "po_lane_external_pr_gate.test.sh"

LANE_FILTER='.prs_open[] | select((.is_external | not) or .is_released)'

if grep -qF "$LANE_FILTER" "$POMD"; then
  printf '  ok    lane filter present in po.md verbatim\n'
else
  printf '  FAIL  lane filter not found in po.md: %s\n' "$LANE_FILTER"; fail=$((fail + 1))
fi

FIXTURE='{"prs_open":[
 {"number":1,"is_external":false,"is_released":false},
 {"number":2,"is_external":true,"is_released":false},
 {"number":3,"is_external":true,"is_released":true}]}'
selected="$(jq -c "[${LANE_FILTER} | .number]" <<<"$FIXTURE")"
check "lane selects internal and released external only" "$selected" "[1,3]"

step0="$(grep -A3 'Step 0 — External PR triage' "$POMD" || true)"
if [[ "$step0" == *'gh pr merge'* ]]; then
  printf '  ok    Step 0 names gh pr merge\n'
else
  printf '  FAIL  Step 0 does not name gh pr merge\n'; fail=$((fail + 1))
fi

quar="$(grep 'EXTERNAL PR QUARANTINE' "$POMD" || true)"
if [[ "$quar" == *'never merged by this session'* ]]; then
  printf '  ok    quarantine bullet forbids any merge\n'
else
  printf '  FAIL  quarantine bullet lacks never-merged rule\n'; fail=$((fail + 1))
fi

[[ $fail -eq 0 ]] || { printf '%d check(s) failed\n' "$fail"; exit 1; }
echo "all checks passed"
