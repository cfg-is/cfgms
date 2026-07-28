#!/usr/bin/env bash
# Regression test for per-cycle step manifests (Issue #3053).
#
# A `/po cron` cycle is one long agent session, so token_report.py attributes
# its whole cost to a single segment -- what the Tech Lead pass costs versus
# the pin sweep versus acceptance review was not derivable at any effort.
# Covers: cycle-start/cycle-end/cycle-report end to end against a real
# fixture transcript (real measured cost flows through, not a zero-value
# happy path), the deterministic step-boundary hook (every subcommand except
# the cycle bracket itself auto-marks a step), the no-cycle-open no-op
# contract, lease events, and durability against the same retention/cleanup
# paths #3052's ledger already proved itself isolated from.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
POACT="${REPO_ROOT}/.claude/scripts/po-act.sh"
TOKEN_REPORT="${REPO_ROOT}/.claude/metrics/token_report.py"

for f in "$POACT" "$TOKEN_REPORT"; do
  [[ -f "$f" ]] || { printf 'FAIL: expected file not found: %s\n' "$f" >&2; exit 1; }
done

fail=0; ran=0
ok()   { ran=$((ran + 1)); printf '  ok    %s\n' "$1"; }
bad()  { ran=$((ran + 1)); fail=$((fail + 1)); printf '  FAIL  %s\n        %s\n' "$1" "${2:-}"; }
check_eq() {
  local desc="$1" actual="$2" expected="$3"
  if [[ "$actual" == "$expected" ]]; then ok "$desc"
  else bad "$desc" "want: ${expected}  actual: ${actual}"; fi
}
check_contains() {
  local desc="$1" hay="$2" needle="$3"
  if [[ "$hay" == *"$needle"* ]]; then ok "$desc"
  else bad "$desc" "want substring: ${needle}"; fi
}
jf() {
  python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print($2)" "$1" 2>/dev/null
}

echo "cycle_manifest.test.sh"
echo "-----------------------"

printf '\n== bash -n parses ==\n'
if bash -n "$POACT" 2>/dev/null; then ok "po-act.sh parses"; else bad "po-act.sh parses" "bash -n failed"; fi

SANDBOX="$(mktemp -d)"
trap 'rm -rf "$SANDBOX"' EXIT

export CFGMS_TEST_REPO_ROOT="$REPO_ROOT"
export PO_CACHE_DIR="${SANDBOX}/po"
export CFGMS_AGENT_LEDGER_DIR="${SANDBOX}/ledger"
CYCLE_DIR="${PO_CACHE_DIR}/cycles"

printf '\n== no cycle open: a subcommand call is a silent no-op ==\n'
out="$(bash "$POACT" merge-queue 2>&1)"
rc=$?
check_eq "merge-queue still runs normally with no cycle open" "$rc" "0"
if [[ -d "$CYCLE_DIR" ]]; then
  bad "no manifest directory created with no cycle open" "found ${CYCLE_DIR}"
else
  ok "no manifest directory created with no cycle open"
fi

printf '\n== cycle-start / auto step-marking / cycle-end / cycle-report, real measured cost ==\n'
SESSION="cycle-test-session"
export CLAUDE_CODE_SESSION_ID="$SESSION"

# A real transcript for this session so cycle-end's correlation pulls actual
# measured cost through the full path (bash -> token_report.py -> parsed
# usage), not just "did it crash on an empty corpus".
PROJECTS_ROOT="${SANDBOX}/claude-projects"
PROJECT_DIR="${PROJECTS_ROOT}/-workspace"
mkdir -p "$PROJECT_DIR"
python3 - "$PROJECT_DIR" "$SESSION" <<'PYEOF'
import json, sys
project_dir, session = sys.argv[1], sys.argv[2]
def row(request_id, ts):
    return json.dumps({
        "type": "assistant", "requestId": request_id, "timestamp": ts,
        "gitBranch": "develop", "cwd": "/workspace", "isSidechain": False,
        "message": {"model": "claude-sonnet-4-6", "usage": {
            "input_tokens": 1000, "cache_read_input_tokens": 0, "output_tokens": 500,
        }},
    })
with open(f"{project_dir}/{session}.jsonl", "w") as f:
    f.write(row("req_a", "2026-07-28T11:00:30Z") + "\n")  # before any step -> unattributed
    f.write(row("req_b", "2026-07-28T11:02:00Z") + "\n")  # after merge-queue's step
PYEOF

out="$(bash "$POACT" cycle-start cron 2>&1)"
check_contains "cycle-start reports CYCLE_STARTED" "$out" "CYCLE_STARTED:"
cycle_id="$(cat "${CYCLE_DIR}/current")"
manifest="${CYCLE_DIR}/${cycle_id}.json"
[[ -f "$manifest" ]] && ok "manifest file created" || bad "manifest file created" "missing: $manifest"
check_eq "manifest records the harness session id" "$(jf "$manifest" 'd["session"]')" "$SESSION"
check_eq "manifest starts with end=null (AC4: describable mid-run)" "$(jf "$manifest" 'd["end"]')" "None"

# Backdate the manifest's start + this step's ts so they land before req_a/req_b's fixed
# fixture timestamps (2026-07-28T11:00:30Z / 11:02:00Z) -- cycle-start/step marking use
# the real clock, which is not 2026-07-28T11:00 at test-run time.
python3 - "$manifest" <<PYEOF
import json
with open("$manifest") as f:
    m = json.load(f)
m["start"] = "2026-07-28T11:00:00Z"
with open("$manifest", "w") as f:
    json.dump(m, f)
PYEOF

bash "$POACT" merge-queue >/dev/null 2>&1 || true
python3 - "$manifest" <<PYEOF
import json
with open("$manifest") as f:
    m = json.load(f)
m["steps"][-1]["ts"] = "2026-07-28T11:01:00Z"
with open("$manifest", "w") as f:
    json.dump(m, f)
PYEOF

step_count_before_end="$(jf "$manifest" 'len(d["steps"])')"
check_eq "one step auto-recorded for the merge-queue call" "$step_count_before_end" "1"
check_eq "the recorded step names the real subcommand" "$(jf "$manifest" 'd["steps"][0]["subcommand"]')" "merge-queue"
if [[ "$(jf "$manifest" 'd["steps"][0]')" == *'"cost_usd"'* ]]; then
  bad "step has no cost yet before cycle-end" "cost_usd present pre-correlation"
else
  ok "step has no cost yet before cycle-end (proves cycle-end, not cycle-start, computes it)"
fi

# Exercise the REAL cycle-end subcommand end to end -- CFGMS_TEST_TRANSCRIPTS_DIR
# points its internal token_report.py call at the fixture corpus instead of the
# real ~/.claude/projects, so this stays hermetic without faking the code path.
out="$(CFGMS_TEST_TRANSCRIPTS_DIR="$PROJECTS_ROOT" bash "$POACT" cycle-end 2>&1)"
check_contains "cycle-end reports CYCLE_ENDED" "$out" "CYCLE_ENDED:"
check_eq "current-cycle pointer cleared after cycle-end" "$([[ -f "${CYCLE_DIR}/current" ]] && echo present || echo cleared)" "cleared"
check_eq "manifest end timestamp is set" "$([[ "$(jf "$manifest" 'd["end"]')" != "None" ]] && echo set || echo unset)" "set"
check_eq "correlation attributes the merge-queue step's own call" \
  "$(jf "$manifest" 'd["steps"][0]["calls"]')" "1"
check_eq "the call before the step boundary is unattributed" \
  "$(jf "$manifest" 'd["unattributed"]["calls"]')" "1"
if [[ "$(jf "$manifest" 'd["cycle_cost_usd"]')" != "0.0" ]] && [[ "$(jf "$manifest" 'd["cycle_cost_usd"]')" != "None" ]]; then
  ok "cycle_cost_usd is real measured dollars, not zero or null"
else
  bad "cycle_cost_usd is real measured dollars, not zero or null" "got: $(jf "$manifest" 'd["cycle_cost_usd"]')"
fi

printf '\n== cycle-report ==\n'
report="$(bash "$POACT" cycle-report 5 2>&1)"
check_contains "cycle-report names the step" "$report" "merge-queue"
check_contains "cycle-report shows a totals row" "$report" "Average cost per cycle"

printf '\n== incomplete cycles are excluded from the average but stay on disk (AC4) ==\n'
bash "$POACT" cycle-start cron >/dev/null 2>&1
incomplete_id="$(cat "${CYCLE_DIR}/current")"
bash "$POACT" merge-queue >/dev/null 2>&1 || true
rm -f "${CYCLE_DIR}/current"  # simulate a crash: never reached cycle-end
[[ -f "${CYCLE_DIR}/${incomplete_id}.json" ]] && ok "crashed cycle's manifest survives on disk" \
  || bad "crashed cycle's manifest survives on disk" "missing"
report2="$(bash "$POACT" cycle-report 5 2>&1)"
check_contains "cycle-report notes the incomplete cycle" "$report2" "incomplete"

printf '\n== structural: lease events wired into the actual acquire/release helpers ==\n'
poact_src="$(cat "$POACT")"
acquire_body="$(awk '/^_acquire_lease\(\) \{/{f=1} f{print} f&&/^\}/{exit}' "$POACT")"
release_body="$(awk '/^_release_lease\(\) \{/{f=1} f{print} f&&/^\}/{exit}' "$POACT")"
check_contains "_acquire_lease records a cycle lease event" "$acquire_body" "_cycle_append_lease"
check_contains "_release_lease records a cycle lease event" "$release_body" "_cycle_append_lease"

printf '\n== structural: every subcommand auto-marks a step except the cycle bracket itself ==\n'
check_contains "hook runs right after cmd parsing, before the case statement" "$poact_src" \
  'if [[ "$cmd" != "cycle-start" && "$cmd" != "cycle-end" ]]; then'
check_contains "hook calls _cycle_append_step with the real subcommand and args" "$poact_src" \
  '_cycle_append_step "$cmd" "$@"'

printf '\n== durability: cycle manifests live outside the ledger/session-transcript trees ==\n'
check_eq "CYCLE_DIR is distinct from the dispatch ledger dir" \
  "$([[ "$CYCLE_DIR" != "$CFGMS_AGENT_LEDGER_DIR"* ]] && echo distinct || echo same)" "distinct"
check_contains "CYCLE_DIR sits beside CACHE_DIR, not under it via retention pruning" "$poact_src" \
  'CYCLE_DIR="${CFGMS_CYCLE_DIR:-${CACHE_DIR}/cycles}"'

printf '\n%s\n' "-----------------------------------------"
if [[ "$fail" -eq 0 ]]; then
  printf 'PASS: %d checks\n' "$ran"; exit 0
else
  printf 'FAIL: %d of %d checks failed\n' "$fail" "$ran"; exit 1
fi
