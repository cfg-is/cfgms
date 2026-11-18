#!/usr/bin/env bash
# Runs one cmd/steward name shard under its time budget (Issue #6328).
#
#   bash scripts/cmd-steward-shard-budget.sh <label> <budget-seconds> -- <go test command...>
#
# Runs the command, streams its output unchanged, then sums the durations of
# the top-level tests it reported (lines "--- PASS|FAIL: Test... (N.NNs)";
# subtests are indented and not counted, so a parent's time is not counted
# twice) and prints
#
#   SHARD_BUDGET <label> sum=<s>s budget=<b>s tests=<n>
#
# When $GITHUB_STEP_SUMMARY is set a table row for the shard is appended to it.
# A sum above the budget also prints a GitHub "::warning" annotation, so the
# overrun shows on the PR without opening the job log. The script warns but
# never fails on the sum: the same test set varies by more than 100 s between
# runs on one runner, so a fail line under the go test -timeout would flap and
# one at or above it would repeat the timeout. The wrapped command's own exit
# status is returned unchanged, and a run that hit -timeout still reports the
# sum of the tests that finished.
set -u

usage() {
    echo "usage: $0 <label> <budget-seconds> -- <command> [args...]" >&2
    exit 2
}

[[ $# -ge 4 ]] || usage
label=$1
budget=$2
[[ "$3" == "--" ]] || usage
shift 3

if [[ ! "$label" =~ ^[A-Za-z0-9._/-]+$ ]]; then
    echo "cmd-steward-shard-budget: label '${label}' must match [A-Za-z0-9._/-]+" >&2
    exit 2
fi
if [[ ! "$budget" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
    echo "cmd-steward-shard-budget: budget '${budget}' is not a number of seconds" >&2
    exit 2
fi

log=$(mktemp "${TMPDIR:-/tmp}/cmd-steward-shard.XXXXXX") || exit 2
trap 'rm -f "$log"' EXIT

"$@" 2>&1 | tee "$log"
rc=${PIPESTATUS[0]}

# \r is stripped because Windows runners can end log lines with CRLF.
read -r sum tests < <(tr -d '\r' < "$log" | awk '
    /^--- (PASS|FAIL): Test/ {
        if (match($0, /\([0-9]+(\.[0-9]+)?s\)[[:space:]]*$/)) {
            t = substr($0, RSTART + 1, RLENGTH - 3)
            sum += t
            n++
        }
    }
    END { printf "%.1f %d\n", sum, n }
')

printf 'SHARD_BUDGET %s sum=%ss budget=%ss tests=%s\n' "$label" "$sum" "$budget" "$tests"

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    {
        echo ""
        echo "| cmd/steward shard | Summed top-level test time | Budget |"
        echo "|---|---|---|"
        echo "| ${label} | ${sum}s | ${budget}s |"
    } >> "$GITHUB_STEP_SUMMARY"
fi

if awk -v s="$sum" -v b="$budget" 'BEGIN { exit !(s + 0 > b + 0) }'; then
    echo "::warning title=cmd/steward shard over budget::${label} summed ${sum}s against ${budget}s"
fi

exit "$rc"
