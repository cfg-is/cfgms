---
name: pipeline-sweep
description: Run the closeout and reconciliation sweep — epic review followed by project board status sync. Closes fully-delivered epics, drafts remediation stories for epics with AC gaps, and moves closed GitHub issues whose project status is stale to Done. Invoked automatically at the end of /po cron and /po cycle; also runnable on demand.
context: fork
agent: general-purpose
allowed-tools: Bash, Read, Grep, Skill
---

# Pipeline Sweep Skill

You run two reconciliation passes against the pipeline:

1. **Epic review** — close every open epic whose work is fully delivered; draft remediation stories for epics whose sub-tasks are done but AC verification fails.
2. **Project status sync** — for every CLOSED GitHub issue on the project board, ensure its project status is `Done`.

The sync direction is **one-way only**: CLOSED-on-GitHub → status `Done`. Never close a GH issue based on its project status — that hides bad merges into sibling branches (see #1760/#1773).

## Phase 1: Epic review

Invoke the `epic-review` skill with no arguments (sweep all open epics):

```
Skill: epic-review
```

Capture its verdict table for the final report. If `Skill` is unavailable in this session, follow the steps from `.claude/skills/epic-review/SKILL.md` inline.

## Phase 2: Project status sync

For each non-terminal status, list its items and check whether their backing GitHub issue is actually CLOSED. Any CLOSED issue at a non-`Done` status is stale and must be updated.

```bash
# Non-terminal statuses worth checking. Done and Blocked are excluded:
#   Done    — already terminal
#   Blocked — may be intentionally held by founder action; don't auto-resolve
for status in "Draft" "Ready" "In Progress" "Reviewing" "Fix" "Failed"; do
    /workspace/scripts/project-queue.sh list-by-status "$status" 2>/dev/null \
      | jq -r --arg s "$status" '.[] | "\($s)\t\(.item_id)\t\(.issue_num)\t\(.title)"'
done > /tmp/pipeline-sweep-nonterm.tsv
```

Batch-query the state of every issue_num found:

```bash
issue_nums=$(awk -F'\t' '{print $3}' /tmp/pipeline-sweep-nonterm.tsv | sort -u | paste -sd,)
gh api graphql -f query='
  query($q: String!) {
    search(query: $q, type: ISSUE, first: 100) {
      nodes { ... on Issue { number state closedAt } }
    }
  }
' -f q="repo:cfg-is/cfgms is:issue state:closed $(awk -F'\t' '{print $3}' /tmp/pipeline-sweep-nonterm.tsv | sed 's/^/ /' | tr -d '\n')" \
  > /tmp/pipeline-sweep-closed.json
```

Or simpler per-issue check (slower but unambiguous, fine for sweep cadence):

```bash
while IFS=$'\t' read -r prev_status item_id issue_num title; do
    state=$(gh issue view "$issue_num" --repo cfg-is/cfgms --json state -q .state 2>/dev/null || echo MISSING)
    if [[ "$state" == "CLOSED" ]]; then
        echo -e "$issue_num\t$prev_status\t$item_id\t$title"
    fi
done < /tmp/pipeline-sweep-nonterm.tsv > /tmp/pipeline-sweep-stale.tsv
```

For each stale entry, move the project item to `Done`:

```bash
while IFS=$'\t' read -r issue_num prev_status item_id title; do
    /workspace/scripts/project-queue.sh update-field "$item_id" status Done
    echo "Updated #$issue_num ($title): $prev_status → Done"
done < /tmp/pipeline-sweep-stale.tsv
```

**Special case — Blocked items:** do NOT touch Blocked items even if the backing issue is CLOSED. Blocked is held intentionally by founder action (CLA Assistant configuration, release tagging, etc.); if a Blocked item's issue is closed, that's a state worth surfacing to the founder, not auto-resolving.

```bash
/workspace/scripts/project-queue.sh list-by-status Blocked \
  | jq -r '.[] | "\(.item_id)\t\(.issue_num)\t\(.title)"' \
  | while IFS=$'\t' read -r item_id issue_num title; do
      state=$(gh issue view "$issue_num" --repo cfg-is/cfgms --json state -q .state 2>/dev/null || echo MISSING)
      if [[ "$state" == "CLOSED" ]]; then
          echo "⚠ Blocked item #$issue_num ($title) is CLOSED on GitHub — review needed (NOT auto-resolved)"
      fi
  done > /tmp/pipeline-sweep-blocked-anomaly.txt
```

## Phase 3: Report

Two sections plus a one-line headline.

### Epic review

Reproduce the verdict table from Phase 1 verbatim.

### Status sync

| Issue | Title | Previous status | Action |
|---|---|---|---|
| #NNNN | <title> | In Progress | → Done |
| #MMMM | <title> | Reviewing | → Done |

If nothing needed correcting: `No stale project items found.`

If any Blocked anomalies in `/tmp/pipeline-sweep-blocked-anomaly.txt`, surface them under a separate "Needs founder review" subsection.

### Headline

One line:
`Epics closed: X. Remediation stories drafted: Y. Status mismatches corrected: Z. Blocked anomalies: W.`

## Conventions

- One-way sync only: closed-GH → `Done`. Never close GH from project state.
- Blocked items are surfaced, never mutated.
- Safe to run repeatedly — idempotent. No-ops when state is already correct.
- Designed to run at the tail of `/po cron` and `/po cycle`. Standalone invocation `/pipeline-sweep` is also supported.
- Read-only on the working tree. All side effects go through `gh issue` and `project-queue.sh` — no file edits, no commits.
