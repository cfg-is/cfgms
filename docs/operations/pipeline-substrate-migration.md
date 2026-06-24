# Pipeline Substrate Migration: Labels → GitHub Projects V2

## Summary

Stories #1476–#1482 (pipeline-security epic #1469) migrated the CFGMS work queue from GitHub
Issues labels (`pipeline:*`, `agent:*`) to a private GitHub Projects V2 board. This document
describes the new substrate, the migration state, and operational procedures.

## What Changed

| Before (labels) | After (Projects V2) |
|-----------------|---------------------|
| `pipeline:draft` label | "Draft" status field value |
| `pipeline:ready` / `agent:ready` label | "Ready" status field value |
| `agent:in-progress` label | "In Progress" status field value |
| `pipeline:reviewing` label | Container existence check (`cfg-agent-review-pr-<N>`) |
| `pipeline:fix` label | "Fix" status field value |
| `agent:failed` label | "Failed" status field value |
| `pipeline:blocked` label | "Blocked" status field value |
| `agent:success` label | "Done" status field value |
| `pipeline:epic` label | `epic` label (kept as GitHub label) |
| `pipeline:story` label | `story` label (kept as GitHub label) |

Labels still in use: `epic`, `story`, `internal`, `community`, `high-priority`, `dependencies`.

## Issue Classes & Materialization (2026-06-24)

Work-items no longer originate as public issues. The pipeline plans and refines on the **private project board**; the public issue tracker is treated as injection + leak surface and is kept minimal.

| Class | Created by | Public? | Locked? | Labels |
|-------|-----------|---------|---------|--------|
| Pipeline story | `project-queue.sh materialize` **at dispatch** (convert draft→issue) | yes | **locked** | `story` + `internal` |
| Epic | `pipeline-helper.sh create-epic` (PO, interactive) | yes | **locked** | `epic` + `internal` |
| Community | `pipeline-helper.sh create-community-issue` (human, interactive) | yes | **unlocked** | `community` |

- **Decomposition** writes private **drafts** (`pipeline-helper.sh create-story`). A draft becomes a GitHub issue **only when dispatched** — `po-act.sh dispatch` calls `materialize-issue`, which converts the draft in place (`convertProjectV2DraftIssueItemToIssue`), locks it, and tags `internal`. Issues stay first-class for the dev/PR/review/merge machinery while nothing un-worked sits on the public tracker.
- **Autonomous agents never run `gh issue create`** — enforced by a PreToolUse hook (`.claude/hooks/block-autonomous-issue-create.sh`, fires when `CFGMS_AUTONOMOUS=true`) and a CI gate (`label-decommission-gate.yml`). The only sanctioned creators are the `pipeline-helper.sh` subcommands above; the `materialize` path uses *convert*, not create.
- **Locking** closes the write/injection vector. `pipeline-helper.sh lock-sweep` (run from the PO cron) locks pipeline PRs and re-locks any unlocked `internal` issue.

## Infrastructure

- **Project board**: configured in `scripts/pipeline.yaml` (project_id, status_field_id, option IDs)
- **Queue script**: `scripts/project-queue.sh` — all project queue operations
- **Key operations**: `list-by-status`, `update-field`, `add-issue`, `get-item`, `create-draft`, `delete-item`

## Migration State

Labels `pipeline:*` and `agent:*` were deleted from `cfg-is/cfgms` before Story #1482 ran.
No open issues carried those labels at cutover time. The migration is complete with no
orphaned labeled issues.

Verification script: `scripts/migrate-queue-to-project.sh` documents and confirms migration state.

## Adding Issues to the Queue

```bash
# Add an issue and get its item_id
item_id=$(bash ./scripts/project-queue.sh add-issue <ISSUE_NUM> | python3 -c "import json,sys; print(json.load(sys.stdin)['item_id'])")

# Set status
bash ./scripts/project-queue.sh update-field "$item_id" status "Ready"
```

The `add-issue` operation is idempotent — calling it on an issue already in the project returns
the existing `item_id` without creating a duplicate.

## Status Lifecycle

```
Draft → Ready → In Progress → [Reviewing] → Done
                     ↓                ↓
                  Failed            Fix → In Progress (fix cycle)
                     ↓
                  Blocked (founder escalation)
```

"Reviewing" is transient and container-gated: the acceptance reviewer container sets it on
launch and clears it on exit (to Fix, Done, or Blocked depending on verdict).

## CI Gate

`.github/workflows/label-decommission-gate.yml` asserts zero executable references to
decommissioned label strings in `.claude/` and `scripts/`. This prevents accidental
reintroduction of label-based queue logic.

## Rollback

There is no automated rollback path — the labels are deleted and the pipeline operates
entirely on Projects V2 status. If the Projects V2 API becomes unavailable, the PO cycle
will fail at the `list-by-status` step and pause until restored.
