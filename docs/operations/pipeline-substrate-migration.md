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

Labels still in use: `epic`, `story`, `internal`, `community`, `high-priority`, `dependencies`, `needs-windows`, `needs-macos`, and the descriptive **`cap:*`** capability namespace (`cap:cms`/`twin`/`dex`/`workflow`/`directory`/`web`/`msp` — the consuming product capability; multi-valued, orthogonal to queue state, never a queue signal; see `docs/product/roadmap.md` → Capability Tags).

## Issue Classes & Materialization (2026-06-24)

> **Revised 2026-07-03 (ADR-015):** materialization moved from dispatch time to decomposition time; `--defer` retains the dispatch-time path for sensitive bodies.

Work-items originate on the **private project board** and become public issues only through the convert-based materialize path — **at decomposition** by default, at dispatch for `--defer` drafts.

| Class | Created by | Public? | Locked? | Labels |
|-------|-----------|---------|---------|--------|
| Pipeline story | `pipeline-helper.sh create-story` **at decomposition** (convert draft→issue; ADR-015) | yes | **locked** | `story` + `internal` (+ inherited `cap:*`) |
| Pipeline story (`--defer`) | `project-queue.sh materialize` **at dispatch** (sensitive bodies held private while queued) | yes | **locked** | `story` + `internal` (+ `cap:*` from body marker) |
| Epic | `pipeline-helper.sh create-epic` (PO, interactive) | yes | **locked** | `epic` + `internal` (+ `cap:*`) |
| Community | `pipeline-helper.sh create-community-issue` (human, interactive) | yes | **unlocked** | `community` |

- **Decomposition** (`pipeline-helper.sh create-story`) creates a draft and immediately converts it in place (`convertProjectV2DraftIssueItemToIssue`), locks it, tags `internal` + `story`, and sub-issue-links it under its epic. Early materialization gives every story a real `#NNN` at authoring time (dependencies, dep-gating, sub-issue decomposition tracking) — see [ADR-015](../architecture/decisions/015-story-materialization-at-decomposition.md). Story bodies are **world-readable at creation**: no secrets, no customer/business specifics, no exploit-grade vulnerability detail. Bodies that can't be public while queued use `create-story ... --defer`, which keeps the old behavior: a private draft, materialized by `po-act.sh dispatch` when work starts.
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
