---
name: pipeline
description: Autonomous pipeline cycle — dedicated entry point for the recurring, clean-context PO cycle (equivalent to `/po cron`, given its own command for clean cost/usage attribution)
---

# Pipeline Command

Runs one full autonomous Pipeline Cycle (`.claude/agents/po.md` §4) as a clean-context subagent — dispatch, review, fix, forward edge, no founder dialogue required. This is the dedicated entry point for the recurring cron/loop invocation (e.g. `/loop 20m /pipeline`); it does exactly what `/po cron` (Path B in `.claude/commands/po.md`) does, given its own top-level command so usage/cost reporting can attribute it to `/pipeline` instead of folding it into general `/po` traffic.

`/po cron` still works unchanged for any existing automation that invokes it that way — this command doesn't replace it, it gives the same cycle a dedicated front door.

## Execution

Spawn a **`po` subagent** to run the full Pipeline Cycle (§4, **skip Step 7 — Planning Team**), same as `/po cron` Path B. Fresh context every invocation — the cycle is stateless, re-derived from GitHub each run. The subagent is on the same host, so it has full Docker access for dispatch/review/fix containers.

```
Agent tool:
  subagent_type: po
  prompt: "Run a full pipeline cycle per §4 of your agent definition (.claude/agents/po.md) — pipeline mode (pass `pipeline` to `cycle-start`, not `cron`), SKIP Step 7 (Planning Team). Execute every step that has work. Two subagent-context adaptations: (1) you have NO `Skill` tool — invoke the pin-refresh (§4.1 Step 1.6) and pipeline-sweep (§7.5) skills by spawning a `general-purpose` Agent that reads and runs the skill's SKILL.md inline; (2) spawn every nested `Agent` (the pin-refresh runner, the pipeline-sweep runner, and the Tech Lead in §2) SYNCHRONOUSLY with `run_in_background: false` — a foreground spawn blocks and returns its result on the same turn, so consume it inline and move on. Do NOT set `run_in_background: true` and do NOT end your turn expecting the harness to re-invoke you on the child's completion: a backgrounded `po` subagent parent is NOT re-invoked, so the cycle stalls. Hold any inline-op lease across a spawn and release it once the result returns on that same turn. Use the distributed leases (§4.-1) as normal. Report the standard cycle summary."
  mode: auto
```

Then relay the subagent's cycle summary to the founder. If the subagent reports a blocker only the main session can resolve (e.g. an epic that needs the Planning Team), surface it as a `/po cycle` / `/po decompose <#>` recommendation.

## Why a separate command

Cost/usage reporting (`token_report.py`) attributes a session to a segment keyed off the first slash command it ran. Routing the autonomous loop through `/po cron` made it indistinguishable from any other `/po` usage in that reporting — a `/loop 20m /po cron` session and a founder's interactive `/po status` session both landed in the same `/po` bucket. `/pipeline` gives the recurring cycle its own segment so cost/usage for "the autonomous loop" can be read directly, without reconstructing it from cycle manifests after the fact.
