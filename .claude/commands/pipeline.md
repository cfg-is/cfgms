---
name: pipeline
description: Autonomous pipeline cycle — dedicated entry point for the recurring, clean-context PO cycle (equivalent to `/po cron`, given its own command for clean cost/usage attribution). `watch` arms an event watcher instead of a fixed loop.
parameters:
  - name: subcommand
    description: "Optional: omit for one full cycle, or 'watch' to arm the event watcher"
    required: false
---

# Pipeline Command

Runs one full autonomous Pipeline Cycle (`.claude/agents/po.md` §4) as a clean-context subagent — dispatch, review, fix, forward edge, no founder dialogue required. This is the dedicated entry point for the recurring autonomous invocation; it does exactly what `/po cron` (Path B in `.claude/commands/po.md`) does, given its own top-level command so usage/cost reporting can attribute it to `/pipeline` instead of folding it into general `/po` traffic.

`/po cron` still works unchanged for any existing automation that invokes it that way — this command doesn't replace it, it gives the same cycle a dedicated front door.

**Prefer `/pipeline watch` over a fixed `/loop 20m /pipeline`.** The loop wakes on a timer and usually finds nothing; the watcher wakes only on a real state change, and falls back to a full cycle every two hours. See the `watch` section below.

## Execution

Route on `$ARGUMENTS`:

- **`watch`** — arm the event watcher. See [`watch` — event-driven mode](#watch--event-driven-mode-no-fixed-loop) below, and do **not** run a cycle here; the watcher's `full_cycle reason=startup` event kicks the first one.
- **anything else (including no argument)** — run exactly one full cycle, as follows.

Spawn a **`po` subagent** to run the full Pipeline Cycle (§4, **skip Step 7 — Planning Team**), same as `/po cron` Path B. Fresh context every invocation — the cycle is stateless, re-derived from GitHub each run. The subagent is on the same host, so it has full Docker access for dispatch/review/fix containers.

```
Agent tool:
  subagent_type: po
  prompt: "Run a full pipeline cycle per §4 of your agent definition (.claude/agents/po.md) — pipeline mode (pass `pipeline` to `cycle-start`, not `cron`), SKIP Step 7 (Planning Team). Execute every step that has work. Two subagent-context adaptations: (1) you have NO `Skill` tool — invoke the pin-refresh (§4.1 Step 1.6) and pipeline-sweep (§7.5) skills by spawning a `general-purpose` Agent that reads and runs the skill's SKILL.md inline; (2) nested `Agent` spawns are FORCED ASYNC here — `run_in_background: false` is NOT honoured, so never rely on it. For the pin-refresh and pipeline-sweep skills, do NOT spawn a runner at all: read the skill's SKILL.md and run its steps INLINE with Bash. When you do spawn (e.g. the Tech Lead in §2), stay in-turn and consume the real completion notification; NEVER end your turn waiting, because a backgrounded po parent is not re-invoked and its child dies with it, losing the result and stranding the lease. If you finish all other work with no result, record that step as `UNKNOWN — no result received`, release its lease, and run cycle-end. The ONLY valid completion signal is the value the spawn returns — never output-file size, mtime, symlink size, process tables or CPU usage (`$D/tasks/<agentId>.output` is a symlink of constant size, so polling it always reports done). NEVER synthesise plausible-looking counts for a step that produced none. Use the distributed leases (§4.-1) as normal. Report the standard cycle summary."
  mode: auto
```

Then relay the subagent's cycle summary to the founder. If the subagent reports a blocker only the main session can resolve (e.g. an epic that needs the Planning Team), surface it as a `/po cycle` / `/po decompose <#>` recommendation.

## Why a separate command

Cost/usage reporting (`token_report.py`) attributes a session to a segment keyed off the first slash command it ran. Routing the autonomous loop through `/po cron` made it indistinguishable from any other `/po` usage in that reporting — a `/loop 20m /po cron` session and a founder's interactive `/po status` session both landed in the same `/po` bucket. `/pipeline` gives the recurring cycle its own segment so cost/usage for "the autonomous loop" can be read directly, without reconstructing it from cycle manifests after the fact.

## `watch` — event-driven mode (no fixed loop)

`/pipeline watch` replaces `/loop 20m /pipeline`. Instead of waking on a timer and usually finding nothing, it arms a host-side watcher that prints a line only when pipeline state actually changes. A quiet pipeline prints nothing and therefore costs nothing — the watcher is a plain bash process, not a model invocation.

### Arming it

```
Monitor tool:
  command: ./.claude/scripts/pipeline-watch.sh watch
  description: pipeline state changes (merges, PR checks, containers, board)
  persistent: true
```

The watcher refuses to start if another instance is already running on this host (PID file in the PO cache dir), so double-arming is safe.

**It needs a live session.** Unlike a cron loop, the watcher dies when the session ends. Run it from a long-lived session — the `po-live` tmux pane is the intended host.

**Keep the main session thin.** Every event is handled by spawning a fresh-context `po` subagent, exactly as the no-arg path does. The main session accumulates only the one-line cycle summaries, so a wake-up after a long quiet gap re-reads a small context rather than a whole day of cycle transcripts.

### Probe tiers

| Tier | Interval | Probes |
|------|----------|--------|
| fast | 60s (`PIPELINE_WATCH_FAST`) | `git ls-remote` for the develop SHA, `docker ps` for `cfg-agent-*` names and age. Local only, measured at ~0.5s. |
| slow | 300s (`PIPELINE_WATCH_SLOW`) | `project-queue.sh list-by-status` for Ready/Fix/Failed, `gh pr list` check rollups. `list-by-status` costs ~15s per status, which is why it is not on the fast tier. |
| full | 7200s (`PIPELINE_WATCH_FULL`) | Emits `full_cycle` unconditionally — the safety net for anything no event can observe. |

All probes are edge-triggered: an unchanged value prints nothing, and a condition already true when the watcher was armed is baselined silently rather than replayed.

### Event → bundle

Each event justifies a **bundle** of §4 steps, not a single step. The bundles are deliberately wide, so the 2-hourly full cycle has very little left to catch.

| Event line | Steps to run (`.claude/agents/po.md` §4.1) |
|------------|--------------------------------------------|
| `full_cycle reason=startup\|interval` | Every step, skipping Step 7 (Planning Team). Identical to the no-arg path. |
| `merged develop_sha=<sha>` | Step 7.5 pipeline sweep, Step 1 unblock check, Step 3 rebase stuck PRs, Step 1.5 agent cleanup, Step 6 dispatch |
| `checks_green pr=<N>` | Step 4 acceptance review for that PR |
| `checks_red pr=<N>` | Step 5 fix cycle for that PR |
| `board_up status=Ready count=<n>` | Step 6 dispatch |
| `board_up status=Fix count=<n>` | Step 5 fix cycle |
| `board_up status=Failed count=<n>` | Step 1.5 agent cleanup, Step 6a stalled-dispatch recovery |
| `container_exited name=<c>` | Step 1.5 agent cleanup, Step 6 dispatch |
| `container_stalled name=<c> age_min=<m>` | Step 6a stalled-dispatch recovery for that container |
| `stop reason=drained cycles=<n>` | Report to the founder. Do **not** re-arm. |

Every bundle runs under the §4.-1 distributed leases exactly as a full cycle does, and the host resource-admission gate still governs every launch. Dispatch remains blocked whenever the preflight reports `code_health.ok == false`.

**`checks_red` does not bypass the fix-round cap.** Step 5 dispatches a fix only for stories the board holds at status `Fix`. A round-2 acceptance failure sets the story to `Blocked`, and Step 5 skips `Blocked` items — so a PR that has already burned its one fix attempt stays parked for a human, no matter how many times its checks go red. The round is owned by the acceptance reviewer and counted from `<!-- cfgms-acceptance-review -->` comments on the PR, never from the board status.

### Reporting each cycle back

After relaying a cycle summary, record the outcome so the watcher knows whether the pipeline is draining:

```bash
./.claude/scripts/pipeline-watch.sh record-cycle <drained|work> <trigger>
```

`<trigger>` is the event name that caused the cycle (`full_cycle`, `merged`, `checks_green`, …). Pass `work` whenever the cycle dispatched, reviewed, fixed, rebased, swept or unblocked anything; `drained` only when it found nothing at all to do.

### Drained shutdown

Two consecutive `record-cycle drained full_cycle` reports mean two scheduled full cycles in a row found an empty pipeline. The watcher then emits `EVENT stop reason=drained` and exits, which ends the Monitor. Tell the founder the pipeline is drained and that `/pipeline watch` will re-arm it.

Only the 2-hourly full cycle counts toward that streak — a bundle that happens to find nothing is inert — so a quiet hour between merges cannot shut the watcher down. Any `record-cycle work` resets the streak to 0.

### Inspecting and resetting

```bash
./.claude/scripts/pipeline-watch.sh state   # persisted baselines + drained streak
./.claude/scripts/pipeline-watch.sh reset   # clear state; next tick re-baselines silently
```

Tests: `.claude/scripts/tests/pipeline_watch.test.sh`, run automatically by `scripts/test-scripts.sh`.
