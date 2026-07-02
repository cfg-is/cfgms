---
name: po
description: Product Owner — pipeline dashboard, intent capture, and autonomous orchestration
parameters:
  - name: subcommand
    description: "Optional: 'status' (default), 'intent <topic>', 'next', 'cron', 'cycle', 'work', 'decompose [<epic#>]', or 'plan [<epic#>]'"
    required: false
---

# Product Owner Command

The PO manages the autonomous pipeline: dashboard, intent capture, targeted unblocks, and orchestration.

## Execution

Three execution paths depending on `$ARGUMENTS`. The dividing line is what the action needs:

- **Live agent team** (named `Agent` teammates coordinated via `SendMessage`, addressing the orchestrator as `main`) — the team is driven from the main conversation, so anything that spawns the Planning Team runs **inline** (Path A).
- **Clean per-run context, no teams** — the autonomous `cron` cycle skips the Planning Team, so it runs as a **clean-context subagent** (Path B) to keep the main session free of per-cycle bloat.
- **Ongoing conversation** — `status`/`intent`/`next` spawn a long-lived PO subagent (Path C).

> **Subagents CAN nest subagents and run bash under `mode: auto` with no approval prompts** (empirically validated 2026-06-29: a `po` subagent ran a full cron cycle — Tech Lead nested-spawn worked, `po-act.sh dispatch`/`gh`/lease ops all prompt-free, docker access intact since it's the same host). What a backgrounded subagent **cannot** host is the **live Planning Team**: its named teammates report to the `main` conversation via `SendMessage`, so the team must be driven from the main session — that is the **only** reason `decompose`/`cycle` stay inline. (Note: the old `TeamCreate`/`TeamDelete` tools no longer exist — the session has a single implicit team; you spawn named background `Agent` teammates directly. See `.claude/agents/po.md` §4.1 Step 7.) This corrects the earlier (now-stale) `feedback_po_run_inline` rationale.

### Path A — needs agent teams (run inline in the main session)

If `$ARGUMENTS` starts with `cycle`, `decompose`, or `plan`, do **NOT** spawn a subagent — execute directly in the main session, because these invoke the **Planning Team** — a live team of named `Agent` teammates coordinated via `SendMessage` to the `main` conversation, which a backgrounded subagent can't host. `work` also runs inline (in-process self-dispatch, no docker).

**Routing within Path A:**

| Args | Action |
|------|--------|
| `cycle` | Pipeline Cycle (§4) — **including Step 7 (Planning Team)**. Manual; full cycle on demand. |
| `work` | Self-Dispatch Mode (§7) — **no docker**. The local session claims and works this host's tagged stories one at a time, in-process, for a host (e.g. Windows) whose `CFGMS_PO_HOST_CAPS` names a non-default execution environment. **Drain-then-stop, not a timer:** works every currently-claimable story back-to-back in ONE invocation — re-running a FRESH preflight after each completed story (the orchestrator on another host drains the pipeline concurrently) — then stops when nothing is claimable. Do NOT wrap in `/loop`/cron; re-invoke on demand or when a blocker clears. |
| `decompose [<epic#>]` | Run §4.1 Step 7 (Planning Team) only — for the named epic, or every `epic` with no sub-issues if no number is given. |
| `plan [<epic#>]` | Alias for `decompose`. |

**How (Path A):**
1. Read `.claude/agents/po.md` to load the PO's behavioral rules and the relevant section.
2. Execute the section directly in the main session in priority order — preflight, unblock check, agent cleanup, pin refresh (§4.1 Step 1.6), Tech Lead pass, rebase (§4.1 Step 3), Acceptance Reviewer (§4.1 Step 4), fix cycle (§4.1 Step 5), dispatch (§4.1 Step 6), Planning Team (§4.1 Step 7), forward edge, session log.
3. Host capacity is enforced automatically by the resource admission gate (`.claude/agents/po.md` §4.-1) — every launch path defers when the host is out of RAM/disk/CPU headroom.
4. Spawn nested subagents via the Agent tool with `mode: auto`. Spawn the Planning Team as named background `Agent` teammates (`name` + `run_in_background: true`) and coordinate via `SendMessage` — no `TeamCreate` (per `.claude/agents/po.md` §4.1 Step 7c).
5. Report the summary back to the founder using the same format the PO subagent uses.

### Path B — autonomous cron (clean-context subagent)

If `$ARGUMENTS` starts with `cron`, spawn a **`po` subagent** to run the full Pipeline Cycle (§4, **skip Step 7 — Planning Team**). This gives each interval a **fresh context window** (the cron cycle is stateless — re-derived from GitHub every run — so nothing is lost), keeping the main session free for founder dialogue. The subagent is on the same host, so it has full Docker access for dispatch/review/fix containers.

```
Agent tool:
  subagent_type: po
  prompt: "Run a full /po cron pipeline cycle per §4 of your agent definition (.claude/agents/po.md) — cron mode, SKIP Step 7 (Planning Team). Execute every step that has work. Two subagent-context adaptations: (1) you have NO `Skill` tool — invoke the pin-refresh (§4.1 Step 1.6) and pipeline-sweep (§7.5) skills by spawning a `general-purpose` Agent that reads and runs the skill's SKILL.md inline; (2) spawn every nested `Agent` (the pin-refresh runner, the pipeline-sweep runner, and the Tech Lead in §2) SYNCHRONOUSLY with `run_in_background: false` — a foreground spawn blocks and returns its result on the same turn, so consume it inline and move on. Do NOT set `run_in_background: true` and do NOT end your turn expecting the harness to re-invoke you on the child's completion: a backgrounded `po` subagent parent is NOT re-invoked, so the cycle stalls. Hold any inline-op lease across a spawn and release it once the result returns on that same turn. Use the distributed leases (§4.-1) as normal. Report the standard cycle summary."
  mode: auto
```

Then relay the subagent's cycle summary to the founder. If the subagent reports a blocker only the main session can resolve (e.g. an epic that needs the Planning Team), surface it as a `/po cycle` / `/po decompose <#>` recommendation.

### Path C — lightweight conversation (spawn the PO subagent)

For `status` (default), `intent <topic>`, `next`, `unblock #NNN`, or any natural-language pipeline query, spawn the PO agent so it stays in role for the rest of the session:

```
Agent tool:
  subagent_type: po
  prompt: "Start a PO session. Arguments: $ARGUMENTS"
  mode: auto
```

The PO agent definition is at `.claude/agents/po.md`. It will:
1. Display the pipeline dashboard on startup
2. Stay in role for ongoing conversation with the founder
3. Handle intent capture, unblocks, next action, and story status queries

If `$ARGUMENTS` contains a subcommand (e.g., `intent certificate rotation`), pass it to the agent so it routes to the correct action immediately.

**Note:** Intent capture (§2) runs in Path C because it's a structured conversation that ends in a `gh issue create` — no Planning Team, no agent dispatch. The created epic is later picked up by `/po cycle` or `/po decompose <#>` (Path A) for BA/Tech Lead orchestration.
