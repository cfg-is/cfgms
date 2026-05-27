---
name: po
description: Product Owner — pipeline dashboard, intent capture, and autonomous orchestration
parameters:
  - name: subcommand
    description: "Optional: 'status' (default), 'intent <topic>', 'next', 'cron', 'cycle', 'decompose [<epic#>]', or 'plan [<epic#>]'"
    required: false
---

# Product Owner Command

The PO manages the autonomous pipeline: dashboard, intent capture, targeted unblocks, and orchestration.

## Execution

Two execution paths depending on `$ARGUMENTS`. The dividing line is whether the action needs to spawn nested subagents or an agent team — those need the parent session's full tool access, so they run inline.

### Path A — team-relevant args (run inline in the main session)

If `$ARGUMENTS` starts with any of `cron`, `cycle`, `decompose`, or `plan`, do **NOT** spawn the PO as a subagent. Instead, execute directly in the main session.

**Why:** A subagent cannot reliably spawn nested subagents (Acceptance Reviewer, BA, Tech Lead, Planning Team) — its `tools:` field is restricted (no `TeamCreate`, `TeamDelete`, `SendMessage`), and its bash commands trigger approval prompts despite `mode: auto`. Running inline gives the cycle full Agent-tool access and the parent session's allow list. Documented in memory `feedback_po_run_inline.md`.

**Routing within Path A:**

| Args | Action |
|------|--------|
| `cron` | Pipeline Cycle (§4) — **skip Step 7 (Planning Team)**. Autonomous; cheap; runs every interval. |
| `cycle` | Pipeline Cycle (§4) — **including Step 7**. Manual; full cycle on demand. |
| `decompose [<epic#>]` | Run §4.1 Step 7 (Planning Team) only — for the named epic, or every `epic` with no sub-issues if no number is given. |
| `plan [<epic#>]` | Alias for `decompose`. |

**How:**
1. Read `.claude/agents/po.md` to load the PO's behavioral rules and the relevant section.
2. Execute the section directly in the main session in priority order — preflight, unblock check, agent cleanup, Tech Lead pass, rebase (§4.1 Step 3), Acceptance Reviewer (§4.1 Step 4), fix cycle (§4.1 Step 5), dispatch (§4.1 Step 6), Planning Team (§4.1 Step 7 — see routing table above), forward edge, session log.
3. Honor the 7-container cap from `feedback_max_running_agents.md` — the cap is on docker containers (`./.claude/scripts/agent-dispatch.sh list-running` count) shared across all autonomous activity (dev, fix-pr, review). When slots are scarce, finish in-flight work first (Steps 3-5) and defer new dev dispatch (Step 6) to the next cycle.
4. Spawn nested subagents via the Agent tool with `mode: auto`. Spawn the Planning Team via `TeamCreate` + Agent calls with `team_name` (per `.claude/agents/po.md` §4.1 Step 7c).
5. Report the summary back to the founder using the same format the PO subagent uses.

### Path B — lightweight conversation (spawn the PO subagent)

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

**Note:** Intent capture (§2) runs in Path B because it's a structured conversation that ends in a `gh issue create` — no Planning Team, no agent dispatch. The created epic is later picked up by `/po cycle` or `/po decompose <#>` (Path A) for BA/Tech Lead orchestration.
