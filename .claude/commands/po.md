---
name: po
description: Product Owner — pipeline dashboard, intent capture, and autonomous orchestration
parameters:
  - name: subcommand
    description: "Optional: 'status' (default), 'intent <topic>', 'next', or 'cron'"
    required: false
---

# Product Owner Command

The PO manages the autonomous pipeline: dashboard, intent capture, targeted unblocks, and orchestration.

## Execution

Two execution paths depending on `$ARGUMENTS`:

### Path A — `cron` (run inline in the main session)

If `$ARGUMENTS` starts with `cron` (with or without further sub-arguments), do **NOT** spawn the PO as a subagent. Instead, execute the pipeline cycle inline in the main session.

**Why:** A subagent cannot reliably spawn nested subagents (Acceptance Reviewer, BA, Tech Lead, Planning Team), and its bash commands trigger approval prompts despite `mode: auto`. Running inline gives the cycle full Agent-tool access and the parent session's allow list. This is documented in memory `feedback_po_run_inline.md`.

**How:**
1. Read `.claude/agents/po.md` to load the PO's behavioral rules and the Pipeline Cycle (§4) steps.
2. Execute Pipeline Cycle (§4) directly in the main session — preflight, unblock check, agent cleanup, Tech Lead pass, dispatch, fix cycle, Acceptance Reviewer (§4.1 Step 5), forward edge, session log.
3. Honor the 4-container cap from `feedback_max_running_agents.md` — the cap is on docker containers (`./.claude/scripts/agent-dispatch.sh list-running` count) only. Acceptance Reviewer subagents are in-process and do NOT count.
4. Spawn the Acceptance Reviewer subagent for each review-ready PR (use the Agent tool with `subagent_type: acceptance-reviewer`, `mode: auto`). Process PRs serially in FIFO order per `.claude/agents/po.md` §4.1 Step 5.
5. **Skip Step 6 (Planning Team) entirely in cron mode.** Planning Team is interactive-only — epic decomposition only runs when the founder invokes `/po` interactively. If undecomposed epics are blocking forward progress, mention it in the cycle summary so the founder can run an interactive session.
6. Report the cycle summary back to the founder using the same format the PO subagent uses.

### Path B — anything else (spawn the PO subagent)

For `status` (default), `intent <topic>`, `next`, or natural-language input, spawn the PO agent so it stays in role for the rest of the session:

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
