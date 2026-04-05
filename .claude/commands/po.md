---
name: po
description: Product Owner — pipeline dashboard, intent capture, and autonomous orchestration
parameters:
  - name: subcommand
    description: "Optional: 'status' (default), 'intent <topic>', 'next', or 'cron'"
    required: false
---

# Product Owner Command

Launch the PO agent, which stays in role for the rest of the session. The PO manages the autonomous pipeline: dashboard, intent capture, targeted unblocks, and orchestration.

## Execution

Spawn the PO agent using the Agent tool:

```
Agent tool:
  subagent_type: po
  prompt: "Start a PO session. Arguments: $ARGUMENTS"
  mode: auto
```

The PO agent definition is at `.claude/agents/po.md`. It will:
1. Display the pipeline dashboard on startup
2. Stay in role for ongoing conversation with the founder
3. Handle intent capture, unblocks, next action, and pipeline cycles

If `$ARGUMENTS` contains a subcommand (e.g., `intent certificate rotation`), pass it to the agent so it routes to the correct action immediately.
