---
name: po-live
description: PO Live — launch a Product Owner session in a docker container in a new tmux pane, pre-seeded with /po <args>
parameters:
  - name: subcommand
    description: "Args to pass to /po inside the live container (e.g., 'intent certificate rotation', 'next', 'status')"
    required: false
---

# PO Live Command

Launch an interactive PO session in a docker container running in a new tmux pane to the right of the current pane. The container is pre-seeded with `/po $ARGUMENTS` so the PO conversation starts in role immediately. State persists via the host-mounted `~/.claude` session storage — you can `claude --continue` later to resume.

## Why use this instead of `/po`

- **Dedicated token budget** — the live container runs its own Claude session, doesn't compete with the main session for context window or rate limits
- **Persistent across sessions** — close tmux, come back tomorrow, `claude --continue` from the same workspace
- **Suited for multi-turn work** — intent capture (5-question structured conversation) and Planning Team orchestration both benefit from a dedicated long-running session
- **Doesn't share context with cron** — the autonomous `/po cron` cycle stays in the main session; founder-driven product conversations live in the live container

## Execution

Run **one** bash command (no `$TMUX` check beforehand — the script handles tmux detection internally and errors out cleanly if not in tmux):

```bash
/home/jrdn/git/cfg.is/cfgms/.claude/scripts/agent-dispatch.sh po-live $ARGUMENTS
```

Inspect the exit code:

### Exit 0 — success (script split a pane and started the container)

Confirm to the founder:
- Container name `cfg-agent-live-po`
- Initial prompt: `/po $ARGUMENTS` (or just `/po` if no args)
- Workspace: `worktrees/po-live` (shared across PO live sessions)
- Resume later: `claude --continue` inside the container, or `claude --resume <session-id>` from any host (sessions are mounted via `~/.claude`)

### Exit 1 with stderr message "po-live requires an interactive tmux session"

Live mode is unavailable. Two-part fallback:

1. **Run `/po $ARGUMENTS` inline** by spawning the PO subagent (Path B of the existing `/po` slash command):

   ```
   Agent tool:
     subagent_type: po
     prompt: "Start a PO session. Arguments: $ARGUMENTS"
     mode: auto
   ```

2. **Tell the founder the one-liner** they can paste into a real terminal to launch live mode manually:

   ```
   /home/jrdn/git/cfg.is/cfgms/.claude/scripts/agent-dispatch.sh po-live $ARGUMENTS
   ```

   (To use it: open a tmux session — `tmux new -s cfgms` — then paste the command. The script will then split a pane and start the live PO container.)

### Any other non-zero exit

Surface the script's stderr to the founder verbatim and stop. Don't auto-fall-back since the failure may need investigation.

## Permissions

`Bash(/home/jrdn/git/cfg.is/cfgms/.claude/scripts/agent-dispatch.sh po-live *)` and `Bash(./.claude/scripts/agent-dispatch.sh *)` are both pre-approved in `.claude/settings.local.json`, so this command should run without permission prompts.

## Cap impact

`po-live` is a founder-controlled interactive session, like `cfg-agent-live-develop`. It does NOT count toward the 4-container cap on autonomous workers per `feedback_max_running_agents.md`. Steady-state ceiling becomes 4 autonomous + (live-develop, po-live, ...) interactive sessions.

## Examples

- `/po-live intent certificate rotation` — opens a new pane and starts intent capture for a "certificate rotation" epic (or falls back to inline + one-liner if not in tmux)
- `/po-live next` — opens a new pane and asks PO for the single highest-leverage next action
- `/po-live` (no args) — opens a new pane at the PO dashboard
- `/po-live unblock #501` — opens a new pane to handle a targeted unblock conversation

## Behavior inside the live container

The pre-seeded `/po $ARGUMENTS` invokes the existing `/po` slash command (Path B — interactive PO subagent). All standard PO behaviors work: intent capture (5-question structured), targeted unblocks, story status queries, next-action recommendations. The live container can also spawn the Planning Team for epic decomposition since it's a fresh top-level Claude session (not a nested subagent).

## Cleaning up

The container uses `--rm` and removes itself on exit. To exit:
- Type `/exit` or `exit` in the live Claude session, then `exit` the bash shell
- Or close the tmux pane (`Ctrl-b x`) — Docker will clean up

The shared `worktrees/po-live` clone persists between sessions; remove manually with `rm -rf worktrees/po-live` if you want a fresh workspace.
