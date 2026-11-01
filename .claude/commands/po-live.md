---
name: po-live
description: PO Live — launch a Product Owner session in a docker container in a new tmux pane, pre-seeded with /po <args>
parameters:
  - name: subcommand
    description: "Args to pass to /po inside the live container (e.g., 'intent certificate rotation', 'next', 'status'), or '--continue' / '--resume [session-id]' to reattach to a past session"
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
- Session: a fresh session seeds `/po $ARGUMENTS` (or `/po` with no args); `--continue` / `--resume [<id>]` instead reattach to an existing session (no `/po` prompt is sent)
- Workspace: `worktrees/po-live` (shared across PO live sessions)
- Resume later: relaunch with `/po-live --resume` (most recent) or `/po-live --resume <session-id>`; the session transcript persists on the host-mounted `~/.claude`. See [Resuming a previous session](#resuming-a-previous-session).

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
- `/po-live --continue` — opens a new pane and **continues the most recent** PO session in the workspace (instead of seeding a fresh `/po`)
- `/po-live --resume 79f06f1d-6d1c-4001-afeb-0618432d81a8` — reattaches to that **specific** session by id
- `/po-live --resume` — bare alias for `--continue` (most recent session)

## Resuming a previous session

`po-live --continue` / `po-live --resume` reattach to an existing Claude
conversation in the shared `worktrees/po-live` clone instead of starting a fresh
`/po`. This is how you pick up after closing the pane, a reboot, or a power loss
— the container is ephemeral (`--rm`) but the session transcript lives on the
host-mounted `~/.claude`, so it survives. These forward Claude's own flags:

- **`--continue`** → runs `claude --continue`: resumes the most recent session
  for the workspace.
- **`--resume <session-id>`** → runs `claude --resume <session-id>`: resumes
  that exact conversation.
- **`--resume`** (bare) → convenience alias for `--continue`.

To find a session id, look under `~/.claude/projects/-workspace/` on the host
(the container runs Claude at `/workspace`), or use bare `--resume` to grab the
latest. The workspace clone is reused as-is (same branch, same uncommitted
files) — see [Cleaning up](#cleaning-up).

## Behavior inside the live container

The pre-seeded `/po $ARGUMENTS` invokes the existing `/po` slash command (Path B — interactive PO subagent). All standard PO behaviors work: intent capture (5-question structured), targeted unblocks, story status queries, next-action recommendations. The live container can also spawn the Planning Team for epic decomposition since it's a fresh top-level Claude session (not a nested subagent).

## Cleaning up

The container uses `--rm` and removes itself on exit. To exit:
- Type `/exit` or `exit` in the live Claude session, then `exit` the bash shell
- Or close the tmux pane (`Ctrl-b x`) — Docker will clean up

The shared `worktrees/po-live` clone persists between sessions.

**Workspace freshness:**
- A **fresh** `/po` session (bare `po-live`, `po-live intent …`, etc.) always
  resets the clone to a **clean, up-to-date `develop`** first, so a stale branch
  left by a prior session can't leak in. Uncommitted changes are **stashed, not
  discarded** (`git -C worktrees/po-live stash list` to recover); committed work
  is already safe on its own branch.
- A **resume** session (`--continue` / `--resume`) does **not** touch the branch
  or working tree — it deliberately reattaches to the workspace exactly as the
  session left it.

Remove the clone manually with `rm -rf worktrees/po-live` if you want it fully
re-cloned from scratch.
