---
name: isoagents
description: Show status of agent containers and offer lifecycle actions
parameters:
  - name: filter
    description: "Optional: issue number or container name to inspect, 'cleanup' to remove finished containers and worktrees, or 'cleanup <name/num>' for a specific one"
    required: false
---

# IsoAgents Command

Show the status of all agent containers and FSM supervisor runs, and offer lifecycle actions (cleanup, review, logs).

Headless dev, fix-pr, resolve-conflict and branch work runs under an FSM supervisor run (`.claude/tooling/scripts/fsm/`). One run starts several containers in turn (agent sessions `cfg-agent-<N>`, `cfg-agent-pr-fix-<N>`, `cfg-agent-resolve-conflict-<N>`, `cfg-agent-branch-<…>`, and validators `cfg-validate-<N>`), and has no container at all while it prepares, snapshots, syncs or publishes. Its workspace lives in the run dir under `~/.cache/cfgms-fsm-runs/`, not under `../worktrees/`. Read run state from the run list, not from containers.

**All operations are instant** — reads container state, no blocking.

## Execution Flow

1. **Gather state** by running these commands in parallel (uses helper to avoid approval prompts):

   a. **Running containers**:
      ```bash
      ./.claude/tooling/scripts/agent-dispatch.sh list-running
      ```
      Output columns: Name, Status, Issue, Mode, Branch, PR (tab-separated).

   b. **Exited containers**:
      ```bash
      ./.claude/tooling/scripts/agent-dispatch.sh list-exited
      ```
      Output columns: Name, Issue, Mode, Branch, PR (tab-separated).

   c. **FSM runs**:
      ```bash
      ./.claude/tooling/scripts/po-act.sh dispatch status
      ```
      Output columns: RUN_ID, STATUS, STATE, MODE, TARGET, CONTAINER, HEARTBEAT, SESSIONS, REASON (tab-separated), or `FSM_RUNS:none`. `STATUS` is `live`, `hung` (lock held, heartbeat stale), `starting`, `crashed` (resumable) or `done`. `po-act.sh dispatch status <RUN_ID>` prints one run as JSON.

   d. **Active clone directories** (interactive, review and legacy clones only):
      ```bash
      ls -d ../worktrees/story-* ../worktrees/pr-fix-* ../worktrees/feature--* ../worktrees/tooling--* ../worktrees/bugfix--* 2>/dev/null
      ```
      Check for all clone directory patterns (issue, PR-fix, and branch-named directories).

2. **If `$ARGUMENTS` is a specific issue number**: Show detailed info for that agent:
   - FSM run: the `dispatch status` row whose TARGET is `<NUM>`, then `./.claude/tooling/scripts/po-act.sh dispatch status <RUN_ID>`
   - Container status and logs: `./.claude/tooling/scripts/agent-dispatch.sh inspect-detail <NUM>`
   - PR status: `gh pr list --head "feature/story-<NUM>-agent" --json url,state,title`
   - Suggest next actions based on state

3. **If `$ARGUMENTS` is a container name** (contains `cfg-agent-`) **or a branch name** (contains `/`): Show detailed info. For branch names, derive the container name by sanitizing (`/` → `--`) and checking for `cfg-agent-branch-<sanitized>` or `cfg-agent-interactive-<sanitized>`:
   - Container status and logs: `./.claude/tooling/scripts/agent-dispatch.sh inspect-container <NAME>`
   - Extract branch from container labels, check for PR on that branch
   - For PR-fix containers: show the original PR being fixed
   - For interactive containers: show "Connect at https://claude.ai/code" and `docker exec -it <NAME> bash` for shell access
   - Suggest next actions based on state

4. **If `$ARGUMENTS` is 'cleanup'** (no target): `cleanup-issue` and `cleanup-container` never remove a container that belongs to an unfinished FSM run; they print `SKIP:container:<name> belongs to an unfinished FSM run (po-act.sh dispatch status)` instead. Finished run dirs are removed by `agent-dispatch.sh cleanup-stale` (24 h after the run ends), not here. For each exited container:
   a. Read container name and mode from labels
   b. For issue-mode containers:
      - Read exit code: `./.claude/tooling/scripts/agent-dispatch.sh inspect-exit <NUM>`
      - Check for PR: `gh pr list --head "feature/story-<NUM>-agent" --json url,state`
      - Clean up: `./.claude/tooling/scripts/agent-dispatch.sh cleanup-issue <NUM>`
   c. For branch/PR-fix containers:
      - Clean up: `./.claude/tooling/scripts/agent-dispatch.sh cleanup-container <NAME>`
   d. For interactive containers: same cleanup as branch containers
   e. Report what was cleaned up

5. **If `$ARGUMENTS` is 'cleanup <NUM>'** (specific issue): Clean up a single issue agent:
   a. `./.claude/tooling/scripts/agent-dispatch.sh cleanup-issue <NUM>`
   b. Report what was cleaned up

6. **If `$ARGUMENTS` is 'cleanup <NAME>'** (specific container name): Clean up by name:
   a. `./.claude/tooling/scripts/agent-dispatch.sh cleanup-container <NAME>`
   b. Report what was cleaned up

7. **Default (no arguments)**: Print status dashboard:

   **Running Agents:**
   | Name | Mode | Issue | Uptime | Branch | Status |
   |------|------|-------|--------|--------|--------|

   **Completed Agents:**
   | Name | Mode | Issue | Exit Code | PR | Action |
   |------|------|-------|-----------|----|--------|

   **FSM Runs:**
   | Run | Status | State | Mode | Target | Container | Heartbeat | Reason |
   |-----|--------|-------|------|--------|-----------|-----------|--------|

   **Clones:**
   List any active clone directories under ../worktrees/

8. **Suggest next actions** based on state:
   - If completed issue agents with exit 0: "Agent #42 finished — PR ready. Run `/pr-review` or `/isoagents cleanup`"
   - If completed issue agents with non-zero exit: "Agent #43 failed — check draft PR with `/isoagents 43`"
   - If completed PR-fix agents with exit 0: "PR #X updated — re-review with `/pr-review X`"
   - If completed PR-fix agents with non-zero exit: "PR-fix agent for PR #X failed — check logs with `/isoagents cfg-agent-pr-fix-X`"
   - If running agents: "Agent still running (25 min). Check back with `/isoagents`"
   - If a run is `crashed`: "Run <RUN_ID> for <TARGET> crashed in <STATE> — resume with `./.claude/tooling/scripts/po-act.sh dispatch resume <RUN_ID>`"
   - If a run is `hung`: "Run <RUN_ID> holds its lock but its heartbeat is <HEARTBEAT> old — leave it; the watcher reports it as `container_stalled … reason=heartbeat`"
   - If interactive containers running: "Interactive session on `<branch>` — connect at https://claude.ai/code or shell: `docker exec -it <name> bash`"
   - If nothing running: "No active agents. Use `/dispatch` to launch new ones."

## Error Handling

- **Docker not running**: Tell user to start Docker
- **No containers found**: "No active or completed agents. Use `/dispatch` to launch."
- **Container inspect fails**: Skip that container, note it in output
