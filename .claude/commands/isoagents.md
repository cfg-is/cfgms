---
name: isoagents
description: Show status of agent containers and offer lifecycle actions
parameters:
  - name: filter
    description: "Optional: issue number to inspect, or 'cleanup' to remove finished containers and worktrees"
    required: false
---

# IsoAgents Command

Show the status of all agent containers and offer lifecycle actions (cleanup, review, logs).

**All operations are instant** — reads container state, no blocking.

## Execution Flow

1. **Gather state** by running these commands in parallel:

   a. **Running containers**:
      ```bash
      docker ps --filter "label=cfg-agent=true" --format '{{.Names}}\t{{.Status}}\t{{.Label "issue"}}'
      ```

   b. **Exited containers**:
      ```bash
      docker ps -a --filter "label=cfg-agent=true" --filter "status=exited" --format '{{.Names}}\t{{.Label "issue"}}'
      ```

   c. **Active worktrees**:
      ```bash
      git worktree list
      ```
      Filter to only show worktrees under `../worktrees/`.

2. **If `$ARGUMENTS` is a specific issue number**: Show detailed info for that agent:
   - Container status and resource usage: `docker stats --no-stream cfg-agent-<NUM>`
   - Last 30 lines of logs: `docker logs --tail 30 cfg-agent-<NUM>`
   - PR status: `gh pr list --head "feature/story-<NUM>-agent" --json url,state,title`
   - Suggest next actions based on state

3. **If `$ARGUMENTS` is 'cleanup'**: For each exited container:
   a. Read exit code: `docker inspect --format '{{.State.ExitCode}}' cfg-agent-<NUM>`
   b. Read issue number from label
   c. Copy result file (best-effort): `docker cp cfg-agent-<NUM>:/tmp/agent-result.json /tmp/`
   d. Check for PR: `gh pr list --head "feature/story-<NUM>-agent" --json url,state`
   e. Remove container: `docker rm cfg-agent-<NUM>`
   f. Remove worktree: `git worktree remove ../worktrees/story-<NUM> --force`
   g. Prune worktree list: `git worktree prune`
   h. Report what was cleaned up

4. **Default (no arguments)**: Print status dashboard:

   **Running Agents:**
   | Issue | Container | Uptime | Status |
   |-------|-----------|--------|--------|

   **Completed Agents:**
   | Issue | Exit Code | PR | Action |
   |-------|-----------|-----|--------|

   **Worktrees:**
   List any active worktrees under ../worktrees/

5. **Suggest next actions** based on state:
   - If completed agents with exit 0: "Agent #42 finished — PR ready. Run `/pr-review` or `/isoagents cleanup`"
   - If completed agents with non-zero exit: "Agent #43 failed — check draft PR with `/isoagents 43`"
   - If running agents: "Agent #44 still running (25 min). Check back with `/isoagents`"
   - If nothing running: "No active agents. Use `/dispatch` to launch new ones."

## Error Handling

- **Docker not running**: Tell user to start Docker
- **No containers found**: "No active or completed agents. Use `/dispatch` to launch."
- **Container inspect fails**: Skip that container, note it in output
