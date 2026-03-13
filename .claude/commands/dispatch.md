---
name: dispatch
description: Launch headless agent containers for GitHub issues
parameters:
  - name: issues
    description: "Space-separated issue numbers to dispatch (e.g., '42 43 44'). Use '--dry-run' after numbers to preview without launching."
    required: true
---

# Dispatch Command

Launch isolated agent containers to implement GitHub issues. Each agent runs in a Docker container with its own git worktree, executes Claude in headless mode, and produces a PR targeting develop.

**Non-blocking**: `docker run -d` returns instantly. Use `/isoagents` to check progress.

## Execution Flow

1. **Read config**: Read `.agent-dispatch.yaml` from the repo root for container settings, branch pattern, and labels.

2. **Parse arguments**: Extract issue numbers and flags from `$ARGUMENTS`. If `--dry-run` is present, set dry run mode — print plan without side effects.

3. **Check prerequisites** (skip in dry-run):
   - Verify Docker is running: `docker info >/dev/null 2>&1`
   - Verify agent image exists: `docker image inspect cfg-agent:latest >/dev/null 2>&1`
   - If image missing, tell user to run `/agent-setup` first

4. **For each issue number**, run these steps:

   a. **Validate issue exists and fetch metadata**:
      ```bash
      gh issue view <NUM> --json title,body,labels,state
      ```
      If the issue doesn't exist or is closed, skip with warning.

   b. **Quality check** (warnings only, do not block):
      - Check issue body has acceptance criteria (`- [ ]` checkboxes) — warn if missing
      - Check issue body length — warn if < 200 characters (likely under-specified)
      - Check for reference implementation mention — warn if absent
      - Print quality summary for the issue

   c. **Check for conflicts** (uses helper to avoid approval prompts):
      ```bash
      ./scripts/agent-dispatch.sh check-conflicts <NUM1> [NUM2...]
      ```
      Output lines prefixed `CONTAINER_EXISTS:<NUM>:` or `CLONE_EXISTS:<NUM>:` indicate conflicts — skip those issues with a warning.

   d. **Create local clone** (skip in dry-run):
      ```bash
      ./scripts/agent-dispatch.sh create-clone <NUM>
      ```
      This creates a fully independent repo copy using hardlinks (fast, low disk usage).
      Each container gets its own `.git` directory — no shared state, safe for 3+ concurrent agents.
      The remote URL is reset to GitHub so `gh` CLI works inside the container.

   e. **Launch container** (skip in dry-run):
      ```bash
      ./scripts/agent-dispatch.sh launch <NUM>
      ```
      Note: `GH_TOKEN` is passed at launch time from the host keyring. The gh config
      mount is no longer needed — `GH_TOKEN` env var is sufficient for all gh CLI operations.

   f. **Update labels** (skip in dry-run):
      ```bash
      gh issue edit <NUM> --remove-label "agent:ready" --add-label "agent:in-progress"
      ```

5. **Print summary table**: Show all dispatched issues with container IDs and branch names.

6. **Remind user**: "Use `/isoagents` to check progress. Agents typically complete in 15-45 minutes."

## Error Handling

- **Docker not running**: Tell user to start Docker and retry
- **Image not found**: Tell user to run `/agent-setup`
- **Issue fetch fails**: Skip that issue, continue with others
- **Clone/container conflict**: Skip with warning, suggest `/isoagents` to check existing state
- **All issues skipped**: Print summary of why each was skipped
