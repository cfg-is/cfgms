---
name: dispatch
description: Launch headless agent containers for GitHub issues, branches, or PR fixes — or start interactive sessions
parameters:
  - name: targets
    description: "Issue numbers, branch names (containing '/'), 'fix-pr <NUM>', or 'interactive <BRANCH>'. Space-separated. Use '--dry-run' to preview."
    required: true
---

# Dispatch Command

Launch isolated agent containers to implement GitHub issues, continue work on branches, fix PR review comments, or start interactive Claude sessions. Each agent runs in a Docker container with its own git clone.

**Non-blocking**: Headless modes use `docker run -d` and return instantly. Interactive mode prints a command for the user to run. Use `/isoagents` to check progress.

## Execution Flow

1. **Read config**: Read `.agent-dispatch.yaml` from the repo root for container settings, branch pattern, and labels.

2. **Parse arguments**: Extract targets and flags from `$ARGUMENTS`. Classify each argument:
   - Purely numeric → **issue number** (existing behavior)
   - Contains `/` → **branch name** (headless branch mode)
   - `fix-pr` followed by a number → **PR-fix mode** (headless)
   - `interactive` followed by a target → **interactive mode**. The target can be:
     - A branch name (contains `/`): `interactive feature/foo`
     - An issue number (numeric): `interactive 416`
     - A PR reference: `interactive fix-pr 478`
   - `--dry-run` → set dry run flag (preview without side effects)

3. **Check prerequisites** (skip in dry-run):
   - Verify Docker is running: `docker info >/dev/null 2>&1`
   - Verify agent image exists: `docker image inspect cfg-agent:latest >/dev/null 2>&1`
   - If image missing, tell user to run `/agent-setup` first
   - **Check credential validity**:
     ```bash
     ./.claude/scripts/agent-dispatch.sh check-creds
     ```
     Parse the output:
     - `CREDS_OK:<minutes>` — Credentials valid, proceed
     - `CREDS_LOW:<minutes>` — Warn: "Credentials expire in <minutes> min — agents may fail mid-run. Run `/agent-setup creds` to refresh."
     - `CREDS_EXPIRED:<minutes>` — **STOP**: "Credentials expired <abs(minutes)> min ago. Run `/agent-setup creds` to refresh before dispatching."
     - `CREDS_MISSING:*` — **STOP**: "No credentials found. Run `/agent-setup creds` first."
     - `CREDS_ERROR:*` — Warn and continue (non-blocking)

4. **Dispatch based on target type**:

### 4a. Issue Dispatch (existing behavior)

For each issue number:

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
      ./.claude/scripts/agent-dispatch.sh check-conflicts <NUM1> [NUM2...]
      ```
      Output lines prefixed `CONTAINER_EXISTS:<NUM>:` or `CLONE_EXISTS:<NUM>:` indicate conflicts — skip those issues with a warning.

   d. **Create local clone** (skip in dry-run):
      ```bash
      ./.claude/scripts/agent-dispatch.sh create-clone <NUM>
      ```

   e. **Launch container** (skip in dry-run):
      ```bash
      ./.claude/scripts/agent-dispatch.sh launch <NUM>
      ```

   f. **Update labels** (skip in dry-run):
      ```bash
      gh issue edit <NUM> --remove-label "agent:ready" --add-label "agent:in-progress"
      ```

### 4b. Branch Dispatch

For each branch name:

   a. **Check if branch exists on remote**:
      ```bash
      git ls-remote --heads origin <BRANCH>
      ```
      If it exists, the agent will check it out. If not, a new branch will be created from develop.

   b. **Auto-detect issue from branch pattern** `story-(\d+)`:
      If found, fetch the issue for quality context (warnings only).

   c. **Check for conflicts**:
      ```bash
      ./.claude/scripts/agent-dispatch.sh check-conflicts --branch <BRANCH>
      ```
      Skip if `CONTAINER_EXISTS` or `CLONE_EXISTS` in output.

   d. **Create local clone** (skip in dry-run):
      ```bash
      ./.claude/scripts/agent-dispatch.sh create-clone-branch <BRANCH>
      ```
      Output: `CLONE_OK:<dir>:<branch>` (existing) or `CLONE_NEW:<dir>:<branch>` (new branch created).

   e. **Launch container** (skip in dry-run):
      Derive sanitized name from branch (`/` → `--`).
      ```bash
      ./.claude/scripts/agent-dispatch.sh launch-generic cfg-agent-branch-<sanitized> <clone_dir> --branch <BRANCH> [--issue <NUM>]
      ```
      Include `--issue <NUM>` only if auto-detected from branch name.

### 4c. PR-Fix Dispatch

For each `fix-pr <NUM>`:

   a. **Validate PR exists and is open**:
      ```bash
      gh pr view <NUM> --json state,headRefName,title
      ```
      If PR doesn't exist or is closed/merged, skip with warning.

   b. **Extract branch and issue from PR**:
      Branch comes from `headRefName`. Issue from PR body (`Fixes #NNN`) or branch pattern `story-(\d+)`.

   c. **Check for conflicts**:
      ```bash
      ./.claude/scripts/agent-dispatch.sh check-conflicts --pr <NUM>
      ```
      Skip if conflict found.

   d. **Create local clone** (skip in dry-run):
      ```bash
      ./.claude/scripts/agent-dispatch.sh create-clone-pr <NUM>
      ```

   e. **Launch container** (skip in dry-run):
      ```bash
      ./.claude/scripts/agent-dispatch.sh launch-generic cfg-agent-pr-fix-<NUM> <clone_dir> --fix-pr <NUM>
      ```

### 4d. Interactive Dispatch

Interactive mode accepts three target types: branch name, issue number, or PR reference.
The target determines how the clone is created; the launch is always the same (`claude remote-control`).

**Determine branch and clone directory based on target type:**

   - **Branch target** (`interactive feature/foo`):
     - Branch = the argument directly
     - Clone: `./.claude/scripts/agent-dispatch.sh create-clone-branch <BRANCH>`
     - Clone dir: `../worktrees/<sanitized>`
     - Conflict check: `./.claude/scripts/agent-dispatch.sh check-conflicts --branch <BRANCH>`

   - **Issue target** (`interactive 416`):
     - Validate issue exists: `gh issue view <NUM> --json title,state`
     - Branch = `feature/story-<NUM>-agent` (same as issue dispatch)
     - Clone: `./.claude/scripts/agent-dispatch.sh create-clone <NUM>`
     - Clone dir: `../worktrees/story-<NUM>`
     - Conflict check: `./.claude/scripts/agent-dispatch.sh check-conflicts <NUM>`

   - **PR target** (`interactive fix-pr 478`):
     - Validate PR exists and is open: `gh pr view <NUM> --json state,headRefName,title`
     - Branch = PR's `headRefName`
     - Clone: `./.claude/scripts/agent-dispatch.sh create-clone-pr <NUM>`
     - Clone dir: `../worktrees/pr-fix-<NUM>`
     - Conflict check: `./.claude/scripts/agent-dispatch.sh check-conflicts --pr <NUM>`

**Then for all target types:**

   a. **Run conflict check** (as determined above). Skip if conflict found.

   b. **Create local clone** (skip in dry-run, using the clone command determined above).

   c. **Launch interactive container** (skip in dry-run):
      ```bash
      ./.claude/scripts/agent-dispatch.sh launch-interactive <BRANCH> [<CLONE_DIR>]
      ```
      Pass `<CLONE_DIR>` explicitly for issue and PR targets (since their clone dirs don't match the sanitized branch pattern).
      This launches a detached container running `claude remote-control --dangerously-skip-permissions`.
      The user connects via https://claude.ai/code — no TTY required.

   d. **Tell the user**:
      "Interactive session starting. Connect at https://claude.ai/code — look for session named `<BRANCH>`."
      "To view the session URL: `docker logs cfg-agent-interactive-<sanitized>`"
      "To drop into a shell: `docker exec -it cfg-agent-interactive-<sanitized> bash`"
      No label updates — interactive is user-driven.

5. **Print full agent dashboard** (skip in dry-run): After launch, gather state for ALL agents (not just the ones dispatched this run):

   ```bash
   ./.claude/scripts/agent-dispatch.sh list-running
   ./.claude/scripts/agent-dispatch.sh list-exited
   ```

   Print a single summary table showing ALL agents:

   **Agent Dashboard:**
   | Name | Mode | Issue | Status | Branch | Notes |
   |------|------|-------|--------|--------|-------|

   Mode values: issue, branch, fix-pr, interactive, live
   Status values: Running, Exited (exit code), Not found
   Notes: uptime for running, PR URL for exited with code 0, failure hint for exited with non-zero

6. **Remind user**: "Agents are running. Use `/isoagents` to check progress (typically 15-45 minutes)."

## Error Handling

- **Docker not running**: Tell user to start Docker and retry
- **Image not found**: Tell user to run `/agent-setup`
- **Issue/PR fetch fails**: Skip that target, continue with others
- **Clone/container conflict**: Skip with warning, suggest `/isoagents` to check existing state
- **All targets skipped**: Print summary of why each was skipped
