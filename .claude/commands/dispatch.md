---
name: dispatch
description: Launch headless agent containers for GitHub issues, branches, or PR fixes — or start interactive sessions
parameters:
  - name: targets
    description: "Issue numbers, branch names (containing '/'), 'fix-pr <NUM>', 'acceptance-review <PR>', or 'interactive <BRANCH>'. Space-separated. Use '--dry-run' to preview."
    required: true
---

# Dispatch Command

Launch isolated agent work to implement GitHub issues, continue work on branches, fix PR review comments, or start interactive Claude sessions.

Headless issue, branch and PR-fix work runs under the FSM supervisor (`.claude/tooling/scripts/fsm/`), started only by `po-act.sh`. The supervisor runs on the host, owns the lease, workspace, validation, commit, push, PR and board updates, and starts agent containers that only edit files and hold no GitHub credential. Interactive and acceptance-review containers keep their own launch subcommands.

**Non-blocking**: `po-act.sh` starts the supervisor detached and returns once the run has launched its first agent (or is still preparing past the wait window, `FSM_LAUNCH_PENDING`). Interactive mode prints a command for the user to run. Use `/isoagents` to check progress.

## Execution Flow

1. **Read config**: Read `.agent-dispatch.yaml` from the repo root for container settings, branch pattern, and labels.

2. **Parse arguments**: Extract targets and flags from `$ARGUMENTS`. Classify each argument:
   - Purely numeric → **issue number** (existing behavior)
   - Contains `/` → **branch name** (headless branch mode)
   - `fix-pr` followed by a number → **PR-fix mode** (headless)
   - `acceptance-review` followed by a number → **acceptance-review mode** (headless review container, Section 4e)
   - `interactive` followed by a target → **interactive mode**. The target can be:
     - A branch name (contains `/`): `interactive feature/foo`
     - An issue number (numeric): `interactive 416`
     - A PR reference: `interactive fix-pr 478`
   - `--dry-run` → set dry run flag (preview without side effects)

3. **Check prerequisites** (skip in dry-run):
   - Verify Docker is running: `docker info >/dev/null 2>&1`
   - Verify agent image exists: `docker image inspect cfg-agent:latest >/dev/null 2>&1`
   - If image missing, tell user to run `/agent-setup` first
   - The headless launch path refuses a stale image: when `cfg-agent:latest`'s `cfgms.build_inputs_hash` label is not this checkout's `.claude/tooling/devcontainer` tree, `po-act.sh` prints `IMAGE_STALE:<image>:<checkout>` and `…_REFUSED:<target>:image_stale` (exit 3) and never rebuilds the image itself. Tell the user to run `/agent-setup rebuild`.
   - **Check credential validity**:
     ```bash
     ./.claude/tooling/scripts/agent-dispatch.sh check-creds
     ```
     Parse the output:
     - `CREDS_MODE:token` — Long-lived agent token in use (containers do not share the host session); proceed, no freshness check applies
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

   b. **Quality check** (warnings only, do not block) — applies when accepting a pre-existing public issue by number; pipeline dev items are materialized locked + `internal` at decomposition (ADR-015; `--defer` drafts at dispatch) and validated by the Planning Team beforehand:
      - Check issue body has acceptance criteria (`- [ ]` checkboxes) — warn if missing
      - Check issue body length — warn if < 200 characters (likely under-specified)
      - Check for reference implementation mention — warn if absent
      - Print quality summary for the issue

   c. **Start the run** (skip in dry-run; in dry-run, show `./.claude/tooling/scripts/po-act.sh dispatch status` instead):
      ```bash
      ./.claude/tooling/scripts/po-act.sh dispatch <NUM>
      ```
      The story must be `Ready` on the project board: otherwise `po-act.sh` prints `ERROR: story #<NUM> not found in project queue with Ready status` and exits 1. Before any side effect it applies the capacity gate, the image staleness gate, the Dependencies gate (any open `#NNN` in `## Dependencies` refuses with `DISPATCH_REFUSED:<NUM>:dependency_open …`, exit 3) the unfinished-run gate (`DISPATCH_SKIPPED:<NUM>:run_in_flight:…` or `:run_resumable:<run>`, exit 0; `DISPATCH_REFUSED:<NUM>:run_index_unreadable`, exit 3) and the duplicate-PR gate (`DISPATCH_REFUSED:<NUM>:open_pr_exists:<PR>` when an open PR on any branch already references the story, `:open_pr_check_failed` when the lookup fails; exit 3). It then acquires the `story-<item>` lease, claims the story (Ready → In Progress) and starts the supervisor run, which clones, works on and publishes `feature/story-<NUM>-agent` itself. No clone or container conflict check is needed: the unfinished-run gate and the lease replace it.

      On success it prints `FSM_RUN:<run>`, `FSM_LAUNCHED:<NUM>:<container>` (or `FSM_LAUNCH_PENDING:<NUM>:<status>`) and `DISPATCHED:<NUM>`. Every other output and exit code is listed in `.claude/agents/po.md` → Helper scripts → Launch outputs; report the line to the user as printed.

### 4b. Branch Dispatch

For each branch name:

   a. **Check if branch exists on remote**:
      ```bash
      git ls-remote --heads origin <BRANCH>
      ```
      If it exists, the run starts from its head (when the head is not already contained in develop). If not, the run starts from develop and publishes a new branch.

   b. **Auto-detect issue from branch pattern** `story-(\d+)`:
      If found, fetch the issue for quality context (warnings only).

   c. **Start the run** (skip in dry-run):
      ```bash
      ./.claude/tooling/scripts/po-act.sh dispatch --branch <BRANCH> [--issue <NUM>]
      ```
      Include `--issue <NUM>` only if auto-detected from branch name. When the branch has an open PR whose author is not trusted at its current head, `po-act.sh` refuses with `DISPATCH_REFUSED:<BRANCH>:external_author (…)` (exit 3). The run holds the `branch-<sanitized>` lease (`/` → `--`) and applies the capacity, image staleness and unfinished-run gates; there is no Dependencies gate, no duplicate-PR gate and no board claim. Branch mode passes no project item, so the agent's `spec.md` is empty: it works from the branch's existing commits. On success it prints `DISPATCHED_BRANCH:<BRANCH>`; other outputs are listed in `.claude/agents/po.md` → Helper scripts → Launch outputs.

### 4c. PR-Fix Dispatch

For each `fix-pr <NUM>`:

   a. **Validate PR exists and is open**:
      ```bash
      gh pr view <NUM> --json state,headRefName,title
      ```
      If PR doesn't exist or is closed/merged, skip with warning.

   b. **Extract branch and issue from PR**:
      Branch comes from `headRefName`. Issue from PR body (`Fixes #NNN`) or branch pattern `story-(\d+)`.

   c. **Start the run** (skip in dry-run):
      ```bash
      ./.claude/tooling/scripts/po-act.sh dispatch-fix <NUM>
      ```
      `po-act.sh` checks author trust against the PR's current head, applies the capacity, image staleness and unfinished-run gates, resolves the story's project item from the PR (`DISPATCH_FIX_REFUSED:<NUM>:no_story_item`, exit 3, when there is none), refuses when another open PR references the same story (`DISPATCH_FIX_REFUSED:<NUM>:open_pr_exists:<PR>`, exit 3) and starts a `fix-pr` run under the `pr-<NUM>` lease. The run gives the agent the PR body, reviews, comments and failing checks, validates the result and pushes one new commit. On success it prints `DISPATCHED_FIX:<NUM>`; other outputs are listed in `.claude/agents/po.md` → Helper scripts → Launch outputs.

### 4d. Interactive Dispatch

Interactive mode accepts three target types: branch name, issue number, or PR reference.
The target determines how the clone is created; the launch is always the same (`claude remote-control`). Interactive mode is the only `/dispatch` mode that still uses `check-conflicts` and the `create-clone*` helpers.

**Determine branch and clone directory based on target type:**

   - **Branch target** (`interactive feature/foo`):
     - Branch = the argument directly
     - Clone: `./.claude/tooling/scripts/agent-dispatch.sh create-clone-branch <BRANCH>`
     - Clone dir: `../worktrees/<sanitized>`
     - Conflict check: `./.claude/tooling/scripts/agent-dispatch.sh check-conflicts --branch <BRANCH>`

   - **Issue target** (`interactive 416`):
     - Validate issue exists: `gh issue view <NUM> --json title,state`
     - Branch = `feature/story-<NUM>-agent` (same as issue dispatch)
     - Clone: `./.claude/tooling/scripts/agent-dispatch.sh create-clone <NUM>`
     - Clone dir: `../worktrees/story-<NUM>`
     - Conflict check: `./.claude/tooling/scripts/agent-dispatch.sh check-conflicts <NUM>`

   - **PR target** (`interactive fix-pr 478`):
     - Validate PR exists and is open: `gh pr view <NUM> --json state,headRefName,title`
     - Branch = PR's `headRefName`
     - Clone: `./.claude/tooling/scripts/agent-dispatch.sh create-clone-pr <NUM>`
     - Clone dir: `../worktrees/pr-fix-<NUM>`
     - Conflict check: `./.claude/tooling/scripts/agent-dispatch.sh check-conflicts --pr <NUM>`

**Then for all target types:**

   a. **Run conflict check** (as determined above). Skip if conflict found.

   b. **Create local clone** (skip in dry-run, using the clone command determined above).

   c. **Launch interactive container** (skip in dry-run):
      ```bash
      ./.claude/tooling/scripts/agent-dispatch.sh launch-interactive <BRANCH> [<CLONE_DIR>]
      ```
      Pass `<CLONE_DIR>` explicitly for issue and PR targets (since their clone dirs don't match the sanitized branch pattern).
      This launches a detached container running `claude remote-control --dangerously-skip-permissions`.
      The user connects via https://claude.ai/code — no TTY required.

   d. **Tell the user**:
      "Interactive session starting. Connect at https://claude.ai/code — look for session named `<BRANCH>`."
      "To view the session URL: `docker logs cfg-agent-interactive-<sanitized>`"
      "To drop into a shell: `docker exec -it cfg-agent-interactive-<sanitized> bash`"
      No label updates — interactive is user-driven.

### 4e. Acceptance-Review Dispatch

For each `acceptance-review <PR_NUM>`:

   a. **Validate PR is open**: `gh pr view <PR> --repo cfg-is/cfgms --json state,headRefName,body,labels`. Skip with warning if not OPEN. The dispatch script will also refuse, but pre-flight gives the user a clearer message.

   b. **Auto-detect story**: extract `Fixes #NNN` (or Closes/Resolves) from PR body, or `feature/story-(\d+)` from `headRefName`. The dispatch script does this too — surface its `REVIEW_REFUSED:<PR>:no_story_link` exit if neither matches.

   c. **Dispatch headless review** (skip in dry-run):
      ```bash
      ./.claude/tooling/scripts/agent-dispatch.sh review-pr <PR_NUM>
      ```
      Output is one of:
      - `REVIEW_DISPATCHED:<PR>:<STORY>:<container_id>` — running headless; check `/isoagents` for progress
      - `REVIEW_REFUSED:<PR>:<reason>: <hint>` — the reason line is self-explanatory; act on the trailing hint directly, no doc lookup needed (`resources` refusals come from the shared capacity gate and already embed their own reason). The full reason→hint table lives in `agent-dispatch.sh`'s `_review_refusal_hint()`, one place, so it can't drift from what the script actually does — don't duplicate it here.
      - `LAUNCH_FAILED:<container_name>:<error>` — Docker error; the script auto-strips the in-flight label

   d. **Tell the user**:
      "Acceptance Reviewer dispatched headless for PR #<NUM>. Container: cfg-agent-review-pr-<NUM>. The review comment will appear on the PR when it's done (~5-15 min). Use `/isoagents` to check progress."
      No label updates needed — the dispatch script sets project status to "Reviewing" and the container updates it on exit.

5. **Print full agent dashboard** (skip in dry-run): After launch, gather state for ALL agents (not just the ones dispatched this run):

   ```bash
   ./.claude/tooling/scripts/agent-dispatch.sh list-running
   ./.claude/tooling/scripts/agent-dispatch.sh list-exited
   ./.claude/tooling/scripts/po-act.sh dispatch status
   ```
   `dispatch status` lists the FSM runs (`RUN_ID STATUS STATE MODE TARGET CONTAINER HEARTBEAT SESSIONS REASON`). A run has no container while it prepares, snapshots, syncs or publishes (and only a `cfg-validate-<N>` container while it validates), so show its run row even when no agent container is listed.

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
- **Unfinished run (`run_in_flight`) or crashed run (`run_resumable:<run>`)**: Skip with warning; for a crashed run suggest `./.claude/tooling/scripts/po-act.sh dispatch resume <run>` (it abandons the run with `FSM_ABANDONED:…` instead when the work already finished)
- **Duplicate PR (`open_pr_exists:<PR>`)**: Skip with warning naming the PR; work that PR instead (`fix-pr <PR>` for a WIP draft)
- **Stale image (`image_stale`)**: Tell user to run `/agent-setup rebuild`
- **Clone/container conflict** (interactive mode): Skip with warning, suggest `/isoagents` to check existing state
- **All targets skipped**: Print summary of why each was skipped
