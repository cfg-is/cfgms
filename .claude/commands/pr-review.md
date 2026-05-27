---
name: pr-review
description: Structured PR review using the pr-reviewer agent for fresh-context 6-phase methodology. Use when reviewing PRs, checking PR quality, or the user says "review PR", "check the PR", "is this ready to merge", "review #X", or wants to approve/reject a pull request.
parameters:
  - name: pr_number
    description: Pull request number to review (optional - auto-selects if 1 PR, shows menu if multiple)
    required: false
---

# PR Review Command

Launch a fresh-context PR review using the **pr-reviewer** agent. The agent executes the full 6-phase review methodology in an isolated context, ensuring objective analysis without development bias.

## Execution Flow

### 1. PR Selection

**If PR number provided**: Use it directly.

**If no PR number provided**:
```bash
gh pr list --state=open --json number,title,author,headRefName,isDraft --limit 20
```
- **0 PRs found**: Report "No open PRs" and exit
- **1 PR found**: Auto-select it, inform user
- **Multiple PRs found**: Present selection menu with AskUserQuestion (letter options for quick selection, or enter PR number directly)

### 2. Pre-Review Git Sync

Ensure the local repo reflects the latest state (uses helper to avoid approval prompts):

```bash
./.claude/scripts/pr-review-helper.sh pre-review <NUM>
```

Parse output:
- `DIRTY:true` — warn user about uncommitted changes
- `UNPUSHED:true` — warn user about unpushed commits, suggest pushing before review

### 3. Launch PR Reviewer Agent

Spawn the **pr-reviewer** agent via the Task tool:

```
Task tool:
  subagent_type: pr-reviewer
  prompt: "Review PR #[number] for the CFGMS project. Execute all 6 phases of the review methodology."
```

The agent runs in isolated context with:
- Full 6-phase review methodology (git workflow, security, testing, docs, CI, approval)
- Read-only tools (Read, Grep, Glob, Bash for gh commands)
- git-workflow and ci-verify skills preloaded
- Sonnet model for fast, capable review

### 4. Report Results

When the agent completes, relay its findings to the user:
- Phase-by-phase summary
- Final recommendation (APPROVED / CHANGES REQUIRED / BLOCKED)
- Any blocking issues that need resolution

### 5. Agent Cleanup on Approval

If the review result is **APPROVED FOR MERGE** or **APPROVED WITH COMMENTS**, check whether the PR branch came from an agent dispatch (branch pattern `feature/story-*-agent`). If so:

1. Extract the story number from the branch name
2. Clean up the agent's container and clone:
   ```bash
   ./.claude/scripts/agent-dispatch.sh cleanup-issue <story_number>
   ```
3. Report what was cleaned up

This keeps agent infrastructure tidy — once a PR is approved, the container and worktree are no longer needed.

## Error Handling

- **Invalid PR number**: Show available open PRs and suggest retry.
- **GitHub unavailable**: Report error, suggest manual review via GitHub UI.
- **Agent fails**: Report error, suggest running `/pr-review` again.
