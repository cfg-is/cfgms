---
name: pr-review
description: Structured PR review using the pr-reviewer agent for fresh-context 6-phase methodology
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

Ensure the local repo reflects the latest state:

```bash
git fetch origin
```

Check for uncommitted changes — warn if working directory is dirty.

Check for unpushed commits on feature branches — push them before review so the PR reflects all code.

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

## Error Handling

- **Invalid PR number**: Show available open PRs and suggest retry.
- **GitHub unavailable**: Report error, suggest manual review via GitHub UI.
- **Agent fails**: Report error, suggest running `/pr-review` again.
