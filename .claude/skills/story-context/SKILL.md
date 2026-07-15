---
name: story-context
description: Detect story from branch name (or roadmap when no branch), fetch GitHub issue details, and calculate acceptance criteria progress. Use when commands need story number, title, progress percentage, or remaining work items.
context: fork
agent: general-purpose
model: haiku
allowed-tools: Bash
---

# Story Context Detection & Progress

## Steps

1. **Detect story number**:
   ```bash
   git branch --show-current
   ```
   Extract the story number from the branch name by finding the numeric part after `story-`.
   If no story number is found in the branch name, check `$ARGUMENTS` for one.
   If still none (e.g. `/story-start` auto-detection before a branch exists), scan the roadmap for candidates instead — this keeps the large roadmap file and issue list out of the caller's context:
   ```bash
   grep -nE '^- \[ \] \*\*.*\*\* \(Issue #[0-9]+\)' docs/product/roadmap.md
   gh issue list --state open --limit 50 --json number,title,labels
   ```
   Return the uncompleted candidates (number + title) rather than a single story, and let the caller choose.

2. **Fetch issue details from GitHub** (use the extracted story number):
   ```bash
   gh issue view <story_number> --json body,title,state,assignees
   ```

3. **Parse acceptance criteria** from issue body:
   - Look for checkbox patterns: `- [ ]` (incomplete) and `- [x]` (complete)
   - Look for `**Acceptance Criteria:**` or `### Requirements` sections
   - Count total criteria and completed criteria

4. **Calculate progress**:
   ```
   completed / total = percentage
   ```

5. **Generate smart recommendation** based on progress:
   - < 50%: "Continue development — significant work remains"
   - 50-89%: "Making good progress — focus on remaining items"
   - 90-99%: "Almost done — consider final testing and documentation"
   - 100%: "Ready for completion — run /story-complete"

6. **Return structured result**:
   - Story number
   - Story title
   - GitHub state (open/closed)
   - Progress: X/Y criteria (Z%)
   - Remaining items (list unchecked criteria)
   - Smart recommendation
