---
name: story-context
description: Detect story from branch name, fetch GitHub issue details, and calculate acceptance criteria progress. Use when commands need story number, title, progress percentage, or remaining work items.
context: fork
agent: general-purpose
allowed-tools: Bash
---

# Story Context Detection & Progress

## Steps

1. **Detect story number from branch**:
   ```bash
   branch=$(git branch --show-current)
   story_number=$(echo "$branch" | grep -oP 'story-\K[0-9]+')
   ```
   If no story number found in branch name, check if a story number was passed as argument: `$ARGUMENTS`

2. **Fetch issue details from GitHub**:
   ```bash
   gh issue view $story_number --json body,title,state,assignees
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
