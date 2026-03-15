---
name: story-start
description: Start a new story with mandatory pre-flight validation and roadmap auto-detection. MUST use when beginning any new development work, picking up an issue, or the user says "start story", "new story", "work on issue", "begin work on #X", or similar.
parameters:
  - name: story_number
    description: The story/issue number (optional - auto-detects from roadmap if omitted)
    required: false
  - name: description
    description: Brief description for branch name (optional if auto-detecting)
    required: false
---

# Story Start Command

Start a new story with mandatory pre-flight checks that establish an **accountability baseline**. If tests pass now, any failures during development are unambiguously caused by the current work.

## Execution Flow

### 1. Auto-Detection (when no story number provided)

Parse `docs/product/roadmap.md` for uncompleted stories:
- Find lines matching `- [ ] **...** (Issue #NNN)` patterns
- Cross-reference with `gh issue list` for status
- If one candidate: confirm with user
- If multiple: present selection menu with AskUserQuestion

### 2. Pre-Flight Validation (BLOCKING)

**CRITICAL**: This establishes the clean baseline. No starting work on top of failures.

```bash
make test
```

- **BLOCKS** if ANY tests fail — fix failures before starting new work
- **BLOCKS** if security issues exist
- **BLOCKS** if linting errors present
- Must achieve 100% clean baseline

**Why this matters**: With a documented clean baseline, there is zero ambiguity about who owns test failures found later. If it passed at start and fails during development, the current work caused it. No excuses.

### 3. Git Status Validation

- Verify on `develop` branch (or prompt to switch)
- Check for uncommitted changes (warn if dirty)
- Ensure local branch is up-to-date: `git pull origin develop`

### 4. Branch Creation

```bash
git checkout -b feature/story-[NUMBER]-[description]
```

Verify: `git branch --show-current` shows new feature branch.

### 5. GitHub Project Update

```bash
# Move issue to "In Progress" on project board
gh project item-edit [project-id] --id [item-id] --field-id [status-field-id] --value "In Progress"
```

### 6. Story Context (invoke story-context skill)

Use the story-context skill to fetch issue details and display acceptance criteria for the story being started.

## Error Handling

- **Pre-flight fails**: Report specific failures, block branch creation. User must fix and retry.
- **Roadmap parse fails**: Fall back to manual story entry — prompt user for story number.
- **GitHub CLI unavailable**: Create branch locally, warn that project update requires manual action.
