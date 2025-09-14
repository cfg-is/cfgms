---
name: pr-create
description: Alias for story-complete - creates PR and completes story
aliases: [story-complete]
parameters:
  - name: story_number
    description: Story number to complete (optional - auto-detects from branch)
    required: false
---

# PR Create Command (Alias)

This is an alias for the `story-complete` command, providing the same functionality with more intuitive naming for users who think in terms of "creating a PR" rather than "completing a story."

## Functionality

**Identical to `/story-complete`** - see [story-complete.md](story-complete.md) for complete documentation.

## Usage

```bash
/pr-create          # Auto-detect story from branch
/pr-create 166      # Complete specific story number
```

## Why This Alias Exists

Different developers have different mental models:

- **Story-Focused**: Think "I need to complete this story" → use `/story-complete`
- **PR-Focused**: Think "I need to create a pull request" → use `/pr-create`

Both commands perform identical operations:
1. Final validation gates
2. Story completeness verification
3. **Duplicate PR detection** (prevents creating multiple PRs for same branch)
4. Pull request creation
5. Project management updates
6. Roadmap updates
7. Branch cleanup

## Command Relationship

```
/pr-create ──────┐
                 ├──► Same underlying implementation
/story-complete ─┘
```

Both aliases are equally valid and provide the same comprehensive story completion workflow with all mandatory quality gates and project management integration.

---

*For complete documentation, see [story-complete.md](story-complete.md)*