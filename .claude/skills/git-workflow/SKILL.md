---
name: git-workflow
description: CFGMS Git workflow rules for branch naming, merge targets, and push procedures. Reference knowledge for PR creation and branch management.
user-invocable: false
---

# CFGMS Git Workflow Rules

## Branch Naming
- Feature branches: `feature/story-[NUMBER]-[description]`
- Hotfix branches: `hotfix/[description]`
- Tooling branches: `tooling/[description]`

## Merge Target Rules (CRITICAL)
- `feature/*` → `develop` (ALWAYS — standard development)
- `hotfix/*` → `main` (emergency fixes only)
- `tooling/*` → `develop` (tooling/infrastructure changes)
- `develop` → `main` (release PRs only)
- `feature/*` → `main` — **BLOCKED** (violates GitFlow)

## PR Creation
- Always use `--base develop` for feature and tooling branches
- Check for existing PR on branch before creating: `gh pr list --head [branch] --state=open`
- If existing PR found, update it with `gh pr edit` instead of creating duplicate

## Push Procedures
- Verify all changes committed before push: `git status --porcelain`
- Push with upstream tracking: `git push -u origin HEAD`
- After push, verify remote is up to date

## Branch Validation

Determine the correct PR base branch from the current branch name:
- `feature/*` or `tooling/*` → base is `develop`
- `hotfix/*` → base is `main`
- Anything else → ERROR: unexpected branch pattern

Use `git branch --show-current` to get the current branch, then match the prefix.
Do NOT compose multi-line bash scripts or use `$()` command substitution for this — use the Bash tool with simple single commands and apply the logic in your reasoning.
