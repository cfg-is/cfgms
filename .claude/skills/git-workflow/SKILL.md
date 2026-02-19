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
- Push with upstream tracking: `git push -u origin $(git branch --show-current)`
- After push, verify remote is up to date

## Branch Validation
```bash
current_branch=$(git branch --show-current)
if [[ $current_branch == feature/* ]] || [[ $current_branch == tooling/* ]]; then
  target_branch="develop"
elif [[ $current_branch == hotfix/* ]]; then
  target_branch="main"
else
  echo "ERROR: Unexpected branch pattern"
fi
```
