---
name: cleanup-stale-branch
description: Check whether a local git branch is already merged (via GitHub PR state or ancestry) and delete it if stale. Use after a PR merges, or when tidying up local branches left over from finished work.
allowed-tools: Bash
---

Run the helper, which does its own staleness detection (merged-PR check first, git-ancestry fallback — needed because this repo's merge queue is squash-only) and its own confirmation prompt:

```bash
./.claude/skills/cleanup-stale-branch/scripts/cleanup-stale-branch.sh $ARGUMENTS
```

`$ARGUMENTS`: `<branch> [--base <branch>] [--remote <name>] [--delete-remote] [--dry-run] [--yes]`. Defaults: `base=develop`, `remote=origin`, local-only delete.

Exit 0 = stale and deleted; exit 1 = not stale, nothing deleted — report the reason, don't delete by other means.
