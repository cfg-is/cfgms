# Merge Protocol

This document describes how PRs merge into `develop` in CFGMS.

## Overview

PRs targeting `develop` merge via the **GitHub merge queue**. The queue auto-rebases each PR against the current develop tip, re-runs all required checks against the combined state, and squash-merges if checks pass.

This replaced the `strict_required_status_checks_policy` (strict mode, Story #793) in Story #801.

## How the Queue Works

1. A PR is marked for merge (`gh pr merge --squash` or the GitHub UI)
2. GitHub creates a temporary branch: `develop` tip + the PR's changes
3. All 5 required checks run against that combined state:
   - `unit-tests`
   - `integration-tests`
   - `Build Gate`
   - `security-deployment-gate`
   - `Controller Integration Tests (Linux)`
4. If all checks pass → PR is squash-merged into develop
5. If any check fails → PR is ejected from the queue; author/agent is notified

## For Interactive Mode

After `/pr-review` approves:

```bash
gh pr merge <PR_NUM> --squash
```

Do **not** use `--auto`. The merge queue (`--squash` without `--auto`) enqueues the PR. GitHub drives it from there.

## For Agent-Dispatched PRs

The acceptance reviewer agent calls `gh pr merge <PR_NUM> --repo cfg-is/cfgms --squash` when all acceptance criteria are met and CI is green. The queue then validates the post-rebase state and merges if checks pass.

## When to Rebase Manually

Manual rebase is only needed for **genuine content conflicts** — cases where `git merge` would produce a conflict that GitHub cannot auto-resolve. Estimated at ~20% of PRs.

Signs you need a manual rebase:
- GitHub shows "This branch has conflicts that must be resolved"
- The merge queue ejects the PR with a conflict message

Steps:
```bash
git fetch origin develop
git rebase origin/develop
# resolve conflicts
git add <resolved files>
git rebase --continue
git push --force-with-lease
```

Do **not** rebase preemptively. Let the queue handle it.

## Configuration

Ruleset 11647684 (Develop Branch Protection):
- Merge method: squash
- Max entries to merge: 1 (serial queue)
- Check response timeout: 60 minutes
- Grouping strategy: ALLGREEN (each PR validated independently)

See [branch-protection-rules.md](./branch-protection-rules.md) for full ruleset details.
