# Merge Protocol

This document describes how PRs merge into `develop` in CFGMS and what to do when multiple PRs touch overlapping files. It extends [git-workflow.md](git-workflow.md), which covers branching, PR creation, and squash merge mechanics.

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

## When Manual Rebase Is Still Needed

The merge queue handles the stale-base case automatically — most PRs never need a manual rebase. The exception is **genuine content conflicts**: cases where `git merge` would produce a conflict that GitHub cannot auto-resolve. Estimated at ~20% of PRs.

Signs you need a manual rebase:
- GitHub shows "This branch has conflicts that must be resolved"
- The merge queue ejects the PR with a conflict message

Steps:

```bash
# 1. Fetch latest develop
git fetch origin develop

# 2. Rebase your branch onto it
git rebase origin/develop

# 3. If conflicts arise, resolve them file by file, then continue
git add <resolved-file>
git rebase --continue

# 4. Push the rebased branch
git push --force-with-lease origin <your-branch>
```

**Do not use `--force` without `--lease`.** `--force-with-lease` refuses the push if the remote has commits you have not fetched, preventing accidental overwrite of a collaborator's push.

After the force-push, re-mark the PR for merge (`gh pr merge <PR_NUM> --squash`). The queue validates the new state and merges if checks pass.

## What Is a Cross-Cutting Change

A PR is cross-cutting if it modifies a type, interface, or import path that is used by files outside its primary package.

Examples:
- **Storage interface taxonomy (PR #772)** — renamed types in `pkg/storage/interfaces`, which every storage consumer imports. Any PR that also touched a storage consumer was downstream of #772.
- **Sensitive-field redaction (PR #777)** — added a logging import alias that conflicted with the alias introduced in #772's companion changes. The alias collision caused a one-character build break (see [Incident Reference](#incident-reference)).

Non-cross-cutting (single-package work, no exported type changes): a PR that only adds a new endpoint handler and its tests, touching no shared interfaces.

**Quick heuristic:** run `git diff --name-only origin/develop...HEAD` and check whether any of those files are in `pkg/*/interfaces/`, `pkg/storage/`, `pkg/logging/`, `pkg/secrets/`, `pkg/cert/`, or any other package listed as a Pluggable or Direct Provider in CLAUDE.md. If yes, treat the PR as cross-cutting.

## Detecting File Overlap With Other Open PRs

The merge queue serializes merges automatically — you don't need to manually order them. But you may want to detect overlap early to avoid unnecessary rebase cycles.

```bash
# For each open PR, check its changed files
gh pr diff <PR_NUMBER> --name-only

# Compare against your own changed files
git diff --name-only origin/develop...HEAD

# Any file appearing in both lists = expect your PR to be rebased
# after the first one merges (queue handles it), OR ejected if there's
# a content conflict (manual rebase required)
```

## Rules for Dispatch Agents

1. After making changes, the acceptance reviewer checks CI status against the queue's combined-state validation. Green CI is authoritative.
2. If the queue ejects the PR for a content conflict, the dispatch or fix agent must rebase manually (see [When Manual Rebase Is Still Needed](#when-manual-rebase-is-still-needed)) and re-queue.
3. Agents do NOT serialize by decision — the queue decides order. Agents just react to queue outcomes.

## Incident Reference

On 2026-04-20, PR #777 (sensitive-field redaction) was opened against a develop snapshot that predated PR #772 (storage interface taxonomy). Both PRs were cross-cutting: #772 changed import aliases in `pkg/storage/interfaces`; #777 introduced a logging alias that collided with the renamed identifier. The collision was a single-character build break invisible to both PR authors because each PR's CI ran against its own stale base.

PR #777 merged first (its CI was green against the old base). When develop incorporated #772 shortly after, the alias collision surfaced and broke the build. Hotfix PR #785 fixed it.

**This is exactly the class of bug the merge queue prevents.** The queue would have created `develop + #777` as a merge-queue branch, run all required checks against that combined state, seen the alias collision as a build break, and ejected the PR before the broken state reached develop.

See [branch-protection-rules.md](./branch-protection-rules.md) for full ruleset details including merge queue configuration.
