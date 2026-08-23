# Task Completion Gates

Run before declaring any coding task done. Identical validation in both execution modes.

## Minimum before every commit
- `make test` — must be green (100% pass; `go build` is NOT sufficient).

## Before commit (full pre-commit gate)
- `make test-commit` = test + lint + lint-log-injection + check-license-headers + security-precommit + check-architecture + security-scan.

## Before opening a PR (story completion)
- `make test-complete` — matches ALL required CI checks (unit, integration, cross-platform compile, Docker integration, E2E, security gate). Native Windows/macOS builds are CI-only (local gap).
- Agent mode: `make test-agent-complete` (Phase 2).

## Self-review checklist (Phase 3)
- No mocks. No `t.Skip()` without justification. No hardcoded secrets.
- `make check-architecture` clean (no central-provider violations).
- Storage imports use `pkg/storage/interfaces` only.

## Required CI checks (all must pass before merge to develop)
`unit-tests`, `integration-tests`, `Build Gate`, `Controller Integration Tests (Linux)`, `security-deployment-gate`, `trivy-scan`, `CodeQL`, `zizmor`, `frontend-checks`, `CLA signature check` — ten contexts; read the live set with `gh api repos/cfg-is/cfgms/rulesets/11647684 --jq '.rules[]|select(.type=="required_status_checks").parameters.required_status_checks[].context'`. Docs-only PRs get stub-green fast path.

## Failure handling
After 3 fix iterations, open a DRAFT PR with error output. Never force-merge, force-push, `reset --hard`, delete branches, or skip validation.

## Merge
Squash via GitHub merge queue: `gh pr merge <N> --squash` to enqueue (queue auto-rebases + re-validates). Manual rebase only for genuine content conflicts.
