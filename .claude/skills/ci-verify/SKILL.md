---
name: ci-verify
description: Verify GitHub Actions CI required checks pass for a pull request. Use before approving PRs or completing stories.
context: fork
agent: general-purpose
allowed-tools: Bash
---

# GitHub Actions CI Verification

## Required Checks (ALL must pass)

Ten contexts are required by the `Develop Branch Protection` ruleset. The
authority is the ruleset, never this list — re-read it with:

```bash
gh api repos/cfg-is/cfgms/rulesets/11647684 \
  --jq '.rules[]|select(.type=="required_status_checks").parameters.required_status_checks[].context'
```

1. `unit-tests` — Core functionality validation
2. `integration-tests` — Fast comprehensive + production-critical tests
3. `Build Gate` — Cross-platform compilation + Docker integration
4. `Controller Integration Tests (Linux)` — Controller integration suite
5. `security-deployment-gate` — Critical vulnerability blocking
6. `trivy-scan` — Filesystem vulnerabilities, secrets, misconfiguration
7. `CodeQL` — Semantic analysis of changed lines
8. `zizmor` — Workflow security (action pins, cache poisoning, injection)
9. `frontend-checks` — `web/` typecheck, lint, and tests
10. `CLA signature check` — Contributor licence agreement

Advisory checks (`nancy-scan`, `gosec-scan`, `staticcheck-scan`,
`security-validation`, `golangci-lint`) are **not** required and do not block.
A finding there is still real work — report it, but do not call the PR failed
for it alone.

## Verification Steps

1. **Check PR required checks** (uses helper to avoid approval prompts):
   ```bash
   ./.claude/scripts/pr-review-helper.sh pr-checks $ARGUMENTS
   ```

   The helper prints the `gh pr checks --required` table, then three machine-readable
   lines:

   - `CHECKS_RC:<n>` — `0` all reported checks passed, `8` at least one pending,
     anything else at least one failed (or nothing reported).
   - `MISSING:<context>` — one line per required context that produced **no check
     run at all**.
   - `MISSING_COUNT:<n>` — how many.

   **`MISSING` is the line that matters most.** `gh pr checks --required` lists only
   contexts that reported, so a context that never ran is simply absent from the
   table — without the `MISSING` lines a caller reads an all-`pass` table and
   concludes "CI PASSED" while required contexts were never evaluated.

2. **Evaluate results** — in this order, and stop at the first that matches:
   - `REQUIRED_SET:unavailable` → Report "CI UNVERIFIED — could not read the
     ruleset". Do **not** report a pass.
   - `MISSING_COUNT` greater than `0` → Report "CI INCOMPLETE — blocking" and name
     every `MISSING` context. This is not a pass, even when every reported check is
     green.
   - Any check in state `fail`, `failure`, `cancelled`, or `timed_out` → Report
     "CI FAILED — blocking" with the failed check names.
   - Any check `pending` / `in_progress`, or `CHECKS_RC:8` → Report "CI IN
     PROGRESS — wait for completion" with the pending check names.
   - `CHECKS:no required checks or PR not found` → Report "CI NOT RUN — branch may
     not be pushed".
   - All ten contexts present, none failing, none pending → Report "CI PASSED — all
     ten required checks green".

   **`skipping` is not a pass and not a failure.** Several required contexts are
   posted by a stub job on one side of the PR / merge-queue split and by the real
   job on the other, so a `skipping` row is normal — but a context whose *only* row
   is `skipping` has not been evaluated. Treat it as CI INCOMPLETE and name it.

3. **For failures, get details** (uses helper to avoid approval prompts):
   ```bash
   ./.claude/scripts/pr-review-helper.sh ci-details $ARGUMENTS
   ```

## Blocking Policy
- BLOCKS PR approval if any required check is failing
- BLOCKS PR approval if any required check is pending (wait for completion)
- BLOCKS PR approval if any required context is missing (`MISSING_COUNT` > 0)
- BLOCKS PR approval if the required-context set could not be read
- BLOCKS PR approval if CI hasn't run (push branch first)

## Return
Report pass/fail/pending/incomplete status with specific check names, the
`MISSING` contexts if any, and any failure details.
