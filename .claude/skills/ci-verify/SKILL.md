---
name: ci-verify
description: Verify GitHub Actions CI required checks pass for a pull request. Use before approving PRs or completing stories.
context: fork
agent: general-purpose
allowed-tools: Bash
---

# GitHub Actions CI Verification

## Required Checks (ALL must pass)
1. `unit-tests` — Core functionality validation
2. `integration-tests` — Fast comprehensive + production-critical tests
3. `Build Gate` — Cross-platform compilation + integration tests
4. `security-deployment-gate` — Security vulnerability blocking

## Verification Steps

1. **Check PR required checks** (uses helper to avoid approval prompts):
   ```bash
   ./scripts/pr-review-helper.sh pr-checks $ARGUMENTS
   ```

2. **Evaluate results**:
   - ALL SUCCESS → Report "CI PASSED — all required checks green"
   - ANY FAILURE → Report "CI FAILED — blocking" with failed check names
   - ANY PENDING → Report "CI IN PROGRESS — wait for completion" with pending check names
   - NO RUNS → Report "CI NOT RUN — branch may not be pushed"

3. **For failures, get details** (uses helper to avoid approval prompts):
   ```bash
   ./scripts/pr-review-helper.sh ci-details $ARGUMENTS
   ```

## Blocking Policy
- BLOCKS PR approval if any required check is failing
- BLOCKS PR approval if any required check is pending (wait for completion)
- BLOCKS PR approval if CI hasn't run (push branch first)

## Return
Report pass/fail/pending status with specific check names and any failure details.
