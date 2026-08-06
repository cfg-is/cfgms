# Branch Protection Rules

This document describes the active GitHub Rulesets configuration for CFGMS. These rules enforce the development workflow described in [git-workflow.md](./git-workflow.md).

**Related**: Issue #283 - Configure branch protection rules and release automation

## Overview

CFGMS uses GitHub Rulesets to protect branches in a GitFlow-style branching model:

| Branch | Purpose | Protection Level | Ruleset ID |
|--------|---------|------------------|------------|
| `main` | Production-ready releases | **Strict** | 11647678 |
| `develop` | Integration branch | **Moderate** | 11647684 |
| `release/*` | Release candidates | **Standard** | 11647689 |

**Implementation**: All protection is enforced via GitHub Rulesets (modern approach), not legacy branch protection rules.

---

## Main Branch (`main`)

**Ruleset**: Main Branch Protection (ID: 11647678)
**Enforcement**: Active
**Bypass Actors**: None (strict for everyone, including administrators)

### Protection Rules

| Rule | Status | Purpose |
|------|--------|---------|
| Deletion | ❌ Blocked | Prevent accidental main branch deletion |
| Force pushes | ❌ Blocked | Preserve commit history |
| Pull request required | ✅ Required | No direct commits to main |
| Required approvals | 1 | Peer review required |
| Dismiss stale reviews | ✅ Yes | Re-review after new commits |
| Require approval of most recent push | ✅ Yes | Prevent last-minute self-approval |
| Require conversation resolution | ✅ Yes | All PR comments must be resolved |
| Status checks required | ✅ Yes | All CI checks must pass |

### Required Status Checks (4 total)

- `unit-tests` - Core functionality validation
- `integration-tests` - Fast comprehensive + production-critical tests
- `Build Gate` - Cross-platform compilation + Docker integration tests
- `security-deployment-gate` - Security vulnerability blocking

Read the list from the ruleset rather than trusting this page:

```bash
gh api repos/cfg-is/cfgms/rulesets/11647678 \
  --jq '.rules[]|select(.type=="required_status_checks").parameters.required_status_checks[].context'
```

**Note**: `main` is reached only by a `develop → main` release PR, so the content
has already cleared develop's ten checks. These four re-validate the merge
commit; they are not the whole of what gated the change.

---

## Develop Branch (`develop`)

**Ruleset**: Develop Branch Protection (ID: 11647684)
**Enforcement**: Active
**Bypass Actors**: None

### Protection Rules

| Rule | Status | Purpose |
|------|--------|---------|
| Deletion | ❌ Blocked | Prevent accidental develop branch deletion |
| Force pushes | ❌ Blocked | Preserve commit history |
| Pull request required | ✅ Required | Feature branches must use PRs |
| Required approvals | 1 | Peer review required |
| Dismiss stale reviews | ✅ Yes | Re-review after new commits |
| Require approval of most recent push | ✅ Yes | Prevent last-minute self-approval |
| Require conversation resolution | ✅ Yes | All PR comments must be resolved |
| Status checks required | ✅ Yes | CI checks must pass |
| Merge queue | ✅ Enabled | Serialized merge with post-rebase validation (replaces strict mode) |

### Required Status Checks (10 total)

- `unit-tests` - Core functionality validation
- `integration-tests` - Fast comprehensive + production-critical tests
- `Build Gate` - Cross-platform compilation + Docker integration tests
- `security-deployment-gate` - Security vulnerability blocking
- `Controller Integration Tests (Linux)` - Controller integration test suite
- `trivy-scan` - Filesystem vulnerabilities, secrets, misconfiguration
- `CodeQL` - Semantic code analysis
- `zizmor` - Workflow security (action pins, cache poisoning, injection)
- `frontend-checks` - `web/` typecheck, lint and tests
- `CLA signature check` - Contributor licence agreement

Read the list from the ruleset rather than trusting this page:

```bash
gh api repos/cfg-is/cfgms/rulesets/11647684 \
  --jq '.rules[]|select(.type=="required_status_checks").parameters.required_status_checks[].context'
```

**Rationale**: Direct required checks pattern (Story #322) replaced the earlier
approach of gating on aggregate workflow results. The `production-risk-assessment`
and `integration-test-gate` jobs this list used to name no longer exist — the
former is commented out in `production-gates.yml`, the latter is absent — so they
are not "excluded" so much as retired.

**Advisory, not required**: `nancy-scan`, `gosec-scan` and `staticcheck-scan`,
plus `security-validation`, the `security-scan.yml` aggregate that evaluates them.
Their jobs fail on findings, but a red one does not block a merge — the ruleset
does not list them. Treat a finding there as real work, not as optional.

### Merge Queue

Enabled in Story #801. The merge queue replaces the previous `strict_required_status_checks_policy` (strict mode, enabled in #793).

**How it works:**
1. A PR marked for merge enters a serial queue
2. GitHub creates a temporary merge-queue branch: current develop tip + the PR's changes
3. All 10 required checks run against that combined (post-rebase) state
4. If checks pass, the PR is squash-merged into develop
5. If checks fail, the PR is ejected from the queue and the author is notified

**Configuration** (Ruleset 11647684):
- Merge method: squash (preserves commit convention)
- Max entries to merge: 1 (serial — prevents ordering bugs like #785)
- Check response timeout: 60 minutes
- Grouping strategy: ALLGREEN (each PR must pass individually)

**Why merge queue instead of strict mode**: Strict mode required every PR author/agent to manually rebase before merge, which was manual work that compounded across the autonomous pipeline. Merge queues perform the rebase and re-validation automatically, eliminating that work for the ~80% of PRs with no genuine content conflict.

**Manual rebases are still needed** for genuine content conflicts (estimated ~20% of cases). A rebase is required only when `git merge` would produce a conflict that GitHub cannot auto-resolve.

**Post-merge sanity catch**: `.github/workflows/develop-sanity.yml` runs `go build ./...` on every push to develop (i.e., after every squash-merge). If the build fails it automatically opens a `pipeline:incident` issue linking to the failed run. This is a complementary catch mechanism for the residual cases not covered by pre-merge validation — it does not replace the required status checks above.

---

## Release Branches (`release/*`)

**Ruleset**: Release Branch Protection (ID: 11647689)
**Enforcement**: Active with wildcard pattern
**Bypass Actors**: None

### Protection Rules

| Rule | Status | Purpose |
|------|--------|---------|
| Deletion | ✅ Allowed | Cleanup after merge to main |
| Force pushes | ❌ Blocked | Preserve release history |
| Pull request required | ❌ Not required | Release automation pushes directly |
| Status checks required | ✅ Yes | Full validation before release |

### Required Status Checks (none)

The Release Branch Protection ruleset configures **no** required status checks.
Deletion and force-push rules apply; CI results do not gate a push to a
`release/*` branch.

```bash
# Returns nothing — there is no required_status_checks rule on this ruleset.
gh api repos/cfg-is/cfgms/rulesets/11647689 \
  --jq '.rules[]|select(.type=="required_status_checks").parameters.required_status_checks[].context'
```

**This is recorded as the measured state, not as an endorsement.** Release
branches are cut from `develop`, whose ten checks have already run on every
commit, so content reaching `release/*` has been validated — but nothing
re-validates the release branch itself. Closing that gap is a ruleset change and
is tracked separately from this document.

---

## Workflow Integration

### Status Check Sources

The context name is the job's `name:`, not its key — these were measured by
grepping `name: <context>` across `.github/workflows/`.

**Required on `develop`** (all ten):

| Context name | Real run | Stub |
|---|---|---|
| `unit-tests` | `test-suite.yml` | `documentation.yml` |
| `integration-tests` | `test-suite.yml` | `documentation.yml` |
| `Build Gate` | `cross-platform-build.yml` | `documentation.yml` |
| `security-deployment-gate` | `production-gates.yml` | `documentation.yml` |
| `Controller Integration Tests (Linux)` | `production-gates.yml` | `documentation.yml` |
| `trivy-scan` | `security-scan.yml` | `documentation.yml` |
| `CodeQL` | `codeql-analysis.yml` | `codeql-stub.yml` |
| `zizmor` | `zizmor.yml` | none |
| `frontend-checks` | `frontend-ci.yml` | none |
| `CLA signature check` | `cla-check.yml` | none |

**Advisory, not required** — these fail on findings but do not block a merge:

| Context name | Source workflow |
|---|---|
| `nancy-scan` | `security-scan.yml` |
| `gosec-scan` | `security-scan.yml` |
| `staticcheck-scan` | `security-scan.yml` |
| `security-validation` | `security-scan.yml` |

---

## Related Documentation

- [Git Workflow](./git-workflow.md) - Development workflow and branching strategy
- [Production Gates](../../.github/workflows/production-gates.yml) - Security and quality gates
