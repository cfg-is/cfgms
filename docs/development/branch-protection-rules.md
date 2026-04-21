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

### Required Status Checks (13 total)

**Core Build & Test Checks**:
- `cross-compile-check` - Cross-platform compilation validation
- `native-builds` - Native builds (Ubuntu, macOS, Windows)
- `integration-tests` - Integration test suite
- `build-gate` - Final build validation

**Security Scans**:
- `trivy-scan` - Container vulnerability scanning
- `nancy-scan` - Go dependency scanning
- `gosec-scan` - Go security analysis
- `staticcheck-scan` - Static code analysis
- `security-validation` - Security validation gate

**Code Analysis**:
- `analyze` - CodeQL security analysis

**Production Gates** (main only):
- `security-deployment-gate` - Security deployment readiness
- `production-risk-assessment` - Production risk evaluation
- `integration-test-gate` - Integration test validation

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

### Required Status Checks (5 total)

- `unit-tests` - Core functionality validation
- `integration-tests` - Fast comprehensive + production-critical tests
- `Build Gate` - Cross-platform compilation + Docker integration tests
- `security-deployment-gate` - Security vulnerability blocking
- `Controller Integration Tests (Linux)` - Controller integration test suite

**Rationale**: Direct required checks pattern (Story #322) replaced the previous 10-check approach. These checks cover unit tests, integration tests, cross-platform builds, and security scanning. Production-specific gates (`production-risk-assessment`, `integration-test-gate`) are excluded to allow faster iteration.

### Merge Queue

Enabled in Story #801. The merge queue replaces the previous `strict_required_status_checks_policy` (strict mode, enabled in #793).

**How it works:**
1. A PR marked for merge enters a serial queue
2. GitHub creates a temporary merge-queue branch: current develop tip + the PR's changes
3. All 5 required checks run against that combined (post-rebase) state
4. If checks pass, the PR is squash-merged into develop
5. If checks fail, the PR is ejected from the queue and the author is notified

**Configuration** (Ruleset 11647684):
- Merge method: squash (preserves commit convention)
- Max entries to merge: 1 (serial — prevents ordering bugs like #785)
- Check response timeout: 60 minutes
- Grouping strategy: ALLGREEN (each PR must pass individually)

**Why merge queue instead of strict mode**: Strict mode required every PR author/agent to manually rebase before merge, which was manual work that compounded across the autonomous pipeline. Merge queues perform the rebase and re-validation automatically, eliminating that work for the ~80% of PRs with no genuine content conflict.

**Manual rebases are still needed** for genuine content conflicts (estimated ~20% of cases). A rebase is required only when `git merge` would produce a conflict that GitHub cannot auto-resolve.

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

### Required Status Checks (10 total)

**Core checks + deployment gate**:
- `cross-compile-check`
- `native-builds`
- `integration-tests`
- `build-gate`
- `trivy-scan`
- `nancy-scan`
- `gosec-scan`
- `staticcheck-scan`
- `security-validation`
- `security-deployment-gate`

**Note**: Release branches require security deployment gate but exclude `production-risk-assessment` and `integration-test-gate` (already validated in develop). CodeQL analysis (`analyze`) is optional since it was already run on develop.

---

## Workflow Integration

### GitHub Actions Permissions

Required workflow permissions for release automation:
- `contents: write` - Create releases and tags
- `pull-requests: write` - Create and manage PRs

### Status Check Sources

| Check Name | Workflow File | Job Name |
|------------|---------------|----------|
| cross-compile-check | cross-platform-build.yml | cross-compile-check |
| native-builds | cross-platform-build.yml | native-builds |
| integration-tests | cross-platform-build.yml | integration-tests |
| build-gate | cross-platform-build.yml | build-gate |
| trivy-scan | security-scan.yml | trivy-scan |
| nancy-scan | security-scan.yml | nancy-scan |
| gosec-scan | security-scan.yml | gosec-scan |
| staticcheck-scan | security-scan.yml | staticcheck-scan |
| security-validation | security-scan.yml | security-validation |
| analyze | codeql-analysis.yml | analyze |
| security-deployment-gate | production-gates.yml | security-deployment-gate |
| production-risk-assessment | production-gates.yml | production-risk-assessment |
| integration-test-gate | production-gates.yml | integration-test-gate |

---

## Related Documentation

- [Git Workflow](./git-workflow.md) - Development workflow and branching strategy
- [Release Automation](../../.github/workflows/release-automation.yml) - Automated release workflow
- [Production Gates](../../.github/workflows/production-gates.yml) - Security and quality gates
