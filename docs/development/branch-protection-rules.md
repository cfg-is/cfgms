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

### Required Status Checks (4 total)

- `unit-tests` - Core functionality validation
- `integration-tests` - Fast comprehensive + production-critical tests
- `Build Gate` - Cross-platform compilation + Docker integration tests
- `security-deployment-gate` - Security vulnerability blocking

**Rationale**: Direct required checks pattern (Story #322) replaced the previous 10-check approach. These 4 checks cover unit tests, integration tests, cross-platform builds, and security scanning. Production-specific gates (`production-risk-assessment`, `integration-test-gate`) are excluded to allow faster iteration.

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
