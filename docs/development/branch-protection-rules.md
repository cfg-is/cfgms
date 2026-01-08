# Branch Protection Rules Configuration

This document provides the exact GitHub branch protection rules configuration for CFGMS. These rules enforce the development workflow described in [git-workflow.md](./git-workflow.md).

**Related**: Issue #283 - Configure branch protection rules and release automation

**Note**: This configuration merges requirements from Issue #283 with enhanced security controls and release automation. Key additions include:

- Require approval of most recent push (prevents last-minute self-approval)
- Require conversation resolution (all PR comments must be addressed)
- Allow force pushes on develop (maintainers only, for rebasing feature branches)
- Release branch protection rules
- Automated release workflow integration

## Overview

CFGMS uses a GitFlow-style branching model with the following protected branches:

| Branch | Purpose | Protection Level |
|--------|---------|------------------|
| `main` | Production-ready releases | **Strict** |
| `develop` | Integration branch | **Moderate** |
| `release/*` | Release candidates | **Standard** |

## Configuration Methods

### Method 1: GitHub UI (Recommended for Initial Setup)

Go to: **Repository → Settings → Branches → Add branch protection rule**

### Method 2: GitHub API

Use the REST API for automated configuration. See examples below.

### Method 3: GitHub Rulesets (Modern Alternative)

GitHub Rulesets provide more flexibility. Go to: **Repository → Settings → Rules → Rulesets**

---

## Branch Protection Rules

### `main` Branch (Production)

**Pattern**: `main`

| Setting | Value | Rationale |
|---------|-------|-----------|
| Require a pull request before merging | ✅ Yes | No direct pushes to production |
| Required approving reviews | 1 | Human review required |
| Dismiss stale pull request approvals | ✅ Yes | Force re-review after changes |
| Require review from code owners | ❌ No | Optional - enable if CODEOWNERS is set |
| Require approval of most recent push | ✅ Yes | Prevent self-approval of last-minute changes |
| Require status checks to pass | ✅ Yes | CI must pass |
| **Required checks** | See below | |
| Require branches to be up to date | ✅ Yes | Merge conflicts resolved before merge |
| Require conversation resolution | ✅ Yes | All comments addressed |
| Require signed commits | ❌ No | Optional - enable for high security |
| Require linear history | ❌ No | Optional - prevents merge commits if enabled |
| Include administrators | ✅ Yes | No bypassing, even for admins |
| Restrict who can push to matching branches | ✅ cfg-is/maintainers | Controlled access to production |
| Allow force pushes | ❌ Never | Preserve history |
| Allow deletions | ❌ Never | Protect main branch |

**Required Status Checks for `main`**:

Core Checks (always required):

- `cross-compile-check` - Cross-platform compilation validation
- `native-builds` - Native builds on Ubuntu, macOS, Windows
- `integration-tests` - Integration test suite
- `build-gate` - Final build gate (from cross-platform-build.yml)
- `trivy-scan` - Container vulnerability scanning
- `nancy-scan` - Go dependency vulnerability scanning
- `gosec-scan` - Go security scanning
- `staticcheck-scan` - Static code analysis
- `security-validation` - Security validation gate (from security-scan.yml)
- `analyze` - CodeQL security analysis (from codeql-analysis.yml)

Production Gates (required for main branch):

- `security-deployment-gate` - Security deployment readiness
- `production-risk-assessment` - Production risk evaluation
- `integration-test-gate` - Integration test validation gate (from production-gates.yml)

### `develop` Branch (Integration)

**Pattern**: `develop`

| Setting | Value | Rationale |
|---------|-------|-----------|
| Require a pull request before merging | ✅ Yes | Feature branches must use PRs |
| Required approving reviews | 1 | Peer review for all changes |
| Dismiss stale pull request approvals | ✅ Yes | Re-review after changes |
| Require review from code owners | ❌ No | Optional - enable if CODEOWNERS is set |
| Require approval of most recent push | ✅ Yes | Prevent self-approval of last-minute changes |
| Require status checks to pass | ✅ Yes | Same checks as main |
| **Required checks** | See below | |
| Require branches to be up to date | ✅ Yes | Ensure compatibility before merge |
| Require conversation resolution | ✅ Yes | All comments addressed |
| Include administrators | ❌ No | Admins can bypass for emergencies |
| Restrict who can force push | ✅ cfg-is/maintainers only | Allow rebasing for cleaner history |
| Allow force pushes | ⚠️ Yes (maintainers only) | Enables rebase workflow for feature cleanup |
| Allow deletions | ❌ Never | Never delete develop |

**Required Status Checks for `develop`**:

- `cross-compile-check` - Cross-platform compilation validation
- `native-builds` - Native builds on Ubuntu, macOS, Windows
- `integration-tests` - Integration test suite
- `build-gate` - Final build gate (from cross-platform-build.yml)
- `trivy-scan` - Container vulnerability scanning
- `nancy-scan` - Go dependency vulnerability scanning
- `gosec-scan` - Go security scanning
- `staticcheck-scan` - Static code analysis
- `security-validation` - Security validation gate (from security-scan.yml)
- `analyze` - CodeQL security analysis (from codeql-analysis.yml)

**Note**: develop requires the same core checks as main, but excludes production-specific gates (deployment-gate, risk-assessment) to allow faster iteration.

### `release/*` Branches (Release Candidates)

**Pattern**: `release/*`

| Setting | Value | Rationale |
|---------|-------|-----------|
| Require a pull request before merging | ❌ No | Release automation pushes directly |
| Require status checks to pass | ✅ Yes | Full test suite must pass |
| **Required checks** | See below | |
| Allow force pushes | ❌ Never | Preserve release history |
| Allow deletions | ✅ Yes | Cleanup after merge to main |

**Required Status Checks for `release/*`**:

- `cross-compile-check` - Cross-platform compilation validation
- `native-builds` - Native builds on Ubuntu, macOS, Windows
- `integration-tests` - Integration test suite
- `build-gate` - Final build gate (from cross-platform-build.yml)
- `trivy-scan` - Container vulnerability scanning
- `nancy-scan` - Go dependency vulnerability scanning
- `gosec-scan` - Go security scanning
- `staticcheck-scan` - Static code analysis
- `security-validation` - Security validation gate (from security-scan.yml)
- `security-deployment-gate` - Security deployment readiness (from production-gates.yml)

**Note**: Release branches require the same checks as main, but CodeQL analysis is optional since it was already run on develop.

---

## GitHub API Configuration

### Configure `main` Branch Protection

```bash
# Using GitHub CLI
gh api -X PUT /repos/{owner}/{repo}/branches/main/protection \
  -f required_status_checks='{"strict":true,"contexts":["cross-compile-check","native-builds","integration-tests","build-gate","trivy-scan","nancy-scan","gosec-scan","staticcheck-scan","security-validation","analyze","security-deployment-gate","production-risk-assessment","integration-test-gate"]}' \
  -f enforce_admins=true \
  -f required_pull_request_reviews='{"dismiss_stale_reviews":true,"require_code_owner_reviews":false,"required_approving_review_count":1,"require_last_push_approval":true}' \
  -f restrictions='{"users":[],"teams":["cfg-is/maintainers"],"apps":[]}' \
  -f allow_force_pushes=false \
  -f allow_deletions=false \
  -f required_conversation_resolution=true
```

### Configure `develop` Branch Protection

```bash
gh api -X PUT /repos/{owner}/{repo}/branches/develop/protection \
  -f required_status_checks='{"strict":true,"contexts":["cross-compile-check","native-builds","integration-tests","build-gate","trivy-scan","nancy-scan","gosec-scan","staticcheck-scan","security-validation","analyze"]}' \
  -f enforce_admins=false \
  -f required_pull_request_reviews='{"dismiss_stale_reviews":true,"require_code_owner_reviews":false,"required_approving_review_count":1,"require_last_push_approval":true}' \
  -f restrictions='{"users":[],"teams":["cfg-is/maintainers"],"apps":[]}' \
  -f allow_force_pushes='{"users":[],"teams":["cfg-is/maintainers"],"apps":[]}' \
  -f allow_deletions=false \
  -f required_conversation_resolution=true
```

**Note**: The `allow_force_pushes` setting restricts force pushes to cfg-is/maintainers only, allowing them to rebase feature branches for cleaner history before merging. The develop branch excludes production gates to enable faster iteration.

### Configure `release/*` Branch Pattern

Note: Wildcard patterns require GitHub Rulesets (not available in classic branch protection).

```bash
# Create a ruleset for release branches
gh api -X POST /repos/{owner}/{repo}/rulesets \
  --input - << 'EOF'
{
  "name": "Release Branch Protection",
  "target": "branch",
  "enforcement": "active",
  "conditions": {
    "ref_name": {
      "include": ["refs/heads/release/*"],
      "exclude": []
    }
  },
  "rules": [
    {
      "type": "required_status_checks",
      "parameters": {
        "required_status_checks": [
          {"context": "cross-compile-check"},
          {"context": "native-builds"},
          {"context": "integration-tests"},
          {"context": "build-gate"},
          {"context": "trivy-scan"},
          {"context": "nancy-scan"},
          {"context": "gosec-scan"},
          {"context": "staticcheck-scan"},
          {"context": "security-validation"},
          {"context": "security-deployment-gate"}
        ],
        "strict_required_status_checks_policy": true
      }
    },
    {
      "type": "non_fast_forward"
    },
    {
      "type": "deletion"
    }
  ]
}
EOF
```

---

## Verification

After configuration, verify the rules are working:

### Test 1: Direct Push to main (Should Fail)

```bash
git checkout main
echo "test" >> test.txt
git add test.txt
git commit -m "Test direct push"
git push origin main
# Expected: Rejected - protected branch
```

### Test 2: PR Without Tests (Should Block Merge)

1. Create a PR with failing tests
2. Attempt to merge
3. Expected: Merge blocked until tests pass

### Test 3: PR Without Approval (Should Block Merge)

1. Create a PR with passing tests
2. Attempt to merge without approval
3. Expected: Merge blocked until approved

---

## Troubleshooting

### "Required status check is expected" Error

The status check name must match exactly. Check the workflow job names:
- In `test-suite.yml`: job `unit-tests` → check name is `unit-tests`
- In `production-gates.yml`: job `security-deployment-gate` → check name is `security-deployment-gate`

### Admins Can Bypass Rules

For `main`, ensure "Include administrators" is enabled. For `develop`, this is intentionally disabled for emergency hotfixes.

### Release Automation Failing

The GitHub Actions bot needs `contents: write` and `pull-requests: write` permissions. Check the workflow permissions section.

---

## Related Documentation

- [Git Workflow](./git-workflow.md) - Development workflow and branching strategy
- [Release Automation](./../.github/workflows/release-automation.yml) - Automated release workflow
- [Production Gates](./../../.github/workflows/production-gates.yml) - Security and quality gates
