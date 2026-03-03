# CFGMS Git Workflow and Branching Strategy

This document outlines the Git workflow, branching strategy, and PR process for CFGMS. For automated workflow, use `/story-start`, `/story-commit`, `/story-complete`.

## Branching Strategy

CFGMS follows GitFlow with **MANDATORY feature branch workflow**:

### Branch Hierarchy

- `main` - Production-ready code only (protected)
- `develop` - Integration branch for features (never delete)
- `feature/*` - New feature development (temporary)
- `fix/*` - Bug fixes (temporary)
- `docs/*` - Documentation updates (temporary)
- `refactor/*` - Code improvements (temporary)

### Branch Protection Rules

- `main`: Merge commits only (no squash/rebase), required status checks, no direct pushes
- `develop`: Squash merge only, required status checks, cannot be deleted
- `release/*`: No direct pushes (non-fast-forward only), no required checks (main handles that)
- Feature branches: Created from and merged back to `develop`

## Feature Branch Workflow

### 1. Starting New Work

```bash
# Always start from develop
git checkout develop
git pull origin develop

# Create feature branch with proper naming
git checkout -b feature/story-[NUMBER]-[brief-description]

# Examples:
git checkout -b feature/story-166-logging-migration
git checkout -b feature/story-167-enhanced-security
```

### 2. During Development

```bash
# Regular commits to feature branch
git add .
git commit -m "Implement core logging provider migration"

# Push feature branch to remote
git push origin feature/story-166-logging-migration

# Keep feature branch updated with develop (if needed)
git checkout develop
git pull origin develop
git checkout feature/story-166-logging-migration
git merge develop  # or rebase if preferred
```

### 3. Completing Work

```bash
# Final push of feature branch
git push origin feature/story-166-logging-migration

# Create PR: feature → develop
gh pr create --base develop --title "Implement Story #166: Logging Provider Migration"

# After PR approval and merge, cleanup
git checkout develop
git pull origin develop
git branch -D feature/story-166-logging-migration
```

## Branch Naming Conventions

### Standard Patterns

- **Feature**: `feature/story-[NUMBER]-[description]`
- **Bug Fix**: `fix/issue-[NUMBER]-[description]` or `fix/[brief-description]`
- **Documentation**: `docs/[topic]` or `docs/story-[NUMBER]-docs`
- **Refactoring**: `refactor/[component]-[description]`
- **Hotfix**: `hotfix/[critical-issue-description]`

### Examples

```bash
# Good examples
feature/story-166-logging-migration
feature/story-167-m365-consent-flow
fix/issue-123-race-condition
fix/docker-compose-v2-compatibility
docs/api-documentation-update
refactor/storage-interface-cleanup
hotfix/security-vulnerability-cve-2023-1234

# Bad examples (avoid)
feature/jordan-work
fix/broken-stuff
refactor/cleanup
docs/updates
```

## Pull Request Process

### CRITICAL RULE: Never Create Direct develop→main PRs

**❌ WRONG (Will Delete Develop Branch):**

```bash
# On develop branch - DON'T DO THIS
gh pr create --base main --title "Epic Complete"  # ❌ Will delete develop!
```

**✅ CORRECT (Release Branch Workflow):**

```bash
# For releases, create a release branch from develop
git checkout develop
git pull origin develop
git checkout -b release/vX.Y.Z
git push -u origin release/vX.Y.Z

# Create PR: release → main (merge commit, not squash)
gh pr create --base main --title "Release vX.Y.Z"
```

### PR Creation Template

```bash
gh pr create --base develop --title "Implement Story #[NUMBER]: [description]" --body "$(cat <<'EOF'
## Summary
[Brief description of the changes]

### Changes Made
- [List key changes]
- [Include any breaking changes]

### Test Results
✅ All tests passing
✅ Security scan clean
✅ Linting passed

### Basic Security Review
[Brief summary - no hardcoded secrets, SQL injection prevention, input validation present]

🤖 Generated with [Claude Code](https://claude.ai/code)

Co-Authored-By: Claude <noreply@anthropic.com>
EOF
)"
```

### PR Merge Settings

Merge methods are enforced by branch protection rulesets — GitHub only shows allowed options:

- **PRs to `develop`**: Squash merge only (enforced)
- **PRs to `main`**: Merge commit only (enforced)

```bash
# Merging a feature PR to develop (squash is the only option)
gh pr merge [PR_NUMBER] --squash

# Merging a release PR to main (merge commit is the only option)
gh pr merge [PR_NUMBER] --merge
```

See [Release Workflow](#release-workflow) for why different merge methods are used.

## PR Review Process

### Mandatory Review Requirements

- **Code Review**: All PRs require review before merge
- **Status Checks**: Tests, security scans, and linting must pass
- **Approval**: At least one approving review required
- **Fresh Context**: Use structured 5-phase review methodology

### Review Commands

```bash
# Review PR using structured methodology
/pr-review [PR_NUMBER]

# Or manual review following docs/development/pr-review-methodology.md
```

## Release Workflow

CFGMS uses a manual release process with strict merge strategy rules to maintain clean history and enable reliable back-sync between main and develop.

### Merge Strategy Rules (CRITICAL)

Each merge target has a specific merge method enforced by branch protection:

| Merge | Method | Why |
|-------|--------|-----|
| `feature/*` → `develop` | **Squash** | Clean atomic commits, one per story |
| `release/*` → `main` | **Merge commit** | Preserves ancestry so main→develop back-sync works cleanly |
| `main` → `develop` (post-release) | **Merge commit** | Syncs release fixes back without conflicts |

**Why merge commits for releases?** Squash merging a release branch into main creates a new commit with no parent relationship to develop's history. This means git sees the entire codebase as "new" when trying to sync main back to develop, producing thousands of false conflicts. Merge commits preserve the parent chain, enabling clean back-sync.

### Release Process

```
feature/* → develop → release/vX.Y.Z → main → tag → back-sync to develop
               ↑         (squash)           (merge commit)     (merge commit)
```

**Step-by-step:**

```bash
# 1. Ensure develop is clean
git checkout develop
git pull origin develop
make test  # Must pass 100%

# 2. Create release branch
git checkout -b release/vX.Y.Z

# 3. Run full validation
make test-complete

# 4. Push release branch and create PR to main
git push -u origin release/vX.Y.Z
gh pr create --base main --title "Release vX.Y.Z" --body "Release description"

# 5. Wait for all CI checks to pass
# Required: unit-tests, integration-tests, security-deployment-gate, Build Gate

# 6. Merge PR using MERGE COMMIT (enforced by branch protection)
# GitHub UI will only show "Create a merge commit" option
gh pr merge [PR_NUMBER] --merge

# 7. Tag the release on main
git checkout main
git pull origin main
git tag vX.Y.Z
git push origin vX.Y.Z

# 8. Back-sync main to develop (brings release merge + any hotfixes)
# Develop requires PRs, so create a sync branch:
git checkout main
git checkout -b sync/main-to-develop-vX.Y.Z
git push -u origin sync/main-to-develop-vX.Y.Z
gh pr create --base develop --title "Sync: main back to develop after vX.Y.Z"
# This PR uses squash merge (develop's merge method) — that's fine for sync
gh pr merge [PR_NUMBER] --squash

# 9. Clean up
git push origin --delete release/vX.Y.Z
git push origin --delete sync/main-to-develop-vX.Y.Z
```

### Handling Release Conflicts

If the PR from release→main has merge conflicts (e.g., from Dependabot PRs merged directly to main):

```bash
# On the release branch, merge main into it to resolve conflicts
git checkout release/vX.Y.Z
git merge origin/main
# Resolve conflicts — develop's content is authoritative for application code
# go.mod/go.sum: keep develop's versions, they're newer
git add .
git commit -m "Resolve merge conflicts with main"
git push origin release/vX.Y.Z
```

**Prevention:** Avoid merging Dependabot PRs directly to main. Instead, merge them to develop and include the dependency updates in the next release.

### Branch Protection Summary

All branch protection is enforced via GitHub rulesets.

| Branch | Merge Method | Required Checks | Notes |
|--------|-------------|-----------------|-------|
| `main` | Merge commit only | unit-tests, integration-tests, security-deployment-gate, Build Gate | No squash/rebase allowed |
| `develop` | Squash only | unit-tests, Build Gate, security-deployment-gate | Cannot be deleted |
| `release/*` | N/A (no PRs into release branches) | None | Non-fast-forward only; main handles merge checks |

### Hotfix Workflow

```bash
# 1. Create hotfix from main
git checkout main
git pull origin main
git checkout -b hotfix/critical-security-fix

# 2. Fix the issue
# ... make changes ...
git add .
git commit -m "Fix critical security vulnerability"

# 3. Create PRs to both main and develop
gh pr create --base main --title "Hotfix: Critical Security Fix"
gh pr create --base develop --title "Hotfix: Critical Security Fix"

# 4. After both PRs merge, tag new version
git checkout main
git pull origin main
git tag v0.4.7.1
git push origin v0.4.7.1
```

## Commit Message Standards

### Commit Message Format

```
[Type] Brief description (50 chars max)

Detailed explanation if needed (wrap at 72 chars)
- Key change 1
- Key change 2
- Security considerations

Basic Security Review: [summary]
```

### Commit Types

- **Implement**: New features or major functionality
- **Fix**: Bug fixes and issue resolution
- **Update**: Enhancements to existing features
- **Refactor**: Code improvements without functionality changes
- **Test**: Test additions or improvements
- **Docs**: Documentation changes
- **Security**: Security-related changes

### Examples

```
Implement Story #166: Global logging provider migration

- Migrate all CFGMS modules to use global logging provider
- Add structured logging fields (tenant_id, session_id, component)
- Update error handling with proper context propagation
- Ensure tenant isolation in all log entries

Basic Security Review: No hardcoded secrets, proper error handling,
input validation maintained for all logging calls
```

## Git Configuration

### Recommended Settings

```bash
# Set up user information
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"

# Useful aliases
git config --global alias.co checkout
git config --global alias.br branch
git config --global alias.ci commit
git config --global alias.st status
git config --global alias.unstage 'reset HEAD --'
git config --global alias.last 'log -1 HEAD'
git config --global alias.visual '!gitk'

# Better diff and merge tools
git config --global diff.tool vimdiff
git config --global merge.tool vimdiff

# Push current branch by default
git config --global push.default current

# Rebase instead of merge on pull (optional)
git config --global pull.rebase true
```

## Multi-Tenancy & Configuration Inheritance

The Git workflow supports CFGMS's multi-tenant architecture:

### Configuration Storage

- **Hierarchical Configuration Inheritance**: MSP (Level 0) → Client (Level 1) → Group (Level 2) → Device (Level 3)
- **Declarative Merging**: Named resources replace entire blocks rather than field-level merging
- **Source Tracking**: Every configuration value includes source attribution and hierarchy level
- **REST API Access**: `/api/v1/stewards/{id}/config/effective` endpoint provides merged configuration with inheritance metadata

### Branch Strategy for Multi-Tenant Features

- Feature branches for tenant-specific functionality
- Careful testing across tenant boundaries
- Configuration inheritance validation in PRs

## Troubleshooting

### Common Issues

#### Merge Conflicts

```bash
# When merge conflicts occur
git status  # See conflicted files
# Edit files to resolve conflicts
git add [resolved-files]
git commit -m "Resolve merge conflicts"
```

#### Branch Cleanup

```bash
# List all branches
git branch -a

# Delete local feature branch
git branch -D feature/old-branch

# Delete remote tracking branch
git push origin --delete feature/old-branch
```

#### Sync Issues

```bash
# If local develop is behind remote
git checkout develop
git pull origin develop

# If feature branch needs updating
git checkout feature/story-123-branch
git merge develop  # or git rebase develop
```

### Emergency Procedures

#### Accidental Commit to Wrong Branch

```bash
# Move commit to correct branch
git log --oneline -5  # Get commit hash
git checkout correct-branch
git cherry-pick [commit-hash]
git checkout wrong-branch
git reset --hard HEAD~1  # Remove commit from wrong branch
```

#### Corrupted Repository

```bash
# Check repository integrity
git fsck --full

# If corrupted, re-clone
cd ..
git clone [repository-url] cfgms-new
cd cfgms-new
# Copy any uncommitted work from old directory
```

---

## Automated Workflow

For automated Git workflow that enforces these standards:

- **`/story-start`** - Creates feature branch with validation
- **`/story-commit`** - Creates commits with proper validation
- **`/story-complete`** - Creates PR and manages cleanup

These slash commands ensure adherence to the Git workflow while providing intelligent automation.
