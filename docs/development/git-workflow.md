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

- `main`: Requires PR review, status checks, no direct pushes
- `develop`: Requires PR review, allows fast-forward merges
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

**✅ CORRECT (Feature Branch Workflow):**

```bash
# ALWAYS create feature branch first
git checkout develop
git checkout -b feature/epic-4-unified-directory
git push origin feature/epic-4-unified-directory

# Create PR: feature → develop (for development)
gh pr create --base develop --title "Epic 4: Unified Directory Management"

# After develop integration, create PR: develop → main (for release)
git checkout develop
git pull origin develop  # Ensure develop has latest
gh pr create --base main --title "Release: Epic 4 to Production"
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

#### GitHub Repository Settings

To prevent accidental branch deletion:

1. Go to GitHub → Repository → Settings → General
2. Under "Pull Requests" section:
   - ✅ Enable "Allow merge commits"
   - ❌ Disable "Automatically delete head branches"
3. For develop branch specifically:
   - ✅ Enable branch protection
   - ✅ Require pull request reviews
   - ❌ Never allow deletion

#### Safe Merge Commands

```bash
# Merge PR without deleting source branch
gh pr merge [PR_NUMBER] --merge --no-delete-branch

# Or use squash merge (preferred for clean history)
gh pr merge [PR_NUMBER] --squash --no-delete-branch
```

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

### Development to Production

```bash
# 1. Feature work (on feature branches)
git checkout -b feature/story-123-new-feature
# ... development work ...
gh pr create --base develop  # Merge to develop

# 2. Release preparation (develop → main)
git checkout develop
git pull origin develop
gh pr create --base main --title "Release: v0.4.7.0"

# 3. After main merge, tag release
git checkout main
git pull origin main
git tag v0.4.7.0
git push origin v0.4.7.0
```

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
