---
name: dev-status
description: Quick development environment status check and current story tracking
parameters: []
---

# Development Status Command

This command provides a quick overview of your current development environment status, active work, and any blocking issues that need attention.

## Status Information Provided

### 1. Git Repository Status
```bash
# Current branch and state
git branch --show-current
git status --porcelain
git log --oneline -3
```

**Information Displayed**:
- **Current Branch**: Which branch you're actively working on
- **Working Directory**: Uncommitted changes status
- **Recent Commits**: Last 3 commits for context
- **Branch Relationship**: Ahead/behind status with develop/main

### 2. Development Environment Health
```bash
# Quick test status
make test 2>/dev/null | tail -5

# Security scan status (quick check)
make security-check 2>/dev/null | grep -E "(✅|❌|⚠️)"
```

**Health Indicators**:
- **Test Status**: Are tests currently passing?
- **Security Status**: Any critical security issues?
- **Build Status**: Can the project build successfully?
- **Lint Status**: Any code quality issues?

### 3. Active Story Detection
```bash
# Extract story from branch name
branch=$(git branch --show-current)
story_number=$(echo "$branch" | grep -o 'story-[0-9]\+' | grep -o '[0-9]\+')

# Get story status from GitHub
gh issue view $story_number --json title,state,assignees 2>/dev/null
```

**Story Information**:
- **Current Story**: Auto-detected from branch name
- **Story Title**: Full story description
- **GitHub Status**: Issue state and assignment
- **Progress Estimate**: Based on recent commit activity

### 4. Blocking Issues Detection
```bash
# Common blocking issues
git status | grep -E "(conflict|merge)" || echo "No merge conflicts"
make test | grep -c "FAIL" || echo "0"
docker ps | grep -c "cfgms" || echo "No CFGMS containers"
```

**Blocking Issues**:
- **Merge Conflicts**: Unresolved conflicts blocking development
- **Test Failures**: Failing tests that need attention
- **Environment Issues**: Missing dependencies or configuration
- **Docker Status**: Integration test environment status

## Usage Examples

### Clean Development State
```bash
/dev-status

# Output:
📊 CFGMS Development Status Report
==================================

🌿 Git Repository:
   Current Branch: feature/story-166-logging-migration
   Status: 3 files modified, ready to commit
   Last Commit: Migrate RBAC module to global logging (2 minutes ago)
   Branch Status: 7 commits ahead of develop

🚦 Environment Health:
   ✅ Tests: 486 passed, 0 failed (Last run: 5 minutes ago)
   ✅ Security: All scans clean (Last run: 8 minutes ago)
   ✅ Build: Successful (All binaries compile)
   ✅ Lint: 0 issues (Code quality maintained)

📋 Active Story:
   Story #166: Logging Provider Migration and Standardization
   Status: In Progress (GitHub)
   Assignee: Current user
   Progress: ~60% (estimated from commits)

🎯 Development Focus:
   • Continue controller module migration
   • Add tenant isolation tests
   • Update documentation

⚡ Ready for Development: All systems green!
```

### Issues Detected
```bash
/dev-status

# Output:
📊 CFGMS Development Status Report
==================================

🌿 Git Repository:
   Current Branch: feature/story-165-broken-tests
   Status: 2 files modified, 1 untracked
   Last Commit: WIP: Fix logging race condition (15 minutes ago)
   Branch Status: 3 commits ahead of develop

🚦 Environment Health:
   ❌ Tests: 2 failed, 484 passed (Last run: 2 minutes ago)
      • pkg/logging/manager_test.go:124 - race condition
      • features/controller/server_test.go:89 - timeout
   ⚠️  Security: 1 medium issue found
      • gosec: Potential file traversal in config loader
   ✅ Build: Successful
   ✅ Lint: 0 issues

📋 Active Story:
   Story #165: Global Logging Provider Foundation
   Status: In Progress (GitHub)
   Progress: ~40% (estimated from commits)

🚨 BLOCKING ISSUES DETECTED:
   Priority 1: Fix failing tests before continuing
   Priority 2: Address security concern in config loader

🛠️  Recommended Actions:
   1. Run: make test to see detailed test failures
   2. Fix race condition in manager_test.go
   3. Address server timeout in server_test.go
   4. Run: make security-gosec for security details
   5. Commit fixes: /story-commit

⚠️  Development Blocked: Resolve issues before proceeding
```

### Off-Story Development
```bash
/dev-status

# Output (when on main/develop or non-story branch):
📊 CFGMS Development Status Report
==================================

🌿 Git Repository:
   Current Branch: develop
   Status: Clean working directory
   Last Commit: Merge pull request #181 (1 hour ago)
   Branch Status: Up to date with origin/develop

🚦 Environment Health:
   ✅ Tests: 486 passed, 0 failed
   ✅ Security: All scans clean
   ✅ Build: Successful
   ✅ Lint: 0 issues

📋 Story Status:
   ⚠️  No active story detected (not on feature branch)

🎯 Next Actions:
   • Start new story: /story-start
   • Check roadmap: docs/product/roadmap.md
   • Review GitHub project: https://github.com/orgs/cfg-is/projects/1

✨ Ready to start new work!
```

## Advanced Status Information

### Docker Integration Status
When Docker services are available:
```markdown
🐳 Docker Environment:
   PostgreSQL: ✅ Running (localhost:5433)
   Gitea: ✅ Running (localhost:3001)
   TimescaleDB: ✅ Running (localhost:5434)

   Integration Tests: ✅ Available
   Storage Providers: ✅ Fully testable
```

### M365 Integration Status
When M365 credentials are configured:
```markdown
🌐 M365 Integration:
   Credentials: ✅ Available (.env.local)
   Test Status: ✅ Last run successful (30 minutes ago)
   API Access: ✅ Connected to tenant

   Integration Tests: ✅ Fully functional
```

### Performance Metrics
Quick performance indicators:
```markdown
⚡ Performance Metrics:
   Test Runtime: 2.3s (last run)
   Build Time: 45s (all binaries)
   Security Scan: 12s (all tools)

   Trend: ✅ Performance stable
```

## Branch Intelligence

### Feature Branch Analysis
```markdown
📊 Branch Analysis:
   Story Branch: feature/story-166-logging-migration
   Created: 3 days ago
   Commits: 7 commits
   Files Changed: 23 files

   Development Velocity: ~2.3 commits/day
   Estimated Completion: 2-3 days remaining
```

### Branch Relationship Status
```markdown
🔀 Branch Status:
   Ahead of develop: 7 commits
   Behind develop: 0 commits
   Merge Conflicts: None detected

   Sync Status: ✅ Up to date with base branch
```

## Error Handling

### Git Repository Issues
```bash
❌ Git Repository Error

   Issue: Not in a Git repository or corrupted .git

   Solutions:
   1. Ensure you're in the CFGMS project directory
   2. Check: ls -la .git
   3. Re-clone if repository is corrupted
```

### GitHub Access Issues
```bash
⚠️  GitHub Access Limited

   Issue: GitHub CLI not authenticated or rate limited

   Story detection unavailable - showing local information only

   Solutions:
   1. Authenticate: gh auth login
   2. Check rate limit: gh api rate_limit
   3. Wait for rate limit reset
```

### Environment Issues
```bash
⚠️  Environment Incomplete

   Missing Tools:
   • make: Required for build and test operations
   • golangci-lint: Required for code quality checks
   • docker: Required for integration testing

   Installation:
   • make: Install via system package manager
   • golangci-lint: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
   • docker: Follow Docker installation guide
```

## Quick Action Suggestions

### Based on Status
The command provides contextual suggestions:

- **Clean State**: Suggests starting new story or continuing current work
- **Test Failures**: Provides specific commands to fix issues
- **Security Issues**: Points to remediation commands
- **Outdated Branch**: Suggests sync with develop
- **Merge Conflicts**: Provides resolution guidance

### Workflow Integration
```markdown
🎯 Suggested Workflow:
   Current: Development blocked by test failures
   Next: Fix tests → /story-commit → continue development

   Commands:
   1. make test (see detailed failures)
   2. Fix failing tests
   3. /story-commit "Fix race conditions"
   4. Continue story development
```

---

## Integration Points

- **Git**: Repository status and branch information
- **GitHub CLI**: Issue and project status
- **Make System**: Test, build, and security status
- **Docker**: Integration environment status
- **CFGMS Workflow**: Story tracking and development guidance

This command serves as a comprehensive development dashboard, providing all the information needed to understand current work status and next actions.