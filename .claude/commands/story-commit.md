---
name: story-commit
description: Commit changes with all mandatory validation checks and progress tracking
parameters:
  - name: message
    description: The commit message (optional - will be generated if omitted)
    required: false
  - name: story_number
    description: Story number for progress tracking (optional - auto-detects from branch)
    required: false
---

# Story Commit Command

This command performs all mandatory validation checks before committing and provides intelligent progress tracking against GitHub issues.

## Mandatory Validation Sequence

Before any commit is created, the command runs blocking validation:

### 1. Test Validation (BLOCKING)
```bash
make test
```
- ❌ **BLOCKS** commit if ANY tests fail
- ✅ Must achieve 100% test success
- **ZERO TOLERANCE POLICY**: Fix all failures first

### 2. Linting Validation (BLOCKING)
```bash
make lint
```
- ❌ **BLOCKS** commit if linting errors exist
- ✅ Must meet code quality standards
- **CONSISTENT QUALITY**: Maintains codebase standards

### 3. Secret Scanning (BLOCKING)
```bash
make security-precommit
```
- ❌ **BLOCKS** commit if secrets detected in staged files
- ✅ Scans ONLY staged files (fast, ~1-2 seconds)
- **TWO-LAYER PROTECTION**: gitleaks (patterns) + truffleHog (verification)
- **PREVENTS CREDENTIAL LEAKS**: Catches secrets BEFORE they enter git history

### 4. Architecture Compliance (BLOCKING) - NEW!
```bash
make check-architecture
```
- ❌ **BLOCKS** commit if central provider violations found
- ✅ Ensures no duplicate implementations of cross-cutting concerns
- **PREVENTS TECH DEBT**: Catches reinvention of central providers early
- **What it checks**:
  - TLS/crypto usage outside `pkg/cert/`
  - Storage implementations outside `pkg/storage/`
  - Logging implementations outside `pkg/logging/`
  - Notification implementations outside `pkg/notifications/`

**Why This Matters**:
- Prevents bugs like the dual-CA issue (separate CAs causing mTLS failures)
- Maintains architectural consistency across the codebase
- Catches problems before code review
- Guides developers to correct patterns immediately

### 5. Security Validation (BLOCKING)
```bash
make security-scan
```
- ❌ **BLOCKS** commit if critical/high vulnerabilities found
- ✅ Must pass all security tools (Trivy, Nancy, gosec, staticcheck)
- **PRODUCTION GATES**: Critical issues prevent deployment

## Story Progress Tracking (Enhanced Feature)

After successful validation, the command provides intelligent progress analysis:

### GitHub Issue Analysis
1. **Auto-Detect Story**: Extract story number from branch name (`feature/story-166-*`)
2. **Fetch Issue Details**: `gh issue view [story_number] --json body,title,state`
3. **Parse Acceptance Criteria**: Extract checklist items from issue body
4. **Calculate Progress**: Compare completed work against total requirements

### Progress Report Generation
```bash
✅ Commit successful: "Migrate RBAC module to global logging provider"

## Story Progress: Issue #166 - Logging Provider Migration

### 🎯 Completed in this commit:
- ✅ Migrated RBAC module to global logging (pkg/rbac/)
- ✅ Added structured logging fields (tenant_id, session_id)
- ✅ Updated error handling with context logging

### ⏳ Remaining work (from GitHub issue):
- ⬜ Migrate controller module (3 files: server.go, routes.go, middleware.go)
- ⬜ Migrate steward module (5 files: main.go, health.go, config.go, handlers.go, client.go)
- ⬜ Add tenant isolation validation tests
- ⬜ Update logging configuration documentation

Progress: 40% complete (3/8 acceptance criteria)

💡 Smart Recommendation: Continue development - significant work remains
⚡ Next Focus: Controller module migration (estimated 2-3 commits)
```

### Smart Recommendations
- **< 50% complete**: "Continue development - significant work remains"
- **50-89% complete**: "Making good progress! Focus on [next major item]"
- **90-99% complete**: "Almost done! Consider final testing and documentation"
- **100% complete**: "🎉 Ready for completion! Run `/story-complete`"

## Commit Message Intelligence

### Auto-Generated Messages
When no message provided, generates contextual commit message:

```bash
/story-commit

# Analyzes git diff and generates:
"Implement RBAC logging migration for Story #166

- Migrate pkg/rbac/ to global logging provider
- Add structured logging fields (tenant_id, session_id, component)
- Update error handling with proper context propagation
- Ensure tenant isolation in all log entries

Progress: 3/8 acceptance criteria complete

Basic Security Review: No hardcoded secrets, proper error handling,
input validation maintained for all logging calls"
```

### Manual Message Override
```bash
/story-commit "Custom commit message describing specific changes"
```

## Acceptance Criteria Parsing

The command intelligently parses GitHub issue bodies for:

### Standard Patterns
- `- [ ] Task description` (uncompleted)
- `- [x] Task description` (completed)
- `**Acceptance Criteria:**` sections
- `### Requirements` sections
- Numbered lists: `1. Requirement`

### Progress Calculation
```
Total Criteria: 8
Completed: 3
Remaining: 5
Progress: 37.5% → displayed as 38%
```

## Usage Examples

### Auto-Detection Mode
```bash
/story-commit

# Output:
🧪 Running mandatory validation checks...
   ✅ Tests: 486 passed, 0 failed
   ✅ Linting: 0 issues found
   ✅ Secret Scanning: No secrets in staged files
   ✅ Architecture: No central provider violations
   ✅ Security: All scans clean

📝 Auto-generating commit message...
📊 Analyzing progress for Story #166...

✅ Commit created successfully!
[Progress report displayed]
```

### Custom Message Mode
```bash
/story-commit "Fix race condition in logging subscriber"

# Same validation + progress tracking
# Uses custom message instead of auto-generated
```

### Cross-Story Detection
```bash
# On branch: feature/story-166-logging-migration
/story-commit

# Auto-detects Story #166 from branch name
# No manual story number needed
```

## Error Handling

### Validation Failures
```bash
❌ VALIDATION FAILED: Tests are failing

   Failed Tests (2):
   • pkg/logging/manager_test.go:124 - TestManager_Subscribe_Race
   • pkg/rbac/roles_test.go:89 - TestRole_Inheritance

   🛠️ Required Actions:
   1. Fix failing tests
   2. Run: make test
   3. Retry: /story-commit

   📋 COMMIT BLOCKED: Zero tolerance for failing tests
```

### GitHub Integration Issues
```bash
⚠️ Could not fetch GitHub issue #166
   Reason: GitHub CLI not authenticated or network issue

✅ Commit successful: [commit hash]

📋 Manual Progress Tracking:
   • Visit: https://github.com/cfg-is/cfgms/issues/166
   • Review acceptance criteria manually
   • Estimate remaining work before /story-complete
```

### Branch Context Issues
```bash
⚠️ Could not detect story number from branch: main

✅ Commit successful: [commit hash]

💡 For progress tracking on story branches:
   1. Use format: feature/story-[NUMBER]-[description]
   2. Or specify: /story-commit "message" 166
```

## Security Integration

### Security Review Auto-Addition
Every commit message automatically includes security review summary:

```
Basic Security Review: No hardcoded secrets, SQL injection prevention
maintained, input validation present, proper error handling without
information disclosure
```

### Security Scan Integration
- **Pre-commit**: Runs full security scan before commit
- **Results**: Security scan results influence commit decision
- **Documentation**: Security status documented in commit

## Performance Optimizations

- **Parallel Execution**: Runs test, security, and lint checks concurrently where possible
- **Smart Caching**: Leverages existing make targets with caching
- **GitHub API**: Efficient single API call for issue details
- **Progress Persistence**: Caches issue parsing between commits

---

## Integration Points

- **GitHub CLI**: Issue fetching and project management
- **Make System**: All validation through existing make targets
- **Git Integration**: Branch detection and commit creation
- **TodoWrite**: Progress tracking integration
- **CLAUDE.md**: Enforces mandatory development checklist