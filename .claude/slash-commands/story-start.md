---
name: story-start
description: Start a new story with all mandatory pre-flight checks and roadmap auto-detection
parameters:
  - name: story_number
    description: The story/issue number (optional - will auto-detect next story if omitted)
    required: false
  - name: description
    description: Brief description for branch name (optional if auto-detecting)
    required: false
---

# Story Start Command

This command ensures all mandatory pre-flight checks pass before starting development and can automatically detect the next story from the roadmap.

## Auto-Detection Logic

When run without parameters (`/story-start`), the command will:

1. **Parse Roadmap**: Examine `docs/product/roadmap.md` for next uncompleted story
2. **Cross-Reference GitHub**: Use `gh project item-list` to check project status
3. **Find Candidates**: Look for stories marked as "Todo" or not yet "In Progress"
4. **Present Options**: If multiple candidates found, present selection menu

## Pre-Flight Checks (MANDATORY)

Before creating any branch, the command performs blocking validation:

1. **Clean Baseline Check**:
   ```bash
   make test
   ```
   - ❌ **BLOCKS** if ANY tests are failing
   - ❌ **BLOCKS** if security issues exist
   - ❌ **BLOCKS** if linting errors present
   - ✅ Only proceeds with 100% clean baseline

2. **Git Status Validation**:
   - Verifies on `develop` branch
   - Checks for uncommitted changes
   - Ensures local branch is up-to-date

## Branch Creation

After successful validation:

1. **Feature Branch Creation**:
   ```bash
   git checkout -b feature/story-[NUMBER]-[description]
   ```

2. **Branch Verification**:
   ```bash
   git branch --show-current  # Must show new feature branch
   ```

3. **GitHub Project Update**:
   ```bash
   gh project item-edit --field-id "Status" --value "In Progress"
   ```

## Roadmap Integration

### Pattern Recognition
The command searches for stories in this format:
```markdown
- [ ] **Story Name** (Issue #XXX) - [points] ✅ COMPLETED/🚧 IN PROGRESS/⏳ PENDING
```

### Auto-Detection Flow
```
1. Parse docs/product/roadmap.md
2. Find uncompleted stories: `- [ ]` prefix
3. Extract issue numbers: `(Issue #XXX)`
4. Cross-reference with GitHub project status
5. Present next logical story or selection menu
```

## Usage Examples

### Auto-Detection Mode
```bash
/story-start

# Output:
🔍 Analyzing roadmap for next story...
📋 Found next story from roadmap:
   Story #166: Logging Provider Migration and Standardization
   Epic: v0.5.0 Beta - Advanced Workflows & Core Readiness
   Status: Todo in GitHub Project
   Points: 8

🚦 Pre-flight checks:
   ✅ All tests passing
   ✅ Security scan clean
   ✅ On develop branch

✨ Proceed with Story #166? (y/n): y

🌟 Creating feature branch: feature/story-166-logging-migration
✅ Story #166 started successfully!
```

### Manual Mode (Legacy)
```bash
/story-start 165 logging-provider

# Same pre-flight checks, then creates:
# feature/story-165-logging-provider
```

## TodoWrite Integration

After successful branch creation, initializes TodoWrite with:

```markdown
- [pending] Implement Story #166: Logging Provider Migration
- [pending] Review acceptance criteria from GitHub issue
- [pending] Set up development environment for story
- [pending] Run tests frequently during development
- [in_progress] Begin story development following TDD approach
```

## Error Handling

### Pre-Flight Failures
```bash
❌ PRE-FLIGHT CHECK FAILED: Tests are failing

   Failed Tests:
   • pkg/logging/manager_test.go: TestManager_Race
   • features/controller/server_test.go: TestServer_Health

   🛠️ Action Required:
   1. Fix failing tests first
   2. Run: make test
   3. Retry: /story-start

   📋 ZERO TOLERANCE POLICY: Cannot start new work with failing tests
```

### Roadmap Parse Errors
```bash
⚠️ Could not parse roadmap automatically
   Falling back to manual story entry

   Please specify story number:
   /story-start [story-number] [description]
```

### GitHub Integration Errors
```bash
⚠️ GitHub CLI unavailable - manual project update required

   Created branch: feature/story-166-logging-migration
   📋 Manual action needed:
   1. Visit: https://github.com/orgs/cfg-is/projects/1
   2. Move issue #166 to "In Progress"
```

## Security Notes

- **No Secrets**: Command never exposes credentials or sensitive data
- **Validation Only**: Pre-flight checks are read-only operations
- **Branch Protection**: Respects Git branch protection rules
- **Safe Parsing**: Roadmap parsing uses safe text processing only

## Integration Points

- **GitHub CLI**: Used for project management integration
- **Roadmap Format**: Expects standard CFGMS roadmap.md format
- **Testing Framework**: Integrates with existing make test infrastructure
- **Branch Naming**: Follows established feature/story-[NUMBER]-[description] pattern

---

## Command Implementation Details

This command automates the critical first steps of the CFGMS development workflow while maintaining all mandatory quality gates and providing intelligent roadmap-driven story selection.