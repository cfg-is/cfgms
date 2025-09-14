---
name: story-complete
description: Complete story with all mandatory gates and create PR
aliases: [pr-create]
parameters:
  - name: story_number
    description: Story number to complete (optional - auto-detects from branch)
    required: false
---

# Story Complete Command

This command handles the final validation and completion of a story, including PR creation and project management updates.

## Final Validation Gates (MANDATORY)

Before marking any story complete, runs comprehensive validation:

### 1. Complete Test Validation (BLOCKING)
```bash
make test-commit
```
**FINAL COMPLETION GATE**: This is the ultimate validation before story completion.

**Includes**:
- ✅ Unit tests with race detection
- ✅ Security scanning (Trivy, Nancy, gosec, staticcheck)
- ✅ Code linting and quality checks
- ✅ M365 integration testing (if credentials available)

**Blocking Policy**:
- ❌ **BLOCKS** completion if ANY validation fails
- ❌ **DO NOT** update GitHub project status on failures
- ❌ **DO NOT** update roadmap on failures
- ❌ **DO NOT** create PR on failures
- ✅ Must achieve 100% success across all validation types

### 2. Story Completeness Check
```bash
gh issue view [story_number] --json body,title,state,assignees
```
- **Progress Analysis**: Verify all acceptance criteria met
- **Issue State**: Confirm issue is ready for completion
- **Assignment**: Validate story assignment and permissions

## Pull Request Creation

After successful validation, creates comprehensive PR:

### 1. PR Template Generation
```bash
gh pr create --base develop --title "Implement Story #[NUMBER]: [title]" --body "[template]"
```

**Template includes**:
```markdown
## Summary
[Auto-generated from story title and description]

### Changes Made
- [Extracted from commit history since story branch creation]
- [Include any breaking changes detected]

### Story Progress
✅ All 8/8 acceptance criteria completed:
- [x] Migrate RBAC module to global logging
- [x] Migrate controller module to global logging
- [x] Migrate steward module to global logging
- [x] Add structured logging fields
- [x] Implement tenant isolation validation
- [x] Update logging configuration
- [x] Add comprehensive tests
- [x] Update documentation

### Test Results
✅ All tests passing (486 tests, 0 failures)
✅ Security scan clean (0 vulnerabilities)
✅ Linting passed (0 issues)
✅ M365 integration validated

### Security Review
✅ No hardcoded secrets or credentials
✅ SQL injection prevention maintained
✅ Input validation present for all new code
✅ Error handling without information disclosure
✅ Tenant isolation maintained throughout

🤖 Generated with [Claude Code](https://claude.ai/code)

Co-Authored-By: Claude <noreply@anthropic.com>
```

### 2. Branch Context Analysis
- **Commit Analysis**: Reviews all commits on story branch
- **File Changes**: Identifies modified files and change scope
- **Breaking Changes**: Detects potential breaking changes
- **Test Coverage**: Analyzes test additions/modifications

## Project Management Integration

After successful PR creation:

### 1. GitHub Project Update
```bash
# Reference exact IDs from docs/github-cli-reference.md
gh project item-edit [project-id] --id [item-id] --field-id [status-field-id] --value "Done"
```

### 2. Roadmap Update
Updates `docs/product/roadmap.md`:
```markdown
# Before:
- [ ] **Logging Provider Migration** (Issue #166) - 8 points 🚧 IN PROGRESS

# After:
- [x] **Logging Provider Migration** (Issue #166) - 8 points ✅ COMPLETED
```

**Progress Tracking**:
- Updates epic completion percentage
- Moves story to completed section
- Updates milestone status if applicable

### 3. Feature Branch Cleanup
```bash
# After successful PR merge
git checkout develop
git pull origin develop  # Get merged changes
git branch -D feature/story-[NUMBER]-[description]  # Clean up local branch
```

## Usage Examples

### Auto-Detection Mode
```bash
/story-complete

# Output:
🔍 Detecting story from branch: feature/story-166-logging-migration
📋 Found Story #166: Logging Provider Migration and Standardization

🧪 Running FINAL VALIDATION GATE...
   ✅ Tests: make test-commit passed (486 tests)
   ✅ Security: All scans clean
   ✅ Linting: 0 issues
   ✅ Integration: M365 tests passed

📊 Story Completeness Check:
   ✅ All 8/8 acceptance criteria completed
   ✅ Issue ready for completion

🚀 Creating Pull Request...
   ✅ PR created: https://github.com/cfg-is/cfgms/pull/182
   ✅ GitHub project updated to "Done"
   ✅ Roadmap updated: Story #166 marked complete

✨ Story #166 completed successfully!
   🔗 PR: https://github.com/cfg-is/cfgms/pull/182
   📊 Epic progress: 2/12 stories complete (17%)
```

### Manual Story Specification
```bash
/story-complete 166

# Same flow but uses specified story number
# Useful when branch naming doesn't match pattern
```

### Cross-Reference Mode
```bash
# On any branch, complete specific story
/story-complete 165

# Handles completion for different story than current branch
```

## Error Handling

### Validation Gate Failures
```bash
❌ FINAL VALIDATION GATE FAILED

   Test Failures:
   • pkg/logging/providers/timescale/plugin_test.go:89
   • features/controller/server_test.go:124

   🛠️ Required Actions:
   1. Fix ALL test failures
   2. Run: make test-commit
   3. Ensure 100% success
   4. Retry: /story-complete

   📋 STORY COMPLETION BLOCKED
   Cannot proceed until all validation passes
```

### Incomplete Story Detection
```bash
⚠️ STORY NOT READY FOR COMPLETION

   Story Progress: 6/8 acceptance criteria (75%)

   Remaining Requirements:
   - [ ] Update logging configuration documentation
   - [ ] Add comprehensive integration tests

   🎯 Recommended Actions:
   1. Complete remaining acceptance criteria
   2. Update issue checklist: https://github.com/cfg-is/cfgms/issues/166
   3. Retry when 100% complete

   💡 Use /story-commit to continue development
```

### GitHub Integration Errors
```bash
⚠️ PR Creation Warning

   ✅ Story validation passed
   ❌ GitHub CLI error: API rate limit exceeded

   📋 Manual Actions Required:
   1. Create PR manually: https://github.com/cfg-is/cfgms/compare/develop...feature/story-166-logging-migration
   2. Update project status: https://github.com/orgs/cfg-is/projects/1
   3. Update roadmap: docs/product/roadmap.md
```

## Smart Completeness Detection

### Acceptance Criteria Analysis
- **Pattern Recognition**: Detects various checklist formats
- **Progress Calculation**: Accurate completion percentage
- **Dependency Checking**: Validates prerequisite completion
- **Quality Gates**: Ensures all requirements met

### File Change Validation
- **Scope Verification**: Confirms changes align with story scope
- **Test Coverage**: Validates new code has corresponding tests
- **Documentation**: Checks for required documentation updates
- **Breaking Changes**: Identifies and documents breaking changes

## Security Integration

### Final Security Review
- **Complete Scan**: Full security validation before completion
- **Vulnerability Check**: Ensures no new security issues introduced
- **Compliance**: Validates security standards maintained
- **Documentation**: Security review documented in PR

### Audit Trail
- **Complete History**: Full story development history captured
- **Decision Points**: All validation decisions documented
- **Approval Chain**: PR approval workflow integration
- **Traceability**: Links between story, commits, and deployment

## Performance Optimizations

- **Parallel Operations**: Runs validation checks concurrently
- **Smart Caching**: Reuses validation results when possible
- **Efficient APIs**: Minimal GitHub API calls with batching
- **Fast Cleanup**: Optimized branch cleanup operations

---

## Aliases and Variations

This command supports multiple invocation patterns:

```bash
/story-complete     # Standard completion
/pr-create          # Alias - same functionality
/story-complete 166 # Manual story specification
/pr-create 166      # Alias with manual story
```

All variations provide identical functionality with natural command naming for different user preferences.