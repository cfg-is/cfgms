---
name: story-complete
description: Complete story with all mandatory gates and create PR
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
make test-complete
```
**FINAL COMPLETION GATE**: This is the ultimate validation before story completion.

**Includes**:
- ✅ Unit tests with race detection
- ✅ Code linting and quality checks
- ✅ License header validation
- ✅ Secret scanning (gitleaks + trufflehog)
- ✅ Architecture compliance checking
- ✅ Security scanning (Trivy, Nancy, gosec, staticcheck)
- ✅ **E2E Tests** (MQTT+QUIC integration + Docker deployment + comprehensive scenarios)

**Blocking Policy**:
- ❌ **BLOCKS** completion if ANY validation fails
- ❌ **DO NOT** update GitHub project status on failures
- ❌ **DO NOT** update roadmap on failures
- ❌ **DO NOT** create PR on failures
- ✅ Must achieve 100% success across all validation types

### 2. Documentation Review (BLOCKING)

**CRITICAL**: All internal tracking documents must be removed before PR creation.

**Automated Scan**:
```bash
# Scan for internal tracking patterns in docs/
git diff --name-only develop...HEAD -- docs/ | grep -iE '(status|summary|validation|report|review|sprint|milestone|story-[0-9]+)'
```

**Manual Review Checklist**:
- ❌ **REMOVE**: Internal progress tracking (e.g., DOCUMENTATION_REVIEW_STATUS.md)
- ❌ **REMOVE**: Sprint/milestone completion reports (e.g., v0.3.2-validation.md)
- ❌ **REMOVE**: Story-specific summaries (e.g., Story #166 Implementation Summary)
- ❌ **REMOVE**: Internal review notes not useful for contributors
- ✅ **KEEP**: Security audits (demonstrates due diligence for OSS)
- ✅ **KEEP**: Architecture decision records (ADRs)
- ✅ **KEEP**: Contributor-facing guides and documentation
- ✅ **KEEP**: Historical design documents (marked with "HISTORICAL DOCUMENT" header)

**Document Classification Decision Tree**:
```
Does this document help future contributors?
├─ YES → Keep (contributor-facing)
│  Examples:
│  • Development guides (getting-started.md)
│  • Architecture decisions (ADR-001-*.md)
│  • Security audits (shows due diligence)
│  • API documentation
│  • Module guides
│
└─ NO → Does it document completed work?
   ├─ YES → Remove (internal tracking)
   │  Examples:
   │  • Story completion summaries
   │  • Sprint validation reports
   │  • Progress tracking documents
   │  • Internal review notes
   │
   └─ NO → Keep but mark as historical
      Examples:
      • Old design documents (grpc-usage-analysis.md)
      • Deprecated architecture docs
```

**Files to Always Remove**:
1. **Progress Tracking**: `*-status.md`, `*-progress.md`
2. **Internal Reviews**: `INTERNAL_*.md`, `*_REVIEW_STATUS.md`
3. **Sprint Reports**: `v[0-9].*-validation.md`, `sprint-*.md`
4. **Story Summaries**: `story-*-summary.md`, `*-implementation-summary.md`
5. **Version-Specific Reports**: Not actual release notes (pre-v1.0 "releases" are internal)

**Transformation Strategy**:
- **Option 1**: Remove entirely (internal tracking with no technical value)
- **Option 2**: Rename and rewrite as contributor guide (has technical content)
  - Remove story references and completion checkboxes
  - Focus on "how to" rather than "what we did"
  - Add practical examples and best practices

**Validation Commands**:
```bash
# Find potentially problematic files
git ls-files docs/ | grep -iE '(validation|report|status|summary|review|sprint|milestone|story-[0-9]+)' | grep -v 'DOCUMENTATION_REVIEW_REPORT\|pr-review-methodology\|test_coverage_analysis\|remediation'

# Check for version-specific internal reports
git ls-files docs/ | grep -E 'v[0-9]+\.[0-9]+\.[0-9]+'

# Look for "Story #" references in docs (may indicate internal tracking)
git grep -l "Story #[0-9]" docs/ | grep -v DOCUMENTATION_REVIEW_REPORT.md
```

**Blocking Policy**:
- ❌ **BLOCKS** PR creation if internal tracking documents found
- ❌ **BLOCKS** PR creation if story-specific summaries present
- ❌ **BLOCKS** PR creation if sprint validation reports exist
- ℹ️ **WARNS** if version-specific files without proper context
- ✅ **PASSES** only when all internal documents cleaned

**Example Cleanup (Story #228)**:
```bash
# Removed:
❌ docs/DOCUMENTATION_REVIEW_STATUS.md (progress tracking)
❌ docs/INTERNAL_CONTENT_REVIEW.md (internal notes)
❌ docs/v0.3.2-validation.md (sprint validation)
❌ docs/releases/v0.2.0-release-notes.md (pre-release internal milestone)

# Transformed:
✅ logging-migration-summary.md → logging-architecture-guide.md
✅ logging-interface-injection-implementation-summary.md → logging-dependency-injection-guide.md

# Kept with context:
✅ docs/architecture/grpc-usage-analysis.md (added "HISTORICAL DOCUMENT" header)
✅ docs/security/audits/*.md (demonstrates security due diligence)
```

### 3. Story Completeness Check
```bash
gh issue view [story_number] --json body,title,state,assignees
```
- **Progress Analysis**: Verify all acceptance criteria met
- **Issue State**: Confirm issue is ready for completion
- **Assignment**: Validate story assignment and permissions

## Pull Request Creation

After successful validation, creates comprehensive PR:

### 0. Git Push to Remote (MANDATORY)

**CRITICAL**: All changes must be pushed to remote before creating PR.

**Push Sequence**:
```bash
# Ensure all changes are committed
git status --porcelain  # Should be empty

# Push current branch to remote
git push origin $(git branch --show-current)

# Verify push succeeded
if [ $? -ne 0 ]; then
  echo "❌ ERROR: Failed to push changes to remote"
  echo "   Cannot create PR until changes are pushed"
  exit 1
fi
```

**Error Handling**:
```bash
❌ PUSH FAILED: Unable to push changes to remote

   Reason: [error message from git]

   Required Actions:
   1. Review git push error
   2. Resolve any conflicts or issues
   3. Retry: git push origin $(git branch --show-current)
   4. Retry: /story-complete

   📋 PR CREATION BLOCKED: Cannot create PR with unpushed changes
```

### 1. Git Workflow Validation (MANDATORY)

**CRITICAL RULE**: All feature branches MUST create PRs to `develop` branch, NEVER to `main`.

**Branch Validation**:
```bash
# Check current branch and validate target
current_branch=$(git branch --show-current)
if [[ $current_branch == feature/* ]]; then
  target_branch="develop"  # ALWAYS develop for feature branches
else
  echo "ERROR: Can only complete stories from feature/* branches"
  exit 1
fi
```

**Git Workflow Rules**:
- ✅ **Feature branches** → `develop` (standard workflow)
- ✅ **Hotfix branches** → `main` (emergency only)
- ❌ **Feature to main**: BLOCKED - violates git workflow
- ❌ **Non-feature branches**: BLOCKED - must be on feature branch

**Automatic Base Correction**:
- If PR accidentally targets `main`, automatically change to `develop`
- Log warning about incorrect base branch
- Update PR with correct base before proceeding

### 2. Duplicate PR Detection & Smart Handling
```bash
gh pr list --head [current-branch] --state=open
```
**Automatic Behavior**:
- ✅ **IF no existing PR**: Creates new PR with full template targeting `develop`
- ✅ **IF existing PR found**: Automatically updates existing PR description and validates base is `develop`
- ✅ **Prevents** duplicate PR creation entirely
- ⚠️ **Base Branch Validation**: Ensures PR targets `develop`, not `main`
- ℹ️ **Informs** user which PR was updated with link

**Commands Used**:
```bash
# If existing PR found:
gh pr edit [pr-number] --body "[updated-template]" --base develop  # Enforce develop
# If no existing PR:
gh pr create --base develop --title "[title]" --body "[template]"  # ALWAYS develop
```

### 3. PR Template Generation
```bash
gh pr create --base develop --title "Implement Story #[NUMBER]: [title]" --body "[template]"
```

**Base Branch Policy**:
- 🎯 **Default**: `develop` (enforced for all feature branches)
- ⚠️ **Never**: `main` (blocked by validation)
- 📋 **Workflow**: Feature → Develop → Main (via release PRs)

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

### 4. Branch Context Analysis
- **Commit Analysis**: Reviews all commits on story branch
- **File Changes**: Identifies modified files and change scope
- **Breaking Changes**: Detects potential breaking changes
- **Test Coverage**: Analyzes test additions/modifications

## Project Management Integration

### 1. Roadmap Update (BEFORE PR Creation)

**CRITICAL**: Roadmap is updated as part of the story branch, not after PR creation.

Updates `docs/product/roadmap.md` in the story branch:
```markdown
# Before:
- [ ] **Logging Provider Migration** (Issue #166) - 8 points 🚧 IN PROGRESS

# After:
- [x] **Logging Provider Migration** (Issue #166) - 8 points ✅ COMPLETED
```

**Workflow**:
1. Update roadmap.md on story branch
2. Commit roadmap changes to story branch
3. Push story branch (includes roadmap update)
4. Create PR (includes both code and roadmap in single PR)
5. When PR merges, roadmap is atomically updated

**Benefits**:
- ✅ Single PR (no separate documentation PR)
- ✅ Roadmap only shows "complete" when work actually merges
- ✅ Atomic operation (everything or nothing)
- ✅ No premature "complete" status
- ✅ Fewer CI runs (no docs-only PR)

**Progress Tracking**:
- Updates epic completion percentage
- Moves story to completed section
- Updates milestone status if applicable

### 2. GitHub Project Update (AFTER PR Creation - Optional)

```bash
# Reference exact IDs from docs/github-cli-reference.md
gh project item-edit [project-id] --id [item-id] --field-id [status-field-id] --value "Done"
```

**Note**: This can be done manually after PR merge if preferred.

### 3. Feature Branch Cleanup
```bash
# After successful PR merge
git checkout develop
git pull origin develop  # Get merged changes (includes roadmap update)
git branch -D feature/story-[NUMBER]-[description]  # Clean up local branch
```

## Why Roadmap Updates Belong in Story Branch

**OLD Approach (Inefficient)**:
1. Create PR for story code
2. Create separate PR for roadmap documentation
3. Merge story PR
4. Merge documentation PR
5. **Problem**: Roadmap shows "complete" before story merges
6. **Problem**: Two PRs, two CI runs, extra overhead

**NEW Approach (Efficient)**:
1. Update roadmap in story branch before pushing
2. Commit roadmap changes to story branch
3. Create single PR with code + roadmap
4. Merge single PR
5. **Benefit**: Roadmap only complete when work merges (atomic)
6. **Benefit**: Single PR, single CI run, cleaner history

## Usage Examples

### Auto-Detection Mode
```bash
/story-complete

# Output:
🔍 Detecting story from branch: feature/story-166-logging-migration
📋 Found Story #166: Logging Provider Migration and Standardization

🧪 Running FINAL VALIDATION GATE...
   ✅ Tests: make test-complete passed (486 tests)
   ✅ Security: All scans clean
   ✅ Linting: 0 issues
   ✅ License headers: All files validated
   ✅ E2E Tests: MQTT+QUIC + Docker + Scenarios passed

📊 Story Completeness Check:
   ✅ All 8/8 acceptance criteria completed
   ✅ Issue ready for completion

🚀 Pushing changes to remote...
   ✅ Changes pushed successfully

📝 Updating roadmap on story branch...
   ✅ Roadmap updated: Story #166 marked complete
   ✅ Roadmap changes committed to story branch

🚀 Pushing changes to remote...
   ✅ Changes pushed successfully (includes roadmap update)

🚀 Creating Pull Request...
   ℹ️ Existing PR detected: #181
   ✅ PR updated: https://github.com/cfg-is/cfgms/pull/181

✨ Story #166 completed successfully!
   🔗 PR: https://github.com/cfg-is/cfgms/pull/182
   📊 Epic progress: 2/12 stories complete (17%)

💡 Roadmap update included in PR - will be applied when merged
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

### Duplicate PR Detection
```bash
⚠️ DUPLICATE PR DETECTED

   ✅ Story validation passed
   ⚠️ Found existing PR for this branch:
      🔗 PR #182: https://github.com/cfg-is/cfgms/pull/182

   📋 Available Actions:
   1. View existing PR: gh pr view 182
   2. Update existing PR description: gh pr edit 182
   3. Continue with existing PR (recommended)
   4. Close duplicate and create new (not recommended)

   💡 Tip: Use existing PR to avoid confusion
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

## Command Execution Flow

This command follows a strict execution sequence:

```bash
/story-complete

# Execution Order:
1. Run make test-complete (BLOCKING)
2. Documentation review (BLOCKING if internal tracking found)
3. Analyze story completeness (BLOCKING if <100%)
4. Update roadmap.md in current story branch (BLOCKING)
5. Commit roadmap changes to story branch
6. Push story branch to remote (includes roadmap update)
7. Validate git workflow (BLOCKING if feature→main)
8. Check for duplicate PRs (auto-update if exists)
9. Create or update PR (includes code + roadmap in single PR)
10. Update GitHub project status (optional)
```

Each step is blocking - failure prevents progression to next step.

**Key Change**: Roadmap update is now part of the story branch, creating a single atomic PR that includes both the work and the documentation update. This ensures the roadmap only shows "complete" when the PR actually merges.

### Documentation Review Error Example

```bash
❌ DOCUMENTATION REVIEW FAILED

   Internal tracking documents detected:
   • docs/story-228-implementation-summary.md
   • docs/PROGRESS_TRACKING.md
   • docs/v0.6.5-validation.md

   🛠️ Required Actions:
   1. Review each file using decision tree above
   2. Remove internal tracking documents
   3. Transform technical summaries into contributor guides
   4. Add historical headers to deprecated design docs
   5. Commit cleanup changes
   6. Retry: /story-complete

   📋 PR CREATION BLOCKED
   Cannot create PR with internal tracking documents
```
