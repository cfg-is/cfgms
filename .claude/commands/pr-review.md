---
name: pr-review
description: Structured PR review following mandatory CFGMS methodology with fresh context
parameters:
  - name: pr_number
    description: Pull request number to review (optional - auto-starts if 1 PR, shows menu if multiple)
    required: false
---

# PR Review Command

This command executes the comprehensive 5-phase PR review methodology required by CFGMS development workflow, ensuring objective and thorough code review with fresh context.

## Interactive PR Selection (Optional Mode)

**ENHANCEMENT**: When run without a PR number, provides interactive selection menu. **Auto-starts review if only one PR exists.**

**PR Discovery Flow**:
```bash
# When /pr-review is called without arguments:
/pr-review

# 1. Fetch all open PRs
gh pr list --state=open --json number,title,author,headRefName,isDraft --limit 20

# 2. Check count and auto-start if only one PR
pr_count=$(gh pr list --state=open --json number --jq 'length')
if [ "$pr_count" -eq 1 ]; then
  pr_number=$(gh pr list --state=open --json number --jq '.[0].number')
  echo "📋 Found 1 open pull request"
  echo ""
  echo "✅ Auto-selecting PR #$pr_number for review..."
  echo ""
  # Proceed directly to review (skip selection menu)
  # Continue to git sync and review phases
elif [ "$pr_count" -eq 0 ]; then
  echo "⚠️ No open pull requests found"
  exit 0
fi

# 3. Display selection menu (only if multiple PRs)
echo "📋 Open Pull Requests:"
echo ""
echo "a) PR #218: Story #214: Controller Health Monitoring & Alerting"
echo "   Author: jrdnr | Branch: feature/story-214-controller-health-monitoring"
echo ""
echo "b) PR #217: Story #213: Endpoint Performance Monitoring"
echo "   Author: jrdnr | Branch: feature/story-213-endpoint-monitoring"
echo ""
echo "c) PR #216: Fix logging integration tests"
echo "   Author: jrdnr | Branch: fix/logging-tests"
echo ""
echo "d) [List more PRs if available]"
echo ""
echo "Select PR to review (a-z), or enter PR number directly:"
echo "Or type 'cancel' to exit"

# 3. Process user selection
# - Letter selection: Map to corresponding PR number
# - Number entry: Use PR number directly
# - 'cancel': Exit without reviewing

# 4. Proceed with selected PR using normal review flow
```

**Selection Behavior**:
- **Letter options (a-z)**: Quick selection from list (supports up to 26 PRs)
- **Direct number**: Enter PR number directly (e.g., "218")
- **Cancel**: Type 'cancel' or 'exit' to abort
- **Invalid input**: Re-prompt with error message

**Display Priority**:
1. Show non-draft PRs first
2. Sort by PR number (newest first)
3. Indicate draft PRs with `[DRAFT]` tag
4. Show author and branch name for context

**Output Example**:
```bash
/pr-review

# Output:
📋 Discovering open pull requests...

Found 4 open PRs:

a) PR #218: Story #214: Controller Health Monitoring & Alerting (8 points)
   👤 Author: jrdnr
   🌿 Branch: feature/story-214-controller-health-monitoring
   📊 Status: Ready for review

b) PR #217: Story #213: Endpoint Performance Monitoring (13 points)
   👤 Author: jrdnr
   🌿 Branch: feature/story-213-endpoint-monitoring
   📊 Status: Ready for review

c) PR #216: Fix logging integration tests
   👤 Author: jrdnr
   🌿 Branch: fix/logging-tests
   📊 Status: Ready for review

d) PR #215: Update documentation for v0.6.0 [DRAFT]
   👤 Author: jrdnr
   🌿 Branch: docs/v0.6.0-updates
   📊 Status: Draft

Select a PR to review:
• Enter letter (a-d) for quick selection
• Enter PR number directly (e.g., 218)
• Type 'cancel' to exit

Your choice:
```

**Error Handling**:
```bash
# No open PRs found
📋 Discovering open pull requests...

⚠️ No open pull requests found

   The repository has no PRs awaiting review.

   💡 Tip: Use '/pr-review [number]' to review a specific closed PR

# Invalid selection
❌ Invalid selection: 'x'

   Please enter:
   • A valid letter (a-d)
   • A PR number (e.g., 218)
   • 'cancel' to exit

Your choice:
```

## Pre-Review Git Synchronization (MANDATORY)

**CRITICAL**: After PR selection, ensure git branch is fully synchronized.

**Git Sync Sequence**:
```bash
# 1. Check for uncommitted changes
if [ -n "$(git status --porcelain)" ]; then
  echo "⚠️ WARNING: Uncommitted changes detected"
  echo "   Recommendation: Commit or stash changes before reviewing"
  echo ""
  git status
  echo ""
fi

# 2. Fetch latest from remote
git fetch origin

# 3. Check if local branch is behind remote
current_branch=$(git branch --show-current)
local_commit=$(git rev-parse HEAD)
remote_commit=$(git rev-parse origin/$current_branch 2>/dev/null || echo "")

if [ -n "$remote_commit" ] && [ "$local_commit" != "$remote_commit" ]; then
  echo "⚠️ WARNING: Local branch is out of sync with remote"
  echo "   Local:  $local_commit"
  echo "   Remote: $remote_commit"
  echo ""
  echo "   Recommended actions:"
  echo "   1. If behind: git pull origin $current_branch"
  echo "   2. If ahead: git push origin $current_branch"
  echo "   3. If diverged: Review and merge/rebase as needed"
  echo ""
fi

# 4. Push any unpushed commits (if on feature branch)
if [[ $current_branch == feature/* ]]; then
  unpushed=$(git log origin/$current_branch..HEAD --oneline 2>/dev/null | wc -l)
  if [ "$unpushed" -gt 0 ]; then
    echo "📤 Found $unpushed unpushed commit(s)"
    echo "   Pushing to remote before review..."
    git push origin $current_branch
    if [ $? -eq 0 ]; then
      echo "   ✅ Successfully pushed to remote"
    else
      echo "   ⚠️ Push failed - review will continue but may not reflect latest code"
    fi
    echo ""
  fi
fi
```

**Why This Matters**:
- Ensures PR reflects the actual code being reviewed
- Prevents review of outdated code
- Catches situations where work was done but not pushed
- Helps maintain clean git history

## Fresh Context Initialization

**CRITICAL**: After git sync, this command clears all conversation context to ensure objectivity and prevent development bias from affecting the review.

**Execution Flow**:
1. **Git Sync**: Ensure local branch is synchronized with remote
2. **Clear Context**: Automatically runs `/clear` to eliminate development history
3. **Fresh Review**: Begins review with no prior context or assumptions
4. **Objective Analysis**: Reviews code purely based on what's presented in the PR
5. **Structured Methodology**: Follows all 5 review phases systematically

## Review Methodology

Follows the **Structured Review Methodology** from CLAUDE.md with fresh context to ensure objectivity and catch issues missed during development.

### Phase 1: PR Overview Assessment

**Objective**: Analyze PR scope, purpose, and completeness

**Execution**:
```bash
gh pr view [pr_number] --json title,body,baseRefName,headRefName,state,author
```

**Git Workflow Validation (CRITICAL)**:

**MANDATORY CHECK**: Validate branch workflow before proceeding with review.

```bash
# Extract branch names
base_branch=$(gh pr view [pr_number] --json baseRefName -q .baseRefName)
head_branch=$(gh pr view [pr_number] --json headRefName -q .headRefName)

# Validate workflow
if [[ $head_branch == feature/* ]] && [[ $base_branch == "main" ]]; then
  echo "❌ CRITICAL ERROR: Git Workflow Violation"
  echo ""
  echo "   Feature branch attempting to merge to main directly"
  echo "   Head: $head_branch"
  echo "   Base: $base_branch"
  echo ""
  echo "   CFGMS Git Workflow:"
  echo "   ✅ Feature branches → develop (required)"
  echo "   ✅ Develop → main (release PRs only)"
  echo "   ❌ Feature → main (BLOCKED)"
  echo ""
  echo "   Required Actions:"
  echo "   1. Close this PR or change base to develop:"
  echo "      gh pr edit [pr_number] --base develop"
  echo "   2. Follow proper git workflow for all future PRs"
  echo ""
  echo "   ⛔ REVIEW BLOCKED - Cannot proceed with workflow violation"
  exit 1
fi
```

**Branch Workflow Rules**:
- ✅ `feature/*` → `develop` (standard development)
- ✅ `hotfix/*` → `main` (emergency fixes only)
- ✅ `develop` → `main` (release PRs)
- ❌ `feature/*` → `main` (BLOCKED - workflow violation)

**Analysis Framework**:
- **Git Workflow**: Is the PR targeting the correct base branch?
- Does the PR clearly state its purpose and scope?
- Are breaking changes properly documented?
- Is the security review status clear?
- Are test results validated and documented?
- Is the PR title descriptive and follows conventions?

**Output Example**:
```markdown
## Phase 1: PR Overview Assessment ✅

**PR #182**: Implement Story #166: Logging Provider Migration and Standardization
- **Scope**: Clear - migrates all modules to global logging provider
- **Purpose**: Well-defined with specific acceptance criteria listed
- **Breaking Changes**: None documented (verified)
- **Security Status**: ✅ Basic security review completed
- **Test Documentation**: ✅ All validation results included

**Assessment**: PR overview is comprehensive and complete
```

### Phase 2: Security & Code Quality Review

**Objective**: Comprehensive security and code quality analysis

**Security Analysis (CRITICAL)**:
- Authentication/Authorization bypass potential
- Input validation and injection prevention
- Cryptographic implementation correctness
- Information disclosure risks
- CFGMS-specific tenant isolation
- Certificate and mTLS validation

**Code Quality Analysis**:
- Go best practices and idioms
- Error handling completeness
- Resource management (defer, cleanup)
- Race condition potential
- Performance implications
- Interface design and dependency injection

**Analysis Tools**:
```bash
# Security pattern analysis
gh pr diff [pr_number] | grep -E "(password|secret|token|auth)" || echo "No obvious security patterns"

# Code quality checks
gh pr view [pr_number] --json files | jq '.files[].filename' | head -10
```

**Output Example**:
```markdown
## Phase 2: Security & Code Quality Review ✅

### Security Analysis:
- ✅ **Input Validation**: All logging calls properly sanitized
- ✅ **Information Disclosure**: No sensitive data in log messages
- ✅ **Tenant Isolation**: tenant_id properly included in all log entries
- ✅ **Error Handling**: Secure error patterns maintained
- ⚠️  **Minor**: Consider structured errors for logging failures

### Code Quality:
- ✅ **Go Idioms**: Proper error handling patterns
- ✅ **Resource Management**: Appropriate defer usage for cleanup
- ✅ **Interface Design**: Consistent with CFGMS patterns
- ✅ **Performance**: No obvious performance regressions

**Overall**: High code quality with excellent security practices
```

### Phase 3: Testing & Validation Review

**Objective**: Validate testing approach and coverage

**Testing Validation**:
- Are tests testing actual functionality vs mocks?
- Is error path testing comprehensive?
- Are integration tests covering component interactions?
- Is race condition testing adequate?
- Are security edge cases tested?

**Test Quality Assessment**:
- Table-driven test patterns used correctly?
- Test data realistic and comprehensive?
- Cleanup and resource management in tests?
- Performance/benchmark testing where needed?

**Analysis Commands**:
```bash
# Identify test files in PR
gh pr diff [pr_number] --name-only | grep "_test.go"

# Check for test quality patterns
gh pr diff [pr_number] | grep -E "(testify|assert|require|t\.Run)" | wc -l
```

**Output Example**:
```markdown
## Phase 3: Testing & Validation Review ✅

### Test Coverage:
- ✅ **Real Components**: Tests use actual logging providers, not mocks
- ✅ **Error Paths**: Comprehensive error condition testing
- ✅ **Integration**: Cross-component interaction tests included
- ✅ **Race Conditions**: Proper concurrent testing with -race flag

### Test Quality:
- ✅ **Table-Driven**: Appropriate use of test tables for logging scenarios
- ✅ **Cleanup**: Proper test cleanup and resource management
- ✅ **Realistic Data**: Tests use realistic log entry patterns
- ✅ **Performance**: Benchmarks for logging performance included

**Added Tests**: 127 new test cases across 8 test files
**Test Pattern**: Excellent adherence to CFGMS testing standards
```

### Phase 4: Documentation & Integration Review

**Objective**: Assess documentation and system integration

**Documentation Analysis**:
- Are exported functions/types properly documented?
- Is architectural context explained?
- Are breaking changes clearly documented?
- Is usage guidance provided?

**Integration Analysis**:
- Will this change affect existing components?
- Are database migrations handled properly?
- Are configuration changes backward compatible?
- Is deployment impact assessed?

**Output Example**:
```markdown
## Phase 4: Documentation & Integration Review ✅

### Documentation:
- ✅ **API Documentation**: All exported functions properly documented
- ✅ **Architecture Context**: Clear explanation of logging provider migration
- ✅ **Usage Guidance**: Examples provided for new logging patterns
- ✅ **Breaking Changes**: None identified

### Integration Impact:
- ✅ **Component Compatibility**: Backward compatible with all modules
- ✅ **Configuration**: Uses existing global storage provider pattern
- ✅ **Deployment**: Zero-downtime deployment possible
- ✅ **Database**: No schema changes required

**Integration Risk**: LOW - Well-isolated changes with clear interfaces
```

### Phase 5: Final Approval Checklist

**Objective**: Comprehensive approval checklist validation

**Required Validations**:
- [ ] All security concerns addressed or documented as accepted risks
- [ ] Code follows CFGMS architecture patterns and Go best practices
- [ ] Tests provide adequate coverage of new functionality
- [ ] Breaking changes are properly documented and justified
- [ ] Performance impact assessed for production workloads
- [ ] Documentation updated for any API/interface changes
- [ ] CI/CD validation passes (tests, security scans, linting)
- [ ] Deployment impact reviewed and mitigation planned

**Output Example**:
```markdown
## Phase 5: Final Approval Checklist ✅

### Approval Criteria:
- ✅ **Security**: All security patterns validated, no concerns identified
- ✅ **Architecture**: Excellent adherence to CFGMS pluggable architecture
- ✅ **Testing**: Comprehensive test coverage with real component testing
- ✅ **Breaking Changes**: None - fully backward compatible
- ✅ **Performance**: Benchmarks show no regression, slight improvement
- ✅ **Documentation**: Complete API documentation and usage examples
- ✅ **CI/CD**: All automated validation passes
- ✅ **Deployment**: Production-ready with zero deployment risk

**RECOMMENDATION**: ✅ **APPROVED FOR MERGE**

This PR demonstrates excellent engineering practices and fully implements
the required functionality with no identified risks or concerns.
```

## Usage Examples

### Auto-Start Mode (Single PR)
```bash
/pr-review

# Output when only 1 PR exists:
📋 Found 1 open pull request

✅ Auto-selecting PR #233 for review...

🔄 Synchronizing git branch with remote...
   ✅ No uncommitted changes
   ✅ Branch is up to date with remote
   ✅ No unpushed commits

🔍 Starting comprehensive review of PR #233...
📋 Fetching PR details and changes...

[Complete 5-phase review execution with detailed analysis]
```

### Interactive Mode (Multiple PRs)
```bash
/pr-review

# Output when multiple PRs exist:
📋 Discovering open pull requests...

Found 3 open PRs:

a) PR #218: Story #214: Controller Health Monitoring & Alerting (8 points)
   👤 Author: jrdnr
   🌿 Branch: feature/story-214-controller-health-monitoring
   📊 Status: Ready for review

b) PR #217: Story #213: Endpoint Performance Monitoring (13 points)
   👤 Author: jrdnr
   🌿 Branch: feature/story-213-endpoint-monitoring
   📊 Status: Ready for review

c) PR #216: Fix logging integration tests
   👤 Author: jrdnr
   🌿 Branch: fix/logging-tests
   📊 Status: Ready for review

Select a PR to review:
• Enter letter (a-c) for quick selection
• Enter PR number directly (e.g., 218)
• Type 'cancel' to exit

Your choice: a

✅ Selected PR #218

🔄 Synchronizing git branch with remote...
   ✅ No uncommitted changes
   ✅ Branch is up to date with remote
   ✅ No unpushed commits

🧹 Clearing conversation context for objective review...
✅ Context cleared - starting fresh review

🔍 Starting comprehensive review of PR #218...
📋 Fetching PR details and changes...

[Complete 5-phase review execution with detailed analysis]
```

### Direct PR Number Mode
```bash
/pr-review 182

# Output:
🔄 Synchronizing git branch with remote...
   ✅ No uncommitted changes
   ✅ Branch is up to date with remote
   ✅ No unpushed commits

🧹 Clearing conversation context for objective review...
✅ Context cleared - starting fresh review

🔍 Starting comprehensive review of PR #182...
📋 Fetching PR details and changes...

[Complete 5-phase review execution with detailed analysis]

## Review Summary
- **Security**: ✅ Excellent security practices
- **Code Quality**: ✅ High-quality implementation
- **Testing**: ✅ Comprehensive test coverage
- **Documentation**: ✅ Complete documentation
- **Integration**: ✅ Production-ready

**Final Recommendation**: ✅ **APPROVED FOR MERGE**
```

### Review with Unpushed Changes
```bash
/pr-review 183

# Output:
🔄 Synchronizing git branch with remote...
   ⚠️ WARNING: Uncommitted changes detected
   Recommendation: Commit or stash changes before reviewing

   On branch feature/story-183-new-feature
   Changes not staged for commit:
     modified:   features/module/handler.go
     modified:   features/module/handler_test.go

   📤 Found 2 unpushed commit(s)
   Pushing to remote before review...
   ✅ Successfully pushed to remote

🧹 Clearing conversation context for objective review...
✅ Context cleared - starting fresh review
```

### Review with Issues Found
```bash
/pr-review 184

# Output would include:
🧹 Clearing conversation context for objective review...
✅ Context cleared - starting fresh review

## Phase 2: Security & Code Quality Review ⚠️

### Security Concerns:
- ❌ **Critical**: Hard-coded credential detected in config.go:45
- ⚠️  **Medium**: Error messages may expose internal paths
- ❌ **High**: SQL query uses string concatenation (injection risk)

### Required Actions:
1. Remove hard-coded credentials - use environment variables
2. Sanitize error messages to remove internal paths
3. Convert SQL query to parameterized statement

**RECOMMENDATION**: ❌ **CHANGES REQUIRED**
Cannot approve until security issues are resolved.
```

## Error Handling

### Git Workflow Violation (CRITICAL)
```bash
/pr-review 199

# Output:
🧹 Clearing conversation context for objective review...
✅ Context cleared - starting fresh review

🔍 Starting comprehensive review of PR #199...
📋 Fetching PR details and changes...

❌ CRITICAL ERROR: Git Workflow Violation

   Feature branch attempting to merge to main directly
   Head: feature/story-178-high-availability-infrastructure
   Base: main

   CFGMS Git Workflow:
   ✅ Feature branches → develop (required)
   ✅ Develop → main (release PRs only)
   ❌ Feature → main (BLOCKED)

   Required Actions:
   1. Close this PR or change base to develop:
      gh pr edit 199 --base develop
   2. Follow proper git workflow for all future PRs

   ⛔ REVIEW BLOCKED - Cannot proceed with workflow violation

# Review stops here - will not proceed with other phases
```

### Invalid PR Number (Direct Mode)
```bash
/pr-review 999

# Output:
❌ PR Review Error: PR #999 not found

   Available open PRs:
   • #218: Story #214: Controller Health Monitoring & Alerting
   • #217: Story #213: Endpoint Performance Monitoring
   • #216: Fix logging integration tests

   💡 Tip: Run '/pr-review' without arguments for interactive selection

   Usage: /pr-review [valid_pr_number]
```

### No Open PRs (Interactive Mode)
```bash
/pr-review

# Output:
📋 Discovering open pull requests...

⚠️ No open pull requests found

   The repository has no PRs awaiting review.

   Recent closed PRs:
   • #217: Story #213: Endpoint Performance Monitoring (merged 2 days ago)
   • #216: Fix logging integration tests (merged 3 days ago)
   • #215: Update documentation for v0.6.0 (merged 1 week ago)

   💡 Tip: Use '/pr-review [number]' to review a specific PR
```

### User Cancellation (Interactive Mode)
```bash
/pr-review

# Output:
📋 Discovering open pull requests...

Found 3 open PRs:
[... PR list ...]

Your choice: cancel

✅ PR review cancelled

   No PR was reviewed.
```

### GitHub Access Issues
```bash
⚠️ GitHub API Access Warning

   Could not fetch PR details for #182
   Reason: API rate limit exceeded / Authentication required

   Manual Review Required:
   1. Visit: https://github.com/cfg-is/cfgms/pull/182
   2. Follow 5-phase review methodology from CLAUDE.md
   3. Document review in PR comments
```

## Review Output Format

### Structured Results
- **Comprehensive Analysis**: Each phase provides detailed findings
- **Clear Recommendations**: Specific actions for any issues found
- **Risk Assessment**: Production deployment risk evaluation
- **Approval Decision**: Clear approve/reject/changes-required status

### Integration with PR Process
- **Review Comments**: Can post structured review as PR comments
- **Status Updates**: Updates PR review status where possible
- **Documentation**: Creates review audit trail
- **Team Communication**: Facilitates team review discussions

## Quality Assurance

### Objectivity Maintenance
- **Fresh Context**: Automatically clears context using `/clear` command
- **Systematic Approach**: Structured methodology prevents bias
- **Comprehensive Coverage**: All critical areas systematically reviewed
- **Consistent Standards**: Same review quality across all PRs

### Review Effectiveness
- **Issue Detection**: Catches problems missed during development
- **Knowledge Transfer**: Reviews serve as learning opportunities
- **Quality Standards**: Maintains consistent code quality
- **Risk Mitigation**: Prevents production issues through thorough review

---

## Integration Points

- **GitHub CLI**: PR data fetching and analysis
- **CFGMS Standards**: Enforces project-specific requirements
- **Security Framework**: Integrates with security scanning tools
- **Documentation**: Links to architectural and security requirements