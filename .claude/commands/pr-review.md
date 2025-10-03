---
name: pr-review
description: Structured PR review following mandatory CFGMS methodology with fresh context
parameters:
  - name: pr_number
    description: Pull request number to review
    required: true
---

# PR Review Command

This command executes the comprehensive 5-phase PR review methodology required by CFGMS development workflow, ensuring objective and thorough code review with fresh context.

## Fresh Context Initialization

**CRITICAL**: This command automatically starts by clearing all conversation context to ensure objectivity and prevent development bias from affecting the review.

**Execution Flow**:
1. **Clear Context**: Automatically runs `/clear` to eliminate development history
2. **Fresh Review**: Begins review with no prior context or assumptions
3. **Objective Analysis**: Reviews code purely based on what's presented in the PR
4. **Structured Methodology**: Follows all 5 review phases systematically

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

### Standard PR Review
```bash
/pr-review 182

# Output:
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

### Review with Issues Found
```bash
/pr-review 183

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

### Invalid PR Number
```bash
/pr-review 999

# Output:
❌ PR Review Error: PR #999 not found

   Available PRs:
   • #182: Implement Story #166: Logging Provider Migration
   • #181: Fix CI infrastructure and testing reliability issues
   • #180: Merge pull request #179

   Usage: /pr-review [valid_pr_number]
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