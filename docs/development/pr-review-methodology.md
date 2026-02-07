# CFGMS PR Review Methodology

This document outlines the mandatory 5-phase PR review methodology for CFGMS. For automated review, use `/pr-review [pr-number]`.

## Overview

**CRITICAL**: All PRs must undergo systematic review with fresh context to ensure objectivity and catch issues missed during development.

## Pre-Review Setup

1. **Clear All Context**: Start fresh Claude Code session or clear conversation history
2. **Review Environment**: Open PR in GitHub web interface for full context
3. **Access Documentation**: Have CLAUDE.md, security requirements, and architecture docs available

## Structured Review Methodology

### Phase 1: PR Overview Assessment

**Objective**: Analyze PR scope, purpose, and completeness

**Key Questions**:

- Does the PR clearly state its purpose and scope?
- Are breaking changes properly documented?
- Is the security review status clear?
- Are test results validated and documented?

**Analysis Framework**:

```bash
gh pr view [pr_number] --json title,body,baseRefName,headRefName,state,author
```

**Expected Output**:

```markdown
## Phase 1: PR Overview Assessment ✅/⚠️/❌

**PR #XXX**: [Title]
- **Scope**: Clear/Unclear - [assessment]
- **Purpose**: Well-defined/Needs clarification
- **Breaking Changes**: Documented/Missing/None
- **Security Status**: Completed/Missing
- **Test Documentation**: Complete/Incomplete

**Assessment**: [Overall assessment with specific recommendations]
```

### Phase 2: Code Quality & Security Review

**Objective**: Comprehensive security and code quality analysis

#### Security Analysis (CRITICAL)

- Authentication/Authorization bypass potential
- Input validation and injection prevention
- Cryptographic implementation correctness
- Information disclosure risks
- CFGMS-specific tenant isolation
- Certificate and mTLS validation

#### Code Quality Analysis

- Go best practices and idioms
- Error handling completeness
- Resource management (defer, cleanup)
- Race condition potential
- Performance implications
- Interface design and dependency injection

#### CFGMS Architecture Compliance

- Follows CFGMS pluggable architecture patterns
- Proper interface usage vs direct imports
- Module system compliance
- Zero-trust security model adherence

**Analysis Commands**:

```bash
# Security pattern analysis
gh pr diff [pr_number] | grep -E "(password|secret|token|auth)"

# Code quality checks
gh pr view [pr_number] --json files
```

**Expected Output**:

```markdown
## Phase 2: Security & Code Quality Review ✅/⚠️/❌

### Security Analysis:
- ✅/❌ **Authentication**: [specific findings]
- ✅/❌ **Input Validation**: [specific findings]
- ✅/❌ **Information Disclosure**: [specific findings]
- ✅/❌ **Tenant Isolation**: [specific findings]

### Code Quality:
- ✅/❌ **Go Idioms**: [specific findings]
- ✅/❌ **Error Handling**: [specific findings]
- ✅/❌ **Resource Management**: [specific findings]
- ✅/❌ **Performance**: [specific findings]

**Critical Issues**: [List any blocking issues]
**Recommendations**: [Specific improvement suggestions]
```

### Phase 3: Testing & Validation Review

**Objective**: Validate testing approach and coverage

#### Testing Validation

- Are tests testing actual functionality vs mocks?
- Is error path testing comprehensive?
- Are integration tests covering component interactions?
- Is race condition testing adequate?
- Are security edge cases tested?

#### Test Quality Assessment

- Table-driven test patterns used correctly?
- Test data realistic and comprehensive?
- Cleanup and resource management in tests?
- Performance/benchmark testing where needed?

**Analysis Commands**:

```bash
# Identify test files in PR
gh pr diff [pr_number] --name-only | grep "_test.go"

# Check for test quality patterns
gh pr diff [pr_number] | grep -E "(testify|assert|require|t\.Run)"
```

**Expected Output**:

```markdown
## Phase 3: Testing & Validation Review ✅/⚠️/❌

### Test Coverage:
- ✅/❌ **Real Components**: Tests use actual vs mocked components
- ✅/❌ **Error Paths**: Comprehensive error condition testing
- ✅/❌ **Integration**: Cross-component interaction tests
- ✅/❌ **Race Conditions**: Proper concurrent testing

### Test Quality:
- ✅/❌ **Table-Driven**: Appropriate test table usage
- ✅/❌ **Cleanup**: Proper test cleanup and resource management
- ✅/❌ **Realistic Data**: Tests use realistic scenarios
- ✅/❌ **Performance**: Benchmarks where appropriate

**Test Statistics**: [Number of new tests, coverage impact]
**Test Pattern Assessment**: [Adherence to CFGMS testing standards]
```

### Phase 4: Documentation & Integration Review

**Objective**: Assess documentation and system integration impact

#### Documentation Analysis

- Are exported functions/types properly documented?
- Is architectural context explained?
- Are breaking changes clearly documented?
- Is usage guidance provided?

#### Integration Analysis

- Will this change affect existing components?
- Are database migrations handled properly?
- Are configuration changes backward compatible?
- Is deployment impact assessed?

**Expected Output**:

```markdown
## Phase 4: Documentation & Integration Review ✅/⚠️/❌

### Documentation:
- ✅/❌ **API Documentation**: All exported functions documented
- ✅/❌ **Architecture Context**: Clear explanation provided
- ✅/❌ **Usage Guidance**: Examples and guidance included
- ✅/❌ **Breaking Changes**: Changes properly documented

### Integration Impact:
- ✅/❌ **Component Compatibility**: Backward compatibility maintained
- ✅/❌ **Configuration**: Config changes handled properly
- ✅/❌ **Deployment**: Deployment impact assessed
- ✅/❌ **Database**: Schema changes handled correctly

**Integration Risk**: LOW/MEDIUM/HIGH - [specific assessment]
```

### Phase 5: Final Approval Checklist

**Objective**: Comprehensive approval decision

#### Required Validations

- [ ] All security concerns addressed or documented as accepted risks
- [ ] Code follows CFGMS architecture patterns and Go best practices
- [ ] Tests provide adequate coverage of new functionality
- [ ] Breaking changes are properly documented and justified
- [ ] Performance impact assessed for production workloads
- [ ] Documentation updated for any API/interface changes
- [ ] CI/CD validation passes (all required checks must be green):
  - `unit-tests` - Core functionality validation
  - `Build Gate` - Cross-platform builds + Docker integration tests (MQTT+QUIC, storage, controller)
  - `security-deployment-gate` - Security vulnerability scans
- [ ] Deployment impact reviewed and mitigation planned

**Final Decision Matrix**:

| Criteria | Status | Notes |
|----------|--------|-------|
| Security | ✅/❌ | [specific items] |
| Code Quality | ✅/❌ | [specific items] |
| Testing | ✅/❌ | [specific items] |
| Documentation | ✅/❌ | [specific items] |
| Integration | ✅/❌ | [specific items] |

**Final Recommendation**:

- ✅ **APPROVED FOR MERGE**: All criteria met, no blocking issues
- ⚠️ **APPROVED WITH COMMENTS**: Minor issues noted, can merge with follow-up
- ❌ **CHANGES REQUIRED**: Blocking issues must be resolved before merge

## Review Output Template

```markdown
# PR Review: #XXX - [Title]

## Review Summary
- **Security**: ✅/⚠️/❌ [brief assessment]
- **Code Quality**: ✅/⚠️/❌ [brief assessment]
- **Testing**: ✅/⚠️/❌ [brief assessment]
- **Documentation**: ✅/⚠️/❌ [brief assessment]
- **Integration**: ✅/⚠️/❌ [brief assessment]

## Critical Issues
[List any blocking issues that must be resolved]

## Recommendations
[List specific improvement suggestions]

## Final Decision
**APPROVED FOR MERGE** / **APPROVED WITH COMMENTS** / **CHANGES REQUIRED**

[Detailed explanation of decision]

---
*Review completed using CFGMS 5-phase methodology*
```

## Review Quality Standards

### Objectivity Maintenance

- **Fresh Context**: Review without development context bias
- **Systematic Approach**: Follow all 5 phases consistently
- **Comprehensive Coverage**: Address all critical areas
- **Consistent Standards**: Apply same criteria to all PRs

### Issue Detection Effectiveness

- **Security Focus**: Prioritize security implications
- **Architecture Alignment**: Ensure CFGMS pattern compliance
- **Quality Standards**: Maintain consistent code quality
- **Risk Assessment**: Evaluate production deployment risks

### Documentation Requirements

- **Clear Findings**: Specific, actionable feedback
- **Risk Assessment**: Clear risk levels and implications
- **Decision Rationale**: Explanation of approve/reject decisions
- **Follow-up Items**: Clear action items for any issues

## Common Review Patterns

### Security Red Flags

- Hard-coded credentials or secrets
- SQL injection vulnerabilities (string concatenation)
- Directory traversal vulnerabilities
- Information disclosure in error messages
- Missing input validation
- Broken tenant isolation

### Code Quality Issues

- Missing error handling
- Resource leaks (missing defer cleanup)
- Race conditions in concurrent code
- Performance anti-patterns
- Violation of Go idioms
- Complex functions without proper decomposition

### Testing Problems

- Excessive mocking of CFGMS components
- Missing error path testing
- Inadequate race condition testing
- Unrealistic test data
- Missing integration test coverage
- Poor test cleanup

### Documentation Gaps

- Missing API documentation
- Unclear usage examples
- Undocumented breaking changes
- Missing architectural context
- Inadequate deployment notes

---

## Automated Alternative

For automated review using this methodology, use:

```bash
/pr-review [pr-number]
```

The slash command executes all 5 phases systematically and provides structured output following this methodology.
