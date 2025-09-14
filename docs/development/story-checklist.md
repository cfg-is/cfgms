# CFGMS Story Development Checklist

This document provides the complete step-by-step checklist for CFGMS story development. For automated workflow, use the slash commands: `/story-start`, `/story-commit`, `/story-complete`.

## MANDATORY Story Development Checklist

### BEFORE STARTING ANY CODE:

#### 0. **Run FULL test suite**
Do not start working on a new feature until all issues (test, linting, and security) have been fixed. From this point forward you will be responsible for ANY issues that show up in your feature branch

#### 1. **Create Feature Branch** (MANDATORY)
```bash
git checkout develop
git pull origin develop
git checkout -b feature/story-[NUMBER]-[brief-description]
```

#### 2. **Verify Branch Creation**
```bash
git branch --show-current  # Must show feature branch name
```

### DURING DEVELOPMENT:

#### 3. **Implement using TDD**
- Write tests first, then implementation
- **CRITICAL**: Never mock CFGMS functionality - test the actual program using real components
- Use real memory stores, real session creation, real component integration
- Only mock external dependencies we don't control (network, file I/O)
- Run tests frequently: `make test`

#### **STORAGE DEVELOPMENT CHECKLIST** (Required for any storage-related work):
- ✅ **EPIC 6 COMPLETED**: Global storage migration complete - all components use pluggable storage
- ❌ **STOP**: Am I storing secrets in cleartext anywhere? (PROHIBITED)
- ✅ **VERIFY**: Does my component use write-through caching (memory → durable)?
- ✅ **VERIFY**: Does my component import only `pkg/storage/interfaces`?
- ✅ **VERIFY**: Does my implementation work with ALL global storage providers (git/database/memory)?
- ✅ **VERIFY**: Does my test use proper storage configuration in test helpers?

#### 4. **Basic Security Review** (CRITICAL)

Perform initial security validation during development:
- No hardcoded secrets, passwords, or keys in code
- SQL queries use parameterized statements (no string concatenation)
- File operations use validated paths (prevent directory traversal)
- Input validation present for user-provided data
- Error messages don't expose sensitive information
- Tenant isolation maintained (no cross-tenant data leaks)

**Note**: Comprehensive security review occurs during PR review phase with fresh context.

**Action Required:** If ANY critical security issues are found, STOP and fix them before proceeding.

### BEFORE ANY COMMITS:

#### 5. **STOP - Run Full Test Suite** (MANDATORY)
```bash
make test  # MUST pass 100% before proceeding
```
**ZERO TOLERANCE POLICY**:
- If ANY tests fail, STOP immediately and fix them before continuing
- This includes ALL unrelated test failures - fix them or the story cannot proceed
- NO exceptions, NO workarounds, NO "fix later" - tests MUST be 100% green
- Stories cannot be marked 'Done' or merged with ANY failing tests
- Bypassing this requirement violates the development workflow

#### 6. **Run Security Scanning** (MANDATORY)
```bash
make security-scan  # MUST pass before proceeding
```
- **Trivy**: Filesystem vulnerability scanning (critical/high blocking)
- **Nancy**: Go dependency vulnerability scanning
- **gosec**: Go security pattern analysis (127 checks)
- **staticcheck**: Advanced static analysis (47 categories)
- Critical/High vulnerabilities will block deployment
- Fix security issues before continuing with commit
- Development certificates in features/controller/certs/ are expected (non-blocking)
- **Claude Code Integration**: Use `make security-remediation-report` for automated fixes

#### 7. **Run Linting** (MANDATORY)
```bash
make lint  # MUST pass before proceeding
```

#### **ALTERNATIVE: Unified Development Validation** (RECOMMENDED)
Instead of steps 5-7, use the unified target that runs all validations:
```bash
make test-commit  # Runs: test + lint + security-scan + M365-dev (skips if no creds)
```
This ensures optimal order and provides clear validation status. M365 tests are skipped gracefully if credentials are not available.

### COMMIT AND PROJECT MANAGEMENT:

#### 8. **Commit Feature Work**
```bash
git add .
git commit -m "Implement Story #[NUMBER]: [description]

Basic Security Review: [Brief summary - no hardcoded secrets, SQL injection prevention, input validation present]"
```

#### 9. **Update Documentation** (REQUIRED)
- Update `docs/product/roadmap.md` if needed
- Update `CLAUDE.md` if workflow/commands changed
- For M365/MSP features, ensure `docs/M365_INTEGRATION_GUIDE.md` is current

#### 10. **Final Test Run - COMPLETION GATE** (MANDATORY)
```bash
make test-commit  # MUST be 100% green before marking story complete
```
**COMPLETION GATE**: This is the final validation before marking story complete. If ANY tests fail here:
- DO NOT update GitHub project status
- DO NOT update roadmap
- DO NOT merge
- Fix all failures first, then restart from this step

#### 11. **Update GitHub Project Status** (MANDATORY - ONLY AFTER TESTS PASS)
```bash
# ONLY proceed if step 10 test run passed 100%
# ALWAYS review docs/github-cli-reference.md FIRST before any gh project commands
# This document contains the exact project IDs, field IDs, and option IDs required
# Never guess or use generic commands - use the documented patterns

# Example workflow:
# 1. Check docs/github-cli-reference.md for current project details
# 2. Add issues to project: gh project item-add 1 --owner cfg-is --url "URL"
# 3. Update status: Use exact IDs from documentation
# 4. Move story from "In Progress" to "Done" using documented commands
```

#### 12. **Update Roadmap** (MANDATORY - ONLY AFTER TESTS PASS)
```bash
# ONLY proceed if step 10 test run passed 100%
# Update docs/product/roadmap.md to reflect story completion
# Mark the completed story with ✅ and update progress
# Update milestone completion percentage if applicable
# This ensures roadmap stays current with actual development progress
```

#### 13. **Create Pull Request for Code Review**
```bash
# Push feature branch to remote
git push origin feature/story-[NUMBER]-[brief-description]

# Create pull request using GitHub CLI
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

# MANDATORY: Objective PR Review (see PR Review Process section)
# After comprehensive review approval, merge the PR
gh pr merge --merge

# Clean up local feature branch after merge
git checkout develop
git pull origin develop  # Get the merged changes
git branch -D feature/story-[NUMBER]-[brief-description]  # Delete local feature branch
```

## Benefits of PR-Based Workflow:
- **Code Review Trail**: Permanent record of changes and review discussions
- **CI/CD Integration**: GitHub Actions run automatically on PRs before merge
- **Quality Gates**: Can enforce status checks, approvals, and branch protection
- **Documentation**: PR descriptions provide context for future reference
- **Team Collaboration**: Enables review comments and suggestions
- **Rollback History**: Easy to identify and revert specific features

## When to Use PRs vs Direct Commits:
- **ALWAYS use PRs for**: Feature development, bug fixes, refactoring, architectural changes
- **Optional for**: Minor documentation updates, typo fixes, CLAUDE.md workflow updates
- **Direct commits allowed for**: Emergency hotfixes (followed by retroactive PR documentation)

## Validation Checkpoints:
- Verify branch was created: `git log --oneline -5`
- **Verify tests pass: `make test` - NO FAILING TESTS ALLOWED**
- Verify security scan passes: `make security-scan`
- Verify project updated: Check GitHub project board
- **Verify roadmap updated: Check docs/product/roadmap.md shows story completion**
- **Verify PR created**: `gh pr view --json title,state,url`
- **Verify PR reviewed using structured methodology**: All 5 review phases completed
- **Verify PR merged**: `gh pr list --state merged --limit 5`
- **Verify feature branch cleaned up**: `git branch -a | grep feature/story-[NUMBER]` (should be empty)
- **BLOCKING REQUIREMENT**: ALL validation checkpoints must pass before story completion

## GitHub Actions CI/CD:
- **Security Scanning Workflow**: Automatic security validation on push/PR
- **Production Deployment Gates**: Critical vulnerabilities block main branch deployment
- **Automated Remediation**: Download artifacts and use Claude Code for automatic fixes
- **Manual Trigger**: Use workflow_dispatch for specific scan types (quick/full/remediation-report)

---

## Automated Alternative

For automated workflow that enforces this checklist, use the CFGMS slash commands:

- **`/story-start`** - Automates steps 0-2 with roadmap integration
- **`/story-commit`** - Automates steps 5-8 with progress tracking
- **`/story-complete`** - Automates steps 10-13 with PR creation

The slash commands ensure no steps are skipped while providing intelligent automation and progress tracking.