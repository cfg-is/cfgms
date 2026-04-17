# CFGMS Development Workflow

This document provides a complete step-by-step workflow for CFGMS feature development. For automated workflow using Claude Code, see the slash commands documentation.

## Development Checklist

### BEFORE STARTING ANY CODE

#### 1. **Run Full Test Suite**

Do not start working on a new feature until all issues (test, linting, and security) have been fixed.

```bash
make test  # Must pass 100% before starting
```

#### 2. **Create Feature Branch** (MANDATORY)

```bash
git checkout develop
git pull origin develop
git checkout -b feature/[brief-description]
```

#### 3. **Verify Branch Creation**

```bash
git branch --show-current  # Must show feature branch name
```

### DURING DEVELOPMENT

#### 4. **Implement using TDD**

- Write tests first, then implementation
- **CRITICAL**: Never mock CFGMS functionality - test the actual program using real components
- Use real memory stores, real session creation, real component integration
- Only mock external dependencies we don't control (network, file I/O)
- Run tests frequently: `make test`

#### **STORAGE DEVELOPMENT CHECKLIST** (Required for any storage-related work)

- ❌ **STOP**: Am I storing secrets in cleartext anywhere? (PROHIBITED)
- ✅ **VERIFY**: Does my component use write-through caching (memory → durable)?
- ✅ **VERIFY**: Does my component import only `pkg/storage/interfaces`?
- ✅ **VERIFY**: Does my implementation work with ALL global storage providers (flatfile+sqlite/database)?
- ✅ **VERIFY**: Does my test use proper storage configuration in test helpers?

#### 5. **Basic Security Review** (CRITICAL)

Perform initial security validation during development:

- No hardcoded secrets, passwords, or keys in code
- SQL queries use parameterized statements (no string concatenation)
- File operations use validated paths (prevent directory traversal)
- Input validation present for user-provided data
- Error messages don't expose sensitive information
- Tenant isolation maintained (no cross-tenant data leaks)

**Note**: Comprehensive security review occurs during PR review phase with fresh context.

**Action Required:** If ANY critical security issues are found, STOP and fix them before proceeding.

### BEFORE ANY COMMITS

#### 6. **STOP - Run Full Test Suite** (MANDATORY)

```bash
make test  # MUST pass 100% before proceeding
```

**ZERO TOLERANCE POLICY**:

- If ANY tests fail, STOP immediately and fix them before continuing
- This includes ALL unrelated test failures - fix them or the work cannot proceed
- NO exceptions, NO workarounds, NO "fix later" - tests MUST be 100% green
- Work cannot be merged with ANY failing tests

#### 7. **Run Security Scanning** (MANDATORY)

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

#### 8. **Run Linting** (MANDATORY)

```bash
make lint  # MUST pass before proceeding
```

#### **ALTERNATIVE: Unified Development Validation** (RECOMMENDED)

Instead of steps 6-8, use the unified target that runs all validations:

```bash
make test-commit  # Runs: test + lint + security-scan + M365-dev (skips if no creds)
```

This ensures optimal order and provides clear validation status. M365 tests are skipped gracefully if credentials are not available.

### COMMIT AND PULL REQUEST

#### 9. **Commit Feature Work**

```bash
git add <specific-files>  # Never use git add . or git add -A
git commit -m "scope: what changed (Issue #XXX)

Why this change was made and what it achieves.

Fixes #XXX"
```

#### 10. **Update Documentation** (REQUIRED)

- Update `docs/product/roadmap.md` if adding major features
- Update `CLAUDE.md` if workflow/commands changed
- For M365/MSP features, ensure `docs/M365_INTEGRATION_GUIDE.md` is current
- Update relevant architecture documentation

#### 11. **Final Story Validation** (MANDATORY)

```bash
make test-complete  # MUST be 100% green (10-20 min)
```

**This runs ALL CI required check tests:**
- ✅ Unit tests (test, test-fast, test-production-critical)
- ✅ Linting and license headers
- ✅ Security scanning (all 4 tools)
- ✅ Architecture compliance
- ✅ Cross-platform compilation (Linux, macOS, Windows)
- ✅ Docker integration tests (storage, controller)
- ✅ E2E tests (transport, Controller)

**Only CI-only tests:**
- Native Windows/macOS builds (requires Windows/macOS runners)

**COMPLETION GATE**: If ANY tests fail:
- DO NOT create pull request
- Fix all failures first, then restart from this step
- test-complete ensures local validation matches 100% of CI (except Windows/macOS native builds)

#### 12. **Create Pull Request for Code Review**

```bash
# Push feature branch to remote
git push origin feature/[brief-description]

# Create pull request using GitHub CLI
gh pr create --base develop --title "[Feature]: [description]" --body "$(cat <<'EOF'
## Summary
[Brief description of the changes]

### Changes Made
- [List key changes]
- [Include any breaking changes]

### Test Results
✅ All tests passing
✅ Security scan clean
✅ Linting passed

### Security Review
[Brief summary - no hardcoded secrets, SQL injection prevention, input validation present]
EOF
)"
```

#### 13. **After PR Approval and Merge**

```bash
# Clean up local feature branch after merge
git checkout develop
git pull origin develop  # Get the merged changes
git branch -D feature/[brief-description]  # Delete local feature branch
```

## Benefits of PR-Based Workflow

- **Code Review Trail**: Permanent record of changes and review discussions
- **CI/CD Integration**: GitHub Actions run automatically on PRs before merge
- **Quality Gates**: Enforces status checks, approvals, and branch protection
- **Documentation**: PR descriptions provide context for future reference
- **Team Collaboration**: Enables review comments and suggestions
- **Rollback History**: Easy to identify and revert specific features

## When to Use PRs vs Direct Commits

- **ALWAYS use PRs for**: Feature development, bug fixes, refactoring, architectural changes
- **Optional for**: Minor documentation updates, typo fixes
- **Direct commits allowed for**: Emergency hotfixes (followed by retroactive PR documentation)

## Validation Checkpoints

- Verify branch was created: `git log --oneline -5`
- **Verify tests pass: `make test` - NO FAILING TESTS ALLOWED**
- Verify security scan passes: `make security-scan`
- **Verify PR created**: `gh pr view --json title,state,url`
- **Verify PR reviewed**: All review phases completed
- **Verify PR merged**: `gh pr list --state merged --limit 5`
- **Verify feature branch cleaned up**: `git branch -a | grep feature/` (your branch should be gone)
- **BLOCKING REQUIREMENT**: ALL validation checkpoints must pass before completion

## GitHub Actions CI/CD

- **Security Scanning Workflow**: Automatic security validation on push/PR
- **Production Deployment Gates**: Critical vulnerabilities block main branch deployment
- **Automated Remediation**: Download artifacts for security fixes
- **Manual Trigger**: Use workflow_dispatch for specific scan types

## Development Best Practices

### Test-Driven Development (TDD)

1. Write failing test first
2. Implement minimum code to pass
3. Refactor while keeping tests green
4. Run full test suite frequently

### Security-First Development

1. Never commit secrets or credentials
2. Always use parameterized SQL queries
3. Validate all user input
4. Maintain tenant isolation boundaries
5. Use secure defaults

### Code Quality Standards

1. Follow Go best practices and idioms
2. Write clear, self-documenting code
3. Add comprehensive error handling
4. Include GoDoc comments for all exported items
5. Keep functions small and focused

### Performance Considerations

1. Use write-through caching for storage operations
2. Implement proper resource cleanup
3. Handle concurrent access safely
4. Profile performance-critical paths
5. Monitor memory and CPU usage

## Getting Help

If you encounter issues:

1. Check existing documentation in `docs/`
2. Search GitHub Issues for similar problems
3. Ask in project discussions
4. Create a new issue with detailed information

## Contributing

See `CONTRIBUTING.md` for complete contribution guidelines, code of conduct, and community standards.
