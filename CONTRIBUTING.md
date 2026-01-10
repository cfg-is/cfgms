# Contributing to CFGMS

## Git Workflow: GitFlow

CFGMS follows the GitFlow branching model for development:

### Main Branches

- `main` - Production-ready code only
- `develop` - Integration branch for ongoing development

### Supporting Branches

- `feature/*` - New features or enhancements
- `release/*` - Release preparation
- `hotfix/*` - Critical fixes for production

### Workflow Rules

1. **Feature Development**
   - Branch from: `develop`
   - Name format: `feature/short-description`
   - Merge back to: `develop`
   - Example: `feature/add-file-module`

2. **Release Preparation**
   - Branch from: `develop`
   - Name format: `release/vX.Y.Z`
   - Merge to: both `main` and `develop`
   - Tag on `main` after merging

3. **Hotfixes**
   - Branch from: `main`
   - Name format: `hotfix/short-description`
   - Merge to: both `main` and `develop`
   - Example: `hotfix/fix-security-issue`

### Commit Guidelines

- Use clear, descriptive commit messages
- Reference issue numbers when applicable
- Keep commits focused on a single logical change
- Sign your commits with `git commit -s`

## Contributor License Agreement (CLA)

**Before contributing code, you must sign the CLA.**

### Why We Require a CLA

CFGMS uses a dual-license model (Apache 2.0 + Elastic License 2.0) for open source and commercial features. The CLA:

- **Assigns copyright** to Jordan Ritz (current copyright holder)
- **Enables dual-licensing** of your contributions under both Apache 2.0 and Elastic License 2.0
- **Protects you** by ensuring you have the rights to contribute
- **Protects the project** from legal issues related to intellectual property
- **Plans for the future** by allowing transfer to cfg.is entity when formed

### How to Sign the CLA

**For Individual Contributors:**

1. **Read the CLA**: Review [docs/legal/CLA.md](docs/legal/CLA.md) carefully
2. **Add your name**: Include your name in [CONTRIBUTORS.md](CONTRIBUTORS.md) as part of your first Pull Request:
   ```markdown
   - [Your Full Name] <your.email@example.com> - YYYY-MM-DD
   ```
3. **Submit your PR**: Once your name is added, you're covered for all future contributions

**For Corporate Contributors:**

If you're contributing on behalf of your employer:

1. Ensure you have authorization from your employer
2. Have an authorized representative add your company to the Corporate Contributors section
3. We may require proof of authorization for significant contributions
4. See [docs/legal/README.md](docs/legal/README.md) for corporate contribution guidance

### What the CLA Covers

By signing the CLA, you certify that:

- ✅ You are the original author of your contributions
- ✅ You have the right to make this contribution
- ✅ Your contribution doesn't violate any third-party rights
- ✅ You agree to copyright assignment to Jordan Ritz
- ✅ Your contributions can be licensed under both Apache 2.0 and Elastic License 2.0

### Questions About the CLA?

- **Read the FAQ**: [docs/legal/README.md](docs/legal/README.md#frequently-asked-questions)
- **Full legal text**: [docs/legal/CLA.md](docs/legal/CLA.md)
- **Legal questions**: Consult your own attorney
- **Process questions**: Open an issue with the `legal` label

**Important**: PRs from contributors who haven't signed the CLA cannot be merged.

## Development Guidelines

### Test-Driven Development

#### TDD Workflow

1. Write table-driven tests first
2. Use Go's testing package effectively
3. Run `go test -v ./...` to verify failures
4. Implement minimal code to pass
5. Run `go test -race -cover ./...` to verify

#### Testing Standards

```go
func TestFeature(t *testing.T) {
    tests := []struct {
        name     string
        input    string
        want     string
        wantErr  bool
    }{
        // test cases
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Test implementation
        })
    }
}
```

### Quality Checks

Before submitting code:

1. `go test ./...`
2. `go vet ./...`
3. `golangci-lint run`
4. `go test -race`
5. `go test -cover`

### Documentation Requirements

- GoDoc format comments
- Testable examples
- Behavior documentation
- Error documentation
- Interface documentation

### Security Guidelines

#### Security Best Practices

1. **No Foot-guns in Development (CRITICAL)**
   - **NEVER build insecure options for development convenience**
   - **NEVER document unsafe alternatives**, even temporarily
   - **NEVER create in-memory-only storage** for features requiring durability in production
   - **Rationale**: Insecure dev options inevitably leak into production through laziness, time pressure, or copy-paste documentation
   - **Rule**: If a feature requires durable storage in production, it MUST use durable storage in development and testing
   - **Allowed**: In-memory write-through caches for ephemeral data (sessions, temporary state)
   - **Forbidden**: In-memory-only stores for data that should survive restarts (configurations, users, policies)

2. **Authentication & Authorization**
   - Use mTLS for internal agent communication
   - Implement proper API key validation
   - Follow principle of least privilege
   - Never store credentials in code or configuration
   - Secrets MUST use OS keychain or encrypted storage, never plaintext files

3. **Network Security**
   - Use HTTPS for all external communication
   - Implement proper TLS configuration
   - Validate all network inputs
   - Sanitize all logging output

4. **Code Security**
   - Run security linters (gosec, etc.)
   - Keep dependencies updated
   - Follow secure coding practices
   - Document security considerations

5. **Testing Security**
   - Include security-focused test cases
   - Test authentication and authorization
   - Validate input sanitization
   - Test error handling for security scenarios
   - Use same storage backends in tests as production

#### Security Review Process

1. **Before Submitting**
   - Run security linters
   - Check for common vulnerabilities
   - Review authentication flows
   - Test error handling

2. **During Review**
   - Security implications will be reviewed
   - Authentication flows will be validated
   - Input validation will be checked
   - Error handling will be verified

3. **After Merging**
   - Security tests will be run
   - Dependencies will be checked
   - Security documentation will be updated

### Reporting Security Issues

**DO NOT** open public GitHub issues for security vulnerabilities.

If you discover a security issue in CFGMS, please report it responsibly:

- **Email**: [security@cfg.is](mailto:security@cfg.is)
- **Response Time**: 48 hours for initial acknowledgment
- **Full Details**: See [SECURITY.md](SECURITY.md) for complete vulnerability disclosure policy

We appreciate responsible disclosure and will work with you to address the issue promptly.

## CI/CD Workflows

CFGMS uses GitHub Actions for automated testing, security scanning, and deployment. All workflows must pass before code can be merged.

### Required Status Checks

The following workflows run automatically on every pull request:

- **Cross-Platform Build**: Validates compilation on Linux, Windows, and macOS
- **Test Suite**: Runs complete test suite with race condition detection
- **Security Scan**: Checks for vulnerabilities using Trivy, gosec, and staticcheck
- **CodeQL Analysis**: Advanced security and code quality analysis
- **License Check**: Validates dependency license compliance

**All checks must pass before merge.**

### Local Validation

Before pushing code, run the same validation locally:

```bash
# Run all tests (matches test-suite.yml workflow)
make test

# Run security scans (matches security-scan.yml workflow)
make security-scan

# Complete pre-commit validation (recommended)
make test-commit

# Full CI validation (matches production-gates.yml)
make test-ci
```

### Workflow Documentation

For complete workflow details, see [.github/workflows/README.md](.github/workflows/README.md)

**Key workflows**:

- `cross-platform-build.yml` - Multi-platform compilation and testing
- `production-gates.yml` - Production readiness validation with emergency override support
- `security-scan.yml` - Comprehensive security vulnerability scanning
- `test-suite.yml` - Complete test suite execution

### CI Failures

**If workflows fail**:

1. **Test failures**: Run `make test` locally to reproduce
2. **Security issues**: Run `make security-scan` to identify vulnerabilities
3. **Platform-specific failures**: Check cross-compilation with `make build`
4. **CodeQL alerts**: Review findings in GitHub Security tab

**Need help?**: Check workflow logs in GitHub Actions tab or ask in pull request comments.
