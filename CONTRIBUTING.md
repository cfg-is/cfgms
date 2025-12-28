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
