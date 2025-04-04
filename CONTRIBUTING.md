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

1. **Authentication & Authorization**
   - Use mTLS for internal agent communication
   - Implement proper API key validation
   - Follow principle of least privilege
   - Never store credentials in code or configuration

2. **Network Security**
   - Use HTTPS for all external communication
   - Implement proper TLS configuration
   - Validate all network inputs
   - Sanitize all logging output

3. **Code Security**
   - Run security linters (gosec, etc.)
   - Keep dependencies updated
   - Follow secure coding practices
   - Document security considerations

4. **Testing Security**
   - Include security-focused test cases
   - Test authentication and authorization
   - Validate input sanitization
   - Test error handling for security scenarios

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
