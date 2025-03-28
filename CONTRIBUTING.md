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
