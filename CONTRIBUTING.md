# Contributing to CFGMS

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
