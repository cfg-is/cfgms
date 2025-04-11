# Testing Approach

This document describes the testing approach used in CFGMS, explaining the principles, patterns, and best practices for testing.

## Testing Principles

CFGMS follows these principles for testing:

1. **Test-Driven Development**: Tests are written before implementation
2. **Table-Driven Tests**: Tests use table-driven testing where appropriate
3. **Selective Mocking**: Dependencies are mocked for development tests but not for release candidates
4. **Test Coverage**: High test coverage is maintained
5. **Integration Tests**: Integration tests verify system behavior
6. **Performance Tests**: Performance tests verify system performance
7. **Security Tests**: Security tests verify system security

## Test Types

CFGMS uses several types of tests:

### Unit Tests

Unit tests verify individual components:

```go
func TestModule_Get(t *testing.T) {
    tests := []struct {
        name      string
        module    string
        resource  string
        want      *GetResponse
        wantError bool
    }{
        {
            name:      "valid request",
            module:    "test",
            resource:  "test-resource",
            want:      &GetResponse{},
            wantError: false,
        },
        {
            name:      "invalid resource",
            module:    "test",
            resource:  "",
            want:      nil,
            wantError: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            m := NewModule(tt.module)
            got, err := m.Get(context.Background(), &GetRequest{
                ResourceID: tt.resource,
            })

            if (err != nil) != tt.wantError {
                t.Errorf("Module.Get() error = %v, wantError %v", err, tt.wantError)
                return
            }

            if !reflect.DeepEqual(got, tt.want) {
                t.Errorf("Module.Get() = %v, want %v", got, tt.want)
            }
        })
    }
}
```

### Integration Tests

Integration tests verify system behavior:

```go
func TestModuleIntegration(t *testing.T) {
    // Create a test environment
    env := NewTestEnvironment(t)
    defer env.Cleanup()

    // Create a module
    m := NewModule("test")

    // Test the module
    tests := []struct {
        name      string
        operation func() error
        wantError bool
    }{
        {
            name: "get configuration",
            operation: func() error {
                _, err := m.Get(context.Background(), &GetRequest{
                    ResourceID: "test-resource",
                })
                return err
            },
            wantError: false,
        },
        {
            name: "set configuration",
            operation: func() error {
                _, err := m.Set(context.Background(), &SetRequest{
                    ResourceID:     "test-resource",
                    Configuration: []byte("test"),
                })
                return err
            },
            wantError: false,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := tt.operation()
            if (err != nil) != tt.wantError {
                t.Errorf("operation error = %v, wantError %v", err, tt.wantError)
            }
        })
    }
}
```

### Performance Tests

Performance tests verify system performance:

```go
func BenchmarkModule_Get(b *testing.B) {
    m := NewModule("test")
    req := &GetRequest{
        ResourceID: "test-resource",
    }

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, err := m.Get(context.Background(), req)
        if err != nil {
            b.Fatal(err)
        }
    }
}
```

### Security Tests

Security tests verify system security:

```go
func TestModuleSecurity(t *testing.T) {
    tests := []struct {
        name      string
        setup     func() (*Module, error)
        operation func(*Module) error
        wantError bool
    }{
        {
            name: "unauthorized access",
            setup: func() (*Module, error) {
                return NewModule("test"), nil
            },
            operation: func(m *Module) error {
                ctx := context.WithValue(context.Background(), "role", "unauthorized")
                _, err := m.Get(ctx, &GetRequest{
                    ResourceID: "test-resource",
                })
                return err
            },
            wantError: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            m, err := tt.setup()
            if err != nil {
                t.Fatal(err)
            }

            err = tt.operation(m)
            if (err != nil) != tt.wantError {
                t.Errorf("operation error = %v, wantError %v", err, tt.wantError)
            }
        })
    }
}
```

## Test Organization

Tests are organized by feature:

```txt
internal/modules/file/
├── module.go
├── module_test.go
├── get.go
├── get_test.go
├── set.go
├── set_test.go
├── test.go
└── test_test.go
```

## Test Dependencies

Test dependencies are managed using interfaces:

```go
// TestDependency defines a test dependency.
type TestDependency interface {
    // Setup sets up the dependency.
    Setup() error

    // Cleanup cleans up the dependency.
    Cleanup() error
}

// TestEnvironment represents a test environment.
type TestEnvironment struct {
    // Dependencies are the test dependencies.
    Dependencies []TestDependency

    // Cleanup functions to run after the test.
    cleanup []func()
}

// NewTestEnvironment creates a new test environment.
func NewTestEnvironment(t *testing.T) *TestEnvironment {
    env := &TestEnvironment{
        Dependencies: make([]TestDependency, 0),
        cleanup:      make([]func(), 0),
    }

    t.Cleanup(func() {
        env.Cleanup()
    })

    return env
}

// AddDependency adds a dependency to the environment.
func (e *TestEnvironment) AddDependency(d TestDependency) error {
    if err := d.Setup(); err != nil {
        return err
    }

    e.Dependencies = append(e.Dependencies, d)
    e.cleanup = append(e.cleanup, func() {
        d.Cleanup()
    })

    return nil
}

// Cleanup cleans up the environment.
func (e *TestEnvironment) Cleanup() {
    for i := len(e.cleanup) - 1; i >= 0; i-- {
        e.cleanup[i]()
    }
}
```

## Test Mocks

Test mocks are generated using interfaces:

```go
//go:generate mockgen -destination=mock_module.go -package=file . Module

// Module defines the interface for modules.
type Module interface {
    // Get returns the current configuration.
    Get(ctx context.Context, req *GetRequest) (*GetResponse, error)

    // Set configures the resource.
    Set(ctx context.Context, req *SetRequest) (*SetResponse, error)

    // Test validates the configuration.
    Test(ctx context.Context, req *TestRequest) (*TestResponse, error)
}
```

## Testing Environments

CFGMS uses different testing environments with different mocking policies:

### Development Environment

- **Purpose**: Rapid development and feedback
- **Mocking**: Allowed and encouraged for faster development
- **Frequency**: Run on every code change
- **Scope**: Unit tests and some integration tests

### Staging Environment

- **Purpose**: Pre-release validation
- **Mocking**: Limited mocking, primarily for external dependencies
- **Frequency**: Run on every pull request to develop branch
- **Scope**: Integration tests and some end-to-end tests

### Release Candidate Environment

- **Purpose**: Final validation before release
- **Mocking**: No mocking allowed - must use real dependencies
- **Frequency**: Run on every release candidate
- **Scope**: All tests, including comprehensive end-to-end tests

### Production Environment

- **Purpose**: Ongoing validation of production systems
- **Mocking**: No mocking allowed
- **Frequency**: Run periodically and after deployments
- **Scope**: Smoke tests and critical path validation

## GitFlow Release Process

CFGMS follows the GitFlow branching model for releases. Here's the process for going from development to a full release:

### Development Phase

1. **Feature Development**:
   - Create feature branch from `develop`: `feature/feature-name`
   - Develop and test with mocking allowed
   - Create pull request to `develop`

2. **Integration**:
   - Code review and automated tests
   - Merge to `develop` when approved
   - Continuous integration on `develop` branch

### Release Candidate Phase

1. **Release Branch Creation**:
   - Create release branch from `develop`: `release/v1.2.0`
   - No new features, only bug fixes and documentation
   - Version bump and changelog updates

2. **Release Candidate Testing**:
   - Run all tests with real dependencies (no mocking)
   - Fix any issues found
   - Create release candidate tag: `v1.2.0-rc.1`

3. **Release Candidate Validation**:
   - Deploy to staging environment
   - Run comprehensive end-to-end tests
   - Address any issues found
   - Create additional release candidates if needed: `v1.2.0-rc.2`

### Production Release

1. **Final Release**:
   - When release candidate passes all tests
   - Create final release tag: `v1.2.0`
   - Merge release branch to `main` and `develop`
   - Deploy to production

2. **Post-Release**:
   - Monitor production systems
   - Address any critical issues with hotfix branches
   - Begin development of next release

## Branch Roles

- **`main`**: Always reflects the most recent stable release
- **`develop`**: Integration branch for features
- **`feature/*`**: Individual feature branches
- **`release/*`**: Release preparation branches
- **`hotfix/*`**: Critical production fix branches

## Test Coverage

Test coverage is maintained using:

1. **Unit Test Coverage**: Coverage of individual components
2. **Integration Test Coverage**: Coverage of system behavior
3. **Performance Test Coverage**: Coverage of performance requirements
4. **Security Test Coverage**: Coverage of security requirements

## Test Best Practices

CFGMS follows these best practices for testing:

1. **Write Tests First**: Write tests before implementation
2. **Use Table-Driven Tests**: Use table-driven tests where appropriate
3. **Selective Mocking**: Mock dependencies for development tests but not for release candidates
4. **Maintain High Coverage**: Maintain high test coverage
5. **Test Edge Cases**: Test edge cases and error conditions
6. **Test Performance**: Test performance requirements
7. **Test Security**: Test security requirements
8. **Document Tests**: Document test cases and requirements
9. **Real-World Validation**: Release candidates must be tested against real systems

## Version Information

- **Version**: 1.0
- **Last Updated**: 2024-04-07
- **Status**: Draft
