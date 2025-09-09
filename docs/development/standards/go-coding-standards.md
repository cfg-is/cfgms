# Go Coding Standards

This document outlines the coding standards for Go code in CFGMS.

## Overview

These standards ensure consistency, readability, and maintainability of Go code in CFGMS. They are based on Go best practices and the specific requirements of CFGMS.

## General Principles

- **Readability**: Code should be easy to read and understand.
- **Maintainability**: Code should be easy to maintain and extend.
- **Consistency**: Code should be consistent with the rest of the codebase.
- **Simplicity**: Code should be as simple as possible, but no simpler.
- **Documentation**: Code should be well-documented.

## Code Organization

### Package Structure

- Organize code by feature, not technical layer.
- Keep all feature code (implementation, tests, errors, interfaces) in a single package.
- Use `internal/` for private implementations.
- Use `pkg/` for public APIs.

### File Organization

- One file per type or small group of related types.
- Group related functions together.
- Keep files focused and concise.
- Use consistent file naming conventions.

### Import Order

1. Standard library imports
2. Third-party imports
3. Internal imports

Example:
```go
import (
    "context"
    "fmt"
    "time"

    "github.com/pkg/errors"
    "go.uber.org/zap"

    "github.com/cfgis/cfgms/internal/core"
    "github.com/cfgis/cfgms/pkg/api"
)
```

## Naming Conventions

### General

- Use descriptive names that reflect the purpose of the code.
- Avoid abbreviations unless they are widely understood.
- Use consistent naming patterns throughout the codebase.

### Packages

- Use lowercase, single-word names.
- Avoid underscores or mixed case.
- Use plural for packages that provide multiple related types.

### Types and Interfaces

- Use PascalCase for exported types and interfaces.
- Use camelCase for unexported types and interfaces.
- Use descriptive names that reflect the purpose of the type.
- Use `er` suffix for interfaces that define a single method.

### Functions and Methods

- Use PascalCase for exported functions and methods.
- Use camelCase for unexported functions and methods.
- Use descriptive names that reflect the purpose of the function.
- Use consistent verb-noun patterns for methods.

### Variables

- Use camelCase for variables.
- Use descriptive names that reflect the purpose of the variable.
- Use consistent naming patterns for similar variables.

### Constants

- Use PascalCase for exported constants.
- Use camelCase for unexported constants.
- Use descriptive names that reflect the purpose of the constant.
- Use consistent naming patterns for similar constants.

## Code Style

### Formatting

- Use `gofmt` to format code.
- Follow the standard Go formatting conventions.
- Use consistent indentation (4 spaces).
- Limit line length to 100 characters.

### Comments

- Use comments to explain why, not what.
- Use `//` for single-line comments.
- Use `/* */` for multi-line comments.
- Use `// TODO:` for TODO comments.
- Use `// FIXME:` for FIXME comments.

### Documentation

CFGMS requires comprehensive documentation for all Go code:

#### Package Documentation
- Every package must have a package comment explaining its purpose
- Include overview of key concepts and primary use cases
- Provide practical usage examples using Go's example testing pattern
- Document any package-level configuration or initialization requirements

#### Function and Method Documentation
- All exported functions and methods must have `godoc` comments starting with the function name
- Document all parameters including their types and expected values
- Document all return values including error conditions
- Explain any side effects or state changes
- Include usage examples for complex functions

#### Type Documentation
- All exported types must be documented with their purpose
- Document key fields and their relationships
- Explain any validation rules or constraints
- Document the lifecycle and proper usage patterns

#### Interface Documentation
- Clearly document interface contracts and expected behavior
- Document all method requirements and guarantees
- Explain implementation responsibilities and constraints
- Provide examples of correct implementations

#### Error Documentation
- Document all possible error conditions and their meanings
- Use custom error types with clear documentation
- Explain error handling strategies and recovery options

#### Examples and Testing
- Include runnable examples using Go's example testing pattern
- Examples should demonstrate real-world usage scenarios
- Test examples to ensure they remain current and functional

#### Implementation Documentation
- Document important design decisions and trade-offs
- Explain any non-obvious behavior or edge cases
- Document performance characteristics where relevant
- Include TODO comments for planned improvements with context

### Error Handling

- Use explicit error types and proper error wrapping.
- Use `errors.Wrap` to add context to errors.
- Use `errors.Cause` to extract the underlying error.
- Return errors, don't log them.
- Handle all errors explicitly, no bare returns.

### Logging

- Use structured logging with consistent fields.
- Use appropriate log levels (debug, info, warn, error).
- Include relevant context in log messages.
- Sanitize sensitive information in logs.

### Testing

- Write table-driven tests for all functions.
- Aim for 100% test coverage for core components.
- Use descriptive test names.
- Use subtests for complex test cases.
- Use test helpers for common test setup.

### Concurrency

- Use goroutines and channels for concurrency.
- Use `context.Context` for cancellation and timeout.
- Use mutexes for shared state.
- Avoid global variables or state.
- Use `sync.WaitGroup` for synchronization.

### Performance

- Profile code to identify performance bottlenecks.
- Optimize critical paths.
- Use appropriate data structures.
- Minimize allocations in hot paths.
- Use benchmarks to measure performance.

## Best Practices

### Dependency Injection

- Use dependency injection for dependencies.
- Use interfaces for dependencies.
- Pass dependencies as parameters.
- Avoid global variables or singletons.

### Configuration

- Use environment variables for configuration.
- Use configuration files for complex configuration.
- Use default values for optional configuration.
- Validate configuration at startup.

### Security

- Validate all input.
- Use secure defaults.
- Follow the principle of least privilege.
- Sanitize all output.
- Use secure communication protocols.

### Resilience

- Design for failure.
- Implement graceful degradation.
- Use circuit breakers for external dependencies.
- Implement retry mechanisms with backoff.
- Monitor and alert on failures.

## Tools

- Use `golangci-lint` for linting.
- Use `go vet` for static analysis.
- Use `go test` for testing.
- Use `go benchmark` for benchmarking.
- Use `go cover` for coverage analysis.

## Version Information
- **Document Version:** 1.0
- **Last Updated:** 2024-04-04
- **Status:** Draft 