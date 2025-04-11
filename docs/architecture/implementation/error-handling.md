# Error Handling

This document describes the error handling approach used in CFGMS, explaining the principles, patterns, and best practices for handling errors.

## Error Handling Principles

CFGMS follows these principles for error handling:

1. **Explicit Error Handling**: All errors are handled explicitly
2. **Error Wrapping**: Errors are wrapped with context
3. **Structured Errors**: Errors are structured with fields
4. **Error Types**: Errors are typed for better handling
5. **Error Logging**: Errors are logged with appropriate context
6. **Error Recovery**: Errors are recovered from when possible
7. **Error Reporting**: Errors are reported to users in a user-friendly way

## Error Types

CFGMS defines several error types for different categories of errors:

### Base Error

The base error type is used for all errors in CFGMS:

```go
// Error represents an error in CFGMS.
type Error struct {
    // Code is the error code.
    Code string

    // Message is the error message.
    Message string

    // Cause is the underlying error.
    Cause error

    // Context is additional context about the error.
    Context map[string]interface{}

    // Stack is the stack trace.
    Stack string
}

// Error returns the error message.
func (e *Error) Error() string {
    return e.Message
}

// Unwrap returns the underlying error.
func (e *Error) Unwrap() error {
    return e.Cause
}
```

### Module Errors

Module errors are used for errors in modules:

```go
// ModuleError represents an error in a module.
type ModuleError struct {
    // Error is the base error.
    Error

    // Module is the name of the module.
    Module string

    // ResourceID is the ID of the resource.
    ResourceID string

    // Operation is the operation that failed.
    Operation string
}
```

### Configuration Errors

Configuration errors are used for errors in configuration:

```go
// ConfigurationError represents an error in configuration.
type ConfigurationError struct {
    // Error is the base error.
    Error

    // Path is the path of the configuration.
    Path string

    // Line is the line number of the error.
    Line int

    // Column is the column number of the error.
    Column int
}
```

### Workflow Errors

Workflow errors are used for errors in workflows:

```go
// WorkflowError represents an error in a workflow.
type WorkflowError struct {
    // Error is the base error.
    Error

    // Workflow is the name of the workflow.
    Workflow string

    // Step is the name of the step that failed.
    Step string
}
```

### Tenant Errors

Tenant errors are used for errors in tenant management:

```go
// TenantError represents an error in tenant management.
type TenantError struct {
    // Error is the base error.
    Error

    // TenantID is the ID of the tenant.
    TenantID string

    // Operation is the operation that failed.
    Operation string
}
```

## Error Creation

Errors are created using factory functions:

```go
// NewError creates a new error.
func NewError(code string, message string, cause error) *Error {
    return &Error{
        Code:    code,
        Message: message,
        Cause:   cause,
        Context: make(map[string]interface{}),
        Stack:   string(debug.Stack()),
    }
}

// NewModuleError creates a new module error.
func NewModuleError(module string, resourceID string, operation string, code string, message string, cause error) *ModuleError {
    return &ModuleError{
        Error: Error{
            Code:    code,
            Message: message,
            Cause:   cause,
            Context: make(map[string]interface{}),
            Stack:   string(debug.Stack()),
        },
        Module:     module,
        ResourceID: resourceID,
        Operation:  operation,
    }
}

// NewConfigurationError creates a new configuration error.
func NewConfigurationError(path string, line int, column int, code string, message string, cause error) *ConfigurationError {
    return &ConfigurationError{
        Error: Error{
            Code:    code,
            Message: message,
            Cause:   cause,
            Context: make(map[string]interface{}),
            Stack:   string(debug.Stack()),
        },
        Path:   path,
        Line:   line,
        Column: column,
    }
}

// NewWorkflowError creates a new workflow error.
func NewWorkflowError(workflow string, step string, code string, message string, cause error) *WorkflowError {
    return &WorkflowError{
        Error: Error{
            Code:    code,
            Message: message,
            Cause:   cause,
            Context: make(map[string]interface{}),
            Stack:   string(debug.Stack()),
        },
        Workflow: workflow,
        Step:     step,
    }
}

// NewTenantError creates a new tenant error.
func NewTenantError(tenantID string, operation string, code string, message string, cause error) *TenantError {
    return &TenantError{
        Error: Error{
            Code:    code,
            Message: message,
            Cause:   cause,
            Context: make(map[string]interface{}),
            Stack:   string(debug.Stack()),
        },
        TenantID: tenantID,
        Operation: operation,
    }
}
```

## Error Wrapping

Errors are wrapped with context using the `Wrap` function:

```go
// Wrap wraps an error with context.
func Wrap(err error, message string) error {
    if err == nil {
        return nil
    }

    var e *Error
    if errors.As(err, &e) {
        e.Message = message + ": " + e.Message
        return e
    }

    return &Error{
        Code:    "unknown",
        Message: message + ": " + err.Error(),
        Cause:   err,
        Context: make(map[string]interface{}),
        Stack:   string(debug.Stack()),
    }
}
```

## Error Handling Patterns

CFGMS uses several patterns for error handling:

### Early Return

The early return pattern is used to handle errors early:

```go
func (m *Module) Get(ctx context.Context, req *GetRequest) (*GetResponse, error) {
    if req == nil {
        return nil, NewModuleError(m.Name(), "", "get", "invalid_request", "request is nil", nil)
    }

    if req.ResourceID == "" {
        return nil, NewModuleError(m.Name(), "", "get", "invalid_request", "resource ID is empty", nil)
    }

    // ... rest of the function
}
```

### Error Checking

The error checking pattern is used to check for errors:

```go
func (m *Module) Set(ctx context.Context, req *SetRequest) (*SetResponse, error) {
    // ... function implementation

    if err != nil {
        return nil, Wrap(err, "failed to set configuration")
    }

    // ... rest of the function
}
```

### Error Recovery

The error recovery pattern is used to recover from errors:

```go
func (m *Module) Set(ctx context.Context, req *SetRequest) (*SetResponse, error) {
    // ... function implementation

    if err != nil {
        // Try to recover
        if err := m.recover(ctx, req.ResourceID); err != nil {
            return nil, Wrap(err, "failed to recover from error")
        }

        // Try again
        return m.Set(ctx, req)
    }

    // ... rest of the function
}
```

### Error Logging

The error logging pattern is used to log errors:

```go
func (m *Module) Set(ctx context.Context, req *SetRequest) (*SetResponse, error) {
    // ... function implementation

    if err != nil {
        log.Error("failed to set configuration", "module", m.Name(), "resource", req.ResourceID, "error", err)
        return nil, Wrap(err, "failed to set configuration")
    }

    // ... rest of the function
}
```

### Error Reporting

The error reporting pattern is used to report errors to users:

```go
func (m *Module) Set(ctx context.Context, req *SetRequest) (*SetResponse, error) {
    // ... function implementation

    if err != nil {
        return &SetResponse{
            Success: false,
            Message: "Failed to set configuration: " + err.Error(),
        }, nil
    }

    // ... rest of the function
}
```

## Error Codes

CFGMS uses error codes to categorize errors:

- **1000-1999**: General errors
- **2000-2999**: Module errors
- **3000-3999**: Configuration errors
- **4000-4999**: Workflow errors
- **5000-5999**: Tenant errors

## Error Handling Best Practices

CFGMS follows these best practices for error handling:

1. **Always Check Errors**: Always check errors returned by functions
2. **Wrap Errors**: Wrap errors with context using the `Wrap` function
3. **Use Error Types**: Use appropriate error types for different categories of errors
4. **Log Errors**: Log errors with appropriate context
5. **Recover from Errors**: Recover from errors when possible
6. **Report Errors**: Report errors to users in a user-friendly way
7. **Use Error Codes**: Use error codes to categorize errors
8. **Document Errors**: Document errors in function signatures and comments

## Version Information

- **Version**: 1.0
- **Last Updated**: 2024-04-07
- **Status**: Draft
