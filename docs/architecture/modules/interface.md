# Module Interface

This document details the standard interface that all modules in CFGMS must implement.

## Overview

The module interface provides a consistent way for CFGMS to interact with modules, ensuring that all modules behave in a predictable and reliable manner. The interface is designed to be simple yet powerful, allowing modules to be developed independently and integrated seamlessly into the CFGMS workflow.

For information about module lifecycle management, see [Module Lifecycle](lifecycle.md).
For information about module security requirements, see [Module Security Requirements](security.md).
For information about module testing requirements, see [Module Testing Requirements](testing.md).

## Core Interface

All modules must implement the following core interface:

```go
// Module is the interface that all CFGMS modules must implement
type Module interface {
    // Get returns the current Configuration of the Resource
    Get(ctx context.Context, resourceID string) (Configuration, error)
    
    // Set updates the Resource Configuration to match the Configuration-Data specification
    Set(ctx context.Context, resourceID string, config Configuration) error
    
    // Test validates if the current Configuration matches the Configuration-Data specification
    Test(ctx context.Context, resourceID string, config Configuration) (bool, TestResult, error)
    
    // Monitor (optional) implements event-driven or system hook-based monitoring
    Monitor(ctx context.Context, resourceID string, config Configuration) (Monitor, error)
}
```

### Get Method

The `Get` method retrieves the current configuration of a resource.

```go
// Get returns the current Configuration of the Resource
Get(ctx context.Context, resourceID string) (Configuration, error)
```

**Parameters:**

- `ctx`: Context for cancellation and timeout
- `resourceID`: Unique identifier for the resource

**Returns:**

- `Configuration`: The current configuration of the resource
- `error`: Any error that occurred during the operation

**Behavior:**

- Must return the current state of the resource as a Configuration object
- Should handle errors gracefully and return meaningful error messages
- Should be idempotent (multiple calls should return the same result)

### Set Method

The `Set` method updates the configuration of a resource to match the specified configuration.

```go
// Set updates the Resource Configuration to match the Configuration-Data specification
Set(ctx context.Context, resourceID string, config Configuration) error
```

**Parameters:**

- `ctx`: Context for cancellation and timeout
- `resourceID`: Unique identifier for the resource
- `config`: The desired configuration for the resource

**Returns:**

- `error`: Any error that occurred during the operation

**Behavior:**

- Must update the resource to match the specified configuration
- Should be idempotent (multiple calls with the same configuration should produce the same result)
- Should handle errors gracefully and return meaningful error messages
- Should validate the configuration before applying it
- Should implement rollback mechanisms for failed operations

### Test Method

The `Test` method validates if the current configuration of a resource matches the specified configuration.

```go
// Test validates if the current Configuration matches the Configuration-Data specification
Test(ctx context.Context, resourceID string, config Configuration) (bool, TestResult, error)
```

**Parameters:**

- `ctx`: Context for cancellation and timeout
- `resourceID`: Unique identifier for the resource
- `config`: The configuration to test against

**Returns:**

- `bool`: Whether the current configuration matches the specified configuration
- `TestResult`: Detailed information about the test result
- `error`: Any error that occurred during the operation

**Behavior:**

- Must call the `Get` method to retrieve the current configuration
- Must compare the current configuration with the specified configuration
- Should return true if all settings specified in the configuration are present in the current configuration
- It is acceptable if the current configuration contains additional settings not specified in the configuration
- Should provide detailed information about any discrepancies
- Should be idempotent (multiple calls should return the same result)
- Should handle errors gracefully and return meaningful error messages
- Should not re-implement a light version of the Get method

### Monitor Method (Optional)

The `Monitor` method sets up monitoring for a resource.

```go
// Monitor (optional) implements event-driven or system hook-based monitoring
Monitor(ctx context.Context, resourceID string, config Configuration) (Monitor, error)
```

**Parameters:**

- `ctx`: Context for cancellation and timeout
- `resourceID`: Unique identifier for the resource
- `config`: The configuration for the resource

**Returns:**

- `Monitor`: A monitor that can be used to detect changes in the resource
- `error`: Any error that occurred during the operation

**Behavior:**

- Must set up monitoring for the resource based on the specified configuration
- Should return a Monitor that can be used to detect changes in the resource
- Should handle errors gracefully and return meaningful error messages
- Should be idempotent (multiple calls should return the same result)

## Supporting Types

### Configuration

The `Configuration` type represents the configuration of a resource.

```go
// Configuration represents the configuration of a resource
type Configuration interface {
    // Validate validates the configuration
    Validate() error
    
    // ToYAML converts the configuration to YAML
    ToYAML() ([]byte, error)
    
    // FromYAML creates a configuration from YAML
    FromYAML(data []byte) error
}
```

### TestResult

The `TestResult` type provides detailed information about the result of a test.

```go
// TestResult provides detailed information about the result of a test
type TestResult interface {
    // IsCompliant returns whether the resource is compliant with the configuration
    IsCompliant() bool
    
    // GetDiscrepancies returns a list of discrepancies between the current and desired configurations
    GetDiscrepancies() []Discrepancy
    
    // ToYAML converts the test result to YAML
    ToYAML() ([]byte, error)
}
```

### Monitor

The `Monitor` type is used to detect changes in a resource.

```go
// Monitor is used to detect changes in a resource
type Monitor interface {
    // Start starts the monitor
    Start(ctx context.Context) error
    
    // Stop stops the monitor
    Stop(ctx context.Context) error
    
    // GetEvents returns a channel that receives events from the monitor
    GetEvents() <-chan Event
}
```

## Error Handling

Modules should use the standard error types defined by CFGMS:

```go
// ModuleError represents an error that occurred in a module
type ModuleError struct {
    // Module is the name of the module that encountered the error
    Module string
    
    // ResourceID is the ID of the resource that encountered the error
    ResourceID string
    
    // Operation is the operation that encountered the error
    Operation string
    
    // Message is a human-readable message describing the error
    Message string
    
    // Cause is the underlying error
    Cause error
}

// Error returns a string representation of the error
func (e *ModuleError) Error() string {
    return fmt.Sprintf("%s: %s: %s: %s", e.Module, e.ResourceID, e.Operation, e.Message)
}

// Unwrap returns the underlying error
func (e *ModuleError) Unwrap() error {
    return e.Cause
}
```

## Context Usage

Modules should use the provided context for cancellation and timeout:

- Use `ctx.Done()` to detect cancellation
- Use `ctx.Err()` to check for errors
- Use `context.WithTimeout` to set timeouts for operations
- Use `context.WithValue` to pass values through the context

## Best Practices

1. **Idempotency**
   - Ensure that all operations are idempotent
   - Handle repeated calls gracefully

2. **Error Handling**
   - Use the standard error types
   - Provide meaningful error messages
   - Include context in error messages

3. **Validation**
   - Validate all inputs before processing
   - Return clear validation errors

4. **Logging**
   - Use structured logging
   - Include relevant context in log messages
   - Log at appropriate levels

5. **Performance**
   - Optimize for common operations
   - Use caching where appropriate
   - Minimize resource usage

## Related Documentation

- [Module Lifecycle](lifecycle.md): How modules are loaded, initialized, and managed
- [Module Core Principles](core-principles.md): Fundamental principles that guide module design
- [Module Security Requirements](security.md): Security considerations for module implementation
- [Module Testing Requirements](testing.md): Testing standards and requirements for modules

## Version Information

- **Document Version:** 1.0
- **Last Updated:** 2024-04-04
- **Status:** Draft
