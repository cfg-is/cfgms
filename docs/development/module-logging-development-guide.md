# Module Logging Development Guide

This guide provides comprehensive instructions for developing CFGMS modules that support the centralized logging system through interface-based logging injection.

## Overview

CFGMS uses an interface-based logging injection pattern that:
- Preserves module binary signatures and application allowlisting
- Enables centralized logging collection and monitoring
- Maintains backward compatibility with existing modules
- Provides secure, transparent logging injection

## Quick Start for New Modules

### 1. Basic Module Structure

```go
package mymodule

import (
    "context"
    "github.com/cfgis/cfgms/features/modules"
    "github.com/cfgis/cfgms/pkg/logging"
)

// myModule implements the Module interface with logging injection support
type myModule struct {
    // Embed default logging support for automatic injection capability
    modules.DefaultLoggingSupport

    // Add your module-specific fields here
    config *MyModuleConfig
}

// New creates a new instance of your module
func New() modules.Module {
    return &myModule{
        config: &MyModuleConfig{},
    }
}
```

### 2. Adding Structured Logging to Operations

```go
// Set implements the module's configuration operation
func (m *myModule) Set(ctx context.Context, resourceID string, config modules.ConfigState) error {
    // Get effective logger (injected or fallback)
    logger := m.GetEffectiveLogger(logging.ForModule("mymodule"))
    tenantID := logging.ExtractTenantFromContext(ctx)

    logger.InfoCtx(ctx, "Starting module operation",
        "operation", "mymodule_set",
        "resource_id", resourceID,
        "tenant_id", tenantID,
        "resource_type", "mymodule")

    // Your implementation here...

    if err := m.validateConfig(config); err != nil {
        logger.ErrorCtx(ctx, "Configuration validation failed",
            "operation", "mymodule_set",
            "resource_id", resourceID,
            "error_code", "CONFIG_VALIDATION_FAILED",
            "error_details", err.Error())
        return err
    }

    // Success logging
    logger.InfoCtx(ctx, "Module operation completed successfully",
        "operation", "mymodule_set",
        "resource_id", resourceID,
        "status", "completed")

    return nil
}
```

## Logging Best Practices

### Required Structured Fields

All log entries should include these standardized fields:

- `operation`: High-level operation being performed (e.g., "mymodule_set", "mymodule_get")
- `resource_id`: The resource being operated on
- `tenant_id`: Extracted from context for multi-tenant isolation
- `resource_type`: Type of resource (module name)

### Error Logging Standards

For errors, include these additional fields:

- `error_code`: Standardized error code (e.g., "CONFIG_VALIDATION_FAILED")
- `error_details`: Detailed error message for debugging

### Common Error Codes

Use these standardized error codes:

- `CONFIG_VALIDATION_FAILED`: Configuration validation errors
- `RESOURCE_NOT_FOUND`: When a resource doesn't exist
- `PERMISSION_DENIED`: Permission or access errors
- `NETWORK_ERROR`: Network connectivity issues
- `EXTERNAL_SERVICE_ERROR`: External service integration errors
- `INTERNAL_ERROR`: Unexpected internal errors

## Advanced Patterns

### Custom Logger Configuration

If you need more control over logging configuration:

```go
// customModule implements both Module and LoggingInjectable interfaces
type customModule struct {
    logger interfaces.Logger
    config *CustomConfig
}

// SetLogger implements LoggingInjectable
func (m *customModule) SetLogger(logger interfaces.Logger) error {
    if logger == nil {
        return fmt.Errorf("logger cannot be nil")
    }

    // Add module-specific context
    m.logger = logger.WithField("component", "custom")
    return nil
}

// GetLogger implements LoggingInjectable
func (m *customModule) GetLogger() (interfaces.Logger, bool) {
    return m.logger, m.logger != nil
}

func (m *customModule) Set(ctx context.Context, resourceID string, config modules.ConfigState) error {
    // Use injected logger or fallback
    logger := m.logger
    if logger == nil {
        logger = logging.ForModule("custom") // Fallback
    }

    // Your implementation...
}
```

### Component-Level Logging

For modules with multiple components:

```go
type complexModule struct {
    modules.DefaultLoggingSupport

    processor *Processor
    validator *Validator
}

func (m *complexModule) initializeComponents() {
    // Get the injected logger or fallback
    baseLogger := m.GetEffectiveLogger(logging.ForModule("complex"))

    // Create component-specific loggers
    m.processor = NewProcessor(baseLogger.WithField("component", "processor"))
    m.validator = NewValidator(baseLogger.WithField("component", "validator"))
}
```

## Security Considerations

### Tenant Isolation

Always extract tenant information from context:

```go
tenantID := logging.ExtractTenantFromContext(ctx)
if tenantID == "" {
    logger.WarnCtx(ctx, "No tenant ID in context",
        "operation", "mymodule_set",
        "resource_id", resourceID,
        "security_warning", "missing_tenant_context")
}
```

### Sensitive Data Protection

Never log sensitive information:

```go
// GOOD: Log operation details without sensitive data
logger.InfoCtx(ctx, "Authentication successful",
    "operation", "auth_login",
    "user_id", userID,
    "auth_method", "oauth2")

// BAD: Don't log passwords, tokens, or secrets
// logger.DebugCtx(ctx, "Auth token", "token", authToken) // DON'T DO THIS
```

## Testing Your Module

### Unit Testing with Mock Loggers

```go
func TestMyModule_Set(t *testing.T) {
    // Create module
    module := New().(*myModule)

    // Create mock logger
    mockLogger := &testing.MockLogger{}

    // Inject logger
    err := module.SetLogger(mockLogger)
    require.NoError(t, err)

    // Test operations
    ctx := context.Background()
    ctx = logging.WithTenant(ctx, "test-tenant")

    err = module.Set(ctx, "test-resource", &TestConfig{})
    require.NoError(t, err)

    // Verify logging calls
    mockLogger.AssertLoggedInfo(t, "Starting module operation")
    mockLogger.AssertLoggedInfo(t, "Module operation completed successfully")
}
```

### Integration Testing

Test that your module works with the actual factory:

```go
func TestModuleWithFactory(t *testing.T) {
    // Create factory
    registry := discovery.ModuleRegistry{
        "mymodule": {Name: "mymodule", Path: "/path/to/module"},
    }
    factory := factory.NewWithStewardID(registry, config.ErrorHandlingConfig{}, "test-steward")

    // Load module
    module, err := factory.LoadModule("mymodule")
    require.NoError(t, err)

    // Verify logger injection
    injectable, ok := module.(modules.LoggingInjectable)
    require.True(t, ok, "module should support logging injection")

    logger, injected := injectable.GetLogger()
    require.True(t, injected, "logger should be injected")
    require.NotNil(t, logger, "injected logger should not be nil")
}
```

## Migration Guide for Existing Modules

### Step 1: Add Logging Support

Add the DefaultLoggingSupport to your module struct:

```go
type existingModule struct {
    // Add this line
    modules.DefaultLoggingSupport

    // Keep existing fields
    existingField string
}
```

### Step 2: Update Operations

Add logging to your Set and Get methods:

```go
func (m *existingModule) Set(ctx context.Context, resourceID string, config modules.ConfigState) error {
    // Add these lines at the beginning
    logger := m.GetEffectiveLogger(logging.ForModule("existing"))
    tenantID := logging.ExtractTenantFromContext(ctx)

    logger.InfoCtx(ctx, "Starting operation",
        "operation", "existing_set",
        "resource_id", resourceID,
        "tenant_id", tenantID,
        "resource_type", "existing")

    // Keep existing implementation...

    // Add success logging at the end
    logger.InfoCtx(ctx, "Operation completed successfully",
        "operation", "existing_set",
        "resource_id", resourceID,
        "status", "completed")

    return nil
}
```

### Step 3: Add Error Logging

Update error handling to include structured logging:

```go
if err := someOperation(); err != nil {
    logger.ErrorCtx(ctx, "Operation failed",
        "operation", "existing_set",
        "resource_id", resourceID,
        "error_code", "OPERATION_FAILED",
        "error_details", err.Error())
    return fmt.Errorf("operation failed: %w", err)
}
```

## Monitoring and Debugging

### Logger Injection Status

Check if your module successfully received logger injection:

```go
func (m *myModule) GetInjectionStatus() map[string]interface{} {
    logger, injected := m.GetLogger()
    return map[string]interface{}{
        "has_injected_logger": injected,
        "logger_type": fmt.Sprintf("%T", logger),
        "fallback_active": !injected,
    }
}
```

### Central Logging Verification

The steward provides monitoring of logger injection:

```go
// In steward/factory
statuses := factory.ListModulesWithLoggers()
for moduleName, status := range statuses {
    fmt.Printf("Module %s: injected=%v, supports=%v\n",
        moduleName, status.Injected, status.SupportsInject)
}
```

## Troubleshooting

### Common Issues

1. **Logger Not Injected**: Ensure your module embeds `modules.DefaultLoggingSupport`
2. **Missing Context Fields**: Always extract tenant ID from context
3. **Inconsistent Field Names**: Use standardized field names (operation, resource_id, etc.)
4. **Sensitive Data Logged**: Review logs for passwords, tokens, or other secrets

### Debug Logging

Enable debug logging to see injection details:

```go
logger.DebugCtx(ctx, "Logger injection debug info",
    "has_injected_logger", m.HasInjectedLogger(),
    "logger_type", fmt.Sprintf("%T", m.GetEffectiveLogger(nil)),
    "module_name", "mymodule")
```

## Performance Considerations

### Async Logging

The global logging provider uses async writes by default:

- Minimal performance impact on module operations
- Automatic batching for high-volume scenarios
- Graceful fallback if logging fails

### Field Optimization

Use consistent field names to enable provider optimizations:

```go
// Preferred: Consistent field names
logger.InfoCtx(ctx, "Operation started",
    "operation", "module_set",
    "resource_id", resourceID)

// Avoid: Inconsistent or dynamic field names
logger.InfoCtx(ctx, "Operation started",
    fmt.Sprintf("op_%s", moduleName), "set",
    "id_" + resourceType, resourceID)
```

## Examples

See these modules for reference implementations:

- `features/modules/directory/` - Basic logging integration
- `features/modules/file/` - File operations with error logging
- `features/modules/script/` - Complex module with audit logging
- `features/modules/firewall/` - Network operations logging

## Support

For questions or issues with module logging:

1. Check existing module implementations
2. Review the logging migration standards
3. Test with the provided test utilities
4. Monitor injection status through the factory

The centralized logging system ensures that all module operations are visible to the controller for complete operational transparency and debugging capability.