# CFGMS Logging Architecture Guide

This guide explains the CFGMS logging architecture and how to use the global logging provider system in your code.

## Overview

CFGMS uses a centralized logging provider system that ensures:

- **Structured Logging**: Consistent field formats across all components
- **Tenant Isolation**: Logs respect multi-tenant boundaries
- **Context Awareness**: Automatic extraction of tenant, session, and operation context
- **Provider Flexibility**: Support for multiple backend providers (file, TimescaleDB)

## Architecture

### Components

1. **Global Logging Provider** (`pkg/logging/`)
   - Central logging hub with pluggable backends
   - Automatic context extraction
   - Structured field management

2. **Context Utilities** (`pkg/logging/context_keys.go`)
   - Shared context keys for consistent logging
   - Helper functions for context manipulation

3. **Logger Factory** (`pkg/logging/manager.go`)
   - Creates loggers for components and modules
   - Handles provider initialization and configuration

## Using the Logging System

### Initializing Logging (Service Startup)

In your service's main function (e.g., `cmd/controller/main.go`, `cmd/steward/main.go`):

```go
import "github.com/cfg-is/cfgms/pkg/logging"

// Initialize global logging provider
loggingConfig := &logging.LoggingConfig{
    Provider:          "file", // or "timescale"
    Level:             "INFO",
    ServiceName:       "controller",
    Component:         "main",
    TenantIsolation:   true,
    EnableCorrelation: true,
    EnableTracing:     true,
}

logging.InitializeGlobalLogging(loggingConfig)
logging.InitializeGlobalLoggerFactory("controller", "main")
```

### Creating a Logger

For components:

```go
logger := logging.ForComponent("authentication")
```

For modules:

```go
logger := logging.ForModule("script")
```

### Logging with Context

**Always use context-aware logging methods** to enable tenant isolation and operation tracking:

```go
// Error logging with context
logger.ErrorCtx(ctx, "Failed to execute operation",
    "operation", "script_execute",
    "resource_id", resourceID,
    "error_code", "EXEC_FAILED",
    "error", err.Error())

// Info logging with context
logger.InfoCtx(ctx, "Operation completed successfully",
    "operation", "config_apply",
    "resource_id", resourceID,
    "duration_ms", elapsed.Milliseconds())

// Warning logging with context
logger.WarnCtx(ctx, "Retry attempt",
    "operation", "api_call",
    "attempt", retryCount,
    "max_attempts", maxRetries)
```

## Structured Logging Fields

### Required Fields by Log Level

**ERROR Level:**

- `operation`: High-level operation name
- `error_code`: Standardized error code
- `error`: Error message
- `resource_id`: Affected resource (if applicable)

**WARN Level:**

- `operation`: High-level operation name
- Context-specific fields explaining the warning

**INFO Level:**

- `operation`: High-level operation name
- Relevant operational metrics

**DEBUG Level:**

- Detailed debugging information
- Use sparingly in production

### Standard Field Names

Use these consistent field names across all logging:

- `tenant_id`: Multi-tenant isolation (auto-extracted from context)
- `session_id`: Session tracking (auto-extracted from context)
- `component`: Component identification
- `operation`: High-level operation tracking
- `resource_id`: Resource identification
- `error_code`: Standardized error codes
- `duration_ms`: Operation duration in milliseconds

## Context Management

### Adding Context Information

Use helper functions to add information to context:

```go
import "github.com/cfg-is/cfgms/pkg/logging"

// Add tenant to context
ctx = logging.WithTenant(ctx, tenantID)

// Add session to context
ctx = logging.WithSession(ctx, sessionID)

// Add operation to context
ctx = logging.WithOperation(ctx, "config_apply")
```

### Extracting Context Information

```go
// Extract tenant from context
tenantID := logging.ExtractTenantFromContext(ctx)

// Extract session from context
sessionID := logging.ExtractSessionFromContext(ctx)

// Extract operation from context
operation := logging.ExtractOperationFromContext(ctx)
```

## Migration Patterns

### Before (Old Style)

```go
// No structured logging
fmt.Printf("Failed to log script execution audit: %v\n", auditErr)

// Using standard library logger
log.Println("Processing configuration for tenant", tenantID)
```

### After (Current Style)

```go
// Structured logging with context
logger.WarnCtx(ctx, "Failed to log script execution audit",
    "operation", "script_execute",
    "resource_id", resourceID,
    "error_code", "AUDIT_LOG_FAILED",
    "audit_error", auditErr.Error())

// Structured info logging
logger.InfoCtx(ctx, "Processing configuration",
    "operation", "config_apply",
    "resource_count", len(resources))
```

## Best Practices

### DO

- ✅ Always use `*Ctx()` methods with context
- ✅ Use consistent field names across components
- ✅ Include `operation` field in all log entries
- ✅ Use structured fields instead of string interpolation
- ✅ Add tenant/session to context early in request lifecycle

### DON'T

- ❌ Use `fmt.Printf()` or `log.Println()` for operational logging
- ❌ Log sensitive information (passwords, tokens, PII)
- ❌ Use string interpolation in log messages
- ❌ Create component-specific logger interfaces
- ❌ Skip context when logging

## Tenant Isolation

The logging system automatically ensures tenant isolation:

- Logs include `tenant_id` extracted from context
- Provider backends can filter logs by tenant
- No cross-tenant information leakage
- Validation of tenant boundaries

## Provider Configuration

### File Provider

```yaml
logging:
  provider: file
  level: INFO
  file:
    path: /var/log/cfgms/
    max_size_mb: 100
    max_backups: 10
```

### TimescaleDB Provider

```yaml
logging:
  provider: timescale
  level: INFO
  timescale:
    host: localhost
    port: 5432
    database: cfgms_logs
    retention_days: 90
```

## Testing Logging

When writing tests, use the test logger:

```go
import "github.com/cfg-is/cfgms/pkg/logging/providers/memory"

func TestMyFeature(t *testing.T) {
    // Use memory provider for testing
    provider := memory.NewProvider()
    logger := logging.NewLoggerWithProvider(provider, "test-component")

    // Your test code...

    // Verify log entries
    entries := provider.GetEntries()
    assert.Equal(t, 1, len(entries))
    assert.Equal(t, "operation_complete", entries[0].Fields["operation"])
}
```

## Related Documentation

- [Logging Migration Standards](logging-migration-standards.md) - Detailed migration guidelines
- [Logging Dependency Injection Guide](logging-dependency-injection-guide.md) - Module injection patterns
- [Module Logging Development Guide](module-logging-development-guide.md) - Module-specific guidance

## Common Patterns

### Request Lifecycle Logging

```go
// Start of request
ctx = logging.WithTenant(ctx, tenantID)
ctx = logging.WithSession(ctx, sessionID)
ctx = logging.WithOperation(ctx, "api_request")

logger.InfoCtx(ctx, "Request received",
    "endpoint", r.URL.Path,
    "method", r.Method)

// During processing
logger.DebugCtx(ctx, "Validating input",
    "field_count", len(fields))

// End of request
logger.InfoCtx(ctx, "Request completed",
    "status_code", statusCode,
    "duration_ms", elapsed.Milliseconds())
```

### Error Handling with Logging

```go
result, err := performOperation(ctx, input)
if err != nil {
    logger.ErrorCtx(ctx, "Operation failed",
        "operation", "perform_operation",
        "error_code", "OP_FAILED",
        "error", err.Error(),
        "input_size", len(input))
    return nil, fmt.Errorf("operation failed: %w", err)
}

logger.InfoCtx(ctx, "Operation completed",
    "operation", "perform_operation",
    "result_size", len(result))
```

## Architecture Decision

See [Architecture Decision Records](../architecture/decisions/README.md) for the rationale behind the global logging provider approach.
