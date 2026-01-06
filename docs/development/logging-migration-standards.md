# CFGMS Logging Provider Migration Standards

## Overview

This document defines the standards for migrating all CFGMS modules and packages to use the global logging provider system (Story #166). The migration ensures consistent structured logging, proper tenant isolation, and standardized field formatting across the entire codebase.

## Structured Logging Field Standards

### Core Required Fields

All log entries MUST include these standardized fields:

#### Service Identification

- `service_name`: Service identifier ("controller", "steward", "cfg")
- `component`: Component within service (e.g., "rbac", "workflow", "dna")
- `module`: Specific module name (e.g., "script", "firewall", "m365")

#### Multi-Tenant Context

- `tenant_id`: Tenant identifier for multi-tenant isolation (REQUIRED for tenant-scoped operations)
- `session_id`: Session identifier for tracking user sessions
- `correlation_id`: Request correlation for distributed tracing

#### Operational Context

- `operation`: High-level operation being performed (e.g., "config_apply", "script_execute", "user_create")
- `resource_id`: Specific resource being operated on (e.g., device ID, user ID)
- `resource_type`: Type of resource (e.g., "device", "user", "configuration")

### Level-Specific Field Requirements

#### ERROR and FATAL Levels

- `error_code`: Standardized error code (e.g., "AUTH_FAILED", "CONFIG_INVALID")
- `error_details`: Additional error context
- `recovery_action`: Suggested recovery action if available

#### INFO Level (for significant operations)

- `duration_ms`: Operation duration in milliseconds
- `status`: Operation status ("started", "completed", "failed")

#### DEBUG Level

- `function`: Function/method name being executed
- `step`: Current step in multi-step operations

### Tenant Isolation Requirements

#### MUST Requirements

- Log entries MUST NOT contain data from other tenants
- Cross-tenant operations MUST use separate log entries per tenant
- Tenant ID MUST be validated before logging tenant-specific data

#### Example Tenant-Safe Logging

```go
// CORRECT: Separate log entries per tenant
for _, tenant := range tenants {
    logger.WithTenant(tenant.ID).Info("Processing configuration",
        "operation", "config_apply",
        "config_count", len(tenant.Configs))
}

// INCORRECT: Cross-tenant data in single log entry
logger.Info("Processing configurations",
    "tenant_configs", tenantConfigMap) // Contains multiple tenants
```

## Migration Strategy

### Phase 1: Core Service Migration

1. Update main service entry points (cmd/controller, cmd/steward)
2. Initialize global logging provider with proper configuration
3. Replace direct logging.NewLogger() calls with logging.ForComponent()

### Phase 2: Module Migration

1. Replace logger initialization in modules with dependency injection
2. Update all logging calls to use structured fields
3. Add proper tenant context extraction

### Phase 3: Package Migration

1. Update shared packages (pkg/*) to use global provider
2. Ensure no direct logging initialization in packages
3. Use logging.ForComponent() for package-specific logging

### Phase 4: Validation & Testing

1. Audit all log outputs for structured format compliance
2. Test tenant isolation under load
3. Validate performance impact

## Implementation Patterns

### Module Logger Initialization

```go
// OLD PATTERN (to be replaced)
type Module struct {
    logger logging.Logger // Remove this
}

func NewModule() *Module {
    return &Module{
        logger: logging.NewLogger("info"), // Remove this
    }
}

// NEW PATTERN (required)
type Module struct {
    logger *logging.ModuleLogger
}

func NewModule() *Module {
    return &Module{
        logger: logging.ForModule("script").WithComponent("executor"),
    }
}
```

### Tenant-Aware Logging

```go
// Extract tenant from context and use structured logging
func (m *Module) ProcessResource(ctx context.Context, resourceID string) error {
    tenantID := extractTenantFromContext(ctx)
    logger := m.logger.WithTenant(tenantID)

    logger.InfoCtx(ctx, "Starting resource processing",
        "operation", "resource_process",
        "resource_id", resourceID,
        "resource_type", "script")

    // ... processing logic ...

    if err != nil {
        logger.ErrorCtx(ctx, "Resource processing failed",
            "operation", "resource_process",
            "resource_id", resourceID,
            "error_code", "EXECUTION_FAILED",
            "error_details", err.Error())
        return err
    }

    logger.InfoCtx(ctx, "Resource processing completed",
        "operation", "resource_process",
        "resource_id", resourceID,
        "status", "completed")

    return nil
}
```

### Service-Level Configuration

```go
// In main.go files, initialize global logging before creating services
func main() {
    // Initialize global logging provider
    loggingConfig := &logging.LoggingConfig{
        Provider:        "file", // or "timescale" for production
        Level:          "INFO",
        ServiceName:     "controller", // or "steward", "cfg"
        Component:       "main",
        TenantIsolation: true,
        EnableCorrelation: true,
        EnableTracing:   true,
    }

    if err := logging.InitializeGlobalLogging(loggingConfig); err != nil {
        log.Fatalf("Failed to initialize global logging: %v", err)
    }

    // Initialize global logger factory
    logging.InitializeGlobalLoggerFactory("controller", "main")

    // Use global logging provider for service creation
    logger := logging.ForComponent("controller")

    // ... rest of service initialization
}
```

## Testing Requirements

### Unit Tests

- Verify structured field format compliance
- Test tenant isolation boundaries
- Validate log level filtering
- Ensure no cross-tenant information leakage

### Integration Tests

- End-to-end logging flow testing
- Multi-tenant scenario validation
- Performance impact measurement
- Provider fallback behavior

### Audit Requirements

- All log outputs must be audited for compliance
- Cross-tenant data leakage detection
- Structured field completeness verification

## Performance Considerations

### Optimization Guidelines

- Use async writes for high-volume logging
- Implement proper log level filtering
- Cache logger instances where appropriate
- Use structured fields efficiently

### Monitoring

- Track logging performance metrics
- Monitor provider availability
- Alert on tenant isolation violations

## Compliance Notes

This migration supports Story #166 acceptance criteria:

1. ✅ **Module Migration**: All features/ modules use injected logging provider
2. ✅ **Package Migration**: All pkg/ packages use global logging provider
3. ✅ **Service Migration**: Controller, Steward services use global provider
4. ✅ **Structured Fields**: Consistent fields (tenant_id, session_id, component, operation)
5. ✅ **Tenant Isolation**: Log entries respect tenant boundaries
6. ✅ **Log Levels**: Proper levels (ERROR, WARN, INFO, DEBUG) with filtering

## Migration Checklist

### For Each Module/Package

- [ ] Replace direct logger initialization with global provider
- [ ] Add structured field support
- [ ] Implement tenant context extraction
- [ ] Update all logging calls to use structured format
- [ ] Add appropriate log levels and filtering
- [ ] Write unit tests for logging behavior
- [ ] Validate tenant isolation compliance

### For Services

- [ ] Initialize global logging provider in main()
- [ ] Configure appropriate provider (file/timescale)
- [ ] Set up global logger factory
- [ ] Update service components to use global provider

### For Integration

- [ ] End-to-end logging flow testing
- [ ] Performance impact validation
- [ ] Multi-tenant scenario testing
- [ ] Provider failover testing
