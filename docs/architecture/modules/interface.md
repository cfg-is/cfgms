# Module Interface

This document defines the standard interface that all CFGMS modules must implement. The interface provides a consistent way for the system to interact with different types of modules while allowing each module to handle its specific resource type.

## Overview

The module interface provides a consistent way for CFGMS to interact with modules, ensuring that all modules behave in a predictable and reliable manner. The interface is designed to be simple yet powerful, allowing modules to be developed independently and integrated seamlessly into the CFGMS workflow.

For information about module lifecycle management, see [Module Lifecycle](lifecycle.md).
For information about module security requirements, see [Module Security Requirements](security.md).
For information about module testing requirements, see [Module Testing Requirements](testing.md).

## Core Interface

All modules must implement the following interface:

```go
package modules

import (
    "context"
)

// Module defines the core interface that all modules must implement
type Module interface {
    // Get returns the current configuration of a resource
    Get(ctx context.Context, resourceID string) (ConfigState, error)

    // Set updates the resource configuration to match the desired state
    Set(ctx context.Context, resourceID string, config ConfigState) error
}

// ConfigState defines the interface that all module configuration states must implement
type ConfigState interface {
    // AsMap returns the configuration as a map for efficient field-by-field comparison
    AsMap() map[string]interface{}
    
    // ToYAML serializes the configuration to YAML for export/storage
    ToYAML() ([]byte, error)
    
    // FromYAML deserializes YAML data into the configuration
    FromYAML([]byte) error
    
    // Validate ensures the configuration is valid
    Validate() error
    
    // GetManagedFields returns the list of fields this configuration manages
    GetManagedFields() []string
}
```

## Method Descriptions

### Get Method

The `Get` method retrieves the current configuration of a resource as a ConfigState.

**Signature:**
```go
Get(ctx context.Context, resourceID string) (ConfigState, error)
```

**Parameters:**
- `ctx`: Context for cancellation and timeouts
- `resourceID`: Unique identifier for the resource to query

**Returns:**
- `ConfigState`: Current configuration of the resource implementing the ConfigState interface
- `error`: Any error that occurred during the operation

**Behavior:**
- Must return the current state of the resource
- Should return a complete configuration that includes all discoverable settings
- Must handle non-existent resources appropriately
- Should be idempotent and side-effect free
- Returns comprehensive state (not just managed fields) for complete system visibility

**Example:**
```go
// Define module-specific configuration struct
type FileConfiguration struct {
    Path        string            `yaml:"path" json:"path"`
    Content     string            `yaml:"content" json:"content"`
    Permissions os.FileMode       `yaml:"permissions" json:"permissions"`
    Owner       string            `yaml:"owner" json:"owner"`
    Group       string            `yaml:"group" json:"group"`
    Size        int64             `yaml:"size" json:"size"`
    ModTime     time.Time         `yaml:"mod_time" json:"mod_time"`
    Checksum    string            `yaml:"checksum" json:"checksum"`
}

// Implement ConfigState interface
func (fc *FileConfiguration) AsMap() map[string]interface{} {
    return map[string]interface{}{
        "path":        fc.Path,
        "content":     fc.Content,
        "permissions": fc.Permissions,
        "owner":       fc.Owner,
        "group":       fc.Group,
        "size":        fc.Size,
        "mod_time":    fc.ModTime,
        "checksum":    fc.Checksum,
    }
}

func (fc *FileConfiguration) ToYAML() ([]byte, error) {
    return yaml.Marshal(fc)
}

func (fc *FileConfiguration) GetManagedFields() []string {
    return []string{"path", "content", "permissions", "owner", "group"}
}

func (m *FileModule) Get(ctx context.Context, resourceID string) (ConfigState, error) {
    // Read current file configuration
    info, err := os.Stat(resourceID)
    if err != nil {
        return nil, err
    }
    
    content, err := os.ReadFile(resourceID)
    if err != nil {
        return nil, err
    }
    
    config := &FileConfiguration{
        Path:        resourceID,
        Content:     string(content),
        Permissions: info.Mode().Perm(),
        Owner:       getOwner(info),
        Group:       getGroup(info),
        Size:        info.Size(),
        ModTime:     info.ModTime(),
        Checksum:    calculateChecksum(content),
    }
    
    return config, nil
}
```

### Set Method

The `Set` method updates the resource to match the desired configuration.

**Signature:**
```go
Set(ctx context.Context, resourceID string, config ConfigState) error
```

**Parameters:**
- `ctx`: Context for cancellation and timeouts
- `resourceID`: Unique identifier for the resource to modify
- `config`: Desired configuration for the resource implementing ConfigState interface

**Returns:**
- `error`: Any error that occurred during the operation

**Behavior:**
- Must update the resource to match the desired configuration
- Should be idempotent - multiple calls with same config should result in same state
- Must handle partial configurations appropriately (only update managed fields)
- Should validate configuration before applying changes
- Must provide atomic operations where possible

**Example:**
```go
func (m *FileModule) Set(ctx context.Context, resourceID string, config ConfigState) error {
    // Type assert to module-specific configuration
    fileConfig, ok := config.(*FileConfiguration)
    if !ok {
        return ErrInvalidConfigType
    }
    
    // Validate configuration
    if err := fileConfig.Validate(); err != nil {
        return err
    }
    
    // Only update managed fields (don't change size, mod_time, checksum - those are derived)
    managedFields := fileConfig.GetManagedFields()
    configMap := fileConfig.AsMap()
    
    // Write file content if managed
    if contains(managedFields, "content") {
        perms := fileConfig.Permissions
        if !contains(managedFields, "permissions") {
            // If permissions not managed, preserve existing
            if info, err := os.Stat(resourceID); err == nil {
                perms = info.Mode().Perm()
            }
        }
        
        if err := os.WriteFile(resourceID, []byte(fileConfig.Content), perms); err != nil {
            return err
        }
    }
    
    // Set ownership if managed
    if contains(managedFields, "owner") || contains(managedFields, "group") {
        return setOwnership(resourceID, fileConfig.Owner, fileConfig.Group)
    }
    
    return nil
}
```

## Test Operation (System-Level)

**Important Note:** While modules only implement Get and Set methods, the Steward system automatically performs test operations by:

1. **Getting current state**: Calls the module's `Get()` method to retrieve current ConfigState
2. **Extracting managed fields**: Uses `GetManagedFields()` to identify which fields to compare
3. **Comparing states**: Compares only managed fields from current state against desired configuration
4. **Detecting drift**: Only calls `Set()` when differences are detected in managed fields
5. **Verifying changes**: After Set, calls `Get()` again to verify the change was applied correctly

This approach maintains the safety of the previous Get/Test/Set pattern while simplifying the module interface and enabling intelligent partial configuration management.

**Smart Comparison Logic:**
```go
// Pseudo-code for system-level comparison
func compareConfigurations(current, desired ConfigState) bool {
    currentMap := current.AsMap()
    desiredMap := desired.AsMap()
    managedFields := desired.GetManagedFields()
    
    for _, field := range managedFields {
        if currentMap[field] != desiredMap[field] {
            return false // Drift detected
        }
    }
    return true // No drift in managed fields
}
```

**Benefits of System-Level Testing:**
- **Selective Comparison**: Only compares fields actually managed by the configuration
- **Complete Visibility**: Get returns full system state for monitoring/export
- **Performance**: Uses AsMap() for efficient field access, no marshal/unmarshal overhead
- **Consistency**: All modules use the same comparison logic
- **Simplicity**: Module developers only need to implement Get/Set
- **Maintainability**: Testing logic is centralized in the Steward
- **Flexibility**: Comparison algorithms can be improved system-wide
- **Safety**: Drift detection prevents unnecessary Set operations

## Optional Monitor Interface

While not part of the core Module interface, modules may optionally implement monitoring capabilities for real-time configuration drift detection:

```go
// Monitor interface for modules that support real-time monitoring
type Monitor interface {
    // Monitor watches for changes to a resource and triggers events
    Monitor(ctx context.Context, resourceID string, configData string) error
    
    // Changes returns a channel for receiving change notifications
    Changes() <-chan ChangeEvent
    
    // Close stops monitoring and releases resources
    Close() error
}

type ChangeEvent struct {
    ResourceID string
    Timestamp  time.Time
    ChangeType ChangeType
    Details    string // YAML describing the change
}

type ChangeType int

const (
    ChangeTypeCreated ChangeType = iota
    ChangeTypeModified
    ChangeTypeDeleted
    ChangeTypePermissions
)
```

**Monitor Implementation Notes:**
- Monitoring is **optional** - not all modules need to support it
- Modules that implement Monitor should use OS-specific hooks (inotify, Windows Event Log, etc.)
- Monitor implementations should be efficient and not impact system performance
- Changes should be reported in YAML format for consistency
- Monitor is primarily used for real-time drift detection in Controller-integrated mode

## Error Handling

### Error Types

Modules should use specific error types to help the system handle different failure scenarios:

```go
type ModuleError struct {
    Type    ErrorType
    Message string
    Cause   error
}

type ErrorType int

const (
    ErrorTypeNotFound ErrorType = iota
    ErrorTypePermission
    ErrorTypeValidation
    ErrorTypeConflict
    ErrorTypeInternal
)
```

### Error Guidelines

- Use appropriate error types for different failure scenarios
- Provide clear, actionable error messages
- Include context about what operation failed
- Wrap underlying errors when appropriate
- Log errors appropriately based on severity

### System Error Handling

The Steward system handles module errors based on user configuration in `hostname.cfg`:

```yaml
steward:
  error_handling:
    module_load_failure: "continue"     # or "fail"
    config_validation_failure: "fail"   # or "continue"
```

**Module Load Failures:**
- `continue`: Skip failed modules, continue with available ones
- `fail`: Stop execution on any module load failure

**Configuration Validation Failures:**
- `fail`: Stop execution on validation errors (default)
- `continue`: Skip invalid configurations, process valid ones

**Runtime Error Behavior:**
- Module failures are always isolated to prevent cascade failures
- Errors are logged with full context for troubleshooting
- Execution continues with remaining modules unless configured otherwise
- Retry logic may be applied for transient errors (ErrorTypeInternal)

## Implementation Guidelines

### Best Practices

1. **Idempotency**: Both Get and Set operations should be idempotent
2. **ConfigState Implementation**: Implement all methods of ConfigState interface correctly
3. **Validation**: Validate inputs thoroughly in both ConfigState.Validate() and Set method
4. **Error Handling**: Use appropriate error types and messages
5. **Performance**: Optimize for common use cases, especially Get operations and AsMap()
6. **Security**: Follow security best practices, validate all inputs
7. **Testing**: Implement comprehensive tests for both Get and Set
8. **Documentation**: Document configuration struct schema and managed fields
9. **Completeness**: Get should return comprehensive state, not just managed fields
10. **Selectivity**: Use GetManagedFields() to specify which fields Set will modify

### Resource Identification

- Use consistent resource identification schemes
- Support hierarchical resource structures where appropriate
- Handle resource dependencies correctly
- Provide clear error messages for invalid resource IDs

### Configuration Management

- **ConfigState Consistency**: Ensure Get output can be used as Set input
- **Schema Validation**: Validate configuration structure in Validate() method
- **Partial Updates**: Use GetManagedFields() to control which fields Set modifies
- **Default Values**: Provide sensible defaults for optional fields in struct initialization
- **Type Safety**: Use strongly-typed structs with proper type definitions
- **Complete Discovery**: Get should return all discoverable state for comprehensive monitoring
- **Managed Field Clarity**: Clearly document which fields are managed vs. read-only

### State Management

- Maintain minimal internal state
- Handle concurrent operations safely
- Clean up resources appropriately
- Support graceful shutdown
- **Comparison Safety**: Ensure Get returns consistent format for system-level comparison

### Execution Flow Integration

Modules should be designed knowing the Steward will:
1. Call `Get()` to retrieve current ConfigState (comprehensive system state)
2. Use `AsMap()` and `GetManagedFields()` for efficient field-level comparison
3. Only call `Set()` when drift is detected in managed fields
4. Call `Get()` again to verify changes

This means:
- Get operations should return complete system state but be optimized for performance
- AsMap() should be fast and efficient (avoid expensive conversions)
- Set operations should be robust and only modify managed fields
- GetManagedFields() should accurately reflect what Set will change
- Both should handle edge cases gracefully
- ConfigState structs should be lightweight and efficient for frequent access

## Context Usage

Modules should use the provided context for cancellation and timeout:

- Use `ctx.Done()` to detect cancellation
- Use `ctx.Err()` to check for errors
- Use `context.WithTimeout` to set timeouts for operations
- Use `context.WithValue` to pass values through the context

## Related Documentation

- [Module Lifecycle](lifecycle.md): How modules are loaded, initialized, and managed
- [Module Core Principles](core-principles.md): Fundamental principles that guide module design
- [Module Security Requirements](security.md): Security considerations for module implementation
- [Module Testing Requirements](testing.md): Testing standards and requirements for modules
- [Standalone Steward Architecture](standalone-steward.md): Complete architecture for standalone operation

## Version Information

- **Document Version:** 2.0
- **Last Updated:** 2024-07-02
- **Status:** Updated for Standalone Steward Architecture
- **Changes:** Simplified interface from Get/Set/Test/Monitor to Get/Set only, added system-level testing explanation