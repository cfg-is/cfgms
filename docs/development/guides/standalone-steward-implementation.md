# Standalone Steward Implementation Guide

## Overview

This guide provides step-by-step implementation guidance for building the standalone Steward functionality (Issue #17). The Steward operates independently using local modules and hostname.cfg files.

## Implementation Order

Follow this sequence for systematic implementation:

### 1. Module Discovery Engine
**File**: `features/steward/discovery/`

**Purpose**: Scan filesystem for available modules

**Implementation Steps:**
1. Scan module directories in priority order:
   - `./modules/` (relative to binary)
   - `/opt/cfgms/modules/` (Linux/macOS) 
   - `C:\Program Files\cfgms\modules\` (Windows)
   - Custom paths from `hostname.cfg`

2. For each directory, check for `module.yaml` file
3. Parse module metadata (name, version, capabilities)
4. Build registry mapping module names to directory paths

**Key Functions Needed:**
```go
func DiscoverModules(paths []string) (ModuleRegistry, error)
func ParseModuleMetadata(path string) (ModuleInfo, error)
func ValidateModuleStructure(path string) error
```

### 2. Configuration Manager
**File**: `features/steward/config/`

**Purpose**: Load and parse hostname.cfg files

**Implementation Steps:**
1. Search for config file in priority order (see steward-configuration.md)
2. Parse YAML configuration structure
3. Validate steward settings and resource definitions
4. Map resource configurations to required modules

**Key Functions Needed:**
```go
func LoadConfiguration(configPath string) (StewardConfig, error)
func ValidateConfiguration(config StewardConfig) error
func GetConfiguredModules(config StewardConfig) []string
```

### 3. Module Factory
**File**: `features/steward/factory/`

**Purpose**: Instantiate and manage module instances

**Implementation Steps:**
1. Load Go modules dynamically from discovery results
2. Instantiate modules that implement the Module interface
3. Validate ConfigState interface implementation
4. Handle module loading errors per user configuration

**Key Functions Needed:**
```go
func LoadModule(moduleName string, path string) (modules.Module, error)
func ValidateModuleInterface(module interface{}) error
func CreateModuleInstance(name string) (modules.Module, error)
```

### 4. Execution Engine
**File**: `features/steward/execution/`

**Purpose**: Orchestrate Get→Compare→Set→Verify workflow

**Implementation Steps:**
1. Load required modules for configured resources
2. For each resource:
   - Call module.Get() to retrieve current state
   - Compare current vs desired using GetManagedFields()
   - If drift detected, call module.Set()
   - Call module.Get() again to verify changes
3. Handle errors per user configuration
4. Generate execution report

**Key Functions Needed:**
```go
func ExecuteResource(resource ResourceConfig, module modules.Module) error
func CompareConfigStates(current, desired modules.ConfigState) bool
func ExecuteConfiguration(config StewardConfig) ExecutionReport
```

### 5. System-Level Testing Logic
**File**: `features/steward/testing/`

**Purpose**: Intelligent field-level comparison

**Implementation Steps:**
1. Extract managed fields from desired ConfigState
2. Compare only managed fields between current and desired
3. Determine if Set operation is needed
4. Provide detailed diff information for logging

**Key Functions Needed:**
```go
func CompareStates(current, desired modules.ConfigState) (bool, StateDiff)
func GetManagedFieldValues(state modules.ConfigState) map[string]interface{}
func CalculateDrift(current, desired map[string]interface{}) StateDiff
```

## Implementation Guidelines

### Error Handling
Follow user configuration from hostname.cfg:
```go
switch config.Steward.ErrorHandling.ModuleLoadFailure {
case "continue":
    log.Warn("Module failed to load", "module", name, "error", err)
    continue
case "fail":
    return fmt.Errorf("module load failed: %w", err)
}
```

### Logging
Use structured logging throughout:
```go
log.Info("Executing resource configuration", 
    "resource", resource.Name, 
    "module", resource.Module,
    "mode", executionMode)
```

### Context Usage
Respect context cancellation for all operations:
```go
func (e *ExecutionEngine) ExecuteResource(ctx context.Context, resource ResourceConfig) error {
    select {
    case <-ctx.Done():
        return ctx.Err()
    default:
        // Continue with execution
    }
}
```

## Directory Structure

Create this structure under `features/steward/`:

```
features/steward/
├── steward.go              # Main steward orchestration
├── discovery/
│   ├── discovery.go        # Module filesystem discovery
│   └── discovery_test.go
├── config/
│   ├── config.go          # Configuration loading and parsing
│   └── config_test.go
├── factory/
│   ├── factory.go         # Module instantiation
│   └── factory_test.go
├── execution/
│   ├── execution.go       # Resource execution orchestration
│   └── execution_test.go
└── testing/
    ├── comparison.go      # ConfigState comparison logic
    └── comparison_test.go
```

## Integration Points

### With Existing Modules
Modules in `features/modules/` need to implement the updated ConfigState interface. See module interface documentation for details.

### With CLI (cmd/steward)
The main steward command should:
1. Parse command-line arguments (config path, execution mode)
2. Initialize Steward with configuration
3. Execute resource management
4. Handle graceful shutdown

### Error Reporting
Provide clear error messages with context:
- Configuration file location and validation errors
- Module discovery and loading failures  
- Resource execution errors with drift information
- System-level errors with recovery suggestions

## Testing Strategy

1. **Unit Tests**: Test each component in isolation with mocks
2. **Integration Tests**: Test Steward with real modules and configurations
3. **Table-Driven Tests**: Test various configuration scenarios
4. **Error Scenarios**: Test error handling and recovery paths

## Next Steps

After implementing the core Steward functionality:
1. Update existing modules to implement ConfigState interface
2. Add comprehensive error handling and logging
3. Implement CLI interface with proper argument handling
4. Add health monitoring and reporting capabilities

This guide provides the foundation for Issue #17 implementation while maintaining focus on essential functionality for v0.1.0.