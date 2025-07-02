# Steward Standalone Module System Architecture

## Overview

The Steward agent is designed to operate in two modes:
1. **Standalone Mode**: Self-contained operation using local modules and configuration files
2. **Controller-Integrated Mode**: Orchestrated operation receiving configurations from a Controller

This document defines the architecture for standalone mode, enabling Stewards to manage local resources without Controller dependency.

## Core Requirements

### Standalone Operation Goals
- **Self-Contained**: No external dependencies for basic resource management
- **Local Configuration**: Read configuration from local files (YAML, JSON)
- **Module Discovery**: Automatically discover and load available modules
- **Resilient**: Graceful handling of module failures and configuration errors
- **Extensible**: Easy addition of new modules without code changes

## Architecture Components

### 1. Module Discovery Engine

**Purpose**: Automatically discover and catalog available modules on the local system.

**Discovery Process**:
```
1. Scan module directories (priority order):
   - ./modules/ (relative to steward binary)
   - /opt/cfgms/modules/ (Linux/macOS)
   - C:\Program Files\cfgms\modules\ (Windows)
   - Custom paths specified in hostname.cfg

2. For each directory found:
   - Check for module.yaml metadata file
   - Validate module structure and interface compliance
   - Load module metadata (name, version, capabilities)

3. Build module registry:
   - Map module names to implementations
   - Track module capabilities and requirements
   - Handle version conflicts and duplicates
```

**Module Structure**:
```
modules/
├── directory/
│   ├── module.yaml          # Module metadata
│   └── module.go           # Implementation
├── file/
│   ├── module.yaml
│   ├── interface.go
│   └── implementation.go
└── firewall/
    ├── module.yaml
    └── module.go
```

### 2. Configuration Manager

**Purpose**: Load, parse, and validate local configuration files.

**Configuration Sources** (priority order):
1. Command-line specified config file: `--config /path/to/hostname.cfg`
2. Environment variable: `CFGMS_CONFIG=/path/to/hostname.cfg`
3. Default locations:
   - `./<hostname>.cfg` (current directory)
   - `/etc/cfgms/<hostname>.cfg` (Linux/macOS)
   - `C:\ProgramData\cfgms\<hostname>.cfg` (Windows)

**Configuration Format**:
```yaml
# hostname.cfg - Steward standalone configuration
steward:
  name: "hostname-steward"
  log_level: "info"
  module_paths:
    - "./modules"
    - "/opt/cfgms/modules"
  error_handling:
    module_load_failure: "continue"  # or "fail"
    config_validation_failure: "fail"  # or "continue"

# Resource configurations
resources:
  - name: "web-directories"
    module: "directory"
    config:
      path: "/var/www"
      owner: "www-data"
      permissions: "755"
      
  - name: "nginx-config"
    module: "file"
    config:
      path: "/etc/nginx/nginx.conf"
      content: |
        # Nginx configuration content
      owner: "root"
      permissions: "644"

  - name: "firewall-web"
    module: "firewall"
    config:
      rules:
        - port: 80
          protocol: "tcp"
          action: "allow"
        - port: 443
          protocol: "tcp"
          action: "allow"
```

### 3. Module Factory

**Purpose**: Instantiate and manage module instances.

**Responsibilities**:
- Load module implementations based on configuration requirements
- Initialize modules with their specific configurations
- Maintain module instance lifecycle
- Handle module loading errors and fallbacks

**Factory Interface**:
```go
type ModuleFactory interface {
    // LoadModule creates and initializes a module instance
    LoadModule(moduleName string, config map[string]interface{}) (Module, error)
    
    // GetAvailableModules returns list of discovered modules
    GetAvailableModules() []ModuleInfo
    
    // ValidateModuleConfig validates configuration using module's internal validation
    ValidateModuleConfig(moduleName string, config map[string]interface{}) error
}
```

### 4. Execution Engine

**Purpose**: Execute module operations according to configuration specifications.

**Execution Modes**:
- **Apply Mode**: Execute Set operations to achieve desired state
- **Check Mode**: Execute Get operations and compare against desired state (dry-run)
- **Drift Mode**: Execute Get operations to detect configuration drift

**Execution Flow**:
```
1. Load Configuration
   ├── Parse configuration file
   ├── Validate configuration syntax
   └── Resolve module dependencies

2. Initialize Modules
   ├── Discover available modules
   ├── Load required modules
   └── Validate module configurations

3. Execute Operations
   ├── For each resource configuration:
   │   ├── Get current state (Get operation)
   │   ├── Compare current vs desired state
   │   ├── Apply changes if needed (Set operation)
   │   └── Verify final state (Get operation + comparison)
   └── Report results and errors

4. Cleanup
   ├── Close module instances
   ├── Release resources
   └── Log final status
```

### 5. Error Handling Strategy

**Module Loading Errors**:
- Default: Log error and continue with available modules
- User configurable via `steward.error_handling.module_load_failure`:
  - `continue`: Skip failed modules, continue with available ones
  - `fail`: Stop execution on any module load failure

**Configuration Errors**:
- Default: Validate all configurations before execution and fail on errors
- User configurable via `steward.error_handling.config_validation_failure`:
  - `fail`: Stop execution on validation errors
  - `continue`: Skip invalid configurations, process valid ones

**Runtime Errors**:
- Always isolate module failures to prevent cascade failures
- Log all errors with full context for troubleshooting
- Continue with remaining modules unless user specifies otherwise

## Standalone vs Controller-Integrated Differences

| Aspect | Standalone Mode | Controller-Integrated Mode |
|--------|----------------|---------------------------|
| **Configuration Source** | Local `hostname.cfg` files | Controller distribution via gRPC |
| **Module Discovery** | Local filesystem scan | Controller registry with versioning |
| **State Reporting** | Local logs only | Report ConfigState to Controller |
| **Orchestration** | Self-contained execution | Controller coordination across fleet |
| **Updates** | Manual configuration changes | Pushed from Controller with rollback |
| **Monitoring** | Local health checks | Controller monitoring with aggregation |
| **Module Updates** | Manual installation | Controller-managed deployment |
| **Dependency Resolution** | Local validation only | Cross-Steward dependency management |
| **Rollback** | Manual configuration revert | Controller-orchestrated rollback |
| **Scaling** | Single endpoint only | Fleet management across thousands |

### Operational Modes Detail

#### Standalone Mode
- **Use Case**: Single endpoints, edge devices, development/testing
- **Benefits**: Simple deployment, no network dependencies, full local control
- **Limitations**: No centralized management, manual configuration updates
- **Configuration**: `hostname.cfg` files with resource definitions
- **Module Loading**: Filesystem-based discovery from local directories
- **State Management**: Local execution logs and health checks only

#### Controller-Integrated Mode  
- **Use Case**: Enterprise fleets, centralized management, compliance reporting
- **Benefits**: Centralized control, fleet orchestration, automated compliance
- **Limitations**: Network dependency, more complex deployment
- **Configuration**: Controller distributes configurations via gRPC
- **Module Loading**: Controller registry with version management
- **State Management**: Real-time reporting to Controller, centralized monitoring

### Migration Path
Stewards can operate in both modes and transition between them:
1. **Standalone → Controller**: Register with Controller, receive configurations
2. **Controller → Standalone**: Fall back to last known local configuration
3. **Hybrid**: Use Controller when available, standalone when disconnected

## Implementation Priorities

### Phase 1: Basic Standalone Operation
1. Module discovery from local filesystem
2. Configuration file parsing and validation
3. Basic module factory and loading
4. Simple execution engine (apply mode only)

### Phase 2: Enhanced Standalone Features
1. Advanced error handling and recovery
2. Configuration drift detection
3. Comprehensive logging and monitoring
4. Multiple execution modes (check, drift)

### Phase 3: Controller Integration Preparation
1. Abstracted configuration sources
2. Pluggable discovery mechanisms
3. State reporting interfaces
4. Remote monitoring hooks

## Next Steps

This architecture provides the foundation for implementing Issue #17 (Steward Module Implementation). The implementation should follow this specification to ensure both standalone operation and future Controller integration capabilities.