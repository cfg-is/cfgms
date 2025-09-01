# CFGMS Modules

This directory contains the module system for CFGMS. Each module is a self-contained package that implements the core module interface for managing specific types of resources.

## Module Structure

Each module follows this structure:

```txt
module-name/
├── README.md            # Module documentation
├── module.yaml          # Module metadata and requirements
├── interface.go         # Module interface implementation
├── implementation.go    # Core implementation
└── tests/               # Module-specific tests
    ├── unit/           # Unit tests
    └── integration/    # Integration tests
```

## Module Interface

All modules must implement the core module interface:

```go
type Module interface {
    // Get returns the current configuration of a resource
    Get(ctx context.Context, resourceID string) (string, error)
    
    // Set updates the resource configuration
    Set(ctx context.Context, resourceID string, configData string) error
    
    // Test validates if the current configuration matches the desired state
    Test(ctx context.Context, resourceID string, configData string) (bool, error)
}
```

## Module Metadata (module.yaml)

Each module must include a `module.yaml` file with the following structure:

```yaml
name: module-name        # Unique module identifier
version: 0.1.0          # Module version
description: >          # Module description
  Brief description of what this module does
  and what resources it manages.

# NEW: Supported execution environments
executors:             # List of supported agent types
  - steward           # Local system management (files, services, local AD)
  - outpost           # Network resource management (remote systems, REST APIs)
  - saas_steward      # SaaS API management (M365, AWS, etc.)

dependencies: []        # List of other modules this module depends on

requirements:           # System requirements
  os: [windows, linux, darwin]  # Supported operating systems
  arch: [amd64, arm64]         # Supported architectures
  min_memory: "512MB"          # Minimum memory requirement
  min_disk: "1GB"              # Minimum disk space

interfaces:            # Implemented interfaces
  - Get
  - Set
  - Test

security:             # Security requirements
  requires_root: false
  capabilities: []    # Required Linux capabilities
  ports: []          # Required network ports

documentation:        # Documentation links
  api: "docs/api.md"
  examples: "docs/examples/"
```

## Module Development Guidelines

1. **Documentation**
   - Each module must have a README.md explaining:
     - Purpose and scope
     - Configuration options
     - Usage examples
     - Known limitations
     - Security considerations

2. **Testing**
   - All modules must include:
     - Unit tests for all functions
     - Integration tests for core functionality
     - Test coverage >= 80%

3. **Error Handling**
   - Use module-specific error types
   - Provide clear error messages
   - Include context in errors

4. **Security**
   - Follow principle of least privilege
   - Validate all inputs
   - Sanitize all outputs
   - Document security requirements

5. **Performance**
   - Optimize for resource usage
   - Document performance characteristics
   - Include benchmarks for critical operations

## Module Categories

Modules are organized by execution environment and category:

### **Steward Modules** (Local System Management)
- **System Modules**: Core local system management
  - file/ - Local file system management
  - directory/ - Local directory management
  - service/ - Local service management
  - activedirectory/ - Local AD management using system context

### **Outpost Modules** (Network Resource Management)
- **Network Directory Modules**: Remote directory management
  - network_activedirectory/ - Remote AD management via LDAP
- **Network Infrastructure Modules**: Remote system management
  - ssh_file/ - Remote file management via SSH
  - rest_api/ - Generic REST API management

### **SaaS Steward Modules** (API-Based Management)
- **Microsoft 365 Modules**: M365 API management
  - entra_user/ - Entra ID user management
  - conditional_access/ - Conditional access policies
  - intune_policy/ - Intune device policies

## Creating a New Module

1. Create the module directory structure
2. Implement the module interface
3. Add module.yaml with metadata
4. Write documentation
5. Implement tests
6. Submit for review

## Module Versioning

Modules follow semantic versioning:

- MAJOR: Breaking changes
- MINOR: New features, backward compatible
- PATCH: Bug fixes, backward compatible

## Module Dependencies

Modules can depend on other modules, but must:

- Declare all dependencies in module.yaml
- Handle dependency failures gracefully
- Not create circular dependencies

## Security Considerations

- Modules run with least privilege
- All network communication must be secured
- Sensitive data must be encrypted
- Logs must be sanitized
- Input must be validated
