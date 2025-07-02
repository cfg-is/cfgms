# CFGMS Architecture

## Overview

CFGMS (Configuration Management System) is a modern, Go-based configuration management system designed with resilience, security, and clean architecture principles. The project implements a zero-trust security model with mutual TLS authentication and follows a feature-based organization structure.

## Core Design Principles

- **Zero-Trust Architecture**: No implicit trust between components
- **Resilient Configuration Management**: Graceful degradation and recovery
- **Hierarchical Multi-Tenant Model**: Scalable organizational structure
- **Secure by Default**: All communications authenticated and encrypted
- **Module-Based Extensibility**: Self-contained resource management modules

## System Components

CFGMS consists of three core components:

### Controller
Central management system that:
- Distributes configurations to Stewards
- Manages tenant hierarchy and RBAC
- Provides REST API for external access
- Handles certificate management and authentication

### Steward  
Cross-platform component that:
- Executes configurations on managed endpoints
- Operates in standalone or Controller-integrated modes
- Implements module-based resource management
- Reports system state and configuration compliance

### Outpost
Proxy cache component that:
- Monitors network devices via SNMP/SSH
- Provides agentless management capabilities
- Caches configurations for offline operation
- Enables network discovery and documentation

## Module System

All resource management is performed through modules that implement a standard interface:

```go
type Module interface {
    Get(ctx context.Context, resourceID string) (ConfigState, error)
    Set(ctx context.Context, resourceID string, config ConfigState) error
}
```

**Key Features:**
- **ConfigState Interface**: Efficient field-level comparison without marshal/unmarshal overhead
- **System-Level Testing**: Steward automatically compares current vs desired state
- **Managed Fields**: Only specified fields are modified, others left unchanged
- **Extensible Design**: Easy addition of new resource types

**Available Modules:**
- `directory` - Directory creation and permissions
- `file` - File content and attributes
- `firewall` - Firewall rules and policies  
- `package` - Software package management

## Operational Modes

### Standalone Mode
- **Use Case**: Single endpoints, edge devices, development
- **Configuration**: Local `hostname.cfg` files
- **Module Discovery**: Filesystem-based scanning
- **Benefits**: Simple deployment, no network dependencies

### Controller-Integrated Mode
- **Use Case**: Enterprise fleets, centralized management
- **Configuration**: Controller distribution via gRPC
- **Module Discovery**: Controller registry with versioning
- **Benefits**: Centralized control, fleet orchestration

## Communication Architecture

### Internal Communication
- **Protocol**: gRPC with mutual TLS
- **Authentication**: Certificate-based identity
- **Connection Model**: Stewards initiate all connections (no open ports)

### External Communication  
- **Protocol**: HTTPS with API key authentication
- **Interface**: REST API for user and system integration
- **Documentation**: OpenAPI/Swagger specifications

## Security Model

### Zero-Trust Principles
- All communications authenticated and encrypted
- Continuous verification of component identity
- Principle of least privilege enforced throughout
- No implicit trust between system components

### Certificate Management
- Unique identity for each component
- Automatic certificate rotation
- Secure key storage and distribution
- Integration with external PKI systems

## Multi-Tenancy

### Hierarchical Model
- Recursive parent-child tenant relationships
- Configuration inheritance with override capabilities
- Tenant-aware RBAC with cascading permissions
- Efficient cross-tenant operations

### Scalability
- Designed to handle 50k+ Stewards across multiple regions
- Path-based targeting for efficient operations
- Distributed Controller architecture support
- Database sharding for massive scale

## Development Architecture

### Feature-Based Organization
```
features/
├── controller/    # Controller component and server logic
├── steward/       # Steward component with health monitoring  
└── modules/       # Module implementations
```

### Key Directories
- `cmd/` - Command-line applications (controller, steward, cfgctl)
- `api/proto/` - Protocol buffer definitions for gRPC
- `pkg/` - Shared packages (logging utilities)
- `test/` - Integration and end-to-end tests
- `docs/` - Architecture and development documentation

## Related Documentation

- [Steward Configuration](steward-configuration.md) - hostname.cfg format and options
- [Module Development](modules/interface.md) - Module interface and development guide
- [Development Roadmap](product/roadmap.md) - Feature timeline and future considerations
- [Development Workflow](development/guides/getting-started.md) - Getting started guide