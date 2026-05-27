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
- **Platform Support**: Linux AMD64 (primary), Windows AMD64 (development)

### Steward  

Cross-platform agent that:

- Executes configurations on managed endpoints
- Operates in standalone or Controller-integrated modes
- Implements module-based resource management with platform-specific optimizations
- Reports system state and configuration compliance
- **Platform Support**: Linux (AMD64/ARM64), Windows (AMD64/ARM64), macOS (ARM64)

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
- **Configuration**: Controller distribution via gRPC-over-QUIC
- **Module Discovery**: Controller registry with versioning
- **Benefits**: Centralized control, fleet orchestration

## Communication Architecture

### Internal Communication

- **Protocol**: gRPC-over-QUIC with mutual TLS
  - **Control Plane** (gRPC service): Real-time commands, heartbeats, failover detection
  - **Data Plane** (gRPC service): High-performance configuration and DNA synchronization
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

## Platform Architecture

### Cross-Platform Design Philosophy

CFGMS implements a **platform-agnostic core** with **platform-specific optimizations**:

- **Unified Business Logic**: Core configuration management logic works identically across platforms
- **Platform-Specific Collectors**: Native system information gathering (WMI on Windows, syscalls on Unix)
- **Adaptive Module System**: Modules automatically adapt to platform capabilities and constraints
- **Consistent API**: Same REST API and gRPC-over-QUIC transport protocol regardless of underlying platform

### Platform-Specific Implementations

#### Windows Optimizations

- **WMI Integration**: Native Windows Management Instrumentation for system data
- **PowerShell Commands**: Advanced system configuration via PowerShell execution  
- **Windows Services**: Native service management and health monitoring
- **Registry Management**: Direct Windows Registry manipulation for configuration
- **ACL Support**: Windows Access Control List integration for security

#### Unix-like Optimizations (Linux/macOS)

- **Syscall Integration**: Direct system call access for efficient data collection
- **Package Manager Integration**: Native support for apt, yum, brew, etc.
- **POSIX Compliance**: Full POSIX file system and process management
- **Process Control**: Advanced Unix process management and signal handling
- **Network Stack**: Native network interface and routing table access

### Deployment Patterns

#### Enterprise MSP Architecture

```
                    ┌─────────────────────┐
                    │   Linux Controller  │
                    │   (Primary Target)  │
                    │                     │
                    │ - High Performance  │
                    │ - Container Ready   │
                    │ - 50k+ Stewards     │
                    └──────────┬──────────┘
                               │ mTLS
           ┌───────────────────┼───────────────────┐
           │                   │                   │
    ┌──────▼──────┐    ┌──────▼──────┐    ┌──────▼──────┐
    │   Linux     │    │   Windows   │    │   macOS     │
    │  Stewards   │    │  Stewards   │    │  Stewards   │
    │             │    │             │    │             │
    │ AMD64/ARM64 │    │ AMD64/ARM64 │    │ ARM64 (M1+) │
    └─────────────┘    └─────────────┘    └─────────────┘
```

#### Development Environment Architecture

```
    ┌─────────────────────────────────────────────────┐
    │          Developer Workstation                  │
    │                                                 │
    │  ┌─────────────────┐    ┌─────────────────┐     │
    │  │   Controller    │    │    Steward      │     │
    │  │   (Any OS)      │    │   (Local OS)    │     │
    │  │                 │    │                 │     │
    │  │ - Windows       │◄──►│ - Same Platform │     │
    │  │ - macOS         │    │ - Local Testing │     │
    │  │ - Linux         │    │                 │     │
    │  └─────────────────┘    └─────────────────┘     │
    └─────────────────────────────────────────────────┘
```

For detailed platform support information, see [docs/deployment/platform-support.md](../deployment/platform-support.md).

## Development Architecture

### Feature-Based Organization

```
features/
├── controller/    # Controller component and server logic
├── steward/       # Steward component with health monitoring  
└── modules/       # Module implementations
```

### Key Directories

- `cmd/` - Command-line applications (controller, steward, cfg)
- `api/proto/` - Protocol buffer definitions (used for data serialization)
- `pkg/` - Shared packages and central providers (logging, storage, security)
- `features/` - Feature implementations organized by component
- `test/` - Integration and end-to-end tests
- `docs/` - Architecture and development documentation

## Monitoring and Observability

CFGMS includes comprehensive monitoring capabilities:

- **Distributed Tracing**: OpenTelemetry-based tracing with correlation IDs
- **Structured Logging**: JSON logs with trace correlation
- **System Metrics**: Resource usage and application performance monitoring
- **Third-Party Integration**: Prometheus, Grafana, ELK stack, Jaeger support
- **REST API**: Monitoring endpoints for external system integration

See the [Monitoring Guide](monitoring.md) for detailed configuration and usage.

## Related Documentation

- [Monitoring Guide](monitoring.md) - Complete monitoring and observability guide
- [REST API Documentation](api/rest-api.md) - API reference including monitoring endpoints
- [Steward Configuration](steward-configuration.md) - hostname.cfg format and options
- [Module Development](modules/interface.md) - Module interface and development guide
- [Development Roadmap](product/roadmap.md) - Feature timeline and future considerations
- [Development Guide](development/README.md) - Development documentation
