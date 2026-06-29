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

All resource management is performed through modules — out-of-process gRPC binaries that implement a standard contract. The steward (or workflow engine) spawns each module binary as a child process over a local socket. Modules are distributed as publisher-signed bundles cached at the controller; stewards pull bundles from the controller rather than from external registries.

For the full module packaging architecture, see [ADR-006](architecture/decisions/006-module-packaging-and-distribution.md).

### Three module kinds

Every module commits to exactly one kind, declared via `executors:` in `module.yaml`:

| Kind | Where it runs | What it manages |
|------|--------------|-----------------|
| `steward` | Endpoint agent | Local device resources (files, packages, firewall, services) |
| `outpost` | Steward host acting as a proxy | Remote LAN devices that cannot run a steward (switches, printers, IoT) |
| `workflow` | Controller workflow engine | Cloud and SaaS APIs (M365, identity providers, ticketing) |

Cross-kind modules are not supported. The same logical resource on different host kinds is implemented as separate modules.

### Four execution paths on a steward

Every byte of code that runs on a steward arrives through exactly one of these paths:

1. **Modules** — publisher-signed bundle spawned as a child process, communicates via gRPC
2. **Scripts** — operator-authored script staged to disk and executed via OS process (publisher-signed)
3. **Inline cfg CLI** — admin mTLS-signed payload, end-to-end *(separate epic)*
4. **Remote shell** — interactive admin session *(separate epic)*

### Three trust modes

The steward verifies module bundles according to the `module_trust.mode` setting in `hostname.cfg`:

| Mode | Verification | When to use |
|------|-------------|-------------|
| `controller` | Steward accepts the controller's attestation (default) | Standard managed deployments |
| `strict` | Steward independently verifies the publisher signature against compiled-in keys | Regulated environments, highest-value modules |
| `bypass` | Signature verification skipped | Development only; never production |

Publisher public keys are baked into the steward binary at build time and cannot be changed via `cfg push`. See [distribution.md](architecture/modules/distribution.md) for the full trust and signing model.

**Key Features:**

- **ConfigState Interface**: Efficient field-level comparison without marshal/unmarshal overhead
- **System-Level Testing**: Steward automatically compares current vs desired state
- **Managed Fields**: Only specified fields are modified, others left unchanged
- **Out-of-process isolation**: A module crash cannot corrupt steward state

**Available Modules:**

- `file` - File content, directory creation, and permissions
- `firewall` - Firewall rules and policies  
- `package` - Software package management
- `service` - OS service state management
- `script` - Cross-platform script execution (file-based)

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

For the controller REST API auth-tier policy (Tier-3 mTLS-only enforcement, the four-tier table, and the full Tier-3 endpoint list), see [Security Architecture — Auth-Tier Policy](security/architecture.md#auth-tier-policy).

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
