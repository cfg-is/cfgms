# CFGMS Architecture

This document provides a high-level overview of the CFGMS (Config Management System) architecture for contributors. For detailed design documents, see [docs/architecture/](docs/architecture/).

## Table of Contents

- [System Overview](#system-overview)
- [Core Components](#core-components)
- [Operational Modes](#operational-modes)
- [Communication Architecture](#communication-architecture)
- [Provider System (Pluggable Architecture)](#provider-system-pluggable-architecture)
- [Module System](#module-system)
- [Security Model](#security-model)
- [Multi-Tenancy](#multi-tenancy)
- [Platform Architecture](#platform-architecture)
- [Monitoring and Observability](#monitoring-and-observability)
- [Design Principles](#design-principles)

## System Overview

CFGMS is a modern configuration management system designed for Managed Service Providers (MSPs) to automate and manage infrastructure at scale. The system follows a **three-tier architecture**:

```
┌─────────────────────────────────────────────────────────────┐
│                        Controller                           │
│  (Central Management & Orchestration)                       │
│  • Workflow engine                                          │
│  • Multi-tenant management                                  │
│  • M365/Cloud API integrations                              │
│  • Configuration storage & versioning                       │
└─────────────────────────────────────────────────────────────┘
                           ▲ │
                           │ │ gRPC-over-QUIC (mTLS)
                           │ ▼
┌──────────────────────────────────────────────────────────────┐
│                      Stewards (Agents)                       │
│  (Endpoint Management)                                       │
│  • Local resource management (files, packages, firewall)     │
│  • Platform-specific operations                              │
│  • DNA collection & drift detection                          │
│  • Offline capability                                        │
└──────────────────────────────────────────────────────────────┘
                           ▲ │
                           │ │ gRPC-over-QUIC (mTLS)
                           │ ▼
┌──────────────────────────────────────────────────────────────┐
│                      Outpost (Optional)                      │
│  (Network Device Monitoring)                                 │
│  • Proxy/cache for network devices                           │
│  • SNMP monitoring                                           │
│  • Regional deployment                                       │
└──────────────────────────────────────────────────────────────┘
```

## Core Components

### Controller

**Purpose**: Central management and orchestration server

**Key Responsibilities**:
- Execute workflows and manage automation
- Store and version configurations
- Manage multi-tenant hierarchy (MSP → Client → Group → Device)
- Integrate with cloud services (M365, AWS, Azure)
- Provide REST API for external integrations
- Manage certificates and authentication

**Deployment**: A single instance or a controller cluster ([ADR-031](docs/architecture/decisions/031-controller-cluster-service-model.md)). Both shapes run the same AGPL-3.0 code.

**Location**: `cmd/controller/`, `features/controller/`

### Steward (Agent)

**Purpose**: Endpoint management agent deployed on managed devices

**Key Responsibilities**:
- Execute local resource management (files, packages, services)
- Collect system DNA (hardware, software, network, security attributes)
- Detect configuration drift
- Report health metrics and status
- Execute platform-specific operations
- Maintain secure connection to controller

**Deployment**: One per managed endpoint (workstation, server, VM)

**Platform Support**:
- Linux: AMD64, ARM64 (all distributions)
- Windows: AMD64, ARM64 (Windows 10/11, Server 2019+)
- macOS: ARM64 (Apple Silicon)

**Location**: `cmd/steward/`, `features/steward/`

### CLI (cfg)

**Purpose**: Command-line interface for system administration

**Key Responsibilities**:
- Manage stewards, configurations, and workflows
- RBAC and user management
- Certificate operations
- Debugging and troubleshooting

**Location**: `cmd/cfg/`

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

CFGMS uses a **unified gRPC-over-QUIC transport** for efficient, bi-directional communication:

### gRPC Control Plane

**Purpose**: Lightweight control messages and real-time status

**Characteristics**:
- Push-based heartbeats (reduced polling overhead)
- Command delivery (controller → steward)
- Status updates (steward → controller)
- Fast failure detection (<15s)
- Single multiplexed QUIC connection per steward

### gRPC Data Plane

**Purpose**: Large data transfers and bulk operations

**Characteristics**:
- Configuration synchronization
- DNA data collection
- File transfers
- Bi-directional streams
- Built-in multiplexing and congestion control

### Security

All communication uses **mutual TLS (mTLS)**:
- Certificate-based steward authentication
- TLS 1.3 encryption
- Certificate pinning
- Automatic certificate rotation
- Stewards initiate all connections (no open ports on managed endpoints)

### External Communication

- **Protocol**: HTTPS
- **Interface**: REST API for user and system integration
- **Documentation**: [REST API reference](docs/api/rest-api.md) and the OpenAPI specification in `docs/api/openapi.yaml`

See [docs/architecture/communication-layer-migration.md](docs/architecture/communication-layer-migration.md) for detailed transport specification.

## Provider System (Pluggable Architecture)

CFGMS implements a **pluggable provider system**, allowing infrastructure components to be swapped without refactoring. This architectural pattern is used throughout the system for any capability that might need different implementations at different scales or deployment models.

### Design Principles

1. **Interface-First Development** - Define contracts before implementations
2. **Runtime Discovery** - Providers register automatically at startup via `init()`
3. **Configuration-Driven** - Users select backends via YAML configuration
4. **Pluggable by Default** - Assume providers are pluggable unless proven unnecessary

### Provider Categories

CFGMS uses providers for all cross-system capabilities:

#### Storage Providers
| Provider | Use Case | Status |
|----------|----------|--------|
| **Git** | GitOps workflows, version control, audit trails | Default |
| **Database** | PostgreSQL/MySQL for high-scale deployments | Available |
| **SQLite** | Single-file database for small deployments | Available |

**CRITICAL**: All storage providers encrypt secrets using SOPS. Cleartext secrets are never stored on disk.

#### Other Providers
- **Logging** - Structured logging (file, timescale)
- **Secrets** - Secret management with encryption (SOPS, Vault)
- **Caching** - Write-through caching (memory, Redis)
- **Session** - Session management (memory, Redis, database)
- **Certificate** - TLS certificate management (internal CA, Let's Encrypt, Vault)
- **Telemetry** - Observability (OpenTelemetry, Datadog, Prometheus)
- **Directory** - Directory services (M365, Active Directory)
- **Transport** - gRPC-over-QUIC transport provider

### Architecture Pattern

The provider pattern enforces clean separation between business logic and infrastructure:

```
Business Logic (features/)
       ↓ imports
pkg/{provider}/interfaces/  ← Import these
       ↓ implements
pkg/{provider}/providers/   ← Never import directly
  ├── implementation-1/
  ├── implementation-2/
  └── implementation-3/
```

**Golden Rule**: Business logic MUST import only `pkg/{provider}/interfaces`, never specific provider implementations.

**Why This Matters**:
- Swap infrastructure without refactoring business logic
- Test with lightweight providers (memory) without mocks
- Scale from single-server to distributed deployments

See [docs/architecture/provider-architecture.md](docs/architecture/provider-architecture.md) for detailed provider development guidelines.

## Module System

All resource management is performed through modules — out-of-process gRPC binaries that implement a standard contract. The steward (or workflow engine) spawns each module binary as a child process over a local socket. Modules are distributed as publisher-signed bundles cached at the controller; stewards pull bundles from the controller rather than from external registries.

For the full module packaging architecture, see [ADR-006](docs/architecture/decisions/006-module-packaging-and-distribution.md).

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

Publisher public keys are baked into the steward binary at build time and cannot be changed via `cfg push`. See [docs/architecture/modules/distribution.md](docs/architecture/modules/distribution.md) for the full trust and signing model.

### Module contract

- **ConfigState Interface**: Efficient field-level comparison without marshal/unmarshal overhead
- **System-Level Testing**: Steward automatically compares current vs desired state
- **Managed Fields**: Only specified fields are modified, others left unchanged
- **Out-of-process isolation**: A module crash cannot corrupt steward state

The gRPC wire contract is specified in [docs/architecture/modules/interface.md](docs/architecture/modules/interface.md).

### Standard library

The steward installer ships a closed set of stdlib modules (ADR-016): `file`, `service`, `package`, `script`, `firewall`, `patch`, `user`, `cert_trust`, `time`, `hostname`. Everything else is an `extended` module pulled on demand. See [docs/architecture/modules/README.md](docs/architecture/modules/README.md) for the membership criterion and the current module inventory, and [docs/modules/](docs/modules/README.md) for per-module operator reference.

### Desired State Configuration (DSC)

Modules operate in DSC mode:
1. **Evaluate** current state
2. **Compare** to desired state
3. **Apply** changes only if needed
4. **Report** changes made

Example:
```yaml
modules:
  - name: file
    path: /etc/app/config.yml
    content: "{{ template }}"
    owner: root
    mode: "0644"
    state: present
```

See [docs/architecture/modules/](docs/architecture/modules/) for detailed module documentation.

## Security Model

CFGMS implements a **zero-trust security model**:

### Authentication

- **Steward-Controller**: Certificate-based mutual TLS
- **API Access**: API key authentication
- **User Access**: Username/password with MFA (planned)

For the controller REST API identity assurance model (ADR-021: AssuranceStrong enforcement, assurance level table, and the full strong-assurance endpoint list), see [Security Architecture — Auth-Tier Policy](docs/security/architecture.md#auth-tier-policy).

### Authorization

- **Role-Based Access Control (RBAC)**: Hierarchical permissions
- **Continuous Authorization**: Real-time permission evaluation
- **Just-In-Time (JIT) Access**: Temporary elevated permissions
- **Tenant Isolation**: Strict boundaries between tenants

### Data Protection

- **Encryption at Rest**: SOPS-encrypted secrets
- **Encryption in Transit**: TLS 1.3 for all communication
- **Audit Logging**: Comprehensive tamper-evident audit trails
- **Secret Management**: Pluggable secret backends (SOPS, Vault)

### Compliance

- **Audit Trails**: All actions logged with tenant/user attribution
- **Compliance Templates**: CIS, HIPAA, PCI-DSS reporting
- **SIEM Integration**: Real-time event correlation

See [SECURITY.md](SECURITY.md) for security policy and vulnerability reporting.

## Multi-Tenancy

CFGMS supports **recursive multi-tenancy** for MSP and SaaS environments:

### Tenant Model

Tenants form a **recursive parent-child tree** with no fixed depth. "MSP → Client → Group → Device" is a common convention, not a structural limit. Tenants are identified by path (e.g., `acme-msp/client-a/production`).

```
acme-msp (root)
 ├── client-a
 │   ├── production
 │   │   ├── device-1 (steward)
 │   │   └── device-2 (steward)
 │   └── development
 │       └── device-3 (steward)
 └── client-b
     └── device-4 (steward)
```

### Configuration Inheritance

- **Recursive Resolution**: Cfgs resolve from root to leaf, merging at each level
- **Override Capability**: Any tenant can override inherited settings
- **Source Tracking**: Every value carries its source tenant path and version
- **Declarative Merging**: Named resources replace entire blocks

### Isolation

- **Data Isolation**: Tenants cannot access other tenants' data
- **Resource Isolation**: CPU/memory limits per tenant
- **Network Isolation**: Separate certificate chains per tenant
- **Audit Isolation**: Separate audit logs per tenant
- **Multi-Root Isolation**: Independent root tenants are fully isolated

### Licensing Boundary

All CFGMS code is licensed under AGPL-3.0. Single-root and multi-root deployments are architectural shapes, not licence tiers; every deployment shape runs the same AGPL-3.0 code. A commercial embedding licence exists only for third parties shipping CFGMS inside proprietary products. See [LICENSING.md](LICENSING.md).

### Scale

Designed for:
- 50,000+ stewards
- 100+ clients per MSP
- Multi-region deployment
- High availability via controller clustering ([ADR-031](docs/architecture/decisions/031-controller-cluster-service-model.md))

## Platform Architecture

### Cross-Platform Design Philosophy

CFGMS implements a **platform-agnostic core** with **platform-specific optimizations**:

- **Unified Business Logic**: Core configuration management logic works identically across platforms
- **Platform-Specific Collectors**: Native system information gathering (WMI on Windows, syscalls on Unix)
- **Adaptive Module System**: Modules automatically adapt to platform capabilities and constraints
- **Consistent API**: Same REST API and gRPC-over-QUIC transport protocol regardless of underlying platform

### Platform-Specific Implementations

#### Windows

- **WMI Integration**: Native Windows Management Instrumentation for system data
- **PowerShell Commands**: Advanced system configuration via PowerShell execution
- **Windows Services**: Native service management and health monitoring
- **Registry Management**: Direct Windows Registry manipulation for configuration
- **ACL Support**: Windows Access Control List integration for security

#### Unix-like (Linux/macOS)

- **Syscall Integration**: Direct system call access for efficient data collection
- **Package Manager Integration**: Native support for apt, yum, brew, etc.
- **POSIX Compliance**: Full POSIX file system and process management
- **Process Control**: Advanced Unix process management and signal handling
- **Network Stack**: Native network interface and routing table access

### Deployment Pattern

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

For detailed platform support information, see [docs/deployment/platform-support.md](docs/deployment/platform-support.md).

## Monitoring and Observability

CFGMS includes comprehensive monitoring capabilities:

- **Distributed Tracing**: OpenTelemetry-based tracing with correlation IDs
- **Structured Logging**: JSON logs with trace correlation
- **System Metrics**: Resource usage and application performance monitoring
- **Third-Party Integration**: Prometheus, Grafana, ELK stack, Jaeger support
- **REST API**: Monitoring endpoints for external system integration

See the [Monitoring Guide](docs/monitoring.md) for detailed configuration and usage.

## Design Principles

### 1. Clean Architecture

**Separation of Concerns**:
- `cmd/` - Application entry points
- `features/` - Business logic
- `pkg/` - Shared libraries and provider interfaces
- `api/proto/` - API definitions
- `test/` - Integration tests

**Dependency Rule**: Inner layers (pkg) never depend on outer layers (features).

### 2. Pluggable Provider System

**Rule**: If functionality is needed by >1 feature, it MUST use or become a pluggable provider.

**Current Providers**:
- `pkg/storage` - Data persistence (git, database, sqlite)
- `pkg/logging` - Structured logging (file, timescale)
- `pkg/secrets` - Secret management (SOPS, Vault)
- `pkg/cache` - Write-through caching (memory, Redis)
- `pkg/session` - Session management (memory, Redis, database)
- `pkg/cert` - Certificate management (internal CA, Let's Encrypt, Vault)
- `pkg/telemetry` - Observability (OpenTelemetry, Datadog, Prometheus)
- `pkg/directory` - Directory services (M365, Active Directory)
- `pkg/transport` - gRPC-over-QUIC transport provider

**Design Philosophy**: Make providers pluggable by default. This allows the system to scale from single-server deployments to distributed, multi-region architectures without refactoring business logic.

See [pkg/README.md](pkg/README.md) for provider development guidelines and [docs/architecture/provider-architecture.md](docs/architecture/provider-architecture.md) for the complete pattern.

### 3. Test-Driven Development

**Philosophy**: Test the actual program using real components, not mocks.

**Standards**:
- Write tests first
- Use real CFGMS components
- Test error paths and race conditions
- 80%+ coverage for new code
- 100% coverage for security/auth

### 4. Security First

**Requirements**:
- No hardcoded secrets
- Input validation at all boundaries
- Parameterized SQL queries
- Mutual TLS for internal communication
- Audit logging for all state changes

### 5. Pluggable by Default

**Assumption**: Make providers pluggable unless proven unnecessary.

**Benefits**:
- Multi-tenant SaaS flexibility
- Testing without mocks
- Future-proofing

## Getting Started

### For Contributors

1. **Read the documentation**:
   - [CONTRIBUTING.md](CONTRIBUTING.md) - Contribution guidelines
   - [DEVELOPMENT.md](DEVELOPMENT.md) - Development setup
   - [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) - Community standards

2. **Explore the architecture docs**:
   - [docs/architecture/](docs/architecture/) - Detailed design documents
   - [docs/development/](docs/development/) - Development guides

3. **Set up your environment**:
   ```bash
   git clone https://github.com/cfg-is/cfgms.git
   cd cfgms
   make test  # Verify environment
   ```

4. **Start contributing**:
   - Check [GitHub Issues](https://github.com/cfg-is/cfgms/issues) for tasks
   - Review [roadmap](docs/product/roadmap.md) for upcoming features
   - Join discussions in GitHub Discussions

### Key Files to Review

- `CLAUDE.md` - AI-assisted development guidelines
- `docs/architecture/provider-architecture.md` - Provider system design
- `docs/architecture/modules/interface.md` - Module development
- `docs/development/story-checklist.md` - Development workflow

## Additional Resources

- [Documentation index](docs/README.md) - Every documentation directory
- [Operating model](docs/architecture/operating-model.md) - Runtime behaviour, failure modes, component roles
- [Steward configuration](docs/architecture/steward-configuration.md) - `hostname.cfg` format and options
- [Terminology](docs/terminology.md) - Component names and definitions
- [REST API reference](docs/api/rest-api.md) - Endpoint documentation
- **Project Website**: https://cfg.is
- **Documentation**: https://docs.cfg.is
- **GitHub Repository**: https://github.com/cfg-is/cfgms
- **Project Board**: https://github.com/orgs/cfg-is/projects/1

## Questions?

For questions about the architecture:

- **General questions**: Open an issue with the `question` label
- **Design discussions**: Use GitHub Discussions
- **Architecture decisions**: See [docs/architecture/decisions/](docs/architecture/decisions/)

---

**Welcome to CFGMS! We're excited to have you contribute to the project.**
