# CFGMS Architecture

This document provides a high-level overview of the CFGMS (Config Management System) architecture for contributors. For detailed design documents, see [docs/architecture/](docs/architecture/).

## Table of Contents

- [System Overview](#system-overview)
- [Core Components](#core-components)
- [Communication Architecture](#communication-architecture)
- [Storage Architecture](#storage-architecture)
- [Module System](#module-system)
- [Security Model](#security-model)
- [Multi-Tenancy](#multi-tenancy)
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

**Deployment**: Typically deployed as a single instance (OSS) or HA cluster (Commercial)

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
- Gate commercial features through provider selection

See [docs/architecture/plugin-architecture.md](docs/architecture/plugin-architecture.md) for detailed provider development guidelines.

## Module System

CFGMS uses a **declarative module system** for configuration management:

### Module Types

#### Workflow Modules
Execute on controller as part of workflows, typically for cloud/SaaS API integrations:
- **M365 Modules**: entra_user, conditional_access, teams, exchange, sharepoint
- **Cloud Modules**: aws_*, azure_*
- **Compliance Modules**: compliance_policy, audit_report

These modules run in the workflow engine and make API calls to external services. They execute centrally because they manage organization-wide resources that aren't tied to a specific endpoint.

#### Steward Modules
Execute on managed endpoints for local resource management:
- **System Modules**: file, directory, package, service
- **Security Modules**: firewall, user, group
- **Configuration Modules**: registry (Windows), plist (macOS), config_file (Linux)
- **Feature or Package Modules**: active_directory, MSSQL, DHCP, DNS
- **Execution Modules**: script, command

These modules run locally on stewards because they manage endpoint-specific resources (files, packages, firewall rules) that require local access.

### Module Interface

All modules implement a standard interface:

```go
type Module interface {
    Name() string
    Execute(ctx context.Context, config ModuleConfig) (ModuleResult, error)
    Validate(config ModuleConfig) error
    GetSchema() ModuleSchema
}
```

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
- **Multi-Root Isolation** (Commercial): Independent root tenants are fully isolated

### Licensing Boundary

- **Apache (OSS)**: Single root tenant tree, unlimited depth
- **Elastic (Commercial)**: Multiple independent root trees on shared infrastructure (SaaS/platform mode)

See [Feature Boundaries](docs/product/feature-boundaries.md) for the complete breakdown.

### Scale

Designed for:
- 50,000+ stewards
- 100+ clients per MSP
- Multi-region deployment
- High availability (Commercial edition)

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

See [pkg/README.md](pkg/README.md) for provider development guidelines and [docs/architecture/plugin-architecture.md](docs/architecture/plugin-architecture.md) for the complete pattern.

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
- Commercial/OSS feature gating
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
- `docs/architecture/plugin-architecture.md` - Plugin system design
- `docs/architecture/modules/interface.md` - Module development
- `docs/development/story-checklist.md` - Development workflow

## Additional Resources

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
