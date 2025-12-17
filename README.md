# CFGMS (Config Management System)

CFGMS is a modern configuration management system designed with resilience, security, and clean architecture in mind.

## Project Status

The project is in early development. Core architecture and structure have been implemented, but many components are still being developed.

### Project Management
Development progress is tracked through the **"CFGMS Development Roadmap"** GitHub Project:
https://github.com/orgs/cfg-is/projects/1

This project board provides real-time visibility into:
- Current development priorities and milestones
- Issue tracking and feature requests
- Sprint planning and task organization
- Overall project completion status

## License

CFGMS uses a **dual licensing model** to balance open source community benefits with sustainable commercial development:

- **[Apache License 2.0](LICENSE-APACHE-2.0)** - The vast majority of CFGMS, including all modules, integrations, CLI/API, workflow engine, DNA system, RBAC, and monitoring
- **[Elastic License 2.0](LICENSE-ELASTIC-2.0)** - A small subset of enterprise features (HA clustering, future Web UI)

**Quick Summary:**
- ✅ **Open Source (Apache 2.0)**: Free forever, use commercially, modify and distribute freely
- ✅ **Commercial (Elastic 2.0)**: Free to use in your infrastructure, cannot offer as a hosted service to third parties

For complete licensing details, feature boundaries, and FAQ, see [LICENSING.md](LICENSING.md).

## Why Open Source?

CFGMS uses an **open core** model that balances community benefits with sustainable development:

### Our Philosophy

**"All code that touches client environments and APIs is open source"**

This principle means:
- ✅ **All integrations are OSS** - M365, Active Directory, endpoint modules, PSA/RMM connectors
- ✅ **Complete automation engine** - Full workflow capabilities, no feature gating
- ✅ **Production-ready security** - RBAC, audit logging, compliance reporting, zero-trust controls
- ✅ **Community-driven modules** - Anyone can contribute integrations and modules

We believe integrations should be transparent, auditable, and community-driven. Our competitive advantage is the **platform experience** (DNA system, drift detection, unified management), not gatekeeping integrations.

### Why This Matters for MSPs

1. **Trust** - Audit all code that touches your client environments
2. **Flexibility** - Start free, upgrade when you need HA or Web UI
3. **No Vendor Lock-in** - Self-host the OSS version forever
4. **Community Velocity** - More contributors = faster integrations
5. **Sustainable** - Commercial features fund continued OSS development

## Features: OSS vs Commercial

| Category | Open Source (Apache 2.0) | Commercial (Elastic 2.0) |
|----------|-------------------------|--------------------------|
| **Core Platform** | | |
| Architecture | ✅ Single controller | ✅ HA clustering (Raft consensus, auto-failover) |
| CLI/API | ✅ Complete functionality | ❌ CLI/API always OSS |
| Web UI | ❌ None | ✅ Drag-and-drop workflow builder, dashboards |
| Storage | ✅ Git, SQLite, PostgreSQL | ✅ Same (HA-optimized PostgreSQL) |
| **Modules & Integrations** | | |
| Endpoint Management | ✅ File, directory, package, script, firewall | ❌ All modules are OSS |
| M365 Integration | ✅ Entra ID, Teams, Exchange, SharePoint, Intune | ❌ All modules are OSS |
| Active Directory | ✅ User/group management, GPO, LDAP | ❌ All modules are OSS |
| PSA/RMM Connectors | ✅ All (when built) | ❌ All modules are OSS |
| **Automation** | | |
| Workflow Engine | ✅ YAML workflows, loops, conditions, error handling | ❌ Engine is OSS |
| Debugging | ✅ Breakpoints, step-through, variable inspection | ❌ Debugging is OSS |
| Orchestration | ❌ None | ✅ Multi-stage workflows, approval gates |
| Visual Editor | ❌ None | ✅ Web UI workflow builder |
| **DNA & Drift Detection** | | |
| DNA Collection | ✅ Hardware, software, network, security attributes | ❌ All DNA is OSS |
| Drift Detection | ✅ Real-time, configurable, remediation workflows | ❌ All DNA is OSS |
| System Blueprints | ✅ Templates, comparisons, compliance | ❌ All DNA is OSS |
| **Security & Compliance** | | |
| RBAC | ✅ Role-based access control (CLI-managed) | ✅ Advanced (Web UI, conditional access) |
| Audit Logging | ✅ Complete audit trail | ❌ Audit is OSS |
| Compliance Reporting | ✅ CIS, HIPAA, PCI-DSS templates | ❌ Reporting is OSS |
| Zero-Trust Controls | ✅ JIT access, continuous authorization | ❌ Security is OSS |
| **Monitoring & Alerting** | | |
| Performance Metrics | ✅ Endpoint & controller monitoring | ❌ Monitoring is OSS |
| Threshold Alerts | ✅ Email, webhook notifications | ❌ Alerting is OSS |
| SIEM Integration | ✅ Real-time event correlation | ❌ SIEM is OSS |
| Predictive Analytics | ❌ None | ✅ ML-based anomaly detection, forecasting |
| **Multi-Tenancy** | | |
| Single MSP | ✅ Unlimited hierarchy (MSP→Client→Group→Device) | ❌ OSS supports single MSP |
| Multiple MSPs | ❌ None | ✅ SaaS-scale multi-MSP deployments |
| **Reporting** | | |
| Data Reports | ✅ Generate all reports via CLI (JSON, CSV, PDF, Excel) | ❌ Reporting engine is OSS |
| Visual Dashboards | ❌ None | ✅ Web UI charts and graphs |
| **Terminal Access** | | |
| Remote Terminal | ✅ Full remote shell capabilities | ❌ Terminal is OSS |

### Key Takeaway

**99% of CFGMS is open source.** The only commercial features are:
- High Availability clustering (for enterprise scale)
- Web UI (future - graphical interface)
- Multi-MSP support (for SaaS providers)
- ML-based predictive analytics (future)

Everything else - all integrations, modules, automation, security, and monitoring - is **completely open source**.

## Upgrade Path: OSS → Commercial

Upgrading from open source to commercial features is seamless:

### When to Upgrade

Consider commercial features when you need:
- **High Availability**: Multiple controllers for 99.99% uptime
- **Web UI**: Graphical workflow builder and dashboards (when released)
- **Multi-MSP**: Hosting multiple MSP customers in a single deployment
- **Predictive Analytics**: ML-based anomaly detection and forecasting (when released)

### How to Upgrade

#### Self-Hosted Commercial

1. **Build with commercial tags**:
   ```bash
   # Instead of standard build
   go build ./cmd/controller

   # Use commercial build
   go build -tags commercial ./cmd/controller
   ```

2. **Configure HA clustering**:
   ```yaml
   # config.yaml
   ha:
     mode: cluster  # or blue-green
     nodes:
       - id: controller-1
         address: controller-1.example.com:7000
       - id: controller-2
         address: controller-2.example.com:7000
       - id: controller-3
         address: controller-3.example.com:7000
   ```

3. **Deploy and test**:
   ```bash
   # All your existing workflows, configurations, and data work immediately
   # No migration required - it's the same codebase!
   ```

#### SaaS Commercial

Contact licensing@cfg.is for commercial licensing:
- **SaaS Pricing**: $250/month for 250 "managed units"
  - 1 endpoint = 1 unit
  - 1 M365 user = 0.1 unit
- **Includes**: Web UI, HA clustering, multi-MSP support, priority support, managed infrastructure

### No Migration Required

The commercial version is the **same codebase** with additional features enabled via build tags. Your configurations, workflows, and data work identically.

For complete licensing details, feature boundaries, and FAQ, see [LICENSING.md](LICENSING.md).

## Platform Support

CFGMS is designed for cross-platform deployment across diverse infrastructure environments:

### Steward (Agent) Support
- **Linux**: AMD64 & ARM64 - Full support across distributions
- **Windows**: AMD64 & ARM64 - Windows 10, 11, Server 2019+
- **macOS**: ARM64 (M series) - Apple Silicon Macs

### Controller Support  
- **Linux**: AMD64 - Primary target for production deployments
- **Windows**: AMD64 - Development and testing environments

For detailed platform information, installation instructions, and deployment architectures, see [docs/deployment/platform-support.md](docs/deployment/platform-support.md).

## Development

CFGMS follows the GitFlow branching model:

- `main` branch contains production-ready code
- `develop` branch is for integration of features
- Feature development happens in `feature/*` branches
- See [CONTRIBUTING.md](CONTRIBUTING.md) for complete workflow details

## Next Steps

For current development priorities and detailed roadmap information, please refer to:

- **Roadmap**: See [docs/product/roadmap.md](docs/product/roadmap.md) for the complete development roadmap and version planning
- **Project Management**: Visit the [CFGMS Development Roadmap](https://github.com/orgs/cfg-is/projects/1) GitHub Project for real-time progress tracking and task management

The roadmap provides detailed milestone planning from v0.1.0 through v3.5.0+, including current development phases, feature priorities, and architectural concepts that guide the project's evolution.

## Security

CFGMS implements a robust security architecture:

- **Internal Communication**
  - MQTT+QUIC hybrid protocol for steward-controller communication
  - MQTT (control plane) with mutual TLS for real-time commands and heartbeats
  - QUIC (data plane) with mutual TLS for high-performance configuration/DNA sync
  - Certificate-based authentication for all steward connections
  - Optional OpenZiti integration for zero-trust networking

- **External Access**
  - REST API with HTTPS and API key authentication
  - Role-based access control
  - Rate limiting and request validation

- **Security Best Practices**
  - No hardcoded credentials
  - Secure defaults
  - Comprehensive logging

## REST API

CFGMS provides a comprehensive REST API for external system integration:

- **Base URL**: `http://localhost:9080/api/v1` (configurable)
- **Authentication**: API key-based authentication
- **Endpoints**: Steward management, configuration, certificates, RBAC
- **Format**: JSON with standardized response structure

### Quick API Example

```bash
# Check system health
curl http://localhost:9080/api/v1/health

# List stewards (requires API key)
curl -H "X-API-Key: your-key" http://localhost:9080/api/v1/stewards

# Get steward configuration
curl -H "X-API-Key: your-key" http://localhost:9080/api/v1/stewards/steward-001/config
```

See [docs/api/rest-api.md](docs/api/rest-api.md) for complete API documentation.

## Project Structure

The project follows a feature-based organization:

- `cmd/` - Command-line applications
  - `controller/` - Controller binary
  - `steward/` - Steward binary
  - `cfg/` - CLI for interacting with the system

- `features/` - Core feature implementations
  - `controller/` - Controller component
  - `steward/` - Steward (agent) component

- `pkg/` - Shared packages
  - `logging/` - Logging utilities

- `api/` - API definitions
  - `proto/` - Protocol buffer definitions

- `test/` - Integration and end-to-end tests

## Quick Start

TODO: Add quick start instructions

## Building from Source

```bash
# Clone the repository
git clone https://github.com/user/cfgms.git
cd cfgms

# Build the controller
go build -o bin/controller ./cmd/controller

# Build the steward
go build -o bin/cfgms-steward ./cmd/steward
```

## Documentation

For full documentation, visit [docs.cfg.is](https://docs.cfg.is)

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and development process.
