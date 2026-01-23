# CFGMS (Config Management System)

CFGMS is a modern configuration management system designed with resilience, security, and clean architecture in mind.

**Key Features:**
- Policy-as-code enforcement or drift detection
- Powerful and easy workflow automation platform
- Built for MSPs multi-tenancy requirements
- Mutual TLS security with zero-trust RBAC
- M365, Active Directory, and endpoint integrations
- Cross-platform support (Windows, macOS, Linux)

[![Build Status](https://github.com/cfg-is/cfgms/workflows/Cross-Platform%20Build%20Validation/badge.svg)](https://github.com/cfg-is/cfgms/actions)
[![Security Scan](https://github.com/cfg-is/cfgms/workflows/Security%20Scanning%20Workflow/badge.svg)](https://github.com/cfg-is/cfgms/actions)
[![CodeQL](https://github.com/cfg-is/cfgms/workflows/CodeQL%20Security%20Analysis/badge.svg)](https://github.com/cfg-is/cfgms/security/code-scanning)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/cfg-is/cfgms/badge)](https://securityscorecards.dev/viewer/?uri=github.com/cfg-is/cfgms)
[![Go Report Card](https://goreportcard.com/badge/github.com/cfg-is/cfgms)](https://goreportcard.com/report/github.com/cfg-is/cfgms)
[![License](https://img.shields.io/badge/License-Apache%202.0%20%2B%20Elastic%20v2-blue.svg)](LICENSING.md)

## Project Status

The project is in early development. Core architecture and structure have been implemented, but many components are still being developed.

### Project Management

Development progress is tracked through the [**CFGMS Development Roadmap** GitHub Project](https://github.com/orgs/cfg-is/projects/1).

This project board provides real-time visibility into:

- Current development priorities and milestones
- Issue tracking and feature requests
- Sprint planning and task organization
- Overall project completion status

## License

CFGMS uses a **dual licensing model**:

- **[Apache License 2.0](LICENSE-APACHE-2.0)** - The vast majority of CFGMS (all modules, integrations, CLI/API, workflow engine, DNA system, RBAC, monitoring)
- **[Elastic License 2.0](LICENSE-ELASTIC-2.0)** - Small subset of enterprise features (HA clustering, future Web UI)

**Quick Summary:**
- **Open Source (Apache 2.0)**: Free forever, use commercially, modify and distribute freely
- **Commercial (Elastic 2.0)**: Free to use in your infrastructure, cannot offer as a hosted service

For complete licensing details, feature boundaries, and FAQ, see [LICENSING.md](LICENSING.md).

## Enterprise Features

Enterprise features (HA clustering, Web UI, multi-MSP) are available by building with `-tags commercial`. These features are **free for internal use** under Elastic License 2.0.

For hosted deployment or support contracts, contact [licensing@cfg.is](mailto:licensing@cfg.is). See [LICENSING.md](LICENSING.md) for complete details.

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

CFGMS implements defense-in-depth security with:

- **Mutual TLS**: All internal communication (MQTT+QUIC) uses certificate-based authentication
- **Zero-Trust RBAC**: Just-in-time access, continuous authorization, audit logging
- **Automated Scanning**: CodeQL, Trivy, gosec, and supply chain security validation
- **Data Protection**: SOPS encryption, TLS 1.3, OS keychain integration

View our security posture: [OpenSSF Scorecard](https://securityscorecards.dev/viewer/?uri=github.com/cfg-is/cfgms)

**Report vulnerabilities** to [security@cfg.is](mailto:security@cfg.is). See [SECURITY.md](SECURITY.md) for complete policy.

## REST API

CFGMS provides a comprehensive REST API for external integration:

- **Authentication**: API key-based
- **Endpoints**: Steward management, configuration, certificates, RBAC
- **Base URL**: `http://localhost:9080/api/v1` (configurable)

See [docs/api/rest-api.md](docs/api/rest-api.md) for complete documentation and examples.

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

**Prerequisites**: Go 1.21+, Git

```bash
# Clone and build
git clone https://github.com/cfg-is/cfgms.git
cd cfgms
make build

# Run controller
./bin/controller

# Run steward (separate terminal)
./bin/cfgms-steward
```

For detailed setup and configuration, see [docs/deployment/](docs/deployment/).

## Building from Source

```bash
# Clone the repository
git clone https://github.com/cfg-is/cfgms.git
cd cfgms

# Build the controller
go build -o bin/controller ./cmd/controller

# Build the steward
go build -o bin/cfgms-steward ./cmd/steward
```

## Documentation

For full documentation, visit [docs.cfg.is](https://docs.cfg.is)

## Contributing

We welcome contributions! Before submitting code:

1. Sign the [Contributor License Agreement](docs/legal/CLA.md) and add your name to [CONTRIBUTORS.md](CONTRIBUTORS.md)
2. Follow the development workflow in [CONTRIBUTING.md](CONTRIBUTING.md)

## Community & Support

- **Issues & Bug Reports**: [GitHub Issues](https://github.com/cfg-is/cfgms/issues)
- **Feature Requests**: [GitHub Issues](https://github.com/cfg-is/cfgms/issues/new)
- **Security Advisories**: [GitHub Security](https://github.com/cfg-is/cfgms/security/advisories)
- **Code Scanning Results**: [GitHub Security](https://github.com/cfg-is/cfgms/security/code-scanning)
- **Project Roadmap**: [GitHub Project Board](https://github.com/orgs/cfg-is/projects/1)
- **Email Contact**: [licensing@cfg.is](mailto:licensing@cfg.is)
