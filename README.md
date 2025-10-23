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
  - gRPC with mutual TLS for steward-controller communication
  - Certificate-based authentication for stewards
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
  - `cfgcli/` - CLI for interacting with the system

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
