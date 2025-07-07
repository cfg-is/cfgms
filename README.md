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

## Development

CFGMS follows the GitFlow branching model:

- `main` branch contains production-ready code
- `develop` branch is for integration of features
- Feature development happens in `feature/*` branches
- See [CONTRIBUTING.md](CONTRIBUTING.md) for complete workflow details

## Next Steps

- [ ] Implement the testing framework
  - [ ] Write unit tests for the controller components
  - [ ] Write unit tests for the steward components
  - [ ] Expand integration tests

- [ ] Implement secure communication layers
  - [ ] Set up gRPC with mTLS for internal steward communication
  - [ ] Implement REST API with HTTPS and API keys
  - [ ] Add optional OpenZiti integration for zero-trust networking
  - [ ] Implement certificate management for steward authentication

- [ ] Create the first basic module
  - [ ] Implement a simple file management module as a proof of concept
  - [ ] Validate the module interface design

- [ ] Enhance the Steward component
  - [ ] Implement health monitoring and self-healing capabilities
  - [ ] Add support for offline operation

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

## Project Structure

The project follows a feature-based organization:

- `cmd/` - Command-line applications
  - `controller/` - Controller binary
  - `steward/` - Steward binary
  - `cfgctl/` - CLI for interacting with the system

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
