# CFGMS Documentation

Welcome to the CFGMS (Configuration Management System) documentation. This index lists every documentation directory; each directory has its own README with a one-line description of every file it holds.

## For Contributors (Start Here)

- [Architecture](../ARCHITECTURE.md) - System design and architectural overview
- [Contributing Guidelines](../CONTRIBUTING.md) - How to contribute to the project
- [Development Setup](../DEVELOPMENT.md) - Local development environment setup
- [Code of Conduct](../CODE_OF_CONDUCT.md) - Community standards and expectations
- [Security Policy](../SECURITY.md) - Security practices and vulnerability reporting
- [Claude Code Integration](../CLAUDE.md) - AI assistant guidance for working with this codebase

## Architecture & Design

- [Architecture](architecture/README.md) - Operating models, design documents, and the module design layer
- [Architecture Decision Records](architecture/decisions/README.md) - Index of all ADRs
- [Module System](architecture/modules/README.md) - Module architecture, manifest fields, and the stdlib set
- [Web UI Design](design/README.md) - Design system, tokens, and reference mockups for the web UI
- [Terminology](terminology.md) - Standardized component terminology and definitions

## Reference

- [Reference](reference/README.md) - Configuration schema reference
- [REST API](api/README.md) - REST API documentation and OpenAPI specification
- [Modules](modules/README.md) - Per-module operator reference (file, firewall, user, time, hostname, cert_trust, script)

## Administration & Operations

- [Administration](administration/README.md) - Day-2 admin from the `cfg` CLI: selectors and steward management
- [Operations](operations/README.md) - Runbooks: upgrades, cluster configuration, Hyper-V onboarding, agent dispatch
- [Runbooks](runbooks/README.md) - Trivy rollback runbook
- [Monitoring Guide](monitoring.md) - Tracing, structured logging, metrics, and third-party integration
- [Troubleshooting](troubleshooting/README.md) - Connectivity troubleshooting and investigation notes

## Deployment

- [Deployment](deployment/README.md) - Deployment modes, walkthroughs, canonical config files, and install guides

## Configuration & Integration Guides

- [Guides](guides/README.md) - Configuration inheritance and script-signing CI
- [M365 Integration Guide](M365_INTEGRATION_GUIDE.md) - Microsoft 365 integration setup
- [CSP Sandbox Setup Guide](CSP_SANDBOX_SETUP_GUIDE.md) - Cloud Solution Provider testing environment

## Development

- [Development](development/README.md) - Contributor process, workflow, standards, and CI documentation
- [Development Standards](development/standards/README.md) - Coding, testing, documentation, and casing standards
- [GitHub CLI Reference](github-cli-reference.md) - Using `gh` with the CFGMS project board
- [Testing](testing/README.md) - Testing strategy, E2E guides, and live-validation runbooks

## Security

- [Security](security/README.md) - Security architecture, certificates, configuration, and credential setup
- [Security Review](security-review/README.md) - Methodology, threat scenarios, and regression corpus for the LLM security review harness

## Product

- [Product](product/README.md) - Vision, roadmap, feature boundaries, and the autonomous agent system PRD

## Legal

- [Legal](legal/README.md) - Contributor License Agreement and enforcement guide

## Examples

- [Examples](examples/README.md) - Logging, monitoring, storage, and role-config examples

## Archive

- [Archive](archive/README.md) - Historical documents kept for reference; not maintained
