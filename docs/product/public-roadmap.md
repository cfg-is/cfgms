# CFGMS Public Roadmap

This document provides a high-level overview of the CFGMS development roadmap for users and potential contributors. For detailed internal planning, see [roadmap.md](./roadmap.md).

## Current Status

**Current Version**: v0.6.0 (Alpha)

CFGMS is currently in active alpha development with a strong foundation complete. The core endpoint management system is functional and includes:

- Multi-tenant configuration management
- Policy-driven automation
- DNA-based system identification and drift detection
- MQTT+QUIC communication protocol
- Pluggable storage (Git with SOPS encryption, PostgreSQL)
- Advanced workflow engine

## Upcoming Releases

### v0.7.0 - Open Source Preparation (Current)

**Target**: Q4 2025

Preparing the codebase for public open source release:

- Community documentation (CONTRIBUTING, CODE_OF_CONDUCT, SECURITY)
- User documentation (QUICK_START, DEVELOPMENT, ARCHITECTURE)
- Dual licensing (Apache 2.0 + Elastic License v2)
- Security audit and hardening
- GitHub community infrastructure

### v0.8.0 - Public Launch

**Target**: Q4 2025

Making the repository publicly available:

- Repository visibility change to public
- GitHub Actions CI/CD workflows enabled
- Automated release process
- Binary distribution

### v0.9.0 - Production Stability (Beta)

**Target**: Q4 2025

Achieving production-ready stability:

- Real-world MSP deployment validation
- Performance optimization
- Complete high availability validation
- Advanced workflow and reporting finalization

### v0.10.0 - Web Interface Foundation

**Target**: Q4 2025

User-friendly web management interface:

- Web UI framework and authentication
- Dashboard with fleet overview
- Configuration management interface
- Basic reporting and visualization

### v0.11.0 - Outpost Foundation

**Target**: Q1 2026

Network infrastructure monitoring component:

- Basic Outpost component implementation
- Proxy cache for configuration distribution
- Network device monitoring foundation
- Outpost-Controller communication

### v0.12.0 - M365 Foundation

**Target**: Q2 2026

Microsoft 365 integration for MSPs:

- M365 CSP infrastructure setup
- Core M365 modules (Entra ID, Teams, Exchange, SharePoint)
- M365 security baseline workflows
- Multi-tenant enterprise app support

### v0.13.0 - MSP PSA Integration

**Target**: Q3 2026

Professional Services Automation integration:

- ConnectWise Manage integration
- AutoTask integration
- Smart Helpdesk Context System
- Customer onboarding automation

### v0.14.0 - MSP RMM & Documentation

**Target**: Q4 2026

RMM and documentation platform integrations:

- SyncroMSP, ConnectWise RMM, Datto RMM
- ITGlue, Hudu, Notion integrations
- Incident response automation

### v1.0.0-RC1 - Release Candidate

**Target**: Q1 2027

Final validation before v1.0:

- Extended production testing period
- Performance optimization and benchmarking
- Security audit completion
- API stability freeze
- Migration guide for v1.0.0

### v1.0.0 - Stable Release

**Target**: Q2 2027

Feature-complete platform with stability guarantees:

- Fully functional web interface
- Basic outpost functionality
- M365 and MSP tool integrations
- Backward compatibility guarantees
- Long-Term Support (LTS)
- Complete API documentation
- Production deployment guides

## Future Directions

### SaaS Management (Post v1.0)

Expanding beyond endpoint management to SaaS platforms:

- Microsoft 365 module suite (Entra ID, Teams, Exchange, SharePoint)
- Google Workspace integration
- MSP tool integrations (ConnectWise, AutoTask, Datto)

### Digital Twin & AI (v2.0+)

Advanced capabilities leveraging the DNA system:

- Comprehensive Digital Twin model
- Predictive analytics
- AI-assisted script generation
- Natural language queries

## Feature Requests

We welcome feature requests and feedback! Here's how to contribute:

1. **Check existing issues**: Search [GitHub Issues](https://github.com/cfgis/cfgms/issues) for similar requests
2. **Create a new issue**: Use the feature request template
3. **Join the discussion**: Participate in [GitHub Discussions](https://github.com/cfgis/cfgms/discussions)

## Version Support

| Version Type | Support Period |
|-------------|----------------|
| Current | Full support with bug fixes and security patches |
| Previous Minor | Security patches for 3 months |
| LTS (1.x.x) | Security patches for 18 months |

See [Versioning Policy](../development/versioning-policy.md) for complete details.

## Open Source vs Commercial

CFGMS uses an open-core model:

- **Open Source (Apache 2.0)**: Core functionality, endpoint modules, single-controller deployments
- **Commercial (Elastic License v2)**: High availability, enterprise features, priority support

See [Feature Boundaries](./feature-boundaries.md) for the complete comparison.

## Contributing

We welcome contributions from the community! To get started:

1. Read [CONTRIBUTING.md](../../CONTRIBUTING.md)
2. Review [DEVELOPMENT.md](../../DEVELOPMENT.md) for local setup
3. Check [good first issues](https://github.com/cfgis/cfgms/labels/good%20first%20issue)

## Stay Updated

- **Releases**: Watch the repository for release notifications
- **Changelog**: See [CHANGELOG.md](../../CHANGELOG.md) for version history
- **Discussions**: Join [GitHub Discussions](https://github.com/cfgis/cfgms/discussions) for announcements

---

*Last updated: 2025-11-19*
