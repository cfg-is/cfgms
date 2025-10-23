# CFGMS Licensing

CFGMS uses a **dual licensing model** to balance open source community benefits with sustainable commercial development.

## License Overview

### Apache License 2.0 (Open Source)

The vast majority of CFGMS is licensed under the [Apache License 2.0](LICENSE-APACHE-2.0), including:

- **Complete CLI and API** - Full command-line and REST API functionality
- **All Modules and Integrations** - Endpoint management, M365, Active Directory, PSA/RMM connectors
- **Workflow Engine** - Complete YAML execution with loops, conditions, error handling, and debugging
- **DNA System** - Drift detection, system blueprints, and templates
- **Security Features** - RBAC, audit logging, compliance, SIEM integration
- **Monitoring & Alerting** - Performance metrics, health monitoring, threshold alerts
- **Terminal Access** - Remote terminal capabilities
- **All Tests and Documentation**

### Elastic License 2.0 (Commercial)

A small subset of enterprise features is licensed under the [Elastic License 2.0](LICENSE-ELASTIC-2.0):

- **High Availability Clustering** - Raft-based consensus, automatic failover, load balancing (located in `commercial/ha/`)
- **Web UI** (planned future feature) - Graphical interface for workflow building and system management

The Elastic License v2 is source-available and prevents competitors from offering CFGMS as a hosted service while allowing you to use it freely in your own infrastructure.

## Why Dual Licensing?

This model provides:

1. **Community Trust** - All integrations and core logic are open source, enabling community contributions and audits
2. **Flexibility** - Use OSS version free forever, or add commercial features when needed
3. **Sustainability** - Commercial features fund continued development of both OSS and commercial code
4. **Competitive Protection** - Prevents large cloud providers from offering CFGMS as a service without contributing back

## What Can I Do?

### With Apache 2.0 Code (OSS)

✅ Use commercially without restrictions
✅ Modify and distribute
✅ Create derivative works
✅ Contribute back to the project
✅ Use in proprietary products
✅ Offer professional services

### With Elastic License 2.0 Code (Commercial)

✅ Use in your own infrastructure
✅ Modify for internal use
✅ Self-host for your organization
❌ Offer as a hosted/managed service to third parties
❌ Remove or circumvent license key functionality

## Building CFGMS

### Open Source Build (Default)

Build the OSS version with single-controller deployment:

```bash
# Build OSS binaries
make build

# Or build specific components
go build ./cmd/controller
go build ./cmd/steward
go build ./cmd/cfgcli

# Run OSS tests (HA tests automatically excluded)
make test
```

**OSS Version Includes:**
- Single controller deployment
- All modules and integrations
- Complete CLI/API functionality
- Full workflow capabilities
- DNA system with drift detection
- RBAC, audit, compliance, monitoring
- Terminal access

**OSS Version Excludes:**
- HA clustering (BlueGreenMode, ClusterMode)
- Raft consensus and automatic failover
- Load balancing and split-brain detection
- Cross-node session synchronization

### Commercial Build

Build the commercial version with full HA clustering:

```bash
# Build commercial binaries with HA support
make build TAGS=commercial

# Or build with tags directly
go build -tags commercial ./cmd/controller

# Run all tests including HA cluster tests
make test TAGS=commercial
```

**Commercial Version Adds:**
- Full HA clustering capabilities
- Raft-based consensus
- Automatic failover with <1.5s recovery
- Geographic load balancing
- Split-brain detection and resolution
- Cross-node session synchronization
- Blue-green deployments

## Feature Boundaries

For a complete breakdown of what's included in OSS vs Commercial, see [docs/product/feature-boundaries.md](docs/product/feature-boundaries.md).

### Key Principles

- **"All code that touches client environments/APIs is OSS"** - This maximizes community trust and contribution velocity
- **Platform features are commercial** - HA clustering, Web UI (future)
- **CLI/API is always OSS** - Complete functionality available via command-line

## Multi-Tenancy

### Single MSP (OSS)
✅ Unlimited hierarchical depth (MSP → Client → Group → Device)
✅ Complete tenant isolation and security
✅ Full multi-tenant capabilities

### Multiple MSPs (Commercial)
✅ Support for SaaS deployments hosting multiple MSPs
✅ MSP-level isolation and management

## Revenue Model

### Open Source
- **Free forever** for single-controller deployments
- **Community support** via GitHub Issues and Discussions
- **Optional paid support** available from maintainers

### Commercial
- **SaaS Pricing**: $250/month for 250 "managed units"
  - 1 endpoint = 1 unit
  - 1 M365 user = 0.1 unit
  - Includes: Web UI, HA clustering, multi-MSP support, priority support
- **Self-Hosted Commercial**: Contact for licensing terms

## FAQ

### Can I use CFGMS commercially?

Yes! Both OSS (Apache 2.0) and Commercial (Elastic License 2.0) code can be used commercially. The Apache 2.0 code has no restrictions, and the Elastic License 2.0 code can be used in your own infrastructure without limitation.

### Can I offer CFGMS as a service?

- **Apache 2.0 components** (all integrations, modules, CLI/API): Yes, with proper attribution
- **Elastic License 2.0 components** (HA clustering, future Web UI): No, you cannot offer these as a hosted service to third parties

### Do I need to open source my modifications?

No. Neither Apache 2.0 nor Elastic License 2.0 requires you to open source your modifications. However, contributions back to the project are always welcome!

### Can I contribute to CFGMS?

Absolutely! We welcome contributions to all parts of CFGMS. By contributing, you agree that your contributions will be licensed under the same license as the component you're contributing to (Apache 2.0 for OSS components, Elastic License 2.0 for commercial components).

### How do I know what's licensed under which license?

- **Apache 2.0**: All source files contain Apache 2.0 license headers
- **Elastic License 2.0**: Files in `commercial/ha/` with `//go:build commercial` tag, future Web UI code
- See [docs/product/feature-boundaries.md](docs/product/feature-boundaries.md) for complete breakdown

### What if I need HA but can't afford commercial licensing?

Reach out to discuss your use case. We may have options for non-profits, educational institutions, or early-stage companies.

### Can I fork CFGMS?

Yes! Apache 2.0 components can be freely forked. Elastic License 2.0 components are source-available and can be viewed/modified but cannot be offered as a competing hosted service.

## License Compatibility

### Apache 2.0 is Compatible With:
- ✅ GPL v3 (but combined work becomes GPL v3)
- ✅ MIT, BSD, ISC
- ✅ Most permissive licenses
- ✅ Commercial/proprietary code

### Elastic License 2.0 is Compatible With:
- ✅ Internal use in any environment
- ✅ Commercial/proprietary code for internal use
- ❌ Offering as a hosted service

## Contact

- **General Questions**: Open a [GitHub Discussion](https://github.com/cfg-is/cfgms/discussions)
- **Commercial Licensing**: Contact licensing@cfg.is
- **Security Issues**: See [SECURITY.md](SECURITY.md)
- **Contributing**: See [CONTRIBUTING.md](CONTRIBUTING.md)

---

**Last Updated**: 2025-10-22
**Version**: v0.7.0

For the complete legal text:
- [Apache License 2.0](LICENSE-APACHE-2.0)
- [Elastic License 2.0](LICENSE-ELASTIC-2.0)
