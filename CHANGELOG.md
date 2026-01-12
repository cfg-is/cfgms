# Changelog

All notable changes to CFGMS will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Semantic versioning policy documentation
- CHANGELOG.md for tracking version history
- Public-facing roadmap for community visibility

### Changed
- Roadmap version numbering updated for clearer progression

## [0.7.0] - Unreleased

### Added

#### Open Source Preparation
- **Dual Licensing**: Apache 2.0 for open source, Elastic License v2 for commercial features
- **License Headers**: SPDX headers added to all 802 source files
- **Community Documentation**: CONTRIBUTING.md, CODE_OF_CONDUCT.md, SECURITY.md
- **User Documentation**: QUICK_START.md, DEVELOPMENT.md, ARCHITECTURE.md
- **Feature Boundaries**: Clear documentation of OSS vs Commercial features

#### Security Hardening
- Security audit with 9/9 findings remediated (100%)
- SQL identifier whitelist validation
- Regex timeout mechanism
- Admin operation audit controls
- API key persistence to durable storage
- PostgreSQL Row-Level Security (RLS) for tenant isolation
- Central Provider Compliance Enforcement System (6-layer defense)

#### Architecture Improvements
- Dual-CA bug fix for production mTLS
- SOPS storage provider configuration fix
- Cache migration to centralized `pkg/cache` (681 lines removed)
- gRPC removal - migrated to MQTT+QUIC protocol
- Renamed cfgctl to cfg for better discoverability

### Changed
- High Availability (HA) code moved to commercial tier with build tags
- Security rating improved from A- to A (0 High/Medium vulnerabilities)
- Upgraded to Go 1.25.3 for security and performance
- Updated golangci-lint to v2.x

### Removed
- gRPC dependencies and service definitions
- 18 internal documentation files before OSS launch
- 9 test binaries from repository
- 24 unfinished TODO items (6 fixed, 18 removed)

## [0.6.0] - 2025-10-21

### Added

#### Endpoint Management
- **Advanced Script Execution**: Git-versioned scripts with semantic versioning
- **DNA Parameter Injection**: Dynamic `$DNA.OS.Version` and `$CompanySettings` variables
- **Ephemeral API Keys**: Secure script-to-controller callbacks
- **Multi-Platform Scripts**: PowerShell, Bash/zsh, Python, batch/cmd support

#### Configuration Templates
- Template marketplace infrastructure with 3 example templates
- OSS template marketplace (GitHub-based, community contributions)
- Template testing framework with unit tests and scenarios
- Compliance validation via DNA + drift detection

#### Windows Patch Compliance
- Policy-driven patching with declarative configuration
- Patch type policies (Critical: 7 days, Important: 14 days)
- Major version upgrade support (Win 10->11, 23H2->24H2)
- Windows Update COM API integration (no WSUS dependency)
- Generic maintenance windows honored by all reboot operations

#### Performance Monitoring
- Endpoint performance metrics (CPU, memory, disk, network)
- Top 10 CPU/memory consumers per device
- Process/service watchlist with auto-start option
- Threshold-based alerting (warning/critical levels)
- Time-series storage interface ready for InfluxDB/TimescaleDB

#### Controller Health Monitoring
- Controller metrics (MQTT broker, storage, queues, resources)
- Workflow/script queue depth monitoring
- Email alerting via SMTP
- Request tracing for troubleshooting
- Health API endpoints (simple + detailed + Prometheus)
- CLI tools: `cfg controller status`, `cfg trace <request_id>`

## [0.5.0] - 2025-09-15

### Added

#### Global Logging
- Pluggable logging provider with File and TimescaleDB backends
- RFC5424 structured logging fields
- Syslog forwarding support
- Complete component migration to structured logging

#### Advanced Workflow Engine
- Conditionals, nested workflows, loops
- Try/catch error handling
- Cron scheduling and webhooks
- SIEM integration API
- Transform functions and Go templates
- JSONPath/XPath support
- Interactive debugging (pause/resume, breakpoints)
- Workflow versioning and templates

#### Reporting Framework
- DNA and audit integration
- 8 compliance report templates
- Multi-format export (JSON/CSV/PDF/HTML/Excel)
- Report scheduling and pagination

#### Platform Capabilities
- Internal platform monitoring with anomaly detection
- Lightweight SIEM engine (10k+ events/sec)
- Production security hardening (HIPAA/SOX/PCI/GDPR)
- High availability with Raft clustering (1.3s failover)
- QA infrastructure consolidation with unified Docker testing

#### MQTT+QUIC Communication
- Complete gRPC to MQTT+QUIC migration
- NAT traversal support
- 2,738 lines of integration tests
- 60+ test scenarios with 79% coverage increase
- TLS/mTLS security validation (98/100 rating)
- Multi-tenant isolation testing

## [0.4.6.0] - 2025-08-20

### Added

#### Complete Storage Migration (Epic 6)
- RBAC storage migration to pluggable architecture
- Audit and compliance storage with retention policies
- Configuration and rollback storage migration
- Session and runtime storage migration
- Storage provider testing infrastructure
- Memory storage backend eliminated from global registry
- Shared cache utility consolidation
- SQLite DNA storage as default backend

## [0.4.5.0] - 2025-08-01

### Added

#### Core Global Storage Foundation (Epic 5B)
- Pluggable storage architecture with provider interfaces
- Enhanced Git storage provider with SOPS encryption
- Enhanced database storage provider with PostgreSQL
- Foundation storage migration maintaining backward compatibility

## [0.4.0] - 2025-07-15

### Added

#### Advanced Module System
- Module dependency management with circular detection
- Complete module lifecycle (init, startup, shutdown)
- Module versioning with semantic versioning support

#### Advanced RBAC + Zero-Trust
- Role inheritance with override capabilities
- Fine-grained permissions with resource-level controls
- Enhanced multi-tenant security with tenant isolation
- Just-In-Time (JIT) access framework
- Risk-based access controls
- Continuous authorization engine
- Zero-trust policy engine

#### M365 Foundation
- Multi-tenant consent flow implementation
- Delegated permissions OAuth2 authentication
- MSP admin consent flow with client onboarding

#### Unified Directory Management
- Directory service abstraction (AD + Entra ID)
- Directory DNA integration with drift detection
- Active Directory provider with LDAP operations
- Entra ID provider with Microsoft Graph API

## [0.3.2] - 2025-06-15

### Fixed
- Critical security vulnerabilities (CVE-2025-21613, CVE-2025-21614)
- GitHub Actions gosec installation issues
- Terminal session race conditions with mutex synchronization

### Changed
- Updated go-git from v5.12.0 to v5.13.0

## [0.3.1] - 2025-06-01

### Added
- Local security scanning (Trivy, Nancy, gosec, staticcheck)
- Unified `make security-scan` and `make test-with-security` targets
- GitHub Actions parallel security workflow (60-70% performance improvement)
- Production deployment gates blocking critical/high vulnerabilities

## [0.3.0] - 2025-05-15

### Added

#### Workflow Engine & SaaS Foundation
- Comprehensive WorkflowError with debugging
- Enhanced condition evaluation (AND/OR/NOT)
- Loop constructs (for, while, foreach)
- M365 Virtual Steward prototype
- API Module Framework with universal provider interface

#### Enterprise Configuration Management
- Git backend with SOPS encryption
- Configuration rollback with risk assessment
- Configuration templates with DNA integration
- Version comparison tools with semantic diff

#### DNA-Based Monitoring
- Enhanced DNA collection (161 attributes)
- DNA storage with content-addressable deduplication
- Drift detection engine
- Comprehensive reporting system

#### Remote Access & Integration
- Terminal core implementation
- Terminal security controls
- E2E test framework for cross-platform testing
- Production readiness validation

## [0.2.1] - 2025-04-01

### Added
- BMAD agent sprint planning implementation
- GitHub CLI automation for project board management
- Test infrastructure cleanup (98%+ success rate)

### Fixed
- Pre-existing test failures (config service, monitoring deadlocks)
- Race conditions in export manager

## [0.2.0] - 2025-03-01

### Added
- Configuration data flow implementation
- gRPC upgrade with configuration push
- DNA-based sync verification
- Configuration validation
- Basic RBAC/ABAC
- Certificate management
- Basic API endpoints
- Configuration inheritance
- Basic monitoring
- Basic multi-tenancy
- Script execution capabilities
- Workflow engine with HTTP client, webhooks, delays

## [0.1.0] - 2025-01-15

### Added
- Core architecture definition
- Component interaction design
- Security model establishment
- Initial documentation
- Module system framework
- Basic Steward functionality
- Basic Controller functionality
- Steward-Controller integration validation

---

## Version Types

- **Alpha** (0.x.x): Active development, API may change
- **Beta** (0.x.x-beta): Feature complete, testing phase
- **Stable** (1.x.x): Production ready with backward compatibility

## Links

- [Roadmap](docs/product/roadmap.md)
- [Versioning Policy](docs/development/versioning-policy.md)
- [Contributing](CONTRIBUTING.md)
