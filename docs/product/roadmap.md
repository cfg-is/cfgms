# CFGMS Development Roadmap

## Overview

This document outlines the development roadmap for the Configuration Management System (CFGMS). It provides a clear vision for the project's development, including milestones, features, and release planning, incorporating recent strategic adjustments to better align with MSP market voids and core product vision.

## Versioning Strategy

CFGMS follows semantic versioning (MAJOR.MINOR.PATCH):

- **Major Version (X.0.0)**: Significant architectural changes or breaking changes
- **Minor Version (0.X.0)**: New features with backward compatibility
- **Patch Version (0.0.X)**: Bug fixes and minor improvements

For detailed versioning policy, support timelines, and upgrade guidance, see [Versioning Policy](../development/versioning-policy.md).

For complete version history and release notes, see [CHANGELOG.md](../../CHANGELOG.md).

## Development Phases

### Phase 1: Foundation (v0.1.0 - v0.6.0)

**Goal**: Establish the core architecture and basic functionality, with an emphasis on critical MSP value, including multi-tenancy, foundational automation, and DNA-driven drift tracking.

#### v0.1.0 (Alpha) - ✅ COMPLETED

Core architecture, security model, module system framework, and basic Steward-Controller integration with end-to-end communication validation.

#### v0.2.0 (Alpha) - Critical Core & Early Multi-Tenancy/Automation - ✅ COMPLETED

Configuration data flow, validation, inheritance, basic RBAC/ABAC, certificate management, API endpoints, monitoring, multi-tenancy, script execution, workflow engine with API integration and webhook primitives. BONUS: DNA-based sync verification.

#### v0.2.1 (Alpha) - Test Infrastructure & Sprint Planning Foundation - ✅ COMPLETED

Test infrastructure cleanup with 98%+ success rate, AI-assisted sprint planning framework with GitHub CLI automation, 25 story points/night development velocity documented.

#### v0.3.0 (Alpha) - Enhanced Automation & SaaS Steward Foundation - ✅ COMPLETED

Enhanced workflow engine (42 pts: Stories #69-73 - error handling, conditionals, loops, SaaS steward, API framework), enterprise config management (34 pts: Stories #74-77 - Git backend, rollback, templates, diff tools), DNA monitoring (34 pts: Stories #78-81 - 161 attributes, storage with 90%+ compression, drift detection, reporting), remote access (39 pts: Stories #82-86 - terminal with RBAC, E2E testing, production readiness with 100+ sessions).

#### v0.3.1 (Alpha) - Security Tools Implementation - ✅ COMPLETED

4 security tools integrated (Trivy, Nancy, gosec, staticcheck), production deployment gates, GitHub Actions parallel workflow with 60-70% performance improvement, comprehensive documentation.

#### v0.3.2 (Alpha) - Security Vulnerability Remediation - ✅ COMPLETED

Critical CVE remediation (go-git v5.13.0), race condition fixes, gosec installation fixes, zero critical/high vulnerabilities, 100% system validation with production readiness confirmed.

#### v0.4.0 (Alpha) - Advanced Multi-Tenancy & Plugin Architecture - ✅ COMPLETED

Advanced module system (21 pts: Issues #110-112 - dependency management, lifecycle, versioning), advanced RBAC with zero-trust (50 pts: Issues #113-115, #124-127 - role inheritance, JIT access, risk-based controls, continuous authorization), RBAC integration validation (25 pts: Issues #128-135 - 1000+ tenants, sub-millisecond auth, attack prevention), M365 direct app access (21 pts: Issues #116-117 - admin consent, OAuth2), unified directory management (47 pts: Issues #120-123 - AD/Entra ID abstraction, DirectoryDNA, LDAP/Graph API).

#### v0.4.5.0 (Alpha) - Core Global Storage Foundation - ✅ COMPLETED

Pluggable storage architecture (Issues #136-139) with Git (SOPS encryption, GitOps) and PostgreSQL (ACID transactions) providers, auto-registration, unified configuration system.

#### v0.4.6.0 (Alpha) - Complete Storage Migration - ✅ COMPLETED

RBAC/audit/config/session migration to pluggable storage (Issues #141-144, #152, #154, #157), memory provider elimination, write-through caching patterns, SQLite/PostgreSQL DNA storage (Issues #145, #159, #146), Docker testing infrastructure, 200+ lines duplicate code removed.

#### v0.5.0 (Beta) - Advanced Workflows & Core Readiness - ✅ COMPLETED

Stories 1.1-12.5 (Issues #166-207): Global logging provider (File/TimescaleDB), advanced workflow engine (conditionals/loops/debugging/versioning), reporting framework (8 compliance templates), SIEM engine (10k+ events/sec), HA infrastructure (Raft, 1.3s failover), MQTT+QUIC migration (2,738 test lines, 100+ concurrent stewards), TLS/mTLS validation (98/100 security rating).

#### v0.6.0 (Alpha) - Finalizing Foundational Endpoint CMS - ✅ COMPLETED

Policy-driven automation with advanced script execution (Issue #210 - Git-versioned, DNA injection, multi-platform), template marketplace (Issue #211 - 3 examples, OSS GitHub-based), Windows patch compliance (Issue #212 - policy-driven, COM API, maintenance windows), endpoint performance monitoring (Issue #213 - 2,746 lines, <1% CPU, watchlist alerts), controller health monitoring (Issue #214 - MQTT/storage/queue metrics, email alerts, request tracing).

#### v0.7.0 (Pre-OSS / Alpha) - Open Source Preparation - ✅ COMPLETED

Codebase prepared for open source launch with proper licensing, clean architecture, and production-ready security. See [v0.7.0-epic.md](./v0.7.0-epic.md) and [feature-boundaries.md](./feature-boundaries.md).

#### v0.7.1: Code Cleanup - ✅ COMPLETED

gRPC removal (Issue #220), cfgctl→cfg rename (Issue #221), HA commercial tier separation (Issue #222), repository cleanup (Issue #223 - 18 files removed, 24 TODOs), sensitive data scan (Issue #224 - zero secrets found).

#### v0.7.2: Security Review - ✅ COMPLETED

Internal security audit (Issue #225 - 9/9 findings remediated), infrastructure hardening (Issue #239 - SQL validation, RLS, A- → A rating), cache consolidation (681 lines removed).

#### v0.7.3: Licensing & Documentation - ✅ COMPLETED

Apache 2.0 + Elastic v2 dual licensing (Issue #226 - 802 SPDX headers), feature boundaries documentation (Issue #227 - 10 categories, 30+ features), comprehensive docs (Issue #228 - CONTRIBUTING/SECURITY/ARCHITECTURE/DEVELOPMENT/QUICK_START).

#### v0.7.4: Community & Launch Prep - ✅ COMPLETED

Community infrastructure (Issue #229 - issue/PR templates, CODEOWNERS, good first issues including #254 CLI error messages), versioning policy (Issue #230), CHANGELOG.md, public roadmap, email infrastructure (Issue #248 - security@/licensing@/conduct@).

#### v0.7.5: Testing Infrastructure & Security Hardening - ✅ COMPLETED

Storage foot-guns eliminated (26 pts: Issues #262-264, #274-275 - tenant/registration/M365 auth/rollback migrated to durable storage), configuration signing (Issue #250 - RSA/ECDSA), explicit environment variable references (Issue #251).

#### v0.7.5 Phase 2: Production-Realistic Testing (Issue #252) - ✅ COMPLETED

Implemented comprehensive Docker-based E2E testing infrastructure that validates all three CFGMS deployment tiers with real binaries in ephemeral containers. Guarantees QUICK_START.md documentation works 100%.

- [x] **QUICK_START Option A Validation** - 5 story points ✅ - Standalone steward E2E testing with Docker (`test/integration/standalone/`, 5 tests passing)
- [x] **Certificate Registration Flow Testing** - 4 story points ✅ - Registration token store wired, QUICK_START.md Options B/C fixed
- [x] **YAML Configuration File Validation** - 3 story points ✅ - Controller+Steward E2E testing (`test/integration/controller/`, 7 tests passing)
- [x] **Cross-Platform Build Validation** - 2-3 story points ✅ - Cross-platform build workflow added (`.github/workflows/cross-platform-build.yml`)
- [x] **Productize Test Infrastructure Tooling** - 2-3 story points ✅ - `bin/cfgms-wait-for-services` released, comprehensive documentation created

**Results**: 12 new E2E tests (100% pass rate), 81 files changed (+5,513/-509 lines), QUICK_START.md validated and corrected

#### v0.8.0 Go public

- [x] Create security scanning configuration files (`.gitleaks.toml`, `.gosec.json`) (issue #279) ✅ COMPLETED
- [x] Add public repository workflows (Dependabot, CodeQL, container scanning, license compliance, SBOM) (issue #280) ✅ COMPLETED
- [ ] Create `SECURITY.md` vulnerability disclosure policy (issue #281)
- [ ] Re-enable and validate GitHub Actions workflows (issue #109, issue #15)
- [ ] ~~Convert repository to public and~~ activate GitHub Advanced Security features (issue #282)
- [ ] Configure branch protection rules (issue #283)
- [ ] Update documentation with security badges and public links (issue #284)

### Phase 2: Production Stability & Feature Completion (v0.9.0 - v1.0.0)

Achieve production stability, complete core platform features, and prepare for stable release.

#### v0.9.0 (Beta) - Production Stability

- [ ] Complete production validation with real MSP deployments
- [ ] Finalize production-ready security hardening
- [ ] Complete high availability validation
- [ ] Finalize advanced configuration management
- [ ] Finalize advanced workflow engine and templates
- [ ] Finalize advanced reporting
- [ ] Communication Layer Abstraction (Issue #267 - 47 story points) - Control/Data Plane provider interfaces, controller/steward migration, deprecate direct MQTT/QUIC imports

#### v0.10.0 - Web Interface Foundation

- [ ] Web UI framework and authentication
- [ ] Dashboard with fleet overview
- [ ] Configuration management interface
- [ ] User and role management
- [ ] Workflow Management
- [ ] Basic reporting and visualization

#### v0.10.5 - Security Maturation & Web Frontend Security

**Goal**: Enhance security posture with advanced tooling and prepare web interface security foundations

**Backend Security Enhancements**:
- [ ] OpenSSF Scorecard optimization (target score: 9.0+)
- [ ] Go native fuzzing integration for critical packages
- [ ] Evaluate and integrate Snyk (if beneficial beyond existing coverage)
- [ ] Evaluate and integrate SonarCloud (if beneficial beyond staticcheck)
- [ ] Security testing automation improvements

**Web Frontend Security Preparation**:
- [ ] Evaluate web application security scanners (OWASP ZAP, Burp Suite Community)
- [ ] Plan Content Security Policy (CSP) implementation
- [ ] Evaluate frontend dependency scanning tools (npm audit, Snyk for JavaScript)
- [ ] Plan XSS/CSRF protection strategies
- [ ] Evaluate SAST tools for frontend code (ESLint security plugins, semgrep for JavaScript)
- [ ] Document web security requirements and tooling strategy

**Security Policy & Process**:
- [ ] Conduct first external security audit (if resources available)
- [ ] Establish CVE response procedures
- [ ] Create security incident response playbook
- [ ] Enhance security testing documentation

**Rationale**: After Web Interface Foundation (v0.10.0), we need to mature our security tooling and establish web-specific security practices before deploying web frontend to production. This ensures we maintain our excellent security posture (9/10) as the system grows in complexity.

#### v0.11.0 - Outpost Foundation

- [ ] Basic Outpost component implementation
- [ ] Proxy cache for configuration distribution
- [ ] Network device monitoring foundation
- [ ] Outpost-Controller communication

#### v0.12.0 - M365 Foundation

- [x] Enhanced Tenant Management (Issue #118 / PR #238 - 8 points) ✅ - M365TenantManager with GDAP discovery, health monitoring, bulk operations
- [ ] M365 CSP Infrastructure Setup (5 points) - Partner Center sandbox, GDAP relationships, enterprise app registration
- [ ] Per-Tenant Token Storage and Management (Issue #119 - 10 points)
- [ ] M365 Integration Validation (8 points) - GDAP discovery, consent flow, health monitoring tests
- [ ] SaaS Steward using workflow engine foundation
- [ ] Core M365 modules (15+) - Entra ID, Teams, Exchange, SharePoint, Security (Defender/Intune/CA policies)
- [ ] M365 security baseline workflows
- [ ] M365 user lifecycle automation

#### v0.13.0 - MSP PSA Integration

- [ ] ConnectWise Manage integration - Company/customer/contact/ticket management, service agreements
- [ ] AutoTask integration - Account/contact management, ticket and contract handling
- [ ] Smart Helpdesk Context System - Phone integration, DNA-driven dashboard, contextual troubleshooting, network topology visualization
- [ ] Customer onboarding automation workflows
- [ ] User lifecycle management workflows

#### v0.14.0 - MSP RMM & Documentation

- [ ] SyncroMSP integration module
- [ ] Connectwise Screenconnect integration modules
- [ ] ConnectWise Azio/RMM integration modules
- [ ] Datto RMM integration modules
- [ ] Notion integration module (knowledge management)
- [ ] ITGlue integration modules (documentation automation)
- [ ] Hudu integration modules (knowledge management)
- [ ] Incident response automation workflows
- [ ] Security monitoring and compliance workflows
- [ ] Multi-tenant management workflows

#### v1.0.0-rc.1 - Pre-1.0 Validation

- [ ] Extended production testing period
- [ ] Performance optimization and benchmarking
- [ ] Complete documentation review
- [ ] Security audit completion
- [ ] Migration guide for v1.0.0
- [ ] API stability freeze (no breaking changes after this point)

#### v1.0.0 (Stable) - General Availability

- [ ] Feature-complete core platform
- [ ] Fully functional web interface
- [ ] Basic outpost functionality
- [ ] LTS (Long-Term Support) designation
- [ ] Backward compatibility guarantees
- [ ] Complete API documentation
- [ ] Production deployment guides

### v1.1.0 - v1.2.0: Advanced SaaS Management & Ecosystem Expansion (Consider moving to Beta pre v1.0)

#### v1.1.0: Advanced SaaS Capabilities

- [ ] Advanced M365 management modules (Power Platform, Purview, etc.)
- [ ] Multi-SaaS platform support (Google Workspace, Salesforce)
- [ ] SaaS configuration templates and best practices library
- [ ] Advanced security policy automation
- [ ] Cross-platform SaaS identity management

#### v1.2.0: MSP Ecosystem & Controller Enhancement

- [ ] Additional MSP tool integrations (N-able, SolarWinds, etc.)
- [ ] Workflow template marketplace for MSPs
- [ ] Advanced multi-tenant SaaS management
- [ ] Hierarchical Controller Management
- [ ] Advanced Outpost functionality for SaaS traffic optimization
- [ ] Advanced Steward functionality

### Future Features

**Goal**: Realize the full potential of DNA-based system identification and expand into advanced resource management and specialized capabilities.

#### Digital Twin Implementation

- [ ] Implement comprehensive Digital Twin model
- [ ] Add support for real-time asset inventory
- [ ] Develop predictive analytics capabilities
- [ ] Implement root cause analysis based on Digital Twin

#### LLM Integration Evaluation

- [ ] Research and evaluate LLM integration for natural language queries
- [ ] Implement AI-assisted script generation
- [ ] Develop AI-driven anomaly detection

#### Further Expansion & Specialization

- [ ] Implement advanced resource management capabilities
- [ ] Develop Digital Employee Experience (DEX) monitoring
- [ ] Implement Cluster-Aware Patching
- [ ] Explore further specialized integrations and features

## Architectural Concepts

The following concepts represent the foundation for future architectural decisions and provide a framework for evaluating new features and capabilities as the system evolves.

### Scalability and Performance

#### Distributed Architecture

- Modular, distributed components for high availability
- Event-driven communication for responsiveness
- Horizontal scaling for increased capacity
- Buffer pools for temporary allocations
- Comprehensive resource monitoring and alerting

#### Hierarchical Scaling Architecture

- Controller clustering with intelligent load balancing
- Hierarchical controller management with parent-child relationships
- Efficient task delegation and distributed processing
- Database sharding strategies for massive scale

#### Comprehensive Validation Framework

Multi-layered validation approach:

- Schema validation for structural correctness
- Constraint checking for business rules
- Dependency validation for complex relationships
- Structured error reporting with clear user guidance

### Configuration Management Insights

#### Steward Connection Architecture

- Stewards initiate all connections (no open ports on endpoints)
- Persistent connections for instant command processing
- Connection resilience with retry backoff and circuit breakers
- Heartbeat-based connection management and health monitoring

#### Advanced Configuration Storage

- Git-based configuration storage with atomic operations
- Automatic state validation and reconciliation
- Comprehensive version history and rollback capabilities
- Integration with external configuration management systems

## Version Information

- **Document Version**: 2.9
- **Last Updated**: 2025-11-26

### Related Documentation

- [Versioning Policy](../development/versioning-policy.md) - Semantic versioning details
- [CHANGELOG.md](../../CHANGELOG.md) - Complete version history
- [Feature Boundaries](./feature-boundaries.md) - OSS vs Commercial features
