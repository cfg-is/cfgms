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

## Current Status

- **Current Version**: 0.6.0 (Alpha) - ✅ v0.6.0 COMPLETE (Finalizing Foundational Endpoint CMS)
- **Status**: v0.6.0 Complete - Foundational endpoint CMS with policy-driven automation, compliance templates, and proactive performance management
- **Focus**: Open source preparation and advanced SaaS management capabilities

## Development Phases

### Phase 1: Foundation (v0.1.0 - v0.6.0)

**Goal**: Establish the core architecture and basic functionality, with an emphasis on critical MSP value, including multi-tenancy, foundational automation, and DNA-driven drift tracking.

#### v0.1.0 (Alpha) - ✅ COMPLETED

- [x] Define core architecture
- [x] Design component interactions
- [x] Establish security model
- [x] Create initial documentation
- [x] Create module system framework
- [x] Implement basic Steward functionality (issue #13)
- [x] Implement basic Controller functionality (issue #14)
- [x] Validate Steward-Controller Integration and End-to-End Communication (issue #28)

#### v0.2.0 (Alpha) - Critical Core & Early Multi-Tenancy/Automation - ✅ COMPLETED

- [x] Implement configuration data flow (issue #29) - ✅ COMPLETED
- [x] Upgrade gRPC to the latest version and implement configuration push from controller (issue #48) - ✅ COMPLETED
- [x] **BONUS**: DNA-based sync verification system - ✅ COMPLETED (advanced sync state verification with minimal bandwidth usage)
- [x] Implement configuration validation (issue #34) - ✅ COMPLETED
- [x] Implement basic RBAC/ABAC (issue #31) - ✅ COMPLETED
- [x] Implement certificate management (issue #35) - ✅ COMPLETED
- [x] Create basic API endpoints (issue #36) - ✅ COMPLETED
- [x] Implement configuration inheritance (issue #37) - ✅ COMPLETED
- [x] Add basic monitoring capabilities (issue #38) - ✅ COMPLETED
- [x] Implement Basic Multi-tenancy (issue #30) - ✅ COMPLETED
- [x] Implement Basic Script Execution Capabilities (issue #39) - ✅ COMPLETED
- [x] Implement Workflow Engine (Basic) (issue #32) - ✅ COMPLETED
  - [x] Extend workflow engine for API-based modules and SaaS Steward foundation
  - [x] Add HTTP client with authentication and rate limiting to workflow engine
  - [x] Implement workflow engine integration framework for external APIs
  - [x] Add webhook and delay workflow primitives - ✅ COMPLETED

#### v0.2.1 (Alpha) - Test Infrastructure & Sprint Planning Foundation - ✅ COMPLETED

**Goal**: Establish clean test foundation and implement BMAD agent-driven sprint planning for v0.3.0 development

**Core Objectives:**

- [x] **Test Infrastructure Cleanup**: Ensure all tests pass cleanly to prevent tech debt in v0.3.0
  - [x] Evaluate current test coverage sufficiency for v0.3.0 progression (98%+ success rate achieved)
  - [x] Fix remaining pre-existing test failures (config service tests, monitoring deadlocks, race conditions)
  - [x] Establish baseline test quality standards for future development (production risk gates implemented)
- [x] **BMAD Agent Sprint Planning Implementation**: Transition to AI-assisted sprint planning methodology
  - [x] Use BMAD agents to analyze v0.3.0 roadmap requirements
  - [x] Generate detailed user stories from v0.3.0 milestone features
  - [x] Create sprint planning framework with automated story breakdown
  - [x] Establish story point estimation using historical v0.2.0 velocity data
  - [x] Set up automated project board management via GitHub CLI integration

**Key Achievements:**
- **BMAD Sprint Planning**: Successfully implemented AI-assisted sprint planning with 149 story points for v0.3.0
- **GitHub CLI Automation**: Complete project board automation with 22 issues created (4 epics + 18 stories)
- **Revolutionary Velocity**: Documented 25 story points/night development pace with AI assistance
- **Comprehensive Documentation**: PRD, sprint plan, and velocity analysis created
- **Issues Completed**: 8 of 9 v0.2.1 issues resolved (#53-56, #58-61)

**Outstanding Work:**
- [x] **Test Stability**: Critical test failures resolved (race conditions, export manager issues)
- [x] **Issue #57**: Test suite validation completed - 98%+ success rate achieved

#### v0.3.0 (Alpha) - Enhanced Automation & SaaS Steward Foundation

**Status**: ✅ COMPLETE - All 4 Epics Complete (v0.3.0 Ready for Production Deployment)

**✅ Epic #65 COMPLETE: Enhanced Workflow Engine & SaaS Foundation (42 story points)**
- [x] **Workflow Error Handling** (Story #71) - ✅ COMPLETED
  - [x] Comprehensive WorkflowError type with debugging information
  - [x] ErrorHandler interface with configurable retry policies
  - [x] Stack trace capture and execution path tracking
  - [x] Best-in-class debugging capabilities with variable state capture
  - [x] Thread-safe integration with existing workflow engine
- [x] **Workflow Conditional Logic** (Story #69) - ✅ COMPLETED
  - [x] Enhanced condition evaluation with AND/OR/NOT support
  - [x] Expression evaluation with variable substitution
  - [x] Nested condition support up to 5 levels deep
- [x] **Workflow Loop Constructs** (Story #70) - ✅ COMPLETED
  - [x] For, while, and foreach loop implementations
  - [x] Safety mechanisms with maximum iteration limits
  - [x] Variable scoping and loop context management
- [x] **SaaS Steward Prototype** (Story #72) - ✅ COMPLETED
  - [x] M365 Virtual Steward implementation using existing module pattern
  - [x] Three core M365 modules: entra_user, conditional_access, intune_policy
  - [x] OAuth2 authentication framework with secure local credential storage
  - [x] Microsoft Graph API client with adaptive rate limiting
  - [x] Multi-tenant support with cascading configuration inheritance
  - [x] Complete example configurations for single tenant and MSP scenarios
- [x] **API Module Framework** (Story #73) - ✅ COMPLETED
  - [x] Universal Provider interface with normalized CRUD operations + raw API access
  - [x] Universal authentication supporting OAuth2, API keys, Basic Auth, JWT, custom headers
  - [x] Workflow engine integration with saas_action and api node types
  - [x] SaaS Steward module bridge maintaining compatibility with existing module system
  - [x] Resource type normalization and mapping across platforms
  - [x] Progressive abstraction: simple normalized ops → raw API fallback

**✅ Epic #66 COMPLETE: Enterprise Configuration Management (34 story points)**
- [x] **Git Backend Implementation** (Story #74) - ✅ COMPLETED
  - [x] Hybrid repository architecture with MSP global + client repositories
  - [x] GitManager interface with full CRUD operations for repositories and configurations
  - [x] Multi-provider abstraction supporting GitHub, GitLab, Bitbucket
  - [x] go-git integration for local repository operations
  - [x] Cross-repository synchronization with template inheritance
  - [x] **BONUS**: SOPS integration for secrets management with multi-KMS support
  - [x] **BONUS**: Git-as-source-of-truth access control with drift detection
  - [x] **BONUS**: Separate script module repository support with security validation
  - [x] Comprehensive test suite with 100% coverage for core components
- [x] **Configuration Rollback** (Story #75) - ✅ COMPLETED
  - [x] Comprehensive RollbackManager with Git integration for reliable rollback operations
  - [x] Multi-level rollback support (device, group, client, MSP)
  - [x] Risk assessment framework with automatic risk level determination
  - [x] Validation system with breaking change detection and dependency checking
  - [x] Approval workflow for high-risk rollbacks with emergency override capability
  - [x] REST API endpoints for rollback operations (list, preview, execute, status, cancel, history)
  - [x] Audit logging system tracking all rollback operations and decisions
  - [x] Notification framework supporting webhooks and composite notifiers
  - [x] Progressive/canary rollback support for safer deployments
  - [x] Comprehensive test suite with mocked dependencies
- [x] **Configuration Templates** (Story #76) - ✅ COMPLETED
  - [x] Template engine with `$variable` syntax for dynamic configuration generation
  - [x] Three-tier variable resolution system (local > inherited > DNA properties)
  - [x] DNA integration for real-time system properties via `$DNA.Property.Path`
  - [x] Control flow with `$if/$elif/$else/$endif` conditionals and proper nesting validation
  - [x] Template inheritance system with `$extend` and `$include` directives
  - [x] Built-in functions for string manipulation, math operations, and utility functions
  - [x] Comprehensive validation framework with syntax checking and dependency validation
  - [x] Template storage with in-memory and Git-backed implementations
  - [x] Security sandbox for safe template execution
  - [x] Comprehensive test suite with 6 test cases covering all functionality
  - [x] Foundation established for future compliance templates (CIS, HIPAA, PCI-DSS)
- [x] **Version Comparison Tools** (Story #77) - ✅ COMPLETED
  - [x] Side-by-side diff view for configuration changes
  - [x] Semantic diff that understands configuration structure 
  - [x] Highlight breaking changes and security impacts
  - [x] Export diffs in multiple formats (text, JSON, HTML, unified, side-by-side, markdown)
  - [x] Integration with approval workflows for change review
  - [x] CLI integration via cfgcli diff command with advanced filtering
  - [x] Three-way comparison support with conflict detection
  - [x] Comprehensive test suite with edge case handling

**✅ Epic #67 COMPLETE: DNA-Based Monitoring & Detection (34 story points)**
- [x] **Enhanced DNA Collection** (Story #78) - ✅ COMPLETED
  - [x] Comprehensive system attribute collection with 161 attributes (71% increase from 94)
  - [x] Cross-platform hardware collection (CPU, memory, disk, motherboard) using platform-specific APIs
  - [x] Software inventory collection (OS, packages, services, processes) with package manager integration
  - [x] Network configuration collection (interfaces, routing, DNS, firewall rules)
  - [x] Security attributes collection (users, groups, permissions, certificates)
  - [x] Performance optimized (~3 second collection time, <1% CPU usage)
  - [x] Platform-specific collectors for Windows, Linux, and macOS
  - [x] Comprehensive test suite with performance benchmarks and concurrency testing
- [x] **DNA Storage System** (Story #79) - ✅ COMPLETED
  - [x] Content-addressable storage with SHA256-based deduplication achieving space savings
  - [x] Multi-algorithm compression (GZIP, ZSTD, LZ4) with 90%+ space savings on typical DNA data
  - [x] Historical query system supporting time-range and device-specific queries with pagination
  - [x] Automatic retention and archival policies with configurable lifecycle management
  - [x] Horizontal scaling through configurable sharding strategies (device-based, time-based, hybrid)
  - [x] Multiple storage backends: Memory, File System, Git, Database, and Hybrid architectures
  - [x] Comprehensive indexing system for fast lookups and metadata queries
  - [x] Performance monitoring with <100MB/month storage growth per device target
  - [x] Full test coverage with integration tests and performance benchmarks
- [x] **Drift Detection Engine** (Story #80)
- [x] **DNA Monitoring - Comprehensive Reporting System** (Story #81) - ✅ COMPLETED
  - [x] Generate compliance reports showing drift from baselines with risk scoring
  - [x] Create executive dashboards with KPI summaries and trend analysis
  - [x] Export reports in multiple formats (JSON, CSV, HTML, PDF, Excel)
  - [x] Schedule automated report generation via REST API endpoints
  - [x] Include visual charts and graphs with chart data for frontend integration
  - [x] Template-based report generation system with built-in templates
  - [x] Performance-optimized report caching with TTL-based cleanup
  - [x] Modular architecture with interfaces-based pluggable components
  - [x] Integration with existing DNA storage and drift detection systems
  - [x] Comprehensive test suite with no regressions to existing functionality

**✅ Epic #68 COMPLETE: Remote Access & Integration (39 story points)**
- [x] **Terminal Core Implementation** (Story #82) - ✅ COMPLETED
- [x] **Terminal Security Controls** (Story #83) - ✅ COMPLETED
- [x] **Integration Testing - Build Comprehensive E2E Test Framework** (Story #84) - ✅ COMPLETED
  - [x] Cross-platform testing framework (Linux, Windows, macOS)
  - [x] GitHub Actions CI/CD integration with private repo optimization
  - [x] Performance regression testing with baselines
  - [x] Comprehensive test reporting with failure analysis
  - [x] Smart retry logic and GitHub Actions runner optimization
- [x] **Integration Testing - Implement Cross-Feature Test Scenarios** (Story #85) - ✅ COMPLETED
  - [x] **Acceptance Criteria 1**: Workflow + Configuration - Realistic template deployment via workflow engine with end-to-end validation
  - [x] **Acceptance Criteria 2**: DNA + Drift - 5-minute SLA drift detection triggering automatic remediation workflows with latency measurement
  - [x] **Acceptance Criteria 3**: Template + Rollback - Template deployment failure simulation with 30-second rollback SLA validation
  - [x] **Acceptance Criteria 4**: Terminal + Audit - Comprehensive terminal session auditing with RBAC security controls and session tracking
  - [x] **Acceptance Criteria 5**: Multi-tenant + SaaS - M365 configuration inheritance validation across complete tenant hierarchy
  - [x] **Technical Implementation**: End-to-end latency measurement for complex multi-component operations (420+ lines enhanced testdata.go)
  - [x] **Technical Implementation**: Failure propagation testing across component boundaries with recovery validation (800+ lines scenarios_test.go)
  - [x] **Technical Implementation**: Data consistency validation across all features (config, DNA, audit, RBAC, workflow, templates)
  - [x] **CI/CD Integration**: Enhanced GitHub Actions workflow with comprehensive cross-feature test targets and reporting
  - [x] **Testing Framework**: Complete test framework optimization for GitHub Actions with smart retry logic and performance tracking
- [x] **v0.3.0 Production Readiness** (Story #86) - ✅ COMPLETED
  - [x] Load tests validate 100+ concurrent terminal sessions with 95% success rate and <2s latency
  - [x] Performance benchmarks and SLA validation (startup <30s, memory <200MB, response <100ms)
  - [x] Security audit with automated vulnerability scanning and input sanitization testing
  - [x] Disaster recovery procedures tested and documented with automated failover validation
  - [x] Monitoring and alerting integration with Prometheus metrics and health endpoints
  - [x] Synthetic monitoring framework for ongoing production validation and alerting
  - [x] Comprehensive operational runbooks with incident response and maintenance procedures
  - [x] CI/CD pipeline integration with 45-minute production readiness validation workflow

#### v0.3.1 (Alpha) - Security Tools Implementation

**Status**: ✅ COMPLETE - All 3 Epics Complete (Local Security Foundation, Advanced Analysis & Automation, CI/CD Safety Net)

**Goal**: Implement local-first automated security scanning integrated with Claude Code workflow and GitHub Actions backup validation

**✅ Epic 1: Local Security Foundation**
- [x] Trivy filesystem vulnerability scanning with blocking exit codes
- [x] Nancy Go dependency scanning with cross-platform installation
- [x] Developer setup guide and comprehensive documentation
- [x] Unified make targets (`make security-scan`, `make test-with-security`)

**✅ Epic 2: Advanced Analysis & Automation**
- [x] gosec Go security pattern analysis
- [x] staticcheck advanced static analysis
- [x] Optional pre-commit hooks integration
- [x] Automated remediation guidance with Claude Code integration

**✅ Epic 3: CI/CD Safety Net & Production Readiness**
- [x] GitHub Actions parallel security workflow (60-70% performance improvement)
- [x] Production deployment gates blocking critical/high vulnerabilities
- [x] Emergency override with audit trail and SARIF GitHub Security integration
- [x] Complete workflow documentation and team expansion preparation

**Key Achievements**: 4 security tools integrated, production gates established, comprehensive documentation delivered, team-ready foundation

#### v0.3.2 (Alpha) - Security Vulnerability Remediation

**Status**: ✅ COMPLETE - All security vulnerabilities resolved, system validated and ready for production deployment

**Goal**: Achieve 100% green test status across local tests, security scans, and GitHub Actions workflows

**Critical Security Vulnerabilities** (RESOLVED):
- [x] **Story #105**: Fix Critical Security Vulnerabilities (CVE-2025-21613, CVE-2025-21614) - ✅ COMPLETED
  - Updated `github.com/go-git/go-git/v5` from v5.12.0 → v5.13.0
  - Priority: CRITICAL (blocks all deployments) - **RESOLVED**

**GitHub Actions Workflow Fixes**:
- [x] **Story #106**: Fix GitHub Actions gosec Installation Issues - ✅ COMPLETED
  - Fixed authentication failures by correcting gosec repository URL from `securecodewarrior` to `securego`
  - Affects: Security Scanning Workflow + Production Risk Gates - **RESOLVED**
- [x] **Story #107**: Fix Terminal Session Race Conditions - ✅ COMPLETED
  - Fixed race conditions in `features/terminal/session.go:195` with mutex synchronization
  - Added `sync.RWMutex` for thread-safe field access across all Session methods
  - Affects: Production readiness validation tests - **RESOLVED**

**System Validation**:
- [x] **Story #108**: Validate Complete System After Security Updates - ✅ COMPLETED
  - Comprehensive validation confirms all systems operational
  - Zero regressions detected, all functionality intact

**Success Criteria** (✅ ALL ACHIEVED):
- ✅ `make security-scan` passes with zero CRITICAL/HIGH vulnerabilities
- ✅ `make test` passes locally with no race conditions  
- ✅ Load testing validates 100+ concurrent terminal sessions
- ✅ Git backend functionality verified with updated dependencies
- ✅ All existing functionality remains intact after security updates

**Key Achievements**:
- **Zero Critical/High Vulnerabilities**: All blocking security issues resolved
- **Production Readiness**: Load testing passes with 100+ concurrent users
- **Code Quality**: Race conditions eliminated, thread safety ensured
- **System Validation**: Comprehensive testing confirms operational readiness

**Note**: GitHub Actions workflows have infrastructure-related failures (cache corruption, workflow logic issues) that do not impact local system functionality. These CI/CD pipeline issues should be addressed in future CI/CD reliability work.

#### v0.4.0 (Alpha) - Advanced Multi-Tenancy & Plugin Architecture

**Status**: 🚧 IN PROGRESS - 134/159 story points completed across 31 stories (Issues #110-117, #121-123, #124-135) - 84.3% complete *(18 points moved to v1.1.0)* - Epic 4 Complete ✅

**Goal**: Transform CFGMS from foundational architecture to production-ready enterprise platform with advanced multi-tenancy, unified directory management, and comprehensive module system.

**✅ Epic 1: Advanced Module System (21 story points) - Issues #110-112 - ✅ COMPLETED**
- [x] **Module Dependency Management** (Issue #110) - 8 points ✅ COMPLETED
  Dependency resolution with circular dependency detection
  Automatic module loading order based on dependency graph
  Runtime dependency validation with clear error reporting
- [x] **Module Lifecycle Management** (Issue #111) - 8 points ✅ COMPLETED
  Complete module lifecycle with initialization, startup, shutdown phases
  Health monitoring and automatic restart capabilities
  Resource cleanup and graceful degradation handling
- [x] **Module Versioning System** (Issue #112) - 5 points ✅ COMPLETED
  Semantic versioning support with compatibility checking
  Module registry with version constraints and conflict resolution
  Automated module updates with rollback capabilities

**✅ Epic 2: Advanced RBAC + Zero-Trust/JIT Access (50/50 story points) - Issues #113-115, #124-127**
- [x] **Role Inheritance System** (Issue #113) - 8 points ✅ COMPLETED
  Hierarchical role inheritance with override capabilities
  Role composition and conflict resolution mechanisms
  Dynamic role assignment based on organizational structure
- [x] **Advanced Permission Management** (Issue #114) - 8 points ✅ COMPLETED
  Fine-grained permission system with resource-level controls
  Permission bundling and template-based assignment
  Real-time permission evaluation and caching
- [x] **Enhanced Multi-Tenant Security** (Issue #115) - 5 points ✅ COMPLETED
  Complete tenant isolation with cross-tenant prevention
  Tenant-aware RBAC with cascading permissions
  Security boundary enforcement at data and API levels
- [x] **Just-In-Time (JIT) Access Framework** (Issue #124) - 8 points ✅ COMPLETED
  Temporary privilege escalation with automatic expiration
  Request-approval workflow with multi-level authorization
  Session-based access controls with activity monitoring
- [x] **Risk-Based Access Controls** (Issue #125) - 8 points ✅ COMPLETED
  Dynamic risk assessment based on user behavior and context
  Adaptive access policies with real-time risk scoring
  Threat detection integration with automatic response
- [x] **Continuous Authorization Engine** (Issue #126) - 8 points ✅ COMPLETED
  Real-time authorization validation throughout session lifecycle
  Dynamic policy evaluation with context-aware decisions
  Performance-optimized authorization caching and invalidation
- [x] **Zero-Trust Policy Engine** (Issue #127) - 5 points ✅ COMPLETED
  Never-trust-always-verify policy enforcement
  Comprehensive audit trail for all access decisions
  Integration with external identity providers and security systems

**✅ Epic 2.5: RBAC Integration & Production Validation (25/25 story points) - Issues #128-135 - ✅ COMPLETE**
- [x] **Terminal-RBAC Integration Testing** (Issue #128) - 3 points ✅ COMPLETED
  Terminal session authorization with RBAC permission validation
  Command-level access controls with real-time enforcement
  Session audit logging with comprehensive access tracking
- [x] **Controller API Authorization Validation** (Issue #129) - 3 points ✅ COMPLETED
  REST API endpoint protection with role-based access controls
  Request authentication and authorization pipeline validation
  API rate limiting and abuse prevention mechanisms
- [x] **Cross-Tenant Permission Isolation** (Issue #130) - 3 points ✅ COMPLETED
  Complete tenant data isolation with access boundary enforcement
  Cross-tenant operation prevention with security validation
  Tenant context propagation through all system layers
- [x] **Concurrent Authorization Performance** (Issue #131) - 3 points ✅ COMPLETED
  High-throughput authorization with sub-millisecond response times
  Concurrent user session handling with performance benchmarking
  Authorization cache optimization for scalable operations
- [x] **Multi-Tenant Scale Validation** (Issue #132) - 3 points ✅ COMPLETED
  Large-scale multi-tenant deployment testing with 1000+ tenants
  Resource isolation and performance validation under load
  Tenant provisioning and deprovisioning automation testing
- [x] **Audit Trail Completeness Under Load** (Issue #133) - 3 points ✅ COMPLETED
  Comprehensive audit logging for all security-relevant events
  High-throughput audit trail processing with data integrity
  Audit log retention and compliance reporting capabilities
- [x] **Component Failure Security Posture** (Issue #134) - 4 points ✅ COMPLETED
  Fail-secure behavior under component failures and degraded states
  Security boundary maintenance during system recovery
  Attack surface analysis and threat model validation
- [x] **Permission Escalation Attack Prevention** (Issue #135) - 5 points ✅ COMPLETED
  Comprehensive privilege escalation attack testing and prevention
  Security vulnerability scanning and penetration testing
  Access control bypass prevention with security hardening

**✅ Epic 3: M365 Direct App Access Foundation (21 story points) - Issues #116-117 - ✅ COMPLETE**
- [x] **Multi-Tenant Consent Flow Implementation** (Issue #116) - 13 points ✅ COMPLETED
  Complete MSP admin consent flow with multi-tenant client onboarding
  Plugin storage architecture with git-based backend provider
  Production-ready MSP functionality for client management
- [x] **Delegated Permissions Model - Direct App Access** (Issue #117) - 8 points ✅ COMPLETED
  Delegated permissions OAuth2 authentication flows
  Interactive authentication with callback handling
  Comprehensive test suite with 100% clean status

**✅ Epic 4: Unified Directory Management Interface (47/47 story points) - Issues #120-123 - ✅ COMPLETE**
- [x] **Directory Service Abstraction Layer** (Issue #120) - 15 points ✅ COMPLETED
  Universal Directory interface supporting Active Directory and Entra ID
  Provider factory pattern with connection pooling and health monitoring  
  Cross-directory operations with conflict resolution and schema normalization
  Bulk operations with batching and comprehensive functionality validation
- [x] **Directory DNA Integration** (Issue #121) - 13 points ✅ COMPLETED
  DirectoryDNA framework extending CFGMS DNA system to directory objects
  Multi-tenant directory operations with hierarchical processing and drift detection
  Performance-optimized collection with automated remediation workflows
  Thread-safe concurrent processing with comprehensive security validation
- [x] **Active Directory Provider Implementation** (Issue #122) - 10 points ✅ COMPLETED
  Complete Active Directory integration with LDAP operations
  Enterprise authentication and user/group management capabilities
  Domain controller connectivity with fault tolerance and failover
- [x] **Entra ID Provider Implementation** (Issue #123) - 9 points ✅ COMPLETED (12/10/2025)
  Complete CRUD operations for Applications, Admin Units, Users, and Groups
  Real Microsoft Graph API integration with 45+ seconds live validation testing
  OAuth2 authentication with comprehensive integration and unit test coverage
  Field validation fixes ensuring complete user data retrieval from Graph API

#### v0.4.5.0 (Alpha) - Core Global Storage Foundation

**Status**: ✅ COMPLETE - 25/25 story points completed - Epic 5B: Core Global Storage Foundation

**✅ Epic 5B: Core Global Storage Foundation (25 story points)**
- [x] **Core Global Storage Interfaces** (Issue #136) - 8 points ✅ COMPLETED
  Pluggable storage architecture with provider abstraction interfaces
  Global storage configuration system with unified client management
  Storage provider discovery and auto-registration capabilities
- [x] **Enhanced Git Storage Provider** (Issue #137) - 8 points ✅ COMPLETED
  Git-based storage with SOPS encryption and multi-repository support
  GitOps workflows with automated synchronization and conflict resolution
  Multi-KMS support with secrets management integration
- [x] **Enhanced Database Storage Provider** (Issue #138) - 6 points ✅ COMPLETED
  Complete PostgreSQL storage provider with ACID transactions
  Hybrid storage architecture enabling GitOps workflows
  Production-scale database operations with connection pooling
- [x] **Foundation Storage Migration** (Issue #139) - 3 points ✅ COMPLETED
  Enhanced controller configuration system with pluggable storage provider support
  Storage provider configuration via YAML and environment variables
  Foundation architecture with backward compatibility maintained

#### v0.4.6.0 (Alpha) - Complete Storage Migration

**Status**: ✅ COMPLETE - 54 story points - Epic 6: Complete Storage Migration (54/54 points complete - 100%)

**✅ Epic 6: Complete Storage Migration (54 story points)**
- [x] **RBAC Storage Migration** (Issue #141) - 8 points ✅ COMPLETED
  Complete RBAC system migration to pluggable storage architecture
  Role and permission storage with tenant-aware data isolation
  Authorization cache integration with write-through persistence
- [x] **Audit & Compliance Storage Migration** (Issue #142) - 8 points ✅ COMPLETED
  Comprehensive audit trail storage with compliance requirements
  High-throughput audit log processing with data integrity guarantees
  Retention policies and compliance reporting capabilities
- [x] **Configuration & Rollback Storage Migration** (Issue #143) - 6 points ✅ COMPLETED
  Configuration storage with version control and rollback capabilities
  Template storage integration with inheritance and validation
  Multi-tenant configuration isolation with hierarchical access
- [x] **Session & Runtime Storage Migration** (Issue #144) - 5 points ✅ COMPLETED
  RuntimeStore interface implementation with session management migration
  Write-through caching pattern established for component optimization
  Memory provider foot-gun eliminated from global registry
- [x] **Storage Provider Testing Infrastructure** (Issue #152) - 5 points ✅ COMPLETED
  Docker-based integration testing with PostgreSQL, Gitea, and Redis
  Complete storage provider validation infrastructure
  100% core test success rate achieved with provider compatibility testing
- [x] **Memory Storage Backend Elimination** (Issue #154) - 8 points ✅ COMPLETED
  Memory provider completely eliminated from global storage provider structure
  Component-level write-through caching patterns established
  Code duplication identified and architectural cleanup completed
- [x] **Shared Cache Utility Consolidation** (Issue #157) - 3 points ✅ COMPLETED
  Unified cache utility with TTL, size limits, and metrics
  Duplicate cache implementations consolidated into single package
  200+ lines of duplicate code eliminated with comprehensive testing
- [x] **DNA Storage Integration Assessment** (Issue #145) - 3 points ✅ COMPLETED
  DNA storage system evaluation and architecture assessment
  Integration with global storage provider framework
  Performance and scalability requirements analysis
- [x] **SQLite DNA Storage Implementation** (Issue #159) - 8 points ✅ COMPLETED
  SQLite as default DNA storage backend with zero-setup deployment
  Complete PostgreSQL implementation for production scale deployments
  Three-tier storage strategy: SQLite → PostgreSQL → File fallback
  Migration of all DNA storage tests from memory to SQLite backends
- [x] **Storage Pattern Validation & Cleanup** (Issue #146) - 3 points ✅ COMPLETED
  Final validation and cleanup ensuring complete Epic 6 storage migration
  Cross-provider compatibility testing with production readiness validation
  Test helpers updated with proper storage configuration
  All hardcoded storage patterns eliminated from business logic

#### v0.5.0 (Beta) - Advanced Workflows & Core Readiness

**Status**: ✅ COMPLETE - 237/237 story points completed (100%) - 20 stories complete, MQTT+QUIC production readiness achieved

**Goal**: Transform CFGMS from foundational architecture (v0.4.6.0) to production-ready enterprise platform by implementing global logging provider, advanced workflow capabilities, comprehensive reporting, internal monitoring, lightweight SIEM, high availability infrastructure, and complete MQTT+QUIC production readiness validation.

**✅ Epic 1: v0.5.0 Beta - Advanced Workflows & Core Readiness**
- [x] **Global Logging Provider Foundation** (Story 1.1) - 8 points ✅ - Pluggable logging with File/TimescaleDB providers, RFC5424 fields, syslog forwarding
- [x] **Logging Provider Migration** (Story 1.2) - 8 points ✅ - All components migrated, structured logging, tenant isolation
- [x] **Advanced Workflow Engine Extensions** (Story 2.1) - 13 points ✅ - Conditionals, nested workflows, loops, try/catch error handling
- [x] **Workflow Trigger and Scheduling** (Story 2.2) - 10 points ✅ - Cron scheduling, webhooks, SIEM integration API
- [x] **Advanced Data Processing** (Story 2.3) - 13 points ✅ - Transform functions, Go templates, JSONPath/XPath, format conversion
- [x] **Interactive Workflow Debugging** (Story 2.5) - 10 points ✅ - Pause/resume, breakpoints, variable inspector, replay capabilities
- [x] **Enhanced Logging for ML Backtesting** (Story 2.6) - 8 points ✅ - Structured event logging, API response capture, ML export
- [x] **Workflow Versioning and Templates** (Story 3.1) - 13 points ✅ - Semantic versioning, template inheritance, forking, rollback
- [x] **Advanced Reporting Framework** (Story 5.1) - 13 points ✅ - DNA/audit integration, 8 compliance templates, RBAC, caching
- [x] **Custom Report Generation** (Story 6.1) - 13 points ✅ - Multi-format export (JSON/CSV/PDF/HTML/Excel), scheduling, pagination
- [x] **Internal Platform Monitoring** (Story 7.1) - 13 points ✅ - Health/performance metrics, anomaly detection, REST endpoints
- [x] **Lightweight SIEM Engine** (Story 8.1) - 13 points ✅ - Real-time log analysis, pattern matching, workflow triggers, 10k+ events/sec
- [x] **Production Security Hardening** (Story 9.1) - 13 points ✅ - Vulnerability remediation, tenant isolation, compliance (HIPAA/SOX/PCI/GDPR)
- [x] **High Availability Infrastructure** (Story 10.1) - 13 points ✅ - Raft clustering, 1.3s failover, session continuity, load balancing
- [x] **QA Infrastructure Consolidation** (Story 11.1) - 13 points ✅ - Unified Docker testing, port conflict elimination, 13 integration tests added
- [x] **Communication Protocol Migration** (Story 12.1) - 13 points ✅ - gRPC→MQTT+QUIC hybrid, NAT traversal, feature parity
- [x] **MQTT+QUIC Integration Testing** (Story 12.2) - 21 points ✅ - 2,738 lines tests, 60+ scenarios, 79% coverage increase, 100+ concurrent stewards
- [x] **Module Execution Validation** (Story 12.3) - 13 points ✅ - Config executor (309 lines), 14 test cases, file/directory/script modules, idempotency
- [x] **TLS/mTLS Security Validation** (Story 12.4) - 8 points ✅ - Certificate infrastructure, TLS 1.2+ enforcement, security hardening (98/100 rating)
- [x] **Multi-Tenant Isolation Testing** (Story 12.5) - 8 points ✅ - 3 tenant Docker infrastructure, comprehensive MQTT topic isolation tests, all acceptance criteria validated

#### v0.6.0 (Alpha) - Finalizing Foundational Endpoint CMS

**Status**: ✅ COMPLETE - 60/60 story points (5/5 stories complete) - 100% complete
**Goal**: Complete foundational endpoint CMS with policy-driven automation, compliance templates, and proactive performance management
**Epic Document**: [v0.6.0-epic.md](./v0.6.0-epic.md)
**Timeline**: 12 weeks (3 months) - Target Q2 2026

**Design Principle**: Configuration as policy, CFGMS as continuous enforcement

**Epic: v0.6.0 - Finalizing Foundational Endpoint CMS**

- [x] **Advanced Script Execution Capabilities** (Issue #210) - 13 points ✅ COMPLETED
  - Git-versioned scripts with semantic versioning
  - DNA-based parameter injection (`$DNA.OS.Version`, `$CompanySettings.BackupPath`)
  - Ephemeral API keys for script-to-controller callbacks
  - Multi-platform support (PowerShell, Bash/zsh, Python, batch/cmd)
  - Workflow engine integration (scheduling, orchestration, dependencies)
  - Real-time monitoring (aggregated view for bulk, drill-down for individuals)
  - Global template library + per-MSP git repositories
  - Exit code capture and workflow-based retry logic
  - No execution sandboxing (endpoint management scripts, not untrusted code)

- [x] **Configuration Templates (Advanced)** (Issue #211) - 13 points ✅ COMPLETED
  - Template marketplace infrastructure with 3 example templates using existing modules
    - Example 1: SSH hardening template (file-based config) ✅
    - Example 2: Baseline security template (file + directory + script) ✅
    - Example 3: Backup configuration template (directory + script) ✅
  - OSS template marketplace (GitHub-based, community contributions) ✅
  - Template testing framework (unit tests, test scenarios) ✅
  - Compliance validation via DNA + drift detection ✅
  - Template versioning and collaboration workflows ✅
  - CI/CD validation for template PRs ✅
  - **Backlog**: Comprehensive CIS/CMMC templates deferred to v0.7.0+ (requires module development)

- [x] **Windows Patch Compliance (Advanced)** (Issue #212) - 13 points ✅ COMPLETED
  - Policy-driven patching (declarative config, automatic enforcement) ✅
  - Patch type policies (Critical: 7 days, Important: 14 days, etc.) ✅
  - Major version upgrades (Win 10→11, 23H2→24H2) with DNA compatibility checks ✅
  - Windows Update COM API integration (no WSUS/WUfB dependency) ✅
  - Generic maintenance windows (honored by ALL reboot operations, not just patching) ✅
  - Proactive compliance alerting (7 days warning, 1 day critical) ✅
  - Basic compliance reporting (patch status, days until breach) ✅
  - Windows built-in rollback handles failed upgrades ✅
  - No canary deployment (deferred to global ring system backlog) ✅

- [x] **Endpoint Performance Monitoring** (Issue #213) - 13 points ✅ COMPLETED
  - ✅ Performance metrics (separate from DNA system)
    - DNA: System "blueprint" (hardware specs, installed software)
    - Performance: System "vital signs" (CPU/memory/disk/network utilization)
  - ✅ Basic resource metrics (CPU overall, memory, disk I/O, network, online status)
  - ✅ Top 10 CPU/memory consumers per device
  - ✅ Process/service watchlist (alert if missing/stopped, optional auto-start)
  - ✅ Threshold-based alerting (warning/critical levels, sustained duration)
  - ✅ Time-series storage (memory/noop backends, ready for InfluxDB/TimescaleDB)
  - ✅ Workflow-triggered remediation (no automatic service restarts)
  - ✅ Multi-platform support (Windows/Linux/macOS) via gopsutil
  - ✅ Collection: 60 seconds default (configurable), <1% CPU overhead validated
  - ✅ Complete test suite: 36 test cases, all acceptance criteria met
  - ✅ 2,746 lines of production code across 15 files
  - **Note**: Storage backend interface ready for InfluxDB/TimescaleDB implementation

- [x] **Controller Health Monitoring & Alerting** (Issue #214) - 8 points ✅ COMPLETED (HIGH PRIORITY - MSP Operations)
  - ✅ Observability and alerting for small-medium deployments (10-1000 stewards)
  - ✅ Controller metrics (MQTT broker, existing storage providers, application queues, system resources)
  - ✅ Workflow/script queue depth monitoring (proactive alerting before MSP impact)
  - ✅ Threshold-based alerting (CRITICAL alerts only for alpha→beta)
  - ✅ Email alerting via SMTP (simple alerts, no tiered escalation)
  - ✅ Request tracing for troubleshooting (request ID propagation, CLI reconstruction)
  - ✅ Health API endpoints (simple + detailed + Prometheus)
  - ✅ CLI tools (`cfgcli controller status`, `cfgcli trace <request_id>`)
  - ✅ 7-day performance retention (30-second collection interval)
  - ✅ Uses existing storage providers (in-memory for alpha, pluggable architecture ready)
  - ✅ <1% overhead validated (0 goroutine growth, 9.31 KB memory for 30 snapshots)
  - **Deferred to v0.7.0**: Self-healing, circuit breakers, tenant migration (5 points)

#### v0.7.0 (Pre-OSS / Alpha) - Open Source Preparation

**Goal**: Prepare codebase for open source launch with proper licensing, clean architecture, and production-ready security

**Epic Document**: [v0.7.0-epic.md](./v0.7.0-epic.md)
**Feature Boundaries**: [feature-boundaries.md](./feature-boundaries.md)
**GitHub Issues**: #220-232 (13 tasks across 4 phases)

#### v0.7.1: Code Cleanup (Weeks 1-2)
- [x] **gRPC Removal** (Issue #220) - 2-3 days ✅ COMPLETED
  - [x] Document current gRPC usage and justification analysis (see `docs/architecture/grpc-usage-analysis.md`)
  - [x] Remove service definitions from .proto files (keep message definitions)
  - [x] Delete auto-generated *_grpc.pb.go files
  - [x] Refactor service implementations to remove gRPC interface conformance
  - [x] Redesign RBAC middleware for HTTP/MQTT (remove gRPC interceptors)
  - [x] Remove google.golang.org/grpc from go.mod
  - [x] Update Makefile proto generation to skip gRPC
  - [x] Validate all tests pass after removal
- [x] **Rename cfgctl to cfgcli** (Issue #221) - 1 day ✅ COMPLETED
  - [x] Rename cmd/cfgctl directory to cmd/cfgcli
  - [x] Update all import paths referencing cfgctl
  - [x] Update documentation and examples
  - [x] Update build scripts and Makefile targets
- [x] **Move HA Code to Commercial Tier** (Issue #222) - 2 days ✅ COMPLETED
  - [x] Separate HA code using Go build tags (commercial vs OSS)
  - [x] Create OSS stub implementation for SingleServerMode
  - [x] Update documentation about HA build tags and availability
  - [x] Ensure graceful degradation in OSS version
- [x] **Repository Cleanup** (Issue #223) - 1-2 days ✅ COMPLETED
  - [x] Perform branch cleanup (verified clean - all stale branches removed)
  - [x] Review repository for sensitive data or internal artifacts (18 files removed)
  - [x] Remove any internal documentation or notes (6 internal docs cleaned)
  - [x] Clean up test fixtures and example data (9 test binaries removed)
  - [x] Review code for unfinished features (24 TODOs addressed: 6 fixed, 18 removed)
- [x] **Sensitive Data Scan** (Issue #224) - 3-5 days ✅ COMPLETED
  - [x] Run gitleaks against entire repository history
  - [x] Run truffleHog against entire repository history
  - [x] Manually review configuration files for API keys, tokens
  - [x] Check commit messages for sensitive information
  - [x] Verify no customer names, internal URLs, or proprietary info
  - [x] Remove any findings using git-filter-repo (NOT NEEDED - no secrets in history)
  - [x] Document scan results and remediation actions

#### v0.7.2: Security Review (Weeks 3-5)

- [x] **Security Code Review (External Audit)** (Issue #225) - 2-3 weeks ✅ COMPLETED [CRITICAL]
  - [x] Static analysis with gosec, staticcheck
  - [x] Dependency vulnerability scan with govulncheck
  - [x] Manual code review focusing on auth/authz, input validation, SQL/command injection
  - [x] **Internal Review Complete**: 9/9 findings remediated (100%)
  - [x] Document security posture for users
  - [ ] **Next**: Engage external security firm for independent audit (ready for external review)
- [x] **Security Hardening - Infrastructure Changes** (Issue #239 / PR #241) - 2-3 days ✅ COMPLETED [MEDIUM]
  - [x] M-INPUT-3: SQL identifier whitelist validation (1 hour)
  - [x] M-INPUT-2: Regex timeout mechanism (2 hours)
  - [x] M-AUTH-2: Admin operation audit controls (3 hours)
  - [x] M-AUTH-1: API key persistence to durable storage (4 hours)
  - [x] M-TENANT-1: PostgreSQL Row-Level Security (RLS) for tenant isolation (4 hours)
  - [x] **BONUS**: Dual-CA bug fix (production-blocking mTLS failures)
  - [x] **BONUS**: SOPS storage provider configuration fix
  - [x] **BONUS**: Central Provider Compliance Enforcement System (6-layer defense)
  - [x] **Security Rating**: A- → A (0 High/Medium vulnerabilities remaining)
- [x] **Eliminate Duplicate Caching Implementations** - 2-3 days [MEDIUM] - ✅ COMPLETED
  - [x] Migrate `features/rbac/zerotrust/cache.go` (363→130 lines, -64%) to use `pkg/cache.Cache`
  - [x] Migrate `features/rbac/continuous/cache_manager.go` (970→574 lines, -41%) to use `pkg/cache.Cache`
  - [x] Migrate `features/reports/cache/memory.go` (136→84 lines, -38%) to use `pkg/cache.Cache`
  - [x] Enhanced `pkg/cache` with LRU/LFU eviction support
  - [x] Removed 681 lines of duplicate caching logic
  - [x] All tests pass (OSS + Commercial builds validated)
  - [x] Verified all cache functionality maintained with centralized provider
  - **Completed**: All three cache implementations successfully migrated
  - **Known Issue**: golangci-lint config needs v2.x migration (separate story required)
  - **Story Points**: 13 points (actual - 3 complex migrations completed)

#### v0.7.3: Licensing & Documentation (Weeks 6-8)

- [x] **Licensing Implementation** (Issue #226) - 3-5 days ✅ COMPLETED
  - [x] Finalize licensing model (Apache 2.0 + Elastic License v2 open core)
  - [x] Define open-core vs commercial feature boundaries (see `docs/product/feature-boundaries.md`)
  - [x] Create LICENSE-APACHE-2.0 file in repository root
  - [x] Create LICENSE-ELASTIC-2.0 file for commercial reference
  - [x] Add SPDX license headers to all 802 source files (.go, .proto)
  - [x] Add license header verification to CI/CD pipeline (`make check-license-headers`)
  - [x] Create comprehensive LICENSING.md documentation (210 lines)
  - [x] Reorganize commercial code to `commercial/ha/` directory
  - [x] Update README.md with licensing section
- [x] **Feature Boundary Documentation** (Issue #227) - 2-3 days ✅ COMPLETED
  - [x] Create user-friendly version of feature-boundaries.md
  - [x] Add feature comparison table to README (10 categories, 30+ comparisons)
  - [x] Document upgrade path from OSS to Commercial
  - [x] Create FAQ about licensing and features (8 new entries)
  - [x] Add "Why Open Source?" philosophy section
  - [x] 228 lines of user-friendly documentation (135 README, 93 LICENSING)
- [x] **Documentation Cleanup & Creation** (Issue #228) - 1-2 weeks ✅ COMPLETED
  - [x] Finalize GTM strategy (see `docs/product/v0.7.0-epic.md`)
  - [x] Create CONTRIBUTING.md for open source contributors
  - [x] Create CODE_OF_CONDUCT.md (use Contributor Covenant)
  - [x] Create SECURITY.md with vulnerability reporting process
  - [x] Update README.md for public consumption
  - [x] Create ARCHITECTURE.md for contributors
  - [x] Create DEVELOPMENT.md for local setup
  - [x] Create QUICK_START.md for new users
  - [x] Complete 68-file documentation audit with cleanup
  - [x] Remove 4 internal tracking documents
  - [x] Update 11 files with gRPC → MQTT+QUIC protocol corrections
  - [x] Create security audit approval (OSS_RELEASE_REVIEW.md)
  - [x] Add mandatory documentation review gate to /story-complete
  - [x] Transform 2 internal summaries into contributor guides

#### v0.7.4: Community & Launch Prep (Weeks 9-10)

- [x] **Community Infrastructure Setup** (Issue #229) - 3-5 days ✅ COMPLETED
  - [x] Create issue/PR templates (bug, feature, question)
  - [x] Create CODEOWNERS file
  - [x] Add repository topics for discoverability
  - [x] Create good first issue tasks (#253, #254, #255)
  - [x] Document issue triage process
  - [x] Set up GitHub Discussions (manual - GitHub UI)
- [x] **Versioning & Roadmap Update** (Issue #230) - 2-3 days ✅ COMPLETED
  - [x] Document semantic versioning policy (see `docs/development/versioning-policy.md`)
  - [x] Update roadmap versions v1.0 -> v0.10, with clear path to v1.0
  - [x] Create CHANGELOG.md (see `CHANGELOG.md`)
  - [x] Create public-facing roadmap (see `docs/product/public-roadmap.md`)
- [x] **Review and Create All Referenced Email Addresses & Web Pages** (Issue #248) - 2-3 days ✅ COMPLETED
  - [x] Audit all documentation for email addresses and web URLs
  - [x] Create comprehensive inventory of referenced resources
  - [x] Set up all email addresses (security@, licensing@, conduct@ cfg.is)
  - [x] Create web pages (security page, PGP key page, landing page)
  - [x] Configure email infrastructure with proper security (Zoho Mail)
  - [x] Generate PGP key for encrypted security reports
  - [x] Create website repository ([cfg-is/cfg.is](https://github.com/cfg-is/cfg.is))
  - [x] Update documentation with example.com placeholders for self-hosters

#### v0.7.5: Testing Infrastructure & Security Hardening (CRITICAL)

(Issue #247)

**Goal**: Ensure tests represent real-world deployment exactly as documented, eliminating development convenience patterns that could leak into production.

**Dual Objectives**:

1. **Eliminate Development Foot-guns** - Remove insecure convenience shortcuts from production code
2. **Production-Realistic Testing** - Ensure all tests use configuration matching QUICK_START.md deployment

**Combined Epic** (30-35 story points)

**Philosophy**: "Test what you ship, ship what you test" - If a feature requires durable storage in production, it MUST use durable storage in development and testing. Tests must validate the exact deployment methods documented in QUICK_START.md and DEVELOPMENT.md.

**Why Combined**: Fixing storage foot-guns REQUIRES fixing test infrastructure (can't test durable storage with in-memory mocks). Production-realistic testing EXPOSES foot-guns (tests fail when configuration doesn't match deployment reality). Both enforce the same core principle.

**Critical Violations Identified**:

1. **Registration Token Storage (CRITICAL)** - 5 story points
   - **Current State**: `features/controller/server/server.go:208` uses `NewMemoryStore()` with comment "ALPHA LIMITATION: Using in-memory store - tokens lost on restart"
   - **Impact**: Registration tokens are lost on controller restart, breaking steward registration in production
   - **Fix**: Implement `registration.Store` backed by `pkg/storage` (git/database)
   - **Testing**: MUST test with actual storage backend, not in-memory mock
   - **Files**: `pkg/registration/store.go`, `features/controller/server/server.go`

2. **Tenant Management Storage (CRITICAL)** - 5 story points
   - **Current State**: `features/controller/server/server.go:117` uses `tenantmemory.NewStore()` with comment "currently uses memory store"
   - **Impact**: All tenant data lost on controller restart, breaking multi-tenancy in production
   - **Fix**: Implement tenant storage backed by `pkg/storage` (git/database)
   - **Testing**: MUST test with actual storage backend
   - **Files**: `features/tenant/`, `features/controller/server/server.go`

3. **RBAC Storage (HIGH)** - 4 story points
   - **Current State**: `features/rbac/memory/store.go` provides in-memory RBAC store, used in multiple places
   - **Impact**: All roles, permissions, and policies lost on restart
   - **Fix**: Implement RBAC storage backed by `pkg/storage`
   - **Testing**: MUST test with actual storage backend
   - **Files**: `features/rbac/memory/`, `features/rbac/manager.go:63`

4. **Rollback Operation Storage (MEDIUM)** - 3 story points
   - **Current State**: `features/config/rollback/store.go` has `InMemoryRollbackStore`
   - **Impact**: Rollback history lost on restart, no audit trail for configuration changes
   - **Fix**: Implement rollback storage backed by `pkg/storage`
   - **Testing**: MUST test with actual storage backend
   - **Files**: `features/config/rollback/store.go`

5. **CLI Token Storage (LOW)** - 1 story point
   - **Current State**: `cmd/cfgcli/cmd/token.go:102` uses `NewMemoryStore()` with comment "in-memory for now, will be controller API in future"
   - **Impact**: CLI-generated tokens not persisted, but CLI is ephemeral so acceptable
   - **Fix**: Remove in-memory store, connect directly to controller API
   - **Files**: `cmd/cfgcli/cmd/token.go`

**Phase 1.5: Environment Variable Security Hardening** (Issue #250, #251) (6 story points)

**Goal**: Prevent environment variable hijacking in hostile environments by using explicit YAML references and configuration signing

1. **Configuration Signing Infrastructure (CRITICAL)** (Issue #250) - 3 story points ✅ COMPLETED

   - **Current Gap**: Configurations sent from controller to steward are not cryptographically signed, allowing MITM attacks despite mTLS
   - **Security Risk**: Compromised controller or MITM attacker could send malicious configurations to stewards
   - **Implementation**: Extend existing script signing framework to full configuration signing
   - **Signing Flow**: Controller signs configs with private key → Steward verifies with controller's public key from mTLS certificate
   - **Verification**: Steward validates signature before applying ANY configuration changes
   - **Algorithms**: RSA-SHA256, ECDSA-SHA256 (reuse existing script signature infrastructure)
   - **Signature Storage**: Embedded in configuration YAML as `_signature` metadata field
   - **Key Management**: Controller uses same private key as mTLS certificate for signing
   - **Backward Compatibility**: Signature validation optional in v0.7.5, required in v0.8.0+
   - **Files**: `features/config/signature/`, `features/steward/config_receiver.go`, `pkg/config/loader.go`

2. **Explicit Environment Variable References (HIGH)** (Issue #251) - 3 story points

   - **Current Gap**: Code uses `os.Getenv()` to read `CFGMS_LOG_DIR`, `CFGMS_CONTROLLER_URL` allowing silent env var hijacking
   - **Security Risk**: Attacker with env var control can redirect steward to malicious controller or manipulate operational settings
   - **Fix**: Remove all implicit `os.Getenv()` calls from `cmd/steward/main.go` and `cmd/controller/main.go`
   - **Implementation**: Use `os.ExpandEnv()` in config loader to support `${ENV_VAR}` syntax in YAML files
   - **Benefit**: Configuration file is source of truth; env vars only used when explicitly declared
   - **Security**: Attacker must modify both config file (ACL-protected, signature validation planned) AND env var to hijack
   - **Validation**: Add startup failure if referenced env var is unset (fail-safe, not silent hijacking)
   - **Documentation**: Update QUICK_START.md with `${ENV_VAR:-default}` syntax examples
   - **SECURITY.md**: Document "Environment variables only used when explicitly declared in config files"
   - **Files**: `pkg/config/loader.go`, `cmd/steward/main.go`, `cmd/controller/main.go`, `QUICK_START.md`, `SECURITY.md`

**Phase 2: Production-Realistic Testing** (Issue #252) (12-15 story points)

**Goal**: Ensure all tests validate the exact deployment methods documented in QUICK_START.md and DEVELOPMENT.md

6. **QUICK_START Option A Validation (CRITICAL)** - 5 story points
   - **Current Gap**: Standalone steward (5-minute setup) never validated end-to-end
   - **Impact**: New users following QUICK_START Option A might encounter undocumented issues
   - **Fix**: Create `test/integration/standalone_steward_test.go`
   - **Testing**: Validate exact QUICK_START workflow with YAML config files
   - **Files**: `test/integration/standalone_steward_test.go`

7. **Certificate Registration Flow Testing (HIGH)** - 4 story points
   - **Current Gap**: Auto-approval documented but not tested; tests use pre-generated certs
   - **Impact**: Key feature (`--register` flag) untested in real-world scenario
   - **Fix**: Add integration tests for dev-mode auto-approval and production manual approval
   - **Testing**: Test full registration flow as shown in QUICK_START
   - **Files**: `test/integration/certificate_registration_test.go`

8. **YAML Configuration File Validation (MEDIUM)** - 3 story points
   - **Current Gap**: Tests use environment variables; YAML config parsing untested
   - **Impact**: Users can't debug YAML configuration issues
   - **Fix**: Add config file validation tests with helpful error messages
   - **Testing**: Test valid/invalid YAML, missing fields, resource references
   - **Files**: `test/integration/config_validation_test.go`

9. **Cross-Platform Build Validation (MEDIUM)** - 2-3 story points
   - **Current Gap**: Build-from-source flow not tested in CI
   - **Impact**: DEVELOPMENT.md build instructions might break for some platforms
   - **Fix**: Add CI targets for cross-platform builds
   - **Testing**: Linux AMD64/ARM64, Windows AMD64/ARM64, macOS ARM64
   - **Files**: `.github/workflows/build.yml`, Makefile

10. **Productize Test Infrastructure Tooling (LOW)** - 2-3 story points
   - **Current Gap**: Excellent scripts exist but not part of core system
   - **Impact**: Users manually replicate test infrastructure for production
   - **Fix**: Move `wait-for-services.sh` to `bin/cfgms-wait-for-services`
   - **Testing**: Document in operations runbooks
   - **Files**: `scripts/wait-for-services.sh`, `docs/operations/production-runbooks.md`

**Combined Acceptance Criteria**:

- [ ] **Storage Foot-guns Eliminated**: All production code uses durable storage (git/database)
- [ ] **In-Memory Stores Removed**: Zero in-memory stores in `cmd/` and `features/` (except tests/caches)
- [ ] **Architecture Enforcement**: `make check-architecture` detects and blocks new foot-guns
- [ ] **QUICK_START Validation**: All three deployment options tested end-to-end with YAML configs
- [ ] **Certificate Registration**: Dev-mode auto-approval and production manual approval tested
- [ ] **Config File Parsing**: YAML validation tests with helpful error messages
- [ ] **Cross-Platform Builds**: Linux/Windows/macOS × AMD64/ARM64 builds validated
- [ ] **Production Tooling**: Test scripts productized (wait-for-services → bin/)
- [ ] **Documentation Audit**: No insecure alternatives or "temporary" setups documented
- [ ] **Security Validation**: All security scans pass with no foot-gun violations

**Definition of Done**:

- [ ] Zero in-memory stores for durable data in production code
- [ ] All storage uses `pkg/storage/interfaces` with pluggable backends
- [ ] `make test` passes with real storage backends matching deployment
- [ ] QUICK_START Options A, B, C validated in integration tests
- [ ] Certificate registration flow tested (auto-approval + manual approval)
- [ ] YAML config parsing tested with production-like files
- [ ] Cross-platform builds tested in CI
- [ ] Documentation audit complete (no insecure patterns)
- [ ] Security scan passes with no violations
- [ ] PR review checklist includes foot-gun and deployment-match verification

**Technical Debt Resolution**: This work pays down critical technical debt from v0.1-v0.6 alpha development phase where "ALPHA LIMITATION" comments indicated temporary in-memory storage, and aligns test infrastructure with documented deployment methods.

#### v0.8.0 Go public

- [ ] Convert repository to Public
- [ ] Re-enable GitHub Actions workflows (move workflows-disabled/ back to workflows/) (issue 109)
- [ ] Configure branch protection rules
- [ ] Set Up GitHub Actions and Acceptance Tests #15
- [ ] Set up github CI CD pipeline  
- [ ] Review Automated secure code scanning tooling implementation
- [ ] Validate all workflows function properly on public repository

### Phase 2: Production Stability & Feature Completion (v0.9.0 - v1.0.0)

**Goal**: Achieve production stability, complete core platform features, and prepare for stable release with LTS guarantees.

#### v0.9.0 (Beta) - Production Stability

- [ ] Complete production validation with real MSP deployments
- [ ] Finalize production-ready security hardening
- [ ] Complete high availability validation
- [ ] Finalize advanced configuration management
- [ ] Finalize advanced workflow engine and templates
- [ ] Finalize advanced reporting

#### v0.10.0 - Web Interface Foundation

- [ ] Web UI framework and authentication
- [ ] Dashboard with fleet overview
- [ ] Configuration management interface
- [ ] User and role management
- [ ] Workflow Management
- [ ] Basic reporting and visualization

#### v0.11.0 - Outpost Foundation

- [ ] Basic Outpost component implementation
- [ ] Proxy cache for configuration distribution
- [ ] Network device monitoring foundation
- [ ] Outpost-Controller communication

#### v0.12.0 - M365 Foundation

- [ ] **M365 CSP Infrastructure Setup** (5 story points):
  - [ ] Microsoft CSP Partner Center sandbox environment configuration - 2 points
  - [ ] GDAP relationship setup for test customer tenants - 1 point
  - [ ] Multi-tenant enterprise app registration with admin consent - 2 points
- [ ] **Complete M365 Multi-Tenant Enterprise App Support** (10/18 story points from v0.4.0):
  - [x] Enhanced Tenant Management (Issue #118 / PR #238) - 8 points ✅ COMPLETED
    - ✅ M365TenantManager with tenant discovery (admin consent + GDAP)
    - ✅ Tenant metadata management and health monitoring
    - ✅ Bulk operations for MSP scale
    - ✅ Comprehensive test suite (545 lines, real components)
    - ⚠️ **Requires live CSP sandbox for GDAP integration testing**
  - [ ] Per-Tenant Token Storage and Management (Issue #119) - 10 points *(requires CSP sandbox setup)*
- [ ] **M365 Integration Validation** (8 story points):
  - [ ] GDAP customer discovery end-to-end testing - 3 points
  - [ ] Multi-tenant consent flow validation with real M365 tenants - 3 points
  - [ ] Tenant health monitoring live integration tests - 2 points
- [ ] Implement SaaS Steward using workflow engine foundation
- [ ] Core M365 modules for CSP management (15+ modules):
  - [ ] Entra ID modules (user, group, license, conditional access)
  - [ ] Teams modules (team, channel, membership)
  - [ ] Exchange modules (mailbox, distribution groups, shared mailboxes)
  - [ ] SharePoint modules (site, list management)
  - [ ] Security modules (Defender policies, Intune device, Conditional Access policies)
- [ ] M365 security baseline workflows
- [ ] M365 user lifecycle automation workflows

#### v0.13.0 - MSP PSA Integration

- [ ] ConnectWise Manage integration modules
  - [ ] Company/customer management
  - [ ] Contact synchronization
  - [ ] Ticket creation and management
  - [ ] Service agreement management
- [ ] AutoTask integration modules
  - [ ] Account and contact management
  - [ ] Ticket and contract management
- [ ] Smart Helpdesk Context System
  - [ ] Phone system integration for automatic client environment loading
  - [ ] Real-time client environment dashboard with DNA-driven system state
  - [ ] Progressive context surfacing based on call notes and issue keywords
  - [ ] Network topology visualization and recent changes timeline
  - [ ] Integration with PSA ticketing for contextual troubleshooting guides
  - [ ] Call logging interface with intelligent information surfacing
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

- **Document Version**: 2.8
- **Last Updated**: 2025-11-19

### Related Documentation

- [Versioning Policy](../development/versioning-policy.md) - Semantic versioning details
- [CHANGELOG.md](../../CHANGELOG.md) - Complete version history
- [Feature Boundaries](./feature-boundaries.md) - OSS vs Commercial features
