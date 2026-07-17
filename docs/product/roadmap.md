# CFGMS Development Roadmap

## Overview

This document outlines the development roadmap for the Configuration Management System (CFGMS). It provides a clear vision for the project's development, including milestones, features, and release planning, incorporating recent strategic adjustments to better align with MSP market voids and core product vision.

**Last Updated**: 2026-07-08

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

Codebase prepared for open source launch with proper licensing, clean architecture, and production-ready security. See [v0.7.0-epic.md](./v0.7.0-epic.md).

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
- [x] Create `SECURITY.md` vulnerability disclosure policy (issue #281) ✅ COMPLETED
- [x] Re-enable and validate GitHub Actions workflows (issue #109, issue #15) ✅ COMPLETED
- [x] Configure branch protection rules for main and develop (issue #283) ✅ COMPLETED
- [x] E2E Test: Fix MQTT+QUIC test skips, add parallelization, reduce test-completion time (issue #297) ✅ COMPLETED
- [x] Update copyright to Jordan Ritz and implement Contributor License Agreement (issue #307) ✅ COMPLETED
- [x] Convert repository to public and activate GitHub Advanced Security features (issue #282) ✅ COMPLETED
- [x] Update documentation with security badges and public links (issue #284) ✅ COMPLETED

#### v0.8.1 Bug fixes and test completion

- [x] Fix single-use registration token enforcement in database storage (issue #299) ✅ COMPLETED
- [x] Complete E2E test framework for MQTT+QUIC mode (issue #294) ✅ COMPLETED
- [x] Remove outdated v0.3.0 and v0.4.0 release gates from production-gates workflow (issue #322) ✅ COMPLETED
- [x] Enable TestModuleExecution suite with proper steward container configuration (issue #312) ✅ COMPLETED
- [x] Configure MQTT broker ACLs for topic-level access control by steward ID (issue #313) ✅ COMPLETED
- [x] Align test-complete with CI required checks for 100% local validation parity (issue #315) ✅ COMPLETED

### v0.9.x Series — Production Stability & Foundation

v0.9.0–v0.9.5 work has shipped to `develop` but no v0.9.x tags have been cut.

#### v0.9.0 — Test & Architecture Foundation ✅ COMPLETED

Test infrastructure, breaking changes, and communication layer architecture — all delivered.

- [x] Fix failsafe component unhealthy state detection (Issue #295 - 5-8 points) ✅
- [x] Enhanced monitoring controls in graceful degradation (Issue #296 - 3-5 points) ✅
- [x] Chaos engineering network partition simulation (Issue #291) ✅
- [x] RBAC failsafe component failure simulation (Issue #292) ✅
- [x] Certificate test performance optimization (Issue #293) ✅
- [x] Add integration-tests to required GitHub checks (Issue #350) ✅
- [x] Optimize zero-trust statistics lock contention (Issue #355) ✅
- [x] Fix Windows flaky test timing assertion (Issue #356) ✅
- [x] Fix flaky TestEnhancedMultiTenantSecurity test (Issue #366) ✅
- [x] Fix MQTT+QUIC E2E config sync signature verification (Issue #378 - 8 points) ✅
- [x] Fix Docker networking in MQTT+QUIC E2E tests (Issue #382 - 2-3 points) ✅
- [x] HA E2E tests: Replace mocked helpers with real implementations (Issue #385) ✅
- [x] Controller config loading refactor (Issue #290) ✅
- [x] Communication Layer Abstraction (Epic #267 - 47 story points) ✅
  - [x] Story #267.1: Control Plane Provider Interface (Issue #360 - 8 points) ✅
  - [x] Story #267.2: Data Plane Provider Interface (Issue #361 - 8 points) ✅
  - [x] Story #267.3: Migrate Controller to Communication Providers (Issue #362 - 13 points) ✅
  - [x] Story #267.4: Migrate Steward to Communication Providers (Issue #363 - 13 points) ✅
  - [x] Story #267.5: Deprecate Direct MQTT/QUIC Imports (Issue #364 - 5 points) ✅
- [x] v0.9.x Project Housekeeping (Issue #392) ✅

#### v0.9.1 — Security Baseline & Stability (~15-20 pts, ~1-2 weeks)

Minimum security hygiene before deploying on a real network.

- [x] Eliminate hardcoded TimescaleDB password (Issue #372 - 3-5 points) - Remove "No Footguns" violation, implement JIT password generation for tests, require explicit credentials in production
- [x] No Footguns sweep: audit and fix remaining insecure defaults (Issue #396 - 3-5 points) - Full codebase audit for hardcoded secrets and insecure defaults, update security-engineer agent with footgun detection
- [x] Implement log injection prevention in pkg/logging (Issue #373 - 3-5 points) - Resolve 25 code scanning alerts, add sanitization infrastructure to prevent log forgery attacks
- [x] Fix Windows workflow test failures (Issue #309) - Required for Windows VM management in v0.9.2

#### v0.9.1.1 — Agent Dispatch Infrastructure (~60 pts, ~3 sprints)

Transition from interactive Claude Code sessions to headless agent dispatch in Docker containers. Adapts Stripe's "Minion" model for solo developer workflow: architect writes PRDs/stories, agents implement in sandboxed containers, developer reviews PRs and merges. See [Agent Dispatch PRD](../archive/prd-agent-dispatch.md).

**Sprint 1 — Prerequisites & Configuration (~13 pts):**
- [x] CI: add integration-tests-controller as required check on develop (Issue #433 - 2 points) - Close CI coverage gap before agents skip Docker tests
- [x] CLAUDE.md: add agent execution mode and headless workflow (Issue #434 - 5 points) - Dual-mode CLAUDE.md with CFGMS_AGENT_MODE detection
- [x] Makefile: add test-agent-complete target for container validation (Issue #435 - 2 points) - test-complete minus Docker targets (~95% coverage)
- [x] GitHub: create agent-story issue template for dispatch workflow (Issue #436 - 3 points) - Structured YAML template with reference impl, acceptance criteria
- [x] GitHub: create agent dispatch label set (Issue #437 - 1 point) - agent:ready/in-progress/success/failed/blocked labels ✅ COMPLETED

**Sprint 2 — Devcontainer Image (~21 pts):**
- [x] Devcontainer: base Dockerfile with Go toolchain and security tools (Issue #438 - 8 points) - golang:1.25-bookworm, gosec, staticcheck, trivy, nancy, gitleaks, trufflehog, Claude Code, pre-cached Go modules + Trivy DB
- [x] Devcontainer: firewall script with allowlisted outbound networking (Issue #439 - 5 points) - iptables default-deny, allowlist GitHub/Anthropic/Go proxy only
- [x] Devcontainer: entrypoint script with issue fetch and agent prompt (Issue #440 - 8 points) - 4-phase agent workflow, credential restore, label management, draft PR on failure

**Sprint 3 — Skills & Setup (~26 pts) — Pivoted from bash scripts to Claude Code skills:**
- [x] Skill: `/dispatch` for launching agent containers from issues (Issue #441 - 8 points) - Replaces dispatch.sh; worktree creation, `docker run -d` (non-blocking), quality checks
- [x] Skill: `/isoagents` for agent status and lifecycle management (Issues #442, #443 - 8 points) - Replaces monitor.sh + status.sh; status dashboard, detailed logs, cleanup, PR review suggestions
- [x] Skill: `/agent-setup` one-time bootstrap (Issue #444 - 5 points) - Replaces setup.sh; image build, credential setup, label creation, directory setup
- [x] Docs: agent dispatch infrastructure developer reference (Issue #445 - 5 points) - Story sizing guidelines, CI failure workflow, troubleshooting

#### v0.9.1.2 — Code Structure Refactoring (~23 pts, ~2 sprints)

Split oversized Go source files into cohesive, single-responsibility modules. 183 of 598 source files (31%) exceed 500 lines. This milestone targets the 7 worst offenders (1,233–3,110 lines each) that violate SRP with multiple unrelated concerns in a single file. Pure mechanical refactoring — no behavior changes, no API changes.

- [x] Split features/workflow/engine.go into 5 cohesive modules (Issue #449 - 5 points) - 3110 lines, 75 methods across 6 concerns: conditions, loops, HTTP, sync, composition
- [x] Split pkg/storage/providers/git/plugin.go by store type (Issue #450 - 3 points) - 2354 lines, 4 store types with duplicated git helpers
- [x] Split features/tenant/security/isolation.go into 4 security domains (Issue #451 - 3 points) - 1794 lines, 4 concerns: rules, vulnerabilities, zero-trust, adaptive
- [x] Split pkg/storage/providers/database/rbac_store.go by entity type (Issue #452 - 3 points) - 1387 lines, 4 entity types with repetitive CRUD
- [x] Split pkg/directory/interfaces/schema.go — extract transformers and validators (Issue #453 - 3 points) - 1367 lines, schema mapping mixed with implementations
- [x] Split features/rbac/risk/integration.go into focused modules (Issue #454 - 3 points) - 1329 lines, 8+ responsibilities in one file
- [x] Split features/tenant/security/policy_engine.go — extract coordination and audit (Issue #455 - 3 points) - 1233 lines, policy eval + zero-trust coordination + audit

#### v0.9.2 — Beta Deployment Validation

Deploy on test cluster and manage real VMs — the core beta milestone.

**Blockers (must resolve before E2E validation):**
- [x] Controller: wire ConfigurationServiceV2 durable storage — V1 is in-memory (Issue #409) - Configs lost on controller restart, deployment blocker
- [x] Controller: separate first-run initialization from normal startup (Issue #410) - Prevent silent CA regeneration on misconfigured restart
- [x] Steward: compile-time controller URL, remove regtoken prefix (Issue #421) - Controller URL baked in at build for signed binary security, shorter tokens for MDM deployment
- [x] Steward: self-install subcommand with interactive mode for GUI launch (Issue #472 - 8-13 points) - `install`/`uninstall`/`status` subcommands, interactive token prompt on double-click, native Windows Service/systemd/launchd registration

**E2E validation:**
- [ ] End-to-end deployment validation on real VMs - Deferred to v0.9.13; the original tracking issue (#390) was repurposed into the Phase 2 Hyper-V dev-infrastructure epic and closed 2026-06-25
- [x] Beta deployment guide (Issue #391 - 3-5 points) ✅ - Production-like deployment documentation beyond dev-focused QUICK_START.md

**Post-validation (discovered gaps, do not block #390):**
- [x] Steward: unify operating model — cfg-driven convergence with optional controller channel (Issue #411) - Single code path, 30-min default converge_interval, controller as additive overlay
- [x] Steward: unify execution engines — standalone has 7 modules, controller has 3 (Issue #412) - Single Get→Compare→Set→Verify engine, platform-aware permissions
- [x] Steward: wire drift detection and performance monitoring into lifecycle (Issue #413) - Drift as part of convergence cycle, performance collector wired into lifecycle
- [x] Steward: implement offline report queueing (Issue #419) - File-backed FIFO queue, atomic writes, ordered delivery on reconnect
- [x] Steward/Controller: implement hash-based DNA sync (Issue #418) - DNA hash in heartbeats, delta over control plane, full sync over data plane
- [x] Controller: wire monitoring and health infrastructure into server (Issue #417) - Passed as nil, placeholder responses
- [x] Controller: wire reports engine and rollback system into API (Issue #416) - Built but routes never registered
- [x] Controller: wire existing workflow engine into REST API and startup (Issue #414) - 7 REST endpoints, trigger manager lifecycle, tenant-scoped
- [x] Steward: registration approval via workflow engine hook (Issue #422) - Hook point with default accept-all, quarantine/reject support
- [x] Controller: per-tenant config source routing Phase 1 (Issue #555, from #428) - ConfigSourceRouter with tenant metadata inheritance, backward compatible
- [x] Controller: fix tenant context key mismatch between auth middleware and config handlers (Issue #430) - Tenant ID never flows from auth to config operations, all ops use "default"
- [x] Controller: replace MockConfigStore in config_service_storage_test.go with real storage (Issue #431) - Testing standards violation, uses mock instead of real git backend
- [x] Steward: optimize Windows DNA collection (Issue #567) - Eliminate Win32_Product, add exec.CommandContext timeouts, cache static hardware data
- [x] Agent dispatch: close quality gaps with adversarial review and enforcement (Issue #557) - 3-specialist review, shell-level validation, strengthened prompts
- [x] Steward: implement Windows ACL support for file/directory modules (Issue #553) - Created, future work

**Post-E2E infrastructure:**
- [ ] Deploy self-hosted CI runners on Hyper-V managed by CFGMS (Issue #565) - In progress: self-hosted Windows runner live for native Windows builds on non-fork PRs; Linux runners and broader CI migration pending
- Issue #596 (GitHub Actions dispatch from label changes) - Closed not-planned 2026-06-19: the label-based queue it depended on was decommissioned (board Status is the only queue signal; dispatch is owned by the PO cron cycle)

**Deferred to v0.10.0 (both since delivered):**
- [x] Controller: implement multi-node orchestration (Issue #415) ✅ - Closed 2026-07-02
- [x] Controller: per-tenant config source routing Phases 2-3 (Issue #428) ✅ - Closed 2026-05-20

#### v0.9.3 — Three-Certificate Architecture (~47-65 pts, ~3-5 weeks)

Proper certificate separation for production security.

- [x] Implement Three-Certificate Architecture for Production Security (Issue #377 - 47-65 points) - Separate public API (Let's Encrypt), internal mTLS, and config signing certificates for proper key separation, compliance, and operational stability
- [x] Steward-Side Secret Management (Issue #404) - OS-native encrypted storage provider for steward endpoints using DPAPI (Windows) and AES-256-GCM with HKDF (Linux/macOS), implementing SecretStore interface with auto-registration
- [x] Let's Encrypt Automation via Certbot Module (Issue #401) - Automated certbot integration for public API certificate management in separated architecture

#### v0.9.4 — Production Hardening (~25-30 pts, ~2-3 weeks)

Authorization hardening + fixes from deployment validation.

- [x] Authorization Memory Management & Circuit Breaker Implementation (Issue #380 - 21 points) - Implement multi-tier circuit breakers (IP, Tenant, Global) with rate limiting and memory management to prevent DoS via resource exhaustion
- [ ] Complete high availability validation on real cluster (multi-node, beyond Docker E2E)
- [ ] Deployment validation fixes (TBD based on v0.9.2 findings)

#### v0.9.5 — Steward-First Controller Bootstrap (~18 pts, ~2 weeks)

Controller nodes managed by stewards — clean separation of node management from fleet orchestration. See [ADR-002](../architecture/decisions/002-steward-bootstrap-for-controllers.md).

- [x] Controller: remove writeTransportCertsToDir — certs used in-memory only (Issue #576 - 5 points) - Removed test-only cert file export, fixed cert_path config alignment, cleaned up docker-compose test-certs mounts
- [x] Steward: implement service module for idempotent OS service management (Issue #577 - 8 points) - systemd/Windows Service/launchd Get→Compare→Set→Verify, replaces script workaround
- [x] Controller: add install/uninstall/status subcommands (Issue #578 - 5 points) - Mirror steward self-install pattern for OS service registration

#### Post-v0.9.5 epics on develop (untagged)

- [x] Epic #786 — CI: pre-merge validation runs against branch state
- [x] Epic #1414 — mTLS admin authentication for controller REST API
- [x] Epic #1500 — Operating-model docs audit/walkthrough/consolidation
- [x] Epic #1501 — Operating-model CLI surface + docker fleet validation
- [x] Epic #1523 — Steward job execution (scripts, inline commands, dispatch)
- [x] Epic #1550 — Post-audit follow-ups
- [x] Epic #1664 — Steward registration trust model (perennial tokens, IP-trust)
- [x] Epic #1714 — Fleet resilience (restart-recovery, cert-reuse, drift)
- [x] Epic #1661 — Steward provisioning installer + trust bootstrap
- [x] Epic #1754 — Decouple controller from steward-internal packages

#### v0.9.6 — Consolidation + AGPL Governance Release ✅ COMPLETED

- [x] Epic #1716 — Migrate licensing model to AGPL-3.0 single license

#### v0.9.7 — Tier 1 Hyper-V controller bringup ✅ COMPLETED

- [x] Epic #1787 — persistent controller on Hyper-V cluster VM, manual install, durable git+SOPS storage, mTLS

#### v0.9.8 — `cfg` CLI on agent containers + Tier 1 connectivity ✅ COMPLETED

- [x] Epic #1788 — `cfg` CLI baked into agent image, per-agent mTLS bundle, routable reach to Tier 1

#### v0.9.9 — Hyper-V management module ✅ COMPLETED

- [x] Epic #1789 — `features/modules/hyperv/`: VM lifecycle, snapshot/restore, vSwitch (PowerShell-over-WinRM)

#### v0.9.10 — Stewards on Hyper-V hosts ✅ COMPLETED

- [x] Epic #1790 — registered, healthy stewards on every Hyper-V cluster node; service account, WinRM, module loading

#### v0.9.11 — Phase 2 dev-agent conventions — CLOSED (not planned)

- Epic #1791 — tenant-scoping, breakage-tolerance ceremony, agent guardrails for Tier 1 — closed not-planned 2026-06-25 alongside the Phase 2 epic closeout

#### Post-Phase-2 epics on develop (untagged, in flight)

- [ ] Epic #2418 — cluster.cfg cascade + owner-gated `hyperv.vm` convergence: HA VMs defined once at cluster scope, cascaded to member stewards, lifecycle gated on current role ownership
- [x] Epic #2657 — workflow-driven Hyper-V role promotion (standalone → FC-role): `cfg workflow promote-hv-role` writes `ha_role`, soaks for steward convergence, migrates the resource to cluster scope; live-validated on cfg-lab (`test/e2e/hyperv/promote_role_test.go`, runbook `docs/testing/hyperv-role-promotion-runbook.md`, #2671)
- [ ] Epic #2359 — Operator-first CLI targeting: hostname & attribute selectors across `cfg steward` verbs

#### v0.9.12 — Ephemeral per-agent dev infrastructure (DRAFT)

- [ ] Epic #1792 — each dispatched agent runs against its own ephemeral controller + steward VMs built from its branch

#### v0.9.13 — Beta deployment validation on real VMs

Original Issue #390 scope, now deferred until after the Hyper-V dev-infra unlock. New issue to be filed when ready.

#### v0.10.0 - Web Interface Foundation

**Deferred from v0.9.x** — now tracked as Epic #2343 (Controller REST APIs; 5 of 6 stories complete):
- [ ] Workflow management REST API (endpoint coverage + reference docs delivered via #2369/#2374; final story #2373 — route-registration fix — queued Ready)
- [x] Config broadcast push API (Issue #2366 - selector targeting + push-status read)
- [x] Session/connection monitoring API (Issues #2367, #2368 - transport + admin-session read APIs)

**Web Interface** — tracked as Epic #2344 (framework, session-token auth, controller-served fleet overview; story decomposition gated on the inline web-session ADR + founder design checkpoint):
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

#### Digital Twin & Digital Employee Experience (DEX) — Tiered Rollout

The twin and DEX share the same foundations and ship as **layers threaded across the timeline**, not as monolithic milestones. The rule: bake data-model commitments in early (cheap now, brutal to retrofit); build the reason layer late (needs the foundation mature). Neither is a prerequisite for the other — but DEX is the twin's first paying consumer, the concrete use case that pulls the foundation into existence. The foundation itself lives in the Captured Backlog module/DNA chain above; this section is the end-state those foundations build toward. **Guard:** none of this jumps the Hyper-V beta bringup queue (v0.9.6–v0.9.13); Tier 1 is schema discipline inside already-scheduled DNA work, so it carries no schedule cost.

**Tier 1 — data-model commitments** (land with the baseline-DNA epic; no separate milestone). Detailed on that Captured Backlog entry. `twin` `dex` `cms`
- [ ] Per-fragment/entity provenance & freshness `{source, observed_at, authority, confidence}`
- [ ] Stable **typed entity id** per managed object (identity primitive for edges + history)
- [ ] Controller **retains versioned fragment history** — per-entity state queryable over time
- [ ] DEX signals attach to the typed device/app entity as an extensible, timestamped, provenanced attribute set

**Tier 2 — first visible surfaces** (Web-UI window, ~v0.10.x). `twin` `dex` `web`
- [ ] Temporal query surface — "what was true at time T", diff two points, correlate a change with its effect
- [ ] **Relationship / topology graph** — `runs-on`, `depends-on`, `connects-to`, `serves`, `member-of` edges over typed entities; enables blast-radius, impact, root-cause. **Gated on a to-draft storage-shape ADR** (property graph + temporal store ≠ git+SOPS KV) — drafted inline (per the ADR practice), companion to ADR-017 Amendment 1 which guarantees only the identity + history substrate this builds on
- [ ] Unified entity query API — "every entity of type X related to Z" (the model surface the Web UI renders)
- [ ] DEX collection v0 + single-device **experience timeline** — per-process/service streams (asset-page views) + "pull up Bob's machine"

**Tier 3 — reason layer & rolling DEX track** (v0.11+; each item dependency-gated).

> **DEX collection — settled architecture (research 2026-07-07).** Collection is **pure usermode, ETW-centric — no kernel-mode driver.** Proof: Microsoft's own Intune Endpoint Analytics derives boot/login/GP/sign-in-responsiveness/app-reliability (and top-processes-at-boot with per-process CPU) driver-free from in-box ETW; per-process CPU/mem/disk is the usermode WinRT `ProcessDiagnosticInfo` API (or classic Win32 `GetProcess*`). The DEX market leader (Nexthink) ships a kernel driver, but its only advantage is anti-tamper — a security property irrelevant to DEX fidelity — and the post-CrowdStrike (Jul 2024) platform direction is decisively *out* of the kernel (Windows Endpoint Security Platform), so a new DEX driver would run against Microsoft's own trajectory. **Language: Go across all three OSes.** Windows + Linux are pure-Go (ETW via `x/sys/windows`+`syscall.NewCallback`, proven by Velociraptor; Linux `/proc`+`/sys`+PSI file reads); **macOS is the one cgo case** (IOKit/libproc) → **implies a macOS CI build runner not yet in #565 (Linux+Windows only).** Design note: run the steward's **own** ETW sessions against `Microsoft-Windows-Diagnostics-Performance` et al. — do **not** depend on the DiagTrack service (breaks if an enterprise sets telemetry to Security/Off). No Rust/Zig required for any signal in scope.

- [ ] **DEX de-risking spike (do FIRST, before committing the collection architecture)** — a Go PoC ETW consumer on Windows that (a) captures the not-yet-independently-verified signals from in-box providers (app-hang/UI-responsiveness via Win32k, SMART via WMI `MSStorageDriver`, thermal via `MSAcpi`, disk queue depth, hard-fault paging, network/DNS/Wi-Fi) and (b) measures **sustained CPU under the chosen provider selection against the sub-1% budget** (the one Go-specific unknown: ETW callback cost). Converts "high-plausibility" → "verified for CFGMS". `dex`
- [ ] DEX **collection track** — *rolling, not a release*; one probe at a time (usermode ETW / WMI / PDH / WinRT, per the architecture note above): app-hang/ETW stalls, boot/login/profile-load duration, disk I/O wait & queue depth, paging pressure, SMART/storage health, thermal throttling, network latency/jitter/DNS. `dex`
- [ ] Experience scoring & normalization model. `dex`
- [ ] Fleet **baselines & percentiles** — "devices where QuickBooks is in the 30th percentile" (needs Tier-1 temporal). `dex` `twin`
- [ ] **Root-cause / correlation** — "Bob is slow *because* X", including causes that never surface in Task Manager (needs Tier-2 graph). `dex` `twin`
- [ ] **Predictive analytics & refresh recommendation** — degradation forecast, replace-by-experience-not-age (needs temporal + scoring). `twin` `dex`
- [ ] **Experience-driven remediation** — degraded experience triggers a workflow-engine fix (kill runaway process, push config). The config-management moat pure-observability DEX vendors can't match. `dex` `workflow` `cms`
- [ ] Twin **simulation / what-if** — "if I push this config / if this host dies, what breaks?" against the model, not production (needs graph + temporal + desired/actual). `twin` `cms`
- [ ] **Discovery of the undeclared** — reflect unmanaged/rogue reality (network scan, cloud inventory); OSquery is the seed, overlaps Outpost (v0.11.0). `twin`
- [ ] Cross-fleet anonymized baselines — requires an explicit tenant consent/aggregation model (parked decision; must not block collection). `dex`

#### LLM Integration Evaluation

- [ ] Research and evaluate LLM integration for natural language queries
- [ ] Implement AI-assisted script generation
- [ ] Develop AI-driven anomaly detection

#### Further Expansion & Specialization

- [ ] Implement advanced resource management capabilities
- [ ] Implement Cluster-Aware Patching
- [ ] Explore further specialized integrations and features

*(DEX monitoring moved to the [Digital Twin & DEX tiered rollout](#digital-twin--digital-employee-experience-dex--tiered-rollout) above — it is a layered track, not a single feature.)*

## Capability Tags

Feature work is tagged with the **product capability that consumes it** — the end-in-mind, not the topic. Tags are **multi-valued**: a story that serves several capabilities carries all of them, and a multi-tag story is a signal that it is *foundational* — its schema/interface must satisfy every listed consumer at once. This is how the twin's and DEX's Tier-1 data-model commitments get built in early instead of retrofitted.

Controlled vocabulary (grows deliberately, not ad hoc):

- `cms` — core config management: desired-state convergence, drift, modules
- `twin` — digital twin: entity model, topology graph, temporal state, simulation
- `dex` — digital employee experience: endpoint experience signals, baselines, root-cause
- `workflow` — automation / workflow engine
- `directory` — identity & directory services (M365, AD/Entra)
- `web` — web UI and visualization surfaces
- `msp` — MSP tool integrations (PSA / RMM / documentation)

Applied going forward (backlog + future work); pure hygiene/infra (CI, refactors, security sweeps) carries no capability tag. Roadmap items carry these tags inline; the parallel **`cap:*` GitHub label namespace** (orthogonal to Projects-V2 work-queue state, purely descriptive, multi-valued) is live end-to-end — created by `/agent-setup`, applied at epic/story creation via `pipeline-helper.sh create-epic|create-story --cap`, inherited epic→story at decomposition (`.claude/agents/po.md` §7, `ba.md`), and carried issue→PR by `lock-sweep`. A capability tag names the *consumer* of the work, never queue state. It coexists with the community **component** labels (`workflow`, `dna`, `security`, `api`, `modules` in `docs/development/issue-triage.md`), which are a distinct *topic* axis — cap = who consumes it, component = what it's about.

## Captured Backlog (unscheduled)

Founder-captured todos awaiting placement in a versioned milestone. Each carries enough context to decompose later; suggested homes are notes, not commitments.

> **Design status:** the module and DNA items below are now designed in **[ADR-016](../architecture/decisions/016-steward-module-foundation.md)** (steward module foundation) and **[ADR-017](../architecture/decisions/017-dna-composition-and-sync.md)** (DNA composition & sync), both *Proposed*. Those ADRs are authoritative for the specifics; the entries here are the roadmap placeholders. Sequencing settled during design: **module foundation → OSquery → baseline DNA → asset page**, with OSquery deliberately *before* baseline DNA so DNA is built on osquery rather than reinventing it.
>
> **Twin/DEX foundation:** the module → OSquery → baseline-DNA → asset-page chain below **is** the Tier-1/Tier-2 foundation of the [Digital Twin & DEX tiered rollout](#digital-twin--digital-employee-experience-dex--tiered-rollout) in Future Features. Entries are tagged with their downstream consumer(s) and tier so the foundation work is built for its end-state, not as isolated plumbing.

- [ ] **Asset detail page — Task Manager + Services views** — The Web UI asset page needs a live Windows Task Manager equivalent (running processes with per-process CPU/memory/disk/network) and a `services.msc` equivalent (service enumeration with state + start/stop/restart control). Requires new steward-side **monitor streams** (process table, per-process resource metrics, service inventory + state) surfaced over the data plane and exposed through the backend API for the Web UI to consume. *Note:* these live views are **telemetry, not DNA** (ADR-017 excludes ephemeral state from the hashed DNA); live service read/control also overlaps the `service` module's desired-state enforcement — clarify the boundary. *Suggested home:* Web UI backend APIs (Epic #2343) + Web UI Foundation (Epic #2344), plus a steward monitoring/streaming capability epic. *Latest of the group — depends on Web UI Foundation.* · **Tags:** `dex`, `twin`, `web` · **Tier 2** — this is DEX collection v0 (the endpoint experience-signal seed).

- [ ] **Full OSquery support** — Integrate osquery as the **unmanaged-host-fact** data source for DNA plus ad-hoc fleet queries. Per ADR-017, osquery feeds DNA only through a **curated stable-fact allowlist** (`host:*` fragments, observe-only) — never its dynamic tables — and the specific query list is gated on the stdlib set being confirmed (ADR-016). Decisions remaining: bundled vs. host-detected binary, scheduling, security envelope. *Suggested home:* its own OSquery-integration epic, sequenced **before** baseline DNA. · **Tags:** `twin`, `cms` · **Tier 1–2** — host-fact source feeds both baseline DNA and later twin *discovery of the undeclared*.

- [ ] **Define & build the standard-library steward modules** — **Decided in ADR-016:** a closed **10-module** stdlib set — `file`, `service`, `package`, `script`, `firewall`, `patch`, **`user`, `cert_trust`, `time`, `hostname`**. Six exist (patch needs a `module.yaml` + stub resolution); **four are net-new cross-platform builds** (`user`, `cert_trust`, `time`, `hostname`). Also adds the `Get`→canonical-DNA-fragment contract, atomic object-level ownership declaration, and a stdlib completeness gate. *This is a build epic, not an audit* — likely splits into (a) reorg + contract + gate + `patch`, and (b) the four new modules. *Suggested home:* near-term module foundation. · **Tags:** `cms` · **Tier 1** — module `Get`→canonical-DNA-fragment contract is the substrate all twin/DEX state hangs on.

- [ ] **Split non-stdlib modules into an on-demand directory** — **Decided in ADR-016:** `features/modules/stdlib/` (installer payload) ↔ `features/modules/extended/` (CFGMS-authored, non-stdlib, pulled on demand per ADR-006), with a build-enforced installer-payload boundary. Registry/scheduled_task/network/mount/sysctl/env are the excluded-from-stdlib candidates that live under `extended/` when built. *Suggested home:* same module-foundation epic as the stdlib work above. · **Tags:** `cms` · **Tier 1**.

- [ ] **Controller baseline DNA per steward** — **Designed in ADR-017:** DNA becomes a fragment set (managed fragments from module `Get`, observe-only host facts from osquery), with object-canonical ids, a module-preempts-osquery authority resolver, a two-level per-fragment + aggregate-root hash, and delta-based partial-sync validation. *Suggested home:* DNA-composition epic, **downstream of both** the module foundation and OSquery. · **Tags:** `twin`, `dex`, `cms` · **Tier 1 — carries the twin/DEX data-model commitments.** This epic must land the four bake-in-now decisions or they become expensive retrofits: (1) per-fragment `{source, observed_at, authority, confidence}` provenance; (2) stable **typed entity id** per managed object; (3) controller **retains versioned fragment history** (per-entity state queryable over time — restores the DNA "memory" that current-state-only sync would discard); (4) DEX signals attach to the typed device/app entity as an extensible, timestamped, provenanced attribute set. See the [tiered rollout](#digital-twin--digital-employee-experience-dex--tiered-rollout) for how these unlock Tier 2/3.

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

- **Document Version**: 4.2
- **Last Updated**: 2026-07-08

### Related Documentation

- [Versioning Policy](../development/versioning-policy.md) - Semantic versioning details
- [CHANGELOG.md](../../CHANGELOG.md) - Complete version history
- [LICENSING.md](../../LICENSING.md) - Licensing details and FAQ
