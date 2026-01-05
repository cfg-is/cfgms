# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CFGMS (Config Management System) is a modern, Go-based configuration management system designed with resilience, security, and clean architecture principles. The project implements a zero-trust security model with mutual TLS authentication and follows a feature-based organization structure.

### Platform Support
**Steward (Agent) Support:**
- Linux: AMD64 & ARM64 - Full cross-distribution support
- Windows: AMD64 & ARM64 - Windows 10/11, Server 2019+
- macOS: ARM64 (M series) - Apple Silicon Macs

**Controller Support:**
- Linux: AMD64 - Primary target for production deployments
- Windows: AMD64 - Development and testing environments

**Cross-Platform Development:** All components compile and run on developer workstations across Windows, macOS, and Linux for seamless development experience.

## Development Workflow

### Slash Commands (Automated Workflow)
Use these commands to enforce mandatory development workflow:

- **`/story-start`** - Begin new story with pre-flight checks and roadmap auto-detection
- **`/story-commit`** - Commit with validation and GitHub issue progress tracking
- **`/story-complete`** - Complete story with final validation gates and PR creation
- **`/pr-review [number]`** - Execute structured 5-phase PR review methodology
- **`/dev-status`** - Quick development environment and current story status

See `.claude/slash-commands/` for complete documentation.

### Critical Development Rules (MANDATORY)

#### Zero Tolerance Policies
- **No Failing Tests**: Cannot start new work or commit with ANY test failures
- **Security Gates**: All security scans must pass before commits
- **Feature Branches**: Always use `feature/story-[NUMBER]-[description]` branches
- **Real Component Testing**: Never mock CFGMS functionality in tests - use real components

#### EPIC 6 Complete: Storage Architecture (CRITICAL)
- ✅ **Memory provider eliminated** from global storage choices
- ✅ **All components migrated** to pluggable storage architecture
- **Required Pattern**: Write-through caching (memory → durable storage)
- **Import Rule**: Business logic imports `pkg/storage/interfaces` ONLY
- **Prohibited**: Cleartext secrets on disk (even in development)

### Manual Workflow (When Not Using Slash Commands)

#### Essential Steps
1. **Pre-flight**: Run `make test` - must pass 100% before starting
2. **Branch**: Create `feature/story-[NUMBER]-[description]` from develop
3. **Develop**: Write tests first, implement with TDD approach
4. **Commit**: Run `make test-commit` - blocks on any failures
5. **Complete**: Create PR and update project status

See [docs/development/story-checklist.md](docs/development/story-checklist.md) for complete manual checklist.

## Essential Commands

### Daily Development
```bash
make test           # Run tests (must pass before commits)
make test-commit    # Pre-commit validation (tests + security + lint)
make security-scan  # Security checks (blocking on critical/high)
make lint          # Code quality validation
```

### Building
```bash
make build                # All binaries (current platform)
make build-controller     # Controller binary only
make build-steward        # Steward binary only
```

### Validation Targets
```bash
make test-ci       # Complete CI validation (8-12min)
make test-integration  # M365 + storage integration tests
```

See [docs/development/commands-reference.md](docs/development/commands-reference.md) for all commands.

## Core Architecture

### System Design
**Three-Tier System:**
- **Controller**: Central management, SaaS operations via workflow engine
- **Steward**: Endpoint management, local operations on devices
- **Outpost**: Proxy cache component for network device monitoring

**Communication:**
- **Internal**: MQTT+QUIC hybrid protocol with mutual TLS between components
  - MQTT control plane for real-time commands, heartbeats, and failover detection
  - QUIC data plane for high-performance configuration/DNA synchronization
- **External**: REST API with HTTPS and API key authentication

### Module Deployment Decision Matrix

**Deploy to Controller When:**
- Cross-system operations or SaaS/Cloud APIs
- Microsoft 365, AWS, Azure integrations
- Organization-wide policies or compliance

**Deploy to Steward When:**
- Local resources (files, packages, firewall)
- Platform-specific operations
- Performance critical or offline capability

**Examples:**
- Controller: `entra_user`, `conditional_access`, `tenant_management`
- Steward: `file`, `firewall`, `package`, `script`, `directory`

### Storage Architecture (EPIC 6 Complete ✅)
- **Global Storage Provider**: Single choice affects entire system (git/database)
- **Pluggable Design**: All components use same storage interfaces
- **Default**: Git with SOPS encryption for security and GitOps workflows
- **Memory Usage**: Internal component optimization only (write-through caching)
- **Security**: All providers ALWAYS use encryption - no cleartext secrets
- **No Memory-Only Storage**: Features requiring durability MUST use durable storage in dev/test/prod

### Certificate Management (CRITICAL)

- **Global Certificate Provider**: `pkg/cert.Manager` handles all certificate operations
- **Auto-Generation**: Controllers auto-generate CA and certificates on first boot
- **Testing Pattern**: Tests use auto-generated certs via `pkg/cert.Manager`
- **No Foot-Guns**: NEVER use static test certificates in passing tests
- **Negative Testing**: Invalid certs generated by `scripts/generate-invalid-test-certs.sh`
- **mTLS Enforcement**: Mutual TLS required for all internal MQTT+QUIC communication
- **Configuration**: Use `CFGMS_MQTT_USE_CERT_MANAGER=true` (never disable)

See [MQTT+QUIC Testing Strategy](docs/testing/mqtt-quic-testing-strategy.md) for details.

### Central Provider System (CRITICAL)
**MANDATORY**: Before implementing any new functionality, check if it belongs in a central provider.

**Golden Rules**:
1. **If functionality is needed by >1 feature, it MUST use or become a central provider**
2. **All central providers SHOULD be pluggable by default** (with `interfaces/` subdirectory)
   - Default assumption: Create pluggable provider
   - Exception: True utilities or proven single-implementation cases
   - **When in doubt: Make it pluggable** - prevents bugs like dual-CA issue

**Why Pluggable by Default?**
- Multi-tenant SaaS with different backend needs
- Commercial/Open Source feature gating
- 50k+ Steward scale requirements
- Cloud vs On-Prem deployment flexibility
- Testing without mocks (use test implementations)
- Future-proofing (cheap now, expensive to retrofit)

**Identifying Providers**:
- **Pluggable** (has `pkg/{name}/interfaces/`) - Multiple implementations, auto-registration
- **Direct** (no `interfaces/`) - Single implementation, direct import (exceptions only)
- See `pkg/README.md` for detailed decision tree and exceptions

**Current Central Providers** (as of Story #239):

**Pluggable Providers** (Multiple Implementations):
1. **`pkg/storage`** - Data persistence (git, database) with write-through caching
2. **`pkg/logging`** - Structured logging (file, timescale)
3. **`pkg/secrets`** - Secret storage with encryption (SOPS backend)
4. **`pkg/directory`** - Directory services (M365, Active Directory)
5. **`pkg/mqtt`** - MQTT broker abstraction (mochi-mqtt)

**Direct Providers** (Single Implementation - Candidates for Pluggable Migration):
6. **`pkg/cert`** - Certificate/TLS management (could support: Internal CA, Let's Encrypt, Vault, PKI)
7. **`pkg/telemetry`** - Observability (could support: OpenTelemetry, Datadog, New Relic, Prometheus)
8. **`pkg/cache`** - Write-through caching (could support: Memory, Redis, Memcached)
9. **`pkg/session`** - Session management (could support: Memory, Redis, Database, JWT-stateless)
10. **`pkg/registration`** - Steward registration
11. **`pkg/monitoring`** - Health monitoring
12. **`pkg/maintenance`** - Maintenance window scheduling
13. **`pkg/security`** - Security utilities (input validation)
14. **`pkg/quic`** - QUIC protocol support

*Note: Direct providers listed above should be evaluated for pluggable migration when adding second implementation or during major refactoring.*

**Not Providers** (Utilities):
- `pkg/config`, `pkg/testing`, `pkg/testutil`, `pkg/version`, `pkg/audit`

**Development Rules**:
- ❌ **PROHIBITED**: Creating new functionality that overlaps with central providers
- ❌ **PROHIBITED**: Creating direct providers without justifying ALL exception criteria
- ✅ **REQUIRED**: Extend existing central providers or propose new one
- ✅ **REQUIRED**: Use dependency injection to consume central providers
- ✅ **REQUIRED**: New providers MUST be pluggable unless proven exception
- ⚠️ **WARNING**: Duplicate functionality will be rejected in PR review and blocked by `make check-architecture`

**Before Starting Work**:
1. Review `pkg/README.md` for provider identification rules and decision tree
2. Check if your feature overlaps with existing provider functionality
3. If overlap exists: extend the central provider instead of creating new code
4. If new provider needed:
   - Default to pluggable architecture with `interfaces/` subdirectory
   - Only create direct provider if you can justify ALL exception criteria (see `pkg/README.md`)
   - Discuss architecture before implementation
5. Update CLAUDE.md and `pkg/README.md` when adding new provider

**Enforcement**:
- `make check-architecture` - Automated pre-commit violation detection (enhanced detection as of bugfix/central-provider-violations)
- `/story-commit` - Blocks commits with violations
- `/pr-review` Phase 2 - Validates central provider compliance

**Known Technical Debt** (Documented as of 2025-10-20):
The following custom cache implementations exist and should be migrated to `pkg/cache`:
- `features/rbac/zerotrust/cache.go` (364 lines) - Custom L1/L2 cache with LRU eviction
- `features/rbac/continuous/cache_manager.go` (970 lines) - Extensive multi-tier cache manager
- `features/reports/cache/` (346 lines across 3 files) - Custom cache package

**Total**: ~1,678 lines of duplicate caching logic that should use `pkg/cache.Cache`

**Why not migrated yet**: These are complex, feature-specific cache implementations with custom eviction
policies and statistics tracking. Migration requires careful refactoring to preserve behavior while
using `pkg/cache` primitives. Recommended approach: Create separate story for each migration to ensure
proper testing and validation.

**Detection**: Enhanced `make check-architecture` now detects custom cache implementations and will
prevent new violations from being committed.

## Critical Development Rules

### Must Follow
- **No Foot-guns in Development (MANDATORY)**: Never build insecure options for convenience. If a feature requires durable storage in production, it MUST use durable storage in development and testing. Never document unsafe alternatives.
- **TDD with Real Components**: Test actual program, not mocks
- **Zero Failing Tests**: 100% pass rate required before any commits
- **Security First**: All scans pass, no hardcoded secrets, credentials use OS keychain only
- **Pluggable Storage**: Import `pkg/storage/interfaces` only
- **Feature Branches**: Never commit directly to develop/main
- **Tenant Isolation**: Maintain strict tenant boundaries
- **Use Central Providers**: ALWAYS check if functionality exists in central providers before creating new code

### Security Requirements
- Mutual TLS for all internal communication
- Input validation and sanitization for all user data
- SQL injection prevention (parameterized queries only)
- No information disclosure in error messages
- Proper certificate and key management

### Testing Standards
- Write tests first (TDD approach)
- Use real CFGMS components, not mocks
- Test error paths and race conditions
- Include security edge case testing
- Achieve 100% coverage for core components

## Code Organization

### Directory Structure
```
cmd/           # Command-line applications (controller, steward, cfg)
api/proto/     # Protocol buffer definitions
pkg/           # Shared packages and global plugin interfaces
  storage/interfaces/  # Global storage contracts (import these)
  storage/providers/   # Storage implementations (don't import)
features/      # Business logic using global plugin interfaces
test/          # Integration and end-to-end tests
docs/          # Comprehensive documentation
```

### Anti-Patterns to Avoid
- Multiple representations of same data across components
- Direct import of storage providers in business logic
- Mocking CFGMS components in tests
- Storing cleartext secrets anywhere
- Bypassing global storage configuration
- **Duplicating TLS configuration code** - Use `pkg/cert` helpers (CreateServerTLSConfig, CreateClientTLSConfig)
- **Creating custom cache implementations** - Use `pkg/cache.Cache` with TTL and eviction
- **Manual certificate loading** - Use `pkg/cert.LoadTLSCertificate()` instead of `tls.LoadX509KeyPair()`
- **Manual CA pool creation** - TLS helpers handle this automatically

## Quick Reference

### Documentation
- **Story Development**: [docs/development/story-checklist.md](docs/development/story-checklist.md)
- **PR Reviews**: [docs/development/pr-review-methodology.md](docs/development/pr-review-methodology.md)
- **All Commands**: [docs/development/commands-reference.md](docs/development/commands-reference.md)
- **Git Workflow**: [docs/development/git-workflow.md](docs/development/git-workflow.md)
- **Architecture**: [docs/architecture/](docs/architecture/)
- **Roadmap**: [docs/product/roadmap.md](docs/product/roadmap.md)

### Project Management
- **GitHub Project**: https://github.com/orgs/cfg-is/projects/1
- **Issues & PRs**: All development tracked through GitHub
- **Roadmap Status**: See docs/product/roadmap.md for current progress

### Development Approach
- **Sprint Planning**: Always conduct sprint planning before milestones
- **AI Integration**: Use slash commands for workflow automation
- **Quality Gates**: Tests, security, and linting must pass
- **Continuous Deployment**: GitHub Actions with production gates

## Multi-Tenancy & Configuration

The system implements recursive parent-child tenant model:
- **Hierarchical Inheritance**: MSP → Client → Group → Device (4 levels)
- **Declarative Merging**: Named resources replace entire blocks
- **Source Tracking**: Full auditability of configuration sources
- **Scale**: Designed for 50k+ Stewards across multiple regions

## Dependencies
- `github.com/spf13/cobra` - CLI framework
- `github.com/stretchr/testify` - Testing utilities
- `github.com/mochi-mqtt/server` - MQTT broker for control plane
- `github.com/quic-go/quic-go` - QUIC protocol for data plane
- `google.golang.org/protobuf` - Protocol buffer support

---

*For complete development workflow automation, use the slash commands in `.claude/slash-commands/`. For manual processes, see the detailed guides in `docs/development/`.*