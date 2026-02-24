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

### Slash Commands (MANDATORY)

**CRITICAL**: You MUST use these slash commands for ALL development work. Manual workflows are deprecated and prone to missing critical validation steps.

**Required Commands:**
- **`/story-start`** - MUST use to begin new story with pre-flight checks and roadmap auto-detection
- **`/story-commit`** - MUST use for all commits with validation and GitHub issue progress tracking
- **`/story-complete`** - MUST use to complete story with parallel adversarial team review (QA + Security agents) and PR creation
- **`/pr-review [number]`** - MUST use to execute structured 6-phase PR review methodology with CI verification

**Why Mandatory:**
- Prevents broken tests from reaching develop branch
- Ensures consistent validation across all commits
- Verifies GitHub Actions CI status before PR approval
- Maintains zero-tolerance quality gates
- Provides progress tracking and audit trail

See `.claude/commands/` for complete documentation.

### Git Hooks Installation (MANDATORY - First Time Setup)

**CRITICAL**: Before starting development, install git hooks to enforce validation:

```bash
./scripts/install-git-hooks.sh
```

**What This Installs:**
- `pre-push` hook - Runs `make test` before every push to remote
- Prevents broken tests from reaching remote branches
- Provides fast feedback (2-5 minutes) before CI runs

**Why Mandatory:**
- Last line of defense against pushing broken code
- Catches issues before GitHub Actions CI (saves time)
- Enforces zero-tolerance policy automatically
- Can be bypassed with `--no-verify` in emergencies (not recommended)

### Critical Development Rules (MANDATORY)

#### Zero Tolerance Policies

- **Git Hooks Installed**: MUST install git hooks before first commit (see above)
- **No Failing Tests**: Cannot start new work or commit with ANY test failures
- **Security Gates**: All security scans must pass before commits
- **Feature Branches**: Always use `feature/story-[NUMBER]-[description]` branches
- **Git Workflow (CRITICAL)**: Feature branches ALWAYS target `develop`, NEVER `main`
  - ✅ CORRECT: `gh pr create --base develop`
  - ❌ WRONG: `gh pr create --base main` (breaks GitFlow workflow)
  - Only `develop → main` PRs allowed (for releases)
  - See [docs/development/git-workflow.md](docs/development/git-workflow.md) for details
- **Real Component Testing**: Never mock CFGMS functionality in tests - use real components
- **Story Completion (Story #315)**: `make test-complete` must pass 100% before creating PR
  - test-complete runs ALL CI required checks locally (100% parity)
  - Only acceptable gap: Windows/macOS native builds (infrastructure limitation)

#### EPIC 6 Complete: Storage Architecture (CRITICAL)

- ✅ **Memory provider eliminated** from global storage choices
- ✅ **All components migrated** to pluggable storage architecture
- **Required Pattern**: Write-through caching (memory → durable storage)
- **Import Rule**: Business logic imports `pkg/storage/interfaces` ONLY
- **Prohibited**: Cleartext secrets on disk (even in development)

### ⚠️ Manual Workflow (DEPRECATED - DO NOT USE)

**IMPORTANT**: Manual workflows are DEPRECATED as of Story #292 (workflow enforcement). Direct use of git/make commands bypasses critical validation gates.

**Known Issues with Manual Workflow:**
- ❌ No automated pre-flight validation before starting work
- ❌ Easy to forget `make test-commit` before commits
- ❌ No GitHub Actions CI verification before PR approval
- ❌ Missing progress tracking and audit trail
- ❌ Allows broken tests to reach develop (root cause of workflow breakdown)

**If You Must Use Manual Commands** (emergency only):
1. **Pre-flight**: Run `make test` - MUST pass 100% before starting
2. **Branch**: Create `feature/story-[NUMBER]-[description]` from develop
3. **Develop**: Write tests first, implement with TDD approach
4. **Commit**: Run `make test-commit` - MUST pass before commit
5. **Complete**: Run `make test-complete` - MUST pass 100% before PR
6. **PR Creation**: Create PR **targeting develop** (`gh pr create --base develop`)
7. **CI Verification**: WAIT for GitHub Actions CI - MUST be green before merge
8. **Project Updates**: Manually update GitHub project status and roadmap

**Recommendation**: Use slash commands instead. They automate all these steps and prevent human error.

See [docs/development/story-checklist.md](docs/development/story-checklist.md) for historical reference.

### Branch Protection & Required Checks

**Develop Branch Protection** (enforced via GitHub rulesets):

The `develop` branch uses direct required status checks to prevent merging without validation:

**Required Checks** (all must pass):
- `unit-tests` - Core functionality validation (fast, ~3-5 min)
- `integration-tests` - Fast comprehensive + production-critical tests (~5-10 min)
- `Build Gate` - Cross-platform compilation + integration tests (~10-15 min total)
  - Cross-platform compilation verification
  - Native builds (Linux, macOS, Windows)
  - Docker integration tests (storage, controller, MQTT+QUIC)
- `security-deployment-gate` - Security vulnerability blocking (~6-10 min)

**Configuration**:
- ✅ No review requirements (solo-friendly development)
- ✅ Squash merge only (clean git history)
- ✅ Strict up-to-date branch enforcement (prevents conflicts)
- ❌ No AI bypass (tests must pass, no admin override needed normally)

**Docs-Only PRs**:
- Documentation changes (`docs/**`, `*.md`) automatically get instant green checks
- Stub jobs in `documentation.yml` provide required check names
- Fast merge path (<2 minutes) for docs-only changes

**Code PRs**:
- Full validation runs (5-15 minutes total)
- All critical workflows execute with path-based filtering
- Comprehensive test suite, security scans, and cross-platform builds

**Previous Approach** (removed in Story #322):
- ❌ Used `merge-gate.yml` with `workflow_run` trigger (had race conditions)
- ❌ Could fail when running before other checks completed
- ❌ Didn't work reliably for PR branches
- ✅ Replaced with direct required checks (GitHub's recommended approach)

## Git Messages & PR Standards

### Core Principle: FACTS ONLY

**CRITICAL**: Everything in commit/PR messages must be provable fact from actual measurements, not estimates or aspirations.

**✅ GOOD:** "Reduced max latency from 5.4ms to 34µs (measured in test run)"
**❌ BAD:** "Should reduce latency by ~50%" (not measured)

**When in doubt:** Either measure it or don't claim it.

### Commit Messages

**Format:** `<scope>: <what changed> (Issue #XXX)`
**Length:** 15-25 lines for significant changes

**Rules:**
- **Title**: Imperative mood ("Fix" not "Fixed"), lowercase after colon, no period
- **Body**: Explain WHY (problem + solution context), then FACTS with citations
- **Changes**: 3-5 bullets of key modifications
- **Footer**: `Fixes #XXX` and `Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>`

**Example:**
```
features/rbac: eliminate statistics lock contention (Issue #355)

The zero-trust policy engine used mutex-based statistics tracking.
Under concurrent load (50 goroutines), this caused serialization
where goroutine #50 waited 5ms while earlier goroutines held the
lock for 100ns each. This was causing performance test failures.

Replaced mutex with atomic operations (atomic.Int64, CAS loop for
EMA). Performance test results show:
- Concurrent max: 5.421ms → 34.093µs (measured in test output)
- Average: 77µs → 5.658µs (50 iterations)
- 100% success rate: 50/50 requests completed

Changes:
- Convert ZeroTrustStats fields to atomic.Int64/Uint64
- Replace mutex.Lock() with atomic.Add() for counters
- Use CAS loop for exponential moving average updates
- Restore 5ms timeout in performance tests (was 10ms)

Fixes #355
Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>
```

### Pull Request Descriptions

**Length:** 60-80 lines for significant changes

**Rules:**
- **Summary**: 2-3 sentences with measured impact and actual numbers
- **Problem Context**: 1-2 paragraphs explaining WHY (enough context to avoid clicking through)
- **Changes**: 3-5 bullets of key technical changes (no code examples)
- **Measured Impact**: FACTS ONLY - cite test names, use table for 4+ metrics
- **Testing**: What was tested + pass/fail status

**Anti-patterns to avoid:**
- ❌ Speculation ("should", "approximately", "estimated")
- ❌ Code dumps (trust the diff)
- ❌ Implementation lectures (belongs in code comments)
- ❌ Repetition (say things once)

**Example:**
```markdown
## Summary

Replaces mutex-based statistics with atomic operations in zero-trust
policy engine. Under concurrent load (50 goroutines), eliminates
serialization that caused 5.4ms max latency. Test results show max
latency reduced to 34µs.

## Problem Context

The zero-trust policy engine tracked statistics using mutex-protected
counters. When 50 goroutines evaluated access concurrently, each
waited for exclusive lock access to increment counters. This created
serialization where goroutine #50 waited 5ms while earlier goroutines
held the lock for ~100ns each.

PR #353 worked around this by relaxing timeout from 5ms to 10ms, but
this was a band-aid that masked the root cause.

## Changes

- Convert ZeroTrustStats fields to atomic.Int64/atomic.Uint64
- Remove sync.RWMutex, use atomic.Add() for counter increments
- Implement CAS loop for exponential moving average calculation
- Create ZeroTrustStatsSnapshot for backward-compatible public API
- Restore 5ms timeout in performance test

## Measured Impact

Test: TestZeroTrustPolicyEvaluationPerformance/Concurrent
- Max latency: 5.421ms → 34.093µs (159x improvement)
- Average: 77µs → 5.658µs (13x improvement)
- Success rate: 50/50 requests (100%)

All measurements from actual test output in test-complete run.

## Testing

Scenarios tested:
- Concurrent load: 50 goroutines evaluating simultaneously
- Sequential batch: 10, 50, 100 request batches
- Sustained load: 478 requests over 5 seconds

Results:
✅ All validation passed (test-complete)
✅ Performance requirements met (<5ms timeout)
✅ Zero test failures

Fixes #355
```

### Pre-Commit Checklist

- [ ] **Facts verified**: All performance claims from actual measurements
- [ ] **Sources cited**: Test names or benchmark references included
- [ ] **No speculation**: No "should", "approximately", "estimated"
- [ ] **No code dumps**: Let the diff show code changes
- [ ] **Issue linked**: `Fixes #XXX` or `Part of #XXX`

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
make test-complete  # Story completion (10-20 min) - MATCHES ALL CI required checks
make test-ci        # Complete CI validation (15-25 min)
make test-integration  # M365 + storage integration tests
```

**Story Completion**: `make test-complete` now runs ALL CI required checks locally:
- ✅ All pre-commit validation (test-commit)
- ✅ Fast comprehensive tests (test-fast)
- ✅ Production critical tests (test-production-critical)
- ✅ Cross-platform compilation (build-cross-validate)
- ✅ Docker integration tests (storage/controller)
- ✅ E2E tests (MQTT+QUIC, Controller)
- ❌ Only gap: Native Windows/macOS builds (CI-only, requires runners)

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

**Current Central Providers** (as of Story #267.5):

**Pluggable Providers** (Multiple Implementations):

1. **`pkg/storage`** - Data persistence (git, database) with write-through caching
2. **`pkg/logging`** - Structured logging (file, timescale)
3. **`pkg/secrets`** - Secret storage with encryption (SOPS backend)
4. **`pkg/directory`** - Directory services (M365, Active Directory)
5. **`pkg/mqtt`** - MQTT broker abstraction (mochi-mqtt) - *broker infrastructure only*
6. **`pkg/controlplane`** - Control plane communication (MQTT provider) - commands, events, heartbeats
7. **`pkg/dataplane`** - Data plane communication (QUIC provider) - config sync, DNA sync, bulk transfers

**Direct Providers** (Single Implementation - Candidates for Pluggable Migration):
8. **`pkg/cert`** - Certificate/TLS management (could support: Internal CA, Let's Encrypt, Vault, PKI)
9. **`pkg/telemetry`** - Observability (could support: OpenTelemetry, Datadog, New Relic, Prometheus)
10. **`pkg/cache`** - Write-through caching (could support: Memory, Redis, Memcached)
11. **`pkg/session`** - Session management (could support: Memory, Redis, Database, JWT-stateless)
12. **`pkg/registration`** - Steward registration
13. **`pkg/monitoring`** - Health monitoring
14. **`pkg/maintenance`** - Maintenance window scheduling
15. **`pkg/security`** - Security utilities (input validation)

**Deprecated** (use providers above instead):
- **`pkg/mqtt/client`** → use `pkg/controlplane/interfaces` (Story #267.5)
- **`pkg/mqtt/types`** → use `pkg/controlplane/types` (Story #267.5)
- **`pkg/quic/client`** → use `pkg/dataplane/interfaces` (Story #267.5)
- **`pkg/quic/session`** → use `pkg/dataplane/interfaces` (Story #267.5)
- **`pkg/quic/server`** → internal infrastructure for data plane provider only

*Note: Direct providers listed above should be evaluated for pluggable migration when adding second implementation or during major refactoring.*
*See [Communication Layer Migration Guide](docs/architecture/communication-layer-migration.md) for migration details.*

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

```text
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
- **Direct MQTT client/types imports** - Use `pkg/controlplane/interfaces` and `pkg/controlplane/types` instead of `pkg/mqtt/client` or `pkg/mqtt/types`
- **Direct QUIC client/session imports** - Use `pkg/dataplane/interfaces` instead of `pkg/quic/client` or `pkg/quic/session`
- **Logging unsanitized user input** - The centralized logger (`pkg/logging`) auto-sanitizes all string values; no call-site wrapping needed

## Quick Reference

### Documentation

- **Story Development**: [docs/development/story-checklist.md](docs/development/story-checklist.md)
- **PR Reviews**: [docs/development/pr-review-methodology.md](docs/development/pr-review-methodology.md)
- **All Commands**: [docs/development/commands-reference.md](docs/development/commands-reference.md)
- **Git Workflow**: [docs/development/git-workflow.md](docs/development/git-workflow.md)
- **Architecture**: [docs/architecture/](docs/architecture/)
- **Roadmap**: [docs/product/roadmap.md](docs/product/roadmap.md)

### Project Management

- **GitHub Project**: [CFGMS Development Roadmap](https://github.com/orgs/cfg-is/projects/1)
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

*For complete development workflow automation, use the slash commands in `.claude/commands/`. For manual processes, see the detailed guides in `docs/development/`.*
