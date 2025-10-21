# ADR 001: Central Provider Compliance Enforcement

**Status**: Accepted

**Date**: 2025-10-20

**Deciders**: Development Team

**Related**: Story #239 (Security Hardening - Infrastructure Changes)

## Context

During Story #239 security audit remediation, we discovered a critical bug: the controller maintained separate Certificate Authorities for HTTP (`CFGMS Root CA`) and MQTT (`CFGMS MQTT CA`). This dual-CA configuration caused mTLS failures even when certificates were properly signed, because HTTP connections expected HTTP CA signatures while MQTT connections expected MQTT CA signatures.

### Root Cause Analysis

The dual-CA bug occurred because:
1. Certificate generation logic was duplicated between HTTP and MQTT initialization
2. No enforcement mechanism prevented bypassing the central `pkg/cert.Manager`
3. Developers were unaware of the existing central certificate provider
4. Code review did not catch the architectural violation

This bug represents a **class of problems** where developers re-implement functionality that already exists in central providers, leading to:
- **Bugs**: Inconsistent behavior (dual-CA causing mTLS failures)
- **Tech Debt**: Duplicate implementations to maintain
- **Scale Issues**: Multiple code paths doing the same thing differently
- **Testing Burden**: Same functionality tested multiple times

### CFGMS Central Provider Architecture

CFGMS implements a **pluggable provider architecture** where cross-cutting concerns are centralized in `pkg/`:

**Existing Central Providers**:
- `pkg/storage` - Data persistence (git, database, cache)
- `pkg/logging` - Structured logging with tenant isolation
- `pkg/cert` - Certificate/TLS management (prevents dual-CA bugs)
- `pkg/secrets` - Secret storage with encryption
- `pkg/telemetry` - Observability (metrics, tracing)
- `pkg/cache` - Write-through caching
- `pkg/session` - Session management
- `pkg/directory` - Directory services (M365, Active Directory)
- `pkg/mqtt` - MQTT broker abstraction
- And 5 others (see `CLAUDE.md`)

**Architecture Pattern**:
```
pkg/{name}/interfaces/  → Pluggable provider (multiple implementations)
pkg/{name}/             → Direct provider (single implementation)
```

**The Problem**: Nothing prevented developers from bypassing these central providers and re-implementing functionality, leading to bugs like dual-CA.

## Decision

We will implement a **multi-layered enforcement system** to prevent central provider re-invention:

### Layer 1: Automated Pre-commit Checks
**Tool**: `make check-architecture` (Makefile target)

**Scans staged files for violations**:
- TLS/crypto usage outside `pkg/cert/`
- Storage implementations outside `pkg/storage/`
- Logging implementations outside `pkg/logging/`
- Notification implementations outside `pkg/notifications/`

**Integration**: Runs automatically in `/story-commit` workflow (blocking)

**Implementation**:
```makefile
check-architecture:
	@violations=0
	# Check for tls.Config{} outside pkg/cert/
	# Check for x509.Certificate outside pkg/cert/
	# Check for sql.Open outside pkg/storage/
	# Check for logrus.New/zap.New outside pkg/logging/
	# Fail build if violations found
```

### Layer 2: Pre-commit Hook (Optional)
**Tool**: `.pre-commit-config.yaml`

**Runs before git commit**:
- Calls `make check-architecture` on changed files
- Provides immediate feedback during development
- Can be bypassed with `--no-verify` if needed

**Benefit**: Catches violations before `/story-commit` runs full test suite

### Layer 3: Linter Integration
**Tool**: `golangci-lint` with `depguard` rules

**Blocks imports at IDE level**:
- `pkg/storage/providers/*` cannot be imported by `features/` (must use `interfaces`)
- `pkg/logging/providers/*` cannot be imported by `features/`
- Direct `crypto/tls`, `crypto/x509` imports restricted outside `pkg/cert/`

**Benefit**: Fastest feedback (IDE shows error immediately)

### Layer 4: PR Review Checklist
**Tool**: `/pr-review` slash command (Phase 2)

**Manual verification**:
- Reviewer checks central provider compliance
- Validates no duplicate implementations
- Ensures proper dependency injection

**Benefit**: Human verification of architectural intent

### Layer 5: Documentation
**Files**: `pkg/README.md`, `CLAUDE.md`

**Content**:
- Golden Rules: Cross-cutting → central provider, pluggable by default
- Complete provider list (14 providers, categorized)
- Decision tree for adding new providers
- Examples of when to extend vs create

**Benefit**: Prevents violations through education

### Pluggable by Default Principle

**New Golden Rule #2**: "All central providers SHOULD be pluggable by default (with `interfaces/` subdirectory)"

**Rationale**:
- Multi-tenant SaaS needs different backends
- Commercial/Open Source feature gating
- 50k+ Steward scale requirements
- **Bug prevention**: Dual-CA impossible with pluggable cert provider (enforced single interface)

**Exceptions**: Only for true utilities (`version`, `testutil`, `config`)

## Consequences

### Positive

1. **Bug Prevention**: Dual-CA class of bugs prevented by automated checks
2. **Architectural Consistency**: Enforced central provider usage across codebase
3. **Early Feedback**: Violations caught at multiple stages (IDE → commit → PR)
4. **Developer Guidance**: Clear rules for when to extend vs create
5. **Reduced Tech Debt**: Prevents duplicate implementations from entering codebase
6. **Testing Improvement**: Single implementation per concern = focused testing

### Negative

1. **Learning Curve**: Developers must learn central provider system
2. **Build Time**: Additional checks add ~1-2 seconds to commit workflow
3. **False Positives**: Rare legitimate use cases might need exceptions
4. **Maintenance**: Rule set must be updated as providers are added

### Mitigation Strategies

- **Learning Curve**: `pkg/README.md` provides decision tree and examples
- **Build Time**: Checks run only on staged files (optimized for speed)
- **False Positives**: `make check-architecture` includes escape hatch for valid exceptions
- **Maintenance**: `make validate-providers` detects undocumented providers

## Implementation Timeline

- ✅ **Completed**: `make check-architecture` target (Story #239)
- ✅ **Completed**: `/story-commit` integration (Story #239)
- ✅ **Completed**: `/pr-review` Phase 2 updates (Story #239)
- ✅ **Completed**: Documentation (`pkg/README.md`, `CLAUDE.md`) (Story #239)
- 🔄 **In Progress**: `.pre-commit-config.yaml` hook (Story #239)
- 🔄 **In Progress**: `.golangci.yml` depguard rules (Story #239)

## Alternatives Considered

### Alternative 1: Documentation Only
**Approach**: Only update docs, no enforcement

**Rejected Because**:
- Dual-CA bug occurred despite architecture docs existing
- Humans forget, automation doesn't
- No guarantee developers read docs before implementing

### Alternative 2: Full Linting Only
**Approach**: Only use golangci-lint depguard rules

**Rejected Because**:
- Limited to import-level checks (misses inline implementations)
- Harder to maintain complex pattern rules
- No integration with workflow commands

### Alternative 3: Runtime Enforcement
**Approach**: Panic if duplicate providers detected at runtime

**Rejected Because**:
- Too late (bugs already in production)
- Difficult to implement reliable detection
- Punishes users for developer mistakes

### Chosen Approach: Multi-Layered Defense
**Rationale**: Defense in depth with multiple checkpoints catches violations early while providing flexibility

## References

- **Story #239**: Security Hardening - Infrastructure Changes
- **Dual-CA Bug Fix**: Commit `13cb95d` (Fix dual-CA bug and SOPS storage provider configuration)
- **Architecture Compliance**: Commit `157bf9b` (Add central provider compliance checks)
- **Documentation**: Commit `e76e63a` (Add central provider documentation and validation helper)
- **Pluggable by Default**: Commit `2e8c8dd` (Establish pluggable by default principle)
- **Related Architecture**: `docs/architecture/plugin-architecture.md`

## Lessons Learned

1. **Architectural Guardrails Matter**: Good intentions and documentation are insufficient without enforcement
2. **Catch Early**: Earlier violation detection = cheaper fixes (IDE < commit < PR < production)
3. **Defense in Depth**: Multiple enforcement layers provide safety net when one layer is bypassed
4. **Automation Over Process**: Automated checks scale better than relying on developer memory

## Future Considerations

1. **Provider Auto-Discovery**: Tool to scan codebase and suggest missing central providers
2. **Migration Tooling**: Automated refactoring to move code into central providers
3. **Metrics**: Track central provider compliance over time
4. **IDE Integration**: Real-time highlighting of violations in VSCode/GoLand
5. **Provider Templates**: Scaffold new pluggable providers with `make new-provider`
