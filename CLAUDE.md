# CLAUDE.md

Guidance for Claude Code when working in this repository.

## Project Overview

CFGMS (Config Management System) is a Go-based configuration management system with zero-trust security, mutual TLS, and feature-based organization. Targets MSPs managing 50k+ endpoints across Windows, Linux, and macOS.

**Three-Tier System:**
- **Controller**: Central management, SaaS operations, fleet orchestration
- **Steward**: Endpoint agent, local operations on devices
- **Outpost**: Proxy cache for network device monitoring

**Communication:** gRPC-over-QUIC with mTLS (internal), REST API with HTTPS (external)

**Platform:** Steward runs on Linux/Windows/macOS (AMD64+ARM64). Controller runs on Linux/Windows (AMD64).

## Execution Mode

Two modes, detected automatically. Both enforce identical validation gates.

- **Agent Mode** (`CFGMS_AGENT_MODE=true`): Follow [Agent Workflow](#agent-implementation-workflow)
- **Interactive Mode** (default): Use [slash commands](#slash-commands)

### Agent Implementation Workflow

**Phase 1 — Implement:** Read the issue (`gh issue view <N>`), check central providers and operating model docs for overlap, write tests first (TDD), implement with real components (no mocks). Branch from `develop`: `feature/story-<N>-<description>`.

**Phase 2 — Validate:** `make test-agent-complete`

**Phase 3 — Self-Review:** No mocks, no `t.Skip()` without justification, no hardcoded secrets, no central provider violations (`make check-architecture`), storage imports use `pkg/storage/interfaces` only.

**Phase 4 — Commit and PR:** Format: `<scope>: <what changed> (Issue #XXX)` with `Fixes #XXX` in body. PR targets `develop`: `gh pr create --base develop`. See [commit standards](docs/development/commit-and-pr-standards.md).

**Failure handling:** After 3 fix iterations, create a **draft** PR with error output. Never force-merge or skip validation.

**Scope constraints:**
- Do not modify `CLAUDE.md`, `Makefile` root targets, `.github/workflows/`, or `scripts/install-git-hooks.sh` unless the story requires it
- Do not add Go module dependencies without story justification
- Do not create new central providers — extend existing ones or flag for human review
- Never force-push, reset --hard, or delete branches

### Slash Commands

In interactive mode, use these for ALL development work:

- **`/story-start`** — Begin story with pre-flight checks
- **`/story-commit`** — Commit with validation and progress tracking
- **`/story-complete`** — Complete story with parallel QA + Security review and PR creation
- **`/pr-review [number]`** — 6-phase PR review with CI verification

See `.claude/commands/` for documentation.

### Git Hooks

Install before first commit: `./scripts/install-git-hooks.sh`

Installs pre-commit (artifact detection) and pre-push (`make test`) hooks. Bypass with `--no-verify` in emergencies only.

## Development Rules

### Zero Tolerance

- **PRs target `develop`**, never `main`. Only `develop → main` for releases.
- **No failing tests.** 100% pass rate before commits.
- **No mocks.** Use real CFGMS components in tests.
- **No hardcoded secrets.** Credentials use OS keychain only.
- **No cleartext secrets on disk.** Even in development.
- **No insecure defaults.** If it needs TLS in production, it needs TLS in dev.
- **Feature branches only.** `feature/story-[NUMBER]-[description]` from develop.
- **`make test-complete` must pass** before creating PR.
- **`git add <specific files>` only.** Never `git add .` or `git add -A`.

### Security

- Mutual TLS for all internal communication
- Input validation and sanitization for all user data
- SQL injection prevention (parameterized queries only)
- No information disclosure in error messages
- Use `logging.SanitizeLogValue()` for HTTP params, URL paths, headers

### Git Messages & PRs

**FACTS ONLY** — every claim must be from actual measurements, not estimates.

Format: `<scope>: <what changed> (Issue #XXX)`. See [commit standards](docs/development/commit-and-pr-standards.md) for full rules and examples.

## Required CI Checks

All must pass before merge to `develop`:

| Check | What it validates |
|-------|-------------------|
| `unit-tests` | Core functionality (~3-5 min) |
| `integration-tests` | Comprehensive + production-critical (~5-10 min) |
| `Build Gate` | Cross-platform compilation + Docker integration (~10-15 min) |
| `security-deployment-gate` | Security vulnerability blocking (~6-10 min) |

Docs-only PRs get instant green checks via stub jobs (<2 min merge path).

**Branch protection config:** Squash merge only, no review requirements (solo-friendly), relaxed up-to-date policy (PRs don't need latest develop to merge).

**Merging:** Interactive mode uses `gh pr merge --squash --auto` after `/pr-review` approval. Agent-dispatched PRs must NOT auto-merge — they require manual `/pr-review` before merging.

**`make test-complete` coverage:**
- All pre-commit validation, fast comprehensive tests, production-critical tests
- Cross-platform compilation, Docker integration tests, E2E tests
- **Gap:** Native Windows/macOS builds (CI-only, requires runners)

## Essential Commands

```bash
make test              # Pre-flight validation (must pass before commits)
make test-commit       # Pre-commit (tests + security + lint)
make test-complete     # Story completion — matches ALL CI checks
make build             # All binaries (current platform)
make security-scan     # Security checks (blocking on critical/high)
make check-architecture # Central provider violation detection
```

## Architecture

### Operating Model

Consult these before implementing steward or controller behavior changes:
- [System](docs/architecture/operating-model.md) — component roles, communication, failure modes
- [Steward](docs/architecture/steward-operating-model.md) — convergence loop, modules, DNA sync
- [Controller](docs/architecture/controller-operating-model.md) — startup, fleet management, orchestration

### Storage

- **Pluggable design** — all components use `pkg/storage/interfaces`
- **Default:** Git with SOPS encryption
- **Write-through caching** pattern (memory → durable storage)
- **No memory-only storage** — features requiring durability use durable storage everywhere

### Certificate Management

- `pkg/cert.Manager` handles all certificate operations
- Controllers auto-generate CA and certs on first boot
- Tests use auto-generated certs (never static test certs)
- mTLS required for all internal gRPC-over-QUIC communication
- `CFGMS_TRANSPORT_USE_CERT_MANAGER=true` (never disable)

### Central Provider System

**Before implementing new functionality, check if it belongs in a central provider.**

**Rules:**
1. If functionality is needed by >1 feature, it MUST use or become a central provider
2. New providers MUST be pluggable by default (`interfaces/` subdirectory)
3. Extend existing providers rather than creating overlapping code
4. `make check-architecture` enforces this automatically

**Why pluggable by default:** Multi-tenant SaaS with different backend needs, commercial/OSS feature gating, 50k+ steward scale, cloud vs on-prem flexibility, testing without mocks (use test implementations). Cheap to do now, expensive to retrofit.

**Pluggable Providers:**

| Package | Purpose |
|---------|---------|
| `pkg/storage` | Data persistence (git, database) |
| `pkg/logging` | Structured logging (file, timescale) |
| `pkg/secrets` | Secret storage with encryption (SOPS) |
| `pkg/directory` | Directory services (M365, AD) |
| `pkg/controlplane` | Control plane communication (gRPC) |
| `pkg/dataplane` | Data plane communication (gRPC) |

**Direct Providers:** `pkg/cert`, `pkg/telemetry`, `pkg/cache`, `pkg/session`, `pkg/registration`, `pkg/monitoring`, `pkg/maintenance`, `pkg/security`

**Utilities (not providers):** `pkg/config`, `pkg/testing`, `pkg/testutil`, `pkg/version`, `pkg/audit`

See `pkg/README.md` for the full decision tree.

### Module Deployment

- **Controller:** Cross-system operations, SaaS/Cloud APIs, org-wide policies
- **Steward:** Local resources (files, packages, firewall), platform-specific, offline capability

## Testing

### Standards

- Write tests first (TDD)
- Use real CFGMS components, not mocks
- Test error paths and race conditions
- Use `t.TempDir()` for any test that writes files (never write to repo root)

### Test File Taxonomy

Tests MUST be placed in the correct location based on what they test.

| Test type | Location | Protocol in filename? |
|-----------|----------|-----------------------|
| Contract tests | `pkg/*/interfaces/contract_test.go` | NO |
| Provider unit tests | `pkg/*/providers/{name}/*_test.go` | YES (OK) |
| Integration tests | `test/integration/transport/` | NO |
| E2E tests | `test/e2e/` | NO |

`test/integration/transport/` and `test/e2e/` filenames must NEVER reference a specific protocol. If a test is protocol-specific, it belongs in `pkg/*/providers/{name}/`.

## Code Organization

```text
cmd/           # CLI applications (controller, steward, cfg)
api/proto/     # Protocol buffer definitions
pkg/           # Shared packages and central providers
  transport/quic/    # QUIC transport adapter for gRPC
  controlplane/      # Control plane provider (gRPC)
  dataplane/         # Data plane provider (gRPC)
  storage/interfaces/  # Storage contracts (import these)
  storage/providers/   # Storage implementations (don't import directly)
features/      # Business logic
test/          # Integration and E2E tests
docs/          # Documentation
```

### Anti-Patterns

- Direct import of storage providers in business logic
- Mocking CFGMS components in tests
- Storing cleartext secrets anywhere
- Duplicating TLS code — use `pkg/cert` helpers
- Creating custom cache — use `pkg/cache.Cache`
- Manual certificate loading — use `pkg/cert.LoadTLSCertificate()`
- Committing test artifacts — use `git add <specific files>`
- Logging unsanitized input — use `logging.SanitizeLogValue()`

## Desired State Development (DSD)

Stories are outcome-based. Work is complete only when the entire system reflects the desired end state.

1. **Issues define desired state.** Acceptance criteria answer: "What does the system look like when this is done?"
2. **No pre-existing conditions.** If any file prevents desired state, it's in scope.
3. **Trace the full path.** Source, tests, fixtures, configs, Docker, docs, CI — all must reflect the new state.
4. **Validation proves desired state.** Done when all tests pass, not when code compiles.

## Multi-Tenancy

Recursive parent-child tenant model with arbitrary depth. Path-based identification (`root/msp-a/client-1/servers`). Config inheritance resolves root to leaf.

### Licensing Boundary

- **Apache (OSS):** Single root tenant tree — one MSP, unlimited depth
- **Elastic (Commercial):** Multi-root / platform mode — multiple independent MSP trees

Ask: "Does this work within a single tenant tree, or require awareness of multiple roots?" Single-tree = Apache. Multi-root = Elastic.

## Quick Reference

- [Commit & PR Standards](docs/development/commit-and-pr-standards.md)
- [Story Checklist](docs/development/story-checklist.md)
- [PR Review Methodology](docs/development/pr-review-methodology.md)
- [Commands Reference](docs/development/commands-reference.md)
- [Git Workflow](docs/development/git-workflow.md)
- [Architecture](docs/architecture/)
- [Roadmap](docs/product/roadmap.md)

## Dependencies

- `github.com/spf13/cobra` — CLI framework
- `github.com/stretchr/testify` — Testing utilities
- `github.com/quic-go/quic-go` — QUIC transport layer
- `google.golang.org/grpc` — gRPC framework
- `google.golang.org/protobuf` — Protocol buffers
