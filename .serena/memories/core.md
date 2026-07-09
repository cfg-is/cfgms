# CFGMS — Core

Go config-management system. Zero-trust, mutual-TLS, feature-organized. Targets MSPs managing 50k+ endpoints (Windows/Linux/macOS).

## Three-tier system
- **Controller** — central mgmt, SaaS ops, fleet orchestration. Runs Linux/Windows (amd64).
- **Steward** — endpoint agent, local host ops. Runs Linux/Windows/macOS (amd64+arm64).
- **Outpost** (future) — proxy cache for stewards, agentless LAN probe/monitor.

Comms: gRPC-over-QUIC + mTLS internal; REST/HTTPS external.

## Source map (relative to repo root)
- `cmd/` — CLI entrypoints: `controller`, `steward`, `cfg` (user-facing CLI = the UX), `cert-manager`, `cfgms-steward-launcher`.
- `api/proto/` — protobuf defs.
- `pkg/` — shared packages + central providers (see `mem:architecture`).
- `features/` — business logic, feature-organized: config, controller, modules, monitoring, rbac, reports, saas, siem, steward, tenant.
- `test/` — `test/integration/`, `test/e2e/`.
- `docs/` — architecture, ADRs, development guides.

## Project-wide invariants
- PRs target `develop`, never `main`. `develop`→`main` only for releases. `develop` is protected: feature branch + PR even for scripts/docs.
- Branch naming: `feature/story-<N>-<description>` from `develop`.
- No mocks in tests — use real CFGMS components. No `t.Skip()` without justification.
- No hardcoded/cleartext secrets anywhere (OS keychain only). No insecure defaults (TLS in dev too).
- `git add <specific files>` only — never `git add .` / `-A`.
- Squash-merge only via GitHub merge queue on develop (`gh pr merge <N> --squash` to enqueue).
- Canonical docs describe CFGMS directly: no "X-inspired"/competitor analogies, no real third-party vendor names as examples (use `vendor-a`, `acme-corp`); real integrations like M365 stated as facts.

## Domain memories
- Build/run/lint/test commands: `mem:suggested_commands`
- Languages, deps, version pins: `mem:tech_stack`
- Central-provider pattern, storage, certs, modules: `mem:architecture`
- Code style, test taxonomy, naming: `mem:conventions`
- Exact gates to run before declaring a task done: `mem:task_completion`
- Memory file conventions (read before adding/editing memories): `mem:memory_maintenance`
