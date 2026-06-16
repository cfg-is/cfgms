# Conventions

## Testing (TDD — write tests first, real components, no mocks)
- Test error paths and race conditions.
- Use `t.TempDir()` for anything that writes files — never write to repo root.
- Test file taxonomy (placement is enforced by intent):
  | type | location | protocol in filename? |
  | contract | `pkg/*/interfaces/contract_test.go` | NO |
  | provider unit | `pkg/*/providers/{name}/*_test.go` | YES ok |
  | integration | `test/integration/transport/` | NO |
  | e2e | `test/e2e/` | NO |
  `test/integration/transport/` and `test/e2e/` filenames must NEVER name a specific protocol. Protocol-specific tests belong in `pkg/*/providers/{name}/`.

## Anti-patterns (avoid)
- Direct import of storage providers in business logic (use `pkg/storage/interfaces`).
- Mocking CFGMS components; storing cleartext secrets; duplicating TLS code (use `pkg/cert`).
- Custom cache (use `pkg/cache.Cache`); manual cert loading (use `pkg/cert.LoadTLSCertificate()`).
- Logging unsanitized input (use `logging.SanitizeLogValue()`); committing test artifacts.

## Commit / PR
- Format: `<scope>: <what changed> (Issue #XXX)`, `Fixes #XXX` in body. FACTS ONLY — claims from real measurements, not estimates.
- See `docs/development/commit-and-pr-standards.md`.

## Desired State Development (DSD)
Stories are outcome-based; done = entire system reflects desired end state (source, tests, fixtures, configs, Docker, docs, CI all updated). No "pre-existing condition" excuses — if a file blocks the desired state, it's in scope. Done = all tests pass, not "code compiles".

## Pre-GA posture
Prefer hard breaking changes over migration shims/deprecation windows.

## Docs language
No competitor analogies, no real third-party vendor names as illustrative examples (use `vendor-a`/`acme-corp`); real integrations (M365) stated as factual capabilities. No history (story numbers/dates/status) in `CLAUDE.md`.
