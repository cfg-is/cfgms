# Architecture

## Central Provider System (enforced by `make check-architecture`)
"Provider"/"plugin"/"pluggable" = this backend pattern ONLY (distinct from Modules).
Rules:
1. Functionality needed by >1 feature MUST use/become a central provider.
2. New providers pluggable by default — define contract in an `interfaces/` subdir.
3. Extend existing providers, don't create overlapping code. Never create a new central provider in agent mode — extend or flag for human review.

Pluggable providers: `pkg/storage`, `pkg/logging`, `pkg/secrets`, `pkg/directory` (M365/AD), `pkg/controlplane` (gRPC), `pkg/dataplane` (gRPC).
Direct providers: `pkg/cert`, `pkg/telemetry`, `pkg/cache`, `pkg/session`, `pkg/registration`, `pkg/monitoring`, `pkg/maintenance`, `pkg/security`, `pkg/ha`.
Utilities (NOT providers): `pkg/config`, `pkg/testing`, `pkg/testutil`, `pkg/version`, `pkg/audit`.
Decision tree: `pkg/README.md`.

## Storage
- All business logic imports `pkg/storage/interfaces` ONLY — never import `pkg/storage/providers/*` directly (anti-pattern, gated).
- Default backend: Git + SOPS encryption. Write-through caching (memory → durable). No memory-only storage for durable features.

## Certificates / mTLS
- `pkg/cert.Manager` owns all cert ops (see `pkg/cert/manager.go`). Controllers auto-gen CA+certs on first boot.
- Use `pkg/cert.LoadTLSCertificate()` — never manual cert loading. Don't duplicate TLS code.
- Tests use auto-generated certs (never static test certs).
- mTLS required for all internal gRPC-over-QUIC.

## Modules (distinct from providers — never use "plugin" terminology)
Unit of resource management; out-of-process gRPC binaries, publisher-signed bundles (ADR-006). One kind per module via `executors:` in `module.yaml`:
- steward modules (manage own host), outpost modules (remote LAN devices), workflow modules (controller engine vs cloud APIs). Cross-kind unsupported.
- Trust: `steward.cfg` `module_trust.mode` = strict | controller(default) | bypass(dev). End-to-end signing — controller never strips/re-signs. Publisher identity baked into steward binary at build time.
- Stdlib (`file`,`service`,`package`,`script`,`firewall`,`patch`) ships in installer using same contract (governance, never compiled-in).
- 4 steward execution paths: modules / scripts (`<interpreter> -File <path>`) / inline `cfg` CLI (mTLS-signed) / remote shell.
- BANNED in modules+scripts: `iex`/`Invoke-Expression`, `powershell -Command`/`-EncodedCommand`/`-ExecutionPolicy Bypass`, `bash -c "<string>"`, `eval`, `python -c`, any runtime code composition.

## Operating model docs (read before steward/controller behavior changes)
- `docs/architecture/operating-model.md`, `steward-operating-model.md`, `controller-operating-model.md`.
- ADRs in `docs/architecture/decisions/` (e.g. 006 module packaging, 008 durable execution substrate).

## Multi-tenancy
Recursive parent-child tenants, arbitrary depth, path-based IDs (`root/msp-a/client-1/servers`); inheritance resolves root→leaf. All code AGPL-3.0; single-root vs multi-root is architectural, not a license boundary.

## Security specifics
- Parameterized SQL only; validate/sanitize all user input; no info disclosure in errors.
- `logging.SanitizeLogValue()` for HTTP params/URL paths/headers (anti-pattern to log unsanitized input).
- CodeQL FPs: extend in-repo pack `.github/codeql/extensions/` (published to ghcr.io by `codeql-pack-publish.yml`; local-path packs unsupported; NOT the upstream github/codeql repo). Custom sanitizers use `barrierModel` (2.25.2+), not summaryModel.
