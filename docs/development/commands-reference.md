# CFGMS Development Commands Reference

This document provides a comprehensive reference for all CFGMS development commands. For quick daily development, see the essential commands in CLAUDE.md.

## Building

### Standard Building

```bash
# Build all binaries (current platform)
make build

# Build individual components (current platform)
make build-controller  # Builds controller binary
make build-steward     # Builds steward binary
make build-cli         # Builds cfg CLI binary
```

### Cross-Platform Builds

#### Steward Cross-Compilation

```bash
GOOS=linux GOARCH=amd64 go build -o bin/cfgms-steward-linux-amd64 ./cmd/steward
GOOS=linux GOARCH=arm64 go build -o bin/cfgms-steward-linux-arm64 ./cmd/steward
GOOS=windows GOARCH=amd64 go build -o bin/cfgms-steward-windows-amd64.exe ./cmd/steward
GOOS=windows GOARCH=arm64 go build -o bin/cfgms-steward-windows-arm64.exe ./cmd/steward
GOOS=darwin GOARCH=arm64 go build -o bin/cfgms-steward-darwin-arm64 ./cmd/steward
```

#### Controller Cross-Compilation

```bash
GOOS=linux GOARCH=amd64 go build -o bin/controller-linux-amd64 ./cmd/controller
GOOS=windows GOARCH=amd64 go build -o bin/controller-windows-amd64.exe ./cmd/controller
```

## Testing

### Basic Testing

```bash
# Run all tests with coverage and race detection
make test
# Equivalent to: go test -v -race -cover ./...

# Run specific test package
go test -v ./features/controller/
go test -v ./features/modules/

# Run single test
go test -v -run TestControllerStart ./features/controller/
```

### Streamlined Testing Workflow

#### Daily Development

```bash
# Fast TDD feedback (2-3 min) - smart unit tests
make test

# Pre-commit validation (4-6 min) - security, lint, architecture
make test-commit
```

#### Story Completion (CI Parity)

```bash
# Story completion validation (10-20 min) - MATCHES ALL CI required checks
make test-complete
```

**Test Validation Levels** (Story #315):

| Target | Time | What it Runs | When to Use |
|--------|------|--------------|-------------|
| `make test` | 2-3 min | Smart unit tests (core + changed modules) | TDD development loop |
| `make test-commit` | 4-6 min | Unit tests + lint + security + architecture | Before every commit |
| `make test-complete` | 10-20 min | **ALL CI required checks** (see below) | **Before creating PR** |
| `make test-ci` | 15-25 min | Complete CI validation with M365 | CI simulation (optional) |

**test-complete CI Parity** - Exactly matches CI required checks:
1. ✅ unit-tests job: `make test`
2. ✅ integration-tests job: `make test-fast` + `make test-production-critical`
3. ✅ cross-compile-check: `make build-cross-validate`
4. ✅ integration-tests (Docker): Storage/controller integration tests
5. ✅ security scans: trivy, nancy, gosec, staticcheck
6. ✅ E2E tests: Transport (gRPC-over-QUIC), Controller

**Only CI-only gap**: Native Windows/macOS builds (requires Windows/macOS runners)

#### Specialized Testing

```bash
# M365 + storage integration
make test-integration

# Security scanning only
make test-security

# Performance and load testing
make test-performance

# Docker environment management
make test-docker
```

#### M365 Credential Handling

- **`test`**: Uses mocked M365 tests only
- **`test-commit`**: Skips M365 tests if credentials unavailable (developer-friendly)
- **`test-ci`**: Requires M365 credentials or fails (CI enforcement)

## Security Scanning

### Security Commands

```bash
# Comprehensive security validation (BLOCKING - recommended)
make security-scan

# Non-blocking security scan (logs issues but continues)
make security-scan-nonblocking

# Quick security check for development
make security-check

# Individual security tools
make security-trivy      # Filesystem vulnerability scanning
make security-deps       # Go dependency vulnerability scanning
make security-gosec      # Go security pattern analysis
make security-staticcheck # Advanced static analysis

# Claude Code Integration (v0.3.1)
make security-remediation-report  # Generate JSON report for automated remediation

# Automatic tool installation
make install-nancy       # Cross-platform Nancy installation
```

### Security Exception Policy (gosec)

#### Configuration File (.gosec.json)

- Use ONLY for project-wide rule suppression that applies to entire codebase
- Use ONLY for excluding non-production directories (test/, examples/, vendor/)
- Use ONLY for excluding generated files (*.pb.go)
- Never exclude production code files via configuration

#### Inline Exclusions (Production Code)

- All production code security exceptions MUST use inline `#nosec` comments
- Each exclusion MUST include business justification
- Use specific rule codes (e.g., `#nosec G204`) rather than blanket exclusions
- Format: Comment must be on the line BEFORE the flagged code
- Use: `// #nosec G204 - Business justification for why this is necessary`

#### Examples

```go
// Correct - Comment before the flagged line with justification
// #nosec G204 - CMS requires script execution for configuration management
cmd := exec.Command("bash", script)

// Correct - Specific rule with context on preceding line
// #nosec G304 - User-specified config paths are validated upstream
data, err := ioutil.ReadFile(userPath)

// Correct - With detailed business context
// #nosec G115 - bounds validated above (0-0777 check)
if err := os.Mkdir(path, os.FileMode(permissions)); err != nil {

// Incorrect - Comment at end of line (gosec may not recognize)
cmd := exec.Command("bash", script) // #nosec G204 - CMS requires script execution

// Incorrect - No justification
// #nosec
cmd := exec.Command("bash", script)

// Incorrect - Should be in .gosec.json instead
// This would belong in config file for test directories
```

**Rationale**: Inline exclusions ensure future vulnerabilities in the same file are still detected, provide visibility during code review, and document security decisions at the point of implementation.

## Unified Development Validation

### Combined Commands

```bash
# Complete validation workflow (test + security + summary)
make test-with-security

# Traditional individual steps
make test
make security-scan
make lint
```

## Code Quality

### Linting

```bash
# Run linter (requires golangci-lint)
make lint
# Equivalent to: golangci-lint run
```

### Invariant Checks

```bash
# Check central provider architecture compliance (no duplicate cross-cutting concerns)
make check-architecture

# Check stdlib payload boundary: all five sources of stdlib module names must agree
# (features/modules/stdlib/ dir, Makefile, .wxs, install.sh, build-pkg.sh)
make check-stdlib-payload-boundary
```

Both checks run automatically as part of `make test-commit`.

## Protocol Buffers

### Proto Generation

```bash
# Generate Go code from proto files
make proto

# Check for required proto tools
make check-proto-tools
```

## Cleanup

### Maintenance

```bash
# Clean build artifacts and test cache
make clean
```

## Docker Integration Testing

### Docker Environment Management

```bash
# Set up Docker test environment with secure credentials
make test-integration-setup

# Clean up Docker test environment and generated credentials
make test-integration-cleanup

# Check status of Docker test services
make test-integration-status

# Run integration tests against real storage providers
make test-with-real-storage

# Test database provider specifically
make test-integration-db

# Test git provider specifically
make test-integration-git

# Complete integration testing workflow
make test-integration-complete
```

## Advanced Security Commands

### Security Workflow Optimization

```bash
# Performance optimization and metrics collection
make security-workflow-metrics

# Parallel security scan optimization
make security-scan-parallel

# Benchmark security workflow performance
make benchmark-security-workflow

# Cache optimization and analysis
make optimize-security-cache

# Team expansion preparation
make prepare-team-workflow
```

## Go-Specific Commands

### Direct Go Commands

```bash
# Run tests for specific packages
go test -v ./pkg/storage/...
go test -v ./features/controller/...

# Run tests with specific flags
go test -race -cover ./...
go test -v -run TestSpecificFunction ./...

# Build specific components
go build -o bin/controller ./cmd/controller
go build -o bin/steward ./cmd/steward
```

## Environment Variables

### Testing Environment Variables

```bash
# Database and service passwords are generated per-session.
# Run 'make test-integration-setup' to generate .env.test with secure credentials.
# NEVER use hardcoded passwords — source .env.test instead:
source .env.test

# Integration Test Control
ALLOW_SKIP_INTEGRATION=true  # Skips M365 tests if credentials unavailable
```

## Command Categories

### Daily Development Commands

These are the most commonly used commands during daily development:

- `make test` - Basic test validation
- `make test-commit` - Pre-commit validation
- `make lint` - Code quality check
- `make build` - Build all binaries
- `make clean` - Clean build artifacts

### Integration Testing Commands

For testing with external services:

- `make test-integration-setup` - Start Docker services
- `make test-with-real-storage` - Test against real backends
- `make test-integration-cleanup` - Clean up environment

### Security Commands

For security validation and remediation:

- `make security-scan` - Full security validation
- `make security-remediation-report` - Generate remediation report
- `make install-nancy` - Install security tools

### CI/CD Commands

For continuous integration and deployment:

- `make test-ci` - Full CI validation
- `make security-scan` - Security gates
- `make test-integration-complete` - Full integration testing

---

## Quick Reference

### Essential Daily Commands

```bash
make test           # Basic testing
make test-commit    # Pre-commit validation
make lint          # Code quality
make build         # Build binaries
```

### Problem-Solving Commands

```bash
make clean                    # Clean build issues
make test-integration-setup   # Fix integration test issues
make install-nancy           # Fix security tool issues
make security-remediation-report  # Get security fixes
```

### Full Validation Commands

```bash
make test-ci                 # Complete validation
make test-integration-complete  # Full integration testing
make security-scan           # Security validation
```

For automation of these commands, use the CFGMS slash commands: `/story-start`, `/story-commit`, `/story-complete`.

## Connection Management

`cfg connect` and `cfg disconnect` manage zero-standing-privilege controller sessions. The session token is stored exclusively in the OS-native secret store (macOS Keychain, Windows Credential Manager, Linux Secret Service) — never written to any file on disk.

### Authentication requirement (all commands)

Every `cfg` command that talks to the controller REST API accepts exactly two credentials — an admin mTLS bundle or an active passkey-authenticated session (`cfg connect`) — and nothing else. The `cfg` CLI has never accepted a bare API key as a matter of design intent; commands resolve a credential via, in order:

1. An active session from `cfg connect` (Bearer session token, OS keychain).
2. An admin mTLS bundle, discovered via `--bundle <path>`, `CFGMS_ADMIN_BUNDLE`, `~/.config/cfgms/admin.bundle.yaml`, or `/etc/cfgms/admin.bundle.yaml`.

If neither resolves, the command fails immediately with an error naming the required credential (`no credential found: provide an admin mTLS bundle (--bundle, CFGMS_ADMIN_BUNDLE, or the default bundle path) or an active session (run 'cfg connect' first)`) — it never silently falls back to a weaker credential.

**Migrating automation off `CFGMS_API_KEY` (Issue #3688):** earlier releases of the `cfg` binary read `CFGMS_API_KEY` as a fallback whenever a bundle was missing or a session had expired, and the command still succeeded — a silent downgrade from the credential the operator believed they were using, with no signal a weaker one had been substituted. That fallback has been removed entirely from the `cfg` binary; every `--api-key` flag it registered is gone with it. Scripts and CI jobs that previously exported `CFGMS_API_KEY` for `cfg` should export `CFGMS_ADMIN_BUNDLE=/path/to/admin.bundle.yaml` instead — an mTLS bundle is exactly as usable non-interactively (CI, cron, unattended scripts) as an API key was, just a stronger credential; this is a configuration change, not a lost capability. This does **not** affect genuine external API consumers: the controller's REST API still accepts API keys directly for callers that talk to it without going through `cfg`.

This admin mTLS bundle / session pair authenticates `cfg` itself against the controller (transport auth). It is a distinct credential from the payload-signing certificate issued by `cfg credential request-signing-cert` (below), which exists solely to sign `operatorpayload.Envelope`s — see [Signing Credential Management](#signing-credential-management). With `CFGMS_API_KEY` gone (Issue #3688), `cfg credential request-signing-cert` is the only CLI path to a signing credential; there is no `--api-key` alternative.

### cfg connect (first-time import) — bootstrap only

Import an admin bundle and start a controller session. This is the bootstrap
exception: an admin bundle is a credential whose private key the controller
itself generated and held, confined accordingly (it cannot approve a credential
enrolment or renew itself, both of which require a passkey presence assertion it
can never obtain; it is *intended* also to be unable to authorise endpoint
execution — [GAP: that requirement is not yet enforced, see Epic #3711, Story
#3696. `verifyOperatorCert` in `features/steward/commands/execute_script.go` and
the operator-signature check in `features/controller/api/handlers_runs.go` both
accept any admin-marked certificate and never require the payload-signing
marker, so a bundle can authorise endpoint execution today] — see
[ADR-021 Amendment 5](../architecture/decisions/021-identity-assurance-levels.md)).
The ordinary way to obtain a session is `cfg login`
[GAP: not yet shipped — see Epic #3711, Story #3721], a browser passkey
assertion; this bundle-import route is for the very first credential on a
controller with no account yet to log in against, or for re-running
`bootstrap-admin` to issue another one while `cfg login` is unavailable.

```bash
cfg connect --bundle /path/to/admin.bundle.yaml --url https://controller:9443
cfg connect --bundle /path/to/admin.bundle.yaml --url https://controller:9443 --name prod
```

The `--url` value must be HTTPS for any non-loopback address. On success the bundle is stored encrypted (machine-bound), a session token is issued via `POST /api/v1/sessions`, and the token is written to the OS keychain.

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--bundle` | — | Path to the admin bundle YAML (required for first-time import) |
| `--url` | — | Controller HTTPS URL (required with `--bundle`; must be HTTPS for non-loopback) |
| `--name` | derived from URL host | Human-readable connection name stored in the local registry |
| `--tls-insecure` | false | Skip TLS certificate verification (development only, env: CFGMS_TLS_INSECURE). Prints an mTLS warning banner; the session-token reconnect path requires typed confirmation (`"I understand the risk"` on a TTY, or `CFGMS_TLS_INSECURE_CONFIRM=yes` non-interactively) |
| `--server-name` | — | Override the TLS server name used for certificate verification (e.g. when dialing by IP against a cert with a hostname SAN) without disabling verification |

### cfg connect (reconnect)

Re-use a previously registered connection without re-importing the bundle.

```bash
# Reconnect by name
cfg connect prod

# Auto-select when exactly one connection is registered
cfg connect

# Interactive numbered selection when multiple connections are registered
cfg connect
```

The encrypted bundle is unlocked with the machine-bound key, a new session token is issued, and the token replaces the previous entry in the OS keychain.

### cfg disconnect

Revoke the active session and remove its token from the OS keychain.

```bash
cfg disconnect
```

Sends `DELETE /api/v1/sessions/{id}` to the controller (best-effort — proceeds even on network error), then removes the token from the OS keychain. Exits 0 with a notice when no active session is found.

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--tls-insecure` | false | Skip TLS certificate verification (development only, env: CFGMS_TLS_INSECURE). Requires typed confirmation (`"I understand the risk"` on a TTY, or `CFGMS_TLS_INSECURE_CONFIRM=yes` non-interactively) since the revoke call carries the session's bearer token |
| `--server-name` | — | Override the TLS server name used for certificate verification without disabling verification |

### cfg connections current

Show the active session from the OS keychain.

```bash
cfg connections current
```

Prints the connection name, controller URL, session ID, and absolute expiry. Prints `no active session` and exits 0 when no valid session is stored.

### Session lifecycle and rolling renewal

After `cfg connect`, all admin commands transparently use the stored session token (Bearer auth). The controller sets an `X-Session-Token` response header on each authenticated request; the CLI automatically writes the new token back to the OS keychain, keeping sessions alive without explicit re-authentication.

When the token is revoked server-side (401 response), the CLI falls back to bundle auth and prints `session expired or revoked — falling back to bundle auth` on stderr.

Use `--bundle` or `--no-bundle` on any command to bypass the session entirely for one-shot overrides.

---

The `cfg connections` commands manage the local registry of known controller connections. The registry stores non-secret metadata only — no credentials, tokens, or keys are ever written to this file.

Registry location:

| Platform | Path |
|----------|------|
| Linux | `$XDG_CONFIG_HOME/cfgms/connections.json` |
| macOS | `~/Library/Application Support/cfgms/connections.json` |
| Windows | `%APPDATA%\cfgms\connections.json` |

File permissions: directory at `0700`, `connections.json` at `0600`.

### cfg connections list

List all registered controller connections.

```bash
# Print a table of known connections (name, URL, identity, last-used)
cfg connections list

# Emit a JSON array
cfg connections list --json
```

When no connections are registered, exits 0 and prints:

```
No connections configured.
```

**Flags:**

| Flag | Description |
|------|-------------|
| `--json` | Emit a JSON array instead of a human-readable table |

## Signing Credential Management

`cfg credential` subcommands manage payload-signing credentials — a purpose distinct
from the mTLS admin bundle covered under [Connection Management](#connection-management).

### cfg credential request-signing-cert (Issue #3693)

Generate an ECDSA P-256 keypair locally and request a signed payload-signing
certificate from the controller. This is the primary — and, since `CFGMS_API_KEY`
was removed (Issue #3688), the only — CLI path to a signing credential: there is no
`--api-key` alternative.

```bash
cfg credential request-signing-cert

cfg credential request-signing-cert \
  --cert-out ~/.config/cfgms/signing-cert.pem

# Development only: also drop an unencrypted copy of the key on disk
cfg credential request-signing-cert --export-plaintext-key --key-out ./dev-signing-key.pem
```

The private key is generated on the operator's machine and never transmitted —
only the PEM-encoded public key crosses the wire, in a `POST
/api/v1/signing-credential/request` request body that carries no other field. The
controller signs the submitted public key (never generating or seeing a private
key for it) and returns a certificate carrying the CFGMS payload-signing marker —
not the admin marker used by mTLS transport bundles, so the two credential types
remain distinguishable by construction. The resulting keypair signs
`operatorpayload.Envelope`s (a future `cfg payload sign` command); it is never
used for mTLS session authentication.

The endpoint is gated by the `signing-credential:request` permission at
`AssuranceStrong` plus a fresh user-presence proof, so this command requires an
authenticated admin mTLS bundle or session (see [Connection
Management](#connection-management)) and completes a WebAuthn presence ceremony —
the CLI opens a browser automatically when one is needed, the same flow used by
other presence-gated commands.

**Where the private key is kept:** the generated key is stored encrypted at rest in
the machine-bound credential store — `<user config dir>/cfgms/credentials/signing-key.enc`,
the same store `cfg connect` uses for the admin bundle's private key — not as a
cleartext PEM file. Mode 0600 alone is access control, not encryption at rest: it
does not protect the key from another process running as the operator, from a
backup, or from a cloud-synced config directory. Only the certificate, which
carries no secret, is written to `--cert-out`.

A cleartext export is available for development interop, but only on explicit
opt-in: `--key-out` without `--export-plaintext-key` is refused with an error
rather than silently writing an unencrypted key. With the opt-in, the encrypted
copy is still written, the export is mode 0600, and the command prints a warning
naming the exported path.

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--cert-out` | `<user config dir>/cfgms/signing-cert.pem` | Path to write the issued certificate PEM (mode 0600) |
| `--credential-name` | `signing-key` | Name the encrypted signing key is stored under in the credential store |
| `--export-plaintext-key` | false | Also export the private key as a cleartext PEM (development only); required to use `--key-out` |
| `--key-out` | `<user config dir>/cfgms/signing-key.pem` | Path for the cleartext key export; ignored unless `--export-plaintext-key` is passed, and an error if passed without it |
| `--api-url` | — | Controller REST API URL (env: `CFGMS_API_URL`) |
| `--tls-insecure` | false | Skip TLS certificate verification (development only, env: `CFGMS_TLS_INSECURE`) |
| `--server-name` | — | Override the TLS server name used for certificate verification |

## Enrolment Tokens and the Pending Credential-Request Queue (Issue #3717)

Story #3717 (Epic #3711 — browser-authenticated CLI enrolment) adds the first half of
zero-custody operator enrolment: an administrator mints a short-lived, single-use
enrolment token and hands it to a machine out of band (e.g. read over a phone call, or
pasted into a terminal). That machine, holding no certificate yet, spends the token to
lodge a certificate signing request carrying only a public key. The request lands in a
durable pending queue that administrators can list and deny. **This story issues no
certificate, binds no account, and collects no credential** — those are the next two
stories in the epic. There is no `cfg` CLI command yet; the endpoints below are REST-only
until that follow-on work lands.

### Minting and revoking an enrolment token

```
POST /api/v1/enrolment-tokens
{"tenant_id": "root/msp-a/client-1"}
```

Requires the `enrolment-token:mint` permission at `AssuranceStrong` (mTLS admin bundle or
a stepped-up web/CLI session — see [Connection Management](#connection-management)).
`tenant_id` is required; a tenant-scoped caller may only mint within its own subtree. The
response includes the raw token value **exactly once**:

```json
{
  "data": {
    "id": "et-<uuid>",
    "token": "<64-char hex — shown only here>",
    "token_prefix": "a1b2c3",
    "tenant_id": "root/msp-a/client-1",
    "created_at": "2026-08-28T10:00:00Z",
    "expires_at": "2026-08-28T11:00:00Z",
    "revoked": false
  }
}
```

Hand the `token` value to the enrolling machine out of band. It is single-use — spent the
moment a lodge succeeds against it, whether or not the resulting request is ever
approved — and expires on its own an hour after minting. Only `token_prefix` (its first 6
characters) is ever shown again, in logs or elsewhere; the full value cannot be retrieved
after this response.

To revoke an unspent token before it is used:

```
POST /api/v1/enrolment-tokens/{id}/revoke
```

Requires `enrolment-token:revoke` at `AssuranceStrong`. A token that has already been
spent cannot be revoked (409) — its one use is already consumed.

### Lodging a signing request

```
POST /api/v1/credential-requests/lodge
Authorization: Bearer <enrolment token>
{"csr_pem": "-----BEGIN CERTIFICATE REQUEST-----...", "hostname": "laptop-01", "label": "sales laptop", "platform": "linux", "purpose": "cli enrolment"}
```

This is the one endpoint in the epic that carries no API key, mTLS certificate, or web
session — only the enrolment token as a bearer credential, exactly as `POST
/api/v1/register` is unauthenticated by design. An absent, unknown, revoked, expired, or
already-spent token all return `401` with an identical body, so no response ever
discloses which of those five conditions applied.

`csr_pem` must be a single PEM `CERTIFICATE REQUEST` block whose own signature verifies
against the public key it carries; a body that also contains any private-key PEM block is
rejected outright. `hostname`, `label`, `platform`, and `purpose` are display-only text —
they are never trusted for any authorization decision, and no caller-supplied field (a
`tenant_id`, `permission`, `account`, or similar claim slipped into the body) has any
effect: the tenant is always derived from the token record.

On success the response is returned **once**:

```json
{
  "data": {
    "request_id": "cr-<uuid>",
    "public_key_fingerprint": "<64-char hex SHA-256 over the public key>",
    "public_key_fingerprint_short": "AB12-CD34-EF56-7890",
    "collect_secret": "<64-char hex — shown only here>",
    "expires_at": "2026-08-28T11:00:00Z"
  }
}
```

`public_key_fingerprint_short` is a deterministic function of the public key alone — the
enrolling machine can compute and print the same value locally, so an administrator
reviewing the pending queue can visually match what is on screen against what the machine
printed before approving. `collect_secret` is consumed by a later story; only its hash is
persisted here.

Lodge is rate limited per source address and bounded by a per-tenant outstanding-pending
cap: once a tenant's queue is full, further lodges are refused (`503`) rather than
evicting older entries — the cap is a ceiling, not a queue-flush primitive.

### Listing and denying pending requests

```
GET /api/v1/credential-requests
```

Requires `credential-request:list`. Returns pending requests scoped to the caller's
tenant subtree (an unscoped mTLS admin sees all), including the fingerprint, its short
comparable form, source address, requested purpose, and expiry — never the CSR, the
collect-secret hash, or which token lodged it.

```
POST /api/v1/credential-requests/{id}/deny
{"reason": "unrecognized device"}
```

Requires `credential-request:deny`. Denial is terminal: a denied request can never later
be approved or collected, and denying it twice returns `409`.

### Expiry

Both unspent enrolment tokens and pending requests expire on a one-hour lifetime and are
removed by a background sweep that runs independently of any read — an expired record is
not merely hidden on the next list call, it is deleted. Spent tokens and denied requests
are left in place; the sweep only removes records that are still live but past their
expiry.

### Permissions

| Permission | Assurance floor | Notes |
|------------|------------------|-------|
| `enrolment-token:mint` | `AssuranceStrong` | Mints a single-use, short-lived token |
| `enrolment-token:revoke` | `AssuranceStrong` | Revokes an unspent token |
| `credential-request:list` | none | Read-only; outside the elevated-assurance surface |
| `credential-request:deny` | none | De-escalation action, mirrors `registration:deny` |

## Workflow Management

`cfg workflow` subcommands manage workflow definitions and their executions on the controller.

### cfg workflow list

List all workflow definitions registered on the controller.

```bash
cfg workflow list --url=https://controller.example.com
cfg workflow list --url=https://controller.example.com --bundle=/path/to/admin.bundle.yaml
```

Prints a plain-text table with columns: NAME, VERSION, STEPS.

Example output:

```
NAME         VERSION  STEPS
deploy-ring  1.2.0    4
sync-entra   2.0.0    7
```

When no workflows are registered, exits 0 and prints:

```
No workflows registered.
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--url` | — | Controller API URL (required) |
| `--tls-ca-cert` | — | Path to CA certificate for TLS verification (env: CFGMS_TLS_CA_CERT) |
| `--tls-insecure` | false | Skip TLS verification (development only, env: CFGMS_TLS_INSECURE) |
| `--server-name` | — | Override TLS server name for certificate verification |

### cfg workflow status

Show the status of a single workflow execution.

```bash
cfg workflow status <execution-id> --workflow <name> --url=https://controller.example.com
```

The `<execution-id>` is returned by `cfg workflow run`.

Example output:

```
execution_id:  exec_1782879897336049056_1
workflow:      deploy-ring
status:        running
current_step:  step-canary
started_at:    2026-07-01T10:00:00Z
error:         -
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--workflow` | — | Workflow name (required) |
| `--url` | — | Controller API URL (required) |
| `--tls-ca-cert` | — | Path to CA certificate for TLS verification (env: CFGMS_TLS_CA_CERT) |
| `--tls-insecure` | false | Skip TLS verification (development only, env: CFGMS_TLS_INSECURE) |
| `--server-name` | — | Override TLS server name for certificate verification |

### cfg workflow cancel

Cancel a running workflow execution.

```bash
cfg workflow cancel <execution-id> --workflow <name> --url=https://controller.example.com
```

Returns an error if the execution is already in a terminal state (completed, failed, or cancelled).

On success:

```
Cancelled execution exec_1782879897336049056_1
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--workflow` | — | Workflow name (required) |
| `--url` | — | Controller API URL (required) |
| `--tls-ca-cert` | — | Path to CA certificate for TLS verification (env: CFGMS_TLS_CA_CERT) |
| `--tls-insecure` | false | Skip TLS verification (development only, env: CFGMS_TLS_INSECURE) |
| `--server-name` | — | Override TLS server name for certificate verification |

### cfg workflow promote-hv-role

Promote a Hyper-V VM from standalone to Failover Cluster role by submitting the
embedded `promote-hv-role` workflow template with the resolved steward and cluster.

```bash
cfg workflow promote-hv-role <vmname> <host-selector> [--cluster <name>] --url=https://controller.example.com
```

`<host-selector>` uses the same grammar as `cfg steward` commands — see
`docs/administration/cli-selectors.md` for the full reference. The selector
**must resolve to exactly one steward**; a selector matching zero or more than
one is always a hard error, never a silent pick. Use a tenant-path prefix or
`id:<steward-id>` to disambiguate across tenants that share a hostname.

When the resolved host belongs to exactly one cluster, `--cluster` is optional.
When it belongs to more than one cluster, `--cluster` is required to name which
cluster the VM should be promoted into.

On success, prints the execution ID and status, which can be observed with:

```bash
cfg workflow status <execution-id> --workflow promote-hv-role --url=https://controller.example.com
```

Example output:

```
Workflow submitted: promote-hv-role
Execution ID: exec_1782879897336049056_1
Status: running
```

**Disambiguating across tenants (multi-cluster case):**

```bash
# Unambiguous single-tenant host with one cluster:
cfg workflow promote-hv-role MyVM hv01 --url=https://controller.example.com

# Multi-tenant environment — use tenant path to pin the correct steward:
cfg workflow promote-hv-role MyVM acme-corp/hv01 --url=https://controller.example.com

# Host in multiple clusters — specify which cluster:
cfg workflow promote-hv-role MyVM hv01 --cluster fc-east --url=https://controller.example.com
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--cluster` | — | Cluster name (required only when the host belongs to more than one cluster) |
| `--url` | — | Controller API URL (required) |
| `--tls-ca-cert` | — | Path to CA certificate for TLS verification (env: CFGMS_TLS_CA_CERT) |
| `--tls-insecure` | false | Skip TLS verification (development only, env: CFGMS_TLS_INSECURE) |
| `--server-name` | — | Override TLS server name for certificate verification |

---

## cfg reboot-window — Reboot Window Authoring (Issue #2979)

A reboot_window constrains when managed endpoints may reboot during patch cycles.
It is declared at tenant level (inherited by all stewards in that tenant) or
overridden at the device level for a specific steward.

The schedule YAML is validated server-side by `schedule.Parse()`. The GET endpoint
returns the full cascaded effective value including the resolved next occurrence; it
never returns a raw cron rule.

**Required permissions:** `reboot_window:override` (PUT), `reboot_window:read` (GET).
These are distinct from `config.update` (ADR-026 decision 3).

**Common flags:**
```
--url <url>              Controller API URL (env: CFGMS_API_URL)
--bundle <path>          Admin mTLS bundle path (env: CFGMS_ADMIN_BUNDLE)
--tls-ca-cert <path>     CA certificate path (env: CFGMS_TLS_CA_CERT)
--tls-insecure           Skip TLS verification (env: CFGMS_TLS_INSECURE)
--server-name <name>     Override TLS server name for certificate verification
--tenant <id>            Target tenant ID
--steward <id>           Target steward ID
```

### cfg reboot-window set

Set the reboot_window at tenant or device level. Exactly one of `--tenant` or
`--steward` must be specified. The schedule file must be a valid reboot_window
YAML block.

```
cfg reboot-window set --tenant <tenant-id> --schedule <file.yaml> [--timezone <tz>]
cfg reboot-window set --steward <steward-id> --schedule <file.yaml>
```

**Example schedule YAML (`window.yaml`):**
```yaml
schedules:
  - freq: weekly
    days: [sunday]
    start: "02:00"
    end: "04:00"
```

**Example:**
```
cfg reboot-window set --tenant acme-corp --schedule window.yaml --timezone America/New_York
```

**Output:**
```
Reboot window updated
Target:  acme-corp
Status:  scheduled
Next:    Sun 17 Aug 2026, 02:00 (America/New_York)
Next (ISO-8601): 2026-08-17T06:00:00Z
Timezone: America/New_York
```

### cfg reboot-window show

Display the effective reboot_window including the resolved next occurrence. The
result reflects the full cascade (MSP → client → group → device); if no window
is declared at any level the status is `unrestricted`.

```
cfg reboot-window show --tenant <tenant-id>
cfg reboot-window show --steward <steward-id>
```

**Example:**
```
cfg reboot-window show --steward sw-1234
```

**Output (window in effect):**
```
Target:  sw-1234
Status:  scheduled
Next:    Sun 17 Aug 2026, 02:00 (America/New_York)
Next (ISO-8601): 2026-08-17T06:00:00Z
```

**Output (no window):**
```
Target:  sw-1234
Status:  unrestricted
Next:    no reboot_window in effect — unrestricted
```

---

## cfg role — Role Config Management (Issue #2543)

Role configs couple a selector expression with a `StewardConfig` fragment. Matching
stewards receive the fragment merged into their effective config during resolution (S4).
Role configs are stored under the `role-policies` ConfigStore namespace and are tenant-scoped.

**Required permissions:** `role:read` (GET), `role:write` (POST, DELETE).

### cfg role create

Create a role config with a selector and a StewardConfig fragment.

```bash
cfg role create <name> --selector "<expr>" --config <fragment.yaml> --url=https://controller.example.com
```

The fragment file is a YAML file containing a partial `StewardConfig`. The steward ID
field is not required — leave it empty for role config fragments.

Example:

```bash
cfg role create github-runners \
  --selector "os:windows tag:github-runner" \
  --config runner-fragment.yaml \
  --url=https://controller.example.com --bundle=/path/to/admin.bundle.yaml
```

Output on success:

```
Created role config "github-runners" (selector: os:windows tag:github-runner)
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--selector` | — | Fleet selector expression (required) |
| `--config` | — | Path to StewardConfig fragment YAML file (required) |
| `--url` | — | Controller API URL (env: CFGMS_API_URL) |
| `--tls-ca-cert` | — | Path to CA certificate (env: CFGMS_TLS_CA_CERT) |
| `--tls-insecure` | false | Skip TLS verification (env: CFGMS_TLS_INSECURE) |
| `--server-name` | — | Override TLS server name for certificate verification |

### cfg role ls

List all role configs for the authenticated tenant.

```bash
cfg role ls --url=https://controller.example.com
```

Example output:

```
NAME             SELECTOR                        CREATED BY
----             --------                        ----------
github-runners   os:windows tag:github-runner    ops-admin
debug-nodes      tag:debug                       ops-admin
```

**Flags:** `--url`, `--tls-ca-cert`, `--tls-insecure`, `--server-name` (same as above).

### cfg role show

Display a role config including its selector and fragment.

```bash
cfg role show <name> --url=https://controller.example.com
```

**Flags:** `--url`, `--tls-ca-cert`, `--tls-insecure`, `--server-name` (same as above).

### cfg role delete

Delete a role config by name.

```bash
cfg role delete <name> --url=https://controller.example.com
```

Returns an error if the role config does not exist.

Output on success:

```
Deleted role config "github-runners"
```

**Flags:** `--url`, `--tls-ca-cert`, `--tls-insecure`, `--server-name` (same as above).

## cfg steward tag — Steward Tag Management (Issue #2545)

Tags are operator-assigned metadata on a steward used by `tag:` selectors in role configs
and fleet commands. Tags are controller-owned: they survive controller restarts and are
never overwritten by the steward's DNA report cycle.

**Tag format:** lowercase alphanumeric, optionally separated by hyphens (1–64 chars).
Examples: `prod`, `web-server`, `github-runner`.

**Required permissions:** `steward:tag:read` (GET), `steward:tag:write` (POST, DELETE).

### cfg steward tag add

Add one or more tags to a steward. Adding a tag that already exists is a no-op (idempotent).

```bash
cfg steward tag add <steward-id> <tag> [tag...] --url=https://controller.example.com --bundle=/path/to/admin.bundle.yaml
```

Example:

```bash
cfg steward tag add steward-abc123 prod web-server \
  --url https://controller.example.com --bundle /path/to/admin.bundle.yaml
```

Output on success:

```
Tags on steward-abc123: prod, web-server
```

### cfg steward tag rm

Remove one or more tags from a steward. Removing a tag that does not exist is a no-op (idempotent).

```bash
cfg steward tag rm <steward-id> <tag> [tag...] --url=https://controller.example.com --bundle=/path/to/admin.bundle.yaml
```

Output on success:

```
Tags on steward-abc123: prod
```

### cfg steward tag ls

List all operator-assigned tags on a steward.

```bash
cfg steward tag ls <steward-id> --url=https://controller.example.com --bundle=/path/to/admin.bundle.yaml
```

Example output:

```
TAG
---
prod
web-server
```

**Flags (all sub-commands):**

| Flag | Default | Description |
|------|---------|-------------|
| `--url` | — | Controller API URL (env: CFGMS_API_URL) |
| `--tls-ca-cert` | — | Path to CA certificate (env: CFGMS_TLS_CA_CERT) |
| `--tls-insecure` | false | Skip TLS verification (env: CFGMS_TLS_INSECURE) |
| `--server-name` | — | Override TLS server name for certificate verification |

## cfg webauthn — Passkey Bootstrap and Recovery (Issue #2783)

Manage WebAuthn passkeys for browser-based controller login. All subcommands require
a valid admin bundle (mTLS certificate) — Bearer session tokens are rejected. This
is an ADR-021 §7 invariant: the cert-authenticated path is the only path for passkey
bootstrap and recovery, preventing a password/email-based downgrade attack.

**Authentication requirement:** The admin bundle must be discoverable via one of:
- `--bundle <path>` flag
- `CFGMS_ADMIN_BUNDLE` environment variable
- `~/.config/cfgms/admin.bundle.yaml` (user config dir)
- `/etc/cfgms/admin.bundle.yaml` (system path)

Run `cfg connect` to generate and install an admin bundle.

### cfg webauthn register

Registers a new WebAuthn passkey for a web account. Opens the system browser to
complete the authenticator ceremony; the browser must be able to reach the controller's
configured RPID origin.

```
cfg webauthn register --username <user> [--label <name>] [--bundle <path>]
```

Example:

```
cfg webauthn register --username alice --label "YubiKey 5C"
# Requesting WebAuthn registration challenge from controller...
# Opening browser at http://127.0.0.1:52341/register
# ...
# Passkey registered successfully!
#   Username:      alice
#   Label:         YubiKey 5C
#   Registered at: 2026-07-19T22:00:00Z
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--username` | — | Account username (required) |
| `--label` | — | Human-readable label for the credential |
| `--bundle` | auto | Path to admin bundle file (env: CFGMS_ADMIN_BUNDLE) |
| `--api-url` | bundle URL | Override controller URL |
| `--timeout` | 5m | Browser ceremony timeout |

### cfg webauthn list

Lists all WebAuthn credentials registered to an account.

```
cfg webauthn list --username <user> [--bundle <path>] [--json]
```

Example:

```
cfg webauthn list --username alice
# WebAuthn credentials for alice (2):
#
#   [1] ID:    6xrtBhJQW6QU4t...
#       Label: YubiKey 5C
#       Registered: 2026-07-01T00:00:00Z
#
#   [2] ID:    Y3JlZGVudGlhb...
#       Registered: 2026-07-10T00:00:00Z
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--username` | — | Account username (required) |
| `--bundle` | auto | Path to admin bundle file (env: CFGMS_ADMIN_BUNDLE) |
| `--api-url` | bundle URL | Override controller URL |
| `--json` | false | Output as JSON |

### cfg webauthn revoke

Removes a WebAuthn credential from an account. Requires `--force` when revoking the
last credential (the mTLS admin certificate remains valid for CLI access regardless
of WebAuthn credential count, per ADR-021 §7).

```
cfg webauthn revoke <credential-id> --username <user> [--force] [--bundle <path>]
```

Example (non-last credential):

```
cfg webauthn revoke Y3JlZGVudGlhbC1pZC0x --username alice
# Credential revoked: Y3JlZGVudGlhbC1pZC0x
```

Example (last credential, requires `--force`):

```
cfg webauthn revoke Y3JlZGVudGlhbC1pZC0x --username alice --force
# Warning: revoking the last WebAuthn credential for alice.
# Browser login will require a new passkey registration via 'cfg webauthn register'.
#
# Credential revoked: Y3JlZGVudGlhbC1pZC0x
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--username` | — | Account username (required) |
| `--force` | false | Required when revoking the last credential |
| `--bundle` | auto | Path to admin bundle file (env: CFGMS_ADMIN_BUNDLE) |
| `--api-url` | bundle URL | Override controller URL |

## cfg account — Account Lifecycle and Certificate Credentials (Issue #3582)

Manage web-admin account lifecycle and bound mTLS certificate credentials.
Account commands call the `/api/v1/accounts` REST endpoints. Certificate binding
commands call the `/api/v1/accounts/{username}/certs` endpoints.

Authentication is resolved via the standard session-or-bundle chain (same as all
other `cfg` commands). The server enforces the required permission on each verb.

### cfg account create

Creates a new web-admin account, or resets an existing one (upsert). On creation
a single-use enrollment magic link is printed once for the admin to share with the
account holder via a secure channel.

```
cfg account create --username <u> [--tenant-id <t> | --root-scope] [--permission <p>]... [--json]
```

Example:

```
cfg account create --username alice --tenant-id acme-corp
# Account provisioned: alice
#   ID:      <uuid>
#   Tenant:  acme-corp
#   ...
#   Enrollment link: deadbeef...
#   (shown once — share with the account holder via a secure channel)
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--username` | — | Account username (required) |
| `--tenant-id` | — | Scope account to this tenant |
| `--root-scope` | false | Grant cross-tenant root scope (mutually exclusive with `--tenant-id`) |
| `--permission` | — | Permission to grant (repeatable) |
| `--json` | false | Output as JSON (includes the enrollment link) |
| `--api-url` | env/bundle | Override controller URL |

### cfg account list

Lists all web-admin accounts visible to the caller's tenant scope.

```
cfg account list [--json]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--json` | false | Output as JSON |
| `--api-url` | env/bundle | Override controller URL |

### cfg account get

Gets account identity and status for a single web-admin account. Returns
`tenant_id`, `root_scope`, `permissions`, `disabled` state, and whether an
outstanding enrollment link exists.

```
cfg account get <username> [--json]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--json` | false | Output as JSON |
| `--api-url` | env/bundle | Override controller URL |

### cfg account update

Updates account permissions and/or disabled state. All flags are optional —
omitted flags retain existing values.

```
cfg account update <username> [--permission <p>]... [--disabled=true|false] [--json]
```

Example:

```
cfg account update alice --disabled=true
cfg account update alice --permission account:list --permission account:get
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--permission` | — | Permissions to set (repeatable; replaces the full existing set) |
| `--disabled` | — | Set disabled state: `true` or `false` |
| `--json` | false | Output as JSON |
| `--api-url` | env/bundle | Override controller URL |

### cfg account delete

Deletes a web-admin account via the offboarding cascade: disable → revoke bound
certificates → revoke sessions → delete. Requires `--force` or interactive
confirmation (mirrors `cfg webauthn revoke`).

```
cfg account delete <username> [--force]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--force` | false | Skip confirmation prompt |
| `--api-url` | env/bundle | Override controller URL |

### cfg account bind-cert

Binds an mTLS certificate serial to a web-admin account. A serial can be bound
to at most one account at a time.

```
cfg account bind-cert <username> --serial <s> [--label <l>] [--fingerprint <f>]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--serial` | — | Certificate serial number (required; 1-40 alphanumeric chars) |
| `--fingerprint` | — | Certificate fingerprint (optional; stored for audit correlation) |
| `--label` | — | Human-readable label for the binding |
| `--api-url` | env/bundle | Override controller URL |

### cfg account certs

Lists all mTLS certificate bindings for a web-admin account.

```
cfg account certs <username> [--json]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--json` | false | Output as JSON |
| `--api-url` | env/bundle | Override controller URL |

### cfg account revoke-cert

Revokes an mTLS certificate via the controller CA and removes its binding.
This is irreversible — the certificate is added to the CRL. Requires `--force`
or interactive confirmation.

```
cfg account revoke-cert <username> <serial> [--force]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--force` | false | Skip confirmation prompt |
| `--api-url` | env/bundle | Override controller URL |

### cfg account rotate-cert

Atomically binds a new certificate serial and revokes the old one in a single
resumable operation. Safe to retry if interrupted — a repeated call with the
same arguments completes the rotation without a second bind or revocation.

Rotation revokes the old serial through the CA, so it is irreversible in the
same way `revoke-cert` is and takes the same guard: `--force` or interactive
confirmation.

```
cfg account rotate-cert <username> <old_serial> --new-serial <s> [--force]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--new-serial` | — | New certificate serial number (required) |
| `--fingerprint` | — | New certificate fingerprint (optional; for audit) |
| `--force` | false | Skip confirmation prompt |
| `--api-url` | env/bundle | Override controller URL |

## Step-Up Authentication (ADR-021 Decision 6)

Certain mutating admin commands require an elevated assurance level or a fresh
user-presence assertion. When `cfg` receives a `401 WWW-Authenticate: CFGMS-StepUp`
response, it distinguishes two cases:

### Interactive terminal

When running interactively (stdin is a TTY):

- **Presence required** (`presence="required"` in the header): `cfg` opens the
  system browser to a local relay page and prompts for a security key touch. After
  the WebAuthn assertion completes, the original request is automatically retried
  with `X-Presence-Token`. No flags or re-invocation are needed.

- **Assurance too low** (no `presence="required"`): `cfg` fails with an actionable
  message directing the operator to use an mTLS-authenticated session or log in via
  the web UI to elevate the session. The in-flight session assurance level cannot be
  upgraded programmatically.

### Non-interactive (CI, scripts)

When stdin is not a TTY, `cfg` fails immediately with:

```
step-up required: <level> assurance needed for this action; re-run interactively or use an mTLS-authenticated session
```

`cfg` never blocks waiting for input it cannot receive. Scripts that call mutating
admin commands should use an mTLS-authenticated session (admin bundle) or run the
command interactively to handle step-up challenges.

**Detecting the error in scripts:** The exit code is non-zero and the error text
contains `"step-up required"`. Example:

```bash
cfg module approve acme/linux abc123 2>&1 | grep "step-up required" && \
  echo "Re-run interactively or use an mTLS bundle"
```
