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
The ordinary way to obtain a session is `cfg login` (Issue #3721), a browser
passkey assertion — see below; this bundle-import route is for the very first
credential on a controller with no account yet to log in against, or for
re-running `bootstrap-admin` to issue another operator bundle.

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
`operatorpayload.Envelope`s; it is never used for mTLS session authentication.

**Consumers (Issue #3696):** `cfg steward run-command` and `cfg steward exec` sign
the inline command's operator envelope with this credential — loaded from the
credential store (`--credential-name`, default `signing-key`) and the certificate
at `CFGMS_SIGNING_CERT` or the default `--cert-out` path above. Neither command
reads the admin bundle's key for this signature: the admin bundle (or an active
session) is still required to authenticate the API connection itself, but the
controller never holds the payload-signing private key at any point — the
zero-custody property this credential exists for is enforced end-to-end only once
these commands stop accepting an admin-bundle-signed envelope, which this story
completes. Run `cfg credential request-signing-cert` once per operator machine
before using either command; a missing credential fails fast with an error naming
the command to run.

The endpoint is gated by the `signing-credential:request` permission at
`AssuranceStrong` plus a fresh user-presence proof, so this command requires an
authenticated admin mTLS bundle or session (see [Connection
Management](#connection-management)). CLI-driven presence assertion is not
currently supported (see [Step-Up Authentication](#step-up-authentication-adr-021-decision-6)),
so this command fails fast with an actionable error when the controller demands a
presence gesture — complete the presence-gated action from the controller web UI
instead.

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
durable pending queue that administrators can list and deny. Story #3718 adds the
approval decision, and story #3719 adds the single-use collect call that signs the
certificate and binds it to an account. Story #3720 (below) adds the `cfg` CLI commands
that drive both halves — minting/revoking from the administrator's workstation, and the
headless machine's own enrolment. Story #3721 (below) adds the interactive
counterpart, `cfg login`: no token to hand out of band, no certificate to mint — an
operator with a browser completes a passkey login and the CLI ends with a session.
Story #3724 (below) adds a further CLI command, `cfg credential renew`, for the step
after collection: keeping an already-issued credential current without a human
present. The REST reference for every endpoint these commands call follows the CLI
sections.

### cfg credential enrolment-token mint / revoke (Issue #3720)

Run by the **administrator**, from an already-authenticated workstation (an admin mTLS
bundle or an active session — see [Connection Management](#connection-management)).

```bash
cfg credential enrolment-token mint --tenant-id root/msp-a/client-1
```

Mints a single-use, one-hour token and prints the raw value **exactly once** — it cannot
be retrieved again afterward, only its non-secret prefix (in a future list command, or
in audit events). Hand that value to the enrolling machine out of band, then have its
operator run `cfg credential enrol` there. Requires `enrolment-token:mint` at
`AssuranceStrong`.

```bash
cfg credential enrolment-token revoke <id>
```

Revokes an unspent token before it is used. A token that has already been spent cannot
be revoked — its one use is already consumed, and the command reports the server's `409`
as an error naming that condition. Requires `enrolment-token:revoke` at
`AssuranceStrong`.

**Flags (both subcommands):**

| Flag | Default | Description |
|------|---------|-------------|
| `--api-url` | — | Controller REST API URL (env: `CFGMS_API_URL`) |
| `--tls-insecure` | false | Skip TLS certificate verification (development only, env: `CFGMS_TLS_INSECURE`) |
| `--server-name` | — | Override the TLS server name used for certificate verification |

`mint` additionally requires `--tenant-id` (no default — a tenant-scoped caller may only
mint within its own subtree).

### cfg credential enrol (Issue #3720)

Run by the **operator on the headless machine** — the one with no `cfg` credential yet.

```bash
cfg credential enrol --token <token> --url https://controller:9443
cfg credential enrol --token <token> --url https://controller:9443 --name prod
```

Generates an ECDSA P-256 keypair locally, builds a certificate signing request over the
public half, and lodges it authenticated by `--token` — the private key never leaves
this machine, and never appears in the request body (only the CSR, which carries the
public key alone). On success the command prints, together and prominently:

```
Credential request lodged (id: cr-...)
Public key fingerprint: AB12-CD34-EF56-7890
Compare this fingerprint with the administrator before they approve the request.
Approval endpoint (an administrator lists and approves pending requests here): https://controller:9443/api/v1/credential-requests
Expires: 2026-08-28T11:00:00Z
```

**The fingerprint comparison is the actual security check** — read it to the
administrator (phone, chat, in person) before they approve. `public_key_fingerprint_short`
is a deterministic function of the public key alone, so the value the administrator sees
next to the pending request in their own tooling must match what this command printed;
approving a request whose fingerprint was never compared is a bare row click on a
credential the approver is about to mark admin-capable.

The command then polls the collect endpoint (`--poll-interval`, default 5s) until an
administrator decides, printing `Waiting for administrator approval...` between polls,
and exits with one of four distinct outcomes — the first three leave no credential file
anywhere on disk:

| Outcome | What happened | Message |
|---|---|---|
| Denied | An administrator denied the request | `credential request was denied by an administrator` |
| Expired | No decision arrived within the request's one-hour lifetime | `credential request expired before it was approved` |
| Interrupted | The operator pressed Ctrl-C while waiting | `enrolment interrupted; no credential was stored` |
| Collected | Approved, and this command already collected it (should not normally occur — see below) | `credential request was already collected` |
| **Success** | Approved and collected | `Enrolled as "<name>" (expires ...)` |

On success the command collects the signed certificate, then finishes the same way
`cfg connect --bundle` does on first import: it registers the connection in the local
registry, stores the certificate and private key through the encrypted credential store
(never cleartext), builds an mTLS client from them, exchanges the certificate for a
session via `POST /api/v1/sessions`, and stores that session token in the OS keychain.
The next ordinary `cfg` command against this controller works without any further step.

The collect secret the lodge call returns is held only in a local variable for the life
of the process — it is never written to disk and never appears in this command's output,
at any verbosity.

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--token` | — | Enrolment token minted by an administrator (env: `CFGMS_ENROLMENT_TOKEN`); required |
| `--url` | — | Controller HTTPS URL; required, and must be HTTPS for any non-loopback address (same rule as `cfg connect`) |
| `--name` | derived from URL host | Connection name to register |
| `--hostname` | this machine's hostname | Display-only text sent with the request (shown to the administrator alongside the fingerprint) |
| `--label` | — | Display-only label sent with the request |
| `--platform` | — | Display-only platform sent with the request |
| `--purpose` | `cli enrolment` | Display-only purpose sent with the request |
| `--tls-insecure` | false | Skip TLS certificate verification (development only, env: `CFGMS_TLS_INSECURE`) |
| `--server-name` | — | Override the TLS server name used for certificate verification |
| `--poll-interval` | 5s | Interval between collect polls |

None of these flags select the certificate's markers (admin, payload-signing, root
scope) — that set is decided entirely by the administrator at approval time, never by
the requesting machine.

### cfg login — browser-authenticated CLI login (Issue #3721)

Run by an **operator who already has a browser** but no `cfg` credential yet — the
default, everyday way to obtain a session. Where `cfg credential enrol` (above) is the
headless path, `cfg login` is the interactive one: no bundle file, no private key
transfer, no shell on the controller.

```bash
cfg login --url https://controller:9443
cfg login --url https://controller:9443 --name prod
```

The command generates a random verifier locally (never written to disk, never placed in
a URL, sent to the controller only once — as a bearer credential at collect time), lodges
a login request over its own connection, and prints:

```
Code: AB3D-7FQK
Approve this login by visiting: https://controller:9443/login/confirm?request_id=cli-login-...
Expires: 2026-08-28T11:05:00Z
```

It then opens the approval URL in the default browser (skip this and only print the URL
with `--no-browser`) — best-effort; if opening fails (a headless SSH session, an
unsupported platform) the command prints a notice and the operator copies the URL to any
browser, on any machine. Complete a passkey login there and confirm the same code this
command printed — **the code comparison is the actual security check**, and applies
uniformly regardless of the account's scope: `cfg login` succeeds the same way for a
root-scoped account as for a tenant-scoped one, and the resulting session carries
whatever scope the approving account has.

**No bundle, no relay, no listener.** `cfg login` never opens a local listening socket.
The session token is handed to this command exactly once, in the response body of the
collect call this command itself makes to the controller — the browser never talks to
this machine, and the token never appears in any URL, query string, fragment, redirect
target, log line, or output stream.

**A tenant-scoped account needs the `cli-login:approve` permission** (granted like any
other RBAC permission) before it can log in this way — `cfg login` reuses the existing
session-creation path (`POST /api/v1/sessions`) for the approving account, gated by its
own `cli-login:approve` permission rather than the `session:create` permission that path
normally requires; it does not mint through a separate route.

The command then polls the collect endpoint (`--poll-interval`, default 3s, bounded by
`--wait-timeout`, default 5m) until the browser confirms, printing `Waiting for browser
approval...` between polls, and exits with one of four distinct outcomes — none of which
leave a session on disk:

| Outcome | What happened | Message |
|---|---|---|
| Denied | The browser session declined the confirmation | `login request was denied by an administrator` |
| Timed out | The wait-timeout elapsed, or the login request's own short lifetime expired first | `timed out waiting for browser approval; run 'cfg credential enrol' for headless enrolment instead` |
| Interrupted | The operator pressed Ctrl-C while waiting | `login interrupted; no session was stored` |
| Already collected | This request was already collected (should not normally occur) | `login request was already collected` |
| **Success** | Confirmed in the browser and collected | `Logged in as "<name>" (expires ...)` |

On success the command registers the connection in the local registry (`unlock_method:
browser` — there is no bundle to later reconnect from; run `cfg login` again for a fresh
session) and stores the session token in the OS keychain, exactly as `cfg connect` does.
The next ordinary `cfg` command against this controller works without any further step.

If a previous session for this controller is already stored, `cfg login` checks it before
starting the browser flow and, if it is no longer usable, prints which of two distinct
reasons applies — both surface as the same `401` from the controller, so the command
never collapses them into one generic message:

```
Note: your previous session was revoked — this usually means the account was disabled. If a fresh login also fails, contact an administrator.
Note: your previous session expired. Logging in again...
```

This is informational only; the fresh browser login proceeds either way.

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--url` | — | Controller HTTPS URL; required, and must be HTTPS for any non-loopback address (same rule as `cfg connect`) |
| `--name` | derived from URL host | Connection label to register |
| `--tls-insecure` | false | Skip TLS certificate verification (development only, env: `CFGMS_TLS_INSECURE`) |
| `--server-name` | — | Override the TLS server name used for certificate verification |
| `--poll-interval` | 3s | Interval between collect polls |
| `--wait-timeout` | 5m | Maximum time to wait for browser approval |
| `--no-browser` | false | Never attempt to open a browser automatically; only print the URL |

### cfg credential revoke-by-token / cancel-request / list-orphaned / revoke-orphaned (Issue #3725)

Run by the **administrator** when an enrolment token or an enrolled host is believed
compromised. Minting (above) and un-minting ship together: this is the containment
half. All four subcommands require `--force` or an interactive `y` confirmation
(`confirmDestructive`, the same guard `cfg account revoke-cert` and `cfg account
delete` use).

```bash
cfg credential revoke-by-token <token-id>
```

Revokes every certificate already issued from one enrolment token and blocks every
still-`pending`/`approved` request under that token from ever producing one. Prints a
per-request outcome (`contained` / `already_contained` / `error`) rather than an
all-or-nothing result. A token with no lodged requests is reported as a failure (non-zero
exit) rather than a silent success — a mistyped or already-exhausted token ID should
never look like "nothing to do."

```bash
cfg credential cancel-request <request-id>
```

Cancels a request that is `approved` but not yet `collected` — this is a state
transition, not a certificate revocation, because collect (not approval) mints the
certificate. Refused with a distinct error for a request that is `pending` (not yet
approved — use `deny` instead), already `collected` (use `revoke-by-token` or
`revoke-orphaned` instead), or already `denied`.

```bash
cfg credential list-orphaned
cfg credential revoke-orphaned <serial>
```

`list-orphaned` finds `collected` enrolment-flow certificates whose bound account no
longer carries a matching binding — the on-demand equivalent of the background sweep
(below) for an administrator who wants to act immediately. Listing never revokes
anything; `revoke-orphaned` is a separate, explicit action on a serial the list
surfaced. It refuses (409) a serial that is still bound to an account (not orphaned) or
already revoked.

**Flags (all four subcommands):**

| Flag | Default | Description |
|------|---------|-------------|
| `--api-url` | — | Controller REST API URL (env: `CFGMS_API_URL`) |
| `--force` | false | Skip the interactive confirmation prompt (not on `list-orphaned`) |
| `--json` | false | Emit JSON output (`list-orphaned` only) |

### REST reference

The sections below document the endpoints the two commands above call. They remain
accurate for a direct API consumer that does not go through `cfg`.

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

### Approving a pending request (Issue #3718)

Story #3718 adds the approval decision. **Approving signs nothing** — the shipped steward
registration path already works this way (`handleApproveRegistration`'s own doc comment:
"no cert is generated here, generate-on-claim") and this endpoint mirrors it: it validates
the approver's own authority, decides which certificate markers the eventual credential
will carry, selects or creates the account it will bind to, and records all three together
on the pending request before moving it to `approved`. No certificate exists at the end of
this call — signing the lodged public key and writing the account binding atomically is the
collect story that follows.

```
POST /api/v1/credential-requests/{id}/approve
{
  "fingerprint": "AB12-CD34-EF56-7890",
  "account_id": "<existing account UUID>",
  "grant_admin_marker": true,
  "grant_payload_signing_marker": false,
  "grant_root_scope_marker": false
}
```

`fingerprint` must match the fingerprint recorded at lodge time — full or short form both
accepted — or the call is rejected with `409`. This closes the window where a second lodge
re-sorts the queue between rendering the list and clicking approve.

Exactly one of `account_id` (select an existing account within the caller's tenant subtree)
or `new_account_username` (plus optional `new_account_tenant_id`, defaulting to the
request's own tenant) must be supplied. A headless host is represented by its own account,
created through the same durable account-persistence path `POST /api/v1/accounts` uses.

Each of the three certificate markers (Epic #3711 D3) is granted only when explicitly
requested **and** only when the approver holds the authority for it — the default is
nothing, and a marker the approver cannot grant refuses the whole call (`403`) rather than
silently dropping it:

| Marker | Requested field | Requires |
|---|---|---|
| `AdminMarkerOID` | `grant_admin_marker` | The approver is themselves a platform administrator (`Principal.ImplicitAdmin`) |
| `PayloadSigningMarkerOID` | `grant_payload_signing_marker` | The approver holds `signing-credential:request` at `AssuranceStrong` — the same gate `POST /api/v1/signing-credential/request` enforces on itself |
| `RootScopeMarkerOID` | `grant_root_scope_marker` | The approver's own request was authenticated by a certified, non-revoked root-scope-marked certificate (`Principal.RootScoped && Principal.CertSerial != ""`) — a session or a cookie can never satisfy this, however many permissions it holds |

An approver can therefore never mint a credential stronger than their own — which is also
what makes **self-approval safe**: approving one's own request (the selected or created
account is the approver's own) grants nothing the approver did not already have. The
approve endpoint records `self_approved` on the audit event so this is visible, not
something a reviewer has to infer.

Requires `credential-request:approve` at `AssuranceStrong` with a fresh user-presence
proof. The presence requirement is what actually confines the retained bootstrap admin
credential here ([ADR-021](../architecture/decisions/021-identity-assurance-levels.md)
Amendment 5): its `ImplicitAdmin` flag satisfies every permission-string check by
construction, but it resolves to no bound account, so no presence token can ever be minted
for it.

### Collecting the signed certificate (Issue #3719)

Story #3719 closes the loop: this is where the certificate is actually signed. The
machine that lodged the request, and only that machine, collects it — authenticated by
the `collect_secret` the lodge response returned exactly once, never by the request ID
or the public-key fingerprint (both are values an observer of the approval screen has
already seen). There is no API key, mTLS certificate, or web session on this call, and
no permission gate — the endpoint is not on the elevated-assurance surface at all,
exactly like lodge.

```
POST /api/v1/credential-requests/{id}/collect
Authorization: Bearer <collect secret>
```

The waiting machine polls this endpoint. Every response is one of:

| Response | Meaning |
|---|---|
| `404 REQUEST_NOT_FOUND` | Unknown ID, **or** a valid ID with the wrong (or absent) collect secret — the two are indistinguishable by design; the endpoint never confirms a request ID exists to an unauthenticated caller |
| `200 {"status": "pending"}` | Correct secret, but no admin decision yet — keep polling |
| `200 {"status": "denied"}` | The request was denied; it will never become collectible |
| `200 {"status": "expired"}` | The request (and its collect secret) passed its one-hour lifetime before it was collected |
| `410 Gone` | Already collected — by this machine's own earlier call, or by the winner of a concurrent race. There is never a second certificate for one request |
| `503` | Not the authoritative node for minting; the request is untouched — retry |
| `200` with a certificate body | Success (below) |

A successful collection returns:

```json
{
  "data": {
    "certificate_pem": "-----BEGIN CERTIFICATE-----...",
    "ca_certificate_pem": "-----BEGIN CERTIFICATE-----...",
    "serial_number": "...",
    "account_id": "<the account recorded at approval>",
    "granted_markers": ["admin"],
    "expires_at": "2027-08-28T10:00:00Z"
  }
}
```

The certificate is signed from exactly the marker set and account recorded at approval
— never recomputed, re-derived, or widened at collect, and never read from the bound
account's own attributes. There is no authenticated principal on this call to derive
anything else from. An approved request that is never collected leaves no certificate
in existence: nothing is signed until collect runs.

Collection is single-use, enforced as a conditional durable state transition
(`approved` → `collected`) that commits **before** the certificate is signed — so a
restart between the transition and the response can never produce a second
certificate, and the loser of a concurrent collect race always receives `410` rather
than a duplicate. The account binding is written **before** the certificate is
returned to the caller, and any failure after signing revokes the just-issued
certificate immediately: a signed certificate is never left observable in a state
where it resolves to no account (that state would otherwise fall through to the mTLS
middleware's bootstrap-fallback path and be granted implicit root).

Minting is leadership-gated, but only on the branch that actually mints: an approved
request found on a non-authoritative node returns `503` and stays `approved` untouched,
while every polling response above (`pending`/`denied`/`expired`/not-found) remains
available regardless of leadership — a waiting machine's poll loop does not stall
during a leadership change.

Collect is rate limited per source address, and the collect secret expires with the
request it belongs to (the same one-hour lifetime and the same background sweep
described above) — a captured secret has a bounded life.

### Revoking and containing enrolment-issued credentials (Issue #3725)

Story #3725 closes the loop on the other side: when an enrolment goes wrong, an
administrator can revoke every certificate already issued from one enrolment token,
cancel a request that was approved but never collected, and find — and, as a separate
explicit action, revoke — enrolment-issued certificates that exist with no account
binding. Minting and un-minting ship together.

```
POST /api/v1/enrolment-tokens/{id}/revoke-issued-credentials
```

Requires `enrolment-token:revoke-issued` at `AssuranceStrong`. Walks every credential
request lodged against the token and, per request:

- `collected`: revokes the issued certificate via the same fail-closed
  revoke-then-unbind ordering `POST /accounts/{username}/certs/revoke/{serial}` uses —
  a failure after the revoke leaves a revoked-but-still-bound certificate, never a live
  unbound one.
- `pending` or `approved`: transitions the request to `denied`, so it can never later be
  approved or collected — this is what makes the containment complete, not just a
  revoke of what has already been signed.
- `denied` already: no-op, reported as already contained.

The response reports one outcome per request rather than failing the whole call on the
first error:

```json
{
  "data": {
    "token_id": "et-<uuid>",
    "results": [
      {"request_id": "cr-<uuid>", "outcome": "contained"},
      {"request_id": "cr-<uuid>", "outcome": "already_contained"},
      {"request_id": "cr-<uuid>", "outcome": "error", "detail": "certificate revoked but binding removal failed"}
    ]
  }
}
```

```
POST /api/v1/credential-requests/{id}/cancel
```

Requires `credential-request:cancel` at `AssuranceStrong`. Cancels a request that is
`approved` but not yet `collected` — a state transition (`approved` → `denied`, the same
terminal status `deny` uses; there is no separate "cancelled" status), not a certificate
revocation, since collect — not approval — is what mints the certificate. Refuses (409)
with a distinct error code for every other status: `REQUEST_NOT_APPROVED` (still
`pending`), `REQUEST_ALREADY_COLLECTED` (a live certificate exists — use
`revoke-issued-credentials` or the orphaned-certificate endpoints instead), or
`REQUEST_ALREADY_DENIED`. Takes the same lock the collect endpoint's
approved→collected compare-and-set uses, so a cancel and an in-flight collect for the
same request can never both observe `approved`.

```
GET /api/v1/credential-requests/orphaned
```

Requires `credential-request:list-orphaned` (no assurance floor — a read surface,
mirroring `credential-request:list`). Lists `collected` requests whose recorded serial
does not appear in its bound account's `CertBindings` — the exact window the background
orphan sweep (above) closes on its own interval, surfaced on demand:

```json
{
  "data": [
    {
      "request_id": "cr-<uuid>",
      "tenant_id": "root/msp-a/client-1",
      "serial": "...",
      "account_id": "<the account recorded at approval>",
      "collected_at": "2026-08-28T10:00:00Z"
    }
  ]
}
```

```
POST /api/v1/credential-requests/orphaned/{serial}/revoke
```

Requires `credential-request:revoke-orphaned` at `AssuranceStrong`. Revokes a listed
serial — a separate explicit action from listing. Re-verifies the serial is still
orphaned immediately before revoking (409 `NOT_ORPHANED` if a binding now exists, 409
`ALREADY_REVOKED` if already revoked), so this endpoint can never be used as a side
channel to revoke a live, properly bound credential.

Every revocation and every cancel emits a durable audit event, and every mutating
handler here calls the same lease-backed leadership check the rest of this package
uses (`503` when not the authoritative node).

### Renewing an issued credential — cfg credential renew (Issue #3724)

Story #3724 closes the epic's last gap: a credential collected via #3719 renews
itself before it expires, with no human present, and cannot use renewal to gain
anything it did not already have.

```bash
cfg credential renew
cfg credential renew --unattended
cfg credential renew --bundle /etc/cfgms/admin.bundle.yaml --unattended
```

Renewal is authorised by presenting the **current, still-valid certificate itself**
over mutual TLS — there is no separate renewal credential, no bearer secret, and
nothing in the request body can name, select, or change which account the renewed
certificate binds to. The command reads the admin bundle (the same file `cfg
connect --bundle` imports and `cfg credential request-signing-cert` authenticates
with), generates a fresh keypair locally, and sends only the new public key as a
certificate signing request:

```
POST /api/v1/credential-renewal
{"csr_pem": "-----BEGIN CERTIFICATE REQUEST-----..."}
```

authenticated by presenting the bundle's own client certificate over mTLS. The
controller derives everything about the new certificate from that certificate: the
account it renews into (the one the presented serial is already bound to — a
presented certificate with no binding at all, the mTLS bootstrap-fallback case, is
refused rather than renewed into), and the exact marker set the presented
certificate carries, copied verbatim and never widened. A CSR that reuses the
current certificate's own public key is refused — a fresh keypair is required on
every renewal.

A successful renewal returns:

```json
{
  "data": {
    "certificate_pem": "-----BEGIN CERTIFICATE-----...",
    "ca_certificate_pem": "-----BEGIN CERTIFICATE-----...",
    "serial_number": "...",
    "account_id": "<the account the presented certificate is bound to>",
    "granted_markers": ["admin"],
    "expires_at": "2027-08-28T10:00:00Z"
  }
}
```

`cfg credential renew` writes the new certificate, its freshly generated private
key, and the CA certificate back into the same bundle file, preserving
`controller_url` and `audit_subject` — the file is fully usable for the next `cfg`
invocation with no further action. The old certificate is revoked and its binding
removed once the new one is confirmed bound; a failure earlier in that sequence
(before the new certificate is bound) leaves the old, still-valid certificate as the
working credential rather than none.

**The renewal window.** The controller refuses renewal outside a 30-day window
before expiry, for an already-expired certificate, and for a revoked serial — a
certificate with most of its life left has no reason to renew early. `--unattended`
is the flag for periodic/cron/systemd-timer invocation: it checks the bundle
certificate's expiry **locally**, before contacting the controller at all, and exits
`0` with no network call when renewal is not yet due — so a job scheduled to run
daily, or even hourly, generates no noise or load until renewal actually matters.
Without `--unattended`, renewal is attempted unconditionally and the controller's
own window check is authoritative.

**The off switch is the bound account, not a lifetime cap.** There is no
total-renewal-count limit and no maximum credential age — a credential may renew
indefinitely. To stop it, disable the bound account
(`POST /api/v1/accounts/{username}` with `disabled: true`, or the equivalent web UI
action): a disabled account's certificate can no longer even authenticate, so the
very next renewal attempt fails, and the host cannot reach the controller for
anything else either.

**When renewal fails.** The error message names the reason (`OUTSIDE_RENEWAL_WINDOW`,
`CERTIFICATE_EXPIRED`, `NO_ACCOUNT_BINDING`, `KEY_REUSE_REJECTED`, or a `401` for a
revoked or disabled-account certificate that never authenticated in the first
place):

- Outside the renewal window: not an error to act on — the certificate is not due
  yet; a scheduled `--unattended` run will pick it up once it is.
- Certificate already expired, or the bound account was disabled: there is no
  recovery through this command. An administrator must mint a fresh enrolment
  token ([above](#minting-and-revoking-an-enrolment-token)) and the host must
  re-enrol from scratch — renewal only ever extends a credential that is still
  alive, never resurrects one that is not.
- Any other failure (network, `503` from a non-leader node, a `5xx`): safe to
  retry: the old certificate is left intact until a new one is confirmed bound, so
  a failed or interrupted renewal never leaves the host without a working
  credential.

Renewal has no RBAC permission gate — the presented certificate is itself the
authorization, matching the "no separate renewal credential" design. It is
leadership-gated on the controller (a non-leader node returns `503`, and the old
credential is left untouched) and records a durable audit event naming the old
serial, the new serial, and the granted marker set.

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--unattended` | false | Only contact the controller if the certificate is within its renewal window; exit `0` without renewing otherwise |
| `--api-url` | bundle's `controller_url` | Controller REST API URL override |
| `--tls-insecure` | false | Skip TLS certificate verification (development only) |
| `--server-name` | — | Override the TLS server name used for certificate verification |

`--bundle`, `--no-bundle`, and `CFGMS_ADMIN_BUNDLE` (the global bundle-discovery
flags — see [Connection Management](#connection-management)) select which bundle
file is renewed; renewal always uses the resolved bundle's own certificate, never a
session token, even if one happens to be active.

### Permissions

| Permission | Assurance floor | Notes |
|------------|------------------|-------|
| `enrolment-token:mint` | `AssuranceStrong` | Mints a single-use, short-lived token |
| `enrolment-token:revoke` | `AssuranceStrong` | Revokes an unspent token |
| `credential-request:list` | none | Read-only; outside the elevated-assurance surface |
| `credential-request:deny` | none | De-escalation action, mirrors `registration:deny` |
| `credential-request:approve` | `AssuranceStrong` + presence | Decides the marker set and account binding (Issue #3718); signs nothing |
| `enrolment-token:revoke-issued` | `AssuranceStrong` | Revokes every certificate issued from a token and blocks its outstanding requests (Issue #3725) |
| `credential-request:cancel` | `AssuranceStrong` | Cancels an approved-but-uncollected request (Issue #3725) |
| `credential-request:list-orphaned` | none | Read-only; outside the elevated-assurance surface |
| `credential-request:revoke-orphaned` | `AssuranceStrong` | Revokes a listed orphaned certificate (Issue #3725) |
| — (none) | — | `POST /api/v1/credential-renewal` (Issue #3724) has no permission gate; the presented certificate is itself the authorization |

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

Fails fast: a WebAuthn ceremony served from a CLI-local loopback listener
(`http://127.0.0.1:<random-port>`) can never satisfy a configured relying party, in any
controller configuration — the browser itself refuses `navigator.credentials.create()`
because a `127.0.0.1` origin can never match a real `rp_id` (see [ADR-021 Amendment
4](../architecture/decisions/021-identity-assurance-levels.md#amendment-4-2026-08-28-relying-party-is-configuration-has-no-default-and-wiring-it-exposed-a-cli-relay-regression)).
The command returns immediately with an error, without contacting the controller's begin
endpoint, starting a local listener, or opening a browser. Register a passkey from the
controller web UI instead, at the `/passkeys` page (ADR-021 Amendment 1 self-enrollment,
Amendment 3 self-service passkey management).

```
cfg webauthn register --username <user> [--label <name>] [--bundle <path>]
```

Example:

```
cfg webauthn register --username alice --label "YubiKey 5C"
# Error: cfg webauthn register cannot run the WebAuthn ceremony from the CLI: a browser
# refuses navigator.credentials.create() from a page served at http://127.0.0.1, which
# can never match a configured relying party (ADR-021 Amendment 4). Register a passkey
# from the controller web UI instead, at the /passkeys page (ADR-021 Amendment 1
# self-enrollment, Amendment 3 self-service passkey management)
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--username` | — | Account username (required) |
| `--label` | — | Human-readable label for the credential |
| `--bundle` | auto | Path to admin bundle file (env: CFGMS_ADMIN_BUNDLE) |
| `--api-url` | bundle URL | Override controller URL |

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

Lists all mTLS certificate bindings for a web-admin account, including each
binding's last-used timestamp (Issue #3715) — the compensating control for
allowing credentials that renew themselves indefinitely: a host that no longer
needs its credential becomes visible because its binding stops accumulating
recent `Last used` activity.

```
cfg account certs <username> [--json]
```

Example:

```
cfg account certs alice

Certificate bindings for alice (2):

  [1] Serial:   12345
      Label:    primary laptop
      Bound at: 2026-08-01T00:00:00Z
      Last used: 2026-08-20T12:30:00Z

  [2] Serial:   67890
      Bound at: 2026-08-15T00:00:00Z
      Last used: never
```

`Last used` renders `never` when the binding has not yet been used to
authenticate — including every binding created before this story shipped.
This is an explicit value, not a blank line or a zero-value date: the
underlying `last_used_at` field is optional and is omitted from the JSON
response entirely until the certificate's first successful authentication.
The timestamp is recorded on a best-effort, coalesced basis (at most once
every few minutes per certificate) and is observational only — it never
affects whether a request is authorised.

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

- **Presence required** (`presence="required"` in the header): CLI-driven presence
  assertion is not currently supported — a ceremony served from a CLI-local loopback
  listener can never satisfy a configured relying party, in any controller
  configuration (see [ADR-021 Amendment
  4](../architecture/decisions/021-identity-assurance-levels.md#amendment-4-2026-08-28-relying-party-is-configuration-has-no-default-and-wiring-it-exposed-a-cli-relay-regression)).
  `cfg` fails fast with an actionable error directing the operator to complete the
  action from the controller web UI.

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
