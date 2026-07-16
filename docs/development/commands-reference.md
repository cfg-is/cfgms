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

### cfg connect (first-time import)

Import an admin bundle and start a controller session.

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

## Workflow Management

`cfg workflow` subcommands manage workflow definitions and their executions on the controller.

### cfg workflow list

List all workflow definitions registered on the controller.

```bash
cfg workflow list --url=https://controller.example.com
cfg workflow list --url=https://controller.example.com --api-key=mykey
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
| `--api-key` | — | API key for authentication |
| `--tls-ca-cert` | — | Path to CA certificate for TLS verification (env: CFGMS_TLS_CA_CERT) |
| `--tls-insecure` | false | Skip TLS verification (development only, env: CFGMS_TLS_INSECURE) |

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
| `--api-key` | — | API key for authentication |
| `--tls-ca-cert` | — | Path to CA certificate for TLS verification (env: CFGMS_TLS_CA_CERT) |
| `--tls-insecure` | false | Skip TLS verification (development only, env: CFGMS_TLS_INSECURE) |

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
| `--api-key` | — | API key for authentication |
| `--tls-ca-cert` | — | Path to CA certificate for TLS verification (env: CFGMS_TLS_CA_CERT) |
| `--tls-insecure` | false | Skip TLS verification (development only, env: CFGMS_TLS_INSECURE) |

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
| `--api-key` | — | API key for authentication |
| `--tls-ca-cert` | — | Path to CA certificate for TLS verification (env: CFGMS_TLS_CA_CERT) |
| `--tls-insecure` | false | Skip TLS verification (development only, env: CFGMS_TLS_INSECURE) |

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
  --url=https://controller.example.com --api-key=mykey
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
| `--api-key` | — | API key for authentication (env: CFGMS_API_KEY) |
| `--tls-ca-cert` | — | Path to CA certificate (env: CFGMS_TLS_CA_CERT) |
| `--tls-insecure` | false | Skip TLS verification (env: CFGMS_TLS_INSECURE) |

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

**Flags:** `--url`, `--api-key`, `--tls-ca-cert`, `--tls-insecure` (same as above).

### cfg role show

Display a role config including its selector and fragment.

```bash
cfg role show <name> --url=https://controller.example.com
```

**Flags:** `--url`, `--api-key`, `--tls-ca-cert`, `--tls-insecure` (same as above).

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

**Flags:** `--url`, `--api-key`, `--tls-ca-cert`, `--tls-insecure` (same as above).

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
cfg steward tag add <steward-id> <tag> [tag...] --url=https://controller.example.com --api-key=mykey
```

Example:

```bash
cfg steward tag add steward-abc123 prod web-server \
  --url https://controller.example.com --api-key mykey
```

Output on success:

```
Tags on steward-abc123: prod, web-server
```

### cfg steward tag rm

Remove one or more tags from a steward. Removing a tag that does not exist is a no-op (idempotent).

```bash
cfg steward tag rm <steward-id> <tag> [tag...] --url=https://controller.example.com --api-key=mykey
```

Output on success:

```
Tags on steward-abc123: prod
```

### cfg steward tag ls

List all operator-assigned tags on a steward.

```bash
cfg steward tag ls <steward-id> --url=https://controller.example.com --api-key=mykey
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
| `--api-key` | — | API key for authentication (env: CFGMS_API_KEY) |
| `--tls-ca-cert` | — | Path to CA certificate (env: CFGMS_TLS_CA_CERT) |
| `--tls-insecure` | false | Skip TLS verification (env: CFGMS_TLS_INSECURE) |
