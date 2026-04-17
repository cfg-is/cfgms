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

# Test OSS composite storage (flatfile+sqlite) specifically
make test-integration-oss

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
