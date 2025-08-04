# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CFGMS (Config Management System) is a modern, Go-based configuration management system designed with resilience, security, and clean architecture principles. The project implements a zero-trust security model with mutual TLS authentication and follows a feature-based organization structure.

## Development Workflow

### Sprint and Development Process
- **Sprint Planning Guideline**: At the start of each milestone, ALWAYS conduct sprint/story planning before beginning work

### MANDATORY Story Development Checklist

**BEFORE STARTING ANY CODE:**

1. **Create Feature Branch** (MANDATORY)
   ```bash
   git checkout develop
   git pull origin develop
   git checkout -b feature/story-[NUMBER]-[brief-description]
   ```

2. **Verify Branch Creation**
   ```bash
   git branch --show-current  # Must show feature branch name
   ```

**DURING DEVELOPMENT:**

3. **Implement using TDD**
   - Write tests first, then implementation
   - Run tests frequently: `make test`

4. **MANDATORY Security Review** (CRITICAL)
   
   **Act as a cybersecurity expert specializing in Go applications and zero-trust systems.** Review ALL code changes for security vulnerabilities with particular attention to:

   **Authentication & Authorization:**
   - Verify all API endpoints require proper authentication
   - Check certificate validation is not bypassed
   - Ensure RBAC permissions are enforced
   - Validate JWT/token handling is secure

   **Input Validation & Injection Prevention:**
   - Check ALL user inputs are validated and sanitized
   - Verify SQL queries use parameterized statements
   - Ensure command injection is prevented in shell executions
   - Validate file path operations prevent directory traversal

   **Cryptography & TLS:**
   - Verify mutual TLS implementation is correct
   - Check certificate handling follows security requirements
   - Ensure no hardcoded cryptographic keys or secrets
   - Validate random number generation uses crypto/rand

   **Information Disclosure:**
   - Check logs don't contain sensitive information (passwords, keys, tokens)
   - Verify error messages don't leak internal details
   - Ensure debug information is not exposed in production paths

   **CFGMS-Specific Security:**
   - Verify tenant isolation is maintained (no cross-tenant data access)
   - Check configuration inheritance doesn't bypass security controls
   - Ensure steward certificates are properly validated
   - Validate gRPC endpoints enforce mTLS

   **Action Required:** If ANY security issues are found, STOP and fix them before proceeding. Document the vulnerability and remediation in commit message.

**BEFORE ANY COMMITS:**

5. **STOP - Run Full Test Suite** (MANDATORY)
   ```bash
   make test  # MUST pass 100% before proceeding
   ```
   - If ANY tests fail, fix them before continuing
   - This includes unrelated test failures

6. **Run Security Scanning** (MANDATORY)
   ```bash
   make security-scan  # MUST pass before proceeding
   ```
   - **Trivy**: Filesystem vulnerability scanning (critical/high blocking)
   - **Nancy**: Go dependency vulnerability scanning  
   - **gosec**: Go security pattern analysis (127 checks)
   - **staticcheck**: Advanced static analysis (47 categories)
   - Critical/High vulnerabilities will block deployment
   - Fix security issues before continuing with commit
   - Development certificates in features/controller/certs/ are expected (non-blocking)
   - **Claude Code Integration**: Use `make security-remediation-report` for automated fixes

7. **Run Linting** (MANDATORY)
   ```bash
   make lint  # MUST pass before proceeding
   ```

**ALTERNATIVE: Unified Development Validation** (RECOMMENDED)
Instead of steps 5-7, use the unified target that runs all validations:
```bash
make test-with-security  # Runs: test + security-scan + displays summary
```
This ensures optimal order (test → security → summary) and provides clear validation status.

**COMMIT AND PROJECT MANAGEMENT:**

8. **Commit Feature Work**
   ```bash
   git add .
   git commit -m "Implement Story #[NUMBER]: [description]

   Security Review: [Brief summary of security review findings/all clear]"
   ```

9. **Update Documentation** (REQUIRED)
   - Update `docs/product/roadmap.md` if needed
   - Update `CLAUDE.md` if workflow/commands changed

10. **Update GitHub Project Status** (MANDATORY)
    ```bash
    # ALWAYS review docs/github-cli-reference.md FIRST before any gh project commands
    # This document contains the exact project IDs, field IDs, and option IDs required
    # Never guess or use generic commands - use the documented patterns
    
    # Example workflow:
    # 1. Check docs/github-cli-reference.md for current project details
    # 2. Add issues to project: gh project item-add 1 --owner cfg-is --url "URL"
    # 3. Update status: Use exact IDs from documentation
    # 4. Move story from "In Progress" to "Done" using documented commands
    ```

11. **Final Test Run** (MANDATORY)
    ```bash
    make test  # Final verification before merge
    ```

12. **Merge to Develop**
    ```bash
    git checkout develop
    git merge feature/story-[NUMBER]-[brief-description]
    git push origin develop
    ```

**VALIDATION CHECKPOINTS:**
- Verify branch was created: `git log --oneline -5`
- Verify tests pass: `make test`
- Verify security scan passes: `make security-scan`
- Verify project updated: Check GitHub project board

**GITHUB ACTIONS CI/CD:**
- **Security Scanning Workflow**: Automatic security validation on push/PR
- **Production Deployment Gates**: Critical vulnerabilities block main branch deployment
- **Automated Remediation**: Download artifacts and use Claude Code for automatic fixes
- **Manual Trigger**: Use workflow_dispatch for specific scan types (quick/full/remediation-report)

## Development Commands

### Building
```bash
# Build all binaries
make build

# Build individual components
make build-controller  # Builds controller binary
make build-steward     # Builds steward binary  
make build-cli         # Builds cfgctl CLI binary
```

### Testing
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

### Production Risk Testing & Release Gates
```bash
# Test production-critical functionality only
make test-production-critical

# Check export reliability and cost protection
make test-export-reliability

# Simulate monitoring costs at scale
make cost-analysis

# Check compliance protection status
make compliance-check

# v0.3.0 Release Gate (Alpha Readiness)
make test-v030-gate

# v0.4.0 Release Gate (Production Readiness)  
make test-v040-gate
```

**IMPORTANT**: Release gates must pass before deployment:
- **v0.3.0 Gate**: Blocks alpha deployment until cost protection and data loss prevention are working
- **v0.4.0 Gate**: Blocks production deployment until ALL export edge cases are resolved

### Security Scanning
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

### Unified Development Validation
```bash
# Complete validation workflow (test + security + summary)
make test-with-security

# Traditional individual steps
make test
make security-scan
make lint
```

### Linting
```bash
# Run linter (requires golangci-lint)
make lint
# Equivalent to: golangci-lint run
```


### Protocol Buffers
```bash
# Generate Go code from proto files
make proto

# Check for required proto tools
make check-proto-tools
```

### Cleanup
```bash
# Clean build artifacts and test cache
make clean
```

## Core Architecture

### System Architecture

**Three-Tier System:**
- **Controller**: Central management system for configuration distribution and tenant hierarchy management
- **Steward**: Cross-platform component that executes configurations on managed endpoints
- **Outpost**: Proxy cache component for network device monitoring and agentless management

**Communication:**
- **Internal**: gRPC with mutual TLS between components
- **External**: REST API with HTTPS and API key authentication
- **Protocol Buffers**: Used for efficient data serialization

**Security:**
- Zero-trust security model with mutual TLS for all internal communication
- Certificate-based authentication for stewards
- Optional OpenZiti integration for zero-trust networking
- Role-based access control (RBAC) with hierarchical permissions

### Module System
All resource management is performed through modules that implement the core interface:
- `Get(ctx, resourceID)` - Returns current configuration as ConfigState
- `Set(ctx, resourceID, config)` - Updates resource to match desired state (managed fields only)
- **System Testing**: Steward automatically compares current vs desired state using managed fields
- `Monitor(ctx, resourceID, config)` - **(Optional)** Real-time event-driven monitoring via separate interface

**ConfigState Interface**: Enables efficient field-level comparison without marshal/unmarshal overhead. Modules return comprehensive system state, but only managed fields are modified.

Available modules: `directory`, `file`, `firewall`, `package`, `script`, SaaS modules: `entra_user`, `conditional_access`, `intune_policy`

### Pluggable Infrastructure Design Paradigm
CFGMS follows a **pluggable architecture design paradigm** where infrastructure components are built with abstraction interfaces, enabling flexible backend selection without core system changes.

**Core Principle**: *Any infrastructure component that could reasonably have multiple implementations should be designed with a provider interface from the start.*

**Current Pluggable Components:**
- **Storage Backends**: `Backend` interface (File, Database, Git, Hybrid)
- **Git Providers**: `GitProvider` interface (GitHub, GitLab, Bitbucket)  
- **Compression**: `Compressor` interface (GZIP, ZSTD, LZ4)
- **Audit Storage**: `AuditStorage` interface (File-based, future DB/remote)

**Future Pluggable Areas** (Design Paradigm):
- **Database Providers**: Postgres, MySQL, MSSQL abstraction
- **KMS Providers**: HashiCorp Vault, AWS KMS, Azure Key Vault
- **Log Storage**: File, InfluxDB, Elasticsearch, Loki
- **Time Series DB**: TimescaleDB, InfluxDB, custom implementations

**Deployment Flexibility:**
- **POC/Small MSP**: Flat file storage, no external dependencies  
- **Medium MSP**: Postgres + basic external services
- **Enterprise**: Postgres + TimescaleDB + Apache AGE + dedicated KMS

This paradigm ensures CFGMS can scale from simple deployments to enterprise infrastructure without architectural refactoring.

## Code Organization

### Feature-Based Structure
```
features/
├── controller/    # Controller component and server logic
├── steward/       # Steward component with health monitoring
├── modules/       # Module implementations (directory, file, firewall, package)
├── saas/          # SaaS provider integrations and API framework
└── workflow/      # Enhanced workflow engine with conditional logic and loops
```

### Key Directories
- `cmd/` - Command-line applications (controller, steward, cfgctl)
- `api/proto/` - Protocol buffer definitions for gRPC communication
- `pkg/` - Shared packages (logging utilities)
- `test/` - Integration and end-to-end tests
- `docs/` - Comprehensive documentation including architecture and standards

## Development Guidelines

### Go Standards
- Use Go 1.23+ features
- Follow dependency injection patterns
- No global variables or state
- Implement proper context cancellation
- Use structured logging with consistent fields
- Handle all errors explicitly
- Achieve 100% test coverage for core components

### Documentation Standards
- **Package Documentation**: Every package must have comprehensive documentation explaining its purpose, key concepts, and usage examples
- **Function Documentation**: All exported functions and methods must have clear documentation starting with the function name
- **Type Documentation**: All exported types must be documented with their purpose and key fields explained
- **Example Code**: Include practical usage examples in package documentation using Go's example testing pattern
- **Implementation Notes**: Document important implementation details, design decisions, and any non-obvious behavior
- **Error Documentation**: Document expected error conditions and their meanings
- **Interface Documentation**: Clearly document interface contracts, expected behavior, and implementation requirements
- **Constants and Variables**: Document all exported constants and variables with their purpose and valid values

### Testing Approach
- **TDD**: Write table-driven tests before implementation
- **Coverage**: Aim for 100% test coverage on core components
- **Race Detection**: Always run tests with `-race` flag
- **Integration**: Test component interactions with real dependencies
- **Chaos Engineering**: Test resilience under failure conditions

### Security Requirements
- All internal network communication must use mTLS to protect gRPC
- All external network communication must use TLS to secure REST
- Implement proper input validation and sanitization
- Use secure defaults in all configurations
- Follow principle of least privilege
- Sanitize all logging output to prevent information leakage

### Stream vs Batch Processing

**Default to streaming approaches** - use batch processing only when:
- Data consumers don't need results for hours/days (no time sensitivity)
- Batch operations are significantly more resource-efficient
- External systems naturally batch data

**Examples:**
- **Good batch use**: Monthly compliance reports (no real-time need, high efficiency)
- **Poor batch use**: Configuration drift detection (needs fast feedback, wastes processing on unchanged systems)

**For time-bounded SLAs**: Implement streaming with time guarantees, not polling intervals.

### Module Development
- Each module must be self-contained with clear ConfigState interface
- Implement Get/Set interface with ConfigState for all resource types
- **Optional Monitor interface** for real-time change detection via OS hooks
- Use idempotent operations and support offline operation
- Include proper error handling and comprehensive validation
- Get returns comprehensive state, Set modifies only managed fields
- Use GetManagedFields() to specify which fields Set will change

## Branching Strategy

Following GitFlow:
- `main` - Production-ready code only
- `develop` - Integration branch for features
- `feature/*` - New feature development
- `fix/*` - Bug fixes
- `docs/*` - Documentation updates
- `refactor/*` - Code improvements

## Multi-Tenancy & Configuration Inheritance
The system implements a recursive parent-child tenant model with:
- **Hierarchical Configuration Inheritance**: MSP (Level 0) → Client (Level 1) → Group (Level 2) → Device (Level 3)
- **Declarative Merging**: Named resources (e.g., `firewall.rules.web`) replace entire blocks rather than field-level merging
- **Source Tracking**: Every configuration value includes source attribution and hierarchy level for full auditability
- **REST API Access**: `/api/v1/stewards/{id}/config/effective` endpoint provides merged configuration with inheritance metadata
- Tenant-aware RBAC with cascading permissions
- Efficient cross-tenant operations using path-based targeting
- Designed to handle 50k+ Stewards across multiple regions

## Current Development Status

See docs/product/roadmap.md and Github Project for current status.

## Project Management

### GitHub Project
The CFGMS development is managed through the **"CFGMS Development Roadmap"** GitHub Project at:
https://github.com/orgs/cfg-is/projects/1

This project board provides:
- **Roadmap Tracking**: Visual progress of major milestones and features
- **Issue Management**: Centralized tracking of bugs, features, and tasks
- **Sprint Planning**: Organized development cycles with clear priorities
- **Status Visibility**: Real-time project status and completion metrics

All development work should be tracked through this project board to ensure coordination and visibility across the team.

### Project Status Flow
The project follows a structured milestone progression workflow:

**Status Definitions:**
- **Done**: Completed work items
- **In Progress**: Current active development
- **Todo**: Next milestone items ready to start immediately
- **Backlog**: Future milestone items planned but not immediate

**Milestone Transitions:**
1. **Milestone Completion**: When a milestone (e.g., v0.1.0) is completed:
   - Move next milestone issues (e.g., v0.2.0) from "Backlog" → "Todo"
   - Create following milestone issues (e.g., v0.3.0) and place in "Backlog"

2. **Benefits of This Approach**:
   - Clear focus on current priorities without scope creep
   - Manageable scope with only one milestone in "Todo" at a time
   - Continuous planning maintains forward momentum
   - Always one milestone ahead in planning for roadmap adjustments

**Current Development**: See roadmap.md and GitHub Project for current milestone status and progress.

This workflow ensures sustainable development rhythm with clear prioritization and forward visibility.

### GitHub CLI Project Management

The project uses GitHub CLI (`gh`) for project management automation. For detailed commands and operational patterns, see **[docs/github-cli-reference.md](docs/github-cli-reference.md)**.

---

## Dependencies
- `github.com/spf13/cobra` - CLI framework
- `github.com/stretchr/testify` - Testing utilities
- `google.golang.org/grpc` - gRPC communication
- `google.golang.org/protobuf` - Protocol buffer support