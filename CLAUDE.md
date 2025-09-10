# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CFGMS (Config Management System) is a modern, Go-based configuration management system designed with resilience, security, and clean architecture principles. The project implements a zero-trust security model with mutual TLS authentication and follows a feature-based organization structure.

### Platform Support
**Steward (Agent) Support:**
- Linux: AMD64 & ARM64 - Full cross-distribution support
- Windows: AMD64 & ARM64 - Windows 10/11, Server 2019+
- macOS: ARM64 (M series) - Apple Silicon Macs

**Controller Support:**
- Linux: AMD64 - Primary target for production deployments  
- Windows: AMD64 - Development and testing environments

**Cross-Platform Development:** All components compile and run on developer workstations across Windows, macOS, and Linux for seamless development experience.

## Development Workflow

### Sprint and Development Process
- **Sprint Planning Guideline**: At the start of each milestone, ALWAYS conduct sprint/story planning before beginning work
- **Sprint Completion**: At the end of each sprint, run `make test-ci` to validate all stories and ensure system integrity before sprint closure

### MANDATORY Story Development Checklist

**BEFORE STARTING ANY CODE:**

0. **Run FULL test suite**
   Do not start working on a new feature until all issues (test, linting, and security) have been fixed. From this point forward you will be responsible for ANY issues that show up in your feature branch

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
   - **CRITICAL**: Never mock CFGMS functionality - test the actual program using real components
   - Use real memory stores, real session creation, real component integration
   - Only mock external dependencies we don't control (network, file I/O)
   - Run tests frequently: `make test`

**STORAGE DEVELOPMENT CHECKLIST** (Required for any storage-related work):
   - ✅ **EPIC 6 COMPLETED**: Global storage migration complete - all components use pluggable storage
   - ❌ **STOP**: Am I storing secrets in cleartext anywhere? (PROHIBITED)
   - ✅ **VERIFY**: Does my component use write-through caching (memory → durable)?
   - ✅ **VERIFY**: Does my component import only `pkg/storage/interfaces`?
   - ✅ **VERIFY**: Does my implementation work with ALL global storage providers (git/database/memory)?
   - ✅ **VERIFY**: Does my test use proper storage configuration in test helpers?

4. **Basic Security Review** (CRITICAL)
   
   Perform initial security validation during development:
   - No hardcoded secrets, passwords, or keys in code
   - SQL queries use parameterized statements (no string concatenation)
   - File operations use validated paths (prevent directory traversal)
   - Input validation present for user-provided data
   - Error messages don't expose sensitive information
   - Tenant isolation maintained (no cross-tenant data leaks)
   
   **Note**: Comprehensive security review occurs during PR review phase with fresh context.
   
   **Action Required:** If ANY critical security issues are found, STOP and fix them before proceeding.

**BEFORE ANY COMMITS:**

5. **STOP - Run Full Test Suite** (MANDATORY)
   ```bash
   make test  # MUST pass 100% before proceeding
   ```
   **ZERO TOLERANCE POLICY**: 
   - If ANY tests fail, STOP immediately and fix them before continuing
   - This includes ALL unrelated test failures - fix them or the story cannot proceed
   - NO exceptions, NO workarounds, NO "fix later" - tests MUST be 100% green
   - Stories cannot be marked 'Done' or merged with ANY failing tests
   - Bypassing this requirement violates the development workflow

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
make test-commit  # Runs: test + lint + security-scan + M365-dev (skips if no creds)
```
This ensures optimal order and provides clear validation status. M365 tests are skipped gracefully if credentials are not available.

**COMMIT AND PROJECT MANAGEMENT:**

8. **Commit Feature Work**
   ```bash
   git add .
   git commit -m "Implement Story #[NUMBER]: [description]

   Basic Security Review: [Brief summary - no hardcoded secrets, SQL injection prevention, input validation present]"
   ```

9. **Update Documentation** (REQUIRED)
   - Update `docs/product/roadmap.md` if needed
   - Update `CLAUDE.md` if workflow/commands changed
   - For M365/MSP features, ensure `docs/M365_INTEGRATION_GUIDE.md` is current

10. **Final Test Run - COMPLETION GATE** (MANDATORY)
    ```bash
    make test-commit  # MUST be 100% green before marking story complete
    ```
    **COMPLETION GATE**: This is the final validation before marking story complete. If ANY tests fail here:
    - DO NOT update GitHub project status
    - DO NOT update roadmap  
    - DO NOT merge
    - Fix all failures first, then restart from this step

11. **Update GitHub Project Status** (MANDATORY - ONLY AFTER TESTS PASS)
    ```bash
    # ONLY proceed if step 10 test run passed 100%
    # ALWAYS review docs/github-cli-reference.md FIRST before any gh project commands
    # This document contains the exact project IDs, field IDs, and option IDs required
    # Never guess or use generic commands - use the documented patterns
    
    # Example workflow:
    # 1. Check docs/github-cli-reference.md for current project details
    # 2. Add issues to project: gh project item-add 1 --owner cfg-is --url "URL"
    # 3. Update status: Use exact IDs from documentation
    # 4. Move story from "In Progress" to "Done" using documented commands
    ```

12. **Update Roadmap** (MANDATORY - ONLY AFTER TESTS PASS)
    ```bash
    # ONLY proceed if step 10 test run passed 100%
    # Update docs/product/roadmap.md to reflect story completion
    # Mark the completed story with ✅ and update progress
    # Update milestone completion percentage if applicable
    # This ensures roadmap stays current with actual development progress
    ```

13. **Create Pull Request for Code Review**
    ```bash
    # Push feature branch to remote
    git push origin feature/story-[NUMBER]-[brief-description]
    
    # Create pull request using GitHub CLI
    gh pr create --base develop --title "Implement Story #[NUMBER]: [description]" --body "$(cat <<'EOF'
    ## Summary
    [Brief description of the changes]
    
    ### Changes Made
    - [List key changes]
    - [Include any breaking changes]
    
    ### Test Results  
    ✅ All tests passing
    ✅ Security scan clean
    ✅ Linting passed
    
    ### Basic Security Review
    [Brief summary - no hardcoded secrets, SQL injection prevention, input validation present]
    
    🤖 Generated with [Claude Code](https://claude.ai/code)
    
    Co-Authored-By: Claude <noreply@anthropic.com>
    EOF
    )"
    
    # MANDATORY: Objective PR Review (see PR Review Process section)
    # After comprehensive review approval, merge the PR
    gh pr merge --merge
    
    # Clean up local feature branch after merge
    git checkout develop
    git pull origin develop  # Get the merged changes
    git branch -D feature/story-[NUMBER]-[brief-description]  # Delete local feature branch
    ```

**Benefits of PR-Based Workflow:**
- **Code Review Trail**: Permanent record of changes and review discussions
- **CI/CD Integration**: GitHub Actions run automatically on PRs before merge
- **Quality Gates**: Can enforce status checks, approvals, and branch protection
- **Documentation**: PR descriptions provide context for future reference
- **Team Collaboration**: Enables review comments and suggestions
- **Rollback History**: Easy to identify and revert specific features

**When to Use PRs vs Direct Commits:**
- **ALWAYS use PRs for**: Feature development, bug fixes, refactoring, architectural changes
- **Optional for**: Minor documentation updates, typo fixes, CLAUDE.md workflow updates
- **Direct commits allowed for**: Emergency hotfixes (followed by retroactive PR documentation)

## PR Review Process (MANDATORY)

**CRITICAL**: All PRs must undergo systematic review with fresh context to ensure objectivity and catch issues missed during development.

### Pre-Review Setup
1. **Clear All Context**: Start fresh Claude Code session or clear conversation history
2. **Review Environment**: Open PR in GitHub web interface for full context
3. **Access Documentation**: Have CLAUDE.md, security requirements, and architecture docs available

### Structured Review Methodology

**Phase 1: PR Overview Assessment**
```
Prompt: "Review this GitHub PR for CFGMS project. Analyze the PR description, title, and overall scope. Identify any missing information or unclear objectives."

Key Questions:
- Does the PR clearly state its purpose and scope?
- Are breaking changes properly documented?
- Is the security review status clear?
- Are test results validated and documented?
```

**Phase 2: Code Quality & Security Review**
```
Prompt: "Act as a senior Go developer and security expert. Perform a comprehensive code review focusing on:

SECURITY (CRITICAL):
- Authentication/Authorization bypass potential
- Input validation and injection prevention  
- Cryptographic implementation correctness
- Information disclosure risks
- CFGMS-specific tenant isolation
- Certificate and mTLS validation

CODE QUALITY:
- Go best practices and idioms
- Error handling completeness
- Resource management (defer, cleanup)
- Race condition potential
- Performance implications
- Interface design and dependency injection

ARCHITECTURE COMPLIANCE:
- Follows CFGMS pluggable architecture patterns
- Proper interface usage vs direct imports
- Module system compliance
- Zero-trust security model adherence"
```

**Phase 3: Testing & Validation Review**
```
Prompt: "Validate the testing approach and coverage:

TESTING VALIDATION:
- Are tests testing actual functionality vs mocks?
- Is error path testing comprehensive?
- Are integration tests covering component interactions?
- Is race condition testing adequate?
- Are security edge cases tested?

TEST QUALITY:
- Table-driven test patterns used correctly?
- Test data realistic and comprehensive?
- Cleanup and resource management in tests?
- Performance/benchmark testing where needed?"
```

**Phase 4: Documentation & Integration Review**
```
Prompt: "Review documentation and integration aspects:

DOCUMENTATION:
- Are exported functions/types properly documented?
- Is architectural context explained?
- Are breaking changes clearly documented?
- Is usage guidance provided?

INTEGRATION:
- Will this change affect existing components?
- Are database migrations handled properly?
- Are configuration changes backward compatible?
- Is deployment impact assessed?"
```

**Phase 5: Final Approval Checklist**
```
REQUIRED BEFORE MERGE:
□ All security concerns addressed or documented as accepted risks
□ Code follows CFGMS architecture patterns and Go best practices
□ Tests provide adequate coverage of new functionality
□ Breaking changes are properly documented and justified
□ Performance impact assessed for production workloads
□ Documentation updated for any API/interface changes
□ CI/CD validation passes (tests, security scans, linting)
□ Deployment impact reviewed and mitigation planned
```

### Review Completion
Only after ALL phases pass and checklist is complete should the PR be merged. Document any concerns or accepted risks in PR comments.

**VALIDATION CHECKPOINTS:**
- Verify branch was created: `git log --oneline -5`
- **Verify tests pass: `make test` - NO FAILING TESTS ALLOWED**
- Verify security scan passes: `make security-scan`
- Verify project updated: Check GitHub project board
- **Verify roadmap updated: Check docs/product/roadmap.md shows story completion**
- **Verify PR created**: `gh pr view --json title,state,url`
- **Verify PR reviewed using structured methodology**: All 5 review phases completed
- **Verify PR merged**: `gh pr list --state merged --limit 5`
- **Verify feature branch cleaned up**: `git branch -a | grep feature/story-[NUMBER]` (should be empty)
- **BLOCKING REQUIREMENT**: ALL validation checkpoints must pass before story completion

**GITHUB ACTIONS CI/CD:**
- **Security Scanning Workflow**: Automatic security validation on push/PR
- **Production Deployment Gates**: Critical vulnerabilities block main branch deployment
- **Automated Remediation**: Download artifacts and use Claude Code for automatic fixes
- **Manual Trigger**: Use workflow_dispatch for specific scan types (quick/full/remediation-report)

## Development Commands

### Building
```bash
# Build all binaries (current platform)
make build

# Build individual components (current platform)
make build-controller  # Builds controller binary
make build-steward     # Builds steward binary  
make build-cli         # Builds cfgctl CLI binary

# Cross-platform builds for all supported platforms
# Steward cross-compilation
GOOS=linux GOARCH=amd64 go build -o bin/cfgms-steward-linux-amd64 ./cmd/steward
GOOS=linux GOARCH=arm64 go build -o bin/cfgms-steward-linux-arm64 ./cmd/steward
GOOS=windows GOARCH=amd64 go build -o bin/cfgms-steward-windows-amd64.exe ./cmd/steward
GOOS=windows GOARCH=arm64 go build -o bin/cfgms-steward-windows-arm64.exe ./cmd/steward
GOOS=darwin GOARCH=arm64 go build -o bin/cfgms-steward-darwin-arm64 ./cmd/steward

# Controller cross-compilation
GOOS=linux GOARCH=amd64 go build -o bin/controller-linux-amd64 ./cmd/controller
GOOS=windows GOARCH=amd64 go build -o bin/controller-windows-amd64.exe ./cmd/controller
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

### Streamlined Testing Workflow

**Daily Development (3 targets):**
```bash
# Fast TDD feedback (30s) - mocked M365 tests
make test

# Pre-commit validation (2-3min) - gracefully skips M365 if no credentials
make test-commit

# CI validation (8-12min) - fails if M365 credentials missing
make test-ci
```

**Specialized Testing:**
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

**M365 Credential Handling:**
- **`test`**: Uses mocked M365 tests only
- **`test-commit`**: Skips M365 tests if credentials unavailable (developer-friendly)
- **`test-ci`**: Requires M365 credentials or fails (CI enforcement)

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

#### Security Exception Policy (gosec)

**Configuration File (.gosec.json)**:
- Use ONLY for project-wide rule suppression that applies to entire codebase
- Use ONLY for excluding non-production directories (test/, examples/, vendor/)
- Use ONLY for excluding generated files (*.pb.go)
- Never exclude production code files via configuration

**Inline Exclusions (Production Code)**:
- All production code security exceptions MUST use inline `#nosec` comments
- Each exclusion MUST include business justification
- Use specific rule codes (e.g., `#nosec G204`) rather than blanket exclusions
- Format: Comment must be on the line BEFORE the flagged code
- Use: `// #nosec G204 - Business justification for why this is necessary`

**Examples**:
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

### **CFGMS Controller: Two Interaction Points with External World**

**FUNDAMENTAL PRINCIPLE**: The controller has exactly **TWO ways** to interact with the outside world:

#### **1. Workflow Engine (SaaS/Cloud Operations)**
- **Purpose**: Manages SaaS and cloud-based resources through API calls
- **Examples**: Microsoft 365, AWS, Azure, Google Workspace operations
- **Implementation**: SaaS Stewards built on top of workflow engine
- **Modules**: `entra_user`, `entra_group`, `conditional_access`, `intune_policy`
- **Authentication**: OAuth2, API keys, service principals
- **Execution**: Centralized at controller level

#### **2. Stewards (Endpoint Operations)** 
- **Purpose**: Manages resources on individual endpoints (Windows, macOS, Linux)
- **Examples**: Files, firewall rules, packages, local AD operations
- **Implementation**: Endpoint Stewards deployed to managed systems
- **Modules**: `file`, `firewall`, `package`, `script`, `directory`, `activedirectory`
- **Authentication**: mTLS certificates
- **Execution**: Distributed to endpoint systems

**CRITICAL ARCHITECTURAL RULE**: 
- **SaaS/Cloud Resources** → Workflow Engine → SaaS Modules
- **Endpoint Resources** → Stewards → Endpoint Modules
- **Never Mix**: Don't put SaaS operations in endpoint modules or endpoint operations in SaaS modules

**Security:**
- Zero-trust security model with mutual TLS for all internal communication
- Certificate-based authentication for stewards
- Optional OpenZiti integration for zero-trust networking
- Role-based access control (RBAC) with hierarchical permissions

### Module System & Controller-Steward Architecture

CFGMS follows a **clear separation of concerns** between the Controller and Stewards:

#### **Controller Role: Unified Abstractions & Orchestration**
- **Central Management**: Provides unified interfaces for complex operations (directory management, tenant hierarchy)
- **Cross-System Coordination**: Manages operations that span multiple endpoints or systems
- **Policy & RBAC**: Enforces access controls and configuration inheritance
- **SaaS Integration**: Routes SaaS operations through workflow engine to appropriate modules
- **Abstraction Layer**: Presents simplified interfaces that hide provider-specific complexity

#### **Steward Role: Endpoint Resource Management** 
- **Local Operations**: Manages resources on individual endpoints (Windows, macOS, Linux)
- **Resource Modules**: Implements modules for endpoint-specific resources (`file`, `firewall`, `package`, `script`)
- **State Enforcement**: Executes configuration changes and maintains desired state
- **Monitoring**: Reports resource state changes back to controller
- **Cross-Platform**: Same steward binary works across all supported platforms

#### **Module Interface Pattern**
All resource management is performed through modules that implement the core interface:
- `Get(ctx, resourceID)` - Returns current configuration as ConfigState
- `Set(ctx, resourceID, config)` - Updates resource to match desired state (managed fields only)
- **System Testing**: Steward automatically compares current vs desired state using managed fields
- `Monitor(ctx, resourceID, config)` - **(Optional)** Real-time event-driven monitoring via separate interface

**ConfigState Interface**: Enables efficient field-level comparison without marshal/unmarshal overhead. Modules return comprehensive system state, but only managed fields are modified.

#### **Module Categories & Deployment**

**Endpoint Modules** (Deployed to Stewards):
- `directory` - Local filesystem directories
- `file` - File management and templating
- `firewall` - Local firewall rules
- `package` - Software package management
- `script` - Script execution and management
- `activedirectory` - AD operations for domain-joined systems

**SaaS Modules** (Executed via Controller Workflow Engine):
- `entra_user` - Microsoft Entra ID user management
- `entra_group` - Microsoft Entra ID group management
- `conditional_access` - Conditional access policies
- `intune_policy` - Intune device configuration

**Controller Service Modules** (Unified Abstractions):
- `directory` service - Unified interface over multiple directory providers
- `tenant` service - Multi-tenant configuration management
- `rbac` service - Role-based access control

### Pluggable Infrastructure Design Paradigm
CFGMS follows a **pluggable architecture** where infrastructure components are built with abstraction interfaces, enabling flexible backend selection without core system changes.

**Core Principle**: *Any infrastructure component that could reasonably have multiple implementations should be designed with a provider interface from the start.*

**Architecture Pattern: Global Controller Storage**
- **Controller-Level Decision**: Single storage provider choice affects entire system
- **All Modules Use Same Backend**: No per-module storage configuration needed  
- **Interface Injection**: Modules receive interfaces, never import specific providers
- **Discovery**: Providers auto-register via `init()` functions
- **Simple Configuration**: One setting: `controller.storage.provider: "database"`

**Directory Structure:**
```
pkg/
├── storage/                   # Global storage system
│   ├── interfaces/           # Storage contracts (used by all modules)
│   │   ├── client_tenant.go # MSP client tenant storage
│   │   ├── config.go        # Configuration storage  
│   │   └── audit.go         # Audit log storage
│   └── providers/           # Durable storage implementations only
│       ├── database/        # Database provider (PostgreSQL)
│       └── git/             # Git provider with SOPS encryption
```

**Component-Level Memory Optimization:**
```
features/[component]/
├── cache/                   # Component-specific memory caching
├── manager.go              # Uses durable storage + memory optimization
└── interfaces.go           # Component interfaces (not storage providers)
```

**Current Pluggable Components:**
- **Storage Providers**: `StorageProvider` interface creates all storage interfaces (durable, encrypted implementations)
- **Git Providers**: `GitProvider` interface (GitHub, GitLab, Bitbucket)  
- **Compression**: `Compressor` interface (GZIP, ZSTD, LZ4)
- **KMS Providers**: `KMSProvider` interface (Vault, AWS KMS, Azure Key Vault)
- **Encryption Providers**: `EncryptionProvider` interface (SOPS, native encryption backends)

**Configuration Flow:**
```
cfgms.yaml (controller.storage.provider: "database")
    ↓
Controller creates DatabaseProvider 
    ↓  
All storage interfaces use database:
  ├── ClientTenantStore → PostgreSQL tables
  ├── ConfigStore → PostgreSQL tables  
  └── AuditStore → PostgreSQL tables
    ↓
Modules get injected with interfaces (don't know it's PostgreSQL)
```

**Deployment Flexibility (Default: Git with SOPS):**
- **POC/Small MSP**: Global storage provider with auto-generated encryption (local), no external dependencies  
- **Simple Deployment**: Global storage provider with encryption key management
- **Distributed Teams**: Global storage provider with shared encryption keys and remote backup
- **Production**: Global storage provider with managed infrastructure or distributed storage
- **Enterprise**: Global storage provider with external KMS integration

**CRITICAL SAFETY REQUIREMENTS:**
1. **Memory Provider Eliminated**: ✅ **COMPLETED in Epic 6** - Memory provider has been eliminated from global storage provider choices. Components now implement internal write-through caching directly for performance optimization with durable storage backends.
2. **Encryption by Default**: All storage providers ALWAYS use encryption. Cleartext secrets on disk are prohibited in all deployment scenarios for security and compliance.

**Plugin Development Guidelines:**
- Each provider implements ALL storage interfaces for consistency
- Plugins auto-register via `init()` functions in `pkg/storage/providers/[name]/plugin.go`
- Business logic imports `pkg/storage/interfaces` only, never specific providers
- Configuration validation and dependency checking handled by provider plugins

**Documentation**: See `docs/architecture/plugin-architecture.md` for complete implementation guide.

This paradigm ensures CFGMS can scale from simple deployments to enterprise infrastructure without architectural refactoring, while maintaining consistency across all storage operations.

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
- `pkg/` - Shared packages and global plugin interfaces
  - `pkg/storage/interfaces/` - Global storage contracts (imported by all modules)
  - `pkg/storage/providers/` - Storage plugin implementations (auto-discovered)
  - `pkg/directory/types/` - Unified directory object types (DirectoryUser, DirectoryGroup)
- `features/` - Business logic using global plugin interfaces only
  - `features/controller/` - Controller-specific services and abstractions
    - `features/controller/directory/` - Unified directory service interface
  - `features/steward/` - Steward-specific functionality
  - `features/modules/` - Module implementations
- `test/` - Integration and end-to-end tests
- `docs/` - Comprehensive documentation including architecture and standards

#### **Anti-Pattern: Code Duplication Across Layers**
**AVOID**: Creating separate representations of the same data across different components:
```go
// WRONG - Multiple representations of users
pkg/directory/interfaces/provider.go: type DirectoryUser struct {...}
features/modules/m365/graph/client.go: type User struct {...}  
features/modules/m365/entra_user/module.go: type EntraUserConfig struct {...}
```

**CORRECT**: Single canonical type with conversion methods:
```go
// RIGHT - Single source of truth with conversions
pkg/directory/types/user.go: type DirectoryUser struct {...}
// + conversion methods: ToGraphUser(), FromGraphUser(), ToEntraUserConfig()
```

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

### Testing Approach - POST-EPIC-6
- **TDD**: Write table-driven tests before implementation
- **Real Component Testing**: **NEVER mock CFGMS functionality in tests - test the actual program**
  - Use real memory stores (e.g., `memory.NewStore()`) instead of mocking RBAC interfaces
  - Use real session creation (`NewSession()`) instead of mock session managers
  - Use real component integration instead of simulated behavior
  - Only mock external dependencies that we don't control (network calls, file I/O)
  - Integration tests must demonstrate actual system functionality, not theoretical behavior
- **Storage Configuration Required**: All tests that create controllers must include storage configuration
  - Integration tests: Use Git provider with temporary directories
  - Performance tests: Use Git provider with disabled encryption
  - Unit tests: Use memory stores for isolated component testing
  - **Test Helper Fixed**: `test/integration/testutil/test_helper.go` and `test/e2e/framework.go` updated with storage config
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

### Module Development Guidelines

#### **Architectural Decision: Controller vs Steward Module Placement**

**CRITICAL**: Before developing any module, determine the correct deployment location:

#### **Deploy to Controller When:**
- **Cross-System Operations**: Module manages resources across multiple endpoints
- **SaaS/Cloud APIs**: Module interacts with external APIs (Microsoft 365, AWS, etc.)
- **Complex Orchestration**: Operations require coordination between multiple systems
- **Centralized Policy**: Module enforces organization-wide policies or compliance
- **Data Aggregation**: Module collects and processes data from multiple sources

**Examples**: `entra_user`, `conditional_access`, `tenant_management`, `rbac_policies`

#### **Deploy to Steward When:**
- **Local Resources**: Module manages resources on individual endpoints
- **Platform-Specific**: Operations are Windows/macOS/Linux specific
- **Performance Critical**: Operations need low latency or offline capability  
- **Security Isolation**: Operations should be isolated to individual systems
- **Endpoint State**: Module maintains state of local system resources

**Examples**: `file`, `firewall`, `package`, `script`, `directory`, `activedirectory` (for domain-joined systems)

#### **Module Implementation Standards**
- Each module must be self-contained with clear ConfigState interface
- Implement Get/Set interface with ConfigState for all resource types
- **Optional Monitor interface** for real-time change detection via OS hooks
- Use idempotent operations and support offline operation
- Include proper error handling and comprehensive validation
- Get returns comprehensive state, Set modifies only managed fields
- Use GetManagedFields() to specify which fields Set will change

### Storage Architecture Requirements (CRITICAL) - EPIC 6 COMPLETE ✅

**POST-EPIC-6 STORAGE PATTERNS - ALL COMPONENTS MIGRATED:**

**Prohibited Patterns (ELIMINATED):**
- ✅ **ELIMINATED**: Memory as a global storage provider choice (Epic 6 Complete)
- ❌ Cleartext secrets on disk (even in development) - STILL PROHIBITED
- ❌ Component-specific storage provider selection - STILL PROHIBITED  
- ❌ Bypassing global storage configuration - STILL PROHIBITED

**Required Patterns:**
- ✅ Git with SOPS is the secure default provider (product decision)
- ✅ Memory used ONLY for internal component optimization
- ✅ All persistent data flows through global storage provider contract
- ✅ Write-through caching pattern (memory → global storage provider)

**Component Memory Optimization Pattern:**
```go
type ComponentManager struct {
    // Fast memory cache for performance
    cache        map[string]*Data
    cacheExpiry  time.Duration
    
    // Durable storage via global storage provider contract
    durableStore interfaces.ComponentStore
}

func (c *ComponentManager) Set(key string, data *Data) error {
    // 1. Write to durable storage first (fail-fast)
    if err := c.durableStore.Set(key, data); err != nil {
        return err
    }
    
    // 2. Update memory cache for performance
    c.cache[key] = data
    return nil
}
```

**Storage Provider Contract Requirements:**
- All deployments (POC → Enterprise) use encrypted durable storage
- Global storage provider automatically enables encryption by default
- All providers implement the same storage contract (durability, encryption, authentication, audit)
- No configuration option to disable encryption

#### **Controller Service Development**
When creating controller-level abstractions:
- **Unified Interfaces**: Create single interface that abstracts multiple providers
- **Provider Pattern**: Use pluggable providers for different backends
- **Graceful Degradation**: Handle provider-specific features transparently
- **Auto-Discovery**: Providers self-register via `init()` functions
- **Configuration Routing**: Route operations to appropriate modules/providers

#### **Common Architectural Confusion: Providers vs Modules**

**AVOID CONFUSION**: Understanding the difference between directory providers and storage providers:

**Directory Providers** (Business Logic):
- **Location**: `features/modules/m365/directory_provider.go`
- **Purpose**: Implement directory operations for specific systems (AD, Entra ID)
- **Interface**: `features/controller/directory.Provider`
- **Examples**: EntraIDDirectoryProvider, ActiveDirectoryProvider
- **Responsibility**: User/group management, authentication, directory-specific operations

**Storage Providers** (Infrastructure):
- **Location**: `pkg/storage/providers/[name]/plugin.go`
- **Purpose**: Persist data using different storage backends
- **Interface**: `pkg/storage/interfaces.StorageProvider`
- **Examples**: MemoryProvider, DatabaseProvider, GitProvider
- **Responsibility**: Data persistence, transactions, storage-specific operations

**KEY DISTINCTION**:
- **Directory Providers**: Handle WHAT data to manage (users, groups, policies)
- **Storage Providers**: Handle WHERE/HOW to store data (database, file, memory)
- **Controller Services**: Provide unified abstractions over multiple providers of the same type

### Storage Plugin Development
- **Golden Rule**: Business logic NEVER imports specific storage providers
- **Interface-Only Imports**: Modules import `pkg/storage/interfaces` only
- **Durable Only**: Only implement providers that guarantee persistence
- **Testing Strategy**: Test modules against all available storage providers automatically
- **Plugin Structure**: Each provider implements ALL storage interfaces (ClientTenantStore, ConfigStore, AuditStore)
- **Auto-Registration**: Providers register via `init()` functions - no manual registry needed
- **Configuration**: Controller selects provider globally via `controller.storage.provider` in YAML

## Branching Strategy & PR Process

Following GitFlow with **MANDATORY feature branch workflow**:

### Branch Hierarchy
- `main` - Production-ready code only (protected)
- `develop` - Integration branch for features (never delete)
- `feature/*` - New feature development (temporary)
- `fix/*` - Bug fixes (temporary)
- `docs/*` - Documentation updates (temporary)
- `refactor/*` - Code improvements (temporary)

### CRITICAL RULE: Never Create Direct develop→main PRs

**❌ WRONG (Will Delete Develop Branch):**
```bash
# On develop branch - DON'T DO THIS
gh pr create --base main --title "Epic Complete"  # ❌ Will delete develop!
```

**✅ CORRECT (Feature Branch Workflow):**
```bash
# ALWAYS create feature branch first
git checkout develop
git checkout -b feature/epic-4-unified-directory
git push origin feature/epic-4-unified-directory

# Create PR: feature → develop (for development)
gh pr create --base develop --title "Epic 4: Unified Directory Management"

# After develop integration, create PR: develop → main (for release)
git checkout develop
git pull origin develop  # Ensure develop has latest
gh pr create --base main --title "Release: Epic 4 to Production"
```

### PR Merge Settings (GitHub Repository Settings)
To prevent accidental branch deletion:
1. Go to GitHub → Repository → Settings → General
2. Under "Pull Requests" section:
   - ✅ Enable "Allow merge commits"
   - ❌ Disable "Automatically delete head branches" 
3. For develop branch specifically:
   - ✅ Enable branch protection
   - ✅ Require pull request reviews
   - ❌ Never allow deletion

### Safe Merge Commands
```bash
# Merge PR without deleting source branch
gh pr merge [PR_NUMBER] --merge --no-delete-branch

# Or use squash merge (preferred for clean history)
gh pr merge [PR_NUMBER] --squash --no-delete-branch
```

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