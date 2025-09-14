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

### Slash Commands (Automated Workflow)
Use these commands to enforce mandatory development workflow:

- **`/story-start`** - Begin new story with pre-flight checks and roadmap auto-detection
- **`/story-commit`** - Commit with validation and GitHub issue progress tracking
- **`/story-complete`** - Complete story with final validation gates and PR creation
- **`/pr-create`** - Alias for `/story-complete` (same functionality)
- **`/pr-review [number]`** - Execute structured 5-phase PR review methodology
- **`/dev-status`** - Quick development environment and current story status

See `.claude/slash-commands/` for complete documentation.

### Critical Development Rules (MANDATORY)

#### Zero Tolerance Policies
- **No Failing Tests**: Cannot start new work or commit with ANY test failures
- **Security Gates**: All security scans must pass before commits
- **Feature Branches**: Always use `feature/story-[NUMBER]-[description]` branches
- **Real Component Testing**: Never mock CFGMS functionality in tests - use real components

#### EPIC 6 Complete: Storage Architecture (CRITICAL)
- ✅ **Memory provider eliminated** from global storage choices
- ✅ **All components migrated** to pluggable storage architecture
- **Required Pattern**: Write-through caching (memory → durable storage)
- **Import Rule**: Business logic imports `pkg/storage/interfaces` ONLY
- **Prohibited**: Cleartext secrets on disk (even in development)

### Manual Workflow (When Not Using Slash Commands)

#### Essential Steps
1. **Pre-flight**: Run `make test` - must pass 100% before starting
2. **Branch**: Create `feature/story-[NUMBER]-[description]` from develop
3. **Develop**: Write tests first, implement with TDD approach
4. **Commit**: Run `make test-commit` - blocks on any failures
5. **Complete**: Create PR and update project status

See [docs/development/story-checklist.md](docs/development/story-checklist.md) for complete manual checklist.

## Essential Commands

### Daily Development
```bash
make test           # Run tests (must pass before commits)
make test-commit    # Pre-commit validation (tests + security + lint)
make security-scan  # Security checks (blocking on critical/high)
make lint          # Code quality validation
```

### Building
```bash
make build                # All binaries (current platform)
make build-controller     # Controller binary only
make build-steward        # Steward binary only
```

### Validation Targets
```bash
make test-ci       # Complete CI validation (8-12min)
make test-integration  # M365 + storage integration tests
```

See [docs/development/commands-reference.md](docs/development/commands-reference.md) for all commands.

## Core Architecture

### System Design
**Three-Tier System:**
- **Controller**: Central management, SaaS operations via workflow engine
- **Steward**: Endpoint management, local operations on devices
- **Outpost**: Proxy cache component for network device monitoring

**Communication:**
- **Internal**: gRPC with mutual TLS between components
- **External**: REST API with HTTPS and API key authentication

### Module Deployment Decision Matrix

**Deploy to Controller When:**
- Cross-system operations or SaaS/Cloud APIs
- Microsoft 365, AWS, Azure integrations
- Organization-wide policies or compliance

**Deploy to Steward When:**
- Local resources (files, packages, firewall)
- Platform-specific operations
- Performance critical or offline capability

**Examples:**
- Controller: `entra_user`, `conditional_access`, `tenant_management`
- Steward: `file`, `firewall`, `package`, `script`, `directory`

### Storage Architecture (EPIC 6 Complete ✅)
- **Global Storage Provider**: Single choice affects entire system (git/database)
- **Pluggable Design**: All components use same storage interfaces
- **Default**: Git with SOPS encryption for security and GitOps workflows
- **Memory Usage**: Internal component optimization only (write-through caching)
- **Security**: All providers ALWAYS use encryption - no cleartext secrets

## Critical Development Rules

### Must Follow
- **TDD with Real Components**: Test actual program, not mocks
- **Zero Failing Tests**: 100% pass rate required before any commits
- **Security First**: All scans pass, no hardcoded secrets
- **Pluggable Storage**: Import `pkg/storage/interfaces` only
- **Feature Branches**: Never commit directly to develop/main
- **Tenant Isolation**: Maintain strict tenant boundaries

### Security Requirements
- Mutual TLS for all internal communication
- Input validation and sanitization for all user data
- SQL injection prevention (parameterized queries only)
- No information disclosure in error messages
- Proper certificate and key management

### Testing Standards
- Write tests first (TDD approach)
- Use real CFGMS components, not mocks
- Test error paths and race conditions
- Include security edge case testing
- Achieve 100% coverage for core components

## Code Organization

### Directory Structure
```
cmd/           # Command-line applications (controller, steward, cfgctl)
api/proto/     # Protocol buffer definitions
pkg/           # Shared packages and global plugin interfaces
  storage/interfaces/  # Global storage contracts (import these)
  storage/providers/   # Storage implementations (don't import)
features/      # Business logic using global plugin interfaces
test/          # Integration and end-to-end tests
docs/          # Comprehensive documentation
```

### Anti-Patterns to Avoid
- Multiple representations of same data across components
- Direct import of storage providers in business logic
- Mocking CFGMS components in tests
- Storing cleartext secrets anywhere
- Bypassing global storage configuration

## Quick Reference

### Documentation
- **Story Development**: [docs/development/story-checklist.md](docs/development/story-checklist.md)
- **PR Reviews**: [docs/development/pr-review-methodology.md](docs/development/pr-review-methodology.md)
- **All Commands**: [docs/development/commands-reference.md](docs/development/commands-reference.md)
- **Git Workflow**: [docs/development/git-workflow.md](docs/development/git-workflow.md)
- **Architecture**: [docs/architecture/](docs/architecture/)
- **Roadmap**: [docs/product/roadmap.md](docs/product/roadmap.md)

### Project Management
- **GitHub Project**: https://github.com/orgs/cfg-is/projects/1
- **Issues & PRs**: All development tracked through GitHub
- **Roadmap Status**: See docs/product/roadmap.md for current progress

### Development Approach
- **Sprint Planning**: Always conduct sprint planning before milestones
- **AI Integration**: Use slash commands for workflow automation
- **Quality Gates**: Tests, security, and linting must pass
- **Continuous Deployment**: GitHub Actions with production gates

## Multi-Tenancy & Configuration

The system implements recursive parent-child tenant model:
- **Hierarchical Inheritance**: MSP → Client → Group → Device (4 levels)
- **Declarative Merging**: Named resources replace entire blocks
- **Source Tracking**: Full auditability of configuration sources
- **Scale**: Designed for 50k+ Stewards across multiple regions

## Dependencies
- `github.com/spf13/cobra` - CLI framework
- `github.com/stretchr/testify` - Testing utilities
- `google.golang.org/grpc` - gRPC communication
- `google.golang.org/protobuf` - Protocol buffer support

---

*For complete development workflow automation, use the slash commands in `.claude/slash-commands/`. For manual processes, see the detailed guides in `docs/development/`.*