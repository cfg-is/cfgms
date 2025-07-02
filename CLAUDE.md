# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CFGMS (Config Management System) is a modern, Go-based configuration management system designed with resilience, security, and clean architecture principles. The project implements a zero-trust security model with mutual TLS authentication and follows a feature-based organization structure.

## Development Commands

### Building
```bash
# Build all binaries
make build

# Build individual components
make build-controller  # Builds controller binary
make build-agent       # Builds agent (steward) binary  
make build-cli         # Builds cfgctl CLI binary

# Alternative: direct Go build commands
go build -o bin/controller ./cmd/controller
go build -o bin/agent ./cmd/agent
go build -o bin/cfgctl ./cmd/cfgctl
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

### Three-Tier System
- **Controller**: Central management system for configuration distribution and tenant hierarchy management
- **Steward**: Cross-platform agent that executes configurations on managed endpoints
- **Outpost**: Proxy cache agent for network device monitoring and agentless management

### Module System
All resource management is performed through modules that implement the core interface:
- `Get(ctx, resourceID)` - Returns current configuration as YAML
- `Set(ctx, resourceID, configData)` - Updates resource to match desired state
- `Test(ctx, resourceID, configData)` - Validates current vs desired state
- `Monitor(ctx, resourceID, config)` - **(Optional)** Implements real-time event-driven monitoring using OS hooks and system events

**Monitor Functionality**: Modules should implement the Monitor method wherever possible to enable real-time configuration drift detection. This allows the steward to receive immediate notifications of configuration changes through:
- **OS Event Hooks**: Windows Event Log monitoring (e.g., Event 4720 for new user creation)
- **File System Triggers**: inotify/FileSystemWatcher for managed file changes
- **Registry Monitoring**: Windows registry change notifications
- **Service Events**: System service state changes
- **Network Events**: Interface configuration changes
- **Process Events**: Application installation/removal notifications

Example modules: `directory`, `file`, `firewall`, `package`

### Communication
- **Internal**: gRPC with mutual TLS between components
- **External**: REST API with HTTPS and API key authentication
- **Protocol Buffers**: Used for efficient data serialization

### Security Architecture
- Zero-trust security model with mutual TLS for all internal communication
- Certificate-based authentication for agents
- Optional OpenZiti integration for zero-trust networking
- Role-based access control (RBAC) with hierarchical permissions

## Code Organization

### Feature-Based Structure
```
features/
├── controller/    # Controller component and server logic
├── steward/       # Steward (agent) component with health monitoring
└── modules/       # Module implementations (directory, file, firewall, package)
```

### Key Directories
- `cmd/` - Command-line applications (controller, agent, cfgctl)
- `api/proto/` - Protocol buffer definitions for gRPC communication
- `pkg/` - Shared packages (logging utilities)
- `test/` - Integration and end-to-end tests
- `docs/` - Comprehensive documentation including architecture and standards

## Development Guidelines

### Go Standards
- Use Go 1.21+ features
- Follow dependency injection patterns
- No global variables or state
- Implement proper context cancellation
- Use structured logging with consistent fields
- Handle all errors explicitly
- Achieve 100% test coverage for core components

### Testing Approach
- **TDD**: Write table-driven tests before implementation
- **Coverage**: Aim for 100% test coverage on core components
- **Race Detection**: Always run tests with `-race` flag
- **Integration**: Test component interactions with real dependencies
- **Chaos Engineering**: Test resilience under failure conditions

### Security Requirements
- All network communication must use mTLS
- Implement proper input validation and sanitization
- Use secure defaults in all configurations
- Follow principle of least privilege
- Sanitize all logging output to prevent information leakage

### Module Development
- Each module must be self-contained with clear interfaces
- Implement Get/Set/Test interface for all resource types
- **Implement Monitor method where possible** for real-time change detection via OS hooks
- Use idempotent operations
- Support offline operation capability
- Include proper error handling and rollback mechanisms
- Add comprehensive validation and structured error types
- Monitor implementations should trigger workflows when configuration drift is detected

## Branching Strategy

Following GitFlow:
- `main` - Production-ready code only
- `develop` - Integration branch for features
- `feature/*` - New feature development
- `fix/*` - Bug fixes
- `docs/*` - Documentation updates
- `refactor/*` - Code improvements

## Multi-Tenancy
The system implements a recursive parent-child tenant model with:
- Hierarchical configuration inheritance
- Tenant-aware RBAC with cascading permissions
- Efficient cross-tenant operations using path-based targeting
- Designed to handle 50k+ Stewards across multiple regions

## Dependencies
- `github.com/spf13/cobra` - CLI framework
- `github.com/stretchr/testify` - Testing utilities
- `google.golang.org/grpc` - gRPC communication
- `google.golang.org/protobuf` - Protocol buffer support