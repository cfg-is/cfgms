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
make build-steward     # Builds steward binary  
make build-cli         # Builds cfgctl CLI binary

# Alternative: direct Go build commands
go build -o bin/controller ./cmd/controller
go build -o bin/cfgms-steward ./cmd/steward
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
- **Steward**: Cross-platform component that executes configurations on managed endpoints
- **Outpost**: Proxy cache component for network device monitoring and agentless management

### Module System
All resource management is performed through modules that implement the core interface:
- `Get(ctx, resourceID)` - Returns current configuration as ConfigState
- `Set(ctx, resourceID, config)` - Updates resource to match desired state (managed fields only)
- **System Testing**: Steward automatically compares current vs desired state using managed fields
- `Monitor(ctx, resourceID, config)` - **(Optional)** Real-time event-driven monitoring via separate interface

**ConfigState Interface**: Enables efficient field-level comparison without marshal/unmarshal overhead. Modules return comprehensive system state, but only managed fields are modified.

Available modules: `directory`, `file`, `firewall`, `package`

### Communication
- **Internal**: gRPC with mutual TLS between components
- **External**: REST API with HTTPS and API key authentication
- **Protocol Buffers**: Used for efficient data serialization

### Security Architecture
- Zero-trust security model with mutual TLS for all internal communication
- Certificate-based authentication for stewards
- Optional OpenZiti integration for zero-trust networking
- Role-based access control (RBAC) with hierarchical permissions

## Code Organization

### Feature-Based Structure
```
features/
├── controller/    # Controller component and server logic
├── steward/       # Steward component with health monitoring
└── modules/       # Module implementations (directory, file, firewall, package)
```

### Key Directories
- `cmd/` - Command-line applications (controller, steward, cfgctl)
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
- All network communication must use mTLS
- Implement proper input validation and sanitization
- Use secure defaults in all configurations
- Follow principle of least privilege
- Sanitize all logging output to prevent information leakage

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

## Multi-Tenancy
The system implements a recursive parent-child tenant model with:
- Hierarchical configuration inheritance
- Tenant-aware RBAC with cascading permissions
- Efficient cross-tenant operations using path-based targeting
- Designed to handle 50k+ Stewards across multiple regions

## Current Development Status

### 🔄 IN PROGRESS - Basic Steward Core (Issue #13)
Currently implementing the basic steward core functionality:
- [ ] Implement steward lifecycle (startup, shutdown)
- [ ] Implement health monitoring and self-healing
- [ ] Implement basic module execution
- [ ] Implement configuration application
- [ ] Implement basic gRPC communication with controller
- [ ] Implement simple authentication
- [ ] Implement error handling and logging

### 📋 NEXT - Basic Controller Functionality (Issue #14)
After completing the basic steward core, the next priority is implementing basic controller functionality.

### 🎯 Module System Foundation (Issue #17 - COMPLETED ✅)
The module system framework has been implemented and provides:
- **Module Discovery**: Filesystem scanning with metadata parsing and validation
- **Module Factory/Registry**: Instance caching and management with initialization handling
- **Configuration Manager**: Complete hostname.cfg parsing with validation framework
- **Execution Engine**: Full Get→Compare→Set→Verify workflow with ConfigState intelligence
- **System Testing**: Field-level comparison using GetManagedFields() for efficient updates
- **Error Handling**: Comprehensive policies with configurable retry mechanisms
- **CLI Interface**: Standalone operation with full command-line interface
- **Health Monitoring**: Self-contained monitoring with metrics collection

All modules (directory, file, firewall, package) implement the ConfigState interface and work seamlessly in both standalone and controller-managed modes.

## Dependencies
- `github.com/spf13/cobra` - CLI framework
- `github.com/stretchr/testify` - Testing utilities
- `google.golang.org/grpc` - gRPC communication
- `google.golang.org/protobuf` - Protocol buffer support