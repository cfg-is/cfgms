# Directory Structure

This document outlines the directory structure of the CFGMS codebase, explaining the organization and purpose of each directory.

## Overview

CFGMS follows a feature-based organization rather than a technical layer-based organization. This approach keeps all code related to a feature (implementation, tests, errors, interfaces) in a single package, making it easier to understand and maintain.

## Root Directory Structure

```txt
cfgms/
├── cmd/                  # Command-line applications
│   ├── controller/       # Controller application
│   ├── steward/          # Steward application
│   └── outpost/          # Outpost application
├── internal/             # Private implementation packages
│   ├── core/             # Core functionality
│   ├── modules/          # Module implementations
│   ├── security/         # Security implementations
│   ├── storage/          # Storage implementations
│   ├── workflow/         # Workflow engine
│   └── tenant/           # Multi-tenancy implementation
├── pkg/                  # Public packages
│   ├── api/              # Public API definitions
│   ├── config/           # Configuration types and utilities
│   ├── module/           # Module interfaces and utilities
│   └── workflow/         # Workflow interfaces and utilities
├── docs/                 # Documentation
├── scripts/              # Build and deployment scripts
├── test/                 # Integration tests
└── tools/                # Development tools
```

## Command Applications

The `cmd` directory contains the main applications for CFGMS:

- **controller**: The central management application that orchestrates the system
- **steward**: The agent application that runs on managed endpoints
- **outpost**: The proxy cache application that can act as an intermediary

Each application follows a similar structure:

```txt
cmd/<application>/
├── main.go               # Application entry point
├── server.go             # Server implementation
└── config/               # Application-specific configuration
```

## Internal Packages

The `internal` directory contains packages that are not intended to be imported by other projects:

### Core

The `core` package contains fundamental functionality used throughout the system:

```txt
internal/core/
├── dna/                  # DNA (system identification) implementation
├── health/               # Health checking and monitoring
├── metrics/              # Metrics collection and reporting
└── telemetry/            # Telemetry and tracing
```

### Modules

The `modules` package contains implementations of various modules:

```txt
internal/modules/
├── file/                 # File management module
├── service/              # Service management module
├── user/                 # User management module
├── group/                # Group management module
└── network/              # Network configuration module
```

Each module follows a similar structure:

```txt
internal/modules/<module>/
├── module.go             # Module implementation
├── get.go                # Get implementation
├── set.go                # Set implementation
├── test.go               # Test implementation
├── monitor.go            # Monitor implementation (if applicable)
└── errors.go             # Module-specific errors
```

### Security

The `security` package contains security-related implementations:

```txt
internal/security/
├── auth/                 # Authentication
├── cert/                 # Certificate management
├── encryption/           # Encryption utilities
└── rbac/                 # Role-based access control
```

### Storage

The `storage` package contains storage implementations:

```txt
internal/storage/
├── file/                 # File-based storage
├── git/                  # Git integration
└── database/             # Database storage
```

### Workflow (internal)

The `workflow` package contains the workflow engine implementation:

```txt
internal/workflow/
├── engine/               # Workflow engine
├── parser/               # Workflow parser
└── executor/             # Workflow executor
```

### Tenant

The `tenant` package contains the multi-tenancy implementation:

```txt
internal/tenant/
├── manager/              # Tenant manager
├── resolver/             # Configuration resolver
└── rbac/                 # Tenant-aware RBAC
```

## Public Packages

The `pkg` directory contains packages that are intended to be imported by other projects:

### API

The `api` package contains public API definitions:

```txt
pkg/api/
├── controller/           # Controller API
├── steward/              # Steward API
└── outpost/              # Outpost API
```

### Config

The `config` package contains configuration types and utilities:

```txt
pkg/config/
├── types/                # Configuration types
├── validation/           # Configuration validation
└── parser/               # Configuration parser
```

### Module

The `module` package contains module interfaces and utilities:

```txt
pkg/module/
├── interface/            # Module interfaces
├── registry/             # Module registry
└── utils/                # Module utilities
```

### Workflow (pkg)

The `workflow` package contains workflow interfaces and utilities:

```txt
pkg/workflow/
├── types/                # Workflow types
├── parser/               # Workflow parser
└── executor/             # Workflow executor
```

## Documentation

The `docs` directory contains documentation:

```txt
docs/
├── architecture/         # Architecture documentation
├── development/          # Development documentation
└── product/              # Product documentation
```

## Scripts

The `scripts` directory contains build and deployment scripts:

```txt
scripts/
├── build/                # Build scripts
├── deploy/               # Deployment scripts
└── test/                 # Test scripts
```

## Tests

The `test` directory contains integration tests:

```txt
test/
├── integration/          # Integration tests
├── performance/          # Performance tests
└── security/             # Security tests
```

## Tools

The `tools` directory contains development tools:

```txt
tools/
├── lint/                 # Linting tools
├── generate/             # Code generation tools
└── benchmark/            # Benchmarking tools
```

## Version Information

- **Version**: 1.0
- **Last Updated**: 2024-04-07
- **Status**: Draft
