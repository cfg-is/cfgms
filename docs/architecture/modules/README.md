# Module System

This directory contains documentation about the module system in CFGMS, which is the core mechanism for extending and customizing the functionality of the system.

## Overview

CFGMS uses a module-based architecture where all resource management tasks are performed by 'Modules'. Each module implements a standard interface that allows it to be integrated into the CFGMS workflow.

## Key Concepts

- **Module**: A collection of related components that implement Get/Set/Test for a resource type
- **Resource**: A manageable entity (e.g., users, groups, web servers, applications)
- **Configuration**: The current state of a Resource or Endpoint
- **Configuration-Data**: A declarative specification of desired state for one or more resources
- **Monitor**: A detector that observes state changes and triggers workflows or alerts

## Module Structure

Each module follows a consistent directory structure:

```
modules/
├── directory/
│   ├── module.yaml          # Module metadata and configuration
│   └── module.go           # Module implementation
├── file/
│   ├── module.yaml
│   ├── interface.go        # Module-specific interfaces (optional)
│   └── implementation.go   # Module implementation
└── firewall/
    ├── module.yaml
    └── module.go
```

**Key Files:**
- `module.yaml` - Required metadata file containing module name, version, description, and capabilities
- `*.go` - Implementation files that must implement the `Module` interface with `ConfigState`
- No `schema.yaml` files - validation is handled within the module's `ConfigState.Validate()` method

## Documentation Structure

- [Core Principles](core-principles.md): Fundamental principles that guide module design and implementation
- [Module Interface](interface.md): Detailed specification of the module interface and ConfigState
- [Lifecycle Management](lifecycle.md): How modules are loaded, initialized, and managed
- [Security Requirements](security.md): Security considerations for module implementation
- [Testing Requirements](testing.md): Testing standards and requirements for modules
- [Standalone Steward Architecture](standalone-steward.md): Complete architecture for standalone operation
- [Module Development](development.md): Guide for developing new modules
- [Example Modules](examples.md): Examples of module implementations

## Version Information
- **Document Version:** 1.0
- **Last Updated:** 2024-04-04
- **Status:** Draft 