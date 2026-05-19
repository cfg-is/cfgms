# Module System

CFGMS uses a module-based architecture where all resource management tasks are performed by modules that implement a standard interface.

## Key Concepts

- **Module**: Implements Get/Set operations for a specific resource type
- **Resource**: A manageable entity (files, directories, packages, etc.)
- **ConfigState**: Interface that modules return, enabling efficient comparison
- **Managed Fields**: Only specified fields are modified by Set operations

## Module Structure

```
modules/
├── directory/
│   ├── module.yaml          # Module metadata
│   └── module.go           # Implementation
├── file/
│   ├── module.yaml
│   └── implementation.go
└── firewall/
    ├── module.yaml
    └── module.go
```

**Required Files:**

- `module.yaml` - Module metadata (name, version, description)
- `*.go` - Implementation that implements the `Module` interface with `ConfigState`

## Available Modules

- `directory` - Directory creation and permissions
- `file` - File content and attributes
- `firewall` - Firewall rules and policies
- `package` - Software package management
- `acme` - ACME/Let's Encrypt certificate management
- `activedirectory` - Active Directory integration
- `m365/*` - Microsoft 365 modules (auth, conditional access, Entra groups/users/apps/admin units, Intune policy, GDAP)

## Documentation

- [Module Interface](interface.md) - Essential interface specification and ConfigState details
