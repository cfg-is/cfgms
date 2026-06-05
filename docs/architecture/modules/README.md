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

- `module.yaml` - Module metadata (name, version, description, publisher, executors)
- `*.go` - Implementation that implements the `Module` interface with `ConfigState`

## Module Manifest Fields

Every `module.yaml` must include the following fields:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Unique module identifier |
| `version` | string | yes | Semantic version (e.g. `1.0.0`) |
| `description` | string | no | Human-readable description |
| `publisher` | string | yes | Module publisher (e.g. `cfgms`) |
| `executors` | list | yes | Exactly one executor: `steward`, `outpost`, or `controller` |
| `kind` | — | derived | Derived from `executors[0]`; never set in YAML (see below) |
| `behavioral_envelope` | object | no | Runtime behavior declaration for security auditing |

### Executor values and derived `kind`

The `executors` field must contain exactly one element. `kind` is computed at parse time and never stored in YAML:

| `executors[0]` | Derived `kind` | Where the module runs |
|----------------|----------------|-----------------------|
| `steward` | `steward` | Endpoint agent (local resources) |
| `outpost` | `outpost` | Proxy/network probe component |
| `controller` | `workflow` | Central controller (SaaS operations) |

### `behavioral_envelope` sub-fields

| Sub-field | Type | Description |
|-----------|------|-------------|
| `shells_out_to` | list | Shells or interpreters the module invokes |
| `writes_paths` | list | File-system paths the module writes |
| `reads_paths` | list | File-system paths the module reads |
| `network_egress` | list | External hosts/ports the module connects to |
| `lolbin_usage_justification` | string | Why a living-off-the-land binary is needed |

## Available Modules

- `directory` - Directory creation and permissions
- `file` - File content and attributes
- `firewall` - Firewall rules and policies
- `package` - Software package management
- `script` - Cross-platform script execution
- `service` - OS service state management
- `acme` - ACME/Let's Encrypt certificate management
- `activedirectory` - Local Active Directory integration (steward)
- `network_activedirectory` - Network-based AD integration via LDAP (outpost)
- `hyperv` - Remote Hyper-V management via WinRM
- `m365/*` - Microsoft 365 modules (auth, conditional access, Entra groups/users/apps/admin units, Intune policy, GDAP)

## Documentation

- [Module Interface](interface.md) - Essential interface specification and ConfigState details
