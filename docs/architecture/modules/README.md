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
├── file/
│   ├── module.yaml          # Module metadata (covers file, directory, symlink types)
│   └── implementation.go
├── firewall/
│   ├── module.yaml
│   └── module.go
└── script/
    ├── module.yaml
    └── implementation.go
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

### What belongs in stdlib

The standard library is not an open-ended collection. A module is **stdlib** only if it meets this test:

> A module is stdlib if it is part of the **declared baseline for nearly every managed machine** — configured on essentially all endpoints to bring them to, and hold them in, a managed/compliant state. The test is **usage across the fleet, not capability**: a powerful module used on only a subset of machines is `extended`, not stdlib.

Two carve-outs:

- **Execution primitives** (e.g. `script`) are stdlib regardless of the usage test — they are core paths through which cfg reaches a host.
- **Platform-scoped** resources qualify where the resource exists (a Windows-only baseline module is still stdlib).

Everything else — however useful — is an `extended` module, built as a standalone bundle and pulled on demand (see [distribution.md](distribution.md) and [ADR-006](../decisions/006-module-packaging-and-distribution.md)). Changing the stdlib set is an ADR-level decision. **[ADR-016](../decisions/016-steward-module-foundation.md) is authoritative** for the criterion, the current members, and the `stdlib/` ↔ `extended/` repository split.

### Current stdlib members

Shipped in the steward installer, all `executors: [steward]` (closed set — see ADR-016):

- `file` - File content, directory creation, and permissions (`type: file` / `type: directory` / `type: symlink`)
- `service` - OS service state management
- `package` - Software package management
- `script` - Cross-platform script execution (file-based, no inline eval) — *execution primitive*
- `firewall` - Firewall rules and policies
- `patch` - OS patch management (Windows Update COM API on Windows; stub on other platforms)
- `user` - Local users & groups, membership, password/lock state — *planned (net-new)*
- `cert_trust` - System trust store: install/trust CA & certs; keeps the CFGMS mTLS chain healthy — *planned (net-new)*
- `time` - Timezone + NTP/time-sync — *planned (net-new)*
- `hostname` - System/computer name & workgroup — *planned (net-new)*

### Extended steward modules (non-stdlib)

CFGMS-authored but used on only a subset of the fleet; built as standalone bundles, pulled on demand:

- `acme` - ACME/Let's Encrypt certificate management
- `activedirectory` - Local Active Directory integration (steward)
- `hyperv` - In-host Hyper-V management via a persistent PowerShell host subprocess (steward kind; runs on the Hyper-V host itself)

**Outpost modules:**

- `network_activedirectory` - Network-based AD integration via LDAP (outpost)

**Workflow modules:**

- `m365/*` (workflow kind, hosted by the controller workflow engine, at `features/workflow/modules/m365/`) - Microsoft 365 modules: `auth`, `conditional_access`, `entra_admin_unit`, `entra_application`, `entra_group`, `entra_user`, `intune_policy`. The `gdap/` and `graph/` directories under the same parent are shared support packages, not module roots.

## Script Module — Parameter Environment Variables

Script parameters are injected into the child process environment only (the steward process environment is never modified). Two namespaces are used:

| Type | Env var name | Example |
|------|-------------|---------|
| Literal param | `CFGMS_PARAM_<NAME_UPPER>` | `path` → `CFGMS_PARAM_PATH` |
| Secret-store param | `CFGMS_SECRET_<NAME_UPPER>` (PowerShell/CMD) or `<NAME_UPPER>` (Unix shells) | `dbPass` → `CFGMS_SECRET_DBPASS` / `DBPASS` |

The `CFGMS_PARAM_` prefix prevents a literal param from silently overwriting a standard environment variable (e.g., a param named `path` becomes `CFGMS_PARAM_PATH`, not `PATH`). Scripts read params via the namespaced name:

```bash
# bash/sh/zsh — literal param named "install_path"
echo "$CFGMS_PARAM_INSTALL_PATH"
```

```powershell
# PowerShell — literal param named "install_path"
Write-Output $env:CFGMS_PARAM_INSTALL_PATH
```

Secret params on Windows use `CFGMS_SECRET_` to avoid logging the value via Event 4688 command-line auditing. On Unix shells, secrets use a bare uppercase name (`<NAME_UPPER>`) following the 12-factor convention.

## Documentation

- [Module Interface](interface.md) - Essential interface specification and ConfigState details
