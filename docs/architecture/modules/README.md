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
├── stdlib/                  # Baseline modules deployed to nearly every managed machine
│   ├── file/
│   │   ├── module.yaml      # Module metadata (covers file, directory, symlink types)
│   │   └── implementation.go
│   ├── firewall/
│   │   ├── module.yaml
│   │   └── module.go
│   ├── package/
│   ├── patch/
│   ├── script/
│   │   ├── module.yaml
│   │   └── implementation.go
│   └── service/
├── extended/                # On-demand modules pulled per ADR-006
│   ├── acme/
│   ├── activedirectory/
│   ├── github_runner/
│   └── network_activedirectory/
├── adapter/                 # gRPC adapter (unaffected by stdlib/extended split)
└── hyperv/                  # Under active development (epic #2418; not split)
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

### `owns:` declaration (ADR-016 clause 5)

The optional `owns:` list declares the object-identity namespaces this module
authoritatively manages. Omitting `owns:` is valid and backward-compatible with
all existing `module.yaml` files — it means the module declares no ownership.

```yaml
# module.yaml — DNA ownership declaration example
owns:
  - kind: service   # authority over service:* objects this module manages
```

**Semantics:** Authority is atomic at the object level. When a module owns an
object kind, it owns every property of every object of that kind it manages —
no sub-property co-authorship. At DNA assembly the steward excludes any object
claimed by an active module from other DNA sources; on module uninstall,
authority reverts. The resolver is defined in ADR-017; this field provides the
declaration that makes resolution possible.

**Adding `owns:` to a module:** Each module's own story adds its specific
`owns:` entries (e.g. `patch` in issue #2472). The `owns:` parsing support is
provided by this story (#2471) and is ready to use.

### `required_fields` declaration (ADR-020)

Each `owns:` entry may carry a `required_fields` list declaring which fragment fields
must be present and non-empty for the DNA snapshot to be accepted at write time:

```yaml
# module.yaml — ownership + required-field declaration example
owns:
  - kind: service
    required_fields:
      - name   # object identity key
      - state  # managed field that must be present in a valid DNA snapshot
```

**Semantics:** The controller collects `required_fields` across all modules active for
an entity and checks the union at DNA write time. A field that is absent or empty in
the snapshot fails the write-integrity guard. Omitting `required_fields` from an
`owns:` entry is valid — the module declares ownership but imposes no additional
required-field constraint. The full declaration contract and configuration-type
resolution rules are defined in [ADR-020](../decisions/020-dna-required-field-declaration.md).

**Implementation (issue #2642):** The manifest-driven loader is now active. On
controller startup the guard builds its required-field table by reading every
`module.yaml` embedded in the controller binary
(`features/modules.StdlibManifests`). All steward-kind modules' `required_fields`
are unioned into the `full-os-device` configuration type (ADR-020 Path A).
Adding `required_fields` to a stdlib `module.yaml` therefore changes what the
guard enforces with no change to `dna_integrity.go`. The hand-coded Go literal
from issue #2617 has been retired; the module manifests are now the authoritative
source.

### `Get` canonical fragment contract (ADR-016 clause 4)

Every module's `Get` implementation must return a **canonical,
deterministically-serialisable DNA fragment**. In terms of the Go code:

- `ConfigState.AsMap()` must return byte-for-byte identical output on every
  call against the same unchanged resource state.
- Only stable desired-comparable fields are included. **Omit all ephemeral
  runtime values**: live PIDs, current CPU/memory statistics, timestamps,
  uptime counters, or any value that changes under the OS without a
  cfg-driven configuration change.

**Verification:** Use the helpers in `features/modules/conformance` in a
module's own `_test.go` file:

```go
import "github.com/cfgis/cfgms/features/modules/conformance"

// AssertDeterministicGet calls Get twice and asserts byte-for-byte equality
// of the canonical JSON-encoded AsMap() output.
conformance.AssertDeterministicGet(t, m, resourceID)

// AssertNoEphemeralFields checks AsMap() keys against the banned list.
state, _ := m.Get(ctx, resourceID)
conformance.AssertNoEphemeralFields(t, state, conformance.DefaultBannedEphemeralFields)
```

See `features/modules/conformance/fragment_test_helper.go` for godoc and
`features/modules/conformance/fragment_test_helper_test.go` for a worked
example using `stdlib/file`.

## Available Modules

### What belongs in stdlib

The standard library is not an open-ended collection. A module is **stdlib** only if it meets this test:

> A module is stdlib if it is part of the **declared baseline for nearly every managed machine** — configured on essentially all endpoints to bring them to, and hold them in, a managed/compliant state. The test is **usage across the fleet, not capability**: a powerful module used on only a subset of machines is `extended`, not stdlib.

Two carve-outs:

- **Execution primitives** (e.g. `script`) are stdlib regardless of the usage test — they are core paths through which cfg reaches a host.
- **Platform-scoped** resources qualify where the resource exists (a Windows-only baseline module is still stdlib).

Everything else — however useful — is an `extended` module, built as a standalone bundle and pulled on demand (see [distribution.md](distribution.md) and [ADR-006](../decisions/006-module-packaging-and-distribution.md)). Changing the stdlib set is an ADR-level decision. **[ADR-016](../decisions/016-steward-module-foundation.md) is authoritative** for the criterion, the current members, and the `stdlib/` ↔ `extended/` repository split.

### Stdlib membership is enforced by the build

Adding or removing a module from stdlib requires **five coordinated changes**, each enforced by `make check-stdlib-payload-boundary` (wired into `make test-commit` and enforced in CI via the `unit-tests` job):

1. `features/modules/stdlib/<name>/` — the module directory
2. `Makefile` `STDLIB_MODULES` variable — drives compilation
3. `build/windows/cfgms-steward.wxs` — Windows MSI installer `<Component>` block (alphabetical insertion order)
4. `build/linux/install.sh` `STDLIB_MODULES` array — Linux install-script payload (one name per line, alphabetical)
5. `build/darwin/build-pkg.sh` `STDLIB_MODULES` array — macOS `.pkg` payload (one name per line, alphabetical)

The build fails if any of the five disagree. New entries in `.wxs`, `install.sh`, and `build-pkg.sh` must be inserted in alphabetical order by module name (not appended at the end).

### Stdlib completeness is enforced by the build (ADR-016 clause 6)

In addition to the payload boundary, `make check-stdlib-completeness` (also wired into `make test-commit`, via `check-stdlib-payload-boundary` as a prerequisite, and enforced in CI via the `unit-tests` job) asserts that every module under `stdlib/` is fully compliant:

| Check | What is verified |
|-------|-----------------|
| **check-2** | `module.yaml` exists and contains all required fields: `name`, `version`, `publisher`, `executors` |
| **check-3** | `cmd/main.go` exists — the bundle entry point that builds the module as a standalone binary |
| **check-4** | `module.yaml` declares at least one `owns:` entry (ADR-016 clause 5) |
| **check-5** | No unresolved-work stubs: no file whose basename starts with `stub_`, no `panic("TODO")`, and no `ErrNotImplemented` in non-test Go source files |

**check-5 distinction:** `ErrUnsupportedPlatform` in build-tag platform-fallback files (e.g. `executor_stub.go` with `//go:build !linux`) is intentional cross-platform boundary behaviour and is **not** flagged. Only `ErrNotImplemented` — the "we haven't built this yet" marker — causes the gate to fail. Use module-specific errors (e.g. `ErrSymlinkNotSupported`) for documented feature gaps that are out-of-scope for the current version, and `ErrUnsupportedPlatform` for genuine platform boundaries.

**Adding a new stdlib module:** satisfy all five payload sources *and* all four completeness checks before the PR will merge.

### Current stdlib members

Shipped in the steward installer, all `executors: [steward]` (closed set — see ADR-016):

- `file` - File content, directory creation, and permissions (`type: file` / `type: directory`; `type: symlink` planned for a future story)
- `service` - OS service state management
- `package` - Software package management
- `script` - Cross-platform script execution (file-based, no inline eval) — *execution primitive*
- `firewall` - Firewall rules and policies
- `patch` - OS patch management (Windows Update COM API on Windows; `modules.ErrUnsupportedPlatform` fallback on Linux/macOS — real non-Windows backends are out of scope per ADR-016 PM Notes)
- `user` - Local users & groups, membership, lock/disable state, password presence (observed only)
- `cert_trust` - System trust store: install/trust CA & certs; keeps the CFGMS mTLS chain healthy fleet-wide
- `time` - Timezone + NTP/time-sync configuration (`timezone`, `ntp_servers`, `ntp_sync_enabled`)
- `hostname` - System/computer name & workgroup

### Extended steward modules (non-stdlib)

CFGMS-authored but used on only a subset of the fleet; built as standalone bundles, pulled on demand:

- `acme` - ACME/Let's Encrypt certificate management
- `activedirectory` - Local Active Directory integration (steward)
- `github_runner` - GitHub Actions self-hosted runner agent lifecycle (install + service management; the module is token-free, never mints/consumes registration tokens). Like `hyperv`, it is currently statically registered in the steward factory as an interim measure pending the future stdlib/extended split-loading story, rather than pulled on-demand per ADR-006.
- `hyperv` - In-host Hyper-V management via a persistent PowerShell host subprocess (steward kind; runs on the Hyper-V host itself). Statically registered in the steward factory as an interim measure (same as `github_runner` above).

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
