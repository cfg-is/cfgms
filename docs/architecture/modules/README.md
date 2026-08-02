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
| `observe_when` | list | no | Activation predicate for read-only DNA observation (ADR-024). Absent = never auto-pulled for DNA. |

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

### `observe_when` declaration (ADR-024)

The optional `observe_when` list is a module-level activation predicate for **read-only DNA observation**. It decides whether a steward auto-pulls this module to observe its whole domain **even when no resource of this module is declared** — and, equivalently, whether this module's state belongs in DNA at all.

```yaml
# module.yaml — observe activation example
observe_when:
  - fact: windows_feature
    contains: hyperv
```

Each list entry is an `ObservePredicate` struct (`features/modules/metadata.go`). Fields:

| Field | Type | Description |
|-------|------|-------------|
| `fact` | string | **Required.** Baseline DNA fact key to match (e.g. `"windows_feature"`, `"os"`) |
| `equals` | string | Exact match on the fact value. Mutually exclusive with `contains`. |
| `contains` | string | Substring match on the fact value. Mutually exclusive with `equals`. |

Exactly one of `equals` or `contains` must be set per predicate; neither or both is a parse error caught at module load time.

**Semantics (full contract in [ADR-024](../decisions/024-module-observation-vs-convergence.md)):**

- **Observation ≠ convergence.** A module reports everything it can observe across its whole `<module>.*` domain (best-effort, silently continuing on absence); it *converges* only the resource instances declared in config. `observe_when` governs observation; declarations govern convergence.
- **Present** → the controller may direct the steward to pull this module and run it in read-only observe mode when the predicate matches the box's baseline DNA. The predicate is a dumb fact-match (`fact` + `equals`/`contains`), not an expression language. It is **module-level** — a module bundle observes its entire domain in one pass (e.g. `hyperv` covers both `hyperv.vm` and `hyperv.cluster`; they are resource *types*, not separate modules).
- **Absent** → the steward never auto-pulls this module for DNA. There is no separate "none" value.
- **DNA vs config/drift.** DNA is observed inventory + fleet-queryable facts config does not already determine. A module carries `observe_when` iff its domain is bounded and inventory-worthy (`service`, `package`, `user`, `hyperv`, …); its whole-domain `Get` *is* its DNA. Content-bearing / unbounded-domain modules (`file`/directory, future registry-value) carry **no** `observe_when` — their declared resources live in **config + drift only**, never enumerated into DNA. The execution primitive `script` has no observation domain and carries none.
- **Read-only guarantee.** An observe-eligible module's observe path runs only enumeration + `Get` (never `Set`), and its `behavioral_envelope` for that path must declare no writes — verified by `conformance.AssertObserveReadOnly` and auditable from the manifest.

Resolution is controller-mediated: the steward reports baseline DNA, the controller matches every module's `observe_when` and returns the module set to pull. The steward needs no capability→module map.

**Evaluating a module for `observe_when`:** existing modules are being tagged as part of the ADR-024 epic; new modules must make a considered declaration (or deliberate omission).

#### Deliberate-omission convention

`module.yaml` has no schema field for "I considered `observe_when` and said no." When a module author deliberately omits `observe_when`, they must record that decision as a YAML comment using the following exact format (checked by `make check-stdlib-completeness` check-6):

```yaml
# observe_when: omitted — <reason>
```

The `<reason>` should explain which ADR-024 §3 criterion applies:

- **Content-bearing / unbounded-domain modules** (`file`, future registry-value): omit permanently, e.g.
  ```yaml
  # observe_when: omitted — file domain is content-bearing and unbounded; declared
  # resources live in config + drift only, never enumerated into DNA (ADR-024 §3).
  ```
- **Execution primitives** (`script`): omit permanently, e.g.
  ```yaml
  # observe_when: omitted — script is an execution primitive with no observation
  # domain; it executes signed files on demand and is never auto-pulled for DNA
  # observation (ADR-024 §3).
  ```
- **Inventory-worthy modules awaiting tagging**: omit temporarily, e.g.
  ```yaml
  # observe_when: omitted — pending module-tagging story (bounded inventory-worthy
  # domain; observe_when predicate will be added by the ADR-024 epic).
  ```

Place the comment in `module.yaml` after the `owns:` block (or after `behavioral_envelope:` if present). The gate checks for the prefix `# observe_when: omitted` — the exact reason text is free-form.

**Build enforcement:** `make check-stdlib-completeness` (check-6) fails if any stdlib module's `module.yaml` has neither an `observe_when:` key nor the omission-marker comment. This ensures every module has made a deliberate decision rather than silently skipping the consideration.

#### Read-only conformance for observe-eligible modules

A module that carries `observe_when` must verify its observe path is provably read-only (ADR-024 §4). Use the conformance helper alongside `AssertDeterministicGet` and `AssertNoEphemeralFields`:

```go
import "github.com/cfgis/cfgms/features/modules/conformance"

// AssertObserveReadOnly performs two checks:
//   Layer 1: BehavioralEnvelope.WritesPaths must be empty.
//   Layer 2: no banned mutating PowerShell verb prefix (New-*, Set-*, Remove-*, Add-*)
//            appears in the caller-supplied command list.
//
// The two-layer design is intentional — the envelope check alone is not sufficient
// because a module could declare an empty writes_paths while its Get still calls a
// mutating command. The command-verb check closes that gap.
conformance.AssertObserveReadOnly(t, module.BehavioralEnvelope, executedCommands)
```

Pass the list of PowerShell script blocks or command strings executed during the observe path as `executedCommands`. This mirrors the `assertNoWriteCmdlets` pattern used in `features/modules/hyperv/observe_test.go`.

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
| **check-6** | `module.yaml` carries either an `observe_when:` predicate or the deliberate-omission comment `# observe_when: omitted — <reason>` (ADR-024 §3) |

**check-5 distinction:** `ErrUnsupportedPlatform` in build-tag platform-fallback files (e.g. `executor_stub.go` with `//go:build !linux`) is intentional cross-platform boundary behaviour and is **not** flagged. Only `ErrNotImplemented` — the "we haven't built this yet" marker — causes the gate to fail. Use module-specific errors (e.g. `ErrSymlinkNotSupported`) for documented feature gaps that are out-of-scope for the current version, and `ErrUnsupportedPlatform` for genuine platform boundaries.

**Adding a new stdlib module:** satisfy all five payload sources *and* all five completeness checks before the PR will merge (checks 2–6).

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
