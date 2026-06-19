# Hyper-V Module

**Kind:** steward

Remote Hyper-V management via WinRM for CFGMS. Manages VMs and virtual switches on Windows Server hosts running the Hyper-V role. All PowerShell commands are executed over an authenticated, TLS-encrypted WinRM connection.

## Purpose and scope

The Hyper-V module provides desired-state management of Hyper-V resources on Windows Server hosts via WinRM. It enables CFGMS to create, start, stop, resize, and remove virtual machines and configure virtual switches — all through an authenticated, TLS-encrypted WinRM connection. A VM's network connection is declared on the VM itself (`switch_name`); the module converges its adapters to match.

The module's scope includes:

- **VM lifecycle**: create (`New-VM`), start (`Start-VM`), stop (`Stop-VM`), remove (`Remove-VM`)
- **VM resize**: update CPU count (`Set-VMProcessor`) and startup memory (`Set-VM -MemoryStartupBytes`) on stopped VMs
- **Virtual switches**: create and remove External, Internal, and Private vSwitches
- **VM networking**: declared on the VM (`switch_name`); the module connects the VM's adapter to the named switch

Out of scope: Hyper-V role installation, storage pool management, live migration, replication policies. Steward-on-host wiring and controller dispatch wiring are delivered by epic #1790 (see `docs/operations/hyperv-host-onboarding.md`).

## Configuration options

The module accepts the following configuration options via `Configure(cfg)`:

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `winrm_host` | string | Yes | Hostname or IP of the Hyper-V host |
| `winrm_user_secret` | string | Yes | SecretStore key for the WinRM username |
| `winrm_pass_secret` | string | Yes | SecretStore key for the WinRM password |
| `tenant_id` | string | No | Tenant identifier recorded on audit events and DNA (not used to alter host-side resource names) |
| `steward_id` | string | No | Steward identifier for audit records (defaults to `<tenantID>/hyperv`) |
| `audit_manager` | `*audit.Manager` | No | Audit manager for recording Hyper-V operations |

VM resource configuration fields (`vm:<name>`):

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `memory_mb` | integer | Yes (create) | Startup memory in MiB |
| `cpu_count` | integer | Yes (create) | Number of virtual processors |
| `vhd_path` | string | Yes (create) | Absolute Windows path to VHD/VHDX |
| `switch_name` | string or list | Yes (create) | The VM's full desired network. One switch name (back-compat) or a list of switch names (multi-NIC). Converged declaratively. |
| `generation` | integer | No | VM generation (`1` or `2`; omit for default `2`) |
| `state` | string | No | Desired state: `running`, `stopped`, or `absent` |
| `source` | object | No | ISO boot-provisioning parameters. When present, the module provisions the OS from install media. See [VM provisioning from install media](#vm-provisioning-from-install-media). |

The `source` block (present only when provisioning a VM from install media):

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `source.iso` | string | Yes | Absolute Windows path to the installation ISO on the Hyper-V host (e.g. `C:\ISO\server.iso`). Never repacked or re-signed. |
| `source.os_family` | string | Yes | Installer family: `linux` or `windows`. Selects the answer-file format, the seed answer-file name, and the Gen2 secure-boot template. |
| `source.unattend` | string | No | Reference to a stored unattended-install profile as a `profile://<name>` URI. Omit to use the built-in default profile for the `os_family` (`debian-12-base` for linux, `windows-server-default` for windows). |
| `source.completion` | object | No | How the module detects provisioning succeeded. `completion.mode` accepts only `steward-registration` (the v1 value); `completion.timeout` is a Go duration string (e.g. `60m`) bounding the wait. |
| `source.on_existing` | string | No | Behaviour when the VM already exists. `never` (default) leaves an existing VM untouched; `recreate` is an explicit opt-in to destroy and re-provision. |

## Usage examples

The resource type is selected via the `module` field as `hyperv.<type>`
(`hyperv.vm`, `hyperv.vswitch`). The `name` field is the plain object name
(strict `[a-zA-Z0-9_-]`). The steward executor translates `module: hyperv.vm`
+ `name: web-01` into the module's internal `vm:web-01` resource ID.

### Create and start a VM

```yaml
- name: web-01
  module: hyperv.vm
  config:
    memory_mb: 4096
    cpu_count: 2
    vhd_path: C:\VMs\web-01.vhdx
    switch_name: External
    generation: 2
    state: running
```

### Stop a VM

```yaml
- name: web-01
  module: hyperv.vm
  config:
    state: stopped
```

### Resize an existing VM (stop → resize → start)

```yaml
- name: web-01
  module: hyperv.vm
  config:
    cpu_count: 4
    memory_mb: 8192
    state: running
```

### Create an external virtual switch

```yaml
- name: External-Switch
  module: hyperv.vswitch
  config:
    switch_type: external
    net_adapter_name: Ethernet0
    state: present
```

## VM provisioning from install media

Adding a `source` block to a `hyperv.vm` resource turns a bare hypervisor into a
managed endpoint: the module creates the VM, attaches the install ISO and an
unattended answer file, powers the VM on, and lets the OS install unattended.
Provisioning is a declarative extension of the existing `hyperv.vm` resource —
there is no separate imperative "provision" verb, and there is exactly one way to
make a VM (ADR-009). Convergence makes the declared VM exist; the OS install is an
implementation detail inside the create path.

### Existence-gating (safety invariant)

The `source` block is acted on **only when the VM does not exist by name** on the
host. Health and bootability are never the trigger. This is the single most
important safety property of the feature:

- VM **absent** → provision from `source`.
- VM **exists** (and has no in-progress provisioning record of ours) → `source`
  is **inert**; the existing VM is never touched, resized, or rebuilt.
- VM **exists but broken / won't boot** → surfaced as `degraded`; the module
  **does not** delete-and-rebuild a VM just because it is unhealthy.
- Destroying and re-provisioning an existing VM is **explicit opt-in** only, via
  `source.on_existing: recreate` (default `never`). The default convergence path
  can never destroy a VM.

To distinguish "my own incomplete provisioning attempt" from "a real existing
VM", the module keeps a per-VM **provisioning record** (the state machine below).
Nothing is destroyed automatically, ever.

### Provisioning state machine

The module advances the provisioning record **one step per convergence cycle** —
it never blocks the convergence loop on a multi-minute install. A controller
restart or a slow install simply resumes from the recorded state.

```
absent ── create VM + disks + NICs, attach install ISO + seed VHDX ──▶ creating
creating ── power on ──▶ installing ── (unattended install runs) ──▶ finalizing
finalizing ── (detach seed, first boot, steward registers) ──▶ ready

installing ── timeout / install marker = fail ──▶ failed
existing-but-unhealthy real VM ──────────────────────────────────▶ degraded
```

| State | Meaning |
|-------|---------|
| `absent` | No VM exists by this name; `source` will provision it. |
| `creating` | VM, disks, and NICs created; install ISO + seed VHDX attached; secure-boot template selected (Gen2). |
| `installing` | VM powered on; the unattended OS install is running inside the guest. |
| `finalizing` | Install judged complete; the seed VHDX is detached so the answer file is gone on subsequent boots; the guest's first boot installs and enrolls the steward. |
| `ready` | The provisioned VM's steward has registered with the controller. |
| `failed` | The install exceeded `completion.timeout`, or a host-side provisioning step failed. |
| `degraded` | An existing real VM is unhealthy; the module surfaces this and takes no destructive action. |

**`ready` is determined controller-side.** The `hyperv` module runs on the
*host's* steward, which cannot see the controller's registry. The host-side module
therefore advances the record only as far as `finalizing` (OS installed, seed
detached, first boot underway). The transition to `ready` is made by the
controller-side completion reconciler when a newly-registered steward's mTLS CN
matches the **correlation identity** baked into the rendered answer file. The
provisioning record carries this correlation value; the controller also flips the
record to `failed` when `completion.timeout` elapses with no matching registration.

### How the answer file is delivered (host-native seed VHDX)

The unattended answer file is delivered on a **secondary VHDX seed disk** attached
to the VM, built on the Hyper-V host with native cmdlets only (`New-VHD` →
`Mount-VHD` → `Format-Volume` → copy), then detached at `finalizing`. The seed is
a FAT32 volume labelled `CFGMS_SEED` created next to the VM's primary VHD
(`<vhd-dir>\cfgms-seed-<vm-name>.vhdx`).

- Windows Setup auto-discovers `autounattend.xml` from the root of attached
  removable media; debian-installer reads `preseed.cfg` from the labelled seed
  volume.
- The seed VHDX works on **both Gen1 and Gen2** VMs (no floppy needed). For Gen2,
  the secure-boot template is selected by `os_family` (`MicrosoftWindows` for
  windows, `MicrosoftUEFICertificateAuthority` for linux); Gen1 has no secure boot.
- **The install ISO is never repacked or re-signed.** It is attached as-is from
  its host path. Repacking signed UEFI boot media breaks the boot chain.

### Annotated Linux example (Debian 12, preseed)

```yaml
- name: stw-lin-01
  module: hyperv.vm
  config:
    generation: 2
    cpu_count: 2
    memory_mb: 4096
    vhd_path: C:\ClusterStorage\CSV01\stw-lin-01.vhdx
    switch_name: HVSwitch_1G
    state: running
    source:
      iso: C:\ClusterStorage\CSV01\iso\debian-12.iso   # host path; never repacked
      os_family: linux                                  # selects preseed + UEFI-CA template
      unattend: profile://debian-12-base                # omit to use the built-in default
      completion:
        mode: steward-registration                      # the only v1 mode
        timeout: 45m
      on_existing: never                                 # default; never destroys an existing VM
```

### Annotated Windows example (Windows Server, autounattend)

```yaml
- name: stw-win-01
  module: hyperv.vm
  config:
    generation: 2
    cpu_count: 4
    memory_mb: 6144
    vhd_path: C:\ClusterStorage\CSV01\stw-win-01.vhdx
    switch_name: HVSwitch_1G
    state: running
    source:
      iso: C:\ClusterStorage\CSV01\iso\windows-server-2025.iso  # host path; never repacked
      os_family: windows                                         # selects autounattend + Windows template
      unattend: profile://windows-server-default                 # omit to use the built-in default
      completion:
        mode: steward-registration
        timeout: 60m
      on_existing: never
```

In both examples, `unattend` may be omitted entirely — the module then uses the
built-in default profile for the `os_family`. Operators add new OS editions,
locales, or enrollment variants by authoring a stored profile and referencing it
here, with **no Go code change**. See
[Adding an unattended-install profile without code changes](../../../docs/operations/hyperv-profile-authoring.md).

### Install media staging is out of scope

`source.iso` is a path on the Hyper-V host (typically on a CSV). Getting the ISO
onto the host is not this module's concern — an operator stages it, or a
declarative `file` module resource does. This module adds no controller blob
store, large-object transfer, or ISO distribution path.

## Known limitations

1. **CPU/memory resize requires a stopped VM** — Hyper-V does not support hot-resize. The module handles this automatically: when `state: running` with a resize, it stops the VM, resizes, then starts it. A brief outage occurs during this sequence.
2. **Generation is fixed at creation** — VM generation cannot be changed after the VM is created.
3. **VHD path is immutable** — The virtual disk path is set at creation and cannot be changed via this module.
4. **Basic auth is structurally disabled** — Only NTLM over HTTPS (port 5986) is supported. WinRM must be configured for HTTPS on the target host.
5. **Integration tests require a live host** — Unit tests use a test implementation of the WinRM transport interface; full end-to-end validation requires `CFGMS_HYPERV_HOST` to be set.
6. **Install media is a host path** — `source.iso` must already exist on the Hyper-V host (typically on a CSV). This module does not download, copy, or distribute ISOs; stage them with the `file` module or out of band. The ISO is attached as-is and is never repacked or re-signed.
7. **No host ISO-builder dependency for the seed** — the unattended answer file is delivered on a host-native VHDX seed disk built with `New-VHD`/`Mount-VHD`/`Format-Volume` (present with the Hyper-V + Storage roles the host already runs), so it needs **no** `oscdimg.exe` (Windows ADK) or `mkisofs` on the host. If you choose to author a profile that ships its answer file via a secondary ISO instead of the VHDX seed, building that ISO on the host would require `oscdimg.exe` or `mkisofs` — neither is present on a stock Hyper-V host, which is why the VHDX seed is the supported mechanism.
8. **Windows enrollment `.ppkg` must be pre-signed** — the Windows path applies a provisioning package (`.ppkg`) at first logon for steward enrollment. The package is referenced by host path (via a secret key) and must be signed ahead of time; this module does not sign `.ppkg` artifacts. An unsigned/self-signed package is acceptable only for lab/dogfood under `module_trust.mode: bypass`.
9. **Provisioning advances one step per convergence cycle** — a long-running OS install does not block the convergence loop. The host-side module advances only as far as `finalizing`; the `ready` transition is controller-side.

## Host detection

The module activates only on hosts where Hyper-V is actually present, and cleanly declines work on hosts where it isn't. This avoids two failure modes the M2 epic explicitly calls out: a steward on a Linux host crashing when a config pushes a `module: hyperv` resource at it, and a misconfigured `%PATH%` on a Windows host tricking the detector into running Hyper-V cmdlets that don't exist.

### Detection on Windows

1. The detector invokes `powershell.exe` via the absolute path `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe`. It never resolves `powershell.exe` through `%PATH%`. Without this, a directory writable by the steward's service account that appears earlier on `%PATH%` than `System32` could host a `powershell.exe` shim that exits 0 with empty output — bypassing the detection gate. The absolute-path resolution closes that bypass.
2. The cmdlet run is `Get-VMHost | ConvertTo-Json`. A successful exit code on its own is not sufficient: the detector parses the JSON output and requires a non-empty `Name` field (the host's own hostname, as reported by Hyper-V). Empty or unparseable stdout is treated as "not a Hyper-V host." This is defense-in-depth against the same shim-bypass scenario, and also fails closed against a degraded Hyper-V install whose cmdlet returns a stub object.
3. Cmdlet-not-found and access-denied errors are classified as soft failures and return `(false, nil)` — the module declines work on those hosts rather than crashing.
4. Positive detection is cached for 5 minutes at the detector level. Negative results are not cached at the detector level. The module wraps the detector with a second 5-minute positive-result cache (`checkDetection` in `module.go`) so that operations within a single steward run don't re-invoke PowerShell on every Set/Get call. A host that gains the Hyper-V role mid-operation is picked up after the longer of the two caches expires.

### Behavior on non-Hyper-V hosts (including all Linux and macOS)

`Get` and `Set` short-circuit at the detection gate and return `ErrHostNotHyperV`. Before returning, both methods emit a structured warning via `slog`:

```
hyperv: declining resource — host is not a Hyper-V host  resource_id=vm:web-01
```

The `resource_id` is sanitised via `logging.SanitizeLogValue()` to defend against log-injection payloads in attacker-controlled resource names. The module does not panic, does not call into the WinRM transport, and does not invoke any Hyper-V cmdlet — operators reading the steward log can immediately see which resource was declined and why.

## Service Account Requirements

The WinRM service account must be a member of the **Hyper-V Administrators** local group on the target host. Domain Admin is not required and must not be granted — follow the principle of least privilege.

```
Computer Management → Local Users and Groups → Groups → Hyper-V Administrators → Add Member
```

## Credential Setup

Credentials are stored in the CFGMS secret store and looked up by key on every WinRM call. No credential values are cached between calls.

Store the WinRM username and password using the following key format:

```
hyperv/winrm/<tenantID>/<hostname>
```

Example for tenant `acme` and host `hv01.acme.local`:

```sh
cfg secret set --key "hyperv/winrm/acme/hv01.acme.local/user" \
               --value '{"Username":"svc-hyperv","Password":""}'

# Or set user and password as separate keys (recommended):
cfg secret set --key "hyperv/winrm/acme/hv01.acme.local/user" --value "svc-hyperv"
cfg secret set --key "hyperv/winrm/acme/hv01.acme.local/pass" --value "your-password-here"
```

Then reference those keys in the module configuration:

```yaml
winrm_host: hv01.acme.local
winrm_user_secret: hyperv/winrm/acme/hv01.acme.local/user
winrm_pass_secret: hyperv/winrm/acme/hv01.acme.local/pass
```

## Constructor

```go
import "github.com/cfgis/cfgms/features/modules/hyperv"

// New creates a module instance. detector implements HypervDetector to check
// whether Hyper-V is available on the target host. Pass nil during initial
// wiring; full detection is added in a later story.
m := hyperv.New(detector)
```

The module must have a SecretStore injected and be configured before use:

```go
m.(modules.SecretStoreInjectable).SetSecretStore(store)
m.(modules.Configurable).Configure(cfg)
```

## Resource ID Formats

In fleet config, resources select their type via `module: hyperv.<type>` and
carry a plain `name`. Internally the module's `Get`/`Set` receive a typed
resource ID string built by the steward executor:

| `module` | `name` + config | Internal resource ID | Operation |
|----------|-----------------|----------------------|-----------|
| `hyperv.vm` | `name: web-01` | `vm:web-01` | Virtual machine management (create, start, stop, remove) |
| `hyperv.vswitch` | `name: External-Switch` | `vswitch:External-Switch` | Virtual switch management (create External/Internal/Private, remove) |

### VM networking (declarative, multi-NIC)

A VM's full desired network is declared on the VM itself via `switch_name`,
which accepts either a single switch name (the common case) or a list:

```yaml
# Single NIC (back-compat — behaves exactly as before)
- name: web-01
  module: hyperv.vm
  config:
    switch_name: External
    # ...

# Multi-NIC — one adapter per switch in the list
- name: db-01
  module: hyperv.vm
  config:
    switch_name:
      - External
      - Storage
    # ...
```

On every convergence the module reads all of the VM's network adapters and
reconciles them to the desired set:

- a switch in the list with no connected adapter → a new adapter is connected
  (`Add-VMNetworkAdapter`);
- a connected adapter on a switch not in the list → that adapter is removed
  (`Remove-VMNetworkAdapter`);
- when the connected set already equals the desired set, no PowerShell mutation
  runs and drift reports no network change (idempotent).

At create time `New-VM -SwitchName <first>` connects the primary adapter and
each additional switch in the list connects one more adapter. This declarative
model is the replacement for the removed standalone `vmattach` resource
(detach / multi-NIC / reattach — #1903, #2021). If `switch_name` is omitted the
module leaves the VM's existing adapters untouched (it never implicitly strips a
VM down to zero NICs).

## Naming Convention

Resources are created on the host with the **exact** name specified in the config — CFGMS never adds a prefix or suffix. A VM named `web-01` in the config appears as `web-01` in Hyper-V; a switch named `External` appears as `External`. Admins specify the name they expect to see on the host.

Names are validated against an allowlist (`^[a-zA-Z0-9_\-]{1,64}$` for VMs, `^[a-zA-Z0-9_\- ]{1,64}$` for switches) purely as an injection-safety guard; the validated name is then used verbatim. Because names are not namespaced, operators sharing a single Hyper-V host across tenants must choose non-colliding names themselves.

## WinRM Connection Details

- **Port:** 5986 (HTTPS/TLS)
- **Auth:** NTLM only — Basic auth is structurally disabled
- **TLS:** Certificate verification is always enabled (`InsecureSkipVerify = false`)
- **Credential lifetime:** Fetched from SecretStore on every PS execution — no in-memory caching

## Module Registration

Register the module in the CFGMS module registry:

```go
registry.RegisterModule(&modules.ModuleMetadata{
    Name:    "hyperv",
    Version: "0.1.0",
}, hyperv.New(detector))
```

## Integration Tests

Integration tests require a real Hyper-V host and are excluded from `make test-complete` by the `integration` build tag.

Set the following environment variables before running:

```sh
export CFGMS_HYPERV_HOST=hv01.example.com
export CFGMS_HYPERV_USER=svc-hyperv
export CFGMS_HYPERV_PASS=your-password-here
```

Run the integration tests:

```sh
go test -tags=integration -run TestHypervIntegration ./features/modules/hyperv/...
```

The tests exercise:
- **`TestHypervIntegration_VMLifecycle`** — create → start → stop → remove
- **`TestHypervIntegration_VSwitch`** — create external switch → attach adapter → detach → remove

Tests skip automatically if `CFGMS_HYPERV_HOST` is not set; `TestHypervIntegration_VSwitch` also skips if no UP physical network adapter is found on the host.

## Out of Scope

The following are **not** managed by this module:

- Hyper-V role installation or host provisioning
- Storage pool or virtual disk management
- Live migration and replication
- Hyper-V replica policies
- Steward lifecycle integration (see issue #1790)
- Controller dispatch wiring (see issue #1790)
- Load or performance testing
- **Golden-image / template cloning, an image registry, and a branch-build → image pipeline** — these are Phase 3 (#1792). Provisioning from install media (the `source` block above) is ISO-install only; cloning a prepared template image is a later, separate capability.
- Controller-side ISO blob store or ISO distribution (install media is a host path; see [VM provisioning from install media](#vm-provisioning-from-install-media))

## Security considerations

- **PowerShell injection prevention**: The `Invoke-Command` parameter injection pattern is used — user values are passed as WinRM `Arguments`, never embedded in the script block text
- **Credential handling**: Credentials are fetched from the SecretStore on every WinRM call and never cached or logged
- **Log sanitization**: All log values that could contain user input are passed through `logging.SanitizeLogValue()`
- **TLS always on**: WinRM connects on port 5986 (HTTPS); `InsecureSkipVerify` is explicitly `false`
- **Least privilege**: The WinRM account needs only the `Hyper-V Administrators` local group — Domain Admin must not be granted

## Related Hypervisor Modules

A future Proxmox, VMware, or KVM module would be implemented as a separate, independent module — not as an extension of this Hyper-V module. Each hypervisor module follows the same shape: a `New(detector)` constructor, a `Configure` method for connection details, and `Get`/`Set` operations with typed resource IDs (e.g., `vm:<name>`, `vswitch:<name>`). Tenant-prefix naming uses the same `cfgms-<sanitizedTenantID>__<resourceName>` convention. Modules do not share code beyond the common `modules.Module` interface — each is platform-specific and ships independently as a copy of this shape, not an extension of it.
