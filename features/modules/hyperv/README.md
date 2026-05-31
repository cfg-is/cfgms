# Hyper-V Module

Remote Hyper-V management via WinRM for CFGMS. Manages VMs, snapshots, and virtual switches on Windows Server hosts running the Hyper-V role. All PowerShell commands are executed over an authenticated, TLS-encrypted WinRM connection.

## Purpose and scope

The Hyper-V module provides desired-state management of Hyper-V resources on Windows Server hosts via WinRM. It enables CFGMS to create, start, stop, resize, and remove virtual machines, manage checkpoints (snapshots), configure virtual switches, and attach VM network adapters — all through an authenticated, TLS-encrypted WinRM connection.

The module's scope includes:

- **VM lifecycle**: create (`New-VM`), start (`Start-VM`), stop (`Stop-VM`), remove (`Remove-VM`)
- **VM resize**: update CPU count (`Set-VMProcessor`) and startup memory (`Set-VM -MemoryStartupBytes`) on stopped VMs
- **Snapshots**: create, restore, and delete Hyper-V checkpoints
- **Virtual switches**: create and remove External, Internal, and Private vSwitches
- **VM attachment**: add and remove network adapter-to-switch connections

Out of scope: Hyper-V role installation, storage pool management, live migration, replication policies, and controller dispatch wiring (see issue #1790).

## Configuration options

The module accepts the following configuration options via `Configure(cfg)`:

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `winrm_host` | string | Yes | Hostname or IP of the Hyper-V host |
| `winrm_user_secret` | string | Yes | SecretStore key for the WinRM username |
| `winrm_pass_secret` | string | Yes | SecretStore key for the WinRM password |
| `tenant_id` | string | No | Tenant identifier used to namespace host-side resource names |
| `steward_id` | string | No | Steward identifier for audit records (defaults to `<tenantID>/hyperv`) |
| `audit_manager` | `*audit.Manager` | No | Audit manager for recording Hyper-V operations |

VM resource configuration fields (`vm:<name>`):

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `memory_mb` | integer | Yes (create) | Startup memory in MiB |
| `cpu_count` | integer | Yes (create) | Number of virtual processors |
| `vhd_path` | string | Yes (create) | Absolute Windows path to VHD/VHDX |
| `switch_name` | string | Yes (create) | Virtual switch name |
| `generation` | integer | No | VM generation (must be 2 or omitted) |
| `state` | string | No | Desired state: `running`, `stopped`, or `absent` |

## Usage examples

### Create and start a VM

```yaml
resource: vm:web-01
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
resource: vm:web-01
config:
  state: stopped
```

### Resize an existing VM (stop → resize → start)

```yaml
resource: vm:web-01
config:
  cpu_count: 4
  memory_mb: 8192
  state: running
```

### Create a snapshot

```yaml
resource: snapshot:web-01/pre-patch
config:
  state: present
```

### Create an external virtual switch

```yaml
resource: vswitch:External-Switch
config:
  switch_type: external
  net_adapter_name: Ethernet0
  state: present
```

## Known limitations

1. **CPU/memory resize requires a stopped VM** — Hyper-V does not support hot-resize. The module handles this automatically: when `state: running` with a resize, it stops the VM, resizes, then starts it. A brief outage occurs during this sequence.
2. **Generation is fixed at creation** — VM generation cannot be changed after the VM is created.
3. **VHD path is immutable** — The virtual disk path is set at creation and cannot be changed via this module.
4. **Basic auth is structurally disabled** — Only NTLM over HTTPS (port 5986) is supported. WinRM must be configured for HTTPS on the target host.
5. **Integration tests require a live host** — Unit tests use a test implementation of the WinRM transport interface; full end-to-end validation requires `CFGMS_HYPERV_HOST` to be set.

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

All operations use a typed resource ID string:

| Format | Operation |
|--------|-----------|
| `vm:<name>` | Virtual machine management (create, start, stop, remove) |
| `snapshot:<vmname>/<snapname>` | Checkpoint management (create, restore, remove) |
| `vswitch:<name>` | Virtual switch management (create External/Internal/Private, remove) |
| `vmattach:<vmname>/<adaptername>` | Network adapter attachment (add/remove adapter to switch) |

## Tenant-Prefix Naming Convention

Resources created by CFGMS use a tenant-prefixed name to prevent collisions across tenants sharing a Hyper-V host:

```
cfgms-<sanitizedTenantID>__<resourceName>
```

The sanitized tenant ID replaces `/` and other path-unsafe characters with `-`. For example, a VM named `web-01` under tenant `root/msp-a/acme` becomes:

```
cfgms-root-msp-a-acme__web-01
```

This prefix is applied consistently by CFGMS before all Hyper-V operations.

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
- **`TestHypervIntegration_VMLifecycle`** — create → start → stop → snapshot → restore → remove
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

## Security considerations

- **PowerShell injection prevention**: The `Invoke-Command` parameter injection pattern is used — user values are passed as WinRM `Arguments`, never embedded in the script block text
- **Credential handling**: Credentials are fetched from the SecretStore on every WinRM call and never cached or logged
- **Log sanitization**: All log values that could contain user input are passed through `logging.SanitizeLogValue()`
- **TLS always on**: WinRM connects on port 5986 (HTTPS); `InsecureSkipVerify` is explicitly `false`
- **Least privilege**: The WinRM account needs only the `Hyper-V Administrators` local group — Domain Admin must not be granted

## Related Hypervisor Modules

A future Proxmox, VMware, or KVM module would be implemented as a separate, independent module — not as an extension of this Hyper-V module. Each hypervisor module follows the same shape: a `New(detector)` constructor, a `Configure` method for connection details, and `Get`/`Set` operations with typed resource IDs (e.g., `vm:<name>`, `snapshot:<vmname>/<snapname>`). Tenant-prefix naming uses the same `cfgms-<sanitizedTenantID>__<resourceName>` convention. Modules do not share code beyond the common `modules.Module` interface — each is platform-specific and ships independently as a copy of this shape, not an extension of it.
