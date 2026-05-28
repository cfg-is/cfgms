# Hyper-V Module

Remote Hyper-V management via WinRM for CFGMS. Manages VMs, snapshots, and virtual switches on Windows Server hosts running the Hyper-V role. All PowerShell commands are executed over an authenticated, TLS-encrypted WinRM connection.

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

## Security Notes

- PowerShell injection is prevented by the `Invoke-Command` parameter injection pattern — user values are passed as WinRM `Arguments`, never embedded in the script block text
- Credentials are fetched from the SecretStore on every call and never logged
- All log values that could contain user input are passed through `logging.SanitizeLogValue()`
