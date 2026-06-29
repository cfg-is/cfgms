# Hyper-V Module

**Kind:** steward

Hyper-V management for CFGMS. Manages VMs, virtual switches, and (read-only)
failover-cluster state on the Windows Server host the steward runs on. The
module is a **steward** module: it runs in-process on the Hyper-V host's own
steward and drives Hyper-V through a persistent in-host PowerShell host
(`psHostTransport`) — a long-lived `powershell.exe` subprocess on the local
host. It is **not** an outpost module and does **not** manage remote hosts. A
legacy WinRM transport remains as a named fallback for the off-host case, but
the default and supported deployment shape is the in-host PS host.

## Purpose and scope

The Hyper-V module provides desired-state management of Hyper-V resources on the
Windows Server host the steward runs on. It enables CFGMS to create, start,
stop, resize, and remove virtual machines, configure virtual switches, and read
failover-cluster topology and ownership — all by invoking host-native Hyper-V /
Failover-Clustering PowerShell cmdlets through the in-host `psHostTransport`. A
VM's network connection is declared on the VM itself (`switch_name`); the module
converges its adapters to match. All user-supplied values travel via PowerShell
`ArgumentList` — never composed into script text.

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
| `cluster_name` | string | No | Failover-cluster **scope cap** (S5): the single cluster this steward is permitted to read. When set, `Get("cluster:<name>")` and the ownership helper reject any other cluster name with `ErrClusterNotDeclared` **before** touching the transport. Empty disables the cap. |
| `cluster_role_names` | list of strings | No | Bounds the set of clustered VM role names in scope (S5). |

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
| `source.image` | string | One of `image`/`iso` (linux) | Absolute Windows path to a **cloud image** (`.raw` or `.vhdx`) on the Hyper-V host (e.g. `C:\images\debian-13-generic-amd64.raw`). Selects the **cloud-init** path (the default/recommended Linux path): the module prepares the VM's boot disk from this image and delivers enrollment via a NoCloud `CIDATA` seed — no boot-media repack, Secure Boot intact. Ignored for `os_family: windows`. See [Linux provisioning: cloud-init](#linux-provisioning-cloud-init-default). |
| `source.iso` | string | Yes (windows); legacy (linux) | Absolute Windows path to the installation ISO on the Hyper-V host (e.g. `C:\ISO\server.iso`). Required for `os_family: windows` (autounattend). For `os_family: linux` it selects the legacy netinst + preseed path (use `image` instead unless you specifically need ISO install). Never repacked or re-signed. |
| `source.resize_gb` | integer | No | Cloud-init path only: grow the converted boot disk to this many GB (cloud-init `growpart` expands the root filesystem on first boot). `0`/omitted leaves the image at its native size. |
| `source.os_family` | string | Yes | Installer family: `linux` or `windows`. Selects the answer-file format and the Gen2 secure-boot template. |
| `source.unattend` | string | No | Reference to a stored unattended-install profile as a `profile://<name>` URI. Omit to use the built-in default profile for the media kind (`debian-cloudinit-base` for a linux cloud image, `debian-12-base` for a linux ISO, `windows-server-default` for windows). |
| `source.edition` | string | No | Windows only: the exact image name the autounattend `ImageInstall` step selects (the `/IMAGE/NAME` value, e.g. `Windows Server 2025 SERVERSTANDARD`). Omit to use the built-in default. |
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

### Linux provisioning: cloud-init (default)

For Linux, the **default and recommended** path boots a prebuilt **cloud image**
(`source.image`) and enrols via **cloud-init**, rather than running a netinst
installer. This is how Linux VMs are idiomatically provisioned on every cloud and
hypervisor, and it sidesteps the netinst constraint that the kernel command line
(the only way to point an installer at a preseed) can only be set by repacking the
boot media — which breaks the signed shim under Secure Boot.

How it works (all host-native — no `qemu-img`, no `xorriso`, no WSL, no external
tool added to the host):

1. **Boot disk from the cloud image.** A `.raw` cloud image is wrapped with a
   fixed-VHD footer and converted to a dynamic VHDX with the Hyper-V `Convert-VHD`
   cmdlet (a `.vhd`/`.vhdx` image is converted/copied directly), optionally grown
   with `source.resize_gb`. The cloud image's **signed bootloader is never
   modified**, so Secure Boot stays on (Gen2 uses the
   `MicrosoftUEFICertificateAuthority` template).
2. **Enrollment via a NoCloud `CIDATA` seed.** A small FAT32 VHDX labelled
   `CIDATA` carrying `user-data` + `meta-data` (plus the steward binary and the
   controller CA) is attached as a data disk. cloud-init **auto-detects the
   `CIDATA` volume by label on first boot — no kernel command line, no boot-media
   repack.** Its `user-data` `runcmd` (list/exec form only — no shell-string
   composition) runs `cfgms-steward install --regtoken … --ca-cert … --fingerprint
   …`, which on a live system stages the binary, writes the systemd unit, and
   starts enrollment.
3. The seed is detached at `finalizing`; the OS disk is the first boot device.

**Host prerequisite:** the cloud image (`source.image`) must already be on the
host, exactly like an ISO — stage it with the `file` module or out of band. Debian
publishes suitable **generic** cloud images (`.raw`) at
`https://cloud.debian.org/images/cloud/<release>/latest/` (use the `generic`
variant, which ships cloud-init — **not** the `nocloud` variant, which has no
cloud-init). No ISO-builder, no Linux toolchain, and no answer-file repack are
required on the host.

```yaml
- name: stw-lin-01
  module: hyperv.vm
  config:
    generation: 2
    cpu_count: 2
    memory_mb: 2048
    vhd_path: C:\VMs\stw-lin-01.vhdx                          # the converted boot disk
    switch_name: HVSwitch_1G
    state: running
    seed_dir: C:\cfgms-seeds                                  # local (non-CSV) seed dir
    source:
      image: C:\images\debian-13-generic-amd64.raw           # cloud image; signed bootloader untouched
      os_family: linux                                        # selects cloud-init + UEFI-CA template
      resize_gb: 20                                           # grow rootfs on first boot (optional)
      unattend: profile://debian-cloudinit-base               # omit to use the built-in default
      completion:
        mode: steward-registration                            # the only v1 mode
        timeout: 60m
      on_existing: never                                       # default; never destroys an existing VM
```

The enrollment join token and CA fingerprint are supplied via the module's
controller-synced config (`enroll_token`, `enroll_ca_fingerprint`), and the
steward binary + CA are staged from `enroll_steward_path` / `enroll_ca_path` (the
linux steward built for the guest). See [ADR-009](../../../docs/architecture/decisions/009-vm-from-iso-managed-endpoint.md).

### Annotated Linux example (legacy netinst ISO + preseed)

The netinst + preseed path remains available for air-gapped or ISO-only sites that
cannot use a cloud image. Set `source.iso` (instead of `source.image`) for a linux
source to select it. It uses a `CFGMS_SEED` preseed seed VHDX and the install ISO
attached as a DVD; the ISO is never repacked or re-signed.

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
      os_family: linux                                  # with iso (not image) → preseed + UEFI-CA template
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
| `hyperv.cluster` | `name: lab-hv` | `cluster:lab-hv` | Failover-cluster state: `Get` (read-only) member nodes, CNO owner, per-role owners, CSV paths; `Set` clustered VM roles (CNO-gated create + `allow_destructive` removal) |

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

## Failover cluster

`hyperv.cluster` exposes and manages the state of a Windows Server **failover
cluster** the host is a member of. `Get` is read-only (member nodes, CNO owner,
per-role owners, CSV paths); `Set` manages **clustered VM roles** — clustering an
existing VM as a highly-available role and (gated) removing one. Cluster
**formation** (`New-Cluster`, `Add-ClusterNode`, `Remove-ClusterNode`, quorum)
remains out of scope. The module reads and writes cluster state by invoking the
host-native Failover-Clustering cmdlets through the in-host `psHostTransport`;
every cluster and role name travels via `ArgumentList`, never composed into
PowerShell text.

`Get("cluster:<name>")` returns a `ClusterStatus` whose observed fields are:

| Field (`AsMap` key) | Meaning |
|---------------------|---------|
| `name` | The cluster (CNO) name. |
| `member_nodes` | The cluster's member node names (`Get-ClusterNode`). |
| `cno_owner_node` | The node currently owning the core *Cluster Group* (the CNO). Empty when the CNO has no current owner (transient failover). |
| `resource_owner` | Map of each clustered VM role group → its current owner node (`Get-ClusterGroup` where `GroupType -eq 'VirtualMachine'`). |
| `csv_paths` | Cluster Shared Volume friendly volume paths (`Get-ClusterSharedVolume`). |

The four read-only cmdlets the module invokes — `Get-Cluster`,
`Get-ClusterNode`, `Get-ClusterGroup`, and `Get-ClusterSharedVolume` — plus the
two write cmdlets `Add-ClusterVirtualMachineRole` and `Remove-ClusterResource`
(S2) are declared in `module.yaml`'s `behavioral_envelope`. No cluster-formation
cmdlet (`New-Cluster`/`Add-ClusterNode`/`Remove-ClusterNode`/quorum) is declared.

### Managing clustered VM roles (`Set`)

`Set("cluster:<name>", config)` reconciles the **declared** clustered-VM-role set
(`role_names`). Its decision order is:

| Step | Behaviour |
|------|-----------|
| **Scope cap (S5)** | An out-of-scope `<name>` returns `ErrClusterNotDeclared` **before** any cmdlet runs. |
| **CNO gate (S1)** | Only the **CNO-owner** node mutates. A non-owner records an *ownership-gated-skip* audit event and returns `nil` (coordination, not authorization — never an error, never a PS write). |
| **Existence check (idempotency)** | Before clustering a role, the owner checks the live per-role owner map (the same `Get-ClusterGroup` read the ownership gate already performs — no extra PS function). An already-clustered role is a no-op. |
| **Create** | An absent declared role is clustered with `Add-ClusterVirtualMachineRole`. If the cmdlet still reports *already configured / already exists* (a post-failover existence-check↔Add race), that error is normalised to `nil`. **Only** that error class is treated as idempotent — every other PS error surfaces. |
| **Destructive gate (S6)** | `state: absent` removes the role with `Remove-ClusterResource`, but **only** when `allow_destructive: true`. With the default `allow_destructive: false` it returns `ErrDestructiveOpBlocked` **without** invoking any write cmdlet. |
| **Drift-not-adopted (S1)** | Only roles named in `role_names` are ever passed to Add/Remove. A role present on the cluster but absent from the config is **never** created, removed, or adopted — even with `allow_destructive: true`. |

Every `Set` path (create / gated-skip / idempotent no-op / destructive / drift)
records a `pkg/audit` event via the same audit path as `Get`, carrying the node
identity, the CNO-owner decision, the role, and before/after state maps, with a
Go receipt-time `Timestamp` (S8).

```yaml
- name: lab-hv
  module: hyperv.cluster
  config:
    role_names: [web-01, db-01]   # cluster these existing VMs as HA roles
    # state: absent                # opt into teardown of the named roles, AND:
    # allow_destructive: true      # ...required for any role removal (default false)
```

### Ownership gate (coordination, not authorization)

Every downstream cluster operation consults an **ownership helper** that reports
whether *this* node currently owns the CNO group and the per-role owner map. The
gate decides **which** node acts (so a clustered operation runs exactly once
across the members), never **whether** CFGMS may act:

- A **non-owner** node is a *nil skip* — it returns no error and does not block
  CFGMS. Ownership is coordination, not authorization (S1).
- When the CNO group has **no current owner** (a transient failover window), the
  helper returns "not owner" with **no error and no intra-cycle retry**
  (Technical Decision) — the node simply treats itself as non-owner this cycle.
- An **out-of-scope cluster name** (see the scope cap below) returns the
  `ErrClusterNotDeclared` sentinel **regardless of ownership**, before any cmdlet
  runs.

Each ownership decision is recorded as a `pkg/audit` event with a Go
receipt-time `Timestamp` (`time.Now()`, never a PS-reported value) and a
non-empty node identity (the local hostname captured once at `Configure`).

### Scope cap (`cluster_name`)

Set `cluster_name` to bound this steward to a single cluster. With the cap set,
both `Get("cluster:<name>")` and the ownership helper reject any other cluster
name with `ErrClusterNotDeclared` **before invoking any PowerShell cmdlet** — a
host can never be steered into reading a cluster it was not declared against.
`cluster_role_names` further bounds the clustered VM roles in scope.

### Module trust: strict

The `hyperv.cluster` surface requires `module_trust.required_mode: strict` (set
in `module.yaml`). A module that reads failover-cluster ownership and topology —
and (S2) **writes** clustered VM roles — must be **independently verified by the
steward**; the steward must not rely on the controller's word alone for it.

Because S2 extends the `behavioral_envelope` with two write cmdlets
(`Add-ClusterVirtualMachineRole`, `Remove-ClusterResource`), the module bundle
must be **re-signed by the publisher and re-approved** (ADR-006) before
`module_trust: strict` stewards will accept the updated module — a strict steward
re-verifies the signature over the changed manifest independently.

```yaml
- name: lab-hv
  module: hyperv.cluster
  config: {}        # read-only; the steward's cluster_name cap declares scope
```

### Cluster DNA Monitor (`cluster:<name>`)

`Monitor("cluster:<name>", nil)` registers interest in a failover cluster's
membership and ownership and starts a **per-cluster polling goroutine**. Unlike
the VM Monitor (one host-level Event Log subscription), there is no
FailoverCluster event channel, so the module polls the read-only S1 cmdlets on a
ticker and emits a `modules.ChangeEvent` on the `Changes()` channel whenever
ownership or membership changes. The poller stops cleanly on `Close()` (the
goroutine is joined before the channel is closed — no leak, no send on a closed
channel). On non-Windows builds `Monitor("cluster:<name>", …)` returns
`ErrNotSupported`, exactly as it does for `vm:`/`vswitch:`.

- **Poll cadence.** Default **30s**; override with the `cluster_poll_interval`
  Configure key (a Go duration string, e.g. `"15s"`).
- **Anti-flap hysteresis (S8).** A detected change is emitted only after it is
  observed on **two consecutive polls** — a mid-failover CNO transient that
  reverts within one poll interval emits nothing. The first poll establishes the
  baseline and emits nothing (read the initial state via `Get`).
- **Receipt-time (S8).** `ChangeEvent.Timestamp` is `time.Now().Unix()` at
  emission, never a cluster-reported time.

Unlike the VM `ChangeEvent` (`Details: nil` — a re-check signal), the cluster
event carries the observed `*ClusterStatus` as **`Details`** (a
`modules.ConfigState`), the DNA payload the controller-side reconciler (epic
\#415) reads. `Details.AsMap()` exposes the stable keys:

| Key | Meaning |
|-----|---------|
| `member_nodes` | cluster member node names |
| `resource_owner` | per-clustered-VM-role → current owner node |
| `cno_owner_node` | node owning the core Cluster Group (CNO) |
| `csv_paths` | Cluster Shared Volume friendly volume paths |
| `name` | cluster (CNO) name |

```go
// Steward-side consumer (illustrative):
_ = mod.Monitor(ctx, "cluster:lab-hv", nil)
for ev := range mod.Changes() {
    if ev.ResourceID == "cluster:lab-hv" && ev.Details != nil {
        dna := ev.Details.AsMap() // member_nodes, resource_owner, cno_owner_node, ...
        _ = dna
    }
}
```

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
- **Golden-image / template cloning, an image registry, and a branch-build → image pipeline** — these are Phase 3 (#1792). The `source` block provisions either from install media (Windows ISO + autounattend, legacy Linux netinst + preseed) or from a vendor **cloud image** booted with cloud-init (the default Linux path). Booting a stock vendor cloud image is **not** the same as cloning a CFGMS-prepared golden template from an image registry — that pipeline is the later, separate Phase 3 capability.
- Controller-side ISO blob store or ISO distribution (install media is a host path; see [VM provisioning from install media](#vm-provisioning-from-install-media))

## Audit records

Every mutation the module makes to a Hyper-V host is recorded through `pkg/audit` via `recordHypervOp`. An entry is emitted for each PS verb (`New-VM`, `Start-VM`, `Stop-VM`, `Set-VMProcessor`, `Set-VMMemory`, `Remove-VM`, `New-VMSwitch`, `Remove-VMSwitch`, `Add-VMNetworkAdapter`, `Remove-VMNetworkAdapter`).

**Resource identity**: the audit `ResourceID` is always the cfg-declared id (`vm:<name>` or `vswitch:<name>`), never the bare host-side object name.

**Before/after changes**: captured as non-sensitive scalar fields only. The allowed fields per verb are:

| Verb | Before | After |
|------|--------|-------|
| `New-VM` | _(empty)_ | `cpu`, `memory_mb`, `state` |
| `Remove-VM` | `cpu`, `memory_mb`, `state` | _(empty)_ |
| `Set-VMProcessor` | `cpu` | `cpu` |
| `Set-VMMemory` | `memory_mb` | `memory_mb` |
| `Start-VM` / `Stop-VM` | `state` | `state` |
| `Add-VMNetworkAdapter` | _(empty)_ | `switch` (cfg switch id) |
| `Remove-VMNetworkAdapter` | `switch` (cfg switch id) | _(empty)_ |
| `New-VMSwitch` | _(empty)_ | `switch_type`, `state` |
| `Remove-VMSwitch` | `switch_type`, `state` | _(empty)_ |

**Excluded from all records**: live VM names (as bare values), VHD/VHDX paths, live switch names, and any host-side values that could aid lateral movement. Switch names in `Add-VMNetworkAdapter`/`Remove-VMNetworkAdapter` records appear as cfg ids (`vswitch:<name>`), not raw host values.

The before-snapshot for delete operations is captured best-effort immediately before the mutation call. If the snapshot fails (VM/switch already absent, host unreachable), the record is emitted with `before=nil` — the audit record is still correct, just less detailed.

## Security considerations

- **PowerShell injection prevention**: The `Invoke-Command` parameter injection pattern is used — user values are passed as WinRM `Arguments`, never embedded in the script block text
- **Credential handling**: Credentials are fetched from the SecretStore on every WinRM call and never cached or logged
- **Log sanitization**: All log values that could contain user input are passed through `logging.SanitizeLogValue()`
- **TLS always on**: WinRM connects on port 5986 (HTTPS); `InsecureSkipVerify` is explicitly `false`
- **Least privilege**: The WinRM account needs only the `Hyper-V Administrators` local group — Domain Admin must not be granted

## Related Hypervisor Modules

A future Proxmox, VMware, or KVM module would be implemented as a separate, independent module — not as an extension of this Hyper-V module. Each hypervisor module follows the same shape: a `New(detector)` constructor, a `Configure` method for connection details, and `Get`/`Set` operations with typed resource IDs (e.g., `vm:<name>`, `vswitch:<name>`). Tenant-prefix naming uses the same `cfgms-<sanitizedTenantID>__<resourceName>` convention. Modules do not share code beyond the common `modules.Module` interface — each is platform-specific and ships independently as a copy of this shape, not an extension of it.
