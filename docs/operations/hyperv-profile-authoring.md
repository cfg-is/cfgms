# Adding an Unattended-Install Profile Without Code Changes

This guide is for operators who want CFGMS to provision a **new** OS edition,
locale variant, or enrollment configuration on a Hyper-V host — without modifying
any Go code. You write a stored-config **profile** describing the unattended
answer file, store it in the controller's config backend, and reference it from a
`hyperv.vm` resource as `unattend: profile://<name>`. The module loads, renders,
and applies it at provision time.

This is the operator-facing companion to the
[Hyper-V module README](../../features/modules/hyperv/README.md) section
*VM provisioning from install media*, which covers the `source` block and the
provisioning state machine. Read that first if you have not.

Design of record: ADR-009 §7 (*Unattended profiles are stored config, addable
without code*).

---

## 1. What a profile is and where it lives

A profile is a stored-config object (ADR-003 storage taxonomy) that describes how
to install one OS family unattended:

- which installer family it targets (`linux` or `windows`),
- which answer-file format it produces (`preseed` or `autounattend`),
- the answer-file template itself (a Go `text/template`), and
- an `enroll` block wiring how the freshly installed OS registers back into CFGMS.

Profiles are stored in the controller's stored-config backend under the namespace
**`hyperv/profiles`**, keyed by the profile name. A profile named `debian-12-base`
lives at the key path:

```
hyperv/profiles/debian-12-base
```

The module's `Configure` wiring builds a config-backed profile store from the
controller's config backend (the `config_store` configuration key). When a VM
source references `profile://debian-12-base`, the module reads
`hyperv/profiles/debian-12-base` from that backend, YAML-decodes it into a profile,
validates it, and renders it.

If a VM source omits `unattend`, the module uses a **built-in default** profile for
the `os_family` — `debian-12-base` for linux and `windows-server-default` for
windows. You can override a built-in default by authoring a stored profile of the
**same name**: a stored profile always wins over the code-resident default.

No Go code changes are needed to add a profile. Authoring a stored-config entry is
the entire operation.

---

## 2. Profile YAML schema

A profile is a YAML document with the following fields (the `UnattendProfile`
shape):

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | No | Profile identifier. Must match `^[a-zA-Z0-9_\-]{1,64}$`. If omitted, the key name (the `<name>` in `hyperv/profiles/<name>`) is authoritative. |
| `os_family` | string | Yes | Installer family: `linux` or `windows`. Must match the `source.os_family` of any VM that references this profile. |
| `answer_format` | string | Yes | Answer-file format: `preseed` (Debian/Ubuntu) or `autounattend` (Windows Setup). |
| `template` | string | Yes | The answer-file body as a Go `text/template`. Rendered with `text/template` (never `html/template`), so installer syntax and XML are never HTML-escaped. |
| `enroll` | object | No | Enrollment wiring (below). |

The `enroll` block:

| Field | Type | Description |
|-------|------|-------------|
| `registration_token_secret_key` | string | Secret **key name** under which the enrollment registration token is stored. The value is fetched from the secrets provider at render time. Never put the token value here. |
| `bundle_url` | string | The location the new endpoint pulls its enrollment bundle from. Available in the template as `{{ .BundleURL }}`. Not a secret. |
| `correlation_label` | string | Optional label tying the provisioned VM back to its provisioning record for the controller-side completion reconciler. |
| `use_setup_complete` | boolean | Windows only. When `true`, a file-staged `SetupComplete.cmd` enrollment fallback is rendered instead of relying solely on the signed `.ppkg` at first logon. Linux profiles ignore this. Defaults to `false`. |

### Template variables

The template is rendered with these per-VM variables (supplied by the module at
provision time — never stored in the profile):

| Variable | Description |
|----------|-------------|
| `{{ .VMName }}` | The host-side VM name being provisioned. |
| `{{ .OSFamily }}` | The installer family (`linux` or `windows`). |
| `{{ .CorrelationID }}` | The correlation identity baked into the answer file. The controller-side completion reconciler matches a registered steward's mTLS CN against this value to flip the provisioning record to `ready`. Use it as the guest hostname / enrollment label. |
| `{{ .BundleURL }}` | The enrollment-bundle URL from the profile's `enroll.bundle_url`. |
| `{{ .EnrollToken }}` | A pre-resolved registration token, supplied by the caller when applicable (used by the Windows `SetupComplete.cmd` fallback). |
| `{{ .ProductEdition }}` | Windows only. The Windows Server image/edition name selected in the autounattend image-install step. Ignored by Linux profiles. |
| `{{ secret "key-name" }}` | Resolves the named secret from the secrets provider at render time and inserts its value into the rendered output. See [§5 Secret references](#5-secret-references). |

Template rendering is **all-or-nothing**: if any template field is unknown, the
template fails to parse, or a `{{ secret "..." }}` lookup fails, rendering returns
an error and **no partial answer file** is written to the seed.

---

## 3. Step by step: a new Debian 12 profile

Suppose you want a Debian 12 profile that pins a specific locale and uses your own
enrollment bundle URL. Author the following YAML.

```yaml
# hyperv/profiles/debian-12-acme-corp
name: debian-12-acme-corp
os_family: linux
answer_format: preseed
enroll:
  registration_token_secret_key: hyperv/enroll/regtoken
  bundle_url: https://controller.acme-corp.example/enroll/cfgms-steward.deb
template: |
  # Debian 12 (bookworm) preseed — rendered for VM {{ .VMName }}
  # (correlation {{ .CorrelationID }}).

  d-i debian-installer/locale string en_GB.UTF-8
  d-i keyboard-configuration/xkb-keymap select gb

  d-i clock-setup/utc boolean true
  d-i time/zone string Etc/UTC

  ### Network (DHCP) — CorrelationID is the hostname/enrollment label
  d-i netcfg/choose_interface select auto
  d-i netcfg/get_hostname string {{ .CorrelationID }}
  d-i netcfg/hostname string {{ .CorrelationID }}

  ### Account setup (root locked; one sudo-capable user)
  d-i passwd/root-login boolean false
  d-i passwd/make-user boolean true
  d-i passwd/username string cfgms
  # Secret KEY name only — the crypted password VALUE is resolved at render time.
  d-i passwd/user-password-crypted password {{ secret "hyperv/enroll/user-password-crypted" }}

  ### Partitioning (guided, entire disk, LVM)
  d-i partman-auto/method string lvm
  d-i partman-auto/disk string /dev/sda
  d-i partman-auto/choose_recipe select atomic
  d-i partman/confirm boolean true
  d-i partman/confirm_nooverwrite boolean true

  tasksel tasksel/first multiselect standard, ssh-server
  d-i pkgsel/include string wget ca-certificates

  ### First-boot enrollment — declared paths only, no runtime code composition.
  d-i preseed/late_command string \
    in-target wget -q {{ .BundleURL }} -O /tmp/cfgms-steward.deb ; \
    in-target dpkg -i /tmp/cfgms-steward.deb ; \
    in-target cfgms-steward enroll --token {{ secret "hyperv/enroll/regtoken" }} --label {{ .CorrelationID }}
```

Store it under the `hyperv/profiles` namespace (the exact command depends on your
stored-config tooling; the key path is `hyperv/profiles/debian-12-acme-corp`).
Then reference it from a VM:

```yaml
- name: stw-lin-02
  module: hyperv.vm
  config:
    generation: 2
    cpu_count: 2
    memory_mb: 4096
    vhd_path: C:\ClusterStorage\CSV01\stw-lin-02.vhdx
    switch_name: HVSwitch_1G
    state: running
    source:
      iso: C:\ClusterStorage\CSV01\iso\debian-12.iso
      os_family: linux
      unattend: profile://debian-12-acme-corp
      completion:
        mode: steward-registration
        timeout: 45m
```

Note the `late_command` uses **declared paths only** — each step is a discrete
invocation joined with `;`. No `eval`, no `bash -c "<string>"`, no inline code
composition (CLAUDE.md module banned patterns).

---

## 4. Step by step: a new Windows Server profile

A Windows profile produces an `autounattend.xml`. Windows Setup auto-discovers
`autounattend.xml` from the root of attached removable media (the `CFGMS_SEED`
volume), so no media repack is required. Enrollment runs at first logon via a
signed `.ppkg` referenced by host path (resolved from a secret key).

```yaml
# hyperv/profiles/windows-server-acme-corp
name: windows-server-acme-corp
os_family: windows
answer_format: autounattend
enroll:
  registration_token_secret_key: hyperv/enroll/regtoken
template: |
  <?xml version="1.0" encoding="utf-8"?>
  <unattend xmlns="urn:schemas-microsoft-com:unattend">
    <settings pass="windowsPE">
      <component name="Microsoft-Windows-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
        <ImageInstall>
          <OSImage>
            <InstallFrom>
              <MetaData wcm:action="add" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
                <Key>/IMAGE/NAME</Key>
                <Value>{{ .ProductEdition }}</Value>
              </MetaData>
            </InstallFrom>
          </OSImage>
        </ImageInstall>
        <UserData>
          <AcceptEula>true</AcceptEula>
          <Organization>{{ .CorrelationID }}</Organization>
        </UserData>
      </component>
    </settings>
    <settings pass="specialize">
      <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
        <ComputerName>{{ .VMName }}</ComputerName>
        <RegisteredOrganization>{{ .CorrelationID }}</RegisteredOrganization>
      </component>
    </settings>
    <settings pass="oobeSystem">
      <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
        <FirstLogonCommands>
          <SynchronousCommand wcm:action="add" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
            <Order>1</Order>
            <Description>Stage CFGMS enrollment provisioning package</Description>
            <!-- Secret KEY name only: the host path to the signed .ppkg is resolved at render time. -->
            <CommandLine>cmd.exe /c copy /Y "{{ secret "ppkg-path-key" }}" "C:\Windows\Temp\cfgms-enroll.ppkg"</CommandLine>
          </SynchronousCommand>
          <SynchronousCommand wcm:action="add" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
            <Order>2</Order>
            <Description>Apply CFGMS enrollment provisioning package</Description>
            <CommandLine>dism.exe /online /add-package /packagepath:"C:\Windows\Temp\cfgms-enroll.ppkg" /quiet /norestart</CommandLine>
          </SynchronousCommand>
        </FirstLogonCommands>
      </component>
    </settings>
  </unattend>
```

Reference it from a VM:

```yaml
- name: stw-win-02
  module: hyperv.vm
  config:
    generation: 2
    cpu_count: 4
    memory_mb: 6144
    vhd_path: C:\ClusterStorage\CSV01\stw-win-02.vhdx
    switch_name: HVSwitch_1G
    state: running
    source:
      iso: C:\ClusterStorage\CSV01\iso\windows-server-2025.iso
      os_family: windows
      unattend: profile://windows-server-acme-corp
      completion:
        mode: steward-registration
        timeout: 60m
```

The `<FirstLogonCommands>` use explicit, quoted, declared paths and fixed argument
lists — `cmd.exe /c copy` and `dism.exe /online /add-package`. No
`iex` / `Invoke-Expression`, no `powershell -Command "<string>"`, no
`-EncodedCommand`, no runtime code composition (CLAUDE.md module banned patterns,
ADR-009 §6).

The `.ppkg` referenced via `{{ secret "ppkg-path-key" }}` must be **pre-signed**
and present at the resolved host path; this module does not sign `.ppkg` artifacts.

---

## 5. Secret references

**No secret value ever appears in a profile, in committed config, or on committed
media.** A profile stores only the secret **key name**; the secrets provider
resolves the value at render time and inserts it directly into the rendered
answer-file bytes, which are written to the (transient) seed VHDX and detached at
`finalizing`.

There are two ways a profile pulls a secret:

1. **`{{ secret "key-name" }}` in the template** — resolves the named key against
   the secrets provider at render time. Use this for any credential or sensitive
   host path the answer file must contain (e.g. a crypted password, the `.ppkg`
   host path). Example: `{{ secret "hyperv/enroll/regtoken" }}`.
2. **`enroll.registration_token_secret_key`** — the key name for the enrollment
   registration token; the module resolves the value when wiring enrollment.

Resolution flow:

```
profile (stores KEY name)  ──▶  secrets provider lookup at render time  ──▶  VALUE
        │                                                                     │
        └── never holds the value ──────────────────────────────────────────┘
                                          rendered answer file (on transient seed)
```

Store the secret VALUE in the secrets provider under the key name your profile
references — for example, a placeholder password key:

```sh
cfg secret set --key "hyperv/enroll/user-password-crypted" \
               --value '<crypted-password-placeholder>'

cfg secret set --key "hyperv/enroll/regtoken" \
               --value '<registration-token-placeholder>'
```

Use placeholder values in any documentation or example; never paste a real secret.
If a referenced key is missing, rendering fails with an error and no answer file is
produced — the VM is not provisioned with a partial or empty answer file.

> Note (ADR-009 §8): in v1, a shared/long-lived enrollment secret may sit on the
> seed media during install. Controller-rendered per-VM, single-use, short-TTL
> enrollment tokens are deferred hardening and are not yet available — do not
> document or rely on them.

---

## 6. Referencing a profile from a VM declaration

Reference a stored profile from a `hyperv.vm` resource's `source` block with a
`profile://<name>` URI, where `<name>` is the key under `hyperv/profiles`:

```yaml
source:
  iso: C:\ClusterStorage\CSV01\iso\debian-12.iso
  os_family: linux
  unattend: profile://debian-12-acme-corp
```

Rules:

- The profile name in the URI must match `^[a-zA-Z0-9_\-]{1,64}$`. A malformed
  reference is rejected before any store lookup.
- The profile's `os_family` must match the VM source's `os_family`.
- Omit `unattend` entirely to use the built-in default profile for the
  `os_family` (`debian-12-base` for linux, `windows-server-default` for windows).
- If you reference a `profile://` name that does not exist in the config backend,
  provisioning fails with a profile-not-found error.

---

## 7. Monitoring provisioning state

The module emits a structured log event each time a VM's provisioning record
advances. Watch the steward log on the Hyper-V host for:

```
hyperv: provisioning state advanced  vm_name=stw-lin-02  from_state=absent  to_state=creating  correlation_id=stw-lin-02
hyperv: provisioning state advanced  vm_name=stw-lin-02  from_state=creating  to_state=installing  correlation_id=stw-lin-02
hyperv: provisioning state advanced  vm_name=stw-lin-02  from_state=installing  to_state=finalizing  correlation_id=stw-lin-02
```

What each event means:

- `to_state=creating` — VM, disks, and NICs exist; the seed VHDX and install ISO
  are attached; the Gen2 secure-boot template is selected.
- `to_state=installing` — the VM is powered on and the unattended install is
  running inside the guest. Expect this state to persist for several minutes.
- `to_state=finalizing` — the install was judged complete; the seed VHDX has been
  detached; the guest's first boot is installing and enrolling the steward.

The host-side module stops at `finalizing`. The transition to **`ready`** is made
**controller-side** when the provisioned steward registers and its mTLS CN matches
the record's `correlation_id`. Look for the controller-side event:

```
hyperv completion: steward matched, record advanced to ready  vm_name=stw-lin-02  steward_id=stw-lin-02
```

A failure is logged as:

```
hyperv: provisioning failed  vm_name=stw-lin-02  correlation_id=stw-lin-02
```

---

## 8. Troubleshooting

**State is stuck at `installing`.** This is normal for the duration of the OS
install. The host judges completion conservatively (it waits at least half of
`completion.timeout` and confirms the VM is running before advancing to
`finalizing`). If it never advances, the install inside the guest is not
completing — check that the answer file is valid for the OS edition on the ISO
(open the rendered file by attaching the seed VHDX manually on the host), and that
the ISO matches the `os_family`.

**State went to `failed`.** Either a host-side provisioning step failed (the
`hyperv: provisioning failed` log carries the sanitized VM name; the underlying
error is the convergence error for that cycle), or `completion.timeout` elapsed
with no matching steward registration. Common causes:

- A `{{ secret "..." }}` key referenced by the profile is missing in the secrets
  provider — rendering fails before the VM is provisioned.
- The Windows `.ppkg` host path (resolved from its secret key) does not exist or is
  not signed — first-logon enrollment fails, so the steward never registers and the
  record times out.
- The enrollment bundle URL is unreachable from the guest — the steward is never
  installed, so it never registers.
- The registration token expired before first boot completed — generate the token
  close to provisioning and set a `completion.timeout` that accommodates the
  install duration.

**State is `degraded`.** A real, already-existing VM is unhealthy. The module does
**not** rebuild it. `source` is inert against an existing VM by default; to
deliberately destroy and re-provision, set `source.on_existing: recreate`
(explicit opt-in) — never as an automatic response to a `degraded` VM.

**Provisioning did nothing and the existing VM is untouched.** This is the
existence-gating safety invariant working as designed: `source` is acted on only
when no VM exists by that name. To re-provision, either remove the VM first
(`state: absent`) or set `source.on_existing: recreate`.

---

## Related

- [Hyper-V module README](../../features/modules/hyperv/README.md) — the `source`
  block, provisioning state machine, and seed VHDX mechanism.
- [Hyper-V host onboarding](hyperv-host-onboarding.md) — registering a Hyper-V host
  with CFGMS.
- ADR-009 — Hyper-V VM provisioning from install media (design of record).
