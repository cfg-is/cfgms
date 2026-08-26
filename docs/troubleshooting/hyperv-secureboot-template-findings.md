# hyperv.vm Set-VMFirmware secure-boot template findings (Issue #3169)

## Summary

The `hyperv.vm` module's `Set-VMFirmware -EnableSecureBoot On -SecureBootTemplate
MicrosoftUEFICertificateAuthority` call reproducibly failed during the
2026-07-31/08-01 cfg-lab rebuild, while the identical call succeeded when run
standalone against a throwaway `-NoVHD` test VM. The isolation experiment
required by this issue **could not reproduce the failure at all** — including
in the configuration that was supposed to replicate the original bug exactly.
This disproves the leading hypothesis (conversion-state/attach-timing) as a
deterministic, fixable cause. The module now ships a declared, configurable
`secure_boot` step (Branch B) instead of a settle/verify fix (Branch A), since
Branch A has no confirmed cause to target.

## Isolation experiment

Run 2026-08-07 on `HV-HOST-01` (`Get-VMHost` / `vmms.exe` version
`10.0.26100.32684`), against the cluster's `debian-13-generic-amd64.raw` seed
asset (`C:\ClusterStorage\CSV01\seed-assets\debian-13-generic-amd64.raw`, 3 GB).
Both variants used the module's own conversion functions verbatim (copied
from `features/modules/hyperv/pstransport_preamble_windows.go`:
`Cfgms-VhdFixedFooter` + `Cfgms-PrepCloudBootDisk`) so the boot disk went
through the identical raw → fixed-VHD → dynamic-VHDX pipeline the module
uses, each into a fresh conversion (not a reused/shared disk) to preserve
the "freshly converted" state the hypothesis is about.

**Test 1 — attach-at-creation (replicates the module's actual sequence):**
`Cfgms-PrepCloudBootDisk` → `New-VM -Generation 2 -VHDPath <converted-vhdx>`
→ `Set-VMFirmware -EnableSecureBoot On -SecureBootTemplate
MicrosoftUEFICertificateAuthority`.

Result: **succeeded.** This is the configuration that failed reliably during
the rebuild — it did not fail here.

**Test 2 — isolation variant (per this issue's AC1):** `Cfgms-PrepCloudBootDisk`
→ `New-VM -Generation 2 -NoVHD` → `Add-VMHardDiskDrive -Path
<converted-vhdx>` (separate call, after VM creation) → `Set-VMFirmware
-EnableSecureBoot On -SecureBootTemplate MicrosoftUEFICertificateAuthority`.

Result: **succeeded.**

Full commands are the exact PowerShell reproduced in this issue's isolation
test script (converted-disk pipeline + both attach variants), run via `cfg
steward exec` (SYSTEM) against the HV-HOST-01 steward, output captured to a
local result file. Both VMs and their VHDX files were removed immediately
after each test.

## Interpretation

The test's own baseline (Test 1, which is supposed to reproduce the original
failure) did not fail. That means this isolation experiment cannot validate
or invalidate the conversion-state/attach-timing hypothesis one way or the
other — it can only report that **a plain, single-process PowerShell
re-run of the module's exact commands does not reproduce the bug**, on this
host, today. Two explanations remain open and are not distinguished by this
test:

1. **Execution-context dependence.** The real module splits work across two
   different transport modes (`features/modules/hyperv/pstransport_dispatch_windows.go`):
   `Cfgms-PrepCloudBootDisk` always runs in a **fresh** `powershell.exe -File`
   process (`runFresh` — required because `Convert-VHD` and related cmdlets
   deadlock in the persistent host), while `Cfgms-CreateVMFromDisk` and
   `Cfgms-SetVMFirmware` run in a **persistent**, long-lived `-Command -`
   PowerShell host process reused across many operations. The isolation test
   ran everything in one foreground script — it never exercised that process
   boundary or whatever session/COM/WMI state the persistent host accumulates
   across prior calls. This is the most likely candidate and was not tested
   here due to the added complexity of standing up an equivalent persistent
   host harness; a future investigation could target this specifically if the
   failure resurfaces.
2. **Transient/host-state-specific.** The original failure occurred during a
   rebuild triggered by a wedged exec-dispatch subsystem and steward on this
   same host (`docs/testing/controller-ha-real-cluster-runbook.md` §1
   "Lab rebuild note"). The condition that caused it may not persist on a
   now-stable host.

Given the test's inconclusive result, and per this issue's mandate ("the
agent cannot close this story with only a findings doc and no code change" /
"This branch is required if Branch A's isolation disproves the
conversion-state hypothesis"), Branch A (a settle/verify fix) has nothing
confirmed to target, so **Branch B is the implemented fix**: a declared,
configurable `secure_boot` field.

## Fix: `hyperv.vm` `source.secure_boot`

New optional field on `source:` (`features/modules/hyperv/vm.go`
`SourceConfig.SecureBoot`, Gen2 only — Gen1 has no secure boot):

```yaml
source:
  image: /path/to/cloud-image.raw
  os_family: linux
  secure_boot: enforce      # default — unchanged pre-#3169 behavior
  # secure_boot: best-effort  # log + turn secure boot off on failure, keep converging
  # secure_boot: disabled     # never attempt the template call, turn secure boot off immediately
```

- **`enforce`** (default, matches every pre-#3169 config unchanged): a
  `Set-VMFirmware` template failure fails provisioning, exactly as before.
- **`best-effort`**: the template call is still attempted first; on failure
  it is logged as a warning and secure boot is explicitly turned off
  (`Set-VMFirmware -EnableSecureBoot Off`) so the VM's firmware state is
  deterministic rather than left ambiguous, and provisioning proceeds.
  Without this, a VM hitting this bug fails identically every 5-minute
  convergence cycle, indefinitely, with no path to `installing`.
- **`disabled`**: the template call is never attempted at all; secure boot is
  turned off immediately. For operators who don't need secure boot on a
  given VM class and would rather skip the noise entirely.

This is the same effective workaround already used in production to build
`ctrl-node-1` and `data-svc-vm` by hand
(`C:\temp\ctrl-vm-create.ps1` / `C:\temp\datasvc-vm-create.ps1` on
`HV-HOST-01`, both calling `Set-VMFirmware -EnableSecureBoot Off` directly) —
this issue makes that workaround a first-class, declared module option
instead of an undocumented manual bypass.

Implementation: `features/modules/hyperv/vm_provision.go` `setSecureBoot`;
new PS verb `psDisableVMFirmwareSecureBoot` /
`Cfgms-DisableVMFirmwareSecureBoot` (`pstransport_dispatch_windows.go`,
`pstransport_preamble_windows.go`). Tests:
`TestProvisionVM_SecureBootEnforce_BlocksOnFirmwareFailure`,
`TestProvisionVM_SecureBootBestEffort_RecoversFromFirmwareFailure`,
`TestProvisionVM_SecureBootDisabled_NeverAttemptsTemplate`,
`TestSourceConfig_Validate_SecureBoot` (`features/modules/hyperv/vm_provision_test.go`).
