// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package hyperv

// psHostPreamble is the script body sent to the PS host once at startup. It
// defines the Cfgms-* verb functions and sets safe defaults.
//
// Each function corresponds to exactly one psXxx const elsewhere in this
// package; the dispatcher in pstransport_dispatch_windows.go maps the
// existing psXxx → Cfgms-VerbName + args.
//
// Function design rules (intentional, do not relax):
//   - Each function wraps EXACTLY ONE cmdlet (or a tiny ConvertTo-Json
//     shaping block around one query). No sequencing, no conditionals
//     beyond the trivial "did this return nothing?" check, no state
//     machines. Orchestration logic lives in Go in vm.go / vswitch.go.
//     Two deliberate exceptions: Cfgms-GetVM (multi-query JSON shaping) and
//     Cfgms-RemoveVM (stop-then-remove is a single host-atomic delete, not
//     Go orchestration — Hyper-V cannot delete a running VM). Both mirror
//     their psXxx const exactly.
//   - All parameters are typed and explicit. Get-Help on each function
//     would produce a sensible signature.
//   - Get-X functions return JSON via ConvertTo-Json -Compress so the Go
//     parsers in *.go (which already expect the JSON shapes from the
//     psXxx constants) keep working unchanged.
//   - Set-X functions return nothing; success is indicated by the absence
//     of an exception. Errors travel via $ErrorActionPreference = 'Stop'
//     and are caught + rethrown by the per-call wrapper in run().
const psHostPreamble = `
# ── Safe defaults ─────────────────────────────────────────────────────
# Stop on any error so the per-call try/catch in the Go transport sees
# the actual failure rather than a silent partial result.
$ErrorActionPreference = 'Stop'
$ProgressPreference   = 'SilentlyContinue'
$WarningPreference    = 'SilentlyContinue'

# ── VM read ───────────────────────────────────────────────────────────
function Cfgms-GetVM {
    param([Parameter(Mandatory)][string]$Name)
    $vm = Get-VM -Name $Name -ErrorAction SilentlyContinue
    if (-not $vm) { Write-Output '{"found":false}'; return }
    # Read ALL network adapters and the switch each is connected to. SwitchNames
    # is the full observed set the declarative multi-NIC reconcile (#2021) diffs
    # against; SwitchName (the first) is kept for the single-NIC back-compat path.
    $adapters = @(Get-VMNetworkAdapter -VMName $Name -ErrorAction SilentlyContinue)
    $switchNames = @($adapters | ForEach-Object { $_.SwitchName } | Where-Object { $_ })
    # $vm.Path is the VM CONFIGURATION directory, not the VHD file. The
    # module's VMConfig.VHDPath stores the path to the virtual disk; read
    # it from Get-VMHardDiskDrive.Path (the first attached disk is the
    # boot/data disk we manage). $vm.Path on its own caused the #1887 B1
    # verification to find 2-changed drift on every successful create.
    $disk = Get-VMHardDiskDrive -VMName $Name -ErrorAction SilentlyContinue | Select-Object -First 1
    # A checkpoint layers a differencing disk (.avhdx) as the ACTIVE disk; the
    # configured base .vhdx becomes the read-only root of the parent chain. Report
    # the chain ROOT as the VHD path so a checkpointed VM — still on its configured
    # disk — does not show false vhd_path drift (#2626). Degrade to the raw path if
    # Get-VHD fails (non-VHD/inaccessible). CheckpointCount is observed-only DNA
    # (not a managed field) so checkpoints are visible but never treated as drift.
    $diskPath = if ($disk) { $disk.Path } else { '' }
    $rootPath = $diskPath
    if ($diskPath) {
        try {
            $v = Get-VHD -Path $diskPath -ErrorAction Stop
            while ($v.ParentPath) { $rootPath = $v.ParentPath; $v = Get-VHD -Path $v.ParentPath -ErrorAction Stop }
        } catch { Write-Warning "Get-VHD chain resolution failed for ${diskPath}: $($_.Exception.Message)" }
    }
    $checkpointCount = @(Get-VMSnapshot -VMName $Name -ErrorAction SilentlyContinue).Count
    # $vm.MemoryStartupBytes is empty on Server 2025's Hyper-V PowerShell
    # module — that property only populates via Get-VMMemory (the proper
    # accessor). Using $vm.<prop> directly returns nil on 2025 even though
    # the VM has memory configured, which caused B1 verification to flag
    # "memory_mb: 0 -> 1024" drift on every successful create. Surfaced
    # 2026-06-08 during live #1852 validation on CFG-70-02.
    $mem = Get-VMMemory -VMName $Name -ErrorAction SilentlyContinue
    $startupBytes = if ($mem) { [long]$mem.Startup } else { 0 }
    $result = @{
        found              = $true
        Name               = $vm.Name
        MemoryStartupBytes = $startupBytes
        ProcessorCount     = [int]$vm.ProcessorCount
        Generation         = [int]$vm.Generation
        Path               = $rootPath
        # The VM's configuration-file directory (#2411). Observed state for the
        # declarative storage-location convergence: the desired location is
        # always dir(vhd_path), so config files anywhere else are drift.
        ConfigurationLocation = [string]$vm.ConfigurationLocation
        # Observed-only (#2626): number of checkpoints on the VM. Surfaced for
        # visibility; absent from GetManagedFields so it never counts as drift.
        CheckpointCount    = [int]$checkpointCount
        SwitchName         = if ($switchNames.Count -gt 0) { $switchNames[0] } else { '' }
        SwitchNames        = $switchNames
        State              = $vm.State.ToString()
    }
    ConvertTo-Json $result -Compress -Depth 4
}

# ── VM lifecycle ──────────────────────────────────────────────────────
function Cfgms-CreateVM {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][int]$MemoryMB,
        [Parameter(Mandatory)][int]$CPU,
        [Parameter(Mandatory)][string]$VHDPath,
        [Parameter(Mandatory)][string]$SwitchName,
        # Generation is a typed parameter (ADR-009 §5 supports Gen1 AND Gen2 —
        # the host-native seed VHDX boots on both, no floppy). The Go dispatcher
        # always passes -Generation (defaulting to 2 when the config omits it),
        # so it is mandatory here; a missing value is a dispatcher bug, not a
        # silent default.
        [Parameter(Mandatory)][int]$Generation,
        # Optional VM home directory (#2411) — dir(vhd_path). When set, New-VM
        # receives it as -Path so the configuration files start co-located with
        # the disk (New-VM appends a VM-name subfolder; the Go create path
        # follows with Cfgms-SetVMHome to land at exactly the home).
        [string]$Path = '',
        # Optional — defaults to a 64 GB dynamic VHD. The schema currently
        # doesn't expose vhd_size_gb so the Go dispatcher never passes one;
        # 64 GB matches the Hyper-V Manager default and is fine for any test
        # VM. Future work: extend VMConfig with VHDSizeGB and propagate from
        # the dispatcher (#1887 follow-up).
        [int]$VHDSizeGB = 64
    )
    # New-VM does NOT accept -ProcessorCount (real PS pitfall — surfaced by
    # PR #1912 live B1 bucket). Create with default 1 vCPU, then resize via
    # Set-VMProcessor only when the operator asked for something different.
    $vmArgs = @{}
    if ($Path) { $vmArgs['Path'] = $Path }
    New-VM -Name $Name -MemoryStartupBytes ($MemoryMB * 1MB) -NewVHDPath $VHDPath -NewVHDSizeBytes ($VHDSizeGB * 1GB) -SwitchName $SwitchName -Generation $Generation @vmArgs | Out-Null
    if ($CPU -ne 1) {
        Set-VMProcessor -VMName $Name -Count $CPU
    }
}

# Cfgms-CreateVMFromDisk creates a VM that boots an EXISTING prepared disk
# (New-VM -VHDPath), used by the cloud-init path where the boot disk is the
# converted cloud image (Cfgms-PrepCloudBootDisk) rather than a fresh empty VHD.
# Mirrors Cfgms-CreateVM except -VHDPath (attach existing) replaces -NewVHDPath.
function Cfgms-CreateVMFromDisk {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][int]$MemoryMB,
        [Parameter(Mandatory)][int]$CPU,
        [Parameter(Mandatory)][string]$VHDPath,
        [Parameter(Mandatory)][string]$SwitchName,
        [Parameter(Mandatory)][int]$Generation,
        # Optional VM home directory (#2411) — see Cfgms-CreateVM.
        [string]$Path = ''
    )
    $vmArgs = @{}
    if ($Path) { $vmArgs['Path'] = $Path }
    New-VM -Name $Name -MemoryStartupBytes ($MemoryMB * 1MB) -VHDPath $VHDPath -SwitchName $SwitchName -Generation $Generation @vmArgs | Out-Null
    if ($CPU -ne 1) {
        Set-VMProcessor -VMName $Name -Count $CPU
    }
}

# Cfgms-RemoveVM mirrors psRemoveVM in vm.go: Hyper-V refuses to remove a VM
# that is not Off ("the operation cannot be performed while the object is in
# its current state"), and a running VM also keeps any connected vSwitch "in
# use" and blocks ITS deletion — so a running VM is hard-powered-off first,
# then removed. A no-op when the VM is already gone. This is (with Cfgms-GetVM)
# one of the two functions that intentionally wraps more than one cmdlet: the
# stop+remove is a single host-atomic delete, not orchestration that belongs
# in Go. Keep it byte-for-byte equivalent to psRemoveVM — the dispatcher maps
# psRemoveVM here, so divergence silently ships the old un-guarded behavior.
function Cfgms-RemoveVM {
    param([Parameter(Mandatory)][string]$Name)
    $vm = Get-VM -Name $Name -ErrorAction SilentlyContinue
    if ($vm) {
        if ($vm.State -ne 'Off') { Stop-VM -Name $Name -Force -TurnOff }
        Remove-VM -Name $Name -Force
    }
}
function Cfgms-RenameVM {
    param([Parameter(Mandatory)][string]$OldName, [Parameter(Mandatory)][string]$NewName)
    Rename-VM -Name $OldName -NewName $NewName -ErrorAction Stop
    # If the VM was registered as a clustered role whose group is named after the
    # old VM name, rename the group too so it tracks the VM. Standalone VMs (no
    # matching cluster group) skip this silently.
    $grp = Get-ClusterGroup -Name $OldName -ErrorAction SilentlyContinue
    if ($grp) { $grp.Name = $NewName }
}
function Cfgms-StartVM      { param([Parameter(Mandatory)][string]$Name) Start-VM -Name $Name }
function Cfgms-StopVM       { param([Parameter(Mandatory)][string]$Name) Stop-VM  -Name $Name -Force }

function Cfgms-SetVMProcessor {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][int]$CPU)
    Set-VMProcessor -VMName $Name -Count $CPU
}

function Cfgms-SetVMMemory {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][int]$MemoryMB)
    Set-VM -Name $Name -MemoryStartupBytes ($MemoryMB * 1MB)
}

# ── Declarative checkpoint policy (#2627) ──────────────────────────────
# Cfgms-GetVMSnapshots lists checkpoints oldest-first as JSON (Name + UTC ISO
# CreationTime) for the Go-side policy evaluation. Cfgms-RemoveVMSnapshot MERGES
# one checkpoint by name (Remove-VMSnapshot folds its differencing disk into the
# parent — non-destructive; never Restore/revert). Both take values only as
# declared params (never string-interpolated).
function Cfgms-GetVMSnapshots {
    param([Parameter(Mandatory)][string]$Name)
    $snaps = @(Get-VMSnapshot -VMName $Name -ErrorAction SilentlyContinue | Sort-Object CreationTime | ForEach-Object { [pscustomobject]@{ Name = $_.Name; CreationTime = $_.CreationTime.ToUniversalTime().ToString('o') } })
    ConvertTo-Json @($snaps) -Compress -Depth 3
}
function Cfgms-RemoveVMSnapshot {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$SnapshotName)
    Remove-VMSnapshot -VMName $Name -Name $SnapshotName -ErrorAction Stop
}

# ── VM network reconcile (declarative multi-NIC, #2021) ────────────────
# Connect/disconnect primitives driven by the VM's desired switch set in
# vm.go reconcileNetwork — NOT a standalone resource. Resurrected from the
# injection-safe Add/Remove-VMNetworkAdapter logic of the removed vmattach
# resource (#1903). Each wraps exactly one cmdlet; orchestration is in Go.
function Cfgms-ConnectVMNic {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$SwitchName)
    Add-VMNetworkAdapter -VMName $Name -SwitchName $SwitchName
}

function Cfgms-DisconnectVMNic {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$SwitchName)
    # Remove the first adapter sitting on the switch being dropped from the
    # desired set. Selecting by SwitchName keeps the primitive purely
    # declarative — no stored adapter name to track.
    $a = Get-VMNetworkAdapter -VMName $Name -ErrorAction SilentlyContinue |
        Where-Object { $_.SwitchName -eq $SwitchName } |
        Select-Object -First 1
    if ($a) { Remove-VMNetworkAdapter -VMNetworkAdapter $a }
}

# ── VM provisioning: seed VHDX + media attach + firmware (ADR-009 §5) ──
# Host-native seed disk (NOT an ISO — oscdimg/ADK is absent on a stock
# Hyper-V host; New-VHD/Mount-VHD/Format-Volume ship with the Hyper-V +
# Storage roles the host already runs). Each function wraps a single logical
# host-atomic step; all user-controlled values travel via parameters.

# SEED VHDX disk ops (New/Mount/Copy/Detach) below run direct cmdlets. They are
# dispatched via the Go transport runFresh() — a fresh powershell.exe -File
# process — NOT the persistent -Command - host. This is REQUIRED: Mount-VHD /
# Dismount-VHD attach the VHD via the async Virtual Disk Service, which DEADLOCKS
# in the persistent stdin-REPL host (and so do Start-Job / Start-Process -Wait
# launched from inside it). A fresh -File process runs them with no deadlock.

# Cfgms-NewSeedVHD creates an empty dynamic VHDX for the answer-file seed,
# creating the parent directory first (seed_dir may be a fresh local path).
function Cfgms-NewSeedVHD {
    param([Parameter(Mandatory)][string]$Path, [int]$SizeBytes = 67108864)
    New-Item -ItemType Directory -Force -Path (Split-Path -Path $Path -Parent) | Out-Null
    if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force }
    New-VHD -Path $Path -SizeBytes $SizeBytes -Dynamic | Out-Null
}

# Cfgms-MountSeedVHD mounts the seed VHDX, lays down a single FAT32 volume
# (label $Label, default CFGMS_SEED — the cloud-init path passes CIDATA), then
# DISMOUNTS (so the later copy step can re-mount; a left-mounted VHD causes a
# 0x80070020 sharing violation on the next Mount-VHD).
function Cfgms-MountSeedVHD {
    param([Parameter(Mandatory)][string]$Path, [string]$Label = 'CFGMS_SEED')
    # try/finally is REQUIRED, not stylistic: without it any failure between the
    # Mount-VHD and the dismount (a Format-Volume error, a partition/letter
    # failure) leaks a host-attached VHD PERMANENTLY. The leak is not confined to
    # this VM — the next VM's Add-VMHardDiskDrive then fails with a 0x80070020
    # sharing violation, so one transient error silently breaks seed provisioning
    # for every subsequent VM on the host until an operator dismounts by hand.
    # Observed on cfg-lab: a seed VHD left Attached=True for two days after its
    # VM had been deleted.
    # $ok distinguishes the two cleanup cases. On the SUCCESS path a dismount
    # failure IS the leak this function exists to prevent, so it must throw. On
    # the FAILURE path it must not: a throwing finally replaces the in-flight
    # exception, losing the real cause — the exact diagnostic blindness that made
    # this class of bug expensive to find.
    $ok = $false
    try {
        Mount-VHD -Path $Path -Passthru |
            Initialize-Disk -PartitionStyle MBR -PassThru |
            New-Partition -UseMaximumSize -AssignDriveLetter |
            Format-Volume -FileSystem FAT32 -NewFileSystemLabel $Label -Confirm:$false | Out-Null
        $ok = $true
    } finally {
        if ($ok) {
            Cfgms-DismountAndVerify -Path $Path
        } else {
            try { Cfgms-DismountAndVerify -Path $Path }
            catch { Write-Warning ('cleanup dismount failed for ' + $Path + ': ' + $_.Exception.Message) }
        }
    }
}

# Cfgms-DismountAndVerify dismounts a seed VHD and confirms it is fully detached
# before returning. A VHD left attached (even transiently after a failed/slow
# dismount) blocks the subsequent Add-VMHardDiskDrive with a 0x80070020
# "in use by another process" error, so the seed build must guarantee detachment.
function Cfgms-DismountAndVerify {
    param([Parameter(Mandatory)][string]$Path)
    Dismount-VHD -Path $Path -ErrorAction SilentlyContinue
    $tries = 0
    while ((Get-VHD -Path $Path -ErrorAction SilentlyContinue).Attached -and $tries -lt 30) {
        Start-Sleep -Milliseconds 200
        Dismount-VHD -Path $Path -ErrorAction SilentlyContinue
        $tries++
    }
    if ((Get-VHD -Path $Path -ErrorAction SilentlyContinue).Attached) {
        throw ('seed VHD still attached to host after dismount: ' + $Path)
    }
}

# Cfgms-CopyToSeedVHD re-mounts the formatted seed (matched by label $Label,
# default CFGMS_SEED), writes $Content to <drive>:\$FileName and — when supplied —
# a second file $Content2 to <drive>:\$FileName2 (the cloud-init path writes both
# user-data and meta-data). It optionally stages the steward binary ($StewardSrc →
# $StewardDest, default cfgms-steward.exe; the linux cloud-init path passes
# cfgms-steward) and the controller CA ($CASrc → controller-ca.crt) so the guest
# can self-install + enroll offline (ADR-010), then dismounts.
function Cfgms-CopyToSeedVHD {
    param(
        [Parameter(Mandatory)][string]$SeedPath,
        [Parameter(Mandatory)][string]$FileName,
        [Parameter(Mandatory)][string]$Content,
        [string]$Label = 'CFGMS_SEED',
        [string]$FileName2 = '',
        [string]$Content2 = '',
        [string]$StewardSrc = '',
        [string]$StewardDest = 'cfgms-steward.exe',
        [string]$LauncherSrc = '',
        [string]$LauncherDest = 'cfgms-steward-launcher',
        [string]$CASrc = ''
    )
    # try/finally is REQUIRED — see the note on Cfgms-MountSeedVHD. A failure in
    # any Set-Content/Copy-Item below (or a null $letter when the labelled volume
    # is not found) would otherwise skip the dismount and leak a host-attached
    # VHD permanently, breaking seed attach for every later VM on this host.
    # See the $ok note on Cfgms-MountSeedVHD: a dismount failure must throw on
    # the success path (it is the leak) but must never replace an in-flight
    # exception on the failure path.
    $ok = $false
    try {
        $disk = Mount-VHD -Path $SeedPath -Passthru
        $letter = ($disk | Get-Disk | Get-Partition | Get-Volume |
            Where-Object { $_.FileSystemLabel -eq $Label } |
            Select-Object -First 1).DriveLetter
        if (-not $letter) { throw ('seed volume with label ' + $Label + ' not found after mount: ' + $SeedPath) }
        Set-Content -Path ($letter + ':\' + $FileName) -Value $Content -NoNewline
        if ($FileName2) { Set-Content -Path ($letter + ':\' + $FileName2) -Value $Content2 -NoNewline }
        if ($StewardSrc -and (Test-Path -LiteralPath $StewardSrc)) { Copy-Item -LiteralPath $StewardSrc -Destination ($letter + ':\' + $StewardDest) -Force }
        if ($LauncherSrc -and (Test-Path -LiteralPath $LauncherSrc)) { Copy-Item -LiteralPath $LauncherSrc -Destination ($letter + ':\' + $LauncherDest) -Force }
        if ($CASrc -and (Test-Path -LiteralPath $CASrc)) { Copy-Item -LiteralPath $CASrc -Destination ($letter + ':\controller-ca.crt') -Force }
        $ok = $true
    } finally {
        if ($ok) {
            Cfgms-DismountAndVerify -Path $SeedPath
        } else {
            try { Cfgms-DismountAndVerify -Path $SeedPath }
            catch { Write-Warning ('cleanup dismount failed for ' + $SeedPath + ': ' + $_.Exception.Message) }
        }
    }
}

# Cfgms-DetachSeedVHD dismounts the seed VHDX from the host (called at
# finalizing). Idempotent via -ErrorAction.
function Cfgms-DetachSeedVHD {
    param([Parameter(Mandatory)][string]$Path)
    Dismount-VHD -Path $Path -ErrorAction SilentlyContinue
}

# Cfgms-DeleteSeedMedia removes the seed VHDX or answer ISO file after
# enrollment (ADR-010 §5). Idempotent — SilentlyContinue means an absent file
# is not an error. The path travels via ArgumentList only; it is never
# interpolated into the script text.
function Cfgms-DeleteSeedMedia {
    param([Parameter(Mandatory)][string]$Path)
    Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
}

# Cfgms-AttachSeedDisk attaches the seed VHDX to the VM as a secondary hard
# disk. $SeedPath travels via ArgumentList.
function Cfgms-AttachSeedDisk {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$SeedPath)
    Add-VMHardDiskDrive -VMName $Name -Path $SeedPath
}

# Cfgms-AttachDVD attaches the install ISO (host path) to the VM as a DVD
# drive. The ISO is never repacked or re-signed (ADR-009 §5). $ISOPath
# travels via ArgumentList.
function Cfgms-AttachDVD {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$ISOPath)
    Add-VMDvdDrive -VMName $Name -Path $ISOPath
}

# Cfgms-SetVMFirmware selects the Gen2 secure-boot template by os_family
# (MicrosoftWindows vs MicrosoftUEFICertificateAuthority). Gen1 VMs have no
# UEFI/secure boot and never call this. $Template travels via ArgumentList.
function Cfgms-SetVMFirmware {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Template)
    Set-VMFirmware -VMName $Name -EnableSecureBoot On -SecureBootTemplate $Template
}

# Cfgms-DisableVMFirmwareSecureBoot turns secure boot off explicitly (#3169
# secure_boot: disabled/best-effort). $Name travels via ArgumentList.
function Cfgms-DisableVMFirmwareSecureBoot {
    param([Parameter(Mandatory)][string]$Name)
    Set-VMFirmware -VMName $Name -EnableSecureBoot Off
}

# Cfgms-SetDVDFirstBoot makes the INSTALL DVD (matched by $ISOPath) the Gen2
# firmware's first boot device so the VM boots the installer rather than the
# empty OS disk or the (bootloader-less) answer ISO. Two DVDs are attached for
# Windows (install ISO + answer ISO), so the install ISO must be selected by
# path. Dispatched via runFresh: Set-VMFirmware -FirstBootDevice references the
# DVD/ISO and deadlocks in the persistent -Command - host.
function Cfgms-SetDVDFirstBoot {
    param([Parameter(Mandatory)][string]$Name, [string]$ISOPath = '')
    $dvd = $null
    if ($ISOPath) { $dvd = Get-VMDvdDrive -VMName $Name | Where-Object { $_.Path -eq $ISOPath } | Select-Object -First 1 }
    if (-not $dvd) { $dvd = Get-VMDvdDrive -VMName $Name | Select-Object -First 1 }
    Set-VMFirmware -VMName $Name -FirstBootDevice $dvd
}

# ── cloud-init (Linux VM-from-cloud-image) ─────────────────────────────
# Host-native cloud-image → VHDX conversion: no qemu-img, no xorriso, no WSL. A
# raw cloud image is wrapped with a fixed-VHD footer (Cfgms-VhdFixedFooter) so
# Convert-VHD can read it, then converted to a dynamic VHDX; a .vhd/.vhdx image is
# converted/copied directly. The cloud image's signed bootloader is never modified
# (Secure Boot stays intact). Dispatched via runFresh (Convert-VHD is heavy I/O).

# Cfgms-VhdFixedFooter returns the 512-byte Microsoft fixed-VHD footer for a disk
# image of $Size bytes (a multiple of 512). All multi-byte fields are big-endian;
# disk geometry (CHS) follows the VHD spec; the checksum is the ones-complement of
# the byte sum (with the checksum field zeroed). Appending it to a raw image
# produces a valid fixed VHD.
function Cfgms-VhdFixedFooter {
    param([Parameter(Mandatory)][long]$Size)
    function _BE { param([uint64]$v, [int]$width)
        $b = New-Object byte[] $width
        for ($i = 0; $i -lt $width; $i++) { $b[$width - 1 - $i] = [byte](($v -shr ($i * 8)) -band 0xFF) }
        return ,$b
    }
    $f = New-Object byte[] 512
    [Array]::Copy([Text.Encoding]::ASCII.GetBytes('conectix'), 0, $f, 0, 8)
    [Array]::Copy((_BE 2 4), 0, $f, 8, 4)                         # features
    [Array]::Copy((_BE 0x00010000 4), 0, $f, 12, 4)              # file format version
    [Array]::Copy((_BE ([uint64]::MaxValue) 8), 0, $f, 16, 8)    # data offset (fixed = all-ones)
    $tstamp = [uint32]([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - 946684800)
    [Array]::Copy((_BE $tstamp 4), 0, $f, 24, 4)                 # timestamp (since 2000-01-01)
    [Array]::Copy([Text.Encoding]::ASCII.GetBytes('cfgm'), 0, $f, 28, 4)   # creator application
    [Array]::Copy((_BE 0x00010000 4), 0, $f, 32, 4)             # creator version
    [Array]::Copy([Text.Encoding]::ASCII.GetBytes('Wi2k'), 0, $f, 36, 4)   # creator host OS (Windows)
    [Array]::Copy((_BE ([uint64]$Size) 8), 0, $f, 40, 8)        # original size
    [Array]::Copy((_BE ([uint64]$Size) 8), 0, $f, 48, 8)        # current size
    # CHS geometry (VHD spec appendix).
    $tsec = [int64]($Size / 512)
    $maxS = [int64]65535 * 16 * 255
    if ($tsec -gt $maxS) { $tsec = $maxS }
    if ($tsec -ge ([int64]65535 * 16 * 63)) {
        $spt = 255; $heads = 16; $cth = [int64]($tsec / $spt)
    } else {
        $spt = 17; $cth = [int64]($tsec / $spt)
        $heads = [int64](($cth + 1023) / 1024)
        if ($heads -lt 4) { $heads = 4 }
        if (($cth -ge ($heads * 1024)) -or ($heads -gt 16)) { $spt = 31; $heads = 16; $cth = [int64]($tsec / $spt) }
        if ($cth -ge ($heads * 1024)) { $spt = 63; $heads = 16; $cth = [int64]($tsec / $spt) }
    }
    $cyl = [int64]($cth / $heads)
    $f[56] = [byte](($cyl -shr 8) -band 0xFF); $f[57] = [byte]($cyl -band 0xFF)
    $f[58] = [byte]$heads; $f[59] = [byte]$spt
    [Array]::Copy((_BE 2 4), 0, $f, 60, 4)                       # disk type = fixed
    [Array]::Copy(([guid]::NewGuid().ToByteArray()), 0, $f, 68, 16)  # unique id
    $sum = [uint64]0
    foreach ($b in $f) { $sum += $b }
    # Ones-complement of the 32-bit byte sum. Use an explicit [uint64] mask: the
    # bare hex literal 0xFFFFFFFF parses as Int32 (-1) in PowerShell, which would
    # make the subtraction negative and fail the [uint32] cast.
    $mask = [uint64]4294967295
    $cks = [uint32]($mask - ($sum -band $mask))
    [Array]::Copy((_BE ([uint64]$cks) 4), 0, $f, 64, 4)         # checksum
    return ,$f
}

# Cfgms-PrepCloudBootDisk prepares the VM boot disk from a cloud image. A .vhdx is
# copied as-is; a .vhd is converted; any other extension is treated as a raw image
# (footer-wrapped → fixed VHD → dynamic VHDX). Optionally resized larger
# ($ResizeBytes > 0; cloud-init growpart expands the rootfs on first boot).
function Cfgms-PrepCloudBootDisk {
    param(
        [Parameter(Mandatory)][string]$ImagePath,
        [Parameter(Mandatory)][string]$VhdPath,
        [long]$ResizeBytes = 0
    )
    New-Item -ItemType Directory -Force -Path (Split-Path -Path $VhdPath -Parent) | Out-Null
    if (Test-Path -LiteralPath $VhdPath) { Remove-Item -LiteralPath $VhdPath -Force }
    $ext = [IO.Path]::GetExtension($ImagePath).ToLowerInvariant()
    if ($ext -eq '.vhdx') {
        Copy-Item -LiteralPath $ImagePath -Destination $VhdPath -Force
    } elseif ($ext -eq '.vhd') {
        Convert-VHD -Path $ImagePath -DestinationPath $VhdPath -VHDType Dynamic
    } else {
        $parent = Split-Path -Path $VhdPath -Parent
        $tmpVhd = Join-Path $parent ([IO.Path]::GetFileNameWithoutExtension($VhdPath) + '.fixed.vhd')
        if (Test-Path -LiteralPath $tmpVhd) { Remove-Item -LiteralPath $tmpVhd -Force }
        Copy-Item -LiteralPath $ImagePath -Destination $tmpVhd -Force
        $size = (Get-Item -LiteralPath $tmpVhd).Length
        if (($size % 512) -ne 0) { throw ('cloud image size not a multiple of 512: ' + $size) }
        $footer = Cfgms-VhdFixedFooter -Size $size
        $fsAppend = [IO.File]::Open($tmpVhd, [IO.FileMode]::Append, [IO.FileAccess]::Write)
        try { $fsAppend.Write($footer, 0, 512) } finally { $fsAppend.Dispose() }
        Convert-VHD -Path $tmpVhd -DestinationPath $VhdPath -VHDType Dynamic
        Remove-Item -LiteralPath $tmpVhd -Force -ErrorAction SilentlyContinue
    }
    if ($ResizeBytes -gt 0) { Resize-VHD -Path $VhdPath -SizeBytes $ResizeBytes }
}

# Cfgms-SetHddFirstBoot makes the OS hard disk (matched by $VHDPath) the Gen2
# firmware's first boot device, so a cloud-init VM boots the cloud image rather
# than the attached CIDATA seed disk. Dispatched via runFresh (Set-VMFirmware
# -FirstBootDevice referencing a disk deadlocks in the persistent host).
function Cfgms-SetHddFirstBoot {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$VHDPath)
    # Match the OS disk by path. Do NOT silently fall back to "first disk found":
    # on a cloud-init VM the seed CIDATA VHDX is also attached, and booting it (a
    # tiny non-bootable FAT32 disk) instead of the OS disk would brick the boot.
    # A genuine no-match is a provisioning bug — fail loudly.
    $hdd = Get-VMHardDiskDrive -VMName $Name | Where-Object { $_.Path -eq $VHDPath } | Select-Object -First 1
    if (-not $hdd) { throw ('OS boot disk not found on VM ' + $Name + ' for path: ' + $VHDPath) }
    Set-VMFirmware -VMName $Name -FirstBootDevice $hdd
}

# Cfgms-BuildAnswerIso builds a small ISO ($IsoPath) carrying the rendered
# answer file ($FileName/$Content) plus, when supplied, the steward binary and
# controller CA, so the new Windows Server 2025 Setup auto-applies the answer
# file (the redesigned Setup scans DVD roots but NOT data disks). Built natively
# via IMAPI2 — no oscdimg/ADK/WSL needed. The IMAPI image IStream is copied to
# the file by a C# helper because the equivalent PowerShell IStream.Read interop
# hangs. Dispatched via runFresh (a fresh process; the COM/file work is heavy and
# must not run in the persistent host).
function Cfgms-BuildAnswerIso {
    param(
        [Parameter(Mandatory)][string]$IsoPath,
        [Parameter(Mandatory)][string]$FileName,
        [Parameter(Mandatory)][string]$Content,
        [string]$StewardSrc = '',
        [string]$CASrc = ''
    )
    Add-Type -ErrorAction SilentlyContinue -TypeDefinition @'
using System; using System.IO; using System.Runtime.InteropServices; using System.Runtime.InteropServices.ComTypes;
public static class CfgmsIsoWriter {
  public static void Save(object comStream, string path) {
    IStream s = (IStream)comStream;
    using (FileStream fs = File.Create(path)) {
      byte[] buf = new byte[1048576];
      IntPtr read = Marshal.AllocHGlobal(4);
      try { while (true) { s.Read(buf, buf.Length, read); int n = Marshal.ReadInt32(read); if (n <= 0) break; fs.Write(buf, 0, n); } }
      finally { Marshal.FreeHGlobal(read); }
    }
  }
}
'@
    $tmp = Join-Path $env:TEMP ('cfgms-ans-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $tmp | Out-Null
    try {
        Set-Content -Path (Join-Path $tmp $FileName) -Value $Content -NoNewline
        if ($StewardSrc -and (Test-Path -LiteralPath $StewardSrc)) { Copy-Item -LiteralPath $StewardSrc -Destination (Join-Path $tmp 'cfgms-steward.exe') -Force }
        if ($CASrc -and (Test-Path -LiteralPath $CASrc)) { Copy-Item -LiteralPath $CASrc -Destination (Join-Path $tmp 'controller-ca.crt') -Force }
        Remove-Item $IsoPath -Force -ErrorAction SilentlyContinue
        $fsi = New-Object -ComObject IMAPI2FS.MsftFileSystemImage
        $fsi.FileSystemsToCreate = 7
        $fsi.VolumeName = 'CFGMS_ANS'
        $fsi.Root.AddTree($tmp, $false)
        $res = $fsi.CreateResultImage()
        [CfgmsIsoWriter]::Save($res.ImageStream, $IsoPath)
    } finally {
        Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Cfgms-BootKeypress drives the VM keyboard for ~40s after power-on to satisfy
# the Windows install media's "Press any key to boot from CD or DVD..." prompt,
# which otherwise times out in a headless VM and the boot loader gives up. Uses
# the Msvm_Keyboard WMI device. Dispatched via runFresh (it blocks ~40s).
function Cfgms-BootKeypress {
    param([Parameter(Mandatory)][string]$Name)
    for ($i = 0; $i -lt 50; $i++) {
        $vm = Get-WmiObject -Namespace root\virtualization\v2 -Class Msvm_ComputerSystem -Filter "ElementName='$Name'"
        $kb = $vm.GetRelated('Msvm_Keyboard') | Select-Object -First 1
        if ($kb) { $kb.TypeKey(0x20) | Out-Null }
        Start-Sleep -Milliseconds 400
    }
}

# ── VM storage location (#2411) ────────────────────────────────────────
# Declarative VM home: the directory of the declared vhd_path holds the VM's
# configuration files AND its disks. Cfgms-SetVMHome is the synchronous
# config-only move used at create; Cfgms-MoveVMStorage is the full live
# migration, run INSIDE a detached process (dispatched via the Go transport's
# runDetached — the executor's per-module-call deadline forbids holding a
# module call open for a multi-minute migration). Failure is surfaced through
# a per-VM error marker under ProgramData that the converge loop probes;
# completion is judged by re-observing the location, never by job objects.

# Cfgms-VMMoveErrFile composes the per-VM move error-marker path. $Name is
# validated upstream against ^[a-zA-Z0-9_\-]{1,64}$ so it is filename-safe.
function Cfgms-VMMoveErrFile {
    param([Parameter(Mandatory)][string]$Name)
    return (Join-Path $env:ProgramData ('cfgms\hyperv\move-' + $Name + '.err'))
}

# Cfgms-SetVMHome homes the VM's configuration files (config + checkpoints +
# smart paging; disks are NOT touched) at exactly $VMHome. New-VM -Path appends
# a VM-name subfolder (verified live on cfg-lab 2026-07-07), so the create path
# always follows New-VM with this move; on a fresh VM it is a KB-scale rename
# that completes well within the module-call deadline. Dispatched via runFresh
# (storage-migration service; the persistent -Command - host deadlocks on
# async storage operations).
function Cfgms-SetVMHome {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$VMHome)
    Move-VMStorage -VMName $Name -VirtualMachinePath $VMHome -SnapshotFilePath $VMHome -SmartPagingFilePath $VMHome
}

# Cfgms-VMStorageMovePreflight reports the bytes required to move the VM's
# disks into $DestDir vs the destination volume's free bytes, as JSON. Only
# disks whose directory differs from $DestDir are counted — disks already at
# the destination do not move (the #2372 shape: disks manually moved to CSV,
# config still local, must not demand disk-sized free space for a KB-scale
# config move). free_bytes is -1 when the volume cannot be resolved; the Go
# caller proceeds and lets the move itself surface a real failure. Get-Volume
# -FilePath resolves CSV mounts (C:\ClusterStorage\...) directly (verified
# live); the walk-up finds the deepest existing ancestor since the destination
# directory may not exist yet.
function Cfgms-VMStorageMovePreflight {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$DestDir)
    $required = [long]0
    foreach ($d in @(Get-VMHardDiskDrive -VMName $Name)) {
        if ((Split-Path -Path $d.Path -Parent).TrimEnd('\') -ine $DestDir.TrimEnd('\')) {
            $required += (Get-Item -LiteralPath $d.Path).Length
        }
    }
    $probe = $DestDir
    while ($probe -and -not (Test-Path -LiteralPath $probe)) { $probe = Split-Path -Path $probe -Parent }
    $free = [long]-1
    if ($probe) {
        $vol = Get-Volume -FilePath $probe -ErrorAction SilentlyContinue
        if ($vol) { $free = [long]$vol.SizeRemaining }
    }
    ConvertTo-Json @{ required_bytes = $required; free_bytes = $free } -Compress
}

# Cfgms-MoveVMStorage performs the full live storage migration: configuration,
# checkpoints, smart paging, and every attached disk whose directory is not
# already $VMHome — each disk lands at $VMHome\<its current leaf> (DIRECTORY-
# level convergence: Hyper-V refuses a -Vhds destination whose file name
# differs from the source — "the source and destination file names must
# match", surfaced live by a checkpointed VM whose current disk is an .avhdx —
# so file names are never changed here). -DestinationStoragePath is
# deliberately NOT used: it drops disks into a "Virtual Hard Disks" subfolder,
# which would never converge the declared vhd_path (verified live on cfg-lab
# 2026-07-07). This function runs INSIDE the detached process (runDetached);
# on failure it writes the error marker the converge loop probes via
# Cfgms-GetVMMoveError.
function Cfgms-MoveVMStorage {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$VMHome
    )
    $errFile = Cfgms-VMMoveErrFile -Name $Name
    New-Item -ItemType Directory -Force -Path (Split-Path -Path $errFile -Parent) | Out-Null
    try {
        $vhds = @()
        foreach ($d in @(Get-VMHardDiskDrive -VMName $Name)) {
            # The [string] casts are REQUIRED: PSObject-wrapped property values
            # inside the -Vhds hashtables fail Move-VMStorage's validation with
            # a misleading "Hash tables in the Vhds parameter must contain
            # 'DestinationFilePath' key" error even though the key is present
            # (root-caused live on cfg-lab 2026-07-07).
            $src = [string]$d.Path
            $dest = [string](Join-Path $VMHome ([string](Split-Path -Path $src -Leaf)))
            if ($src -ine $dest) {
                $vhds += @{ SourceFilePath = $src; DestinationFilePath = $dest }
            }
        }
        if ($vhds.Count -gt 0) {
            Move-VMStorage -VMName $Name -VirtualMachinePath $VMHome -SnapshotFilePath $VMHome -SmartPagingFilePath $VMHome -Vhds $vhds
        } else {
            Move-VMStorage -VMName $Name -VirtualMachinePath $VMHome -SnapshotFilePath $VMHome -SmartPagingFilePath $VMHome
        }
    } catch {
        Set-Content -LiteralPath $errFile -Value $_.Exception.Message
        throw
    }
}

# Cfgms-GetVMMoveError reads the per-VM move error marker as JSON ({"error":""}
# when no failure is recorded).
function Cfgms-GetVMMoveError {
    param([Parameter(Mandatory)][string]$Name)
    $errFile = Cfgms-VMMoveErrFile -Name $Name
    $text = ''
    if (Test-Path -LiteralPath $errFile) {
        $text = [string](Get-Content -LiteralPath $errFile -Raw -ErrorAction SilentlyContinue)
    }
    ConvertTo-Json @{ error = $text.Trim() } -Compress
}

# Cfgms-ClearVMMoveError removes a stale error marker before a (re)dispatch so
# a prior failure is never misattributed to the new attempt. Idempotent.
function Cfgms-ClearVMMoveError {
    param([Parameter(Mandatory)][string]$Name)
    Remove-Item -LiteralPath (Cfgms-VMMoveErrFile -Name $Name) -Force -ErrorAction SilentlyContinue
}

# ── VSwitch read + lifecycle ──────────────────────────────────────────
function Cfgms-GetVSwitch {
    param([Parameter(Mandatory)][string]$Name)
    $sw = Get-VMSwitch -Name $Name -ErrorAction SilentlyContinue
    if (-not $sw) { Write-Output '{"found":false}'; return }
    ConvertTo-Json @{
        found      = $true
        Name       = $sw.Name
        SwitchType = $sw.SwitchType.ToString()
    } -Compress
}

# Cfgms-RemoveVSwitch mirrors psRemoveVSwitch: removing an already-absent
# switch is a clean no-op (Remove-VMSwitch otherwise throws ObjectNotFound).
# Keep it byte-for-byte equivalent to psRemoveVSwitch — the dispatcher maps
# psRemoveVSwitch here.
function Cfgms-RemoveVSwitch {
    param([Parameter(Mandatory)][string]$Name)
    $sw = Get-VMSwitch -Name $Name -ErrorAction SilentlyContinue
    if ($sw) { Remove-VMSwitch -Name $Name -Force }
}
function Cfgms-CreateVSwitchInternal { param([Parameter(Mandatory)][string]$Name) New-VMSwitch -Name $Name -SwitchType Internal | Out-Null }
function Cfgms-CreateVSwitchPrivate  { param([Parameter(Mandatory)][string]$Name) New-VMSwitch -Name $Name -SwitchType Private  | Out-Null }

function Cfgms-CreateVSwitchExternal {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$NetAdapter,
        [Parameter(Mandatory)][bool]$AllowManagementOS
    )
    New-VMSwitch -Name $Name -SwitchType External -NetAdapterName $NetAdapter -AllowManagementOS $AllowManagementOS | Out-Null
}

# ── Failover cluster read (read-only, #2199 S1) ───────────────────────
# Each function wraps a single Get-Cluster* query and emits JSON via
# ConvertTo-Json so the Go parsers in cluster.go keep working unchanged.
# $ClusterName travels via ArgumentList — never interpolated. No write
# cmdlet (Add-*/Remove-*/New-*) appears here; cluster mutation is S2.

# Cfgms-GetCluster mirrors psGetCluster: cluster identity + member node names +
# CSV friendly volume paths. Emits {"found":false} when the cluster is absent.
function Cfgms-GetCluster {
    param([Parameter(Mandatory)][string]$ClusterName)
    $c = Get-Cluster -Name $ClusterName -ErrorAction SilentlyContinue
    if (-not $c) { Write-Output '{"found":false}'; return }
    $nodes = @(Get-ClusterNode -Cluster $ClusterName -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
    $csv = @(Get-ClusterSharedVolume -Cluster $ClusterName -ErrorAction SilentlyContinue | ForEach-Object { $_.SharedVolumeInfo.FriendlyVolumeName })
    ConvertTo-Json @{ found = $true; Name = $c.Name; MemberNodes = $nodes; CsvPaths = $csv } -Compress -Depth 4
}

# Cfgms-GetClusterOwnerNode mirrors psGetClusterOwnerNode: the current owner
# node of the core "Cluster Group" (the CNO). Emits {"owner":""} when the group
# has no current owner (transient failover) so the Go helper treats absence as
# non-error.
function Cfgms-GetClusterOwnerNode {
    param([Parameter(Mandatory)][string]$ClusterName)
    $g = Get-ClusterGroup -Cluster $ClusterName -Name 'Cluster Group' -ErrorAction SilentlyContinue
    if (-not $g -or -not $g.OwnerNode) { Write-Output '{"owner":""}'; return }
    ConvertTo-Json @{ owner = $g.OwnerNode.Name } -Compress
}

# Cfgms-GetClusterResourceOwner mirrors psGetClusterResourceOwner: the current
# owner node of every clustered VM role group (GroupType -eq 'VirtualMachine').
function Cfgms-GetClusterResourceOwner {
    param([Parameter(Mandatory)][string]$ClusterName)
    $owners = @{}
    Get-ClusterGroup -Cluster $ClusterName -ErrorAction SilentlyContinue |
        Where-Object { $_.GroupType -eq 'VirtualMachine' } |
        ForEach-Object { $owners[$_.Name] = if ($_.OwnerNode) { $_.OwnerNode.Name } else { '' } }
    ConvertTo-Json @{ owners = $owners } -Compress -Depth 4
}

# Cfgms-GetClusterAccessSelf mirrors psGetClusterAccessSelf: reports whether THIS
# node's computer account holds cluster-management access (#2306 onboarding).
# Read-only; a denied/absent Get-ClusterAccess read yields access_ok=false. The
# account and the exact remediation grant come from here, never composed in Go.
function Cfgms-GetClusterAccessSelf {
    param([Parameter(Mandatory)][string]$ClusterName)
    $me = '{0}\{1}$' -f $env:USERDOMAIN, $env:COMPUTERNAME
    $acl = @(Get-ClusterAccess -Cluster $ClusterName -ErrorAction SilentlyContinue)
    $ok = @($acl | Where-Object { $_.IdentityReference -ieq $me }).Count -gt 0
    ConvertTo-Json @{ account = $me; access_ok = $ok; remediation = ("Grant-ClusterAccess -Cluster {0} -User '{1}' -Full" -f $ClusterName, $me) } -Compress
}

# ── Failover cluster write (#2202 S2) ─────────────────────────────────
# Each function wraps a single write cmdlet; the exactly-once coordination
# (only the CNO-owner node calls these), the existence/idempotency check, and
# the allow_destructive gate all live in Go (setCluster). $ClusterName/$VMName/
# $Name travel via ArgumentList — never interpolated. Both are dispatched on the
# persistent host: Add-ClusterVirtualMachineRole / Remove-ClusterResource are
# synchronous and do not hit the async-VHD deadlock the seed disk ops do.

# Cfgms-AddClusterVMRole mirrors psAddClusterVMRole: cluster an existing Hyper-V
# VM as a highly-available role. The Go caller normalises an "already
# registered"/"already exists" error to a no-op (idempotency).
function Cfgms-AddClusterVMRole {
    param([Parameter(Mandatory)][string]$ClusterName, [Parameter(Mandatory)][string]$VMName)
    # Cluster by -VMId, NOT -VirtualMachine <name>: the by-name path makes
    # Add-ClusterVirtualMachineRole resolve the VM via a cross-node WMI
    # enumeration (ViridianVirtualMachine.GetAllVirtualMachinesByName ->
    # ManagementScope.Initialize), which fails "Access is denied" when the module
    # runs as the LocalSystem steward. Get-VM -Name is a local WMI call that
    # succeeds; clustering by the resolved -VMId skips the enumeration.
    $vmid = (Get-VM -Name $VMName -ErrorAction Stop).Id
    Add-ClusterVirtualMachineRole -Cluster $ClusterName -VMId $vmid | Out-Null
}

# Cfgms-RemoveClusterResource mirrors psRemoveClusterResource: remove a clustered
# role group. Reached only after the Go destructive gate (allow_destructive:
# true) has confirmed the operator opted in.
function Cfgms-RemoveClusterResource {
    param([Parameter(Mandatory)][string]$Name)
    # Remove the clustered VM ROLE by its GROUP name. Add-ClusterVirtualMachineRole
    # creates a cluster group named after the VM whose resources are named
    # "Virtual Machine <name>" / "Virtual Machine Configuration <name>" — so
    # Remove-ClusterResource -Name <VMname> is ObjectNotFound (that is the group
    # name, not a resource name). Remove-ClusterGroup -RemoveResources removes the
    # group and all its resources (unclustering the VM; the VM itself persists).
    Remove-ClusterGroup -Name $Name -RemoveResources -Force
}

# ── Failover cluster-role properties (#2306 PROPERTIES-B) ──────────────
# Declarative placement/scheduling properties for a clustered VM role. Reconciled
# only on the CNO-owner node, after the role exists (Go gate in setCluster). All
# args travel via ArgumentList; comma-joined owner lists are split here, never
# composed into the command text.

function Cfgms-SetClusterRolePreferredOwners {
    param([Parameter(Mandatory)][string]$ClusterName, [Parameter(Mandatory)][string]$GroupName, [Parameter(Mandatory)][string]$Owners)
    Set-ClusterOwnerNode -Cluster $ClusterName -Group $GroupName -Owners ($Owners -split ',')
}

function Cfgms-SetClusterRolePossibleOwners {
    param([Parameter(Mandatory)][string]$ClusterName, [Parameter(Mandatory)][string]$ResourceName, [Parameter(Mandatory)][string]$Owners)
    # Possible owners apply to the VM RESOURCE inside the role group; $ResourceName
    # is the role (group) name — resolve its Virtual Machine resource. Materialise
    # the match into an array (no Select -First, which trips the FailoverClusters
    # provider with "pipeline has been stopped").
    #
    # Compare via [string] coercion, NOT .OwnerGroup.Name / .ResourceType.Name:
    # depending on the FailoverClusters PowerShell build, Get-ClusterResource
    # returns .OwnerGroup and .ResourceType as plain STRINGS (verified on Windows
    # Server 2025), on which .Name is $null — so a .Name filter silently matches
    # nothing and possible_owners is never applied. [string]$_.OwnerGroup yields
    # the group name whether the property is a string (itself) or a ClusterGroup
    # object (ToString → name), so the filter is robust across builds.
    $res = @(Get-ClusterResource -Cluster $ClusterName -ErrorAction SilentlyContinue | Where-Object { [string]$_.OwnerGroup -eq $ResourceName -and [string]$_.ResourceType -eq 'Virtual Machine' })
    if ($res.Count -gt 0) { Set-ClusterOwnerNode -Cluster $ClusterName -Resource $res[0].Name -Owners ($Owners -split ',') }
}

function Cfgms-SetClusterGroupPriority {
    param([Parameter(Mandatory)][string]$ClusterName, [Parameter(Mandatory)][string]$GroupName, [Parameter(Mandatory)][int]$Priority)
    $g = Get-ClusterGroup -Cluster $ClusterName -Name $GroupName -ErrorAction Stop
    $g.Priority = $Priority
}

function Cfgms-SetClusterGroupAutoStart {
    param([Parameter(Mandatory)][string]$ClusterName, [Parameter(Mandatory)][string]$GroupName, [Parameter(Mandatory)][int]$AutoStart)
    $g = Get-ClusterGroup -Cluster $ClusterName -Name $GroupName -ErrorAction Stop
    $g.AutoStart = $AutoStart
}

function Cfgms-SetClusterGroupAntiAffinity {
    param([Parameter(Mandatory)][string]$ClusterName, [Parameter(Mandatory)][string]$GroupName, [Parameter(Mandatory)][string]$ClassName)
    $g = Get-ClusterGroup -Cluster $ClusterName -Name $GroupName -ErrorAction Stop
    $g.AntiAffinityClassNames = if ($ClassName) { @($ClassName) } else { @() }
}

# ── Cluster-access lifecycle (#2306 option 3, PRIVILEGED) ──────────────
# Controller-orchestrated grant/revoke of node computer accounts, tied to node
# lifecycle. NOT reachable from routine cluster cfg convergence. $NodeName is a
# short node name; the DOMAIN\<node>$ computer account is built here from
# $env:USERDOMAIN, never composed in Go.

function Cfgms-ListClusterAccessNodes {
    param([Parameter(Mandatory)][string]$ClusterName)
    $nodes = @(Get-ClusterAccess -Cluster $ClusterName -ErrorAction SilentlyContinue | Where-Object { $_.IdentityReference -match '\$$' } | ForEach-Object { ($_.IdentityReference -replace '.*\\','') -replace '\$$','' })
    ConvertTo-Json @{ nodes = $nodes } -Compress
}

function Cfgms-GrantClusterAccess {
    param([Parameter(Mandatory)][string]$ClusterName, [Parameter(Mandatory)][string]$NodeName)
    $acct = '{0}\{1}$' -f $env:USERDOMAIN, $NodeName
    Grant-ClusterAccess -Cluster $ClusterName -User $acct -Full
}

function Cfgms-RevokeClusterAccess {
    param([Parameter(Mandatory)][string]$ClusterName, [Parameter(Mandatory)][string]$NodeName)
    $acct = '{0}\{1}$' -f $env:USERDOMAIN, $NodeName
    Remove-ClusterAccess -Cluster $ClusterName -User $acct
}
`
