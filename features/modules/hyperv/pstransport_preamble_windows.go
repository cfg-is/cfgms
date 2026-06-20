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
        Path               = if ($disk) { $disk.Path } else { '' }
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
    New-VM -Name $Name -MemoryStartupBytes ($MemoryMB * 1MB) -NewVHDPath $VHDPath -NewVHDSizeBytes ($VHDSizeGB * 1GB) -SwitchName $SwitchName -Generation $Generation | Out-Null
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

# Cfgms-RunDiskScript runs a disk/VHD script in a FRESH powershell.exe child via
# Start-Process -Wait. This is REQUIRED for Mount-VHD / Dismount-VHD: those
# cmdlets attach the VHD asynchronously via the Virtual Disk Service, which
# DEADLOCKS when run in this persistent stdin-REPL host (powershell.exe
# -Command -) — and so do Start-Job / Wait-Job (they share the host's async
# machinery). Start-Process -Wait blocks on the OS process handle, which does NOT
# deadlock, and the child (a normal -File invocation) runs the disk cmdlets fine.
# $BodyLines are written to a temp .ps1; $ScriptArgs bind positionally to its
# param() block (never interpolated into script text). A non-zero child exit
# re-throws the captured stderr.
function Cfgms-RunDiskScript {
    param([Parameter(Mandatory)][string[]]$BodyLines, [string[]]$ScriptArgs = @())
    $tmp = Join-Path $env:TEMP ('cfgms-seed-' + [guid]::NewGuid().ToString('N') + '.ps1')
    $errFile = $tmp + '.err'
    Set-Content -Path $tmp -Value $BodyLines -Encoding UTF8
    try {
        $quoted = ($ScriptArgs | ForEach-Object { '"' + ($_ -replace '"', '""') + '"' }) -join ' '
        $argLine = '-NoProfile -NonInteractive -File "' + $tmp + '" ' + $quoted
        $pr = Start-Process -FilePath 'powershell.exe' -ArgumentList $argLine -Wait -PassThru -WindowStyle Hidden -RedirectStandardError $errFile
        if ($pr.ExitCode -ne 0) {
            $e = ''
            if (Test-Path $errFile) { $e = (Get-Content $errFile -Raw) }
            throw ('hyperv seed disk script exit ' + $pr.ExitCode + ': ' + $e)
        }
    } finally {
        Remove-Item $tmp, $errFile -Force -ErrorAction SilentlyContinue
    }
}

# Cfgms-NewSeedVHD creates an empty dynamic VHDX for the answer-file seed,
# creating the parent directory first (seed_dir may be a fresh local path).
# New-VHD is synchronous and is safe to run in-host.
function Cfgms-NewSeedVHD {
    param([Parameter(Mandatory)][string]$Path, [int]$SizeBytes = 67108864)
    New-Item -ItemType Directory -Force -Path (Split-Path -Path $Path -Parent) | Out-Null
    New-VHD -Path $Path -SizeBytes $SizeBytes -Dynamic | Out-Null
}

# Cfgms-MountSeedVHD mounts the seed VHDX, lays down a single FAT32 volume
# labelled CFGMS_SEED, then DISMOUNTS (so the later copy step can re-mount; a
# left-mounted VHD causes a 0x80070020 sharing violation on the next Mount-VHD).
# Runs in a fresh child process (Mount-VHD deadlocks in the persistent host).
function Cfgms-MountSeedVHD {
    param([Parameter(Mandatory)][string]$Path)
    Cfgms-RunDiskScript -ScriptArgs $Path -BodyLines @(
        'param([string]$p)',
        '$ErrorActionPreference = ''Stop''',
        '$ProgressPreference = ''SilentlyContinue''',
        'Mount-VHD -Path $p -Passthru | Initialize-Disk -PartitionStyle MBR -PassThru | New-Partition -UseMaximumSize -AssignDriveLetter | Format-Volume -FileSystem FAT32 -NewFileSystemLabel ''CFGMS_SEED'' -Confirm:$false | Out-Null',
        'Dismount-VHD -Path $p'
    )
}

# Cfgms-CopyToSeedVHD re-mounts the formatted seed, writes $Content to
# <drive>:\$FileName, optionally stages the steward binary ($StewardSrc →
# cfgms-steward.exe) and controller CA ($CASrc → controller-ca.crt) so a Windows
# guest can self-install + enroll offline (ADR-010), then dismounts. Runs in a
# fresh child process (Mount-VHD deadlocks in the persistent host). The answer
# content is handed to the child via a temp file (avoids argv size/quoting
# limits); paths bind positionally.
function Cfgms-CopyToSeedVHD {
    param(
        [Parameter(Mandatory)][string]$SeedPath,
        [Parameter(Mandatory)][string]$FileName,
        [Parameter(Mandatory)][string]$Content,
        [string]$StewardSrc = '',
        [string]$CASrc = ''
    )
    $contentFile = Join-Path $env:TEMP ('cfgms-ans-' + [guid]::NewGuid().ToString('N') + '.tmp')
    Set-Content -Path $contentFile -Value $Content -NoNewline
    try {
        Cfgms-RunDiskScript -ScriptArgs $SeedPath, $FileName, $contentFile, $StewardSrc, $CASrc -BodyLines @(
            'param([string]$sp,[string]$fn,[string]$cf,[string]$ss,[string]$ca)',
            '$ErrorActionPreference = ''Stop''',
            '$ProgressPreference = ''SilentlyContinue''',
            '$content = Get-Content -LiteralPath $cf -Raw',
            '$disk = Mount-VHD -Path $sp -Passthru',
            '$letter = ($disk | Get-Disk | Get-Partition | Get-Volume | Where-Object { $_.FileSystemLabel -eq ''CFGMS_SEED'' } | Select-Object -First 1).DriveLetter',
            'Set-Content -Path ($letter + '':\'' + $fn) -Value $content -NoNewline',
            'if ($ss -and (Test-Path -LiteralPath $ss)) { Copy-Item -LiteralPath $ss -Destination ($letter + '':\cfgms-steward.exe'') -Force }',
            'if ($ca -and (Test-Path -LiteralPath $ca)) { Copy-Item -LiteralPath $ca -Destination ($letter + '':\controller-ca.crt'') -Force }',
            'Dismount-VHD -Path $sp'
        )
    } finally {
        Remove-Item $contentFile -Force -ErrorAction SilentlyContinue
    }
}

# Cfgms-DetachSeedVHD dismounts the seed VHDX from the host (called at
# finalizing). Idempotent via -ErrorAction. Runs in a fresh child process for the
# same Dismount-VHD-deadlock reason as the mount path.
function Cfgms-DetachSeedVHD {
    param([Parameter(Mandatory)][string]$Path)
    Cfgms-RunDiskScript -ScriptArgs $Path -BodyLines @(
        'param([string]$p)',
        '$ProgressPreference = ''SilentlyContinue''',
        'Dismount-VHD -Path $p -ErrorAction SilentlyContinue'
    )
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
`
