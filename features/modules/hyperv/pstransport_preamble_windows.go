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
//     machines. Orchestration logic lives in Go in vm.go / vswitch.go /
//     snapshot.go.
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
    $adapter = Get-VMNetworkAdapter -VMName $Name -ErrorAction SilentlyContinue | Select-Object -First 1
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
        SwitchName         = if ($adapter) { $adapter.SwitchName } else { '' }
        State              = $vm.State.ToString()
    }
    ConvertTo-Json $result -Compress
}

# ── VM lifecycle ──────────────────────────────────────────────────────
function Cfgms-CreateVM {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][int]$MemoryMB,
        [Parameter(Mandatory)][int]$CPU,
        [Parameter(Mandatory)][string]$VHDPath,
        [Parameter(Mandatory)][string]$SwitchName,
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
    New-VM -Name $Name -MemoryStartupBytes ($MemoryMB * 1MB) -NewVHDPath $VHDPath -NewVHDSizeBytes ($VHDSizeGB * 1GB) -SwitchName $SwitchName -Generation 2 | Out-Null
    if ($CPU -ne 1) {
        Set-VMProcessor -VMName $Name -Count $CPU
    }
}

function Cfgms-RemoveVM     { param([Parameter(Mandatory)][string]$Name) Remove-VM -Name $Name -Force }
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

function Cfgms-RemoveVSwitch         { param([Parameter(Mandatory)][string]$Name) Remove-VMSwitch -Name $Name -Force }
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

# ── VM ↔ VSwitch attachment ───────────────────────────────────────────
function Cfgms-GetVMAttachment {
    param(
        [Parameter(Mandatory)][string]$VMName,
        [Parameter(Mandatory)][string]$SwitchName
    )
    $adapter = Get-VMNetworkAdapter -VMName $VMName -ErrorAction SilentlyContinue |
        Where-Object { $_.SwitchName -eq $SwitchName } |
        Select-Object -First 1
    if (-not $adapter) { Write-Output '{"found":false}'; return }
    ConvertTo-Json @{ found = $true; AdapterName = $adapter.Name } -Compress
}

function Cfgms-AttachVMDefaultAdapter {
    param([Parameter(Mandatory)][string]$VMName, [Parameter(Mandatory)][string]$SwitchName)
    Add-VMNetworkAdapter -VMName $VMName -SwitchName $SwitchName
}

function Cfgms-AttachVMNamedAdapter {
    param(
        [Parameter(Mandatory)][string]$VMName,
        [Parameter(Mandatory)][string]$SwitchName,
        [Parameter(Mandatory)][string]$Name
    )
    Add-VMNetworkAdapter -VMName $VMName -SwitchName $SwitchName -Name $Name
}

function Cfgms-DetachVMAdapter {
    param([Parameter(Mandatory)][string]$VMName, [Parameter(Mandatory)][string]$Name)
    Remove-VMNetworkAdapter -VMName $VMName -Name $Name
}

# ── Snapshot ──────────────────────────────────────────────────────────
function Cfgms-GetSnapshot {
    param([Parameter(Mandatory)][string]$VMName, [Parameter(Mandatory)][string]$Name)
    $snap = Get-VMSnapshot -VMName $VMName -Name $Name -ErrorAction SilentlyContinue
    if (-not $snap) { Write-Output '{"found":false}'; return }
    Write-Output '{"found":true}'
}

function Cfgms-CreateSnapshot  { param([Parameter(Mandatory)][string]$VMName, [Parameter(Mandatory)][string]$Name) Checkpoint-VM      -VMName $VMName -SnapshotName $Name }
function Cfgms-RemoveSnapshot  { param([Parameter(Mandatory)][string]$VMName, [Parameter(Mandatory)][string]$Name) Remove-VMSnapshot  -VMName $VMName -Name $Name }
function Cfgms-RestoreSnapshot { param([Parameter(Mandatory)][string]$VMName, [Parameter(Mandatory)][string]$Name) Restore-VMSnapshot -VMName $VMName -Name $Name -Confirm:$false }
`
