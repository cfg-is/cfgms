<#
.SYNOPSIS
Resource sampler for CFGMS self-hosted CI runners (Windows).

.DESCRIPTION
Backgrounds a CPU+memory sampling loop during a job; reports peak values on completion.
State dir should be $env:RUNNER_TEMP-scoped (job-unique) — not $env:TEMP.

.PARAMETER Mode
Start    — background the sampling loop; write PID to <StateDir>\sampler.pid.
Report   — kill the sampler, compute peaks, emit one RESOURCE_PROFILE: line.
Loop     — internal: the actual sampling loop (invoked by Start via Start-Process).

.PARAMETER StateDir
Directory for sampler state (samples.txt, sampler.pid).  Created by Start if absent.

.PARAMETER ArtifactOut
Output artifact file path (required for Report mode).

.EXAMPLE
resource-sampler.ps1 -Mode Start  -StateDir "$env:RUNNER_TEMP\resource-sampler"
resource-sampler.ps1 -Mode Report -StateDir "$env:RUNNER_TEMP\resource-sampler" -ArtifactOut "resource-samples-native-windows.txt"

RESOURCE_PROFILE: line formats:
  success: os=windows cpu_peak_pct=<n> mem_peak_mb=<peak>/<total> vm=<n>vCPU/<n>GB
  error:   os=windows error=<reason> vm=<n>vCPU/<n>GB
  reason values: sampler_start_failed | no_samples_collected

Loop is bounded at 720 iterations (~60 min at 5 s each) so an interrupted job
cannot leave an orphaned sampler running indefinitely on a persistent runner.
Background spawn uses 'powershell' (never 'pwsh') per Issue #2485 AC1.
Style follows .github/scripts/install-trivy.sh.
#>
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('Start', 'Report', 'Loop')]
    [string]$Mode,

    [Parameter(Mandatory=$true)]
    [string]$StateDir,

    [string]$ArtifactOut = ""
)

$SamplesFile = Join-Path $StateDir "samples.txt"
$PidFile     = Join-Path $StateDir "sampler.pid"

switch ($Mode) {
    'Start' {
        $ErrorActionPreference = 'Stop'
        if (-not (Test-Path $StateDir)) {
            New-Item -ItemType Directory -Path $StateDir | Out-Null
        }
        $thisScript = $PSCommandPath
        $proc = Start-Process powershell -ArgumentList @(
            '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
            '-File', $thisScript, '-Mode', 'Loop', '-StateDir', $StateDir
        ) -PassThru -WindowStyle Hidden
        $proc.Id | Set-Content $PidFile -Encoding UTF8
        Write-Host "resource-sampler: started (pid=$($proc.Id), state=${StateDir})"
    }

    'Loop' {
        # Sampling loop: try/catch around every read so one failure skips one
        # 5 s sample without killing the loop.  Bounded at 720 iterations.
        $iter    = 0
        $maxIter = 720
        while ($iter -lt $maxIter) {
            try {
                $cpuVal     = (Get-Counter '\Processor(_Total)\% Processor Time' -ErrorAction Stop).CounterSamples[0].CookedValue
                $memAvailMB = (Get-Counter '\Memory\Available MBytes' -ErrorAction Stop).CounterSamples[0].CookedValue
                $memTotalMB = [Math]::Round((Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).TotalPhysicalMemory / 1MB)
                $cpuPct     = [Math]::Round($cpuVal)
                $memUsedMB  = $memTotalMB - [Math]::Round($memAvailMB)
                $ts         = Get-Date -Format 'HH:mm:ss'
                Add-Content $SamplesFile "$ts cpu_pct=$cpuPct mem_used_mb=$memUsedMB/$memTotalMB"
            } catch {}
            Start-Sleep -Seconds 5
            $iter++
        }
    }

    'Report' {
        $ErrorActionPreference = 'Stop'
        if ([string]::IsNullOrEmpty($ArtifactOut)) {
            Write-Error "ArtifactOut is required for Report mode"
            exit 2
        }

        # Real VM spec from CIM (never hardcoded).
        $vCPU  = 0
        $ramGB = 0
        try {
            $cs    = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
            $vCPU  = $cs.NumberOfLogicalProcessors
            $ramGB = [Math]::Round($cs.TotalPhysicalMemory / 1GB)
        } catch {}
        $vmSpec = "${vCPU}vCPU/${ramGB}GB"

        # Kill the sampler (best-effort; may have already exited).
        if (Test-Path $PidFile) {
            try {
                $samplerPid = [int](Get-Content $PidFile -Raw -ErrorAction Stop).Trim()
                Stop-Process -Id $samplerPid -ErrorAction SilentlyContinue
            } catch {}
        }

        if (-not (Test-Path $PidFile)) {
            Write-Host "RESOURCE_PROFILE: os=windows error=sampler_start_failed vm=${vmSpec}"
            "" | Set-Content $ArtifactOut -Encoding UTF8
        } elseif (-not (Test-Path $SamplesFile) -or (Get-Item $SamplesFile).Length -eq 0) {
            Write-Host "RESOURCE_PROFILE: os=windows error=no_samples_collected vm=${vmSpec}"
            "" | Set-Content $ArtifactOut -Encoding UTF8
        } else {
            $cpuPeak = 0; $memPeak = 0; $memTotal = 0
            foreach ($line in (Get-Content $SamplesFile)) {
                if ($line -match 'cpu_pct=(\d+)') {
                    $v = [int]$Matches[1]; if ($v -gt $cpuPeak) { $cpuPeak = $v }
                }
                if ($line -match 'mem_used_mb=(\d+)/(\d+)') {
                    $v = [int]$Matches[1]; if ($v -gt $memPeak) { $memPeak = $v }
                    $memTotal = [int]$Matches[2]
                }
            }
            Write-Host "RESOURCE_PROFILE: os=windows cpu_peak_pct=$cpuPeak mem_peak_mb=$memPeak/$memTotal vm=$vmSpec"
            Copy-Item $SamplesFile $ArtifactOut
        }
    }
}
