# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# install-hyperv-host.ps1 — Install cfgms-steward on a Windows Hyper-V host.
#
# Downloads (or uses a pre-built) cfgms-steward binary, verifies the controller
# CA cert fingerprint, then delegates to `cfgms-steward install --hyperv` with
# the WinRM service-account password delivered via stdin pipe — never as argv.
# Polls until the steward reports healthy (up to 60 s). Mirrors the shape of
# build/linux/install.sh for operators familiar with the Linux flow.
#
# Usage (non-interactive):
#   .\scripts\install-hyperv-host.ps1 `
#       -ControllerURL https://ctrl.example.com `
#       -RegToken <token> `
#       -CAFingerprint <lowercase-hex-no-colons>
#
# Usage with pre-built binary (mirrors build/windows/build-msi.ps1 -BinaryPath):
#   .\scripts\install-hyperv-host.ps1 `
#       -ControllerURL https://ctrl.example.com `
#       -RegToken <token> `
#       -CAFingerprint <hash> `
#       -BinaryPath .\artifacts\cfgms-steward.exe
#
# Security notes:
#   - -WinRMPass is a SecureString; its plaintext is live only during the stdin
#     pipe write, then immediately cleared with Remove-Variable + ZeroFreeBSTR.
#   - The plaintext NEVER appears in stdout, stderr, Windows event log, or
#     PowerShell transcripts.
#   - WARNING: Do not pass the same -WinRMPass value across multiple hosts —
#     use the auto-generate path (omit -WinRMPass) for each host so that each
#     host has a unique credential, limiting blast radius if one is compromised.

[CmdletBinding()]
param(
    # Controller URL (required).
    [Parameter(Mandatory = $true)]
    [string]$ControllerURL,

    # Registration token (required).
    [Parameter(Mandatory = $true)]
    [string]$RegToken,

    # CA cert SHA-256 fingerprint, lowercase hex without colons (required for
    # non-interactive runs). Mirrors --fingerprint in build/linux/install.sh.
    [Parameter(Mandatory = $false)]
    [string]$CAFingerprint = "",

    # Path to the controller CA cert PEM file.
    # Default: ca.crt in the same directory as this script (matches bundle layout).
    [Parameter(Mandatory = $false)]
    [string]$CACertPath = "",

    # Version tag to download when BinaryPath is empty (e.g. "v1.2.3").
    # When omitted, the latest GitHub release tag is resolved at runtime.
    [Parameter(Mandatory = $false)]
    [string]$Version = "",

    # Path to a pre-downloaded cfgms-steward binary.
    # When empty, the binary is downloaded from GitHub Releases.
    # Mirrors -BinaryPath in build/windows/build-msi.ps1.
    [Parameter(Mandatory = $false)]
    [string]$BinaryPath = "",

    # WinRM service-account username created during install.
    [Parameter(Mandatory = $false)]
    [string]$WinRMUser = "cfgms-hyperv",

    # WinRM service-account password as a SecureString.
    # WARNING: Do not pass the same -WinRMPass value across multiple hosts —
    # use the auto-generate path (omit -WinRMPass) for each host so that each
    # host has a unique credential, limiting blast radius if one is compromised.
    # When omitted, a 32-byte random password is generated automatically.
    [Parameter(Mandatory = $false)]
    [System.Security.SecureString]$WinRMPass = $null,

    # Maximum seconds to wait for the steward to report healthy.
    # Override via $env:CFGMS_INSTALL_STATUS_TIMEOUT for test isolation
    # (mirrors the CFGMS_INSTALL_PREFIX pattern in build/linux/install.sh).
    [Parameter(Mandatory = $false)]
    [int]$StatusPollTimeoutSeconds = $(
        if ($env:CFGMS_INSTALL_STATUS_TIMEOUT) { [int]$env:CFGMS_INSTALL_STATUS_TIMEOUT } else { 60 }
    )
)

$ErrorActionPreference = "Stop"

$ScriptDir = $PSScriptRoot

# ── Locate CA cert ─────────────────────────────────────────────────────────────

if ($CACertPath -eq "") {
    $DefaultCACert = Join-Path $ScriptDir "ca.crt"
    if (Test-Path $DefaultCACert) {
        $CACertPath = $DefaultCACert
    }
}

# ── Fingerprint verification ───────────────────────────────────────────────────
# Mirrors build/linux/install.sh:73-110. Compute SHA-256 from $CACertPath,
# normalise to lowercase hex without colons, compare to caller-supplied value.
# Exit non-zero before any install action if there is a mismatch.

if ($CACertPath -ne "") {
    if (-not (Test-Path $CACertPath)) {
        Write-Error "CA cert not found: $CACertPath"
    }

    if ($CAFingerprint -ne "") {
        # Non-interactive: compute and compare.
        $CertBytes  = [System.IO.File]::ReadAllBytes($CACertPath)
        $Cert        = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertBytes)
        $Sha256      = [System.Security.Cryptography.SHA256]::Create()
        $Hash        = $Sha256.ComputeHash($Cert.RawData)
        $Computed    = ($Hash | ForEach-Object { $_.ToString("x2") }) -join ""
        $Expected    = $CAFingerprint.ToLowerInvariant() -replace ":", ""

        if ($Computed -ne $Expected) {
            Write-Host "Fingerprint mismatch:" -ForegroundColor Red
            Write-Host "  expected: $Expected"
            Write-Host "  computed: $Computed"
            Write-Host "Installation aborted. Verify the CA fingerprint before deploying." -ForegroundColor Red
            exit 1
        }
        Write-Host "CA fingerprint verified." -ForegroundColor Green
    } else {
        # Interactive: display computed fingerprint and prompt.
        $CertBytes = [System.IO.File]::ReadAllBytes($CACertPath)
        $Cert      = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertBytes)
        $Sha256    = [System.Security.Cryptography.SHA256]::Create()
        $Hash      = $Sha256.ComputeHash($Cert.RawData)
        $Displayed = ($Hash | ForEach-Object { $_.ToString("x2") }) -join ""

        Write-Host ""
        Write-Host "CA Certificate Fingerprint (SHA-256):"
        Write-Host "  $Displayed"
        Write-Host ""
        $Answer = Read-Host "Verify this fingerprint against your controller --init output. Continue? [y/N]"
        if ($Answer -notmatch "^[yY]") {
            Write-Host "Installation aborted. Verify the CA fingerprint before deploying." -ForegroundColor Red
            exit 1
        }
    }
}

# ── Resolve binary ─────────────────────────────────────────────────────────────

if ($BinaryPath -eq "") {
    # Resolve version from latest GitHub release when not specified.
    if ($Version -eq "") {
        Write-Host "Resolving latest cfgms-steward release..." -ForegroundColor Yellow
        try {
            $Release = Invoke-RestMethod -Uri "https://api.github.com/repos/cfg-is/cfgms/releases/latest" `
                -Headers @{ "User-Agent" = "cfgms-install-hyperv-host" }
            $Version = $Release.tag_name
        } catch {
            Write-Error "Failed to resolve latest release tag: $_"
        }
        Write-Host "  Latest version: $Version"
    }

    $DownloadURL = "https://github.com/cfg-is/cfgms/releases/download/$Version/cfgms-steward-windows-amd64.exe"
    $TempBinary  = Join-Path $env:TEMP "cfgms-steward-$Version.exe"

    if (-not (Test-Path $TempBinary)) {
        Write-Host "Downloading cfgms-steward $Version..." -ForegroundColor Yellow
        try {
            Invoke-WebRequest -Uri $DownloadURL -OutFile $TempBinary -UseBasicParsing
        } catch {
            Write-Error "Failed to download binary from $DownloadURL`: $_"
        }
        Write-Host "  Downloaded: $TempBinary" -ForegroundColor Green
    } else {
        Write-Host "Using cached binary: $TempBinary"
    }

    $BinaryPath = $TempBinary
} else {
    if (-not (Test-Path $BinaryPath)) {
        Write-Error "Binary not found: $BinaryPath"
    }
    Write-Host "Using pre-built binary: $BinaryPath"
}

# ── Generate WinRM password when not supplied ─────────────────────────────────

if ($null -eq $WinRMPass) {
    $RandomBytes = [byte[]]::new(32)
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($RandomBytes)
    $RandomBase64 = [Convert]::ToBase64String($RandomBytes)
    $WinRMPass   = ConvertTo-SecureString -String $RandomBase64 -AsPlainText -Force
    Remove-Variable RandomBytes, RandomBase64
    Write-Host "WinRM password auto-generated (unique per host)." -ForegroundColor Green
}

# ── Invoke cfgms-steward install via stdin pipe ────────────────────────────────
# SECURITY: plaintext is live only for the duration of the pipe write.
# Remove-Variable immediately follows. The value MUST NOT appear in argv.

Write-Host ""
Write-Host "Installing CFGMS Steward (Hyper-V host)..." -ForegroundColor Cyan

$InstallArgs = @(
    "install",
    "--regtoken", $RegToken,
    "--hyperv",
    "--winrm-user", $WinRMUser,
    "--winrm-pass-stdin"
)

if ($CACertPath -ne "") {
    $InstallArgs += @("--ca-cert", $CACertPath)
}
if ($CAFingerprint -ne "") {
    $InstallArgs += @("--fingerprint", ($CAFingerprint.ToLowerInvariant() -replace ":", ""))
}
if ($ControllerURL -ne "") {
    $InstallArgs += @("--controller-url", $ControllerURL)
}

$bstr  = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($WinRMPass)
$plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)

$plain | & $BinaryPath @InstallArgs
$InstallExit = $LASTEXITCODE

Remove-Variable plain

if ($InstallExit -ne 0) {
    Write-Host "cfgms-steward install failed (exit $InstallExit)." -ForegroundColor Red
    exit $InstallExit
}

Write-Host "Install command succeeded." -ForegroundColor Green

# ── Poll until steward reports healthy ────────────────────────────────────────

Write-Host ""
Write-Host "Waiting for steward to report healthy (up to $StatusPollTimeoutSeconds s)..." -ForegroundColor Yellow

$Deadline = (Get-Date).AddSeconds($StatusPollTimeoutSeconds)
$Healthy  = $false

while ((Get-Date) -lt $Deadline) {
    $StatusExit = 0
    & $BinaryPath status 2>&1 | Out-Null
    $StatusExit = $LASTEXITCODE
    if ($StatusExit -eq 0) {
        $Healthy = $true
        break
    }
    Start-Sleep -Seconds 5
}

if ($Healthy) {
    Write-Host ""
    Write-Host "CFGMS Steward is registered and healthy." -ForegroundColor Green
    exit 0
} else {
    Write-Host ""
    Write-Host "Timeout: steward did not report healthy within $StatusPollTimeoutSeconds s." -ForegroundColor Red
    Write-Host "Check the steward logs: Get-EventLog -LogName Application -Source cfgms-steward" -ForegroundColor Yellow
    exit 1
}
