# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jordan Ritz
#
# build-msi.ps1 — Build a Windows MSI installer for cfgms-steward using WiX 4.
#
# Prerequisites:
#   - Go toolchain (for building the binary when -BinaryPath is not supplied)
#   - .NET SDK (WiX is installed automatically via dotnet tool if absent)
#
# Code signing (optional):
#   Provide -SigningCertThumbprint to sign with signtool.exe from the Windows SDK.
#   Without it the MSI is produced unsigned and a warning is printed.
#   Windows SmartScreen may flag unsigned installers; sign production builds.
#
# Usage examples:
#   # Build and sign for amd64:
#   .\build\windows\build-msi.ps1 `
#       -ControllerURL https://ctrl.example.com `
#       -Version v1.0.0 `
#       -SigningCertThumbprint AABBCCDD...
#
#   # Use a pre-built binary (e.g., from CI artifact):
#   .\build\windows\build-msi.ps1 `
#       -ControllerURL https://ctrl.example.com `
#       -Version v1.0.0 `
#       -BinaryPath .\artifacts\cfgms-steward-windows-amd64.exe
#
#   # Build arm64 MSI:
#   .\build\windows\build-msi.ps1 `
#       -ControllerURL https://ctrl.example.com `
#       -Version v1.0.0 `
#       -Arch arm64

[CmdletBinding()]
param(
    # Controller URL baked into the steward binary at build time.
    # The binary only connects to the controller it was built for (trust assertion).
    # When omitted, the binary is built without a URL override (same as the cross-platform
    # release binaries) — suitable for CI release artifacts that operators re-package
    # with their own controller URL via the controller's install-package generator.
    [Parameter(Mandatory = $false)]
    [string]$ControllerURL = "",

    # Version string embedded in the binary and MSI product version (e.g. "v1.2.3").
    # Leading 'v' is stripped for the MSI product version field (requires N.N.N format).
    [Parameter(Mandatory = $false)]
    [string]$Version = "0.0.0",

    # Path to a pre-built cfgms-steward binary.
    # When empty, the script builds the binary from the repository source.
    [Parameter(Mandatory = $false)]
    [string]$BinaryPath = "",

    # Target architecture for the binary and MSI. Both amd64 and arm64 are supported.
    [Parameter(Mandatory = $false)]
    [ValidateSet("amd64", "arm64")]
    [string]$Arch = "amd64",

    # SHA-1 thumbprint of a code signing certificate in the local certificate store.
    # When provided, signtool.exe signs the MSI using SHA-256 with a timestamp.
    # When omitted, the MSI is built unsigned with a warning.
    [Parameter(Mandatory = $false)]
    [string]$SigningCertThumbprint = "",

    # Base64-encoded Ed25519 public key for the CFGMS module publisher.
    # When non-empty, baked into the binary via ldflags so the steward verifies
    # module/upgrade bundles against this key. When omitted, the binary keeps the
    # compiled-in all-zero placeholder from pkg/modules/trust/identity.go — a
    # placeholder-key build cannot verify genuine signed upgrades (fail-closed dev
    # behavior). The real key is supplied by the code-signing pipeline (ADR-013 §5).
    [Parameter(Mandatory = $false)]
    [string]$PublisherKey = ""
)

$ErrorActionPreference = "Stop"

$ScriptDir = $PSScriptRoot
$RepoRoot  = Resolve-Path (Join-Path $ScriptDir ".." "..")

# Normalize version: strip leading 'v' for the MSI ProductVersion field.
# MSI requires N.N.N or N.N.N.N; fall back to 0.0.0 for non-conforming strings.
$MsiVersion = $Version -replace '^v', ''
if ($MsiVersion -notmatch '^\d+\.\d+\.\d+') {
    $MsiVersion = "0.0.0"
}

Write-Host "=== CFGMS Steward MSI Build ===" -ForegroundColor Cyan
Write-Host "Version:        $Version"
Write-Host "MSI Version:    $MsiVersion"
Write-Host "ControllerURL:  $(if ($ControllerURL -ne '') { $ControllerURL } else { '(not set — generic build)' })"
Write-Host "PublisherKey:   $(if ($PublisherKey -ne '') { '(set)' } else { '(not set — placeholder key)' })"
Write-Host "Arch:           $Arch"

# ── Step 1: Build the binary (when not pre-supplied) ─────────────────────────

if ($BinaryPath -eq "") {
    Write-Host ""
    Write-Host "Building cfgms-steward binary for windows/$Arch..." -ForegroundColor Yellow

    $BinaryName = "cfgms-steward-windows-$Arch.exe"
    $BinaryPath = Join-Path $RepoRoot "bin" $BinaryName

    $OutDir = Split-Path $BinaryPath
    if (-not (Test-Path $OutDir)) {
        New-Item -ItemType Directory -Path $OutDir | Out-Null
    }

    $env:GOOS        = "windows"
    $env:GOARCH      = $Arch
    $env:CGO_ENABLED = "0"

    $VersionFlag = "-X github.com/cfgis/cfgms/pkg/version.Version=$Version"
    $LdFlags = if ($ControllerURL -ne "") {
        "-s -w -X main.ControllerURL=$ControllerURL $VersionFlag"
    } else {
        "-s -w $VersionFlag"
    }
    if ($PublisherKey -ne "") {
        $LdFlags += " -X github.com/cfgis/cfgms/pkg/modules/trust.cfgmsPublisherPublicKey=$PublisherKey"
    }
    $BuildArgs = @(
        "build",
        "-trimpath",
        "-ldflags", $LdFlags,
        "-o", $BinaryPath,
        "./cmd/steward"
    )

    Push-Location $RepoRoot
    try {
        & go @BuildArgs
        if ($LASTEXITCODE -ne 0) {
            Write-Error "go build failed (exit $LASTEXITCODE)"
        }
    } finally {
        Pop-Location
        Remove-Item Env:GOOS        -ErrorAction SilentlyContinue
        Remove-Item Env:GOARCH      -ErrorAction SilentlyContinue
        Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue
    }

    Write-Host "  Binary: $BinaryPath" -ForegroundColor Green
} else {
    Write-Host "Using pre-built binary: $BinaryPath"
    if (-not (Test-Path $BinaryPath)) {
        Write-Error "Binary not found: $BinaryPath"
    }
}

# ── Step 1b: Build stdlib module binaries ────────────────────────────────────

Write-Host ""
Write-Host "Building stdlib module binaries for windows/$Arch..." -ForegroundColor Yellow

$StdlibModules = @("file", "service", "package", "script", "firewall", "patch")
$ModulesDir = Join-Path $RepoRoot "bin" "modules-windows-$Arch"

if (-not (Test-Path $ModulesDir)) {
    New-Item -ItemType Directory -Path $ModulesDir | Out-Null
}

$env:GOOS        = "windows"
$env:GOARCH      = $Arch
$env:CGO_ENABLED = "0"

Push-Location $RepoRoot
try {
    foreach ($module in $StdlibModules) {
        $moduleBinPath = Join-Path $ModulesDir "cfgms-module-$module.exe"
        $moduleArgs = @(
            "build",
            "-trimpath",
            "-ldflags", "-s -w",
            "-o", $moduleBinPath,
            "./features/modules/$module/cmd"
        )
        & go @moduleArgs
        if ($LASTEXITCODE -ne 0) {
            Write-Error "go build failed for module $module (exit $LASTEXITCODE)"
        }
        Write-Host "  Module: $moduleBinPath" -ForegroundColor Green
    }
} finally {
    Pop-Location
    Remove-Item Env:GOOS        -ErrorAction SilentlyContinue
    Remove-Item Env:GOARCH      -ErrorAction SilentlyContinue
    Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue
}

# ── Step 1c: Build the steward launcher binary ──────────────────────────────
# The launcher is bundled in the MSI payload next to cfgms-steward.exe;
# windowsManager.Install() registers it as the service binary and requires it
# in the bundle (launcher-managed install — what makes the steward
# push-upgradeable). Never fetched post-install.

Write-Host ""
Write-Host "Building cfgms-steward-launcher binary for windows/$Arch..." -ForegroundColor Yellow

$LauncherPath = Join-Path $RepoRoot "bin" "cfgms-steward-launcher-windows-$Arch.exe"

$env:GOOS        = "windows"
$env:GOARCH      = $Arch
$env:CGO_ENABLED = "0"

Push-Location $RepoRoot
try {
    $LauncherArgs = @(
        "build",
        "-trimpath",
        "-ldflags", "-s -w -X github.com/cfgis/cfgms/pkg/version.Version=$Version",
        "-o", $LauncherPath,
        "./cmd/cfgms-steward-launcher"
    )
    & go @LauncherArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Error "go build failed for cfgms-steward-launcher (exit $LASTEXITCODE)"
    }
} finally {
    Pop-Location
    Remove-Item Env:GOOS        -ErrorAction SilentlyContinue
    Remove-Item Env:GOARCH      -ErrorAction SilentlyContinue
    Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue
}

Write-Host "  Launcher: $LauncherPath" -ForegroundColor Green

# ── Step 2: Ensure WiX 4 toolset is installed ────────────────────────────────

Write-Host ""
Write-Host "Checking WiX 4 toolset..." -ForegroundColor Yellow

$WixInstalled = $false
try {
    $toolList = & dotnet tool list --global 2>&1
    $WixInstalled = ($toolList | Select-String "wix") -ne $null
} catch {
    $WixInstalled = $false
}

if (-not $WixInstalled) {
    Write-Host "  Installing WiX 4 via dotnet tool install..."
    & dotnet tool install --global wix
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to install WiX 4 toolset (exit $LASTEXITCODE)"
    }
    Write-Host "  WiX 4 installed." -ForegroundColor Green
} else {
    Write-Host "  WiX 4 is already installed." -ForegroundColor Green
}

# ── Step 3: Build MSI with wix build ─────────────────────────────────────────

$WxsFile   = Join-Path $ScriptDir "cfgms-steward.wxs"
$OutputMsi = Join-Path $RepoRoot "bin" "cfgms-steward-windows-$Arch.msi"

$OutDir = Split-Path $OutputMsi
if (-not (Test-Path $OutDir)) {
    New-Item -ItemType Directory -Path $OutDir | Out-Null
}

Write-Host ""
Write-Host "Building MSI..." -ForegroundColor Yellow
Write-Host "  Source:  $WxsFile"
Write-Host "  Binary:  $BinaryPath"
Write-Host "  Output:  $OutputMsi"

$WixArgs = @(
    "build",
    $WxsFile,
    "-d", "ProductVersion=$MsiVersion",
    "-d", "BinaryPath=$BinaryPath",
    "-d", "LauncherPath=$LauncherPath",
    "-d", "ModulesDir=$ModulesDir",
    "-out", $OutputMsi
)

& wix @WixArgs
if ($LASTEXITCODE -ne 0) {
    Write-Error "wix build failed (exit $LASTEXITCODE)"
}

Write-Host "  MSI built: $OutputMsi" -ForegroundColor Green

# ── Step 4: Code signing (optional) ──────────────────────────────────────────

if ($SigningCertThumbprint -ne "") {
    Write-Host ""
    Write-Host "Signing MSI..." -ForegroundColor Yellow

    # Locate signtool.exe from the Windows SDK (prefer the newest x64 copy).
    $SignTool = Get-ChildItem `
        -Path "C:\Program Files (x86)\Windows Kits\10\bin" `
        -Recurse -Filter "signtool.exe" -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match "x64" } |
        Sort-Object FullName -Descending |
        Select-Object -First 1 -ExpandProperty FullName

    if ($null -eq $SignTool) {
        Write-Error ("signtool.exe not found under C:\Program Files (x86)\Windows Kits\10\bin. " +
                     "Install the Windows SDK: https://developer.microsoft.com/windows/downloads/windows-sdk/")
    }

    Write-Host "  signtool: $SignTool"

    & $SignTool sign `
        /sha1 $SigningCertThumbprint `
        /fd sha256 `
        /tr http://timestamp.digicert.com `
        /td sha256 `
        /d "CFGMS Steward" `
        $OutputMsi

    if ($LASTEXITCODE -ne 0) {
        Write-Error "signtool.exe signing failed (exit $LASTEXITCODE)"
    }

    Write-Host "  MSI signed." -ForegroundColor Green
} else {
    Write-Host ""
    Write-Warning "No -SigningCertThumbprint provided — MSI is unsigned."
    Write-Warning "Windows SmartScreen may show an 'unknown publisher' warning."
    Write-Warning "For production: obtain a code signing certificate and re-run with -SigningCertThumbprint <thumbprint>."
}

# ── Summary ───────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "=== Build Complete ===" -ForegroundColor Green
Write-Host "MSI: $OutputMsi"
$MsiLeaf = Split-Path $OutputMsi -Leaf
Write-Host ""
Write-Host "Deploy with RMM (public CA):"
Write-Host "  msiexec /qn /i `"$MsiLeaf`" REGTOKEN=`"<token>`" CA_FINGERPRINT=`"<hex>`""
Write-Host ""
Write-Host "Deploy with install package (private CA, ca.crt alongside MSI):"
Write-Host "  # Extract the install package tar.gz; ca.crt is auto-detected from the same directory."
Write-Host "  msiexec /qn /i `"$MsiLeaf`" REGTOKEN=`"<token>`" CA_FINGERPRINT=`"<hex>`""
