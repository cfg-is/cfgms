# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# build-msi_test.ps1 - the MSI build refuses a malformed -ControllerRootFingerprints
# before building anything. Run on the native Windows CI leg:
#   pwsh -NonInteractive -File build/windows/build-msi_test.ps1

$ErrorActionPreference = "Stop"
$script = Join-Path $PSScriptRoot "build-msi.ps1"
$good = "ab" * 32
$bad = @(
    "ABCDEF",
    ("A" * 64),
    "$good,zz",
    "$good,",
    (($good, $good, $good, $good, $good) -join ",")
)

$failed = 0
foreach ($value in $bad) {
    $refused = $false
    try {
        & pwsh -NonInteractive -File $script -ControllerRootFingerprints $value -BinaryPath "nonexistent.exe" 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { $refused = $true }
    } catch {
        $refused = $true
    }
    if ($refused) {
        Write-Host "PASS: refused '$value'"
    } else {
        Write-Host "FAIL: accepted '$value'"
        $failed++
    }
}
if ($failed -gt 0) { exit 1 }
