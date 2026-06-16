# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# install-hyperv-host_test.ps1 — Pester 5 tests for install-hyperv-host.ps1.
#
# The story spec explicitly prescribes a "mock cfgms-steward.exe stub" for
# logic tests (the binary is not available in test environments). This follows
# the same pattern as build/linux/install_test.sh, which injects a mock
# cfgms-steward shell script to verify install.sh argument-passing conventions.
# The no-mocks rule applies to Go unit tests; script orchestrator tests require
# a stub to exercise the script's argument-passing and security properties.
#
# Run with:
#   pwsh -NonInteractive -File scripts/install-hyperv-host_test.ps1
# Or via Make:
#   make test-install-hyperv-ps1

#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

param()

$ErrorActionPreference = "Stop"

$ScriptUnderTest = Join-Path $PSScriptRoot "install-hyperv-host.ps1"

# ── Helpers ────────────────────────────────────────────────────────────────────

function New-TempDir {
    $d = Join-Path $env:TEMP ("cfgms-test-" + [System.IO.Path]::GetRandomFileName())
    New-Item -ItemType Directory -Path $d | Out-Null
    $d
}

# Generate a self-signed test CA cert and return its path and SHA-256 fingerprint.
function New-TestCACert {
    param([string]$Dir)

    $CertPath = Join-Path $Dir "ca.crt"

    $Rsa = [System.Security.Cryptography.RSA]::Create(2048)
    $Req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        "CN=test-ca",
        $Rsa,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    )
    $Cert = $Req.CreateSelfSigned(
        [DateTimeOffset]::UtcNow.AddMinutes(-1),
        [DateTimeOffset]::UtcNow.AddDays(1)
    )

    $DerBytes = $Cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    $B64      = [Convert]::ToBase64String($DerBytes, [Base64FormattingOptions]::InsertLineBreaks)
    $Pem      = "-----BEGIN CERTIFICATE-----`n$B64`n-----END CERTIFICATE-----"
    [System.IO.File]::WriteAllText($CertPath, $Pem)

    $Sha256 = [System.Security.Cryptography.SHA256]::Create()
    $Hash   = $Sha256.ComputeHash($DerBytes)
    $Fp     = ($Hash | ForEach-Object { $_.ToString("x2") }) -join ""

    [PSCustomObject]@{ Path = $CertPath; Fingerprint = $Fp }
}

# Build a mock cfgms-steward stub (a .ps1 script).
# The stub records argv and stdin to log files so tests can assert them
# without the real binary. This mirrors the approach in
# build/linux/install_test.sh where a mock cfgms-steward shell script records
# arguments to verify install.sh's argument-passing conventions.
#
# The stub always creates the argv log on startup (even for status subcommand),
# so tests can assert its existence or absence unconditionally.
function New-MockSteward {
    param([string]$Dir, [string]$StatusBehavior = "healthy")

    $ArgvLog  = Join-Path $Dir "argv.txt"
    $StdinLog = Join-Path $Dir "stdin.txt"

    $StubPs1 = Join-Path $Dir "cfgms-steward.ps1"
    $StubContent = @"
param()
`$ArgvLog  = '$($ArgvLog -replace "'","''")'
`$StdinLog = '$($StdinLog -replace "'","''")'
`$StatusBehavior = '$StatusBehavior'

# Always write the argv log so tests can assert it exists unconditionally.
(`$args -join "`n") | Out-File -FilePath `$ArgvLog -Encoding utf8 -Append -Force

# Capture piped stdin when present.
if ([Console]::IsInputRedirected) {
    `$stdin = `$input | Out-String
    `$stdin | Out-File -FilePath `$StdinLog -Encoding utf8 -Append -Force
}

`$sub = if (`$args.Count -gt 0) { `$args[0] } else { "" }
switch (`$sub) {
    "install" { exit 0 }
    "status"  {
        if (`$StatusBehavior -eq "healthy") { exit 0 }
        exit 1
    }
    default   { exit 0 }
}
"@
    Set-Content -Path $StubPs1 -Value $StubContent -Encoding utf8

    [PSCustomObject]@{
        Ps1Path  = $StubPs1
        ArgvLog  = $ArgvLog
        StdinLog = $StdinLog
    }
}

# Invoke the script under test in a child pwsh process, capturing exit code and output.
# Additional environment variables can be passed via $Env hashtable.
function Invoke-Script {
    param(
        [hashtable]$Params,
        [string]$BinaryPath = "",
        [hashtable]$Env     = @{}
    )

    $ArgList = @("-NonInteractive", "-File", $ScriptUnderTest)
    foreach ($kv in $Params.GetEnumerator()) {
        $ArgList += "-$($kv.Key)"
        if ($null -ne $kv.Value -and $kv.Value -ne "") {
            $ArgList += "$($kv.Value)"
        }
    }
    if ($BinaryPath -ne "") {
        $ArgList += "-BinaryPath"
        $ArgList += $BinaryPath
    }

    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName               = "pwsh"
    $psi.UseShellExecute        = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true

    foreach ($a in $ArgList) { $psi.ArgumentList.Add($a) }
    foreach ($kv in $Env.GetEnumerator()) {
        $psi.Environment[$kv.Key] = $kv.Value
    }

    $proc   = [System.Diagnostics.Process]::Start($psi)
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()
    $proc.WaitForExit()

    [PSCustomObject]@{
        ExitCode = $proc.ExitCode
        Output   = $stdout + $stderr
    }
}

# ── Pester suite ───────────────────────────────────────────────────────────────

Describe "install-hyperv-host.ps1" {

    # ── Fingerprint mismatch ───────────────────────────────────────────────────

    Context "Fingerprint mismatch" {
        It "exits non-zero before any install action" {
            $TmpDir = New-TempDir
            try {
                $CA     = New-TestCACert -Dir $TmpDir
                $Stub   = New-MockSteward -Dir $TmpDir
                $WrongFP = "0000000000000000000000000000000000000000000000000000000000000000"

                $Result = Invoke-Script -Params @{
                    ControllerURL = "https://ctrl.example.com"
                    RegToken      = "tok-test"
                    CAFingerprint = $WrongFP
                    CACertPath    = $CA.Path
                    WinRMUser     = "cfgms-hyperv"
                } -BinaryPath $Stub.Ps1Path

                # Must exit non-zero.
                $Result.ExitCode | Should -Not -Be 0

                # Output must mention mismatch or aborted.
                $Result.Output | Should -Match "(?i)(mismatch|aborted)"

                # The stub always creates the argv log on any invocation.
                # If install was never called, the argv log must not exist.
                $Stub.ArgvLog | Should -Not -Exist
            } finally {
                Remove-Item $TmpDir -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }

    # ── Correct fingerprint ────────────────────────────────────────────────────

    Context "Correct fingerprint" {
        It "exits 0 when steward becomes healthy" {
            $TmpDir = New-TempDir
            try {
                $CA   = New-TestCACert -Dir $TmpDir
                $Stub = New-MockSteward -Dir $TmpDir -StatusBehavior "healthy"

                $Result = Invoke-Script -Params @{
                    ControllerURL = "https://ctrl.example.com"
                    RegToken      = "tok-test"
                    CAFingerprint = $CA.Fingerprint
                    CACertPath    = $CA.Path
                    WinRMUser     = "cfgms-hyperv"
                } -BinaryPath $Stub.Ps1Path

                $Result.ExitCode | Should -Be 0
                $Result.Output   | Should -Match "(?i)healthy"
            } finally {
                Remove-Item $TmpDir -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }

    # ── Password not in argv ───────────────────────────────────────────────────

    Context "WinRM password delivery" {
        It "does not appear in child process argv, stdout, stderr, or any written file" {
            $TmpDir = New-TempDir
            try {
                $CA     = New-TestCACert -Dir $TmpDir
                $Stub   = New-MockSteward -Dir $TmpDir -StatusBehavior "healthy"
                $Secret = "SUPERSECRET-$(New-Guid)"

                $ArgList = @(
                    "-NonInteractive", "-File", $ScriptUnderTest,
                    "-ControllerURL",  "https://ctrl.example.com",
                    "-RegToken",       "tok-test",
                    "-CAFingerprint",  $CA.Fingerprint,
                    "-CACertPath",     $CA.Path,
                    "-WinRMUser",      "cfgms-hyperv",
                    "-BinaryPath",     $Stub.Ps1Path,
                    # Pass as plain string so the test holds the sentinel to verify
                    # it doesn't propagate into the child binary's argv or output.
                    # PowerShell parameter binding coerces [string] → [SecureString].
                    "-WinRMPass",      $Secret
                )

                $psi = [System.Diagnostics.ProcessStartInfo]::new()
                $psi.FileName               = "pwsh"
                $psi.UseShellExecute        = $false
                $psi.RedirectStandardOutput = $true
                $psi.RedirectStandardError  = $true
                foreach ($a in $ArgList) { $psi.ArgumentList.Add($a) }
                $proc   = [System.Diagnostics.Process]::Start($psi)
                $stdout = $proc.StandardOutput.ReadToEnd()
                $stderr = $proc.StandardError.ReadToEnd()
                $proc.WaitForExit()

                $AllOutput = $stdout + $stderr

                # Argv log must exist (stub was called) and must NOT contain the secret.
                $Stub.ArgvLog | Should -Exist
                $ArgvContent  = Get-Content $Stub.ArgvLog -Raw
                $ArgvContent  | Should -Not -Match ([regex]::Escape($Secret))

                # Script output must not contain the secret.
                $AllOutput | Should -Not -Match ([regex]::Escape($Secret))

                # No files in the temp dir should contain the secret.
                Get-ChildItem $TmpDir -Recurse -File | ForEach-Object {
                    $FileContent = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
                    if ($null -ne $FileContent) {
                        $FileContent | Should -Not -Match ([regex]::Escape($Secret))
                    }
                }
            } finally {
                Remove-Item $TmpDir -Recurse -Force -ErrorAction SilentlyContinue
            }
        }

        It "passes password via stdin — not via argv" {
            $TmpDir = New-TempDir
            try {
                $CA     = New-TestCACert -Dir $TmpDir
                $Stub   = New-MockSteward -Dir $TmpDir -StatusBehavior "healthy"
                $Secret = "PIPE-CHECK-$(New-Guid)"

                $ArgList = @(
                    "-NonInteractive", "-File", $ScriptUnderTest,
                    "-ControllerURL",  "https://ctrl.example.com",
                    "-RegToken",       "tok-test",
                    "-CAFingerprint",  $CA.Fingerprint,
                    "-CACertPath",     $CA.Path,
                    "-WinRMUser",      "cfgms-hyperv",
                    "-BinaryPath",     $Stub.Ps1Path,
                    "-WinRMPass",      $Secret
                )

                $psi = [System.Diagnostics.ProcessStartInfo]::new()
                $psi.FileName               = "pwsh"
                $psi.UseShellExecute        = $false
                $psi.RedirectStandardOutput = $true
                $psi.RedirectStandardError  = $true
                foreach ($a in $ArgList) { $psi.ArgumentList.Add($a) }
                $proc = [System.Diagnostics.Process]::Start($psi)
                $proc.StandardOutput.ReadToEnd() | Out-Null
                $proc.StandardError.ReadToEnd()  | Out-Null
                $proc.WaitForExit()

                # Argv log must exist and must NOT contain the secret.
                $Stub.ArgvLog | Should -Exist
                $ArgvContent  = Get-Content $Stub.ArgvLog -Raw
                $ArgvContent  | Should -Not -Match ([regex]::Escape($Secret))

                # Stdin log must exist — the password must have arrived via pipe.
                $Stub.StdinLog | Should -Exist
                $StdinContent  = Get-Content $Stub.StdinLog -Raw
                $StdinContent  | Should -Match ([regex]::Escape($Secret))
            } finally {
                Remove-Item $TmpDir -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }

    # ── Idempotency ────────────────────────────────────────────────────────────

    Context "Idempotency" {
        It "succeeds on second invocation with same parameters" {
            $TmpDir = New-TempDir
            try {
                $CA   = New-TestCACert -Dir $TmpDir
                $Stub = New-MockSteward -Dir $TmpDir -StatusBehavior "healthy"

                $Params = @{
                    ControllerURL = "https://ctrl.example.com"
                    RegToken      = "tok-test"
                    CAFingerprint = $CA.Fingerprint
                    CACertPath    = $CA.Path
                    WinRMUser     = "cfgms-hyperv"
                }

                $First  = Invoke-Script -Params $Params -BinaryPath $Stub.Ps1Path
                $Second = Invoke-Script -Params $Params -BinaryPath $Stub.Ps1Path

                $First.ExitCode  | Should -Be 0
                $Second.ExitCode | Should -Be 0
            } finally {
                Remove-Item $TmpDir -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }

    # ── Health poll timeout ────────────────────────────────────────────────────

    Context "Health poll timeout" {
        It "exits non-zero with a clear message when steward never becomes healthy" {
            $TmpDir = New-TempDir
            try {
                $CA   = New-TestCACert -Dir $TmpDir
                # StatusBehavior = "unhealthy" makes the stub always exit 1 for `status`.
                $Stub = New-MockSteward -Dir $TmpDir -StatusBehavior "unhealthy"

                # Use CFGMS_INSTALL_STATUS_TIMEOUT=10 to shorten the poll deadline
                # from 60 s to 10 s (mirrors the CFGMS_INSTALL_PREFIX isolation
                # pattern in build/linux/install.sh). This exercises the real
                # polling loop in install-hyperv-host.ps1 without a 60-second wait.
                $Result = Invoke-Script -Params @{
                    ControllerURL = "https://ctrl.example.com"
                    RegToken      = "tok-test"
                    CAFingerprint = $CA.Fingerprint
                    CACertPath    = $CA.Path
                    WinRMUser     = "cfgms-hyperv"
                } -BinaryPath $Stub.Ps1Path -Env @{ CFGMS_INSTALL_STATUS_TIMEOUT = "10" }

                $Result.ExitCode | Should -Not -Be 0
                $Result.Output   | Should -Match "(?i)(timeout|healthy)"
            } finally {
                Remove-Item $TmpDir -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }

    # ── Pre-built binary ───────────────────────────────────────────────────────

    Context "Pre-built binary (-BinaryPath)" {
        It "uses the pre-supplied binary without download" {
            $TmpDir = New-TempDir
            try {
                $CA   = New-TestCACert -Dir $TmpDir
                $Stub = New-MockSteward -Dir $TmpDir -StatusBehavior "healthy"

                $Result = Invoke-Script -Params @{
                    ControllerURL = "https://ctrl.example.com"
                    RegToken      = "tok-test"
                    CAFingerprint = $CA.Fingerprint
                    CACertPath    = $CA.Path
                    WinRMUser     = "cfgms-hyperv"
                } -BinaryPath $Stub.Ps1Path

                $Result.ExitCode | Should -Be 0
                # Stub was invoked — argv log must exist.
                $Stub.ArgvLog | Should -Exist
            } finally {
                Remove-Item $TmpDir -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

# ── Run Pester ─────────────────────────────────────────────────────────────────

$PesterConfig = New-PesterConfiguration
$PesterConfig.Output.Verbosity = "Normal"
$PesterConfig.Run.Path         = $PSCommandPath
$PesterConfig.Run.Exit         = $true

Invoke-Pester -Configuration $PesterConfig
