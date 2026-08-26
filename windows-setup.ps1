# Windows Development Environment Setup Script
# Run PowerShell as Administrator, then execute this script

param(
    [switch]$SkipDocker,
    [switch]$SkipClaudeCode
)

Write-Host "=== CFGMS Windows Development Environment Setup ===" -ForegroundColor Cyan
Write-Host "This script will install all required development tools.`n"

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
    Write-Host "Right-click PowerShell and select 'Run as Administrator'"
    exit 1
}

# Install Chocolatey if not present
if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
    Write-Host "`n=== Installing Chocolatey ===" -ForegroundColor Yellow
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

    # Refresh environment variables
    $env:ChocolateyInstall = Convert-Path "$((Get-Command choco).Path)\..\.."
    Import-Module "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"
    refreshenv
} else {
    Write-Host "Chocolatey already installed" -ForegroundColor Green
}

# Install core development tools
Write-Host "`n=== Installing Core Development Tools ===" -ForegroundColor Yellow
choco install -y golang git make gh nodejs

# Refresh environment to pick up new PATHs
refreshenv

# =====================================================================
# CFGMS validation tooling (lint + security scanners)
#
# A Windows dev box runs the same gates as CI (`make test-commit`,
# `make security-scan`), so it needs the same tools at the same versions.
# Every version below is pinned to match
# .github/workflows/dependency-pin-check.yml and .devcontainer/Dockerfile
# — if you bump one, bump all three or the pin-check workflow will flag it.
#
# Two install paths, deliberately:
#
#   go install        for tools that are go-gettable at a version tag.
#
#   Verified download for tools distributed only as release binaries. Each
#                     is SHA-256 checked against a value pinned HERE rather
#                     than fetched at runtime — same reasoning as
#                     .github/scripts/install-trivy.sh: a checksum fetched
#                     at runtime is worthless if the supply chain is
#                     mid-compromise. Take the values from the release's
#                     own checksums asset when bumping a version.
#
# Trivy note: NEVER pin v0.69.4, v0.69.5 or v0.69.6 — those releases are
# known-compromised (CVE-2026-33634). See docs/runbooks/trivy-rollback.md.
# =====================================================================
Write-Host "`n=== Installing CFGMS Validation Tooling ===" -ForegroundColor Yellow

$goPath = (& go env GOPATH)
if ($LASTEXITCODE -ne 0 -or -not $goPath) {
    Write-Host "  [--] Go not on PATH — skipping tooling install" -ForegroundColor Yellow
    $goBinDir = $null
} else {
    $goBinDir = Join-Path $goPath 'bin'
    if (-not (Test-Path $goBinDir)) {
        New-Item -ItemType Directory -Path $goBinDir -Force | Out-Null
    }
}

if ($goBinDir) {

    # --- go install path -------------------------------------------------
    # golangci-lint belongs here rather than in the verified-download list below:
    # it refuses to start when the Go it was built with is older than the version
    # go.mod targets via its `toolchain` directive, so an upstream release archive
    # breaks `make lint` on every toolchain bump until upstream rebuilds. Building
    # from source ties its build Go to the Go on this box, which the same bump
    # already moved. See the comment in .devcontainer/Dockerfile (Issue #3627).
    $goTools = @(
        @{ Name = 'gosec';         Package = 'github.com/securego/gosec/v2/cmd/gosec@v2.28.0' },
        @{ Name = 'staticcheck';   Package = 'honnef.co/go/tools/cmd/staticcheck@2026.2.1' },
        @{ Name = 'gitleaks';      Package = 'github.com/zricethezav/gitleaks/v8@v8.30.1' },
        @{ Name = 'go-licenses';   Package = 'github.com/google/go-licenses/v2@v2.0.1' },
        @{ Name = 'golangci-lint'; Package = 'github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.13.1' }
    )

    foreach ($tool in $goTools) {
        Write-Host "  installing $($tool.Name) ..."
        & go install $tool.Package
        if ($LASTEXITCODE -ne 0) {
            Write-Host "  [--] $($tool.Name): go install failed" -ForegroundColor Yellow
        } else {
            Write-Host "  [OK] $($tool.Name)" -ForegroundColor Green
        }
    }

    # --- verified-download path ------------------------------------------
    # Installs $Name.exe into $DestDir after verifying the download's
    # SHA-256. Returns $true only when the binary was installed; a hash
    # mismatch installs nothing and returns $false.
    function Install-VerifiedBinary {
        param(
            [Parameter(Mandatory)][string]$Name,
            [Parameter(Mandatory)][string]$Url,
            [Parameter(Mandatory)][string]$Sha256,
            [Parameter(Mandatory)][string]$DestDir,
            # File to pull out of the archive. Omit for a bare .exe download.
            [string]$ArchiveMember
        )

        $work = Join-Path ([System.IO.Path]::GetTempPath()) ("cfgms-$Name-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $work -Force | Out-Null

        try {
            $leaf    = Split-Path $Url -Leaf
            $archive = Join-Path $work $leaf

            $progressPreference = 'SilentlyContinue'   # Invoke-WebRequest is ~10x slower with the progress bar
            Invoke-WebRequest -Uri $Url -OutFile $archive -UseBasicParsing

            $actual = (Get-FileHash -Path $archive -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($actual -ne $Sha256.ToLowerInvariant()) {
                Write-Host "  [!!] $Name : SHA-256 MISMATCH - refusing to install" -ForegroundColor Red
                Write-Host "       expected $($Sha256.ToLowerInvariant())"
                Write-Host "       actual   $actual"
                return $false
            }

            $dest = Join-Path $DestDir "$Name.exe"

            if (-not $ArchiveMember) {
                Copy-Item -Path $archive -Destination $dest -Force
            }
            elseif ($leaf -like '*.zip') {
                Expand-Archive -Path $archive -DestinationPath $work -Force
                # Some archives nest the binary one directory down.
                $found = @(Get-ChildItem -Path $work -Filter $ArchiveMember -Recurse -File)
                if ($found.Count -eq 0) {
                    Write-Host "  [--] $Name : '$ArchiveMember' not found in archive" -ForegroundColor Yellow
                    return $false
                }
                Copy-Item -Path $found[0].FullName -Destination $dest -Force
            }
            else {
                # .tar.gz — bsdtar ships with Windows 10 1803+ and Server 2019+.
                & tar -xzf $archive -C $work $ArchiveMember
                $extracted = Join-Path $work $ArchiveMember
                if ($LASTEXITCODE -ne 0 -or -not (Test-Path $extracted)) {
                    Write-Host "  [--] $Name : could not extract '$ArchiveMember'" -ForegroundColor Yellow
                    return $false
                }
                Copy-Item -Path $extracted -Destination $dest -Force
            }

            Write-Host "  [OK] $Name -> $dest" -ForegroundColor Green
            return $true
        }
        catch {
            Write-Host "  [--] $Name : $($_.Exception.Message)" -ForegroundColor Yellow
            return $false
        }
        finally {
            Remove-Item -Path $work -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    $verifiedTools = @(
        @{
            Name   = 'trivy'
            Url    = 'https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_windows-64bit.zip'
            Sha256 = '94c40e0696e4b907a74b7b2e1438d5d72ebaca83115817407f568a002d520842'
            Member = 'trivy.exe'
        },
        @{
            Name   = 'trufflehog'
            Url    = 'https://github.com/trufflesecurity/trufflehog/releases/download/v3.97.0/trufflehog_3.97.0_windows_amd64.tar.gz'
            Sha256 = '2a8208e6e5be8d6cd855322480eda4790a437f805dbd6538ad7495c27f40d4e5'
            Member = 'trufflehog.exe'
        },
        @{
            Name   = 'nancy'
            Url    = 'https://github.com/sonatype-nexus-community/nancy/releases/download/v2.1.0/nancy-v2.1.0-windows-amd64.exe'
            Sha256 = '77ecff35d3772794d4119b98b6405170d7b480bdc92076871ead4f52f574a0cf'
            Member = $null
        }
    )

    foreach ($tool in $verifiedTools) {
        Write-Host "  installing $($tool.Name) ..."
        $null = Install-VerifiedBinary -Name $tool.Name -Url $tool.Url `
            -Sha256 $tool.Sha256 -DestDir $goBinDir -ArchiveMember $tool.Member
    }

    # Pre-seed the Trivy vulnerability DB so the first `make security-scan`
    # isn't also a large download. Best-effort — a failure here is not fatal.
    if (Test-Path (Join-Path $goBinDir 'trivy.exe')) {
        Write-Host "  warming Trivy vulnerability DB (best-effort) ..."
        & (Join-Path $goBinDir 'trivy.exe') fs --download-db-only 2>$null | Out-Null
    }
}

# Install Docker Desktop (required for integration tests)
if (-not $SkipDocker) {
    Write-Host "`n=== Installing Docker Desktop ===" -ForegroundColor Yellow

    # Check if Docker is already installed
    if (Get-Command docker -ErrorAction SilentlyContinue) {
        Write-Host "Docker already installed" -ForegroundColor Green
    } else {
        # Install Docker Desktop
        choco install -y docker-desktop

        Write-Host "`nDocker Desktop installed. Important notes:" -ForegroundColor Cyan
        Write-Host "  - You may need to restart your computer after installation"
        Write-Host "  - Docker Desktop requires Windows 10/11 Pro, Enterprise, or Education"
        Write-Host "  - For Windows Home, WSL 2 backend is required"
        Write-Host "  - After restart, launch Docker Desktop and complete setup"
    }

    # Enable Hyper-V and Containers features (required for Docker)
    Write-Host "`n=== Enabling Windows Features for Docker ===" -ForegroundColor Yellow

    # Check if Hyper-V is available (not on Windows Home)
    $osInfo = Get-WmiObject -Class Win32_OperatingSystem
    $isHomeEdition = $osInfo.Caption -match "Home"

    if ($isHomeEdition) {
        Write-Host "Windows Home detected - using WSL 2 backend for Docker" -ForegroundColor Yellow
        # Enable WSL
        Write-Host "Enabling WSL..."
        dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart 2>$null
        dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart 2>$null

        # Install WSL 2
        Write-Host "Installing WSL 2..."
        wsl --install --no-distribution 2>$null
        wsl --set-default-version 2 2>$null
    } else {
        Write-Host "Enabling Hyper-V and Containers..."
        Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All -NoRestart -ErrorAction SilentlyContinue
        Enable-WindowsOptionalFeature -Online -FeatureName Containers -All -NoRestart -ErrorAction SilentlyContinue
    }
}

# Refresh environment
refreshenv

# Install Claude Code via npm
if (-not $SkipClaudeCode) {
    Write-Host "`n=== Installing Claude Code ===" -ForegroundColor Yellow
    npm install -g @anthropic-ai/claude-code
}

# Refresh environment one more time
refreshenv

# Verify installations
Write-Host "`n=== Verification ===" -ForegroundColor Green

$tools = @(
    @{Name="Go"; Command="go version"},
    @{Name="Git"; Command="git --version"},
    @{Name="Make"; Command="make --version"},
    @{Name="GitHub CLI"; Command="gh --version"},
    @{Name="Node.js"; Command="node --version"},
    @{Name="npm"; Command="npm --version"}
)

if (-not $SkipDocker) {
    $tools += @{Name="Docker"; Command="docker --version"}
}

if (-not $SkipClaudeCode) {
    $tools += @{Name="Claude Code"; Command="claude --version"}
}

foreach ($tool in $tools) {
    try {
        $result = Invoke-Expression $tool.Command 2>$null
        if ($result) {
            Write-Host "  [OK] $($tool.Name): $($result.Split("`n")[0])" -ForegroundColor Green
        } else {
            Write-Host "  [--] $($tool.Name): Not found or not in PATH" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  [--] $($tool.Name): Not found or not in PATH" -ForegroundColor Yellow
    }
}

# Check Docker status
if (-not $SkipDocker) {
    Write-Host "`n=== Docker Status ===" -ForegroundColor Green
    try {
        $dockerInfo = docker info 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  Docker daemon is running" -ForegroundColor Green
        } else {
            Write-Host "  Docker daemon is NOT running" -ForegroundColor Yellow
            Write-Host "  Please start Docker Desktop after installation"
        }
    } catch {
        Write-Host "  Docker not available - restart may be required" -ForegroundColor Yellow
    }
}

Write-Host "`n=== Next Steps ===" -ForegroundColor Cyan
Write-Host "1. RESTART your computer (required for Docker/Hyper-V)" -ForegroundColor White
Write-Host "2. Launch Docker Desktop and complete initial setup" -ForegroundColor White
Write-Host "3. Open a new PowerShell window" -ForegroundColor White
Write-Host "4. Authenticate Claude: claude auth login" -ForegroundColor White
Write-Host "5. Clone repo: git clone https://github.com/cfg-is/cfgms-t1.git" -ForegroundColor White
Write-Host "6. cd cfgms-t1" -ForegroundColor White
Write-Host "7. Run unit tests: go test -short ./..." -ForegroundColor White
Write-Host "8. Run all tests (requires Docker): go test ./..." -ForegroundColor White

Write-Host "`n=== Test Categories ===" -ForegroundColor Cyan
Write-Host "  Unit tests (no Docker):        go test -short ./..." -ForegroundColor Gray
Write-Host "  All tests (Docker required):   go test ./..." -ForegroundColor Gray
Write-Host "  Integration tests only:        go test ./test/integration/..." -ForegroundColor Gray
Write-Host "  E2E tests only:                go test ./test/e2e/..." -ForegroundColor Gray

if (-not $SkipDocker) {
    Write-Host "`n=== Docker Notes ===" -ForegroundColor Cyan
    Write-Host "  - Integration tests require Docker to be running"
    Write-Host "  - First run may take longer as images are pulled"
    Write-Host "  - Use 'docker ps' to verify Docker is working"
}
