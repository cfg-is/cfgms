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
