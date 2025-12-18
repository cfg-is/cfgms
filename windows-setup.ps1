# Windows Development Environment Setup Script
# Run PowerShell as Administrator, then execute this script

# Install Chocolatey
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# Refresh environment variables
$env:ChocolateyInstall = Convert-Path "$((Get-Command choco).Path)\..\.."
Import-Module "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"
refreshenv

# Install development tools
choco install -y golang git make gh nodejs

# Refresh environment again to pick up new PATHs
refreshenv

# Install Claude Code via npm
npm install -g @anthropic-ai/claude-code

# Refresh environment one more time
refreshenv

# Verify installations
Write-Host "`n=== Verification ===" -ForegroundColor Green
go version
git --version
make --version
gh --version
node --version
npm --version
claude --version

Write-Host "`n=== Next Steps ===" -ForegroundColor Cyan
Write-Host "1. Close and reopen PowerShell (or run 'refreshenv')"
Write-Host "2. Authenticate Claude: claude auth login"
Write-Host "3. Clone repo: git clone https://github.com/cfg-is/cfgms-t1.git"
Write-Host "4. cd cfgms-t1"
Write-Host "5. git checkout feature/story-252-production-realistic-testing"
Write-Host "6. Start Claude: claude"
Write-Host "7. Run tests: go test -v ./..."
