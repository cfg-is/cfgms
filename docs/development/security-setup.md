# CFGMS Security Tools Setup Guide

This guide provides comprehensive instructions for setting up all security scanning tools required for CFGMS development. These tools are integrated into the development workflow via make targets and are mandatory for all code contributions.

## Overview

CFGMS uses a multi-layered security scanning approach with four primary tools:

- **🔍 Trivy**: Filesystem scanning for vulnerabilities, secrets, and misconfigurations
- **📦 Nancy**: Go dependency vulnerability scanning 
- **🛡️ gosec**: Go security pattern analysis (Future: v0.3.1 Story 2.1)
- **🔬 staticcheck**: Advanced static analysis (Future: v0.3.1 Story 2.2)

## Quick Start

```bash
# 1. Install all security tools (see platform-specific instructions below)
# 2. Verify installation
make security-scan  # This will show installation instructions for missing tools

# 3. Run individual tools
make security-trivy    # Filesystem scanning
make security-deps     # Dependency scanning

# 4. Run unified security validation
make security-scan     # All tools (used in CLAUDE.md workflow)
make security-check    # Quick development check
```

## Installation Instructions

### 🔍 Trivy Installation

Trivy scans for vulnerabilities, secrets, and misconfigurations in the filesystem.

#### Linux (x86_64)
```bash
# Recommended: Go installation
go install github.com/aquasecurity/trivy/cmd/trivy@latest

# Alternative: Binary download
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.48.3
```

#### macOS
```bash
# Recommended: Homebrew
brew install trivy

# Alternative: Go installation
go install github.com/aquasecurity/trivy/cmd/trivy@latest
```

#### Windows (PowerShell)
```powershell
# Go installation
go install github.com/aquasecurity/trivy/cmd/trivy@latest

# Alternative: Binary download
$version = "v0.48.3"
Invoke-WebRequest -Uri "https://github.com/aquasecurity/trivy/releases/download/$version/trivy_$($version.TrimStart('v'))_Windows-64bit.zip" -OutFile "trivy.zip"
Expand-Archive trivy.zip -DestinationPath .
Move-Item trivy.exe $env:USERPROFILE\go\bin\trivy.exe
```

### 📦 Nancy Installation

Nancy scans Go dependencies for known vulnerabilities.

#### Linux (x86_64)
```bash
# Binary download (recommended)
curl -L https://github.com/sonatype-nexus-community/nancy/releases/download/v1.0.51/nancy-v1.0.51-linux-amd64 -o /tmp/nancy
chmod +x /tmp/nancy && sudo mv /tmp/nancy /usr/local/bin/nancy
```

#### macOS (Intel)
```bash
# Homebrew (recommended)
brew install nancy

# Binary download
curl -L https://github.com/sonatype-nexus-community/nancy/releases/download/v1.0.51/nancy-v1.0.51-darwin-amd64 -o /tmp/nancy
chmod +x /tmp/nancy && sudo mv /tmp/nancy /usr/local/bin/nancy
```

#### macOS (Apple Silicon)
```bash
# Binary download
curl -L https://github.com/sonatype-nexus-community/nancy/releases/download/v1.0.51/nancy-v1.0.51-darwin-arm64 -o /tmp/nancy
chmod +x /tmp/nancy && sudo mv /tmp/nancy /usr/local/bin/nancy
```

#### Linux (Arch)
```bash
# AUR package
yay -S nancy-bin
```

#### Windows (PowerShell)
```powershell
# Binary download
Invoke-WebRequest -Uri 'https://github.com/sonatype-nexus-community/nancy/releases/download/v1.0.51/nancy-v1.0.51-windows-amd64.exe' -OutFile 'nancy.exe'
Move-Item nancy.exe C:\Windows\System32\nancy.exe
```

### 🛡️ gosec Installation (Future - v0.3.1 Story 2.1)

gosec analyzes Go source code for security problems.

```bash
# Go installation (all platforms)
go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
```

### 🔬 staticcheck Installation (Future - v0.3.1 Story 2.2)

staticcheck provides advanced static analysis for Go.

```bash
# Go installation (all platforms) 
go install honnef.co/go/tools/cmd/staticcheck@latest
```

## Verification Steps

After installing the tools, verify they're working correctly:

### 1. Tool Availability Check
```bash
# Check all tools are in PATH
trivy --version      # Should show: trivy version X.X.X
nancy --version      # Should show: nancy version X.X.X

# Future tools (v0.3.1)
# gosec --version     # Should show: gosec version X.X.X
# staticcheck --version # Should show: staticcheck version X.X.X
```

### 2. Individual Tool Testing
```bash
# Test Trivy filesystem scanning
make security-trivy

# Test Nancy dependency scanning  
make security-deps

# Future: gosec and staticcheck testing
# make security-gosec
# make security-staticcheck
```

### 3. Unified Security Validation
```bash
# Test complete security pipeline
make security-scan

# Quick development check
make security-check
```

## Integration with Development Workflow

### CLAUDE.md Workflow Integration

Security scanning is mandatory in the CLAUDE.md development workflow:

```bash
# Before any commits (mandatory order):
make test           # 1. Run full test suite
make security-scan  # 2. Run security scanning  
make lint          # 3. Run linting
```

### Development Usage Patterns

#### During Development
```bash
# Quick security check while developing
make security-check

# Check specific tool output
make security-trivy    # Focus on filesystem issues
make security-deps     # Focus on dependency issues
```

#### Before Committing
```bash
# Full validation (part of CLAUDE.md workflow)
make security-scan     # Must pass before commit
```

#### CI/CD Integration
```bash
# In GitHub Actions (future v0.3.1 Story 3.1)
make security-scan     # Blocks deployment on critical issues
```

## Configuration Files

### .trivyignore
Located at project root, manages Trivy false positives:

```bash
# Development certificates (expected)
features/controller/certs/
features/steward/certs/

# Build artifacts  
bin/
dist/
*.log
```

### Security Tool Behavior

- **Trivy**: Blocks on CRITICAL/HIGH vulnerabilities, shows all findings
- **Nancy**: Non-blocking, provides remediation guidance
- **gosec**: (Future) Configurable blocking via .gosec.json
- **staticcheck**: (Future) Focuses on important issues, excludes style warnings

## Troubleshooting

### Common Issues

#### 1. Tool Not Found in PATH
```bash
# Symptom: "command not found" errors
# Solution: Ensure Go bin directory is in PATH
export PATH=$PATH:$(go env GOPATH)/bin

# For permanent fix, add to your shell profile:
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc  # Linux/WSL
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.zshrc   # macOS/zsh
```

#### 2. Permission Denied on Binary Installation
```bash
# Symptom: Permission errors when moving to /usr/local/bin
# Solution: Use sudo or install to user directory
mkdir -p ~/bin
curl -L <download-url> -o ~/bin/toolname
chmod +x ~/bin/toolname
export PATH=$PATH:~/bin
```

#### 3. Trivy Database Update Issues
```bash
# Symptom: "Failed to update vulnerability database"
# Solution: Manual database update
trivy image --download-db-only

# Or skip database update for offline work
trivy fs . --skip-update
```

#### 4. Nancy SSL/Network Issues
```bash
# Symptom: SSL certificate or network errors
# Solution: Use --skip-update-check flag (already in make target)
go list -json -deps ./... | nancy sleuth --skip-update-check
```

#### 5. Go Module Issues
```bash
# Symptom: "go list" errors in Nancy scanning
# Solution: Ensure go.mod is properly initialized
go mod download
go mod tidy
```

### Platform-Specific Troubleshooting

#### Windows
- **PowerShell Execution Policy**: Run `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`
- **Path Issues**: Use `$env:PATH += ";C:\path\to\tools"` or add via System Properties

#### macOS
- **Quarantine Issues**: Run `xattr -d com.apple.quarantine /path/to/binary` for downloaded binaries
- **ARM64 Compatibility**: Ensure you download ARM64 binaries for Apple Silicon Macs

#### Linux
- **Permission Issues**: Ensure user has sudo access or use user-local installation
- **Distribution Packages**: Some tools may be available via package managers (apt, yum, pacman)

## Make Target Reference

### Individual Tools
```bash
make security-trivy      # Trivy filesystem scanning
make security-deps       # Nancy dependency scanning
make security-gosec      # gosec Go security patterns (future)
make security-staticcheck # staticcheck static analysis (future)
```

### Unified Targets  
```bash
make security-scan       # Run all security tools (blocking on critical issues)
make security-check      # Quick security validation for development
```

### Output Interpretation

#### Success Output
```
✅ Trivy scan completed - no issues found
✅ Nancy dependency scan completed - no critical vulnerabilities found
🎯 All security tools passed - deployment approved
```

#### Failure Output
```
❌ CRITICAL/HIGH vulnerabilities found - deployment blocked!
⚠️  Nancy found vulnerable dependencies. Consider updating:
   - Review the vulnerabilities listed above
   - Update dependencies with: go get -u <package>@<safe-version>
```

## Security Tool Versions

Current tool versions (as of v0.3.1):
- **Trivy**: v0.48.3+ (latest recommended)
- **Nancy**: v1.0.51
- **gosec**: latest (future implementation)  
- **staticcheck**: latest (future implementation)

## Contributing to Security Setup

When adding new security tools:

1. Update this guide with installation instructions
2. Add make targets following the `security-*` naming convention
3. Update `.PHONY` declarations in Makefile
4. Include tool in unified `security-scan` target
5. Add verification steps and troubleshooting guidance
6. Test on all supported platforms (Linux, macOS, Windows)

## Support and Documentation

- **CFGMS Security Architecture**: [docs/security/architecture.md](../security/architecture.md)
- **Development Workflow**: [CLAUDE.md](../../CLAUDE.md)
- **Issue Reporting**: [GitHub Issues](https://github.com/cfg-is/cfgms/issues)
- **Tool Documentation**:
  - [Trivy Documentation](https://aquasecurity.github.io/trivy/)
  - [Nancy Documentation](https://github.com/sonatype-nexus-community/nancy)

---

**Last Updated**: 2025-08-04 (v0.3.1 Story 1.3)  
**Version**: 1.0 - Foundation Security Tools (Trivy + Nancy)