# CFGMS Security Tools Setup Guide

This guide provides comprehensive instructions for setting up all security scanning tools required for CFGMS development. These tools are integrated into the development workflow via make targets and are mandatory for all code contributions.

## Overview

CFGMS uses a multi-layered security scanning approach with four primary tools:

- **🔍 Trivy**: Filesystem scanning for vulnerabilities, secrets, and misconfigurations
- **📦 Nancy**: Go dependency vulnerability scanning
- **🛡️ gosec**: Go security pattern analysis and anti-pattern detection
- **🔬 staticcheck**: Advanced static analysis with curated rule sets

## Quick Start

```bash
# 1. Install security tools
go install github.com/aquasecurity/trivy/cmd/trivy@v0.69.3  # NEVER @latest — see CVE-2026-33634
go install github.com/securego/gosec/v2/cmd/gosec@v2.25.0
go install honnef.co/go/tools/cmd/staticcheck@2026.1
make install-nancy     # Auto-install Nancy for your platform

# 2. Verify installation and run security scan
make security-scan     # All tools (used in CLAUDE.md workflow)

# 3. Run individual tools if needed
make security-trivy    # Filesystem scanning
make security-deps     # Dependency scanning  
make security-gosec    # Go security pattern analysis
make security-staticcheck # Advanced static analysis

# 4. Quick development check
make security-check    # Same as security-scan but optimized for development
```

## Installation Instructions

### 🔍 Trivy Installation

Trivy scans for vulnerabilities, secrets, and misconfigurations in the filesystem.

#### Linux (x86_64)

```bash
# Recommended: Go installation (pin to v0.69.3 — NEVER use @latest, see CVE-2026-33634)
go install github.com/aquasecurity/trivy/cmd/trivy@v0.69.3

# Alternative: Binary download
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.69.3
```

#### macOS

```bash
# Recommended: Go installation (pin to v0.69.3 — NEVER use @latest, see CVE-2026-33634)
go install github.com/aquasecurity/trivy/cmd/trivy@v0.69.3

# Alternative: Homebrew (verify version after install: trivy --version)
brew install trivy
```

#### Windows (PowerShell)

```powershell
# Go installation (pin to v0.69.3 — NEVER use @latest, see CVE-2026-33634)
go install github.com/aquasecurity/trivy/cmd/trivy@v0.69.3

# Alternative: Binary download
$version = "v0.69.3"
Invoke-WebRequest -Uri "https://github.com/aquasecurity/trivy/releases/download/$version/trivy_$($version.TrimStart('v'))_Windows-64bit.zip" -OutFile "trivy.zip"
Expand-Archive trivy.zip -DestinationPath .
Move-Item trivy.exe $env:USERPROFILE\go\bin\trivy.exe
```

### 📦 Nancy Installation

Nancy scans Go dependencies for known vulnerabilities.

#### Automatic Installation (Recommended)

```bash
# Cross-platform automatic installation
make install-nancy

# This automatically detects your platform and installs Nancy v1.2.0
# to your Go bin directory (already in PATH)
```

#### Manual Installation Options

##### Linux (x86_64)

```bash
# Binary download to Go bin directory
curl -L https://github.com/sonatype-nexus-community/nancy/releases/download/v1.2.0/nancy-v1.2.0-linux-amd64 -o ~/nancy
chmod +x ~/nancy && mv ~/nancy $(go env GOPATH)/bin/nancy
```

##### macOS (Intel)

```bash
# Homebrew (recommended)
brew install nancy

# Binary download to Go bin directory
curl -L https://github.com/sonatype-nexus-community/nancy/releases/download/v1.2.0/nancy-v1.2.0-darwin-amd64 -o ~/nancy
chmod +x ~/nancy && mv ~/nancy $(go env GOPATH)/bin/nancy
```

##### macOS (Apple Silicon)

```bash
# Binary download to Go bin directory
curl -L https://github.com/sonatype-nexus-community/nancy/releases/download/v1.2.0/nancy-v1.2.0-darwin-arm64 -o ~/nancy
chmod +x ~/nancy && mv ~/nancy $(go env GOPATH)/bin/nancy
```

##### Linux (Arch)

```bash
# AUR package
yay -S nancy-bin
```

##### Windows (PowerShell)

```powershell
# Binary download to Go bin directory
Invoke-WebRequest -Uri 'https://github.com/sonatype-nexus-community/nancy/releases/download/v1.2.0/nancy-v1.2.0-windows-amd64.exe' -OutFile 'nancy.exe'
Move-Item nancy.exe $(go env GOPATH)\bin\nancy.exe
```

### 🛡️ gosec Installation

gosec analyzes Go source code for security problems and anti-patterns.

```bash
# Go installation (all platforms) - RECOMMENDED
go install github.com/securego/gosec/v2/cmd/gosec@v2.25.0

# Verify installation
gosec --version
```

**Key Features:**

- Detects SQL injection, crypto weaknesses, and other security anti-patterns
- Configurable via .gosec.json for rule management and false positive suppression
- Non-blocking by default - reports issues without stopping development workflow
- Excludes test files automatically to focus on production code security

### 🔬 staticcheck Installation

staticcheck provides advanced static analysis for Go with curated rule sets that focus on important issues while excluding style warnings for development velocity.

```bash
# Go installation (all platforms) 
go install honnef.co/go/tools/cmd/staticcheck@2026.1
```

**Configuration**: CFGMS includes a `staticcheck.conf` file with curated rules that:

- Focus on critical correctness issues (SA* rules)
- Include standard library misuse detection (ST* rules)
- Exclude style warnings for faster development
- Enable performance optimizations (caching, concurrency)
- Provide clear priority guidance for issue resolution

## Verification Steps

After installing the tools, verify they're working correctly:

### 1. Tool Availability Check

```bash
# Check all tools are in PATH
trivy --version      # Should show: trivy version X.X.X
nancy --version      # Should show: nancy version X.X.X
gosec --version      # Should show: Version: X.X.X

staticcheck --version # Should show: staticcheck version X.X.X
```

### 2. Individual Tool Testing

```bash
# Test Trivy filesystem scanning
make security-trivy

# Test Nancy dependency scanning  
make security-deps

# Test gosec Go security pattern analysis
make security-gosec

# Test staticcheck advanced static analysis  
make security-staticcheck
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

### .gosec.json

Located at project root, configures gosec security analysis:

```json
{
  "global": {
    "nosec": false,
    "exclude-generated": true
  },
  "exclude": {
    "paths": [
      "test/**/*",
      "*_test.go", 
      "*/testdata/*",
      "examples/**/*",
      "docs/**/*"
    ]
  },
  "severity": "medium",
  "confidence": "medium"
}
```

**Key Configuration Options:**

- **exclude.paths**: Automatically excludes test files and documentation
- **severity/confidence**: Set to "medium" to focus on actionable issues
- **nosec comments**: Use `#nosec` in code to suppress false positives on specific lines

### Security Tool Behavior

- **Trivy**: Blocks on CRITICAL/HIGH vulnerabilities, shows all findings
- **Nancy**: Non-blocking, provides remediation guidance for vulnerable dependencies
- **gosec**: Non-blocking, reports security anti-patterns with configurable rules via .gosec.json
- **staticcheck**: Curated rule sets focus on critical issues, performance-optimized with caching

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

### Installation Helpers

```bash
make install-nancy       # Automatic cross-platform Nancy installation
```

### Individual Tools

```bash
make security-trivy      # Trivy filesystem scanning
make security-deps       # Nancy dependency scanning
make security-gosec      # gosec Go security pattern analysis
make security-staticcheck # staticcheck advanced static analysis
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

- **Trivy**: v0.69.3 (pinned — v0.69.4+ compromised per CVE-2026-33634, NEVER use @latest)
- **Nancy**: v1.2.0
- **gosec**: v2.25.0 (pinned — avoid @latest)
- **staticcheck**: 2026.1 (pinned — avoid @latest)

## Contributing to Security Setup

When adding new security tools:

1. Update this guide with installation instructions
2. Add make targets following the `security-*` naming convention
3. Update `.PHONY` declarations in Makefile
4. Include tool in unified `security-scan` target
5. Add verification steps and troubleshooting guidance
6. Test on all supported platforms (Linux, macOS, Windows)

## 🪝 Optional: Pre-commit Hooks (Story 2.3)

**OPTIONAL** pre-commit hooks provide automated security scanning before commits for developers who want additional safety without impacting the core development workflow.

### Quick Setup

```bash
# Install pre-commit (Python package)
pip install pre-commit

# Install hooks in your local repository  
pre-commit install

# Verify installation
pre-commit --version
```

### What's Included

The `.pre-commit-config.yaml` configuration includes:

**🛡️ Security Hooks (Performance Optimized):**

- **gosec**: Go security pattern analysis on changed files only
- **staticcheck**: Static analysis with curated rules on changed files only
- **detect-secrets**: Secret detection with known development certificate exclusions

**⚡ Fast Development Hooks:**

- **go fmt**: Code formatting
- **go imports**: Import organization  
- **go vet**: Basic Go analysis
- **go mod tidy**: Module maintenance

**📁 File Quality Hooks:**

- Trailing whitespace removal
- File ending fixes
- YAML/JSON/TOML validation
- Merge conflict detection
- Large file prevention (1MB limit)

### Usage

**Normal Commit (with hooks):**

```bash
git add .
git commit -m "Your commit message"
# Hooks run automatically on changed files only
```

**Bypass When Needed:**

```bash
# Skip all hooks (emergency commits, CI fixes, etc.)
git commit --no-verify -m "Emergency fix"

# Skip specific hooks  
SKIP=gosec,staticcheck git commit -m "Skip security checks"
```

**Manual Hook Execution:**

```bash
# Run hooks on all files (useful for initial setup)
pre-commit run --all-files

# Run specific hook
pre-commit run gosec

# Update hook versions
pre-commit autoupdate
```

### Performance Design

**Optimized for Development Velocity:**

- Hooks run only on **changed files** (not entire codebase)
- Security tools use **medium severity/confidence** for speed
- **Non-blocking**: Hooks can be bypassed when needed
- **Fast exit**: Basic checks run first, expensive checks run last

**Resource Usage:**

- Average hook execution: **2-5 seconds** for typical commits
- Large commits (10+ files): **10-15 seconds**  
- Full codebase scan: **60+ seconds** (only on `--all-files`)

### Integration with Existing Workflow

**Pre-commit hooks are OPTIONAL and do not replace:**

- CLAUDE.md mandatory workflow security scanning
- CI/CD pipeline security validation
- Make targets for security scanning

**Benefits:**

- **Early Detection**: Catch issues before they reach CI/CD
- **Developer Choice**: Enable when you want extra safety
- **Learning Tool**: See security patterns as you develop
- **Consistency**: Automatic formatting and basic checks

### Troubleshooting

**Hook Installation Issues:**

```bash
# Reinstall hooks
pre-commit uninstall
pre-commit install

# Clear cache and reinstall
pre-commit clean
pre-commit install --install-hooks
```

**Tool Not Found Errors:**

```bash
# Install missing Go tools
go install honnef.co/go/tools/cmd/staticcheck@2026.1
go install github.com/securego/gosec/v2/cmd/gosec@v2.25.0

# Verify PATH
which staticcheck gosec
```

**Performance Issues:**

```bash
# Skip expensive hooks temporarily
SKIP=detect-secrets git commit -m "Skip secret detection"

# Or disable pre-commit entirely
git config core.hooksPath /dev/null  # Disable
git config --unset core.hooksPath     # Re-enable
```

## GitHub Advanced Security Features

CFGMS uses GitHub Advanced Security features for comprehensive security scanning in CI/CD:

### CodeQL Analysis

**What It Is**: Semantic code analysis that finds security vulnerabilities using queries against a code database.

**Accessing Results**:
1. Visit [Security Tab](https://github.com/cfg-is/cfgms/security) in the repository
2. Click "Code scanning" to view CodeQL findings
3. Review alerts with severity ratings and remediation guidance

**Configuration**: See `.github/workflows/codeql.yml` for query configuration and scan schedule.

**Local Testing**: CodeQL requires GitHub infrastructure and cannot be run locally, but findings are visible in pull requests.

### Dependabot Security Updates

**What It Is**: Automated dependency vulnerability detection and update pull requests.

**Workflow**:
1. Dependabot scans `go.mod` daily for vulnerable dependencies
2. Creates automated PRs for security updates
3. PRs include vulnerability details and version compatibility info

**Managing Dependabot PRs**:
```bash
# Review Dependabot PR
gh pr view [PR-NUMBER]

# Check for breaking changes
make test

# Merge if tests pass
gh pr merge [PR-NUMBER] --squash
```

**Configuration**: See `.github/dependabot.yml` for update schedules and package ecosystems.

### Secret Scanning

**What It Is**: Prevents accidental commit of credentials, API keys, and sensitive data.

**Features**:
- Automatic scanning of all commits for known secret patterns
- Push protection (blocks commits with secrets)
- Partner patterns (GitHub, AWS, Azure, etc.)
- Custom patterns for CFGMS-specific secrets

**If Secret Detected**:
1. Do NOT force push to bypass protection
2. Remove the secret from the commit
3. Rotate/revoke the exposed credential
4. Rewrite git history: `git rebase -i` or create fresh branch

**Viewing Alerts**: Navigate to [Security > Secret scanning](https://github.com/cfg-is/cfgms/security/secret-scanning)

### Security Advisories

**What It Is**: Private vulnerability reporting and coordinated disclosure.

**For Reporters**:
1. Visit [Security Advisories](https://github.com/cfg-is/cfgms/security/advisories)
2. Click "Report a vulnerability"
3. Provide details privately (NOT public issues)
4. We respond within 48 hours

**For Maintainers**:
- Triage reports in Security > Advisories
- Create CVE if applicable
- Coordinate disclosure timeline
- Publish advisory after fix deployed

### OpenSSF Scorecard

**What It Is**: Automated security health metrics using best practice checks.

**Metrics Tracked**:
- Dependency update practices
- Code review requirements
- CI/CD security configuration
- Branch protection enforcement
- Security policy presence
- Vulnerability disclosure process

**View Scorecard**: [securityscorecards.dev/viewer/?uri=github.com/cfg-is/cfgms](https://securityscorecards.dev/viewer/?uri=github.com/cfg-is/cfgms)

**Improving Score**:
- Maintain branch protection on main/develop
- Require code reviews for all PRs
- Keep dependencies updated
- Use SAST tools (CodeQL, gosec)
- Document security policy (SECURITY.md)

### Navigating GitHub Security Tab

**Quick Access**:
```
Repository → Security tab (shield icon)
  ├── Overview: Security posture summary
  ├── Code scanning: CodeQL findings
  ├── Secret scanning: Detected secrets
  ├── Dependabot: Dependency vulnerabilities
  ├── Security advisories: CVE reporting
  └── Security policy: SECURITY.md
```

**Best Practices**:
- Review security tab weekly
- Triage high/critical findings immediately
- Track remediation in GitHub Issues
- Link security fixes to advisories

## Support and Documentation

- **CFGMS Security Architecture**: [docs/security/architecture.md](../security/architecture.md)
- **Development Workflow**: [CLAUDE.md](../../CLAUDE.md)
- **Issue Reporting**: [GitHub Issues](https://github.com/cfg-is/cfgms/issues)
- **Security Tab**: [GitHub Security](https://github.com/cfg-is/cfgms/security)
- **Tool Documentation**:
  - [Trivy Documentation](https://aquasecurity.github.io/trivy/)
  - [Nancy Documentation](https://github.com/sonatype-nexus-community/nancy)
  - [CodeQL Documentation](https://codeql.github.com/docs/)
  - [Dependabot Documentation](https://docs.github.com/en/code-security/dependabot)
  - [OpenSSF Scorecard](https://github.com/ossf/scorecard)

---

**Last Updated**: 2026-01-11 (v0.8.0 - Public Repository Launch)
**Version**: 2.0 - Added GitHub Advanced Security Features
