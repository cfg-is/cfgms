# GitHub Actions Workflows

This directory contains automated CI/CD workflows for CFGMS. All workflows are now active for the public repository.

## Active Workflows

### Build & Test Workflows

#### `cross-platform-build.yml`
**Purpose**: Cross-platform compilation and native build validation

**Triggers**: Push to main/develop, Pull Requests, Manual dispatch

**Platforms**:
- Linux (AMD64)
- Windows (AMD64)
- macOS (ARM64 - Apple Silicon)

**What it does**:
- Cross-compilation verification for all supported platforms
- Native builds on Linux, Windows, and macOS
- Integration tests with Docker infrastructure
- Binary artifact validation

**Runtime**: ~4-5 minutes

---

#### `test-suite.yml`
**Purpose**: Complete test suite execution

**Triggers**: Push to main/develop, Pull Requests

**What it does**:
- Full unit test coverage
- Integration test execution
- Module testing (file, directory, script, etc.)
- Race condition detection (-race flag)
- Commercial build validation

**Runtime**: ~3-4 minutes

---

#### `production-gates.yml`
**Purpose**: Production Risk Gates with cross-platform validation

**Triggers**: Push to main/develop, Pull Requests, Manual dispatch with gate selection

**What it does**:
- Security deployment gate (Critical/High vulnerability blocking)
- Cross-platform integration tests (Linux, Windows, macOS)
- Template and configuration validation
- Production readiness verification
- Emergency override support (with justification required)

**Features**:
- Configurable gate types (v030, v040, all)
- Emergency override mechanism with audit trail
- Comprehensive security scanning
- Platform-specific validation

**Runtime**: ~8-12 minutes

---

### Security Workflows

#### `security-scan.yml`
**Purpose**: Comprehensive security vulnerability scanning

**Triggers**: Push to main/develop, Pull Requests, Daily schedule (3 AM UTC)

**Security Tools**:
- **Trivy**: Dependency vulnerability scanning
- **gosec**: Go security code analysis
- **staticcheck**: Advanced Go static analysis
- **nancy**: Go dependency vulnerability checking

**What it does**:
- Scans dependencies for known vulnerabilities
- Performs static security analysis of Go code
- Checks for common security anti-patterns
- Uploads results to GitHub Security tab (SARIF)

**Runtime**: ~5-7 minutes

---

#### `codeql-analysis.yml`
**Purpose**: GitHub CodeQL security analysis

**Triggers**: Push to main/develop, Pull Requests, Weekly schedule

**What it does**:
- Advanced semantic code analysis
- Security vulnerability detection
- Code quality analysis
- Uploads findings to GitHub Security tab

**Runtime**: ~2-3 minutes

---

#### `docker-security.yml`
**Purpose**: Container image security scanning

**Triggers**: Push to main/develop, Pull Requests, Manual dispatch

**What it does**:
- Scans Docker images for vulnerabilities
- Validates Dockerfile best practices
- Checks base image security
- SBOM (Software Bill of Materials) generation

**Runtime**: ~3-4 minutes

---

### Compliance & Quality Workflows

#### `template-validation.yml`
**Purpose**: Template and configuration file validation

**Triggers**: Push to main/develop, Pull Requests

**What it does**:
- Validates workflow templates
- Checks configuration file syntax
- Validates YAML schema compliance
- Ensures template consistency

**Runtime**: ~1-2 minutes

---

#### `license-check.yml`
**Purpose**: License compliance and dependency validation

**Triggers**: Push to main/develop, Pull Requests

**What it does**:
- Validates all dependencies have compatible licenses
- Generates license report
- Checks for license conflicts
- SBOM generation for compliance

**Runtime**: ~2-3 minutes

---

### Release Workflows

#### `release.yml`
**Purpose**: Automated release build and deployment

**Triggers**: Tag creation (v*), Manual dispatch

**What it does**:
- Multi-platform binary builds (Linux, Windows, macOS)
- Cross-compilation for all supported architectures
- Release artifact generation
- GitHub Release creation
- Changelog generation

**Platforms**: Linux AMD64/ARM64, Windows AMD64/ARM64, macOS ARM64

**Runtime**: ~10-15 minutes

---

## Workflow Status Badges

Add these badges to your README.md:

```markdown
[![Cross-Platform Build](https://github.com/cfg-is/cfgms/actions/workflows/cross-platform-build.yml/badge.svg)](https://github.com/cfg-is/cfgms/actions/workflows/cross-platform-build.yml)
[![Security Scan](https://github.com/cfg-is/cfgms/actions/workflows/security-scan.yml/badge.svg)](https://github.com/cfg-is/cfgms/actions/workflows/security-scan.yml)
[![CodeQL](https://github.com/cfg-is/cfgms/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/cfg-is/cfgms/actions/workflows/codeql-analysis.yml)
```

## Running Workflows Locally

Most workflow validation can be run locally using make targets:

```bash
# Run full test suite (same as test-suite.yml)
make test

# Run security scans (similar to security-scan.yml)
make security-scan

# Combined validation (tests + security)
make test-commit

# Complete CI validation (matches production-gates.yml)
make test-ci
```

## Workflow Trigger Matrix

| Workflow | Push (main/develop) | Pull Request | Schedule | Manual |
|----------|---------------------|--------------|----------|--------|
| cross-platform-build.yml | ✅ | ✅ | ❌ | ✅ |
| test-suite.yml | ✅ | ✅ | ❌ | ❌ |
| production-gates.yml | ✅ | ✅ | ❌ | ✅ |
| security-scan.yml | ✅ | ✅ | Daily (3 AM UTC) | ❌ |
| codeql-analysis.yml | ✅ | ✅ | Weekly | ❌ |
| docker-security.yml | ✅ | ✅ | ❌ | ✅ |
| template-validation.yml | ✅ | ✅ | ❌ | ❌ |
| license-check.yml | ✅ | ✅ | ❌ | ❌ |
| release.yml | ❌ | ❌ | ❌ | ✅ (tags: v*) |

## Required Status Checks for Branch Protection

The following workflows should be configured as required status checks:

- **cross-platform-build.yml**: All platform builds must pass
- **test-suite.yml**: Complete test suite must pass
- **security-scan.yml**: No critical/high vulnerabilities allowed
- **codeql-analysis.yml**: CodeQL security analysis must pass
- **license-check.yml**: License compliance must pass

See [Branch Protection Rules](https://github.com/cfg-is/cfgms/settings/branches) for configuration.

## Troubleshooting

### Workflow Failures

**Security scan blocking deployment**:
- Check GitHub Security tab for vulnerability details
- Run `make security-scan` locally to reproduce
- Fix vulnerabilities or request emergency override (production-gates.yml)

**Cross-platform build failures**:
- Verify code compiles on target platform
- Check platform-specific dependencies
- Review cross-compilation settings in Makefile

**Test failures**:
- Run `make test` locally to reproduce
- Check for race conditions with `make test-race`
- Review test logs in GitHub Actions output

### Emergency Override (Production Gates)

In exceptional circumstances, the production-gates.yml workflow supports emergency override:

1. Trigger manual workflow dispatch
2. Enable `emergency_override: true`
3. Provide detailed `override_reason`
4. Override is logged and auditable
5. Use only for critical production deployments

**Note**: Emergency overrides require justification and are tracked in audit logs.

## Adding New Workflows

When creating new workflows:

1. Place `.yml` file in `.github/workflows/`
2. Follow naming convention: `feature-name.yml`
3. Include clear `name:` field
4. Document purpose in this README
5. Test locally before committing
6. Consider adding to required status checks

## Security Considerations

- **No secrets in workflows**: Use GitHub Secrets for sensitive data
- **Minimal permissions**: Workflows run with least privilege
- **SARIF uploads**: Security findings uploaded to GitHub Security tab
- **Audit trail**: All workflow runs logged and traceable

## References

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [CFGMS Contributing Guide](../../CONTRIBUTING.md)
- [CFGMS Development Workflow](../../docs/development/story-checklist.md)
- [Security Policy](../../SECURITY.md)

---

**Last Updated**: 2025-12-28 (v0.8.0 - Re-enabled all workflows for public repository)
