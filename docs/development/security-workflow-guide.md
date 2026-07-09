# CFGMS Security Workflow Guide

## Overview

This guide provides comprehensive documentation for the CFGMS security workflow, covering the complete pipeline from local development to production deployment. The security workflow ensures that no critical vulnerabilities reach production while providing automated remediation guidance and emergency override capabilities.

## Table of Contents

1. [Security Tools Overview](#security-tools-overview)
2. [Local Development Workflow](#local-development-workflow)
3. [GitHub Actions Integration](#github-actions-integration)
4. [Production Deployment Gates](#production-deployment-gates)
5. [Emergency Override Process](#emergency-override-process)
6. [Automated Remediation](#automated-remediation)
7. [Troubleshooting](#troubleshooting)
8. [Performance Optimization](#performance-optimization)
9. [Metrics and Monitoring](#metrics-and-monitoring)

## Security Tools Overview

The CFGMS security workflow integrates four complementary security scanning tools:

### 1. Trivy - Vulnerability Scanning

- **Purpose**: Scans filesystem for known vulnerabilities in dependencies and infrastructure
- **Scope**: Critical/High CVEs, secrets, misconfigurations
- **Blocking**: Yes (Critical/High vulnerabilities block deployment)
- **SARIF Support**: Yes (GitHub Security tab integration)

### 2. Nancy - Go Dependency Scanning

- **Purpose**: Specialized Go module vulnerability scanning
- **Scope**: Go dependencies and transitive dependencies
- **Blocking**: No (informational, but tracked)
- **SARIF Support**: No (custom integration)

### 3. gosec - Go Security Patterns

- **Purpose**: Static analysis for Go security anti-patterns
- **Scope**: 127+ security checks for common Go vulnerabilities
- **Blocking**: No (informational, but tracked)
- **SARIF Support**: Yes (GitHub Security tab integration)

### 4. staticcheck - Advanced Static Analysis

- **Purpose**: Advanced Go code quality and correctness analysis
- **Scope**: 47 categories of code quality issues
- **Blocking**: No (code quality focus)
- **SARIF Support**: Limited (JSON output converted)

### 5. CodeQL - Semantic Code Analysis

- **Purpose**: Deep semantic / data-flow analysis (taint tracking) for vulnerability classes like path-injection (CWE-22), log-injection (CWE-117), and clear-text logging (CWE-312)
- **Scope**: Whole-program data flow, run in GitHub Actions (`codeql-analysis.yml`)
- **Blocking**: Findings post as PR review threads; main's ruleset requires thread resolution, so they gate release PRs in practice
- **SARIF Support**: Native (results land in the Security → Code scanning tab)

#### Custom models & false positives (IMPORTANT)

CodeQL cannot see our runtime validators, so it raises false positives where a value is actually sanitized. We correct this with a **CodeQL data-extension pack**, not by editing the upstream `github/codeql` repo:

- **Pack source**: `.github/codeql/extensions/` — `qlpack.yml` (`cfg-is/cfgms-go-extensions`) plus `models/*.model.yml`.
- **Publish requirement**: the pack is referenced *by name* from `.github/codeql/codeql-config.yml` (`packs:`) and **must be published to the ghcr.io CodeQL pack registry** by `.github/workflows/codeql-pack-publish.yml`. **Local-path pack references are not supported by the codeql-action** — a model file on disk does nothing until the pack is republished.
- **Bump the version (REQUIRED for every model change)**: editing a `models/*.yml` does nothing on its own. `codeql pack publish` refuses to overwrite an existing `<name>@<version>` and no-ops (`"already exists"`); the publish workflow treats that as a green no-op. You **must bump `version:` in `.github/codeql/extensions/qlpack.yml`** in the same change, or the registry keeps serving the old pack and your model stays inert (it will still *bundle* fine, masking the problem).
- **Already modeled**: `safeJoin` (path-injection), `ValidateAndCleanPath` (path-injection), `SanitizeLogValue` + `RedactedID` (log-injection / clear-text-logging).

Decision path for a CodeQL alert:

1. **Genuine bug** → fix the code (e.g. wrap operator-supplied values in `logging.SanitizeLogValue`).
2. **False positive with a real, value-returning sanitizer** (e.g. `safeJoin`, `ValidateAndCleanPath`) → add/extend a model. Use **both** `barrierModel` (kind = the sink kind, e.g. `path-injection`; CodeQL ≥ 2.25.2) **and** `summaryModel(kind=value)` together — neither is reliable alone across all taint-flow paths (json.Decode field-selection flows bypass barrierModel in some CodeQL versions; summaryModel can miss other paths). Also prefer refactoring the call site to *use the sanitizer's return value* (e.g. `cleanedBase := ValidateAndCleanPath(...)`) rather than discarding it — a code-level taint barrier is more robust than any model. Verify the exact `barrierModel` tuple format against `github/codeql:go/ql/lib/ext/` — the format is finicky and CI is the only reliable verification (CodeQL can't be modeled-and-tested purely locally).
3. **False positive from a guard-style validator** (returns only `error`, e.g. blobstore `validateKey`/`validateKeyComponent`) or a **heuristic source** (CodeQL flagging a variable *named* `*SecretKey` that holds a SecretStore key *reference*, not a value) → data extensions can't cleanly model these; **dismiss the alert with justification** (or refactor to a value-returning sanitizer that *can* be modeled).
4. **False positive from struct field-insensitivity** (CodeQL traces taint through a whole struct because one field is a secret — e.g. `APIKey.Key` — even though only non-secret fields are logged) → these **cannot** be fixed by extension-pack models (no field-access barrier primitive exists). Dismiss with justification; confirm via grep that no secret/credential field value is passed to the logger at the flagged site.

#### Model inventory and dismissal log (most recent first)

| Pack version | Alert IDs | Kind | Resolution | Notes |
|---|---|---|---|---|
| 0.0.7 | #745, #746 | path-injection | Code fix + model | `git_store.go`: use `cleanedBase` (return value of `ValidateAndCleanPath`) instead of raw `tenantID` in `filepath.Join`. `ValidateAndCleanPath` added as `summaryModel` + `barrierModel` in `path-injection-sanitizers.model.yml`. |
| 0.0.7 | #669, #713, #714, #715, #722 | log-injection | Model + dismiss | `SanitizeLogValue` `summaryModel(kind=value)` added as belt-and-suspenders over existing `barrierModel` (json.Decode field-selection flows bypass barrierModel alone). Alerts dismissed as FP: all sites already wrap input in `SanitizeLogValue`; the barrierModel is correct but insufficiently reliable. |
| 0.0.7 | #774, #777 | clear-text-logging | Dismiss | Struct field-insensitivity FP: `keyInfo.ID`/`keyInfo.TenantID` (middleware.go) and `deviceID` (controller_service.go) are non-secret fields; the struct's `Key`/`Token` field is never logged. Cannot be modeled (no field-access barrier primitive). |
| 0.0.6 | #747–#751 | log-injection | Dismiss | handlers_registration_refresh.go — json.Decode field-selection sources; all sites use `SanitizeLogValue`. Same heuristic-source class as #669–#722. |
| 0.0.5 | safeJoin | path-injection | Model | `summaryModel` + `barrierModel` for `pkg/storage/providers/flatfile.safeJoin`. |

## Local Development Workflow

### Prerequisites

Install security tools locally:

```bash
# Install all security tools
make install-nancy

# Install individual tools (Ubuntu/Debian)
sudo apt-get install trivy
go install github.com/securego/gosec/v2/cmd/gosec@v2.27.1
go install honnef.co/go/tools/cmd/staticcheck@2026.1
```

### Development Security Commands

```bash
# Quick security check (development)
make security-check

# Comprehensive security scan (pre-commit)
make security-scan

# Non-blocking scan (CI-friendly)
make security-scan-nonblocking

# Generate remediation report for Claude Code
make security-remediation-report

# Unified development validation
make test-with-security
```

### Integration with CLAUDE.md Workflow

The security workflow is integrated into the mandatory CLAUDE.md development process:

```bash
# Step 6: Run Security Scanning (MANDATORY)
make security-scan  # MUST pass before proceeding

# Alternative: Unified validation (RECOMMENDED)
make test-with-security  # Runs: test + security-scan + summary
```

## GitHub Actions Integration

### Security Scanning Workflow

**File**: `.github/workflows/security-scan.yml`

**Features**:

- Parallel execution across 4 security tools
- SARIF output for GitHub Security tab integration
- Tool-specific caching for performance
- Automated remediation report generation
- Failure notifications with actionable guidance

**Triggers**:

- Push to `develop` and `main` branches
- Pull requests to `develop` and `main` branches
- Manual workflow dispatch with scan type options

**Parallel Jobs**:

1. `trivy-scan` - Vulnerability scanning with SARIF output
2. `nancy-scan` - Go dependency scanning
3. `gosec-scan` - Security pattern analysis with SARIF output
4. `staticcheck-scan` - Code quality analysis
5. `security-validation` - Consolidated results and reporting

### Production Deployment Gates

**File**: `.github/workflows/production-gates.yml`

**Security Gate Features**:

- Critical/High vulnerability blocking
- Emergency override mechanism
- Comprehensive audit trail
- Automated notifications
- Integration with existing release gates

**Gate Flow**:

1. `security-deployment-gate` - Primary security validation
2. `production-risk-assessment` - Risk analysis (requires security approval)
3. `deployment-notification` - Automated status notifications

## Production Deployment Gates

### Security Gate Logic

The security deployment gate blocks production deployments when:

- **Critical vulnerabilities** are detected (CVE severity: CRITICAL)
- **High vulnerabilities** are detected (CVE severity: HIGH)
- Security scanning tools fail to execute properly

### Gate Decision Matrix

| Security Status | Deployment Allowed | Action Required |
|----------------|-------------------|-----------------|
| Clean | ✅ Yes | Proceed with deployment |
| Medium/Low Issues | ✅ Yes | Monitor and plan remediation |
| High Issues | ❌ No | Fix vulnerabilities or use override |
| Critical Issues | ❌ No | **Mandatory fix** or emergency override |

### Integration Points

All production gates depend on security approval:

- `production-risk-assessment` requires `security-deployment-gate` success

## Emergency Override Process

### When to Use Emergency Override

Emergency override should only be used for:

- **Critical production outages** requiring immediate fixes
- **Security vulnerabilities** in production that need urgent patching
- **Business-critical deployments** that cannot wait for vulnerability fixes

### Override Methods

#### Method 1: Workflow Dispatch

1. Go to Actions → Production Risk Gates → Run workflow
2. Set `emergency_override` to `true`
3. Provide detailed `override_reason`
4. Submit and monitor execution

#### Method 2: Emergency File

1. Create `EMERGENCY_DEPLOYMENT` file in repository root
2. Commit and push to trigger deployment
3. File presence automatically enables override

### Override Audit Trail

Every override creates comprehensive audit documentation:

- **Deployment details**: Branch, commit, actor, timestamp
- **Override reason**: Justification and authorization
- **Security status**: Issues present during override
- **Approval chain**: Required post-deployment actions

**Audit Artifacts**:

- `security-deployment-audit` (90-day retention)
- `deployment-notification` (30-day retention)

### Post-Override Requirements

When emergency override is used:

1. **Immediate Risk Assessment**: Document security risks
2. **Remediation Planning**: Create timeline for fixes
3. **Security Review**: Obtain security team approval
4. **Follow-up Deployment**: Apply security fixes ASAP

## Automated Remediation

### Claude Code Integration

The security workflow generates structured JSON reports for automated remediation:

```bash
# Generate remediation report
make security-remediation-report

# Output location
/tmp/cfgms-security-remediation.json
```

### Remediation Report Structure

```json
{
  "timestamp": "2025-08-04T16:15:33Z",
  "project": "cfgms",
  "scanning_tools": ["trivy", "nancy", "gosec", "staticcheck"],
  "summary": {
    "total_issues": 327,
    "critical": 1,
    "high": 1,
    "medium": 87,
    "low": 238
  },
  "remediation_suggestions": [
    {
      "tool": "trivy",
      "category": "dependency_vulnerabilities",
      "severity": "CRITICAL_HIGH",
      "auto_fixable": true,
      "claude_prompt": "Fix critical and high vulnerability dependencies...",
      "priority": 1,
      "validation_command": "make security-trivy"
    }
  ]
}
```

### Automated Remediation Workflow

1. **Detection**: Security scan identifies issues
2. **Report Generation**: Structured JSON created
3. **Claude Code Processing**: AI applies fixes automatically
4. **Validation**: Run security scans to verify fixes
5. **Commit**: Push remediated code

### Remediation Priority

1. **Priority 1**: CRITICAL/HIGH CVEs (deployment blocking)
2. **Priority 2**: Dependency vulnerabilities (same session)
3. **Priority 3**: Security patterns (high → medium)
4. **Priority 4**: Code quality (cleanup/refactoring)

## Performance Optimization

### Parallel Execution

The security workflow uses parallel job execution for optimal performance:

**Before Optimization**: Sequential execution (~15-20 minutes)

```
trivy → nancy → gosec → staticcheck → validation
```

**After Optimization**: Parallel execution (~5-8 minutes)

```
┌─ trivy-scan (3-5 min)
├─ nancy-scan (1-2 min)  
├─ gosec-scan (2-4 min)
└─ staticcheck-scan (3-5 min)
    ↓
security-validation (1 min)
```

### Caching Strategy

Each security tool uses optimized caching:

#### Go Module Caching

```yaml
- name: Cache Go modules
  uses: actions/cache@v3
  with:
    path: ~/go/pkg/mod
    key: ${{ runner.os }}-[tool]-go-${{ hashFiles('**/go.sum') }}
    restore-keys: |
      ${{ runner.os }}-[tool]-go-
```

#### Tool-Specific Caching

- **Trivy**: Database and cache directory caching
- **Nancy**: Binary and database caching
- **gosec**: Go module and binary caching
- **staticcheck**: Go module and analysis caching

### Performance Benchmarks

| Tool | Sequential Time | Parallel Time | Improvement |
|------|----------------|---------------|-------------|
| Trivy | 3-5 min | 3-5 min | Baseline |
| Nancy | 1-2 min | 1-2 min | Baseline |
| gosec | 2-4 min | 2-4 min | Baseline |
| staticcheck | 3-5 min | 3-5 min | Baseline |
| **Total** | **15-20 min** | **5-8 min** | **60-70% faster** |

### Resource Optimization

- **Timeout Management**: Tool-specific timeouts prevent hanging
- **Memory Limits**: Prevent resource exhaustion
- **Concurrent Limits**: Optimal parallel job count
- **Artifact Management**: Efficient artifact upload/download

## Metrics and Monitoring

### Workflow Effectiveness Metrics

The security workflow collects the following metrics:

#### Security Scan Metrics

- **Vulnerability Detection Rate**: Issues found per scan
- **False Positive Rate**: Invalid alerts per tool
- **Remediation Time**: Time from detection to fix
- **Scan Success Rate**: Successful scans vs failures

#### Performance Metrics

- **Scan Duration**: Time per tool and total workflow
- **Cache Hit Rate**: Caching effectiveness
- **Resource Usage**: CPU, memory, and artifact storage
- **Parallel Efficiency**: Speedup from parallelization

#### Deployment Gate Metrics

- **Blocking Rate**: Deployments blocked by security issues
- **Override Usage**: Emergency override frequency and reasons
- **Gate Effectiveness**: Issues caught before production
- **Remediation Success**: Fixes applied successfully

#### Developer Experience Metrics

- **Local vs CI Consistency**: Tool behavior across environments
- **Developer Adoption**: Usage of local security commands
- **Remediation Automation**: Claude Code usage statistics
- **Workflow Completion Time**: End-to-end development cycle

### Metrics Collection Implementation

```bash
# Workflow effectiveness analysis
make analyze-security-metrics

# Performance benchmarking
make benchmark-security-workflow

# Developer experience survey
make security-workflow-survey
```

### Metrics Dashboard

Future implementation will include:

- **Grafana Dashboard**: Real-time security metrics
- **Prometheus Integration**: Metrics collection and alerting
- **GitHub Insights**: Repository security health scores
- **Team Metrics**: Developer productivity and security adoption

## Team Expansion Preparation

### PR-Based Workflow Foundation

The current security workflow is designed to scale for team expansion:

#### Current State (Individual Development)

- Security scans on `develop` and `main` pushes
- Direct branch commits with security validation
- Manual emergency overrides

#### Future State (Team Development)

- Security scans on all pull requests
- Branch protection rules requiring security approval
- Code review integration with security results
- Automated PR status checks

### Branch Protection Configuration

When ready for team expansion, implement:

```yaml
# .github/branch-protection.yml
branches:
  develop:
    protection:
      required_status_checks:
        strict: true
        contexts:
          - "security-validation"
          - "trivy-scan"
          - "gosec-scan"
      enforce_admins: true
      required_pull_request_reviews:
        required_approving_review_count: 1
        dismiss_stale_reviews: true
```

### Code Review Integration

Future enhancements for team workflows:

- **Security Review Bot**: Automated security feedback on PRs
- **Risk Assessment Comments**: Automated risk analysis
- **Remediation Suggestions**: In-line fix recommendations
- **Security Score**: PR security health metrics

### Training and Onboarding

Documentation prepared for team expansion:

- **Security Workflow Training**: Complete guide for new developers
- **Tool-Specific Guides**: Individual tool documentation
- **Troubleshooting Runbook**: Common issues and solutions
- **Best Practices**: Security-first development guidelines

## Troubleshooting

### Common Issues and Solutions

#### Issue: Trivy Database Update Failures

**Symptoms**: `trivy` fails with database update errors
**Solution**:

```bash
# Clear Trivy cache and database
trivy clean --all
# Retry scan
make security-trivy
```

#### Issue: Nancy Binary Download Failures

**Symptoms**: `nancy` installation fails or binary not found
**Solution**:

```bash
# Reinstall Nancy with platform detection
make install-nancy
# Verify installation
nancy --version
```

#### Issue: gosec False Positives

**Symptoms**: `gosec` reports issues in vendor code or test files
**Solution**:

```bash
# Add exclusions to .gosecrc file
echo 'exclude-dirs: vendor,testdata' > .gosecrc
# Or exclude specific rules
gosec -exclude G204 ./...
```

#### Issue: staticcheck Performance Issues

**Symptoms**: `staticcheck` runs slowly or times out
**Solution**:

```bash
# Run with specific packages only
staticcheck ./features/... ./pkg/...
# Or increase timeout
staticcheck -timeout 10m ./...
```

### GitHub Actions Troubleshooting

#### Issue: Security Gate Not Blocking Deployment

**Symptoms**: Deployment proceeds despite security issues
**Diagnosis**:

1. Check security gate job logs
2. Verify `deployment-allowed` output
3. Review security scan results

**Solution**:

```bash
# Debug security gate logic
gh run view [run-id] --log
# Check specific job outputs
gh api repos/cfg-is/cfgms/actions/runs/[run-id]/jobs
```

#### Issue: Emergency Override Not Working

**Symptoms**: Override inputs ignored or not processed
**Diagnosis**:

1. Verify workflow dispatch inputs
2. Check override reason provided
3. Review audit trail generation

**Solution**:

```bash
# Verify workflow inputs
gh workflow run production-gates.yml \
  --field emergency_override=true \
  --field override_reason="Critical production fix"
```

### Performance Issues

#### Issue: Slow Security Scans

**Symptoms**: Workflow takes longer than expected
**Diagnosis**:

1. Check individual tool performance
2. Review cache hit rates
3. Analyze resource usage

**Solution**:

- Optimize Go module caching
- Increase parallel job limits
- Reduce scan scope if appropriate

#### Issue: Cache Misses

**Symptoms**: Tools reinstalling on every run
**Diagnosis**:

1. Verify cache key generation
2. Check cache size limits
3. Review cache restoration logs

**Solution**:

```yaml
# Optimize cache keys
key: ${{ runner.os }}-${{ runner.arch }}-tool-${{ hashFiles('**/go.sum') }}
```

### Support and Escalation

For additional support:

1. **Internal Documentation**: Check `docs/development/` directory
2. **GitHub Issues**: Create issue with `security` label
3. **Security Team**: Escalate critical security issues
4. **DevOps Team**: Infrastructure and CI/CD issues

## Summary

The CFGMS security workflow provides comprehensive protection from development to production:

- **4 Security Tools**: Vulnerability scanning, dependency analysis, security patterns, code quality
- **Parallel Execution**: 60-70% performance improvement
- **GitHub Integration**: SARIF output, Security tab, status checks
- **Production Gates**: Critical vulnerability blocking with emergency override
- **Automated Remediation**: Claude Code integration for automatic fixes
- **Comprehensive Audit**: Full audit trail for all security decisions
- **Team Ready**: Foundation prepared for team expansion and PR workflows

The workflow ensures security-first development while maintaining developer productivity and providing clear paths for issue resolution.
