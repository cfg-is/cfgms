# Security Workflow Troubleshooting Guide

## Quick Reference

### Emergency Commands

```bash
# Fix common issues immediately
make security-scan-nonblocking  # Skip blocking on failures
trivy clean --all              # Reset Trivy database
make install-nancy             # Reinstall Nancy
rm -rf ~/.cache/gosec          # Clear gosec cache
```

### Status Check Commands

```bash
# Verify tool installation
trivy --version && nancy --version && gosec -version && staticcheck -version

# Test individual tools
make security-trivy
make security-deps  
make security-gosec
make security-staticcheck

# Generate debug report
make security-remediation-report
```

## Tool-Specific Issues

### Trivy Issues

#### Database Update Failures
**Error**: `Failed to initialize Trivy DB`
```bash
# Solution 1: Clear cache and retry
trivy clean --all
make security-trivy

# Solution 2: Manual database update
trivy image --download-db-only
```

#### Network/Proxy Issues
**Error**: `Failed to fetch security database`
```bash
# Solution: Configure proxy
export HTTP_PROXY=http://proxy:8080
export HTTPS_PROXY=http://proxy:8080
trivy fs . --offline  # Use offline mode
```

#### Permission Issues
**Error**: `Permission denied writing to cache`
```bash
# Solution: Fix cache permissions
sudo chown -R $USER ~/.cache/trivy
chmod -R 755 ~/.cache/trivy
```

#### Large Repository Timeouts
**Error**: `Scan timeout exceeded`
```bash
# Solution: Increase timeout and scope
trivy fs . --timeout 10m --scanners vuln
# Or scan specific directories
trivy fs ./features --timeout 5m
```

### Nancy Issues

#### Installation Problems
**Error**: `nancy: command not found`
```bash
# Solution 1: Reinstall with make target
make install-nancy

# Solution 2: Manual installation
curl -sSfL https://github.com/sonatypecommunity/nancy/releases/download/v1.0.51/nancy-v1.0.51-linux-amd64 \
  -o /usr/local/bin/nancy && chmod +x /usr/local/bin/nancy
```

#### Go Module Issues
**Error**: `Could not parse go.mod`
```bash
# Solution: Verify go.mod format
go mod tidy
go mod verify
make security-deps
```

#### False Positives
**Error**: Nancy reports vulnerabilities in vendor code
```bash
# Solution: Use .nancy-ignore file
echo "CVE-2021-xxxxx" > .nancy-ignore
nancy sleuth --exclude-vulnerability-file .nancy-ignore
```

### gosec Issues

#### High Memory Usage
**Error**: `gosec killed (OOM)`
```bash
# Solution: Limit scan scope
gosec -exclude-dir=vendor ./...
gosec ./features/... ./pkg/...  # Specific directories only
```

#### False Positives
**Error**: gosec reports issues in test files
```bash
# Solution 1: Use .gosecrc configuration
cat > .gosecrc << EOF
{
  "exclude-dirs": ["vendor", "testdata"],
  "exclude": ["G204", "G304"],
  "tests": false
}
EOF

# Solution 2: Command line exclusions
gosec -exclude G204,G304 -exclude-dir vendor ./...
```

#### SSL/TLS Check Issues
**Error**: G402 - TLS InsecureSkipVerify set true
```bash
# Solution: Properly handle test vs production code
# In test files, add build constraint:
//go:build integration
// +build integration

# Or exclude test files:
gosec -tests=false ./...
```

### staticcheck Issues

#### Performance Problems
**Error**: staticcheck runs very slowly
```bash
# Solution 1: Limit scope
staticcheck ./features/... ./pkg/...

# Solution 2: Increase resources
staticcheck -timeout 10m ./...

# Solution 3: Use Go build cache
export GOCACHE=/tmp/go-build-cache
staticcheck ./...
```

#### Module Resolution Issues
**Error**: `could not load packages`
```bash
# Solution: Clean and rebuild
go clean -modcache
go mod download
staticcheck ./...
```

## GitHub Actions Issues

### Workflow Failures

#### Security Gate Not Blocking
**Symptoms**: Deployment proceeds despite security issues
**Diagnosis**:
```bash
# Check workflow run logs
gh run list --workflow=production-gates.yml
gh run view [run-id] --log

# Check security gate outputs
gh api repos/cfg-is/cfgms/actions/runs/[run-id]/jobs | \
  jq '.jobs[] | select(.name | contains("security")) | .steps[].conclusion'
```

**Solutions**:
1. Verify `deployment-allowed` output is `false`
2. Check conditional logic in dependent jobs
3. Ensure security scan actually detected issues

#### SARIF Upload Failures
**Error**: `Error uploading SARIF file`
**Solutions**:
```bash
# Check SARIF file validity
cat sarif-results/trivy.sarif | jq .

# Verify file size (GitHub limit: 10MB)
ls -lh sarif-results/

# Check GitHub Security tab permissions
gh api repos/cfg-is/cfgms/security-advisories --method GET
```

#### Cache Issues
**Error**: Cache restore failures or misses
**Solutions**:
```yaml
# Optimize cache keys
- name: Cache Go modules
  uses: actions/cache@v3
  with:
    path: |
      ~/go/pkg/mod
      ~/.cache/go-build
    key: ${{ runner.os }}-${{ runner.arch }}-go-${{ hashFiles('**/go.sum') }}
    restore-keys: |
      ${{ runner.os }}-${{ runner.arch }}-go-
```

#### Parallel Job Failures
**Error**: Jobs failing due to resource contention
**Solutions**:
1. Reduce concurrent job count
2. Add job dependencies to sequence resource-heavy operations
3. Increase timeout values

### Emergency Override Issues

#### Override Not Recognized
**Symptoms**: Emergency override input ignored
**Diagnosis**:
```bash
# Check workflow dispatch inputs
gh run list --workflow=production-gates.yml -L 1
gh run view [run-id] --json inputs

# Verify override logic
gh run view [run-id] --log-failed
```

**Solutions**:
1. Ensure `override_reason` is provided when using `emergency_override: true`
2. Verify EMERGENCY_DEPLOYMENT file is in repository root
3. Check override detection logic in workflow

#### Audit Trail Missing
**Symptoms**: No audit artifacts generated
**Solutions**:
1. Check artifact upload step execution
2. Verify audit trail generation logic
3. Ensure proper JSON formatting in audit files

## Performance Issues

### Slow Local Scans

#### Comprehensive Diagnosis
```bash
# Benchmark individual tools
time make security-trivy
time make security-deps
time make security-gosec
time make security-staticcheck

# Check cache status
ls -la ~/.cache/trivy
ls -la ~/.cache/go-build
go env GOCACHE
```

#### Optimization Solutions
```bash
# 1. Optimize Go build cache
export GOCACHE=/tmp/go-build-cache
export GOMODCACHE=/tmp/go-mod-cache

# 2. Use focused scans
trivy fs . --scanners vuln --severity CRITICAL,HIGH
gosec -exclude-dir vendor,testdata ./...

# 3. Parallel execution (local)
(make security-trivy &); (make security-gosec &); wait
```

### GitHub Actions Performance

#### Slow Workflow Execution
**Diagnosis**:
```bash
# Analyze workflow timing
gh run view [run-id] --json jobs | \
  jq '.jobs[] | {name, startedAt, completedAt, conclusion}'

# Check runner resource usage
gh run view [run-id] --log | grep -i "resource\|memory\|cpu"
```

**Solutions**:
1. Optimize caching strategies
2. Use faster runners (if available)
3. Reduce scan scope for non-critical paths
4. Implement smart differential scanning

## Network and Connectivity Issues

### Corporate Proxy/Firewall

#### Tool Configuration
```bash
# Set proxy for all tools
export HTTP_PROXY=http://proxy.corp.com:8080
export HTTPS_PROXY=http://proxy.corp.com:8080
export NO_PROXY=localhost,127.0.0.1,.corp.com

# Tool-specific proxy configuration
trivy --proxy http://proxy.corp.com:8080 fs .
```

#### Certificate Issues
```bash
# Add corporate certificates
export SSL_CERT_FILE=/path/to/corp-ca-bundle.crt
export REQUESTS_CA_BUNDLE=/path/to/corp-ca-bundle.crt

# Skip certificate verification (NOT recommended for production)
export TRIVY_INSECURE=true
```

### Database Update Issues

#### Offline Mode Setup
```bash
# Pre-download databases
trivy image --download-db-only
nancy --update-db

# Use offline mode
trivy fs . --offline
```

## Integration Issues

### Claude Code Remediation

#### Report Generation Failures
**Error**: No remediation report generated
```bash
# Debug report generation
make security-remediation-report
ls -la /tmp/cfgms-security-remediation.json
cat /tmp/cfgms-security-remediation.json | jq .
```

#### Invalid JSON Format
**Error**: Malformed remediation JSON
```bash
# Validate JSON format
cat /tmp/cfgms-security-remediation.json | python -m json.tool

# Regenerate with debug output
make security-remediation-report 2>&1 | tee remediation-debug.log
```

### Version Compatibility

#### Tool Version Mismatches
```bash
# Check current versions
trivy --version      # Should be latest stable
nancy --version      # Should be v1.0.51+
gosec -version       # Should be v2.18+
staticcheck -version # Should be 2023.1+

# Update to compatible versions
go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
go install honnef.co/go/tools/cmd/staticcheck@latest
```

## Escalation Procedures

### Level 1: Self-Service
1. Check this troubleshooting guide
2. Review tool-specific documentation
3. Check GitHub Actions logs
4. Try clean reinstallation

### Level 2: Team Support
1. Create GitHub issue with `security` and `bug` labels
2. Include diagnostic information:
   - Tool versions
   - Error messages
   - Workflow run IDs
   - Environment details

### Level 3: Security Team
For security-critical issues:
1. Escalate to security team immediately
2. Document security impact
3. Consider emergency override if appropriate
4. Plan post-resolution security review

### Level 4: Emergency Response
For production-blocking security issues:
1. Use emergency override process
2. Document override reason thoroughly
3. Notify security and DevOps teams
4. Schedule immediate post-deployment remediation

## Diagnostic Commands Reference

### Environment Diagnostics
```bash
# System information
echo "OS: $(uname -a)"
echo "Go: $(go version)"
echo "Git: $(git --version)"

# Tool availability
which trivy nancy gosec staticcheck

# Environment variables
env | grep -E "(PROXY|SSL|CERT|GOPATH|GOCACHE)"
```

### Security Scan Diagnostics
```bash
# Full diagnostic run
make security-scan 2>&1 | tee security-diagnostic.log

# Individual tool diagnostics
trivy fs . --debug 2>&1 | tee trivy-debug.log
gosec -verbose ./... 2>&1 | tee gosec-debug.log
```

### GitHub Actions Diagnostics
```bash
# Recent workflow runs
gh run list --workflow=security-scan.yml -L 5

# Detailed run information
gh run view [run-id] --json | jq '{id, status, conclusion, jobs: [.jobs[] | {name, conclusion, startedAt, completedAt}]}'

# Download artifacts for analysis
gh run download [run-id]
```

## Prevention Best Practices

### Local Development
1. Run `make security-check` regularly during development
2. Use `make test-with-security` before commits
3. Keep security tools updated monthly
4. Configure IDE/editor security plugin integration

### CI/CD Maintenance
1. Monitor workflow performance trends
2. Update tool versions quarterly
3. Review and update ignore files regularly
4. Test emergency override procedures

### Team Coordination
1. Document all override usage
2. Share security findings with team
3. Conduct monthly security workflow reviews
4. Maintain troubleshooting knowledge base

## Quick Fix Scripts

### Reset All Security Tools
```bash
#!/bin/bash
# reset-security-tools.sh

echo "Resetting all security tools..."

# Clear all caches
trivy clean --all
rm -rf ~/.cache/gosec
rm -rf ~/.cache/staticcheck

# Reinstall tools
make install-nancy
go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
go install honnef.co/go/tools/cmd/staticcheck@latest

# Test installations
trivy --version && nancy --version && gosec -version && staticcheck -version

echo "Security tools reset complete!"
```

### Emergency Scan Override
```bash
#!/bin/bash
# emergency-scan.sh

echo "Running emergency security scan with reduced scope..."

# Focus on critical issues only
trivy fs . --severity CRITICAL --exit-code 0
gosec -severity high ./... || true
make security-deps || true

echo "Emergency scan complete - review results manually"
```