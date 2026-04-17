# CFGMS Release Validation Checklist

## Overview

This checklist ensures all critical functionality works before releasing a new version of CFGMS. Follow this process for every release (minor, major, or patch).

**Target Completion Time:** 30-45 minutes
**Required Resources:** Docker, test infrastructure, clean environment

---

## Pre-Release Validation

### 1. Code Quality Gates ✅

Run these commands and ensure 100% pass rate:

```bash
# Must pass before proceeding
make test              # All unit & integration tests
make lint              # Code quality checks
make security-scan     # Security vulnerability scan
make check-architecture # Central provider compliance
```

**Exit Criteria:**

- [ ] All tests pass (0 failures)
- [ ] No linting errors
- [ ] No critical/high security vulnerabilities
- [ ] No central provider violations

---

## Tier 1: Standalone Steward Validation

### 2. QUICK_START.md Option A - Standalone Steward ✅

Validates the 5-minute quick start for new users.

```bash
# Run Docker-based E2E tests
cd test/integration/standalone
go test -v -timeout 5m
```

**Tests Validated:**

- [ ] TestQuickStartOptionA - Complete workflow validation
- [ ] TestFilePermissions - File creation with 0644
- [ ] TestDirectoryPermissions - Directory creation with 0755
- [ ] TestIdempotency - Multiple runs work correctly
- [ ] TestStewardLogs - Container startup successful

**Manual Validation (Optional):**

```bash
# Build steward
make build-steward

# Create test config
sudo mkdir -p /etc/cfgms
sudo tee /etc/cfgms/test-release.yaml > /dev/null <<EOF
steward:
  id: release-test-steward

resources:
  - name: test-file
    module: file
    config:
      path: /tmp/cfgms-release-test.txt
      content: "Release $(git describe --tags) validation"
      state: present
      mode: "0644"
EOF

# Run steward
sudo ./bin/cfgms-steward -config /etc/cfgms/test-release.yaml

# Verify
cat /tmp/cfgms-release-test.txt

# Cleanup
sudo rm /tmp/cfgms-release-test.txt /etc/cfgms/test-release.yaml
```

**Exit Criteria:**

- [ ] All Docker tests pass
- [ ] (Optional) Manual test creates file successfully

---

## Tier 2: Controller + Steward Validation

### 3. QUICK_START.md Option B - Standalone Controller ✅

Validates controller with flatfile+sqlite OSS composite storage for workflow/SaaS operations.

```bash
# Run Docker-based E2E tests
cd test/integration/controller
go test -v -timeout 10m
```

**Tests Validated:**

- [ ] TestControllerStartup - Controller starts successfully
- [ ] TestControllerAPI - HTTP API accessible
- [ ] TestStewardConnection - Steward connects via gRPC-over-QUIC
- [ ] TestStorageInitialization - Git storage initialized
- [ ] TestTransportServer - Transport server running
- [ ] TestModuleExecution - Module execution validated
- [ ] TestCertificateManagement - TLS configuration correct

**Exit Criteria:**

- [ ] All Docker tests pass
- [ ] Controller starts without errors
- [ ] Steward successfully connects

### 4. QUICK_START.md Option C - Controller + Fleet ✅

Validates full platform with registration tokens.

**Manual Validation:**

```bash
# Build all components
make build

# Start controller
cat > /tmp/controller-release-test.yaml <<EOF
storage:
  provider: git
  config:
    repository_path: /tmp/cfgms-release-storage
    branch: main
    auto_init: true

certificate:
  enable_cert_management: true
  auto_generate: true
  ca_path: /tmp/cfgms-release-certs/ca

logging:
  provider: file
  level: INFO
  file:
    directory: /tmp/cfgms-release-logs

transport:
  listen_addr: "127.0.0.1:4433"
  use_cert_manager: true
EOF

mkdir -p /tmp/cfgms-release-{storage,certs,logs}
./bin/controller -config /tmp/controller-release-test.yaml &
CONTROLLER_PID=$!
sleep 10

# Create registration token
TOKEN=$(curl -s -X POST http://localhost:9080/api/v1/admin/registration-tokens \
  -H "Content-Type: application/json" \
  -d '{"tenant_id":"default","group":"release-test","validity_days":1,"single_use":false}' \
  | jq -r '.token')

echo "Registration token: $TOKEN"

# Register steward (in separate terminal if needed)
# ./bin/cfgms-steward -regtoken $TOKEN

# Cleanup
kill $CONTROLLER_PID
rm -rf /tmp/cfgms-release-* /tmp/controller-release-test.yaml
```

**Exit Criteria:**

- [ ] Controller starts successfully
- [ ] Registration token created
- [ ] (Optional) Steward registers successfully

---

## Tier 3: High Availability Validation

### 5. HA Cluster Tests (Commercial Only) ✅

**For commercial builds only:**

```bash
cd test/integration/ha
go test -v -tags commercial -timeout 30m
```

**Tests Validated:**

- [ ] Leader election
- [ ] Failover scenarios
- [ ] Network partition handling
- [ ] Geographic distribution
- [ ] Configuration continuity
- [ ] Authentication workflows

**Exit Criteria:**

- [ ] All HA tests pass (25+ tests)
- [ ] Failover works within 10 seconds
- [ ] No data loss during failover

---

## Cross-Platform Build Validation

### 6. Platform Binary Compilation ✅

Validate that binaries compile for all supported platforms.

```bash
# Run cross-platform build validation
make build-cross-validate
```

**Platforms Validated:**

- [ ] Linux AMD64
- [ ] Linux ARM64
- [ ] Windows AMD64
- [ ] Windows ARM64
- [ ] macOS ARM64

**Exit Criteria:**

- [ ] All platform binaries compile successfully
- [ ] Binary sizes are reasonable (< 100MB per binary)
- [ ] No compilation warnings

---

## Configuration & Certificate Validation

### 7. Configuration File Validation ✅

```bash
cd test/integration
go test -v -run TestConfigValidation
```

**Tests Validated:**

- [ ] Valid YAML parsing
- [ ] Invalid YAML error handling
- [ ] Missing required fields detection
- [ ] Helpful error messages
- [ ] Environment variable substitution
- [ ] Tab vs space validation

**Exit Criteria:**

- [ ] All config validation tests pass
- [ ] Error messages are user-friendly

### 8. Certificate Registration Flow ✅

```bash
cd test/integration
go test -v -run TestCertificateRegistration
```

**Tests Validated:**

- [ ] Auto-approval in dev mode
- [ ] Manual approval workflow
- [ ] Certificate rotation
- [ ] Invalid token rejection
- [ ] Certificate expiry handling

**Exit Criteria:**

- [ ] All certificate tests pass
- [ ] Registration flow works end-to-end

---

## Service Infrastructure Validation

### 9. Wait-for-Services Tool ✅

Test the productized service readiness tool:

```bash
# Start test infrastructure
docker compose -f docker-compose.test.yml --profile database --profile timescale --profile git up -d

# Wait for services
./bin/cfgms-wait-for-services

# Verify output shows all services ready
# Should see: PostgreSQL ✅, TimescaleDB ✅, Gitea ✅

# Cleanup
docker compose -f docker-compose.test.yml down -v
```

**Exit Criteria:**

- [ ] Tool reports all services ready
- [ ] No false positives/negatives
- [ ] Helpful error messages on failure

---

## Documentation Validation

### 10. QUICK_START.md Accuracy ✅

Manually verify key documentation claims:

**Option A - Standalone Steward:**

- [ ] Step-by-step commands work exactly as written
- [ ] Expected output matches actual output
- [ ] No undocumented prerequisites

**Option B - Standalone Controller:**

- [ ] Controller.yaml configuration is complete
- [ ] Workflow example runs successfully
- [ ] All required directories documented

**Option C - Controller + Fleet:**

- [ ] Registration token creation works
- [ ] Steward CLI flags are correct
- [ ] gRPC-over-QUIC transport configuration complete

**Exit Criteria:**

- [ ] All three options validated
- [ ] No documentation/reality gaps

---

## Performance & Scale Validation

### 11. Performance Baselines ✅

Run performance tests to establish baselines:

```bash
cd test/performance
go test -v -bench=. -benchtime=10s
```

**Metrics to Record:**

- [ ] Configuration apply time (target: < 100ms for 100 resources)
- [ ] Transport message throughput (target: > 1000 msg/sec)
- [ ] Storage operation latency (target: < 50ms p99)
- [ ] Memory usage under load (target: < 500MB)

**Exit Criteria:**

- [ ] Performance within acceptable ranges
- [ ] No regressions vs previous release

---

## Security Validation

### 12. Security Scan Results ✅

Review security scan outputs:

```bash
make security-scan
```

**Required Checks:**

- [ ] Trivy: No critical/high vulnerabilities
- [ ] Nancy: No vulnerable dependencies
- [ ] gosec: No security patterns detected
- [ ] staticcheck: No critical issues
- [ ] No hardcoded secrets in codebase

**Exit Criteria:**

- [ ] All security scans pass
- [ ] Known issues documented in security log
- [ ] CVE report updated

---

## Final Release Checklist

### 13. Pre-Release Sign-Off ✅

Before tagging the release:

- [ ] All automated tests pass (Tier 1, 2, 3)
- [ ] Cross-platform builds successful
- [ ] Documentation validated
- [ ] Performance benchmarks recorded
- [ ] Security scans pass
- [ ] CHANGELOG.md updated
- [ ] Version bumped in version.go
- [ ] Migration guide created (if breaking changes)
- [ ] Roadmap updated (mark completed stories)

### 14. Release Artifacts ✅

After tagging (vX.Y.Z):

- [ ] GitHub release created
- [ ] Binaries attached to release (all platforms)
- [ ] Docker images pushed to registry
- [ ] Release notes published
- [ ] Documentation site updated
- [ ] Announcement prepared

### 15. Post-Release Validation ✅

Within 24 hours of release:

- [ ] Download and test release binaries
- [ ] Verify Docker images pull correctly
- [ ] Check documentation links work
- [ ] Monitor GitHub issues for user feedback
- [ ] Test upgrade path from previous version

---

## Validation Summary

**Total Checks:** 60+
**Estimated Time:** 30-45 minutes (automated) + 15 minutes (manual)
**Automation Coverage:** ~80%

### Quick Validation Command

Run all automated checks in one command:

```bash
# Complete pre-release validation
make test-commit && \
cd test/integration/standalone && go test -v && \
cd ../controller && go test -v && \
cd ../.. && make build-cross-validate

echo "✅ Release validation complete!"
```

---

## Troubleshooting

### Common Issues

**Tests fail with "permission denied":**

- Ensure Docker has sufficient permissions
- Check /var/log/cfgms directory permissions
- Verify user is in docker group

**Cross-platform builds fail:**

- Install required Go version (1.25+)
- Check CGO requirements for platform
- Verify GOOS/GOARCH combinations

**Service wait times out:**

- Check Docker Compose services are running
- Verify network connectivity
- Check service logs: `docker compose logs <service>`

---

## Version History

- **v1.0** (2025-12-16): Initial release validation checklist
  - Created for Story #252: Production-Realistic Testing Infrastructure
  - Covers all three QUICK_START.md deployment tiers
  - Includes Docker E2E testing validation
  - Cross-platform build validation
  - Security and performance checks

---

**Document Owner:** Engineering Team
**Last Updated:** 2025-12-16
**Next Review:** Before v0.7.5 release
