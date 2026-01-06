# MQTT+QUIC Test Execution Strategy

## Overview

MQTT+QUIC integration tests use different execution strategies for local development vs CI:

- **Local**: All tests execute (84% pass rate - 16/19 subtests)
- **CI**: Tests excluded via grep filter (functional bugs - Issue #294)

This document explains the rationale behind this strategy, how to run tests locally, and the roadmap for full CI integration.

---

## Local Test Execution

### Running Tests

```bash
# Full MQTT+QUIC test suite (requires Docker)
make test-mqtt-quic-setup  # Start infrastructure
make test-mqtt-quic        # Run all 14 test files

# Individual test suites
go test -v ./test/integration/mqtt_quic/tls_security_test.go
go test -v ./test/integration/mqtt_quic/registration_test.go
go test -v ./test/integration/mqtt_quic/mqtt_connectivity_test.go
go test -v ./test/integration/mqtt_quic/config_sync_test.go
go test -v ./test/integration/mqtt_quic/module_execution_test.go
go test -v ./test/integration/mqtt_quic/load_test.go
go test -v ./test/integration/mqtt_quic/config_signature_test.go
go test -v ./test/integration/mqtt_quic/heartbeat_failover_test.go
go test -v ./test/integration/mqtt_quic/multi_tenant_test.go
go test -v ./test/integration/mqtt_quic/quic_session_test.go
go test -v ./test/integration/mqtt_quic/dna_update_test.go
```

### Current Status

- **Passing**: 16/19 subtests (84%)
- **Failing**: 3/19 subtests
- **Issues**: Certificate loading, QUIC session infrastructure dependencies

### Test Infrastructure

The tests use Docker Compose to create a realistic environment:

- **Controller**: Runs in MQTT+QUIC mode
- **MQTT Broker**: Embedded in controller with TLS
- **Database**: TimescaleDB for state persistence
- **Certificates**: Auto-generated via `pkg/cert.Manager`

**Docker Services**:

```yaml
controller-standalone:
  - MQTT: localhost:1886 (TLS)
  - QUIC: localhost:4436 (UDP)
  - HTTP: localhost:8080
```

---

## CI Execution (GitHub Actions)

### Exclusion Pattern

Tests excluded in `.github/workflows/production-gates.yml` line 514:

```bash
# Skip MQTT+QUIC tests until Issue #294 (functional bugs in test suite)
go test -v -race -timeout=10m $(go list ./test/integration/... | grep -v mqtt_quic | grep -v "test/integration$")
```

**Why double grep?**

- First grep excludes `test/integration/mqtt_quic/` subdirectory
- Second grep excludes parent-level tests (`mqtt_quic_integration_test.go`, `mqtt_quic_flow_test.go`)

### Why Excluded

1. **Certificate Issues**: Some tests skip if certs unavailable (config_signature_test.go lines 377, 383, 436, 442)
2. **Infrastructure Dependencies**: QUIC tests require actual server (quic_session_test.go lines 257, 269)
3. **IPv6 Resolution**: Fixed in commit 78503bd (localhost → 127.0.0.1)
4. **Broker Restart**: Reconnection test requires broker restart (mqtt_connectivity_test.go line 385)
5. **Module Execution TODOs**: Load/apply config via API not yet implemented (module_execution_test.go lines 202, 334)

### Roadmap to Full CI

**Issue #294**: Complete E2E test framework for MQTT+QUIC mode (v0.8.1)

**Required Fixes**:

- [ ] Remove certificate-related skips (use auto-generation consistently)
- [ ] Add QUIC server infrastructure to docker-compose
- [ ] Resolve async timing issues in breach indicator tests
- [ ] Implement module configuration API integration
- [ ] Enable in production-gates.yml workflow

**Target Date**: v0.8.1 release

---

## Certificate Strategy (Hybrid Approach)

### Passing Tests → Auto-Generated Certificates ✅

Uses `pkg/cert.Manager` for security and Story #109 compliance:

```go
// Pattern from tls_security_test.go lines 48-114
func (s *TLSSecurityTestSuite) ensureCertificatesExist() {
    caCertPath := filepath.Join(s.certsPath, "ca-cert.pem")

    // Check if certificates already exist
    if _, err := os.Stat(caCertPath); err == nil {
        s.T().Log("Certificates already exist, skipping generation")
        return
    }

    // Generate using pkg/cert.Manager
    certManager, err := cert.NewManager(&cert.ManagerConfig{
        StoragePath: s.certsPath,
        CAConfig: &cert.CAConfig{
            Organization: "CFGMS Test CA",
            ValidityDays: 365,
            KeySize:      2048,
        },
        LoadExistingCA: false, // Create new CA for tests
    })

    certManager.GenerateServerCertificate(...)
    certManager.GenerateClientCertificate(...)
}
```

**Benefits**:

- ✅ Production-realistic (same code path as production)
- ✅ Self-contained (no manual certificate setup)
- ✅ Secure (prevents static test cert foot-guns)
- ✅ Story #109 compliant (auto-generation on first run)

### Negative Tests → Static Invalid Certificates ⚠️

Uses `scripts/generate-invalid-test-certs.sh` for:

- `expired-cert.pem` (TLS rejection test)
- `selfsigned-cert.pem` (CA validation test)
- `wrong-ca-cert.pem` (mTLS failure test)

**CRITICAL**: Static certs ONLY for tests that should FAIL

**Example Usage**:

```go
// Test that expired certificates are rejected
tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{expiredCert},
    RootCAs:      caCertPool,
}
client := mqtt.NewClient(opts)
token := client.Connect()
assert.Error(t, token.Error()) // Should fail with cert expired
```

---

## Developer Workflow

### Step-by-Step Local Testing

1. **Start Docker Infrastructure**:

   ```bash
   make test-mqtt-quic-setup
   ```

   Expected output:

   ```
   ✅ MQTT+QUIC Docker environment ready!
      MQTT: 127.0.0.1:1886 (TLS)
      QUIC: 127.0.0.1:4436
      HTTPS: 127.0.0.1:8080
   ```

2. **Run Tests**:

   ```bash
   make test-mqtt-quic
   ```

   Expected results:
   - 16/19 subtests passing (84%)
   - 3 subtests may skip or fail (expected until Issue #294)

3. **Debug Failures**:

   ```bash
   # View controller logs
   docker logs cfgms-controller-standalone

   # Check certificate generation
   docker exec cfgms-controller-standalone ls -la /app/certs/

   # Manual test execution with verbose output
   go test -v -race ./test/integration/mqtt_quic/tls_security_test.go
   ```

4. **Create PR**:
   - Tests will be excluded from CI (expected)
   - Reviewers understand local vs CI execution strategy
   - Issue #294 tracks full CI enablement

5. **Cleanup**:

   ```bash
   make test-mqtt-quic-cleanup
   ```

---

## FAQ

### Q: Why do tests pass locally but skip in CI?

**A**: Local tests validate functionality during development. CI exclusion prevents flaky/incomplete tests from blocking PRs while Issue #294 work is in progress.

This is a **temporary state** until the E2E framework is complete.

### Q: Should I fix MQTT+QUIC test failures locally?

**A**: Yes - investigate and report in Issue #294. Local failures may indicate real issues that need addressing.

If a test consistently fails locally:

1. Check Docker infrastructure is running (`docker ps`)
2. Verify certificates were generated (`ls test/integration/mqtt_quic/certs/`)
3. Review test logs for specific errors
4. Report findings in Issue #294 with reproduction steps

### Q: Can I use static test certificates in docker-compose?

**A**: ❌ **NO** - Use `CFGMS_MQTT_USE_CERT_MANAGER: "true"` for auto-generation.

Static certs violate the "No Foot-guns in Development" rule from CLAUDE.md:
> "Never build insecure options for convenience. If a feature requires durable storage in production, it MUST use durable storage in development and testing."

**Why this matters**:

- If docker-compose config is copied to production, static test certs bypass security
- Auto-generation uses the same code path as production (better testing)
- Prevents accidental test certificate exposure

### Q: When will MQTT+QUIC tests run in CI?

**A**: After Issue #294 (v0.8.1) completes E2E test framework work.

**Milestone**: v0.8.1 (Q1 2026)

**Tracking**: <https://github.com/cfg-is/cfgms/issues/294>

### Q: What's the difference between MQTT+QUIC mode and HTTP-only mode?

**A**: CFGMS supports two operational modes:

**MQTT+QUIC Mode** (Production Default):

- MQTT control plane for real-time commands, heartbeats, failover
- QUIC data plane for high-performance config/DNA synchronization
- Scales to 50k+ stewards
- Requires TLS/mTLS for security

**HTTP-only Mode** (Development/Simple Deployments):

- REST API only
- Simpler deployment (no MQTT broker)
- Limited scalability (< 1000 stewards)
- Suitable for testing and small deployments

Most integration tests use HTTP-only mode for simplicity. MQTT+QUIC tests validate the production-scale architecture.

### Q: How do I test certificate rejection (negative tests)?

**A**: Use the invalid certificate generation script:

```bash
# Generate intentionally-invalid certificates
./scripts/generate-invalid-test-certs.sh

# Use in tests to verify rejection
expired := loadCertificate("test/certs/expired-cert.pem")
client := connectWithCert(expired)
assert.Error(t, client.Connect()) // Should reject expired cert
```

**Available invalid certificates**:

- `expired-cert.pem` - Expired (past validity date)
- `selfsigned-cert.pem` - Self-signed (not from CA)
- `wrong-ca-cert.pem` - Signed by different CA

### Q: What happens if I forget to start Docker infrastructure?

**A**: Tests will fail with connection errors:

```
Error: dial tcp 127.0.0.1:1886: connect: connection refused
```

**Solution**: Run `make test-mqtt-quic-setup` before running tests.

---

## Test Suite Details

### 1. TLS Security Test Suite (`tls_security_test.go`)

**Purpose**: Validate TLS/mTLS certificate handling
**Coverage**:

- CA certificate generation
- Server certificate validation
- Client certificate validation (mTLS)
- Certificate expiration handling
- Invalid certificate rejection

**Key Tests**:

- `TestTLSCertificateGeneration` - Auto-generation via pkg/cert
- `TestMTLSConnection` - Mutual TLS handshake
- `TestInvalidCertificateRejection` - Security boundary testing

### 2. Registration Test Suite (`registration_test.go`)

**Purpose**: Validate steward registration flow
**Coverage**:

- Registration token generation
- Token validation
- Registration completion
- Duplicate registration prevention

### 3. MQTT Connectivity Test Suite (`mqtt_connectivity_test.go`)

**Purpose**: Validate MQTT broker connectivity
**Coverage**:

- TLS connection establishment
- Client authentication
- Topic subscription
- Message publishing/receiving

### 4. Config Sync Test Suite (`config_sync_test.go`)

**Purpose**: Validate configuration synchronization
**Coverage**:

- Configuration push to steward
- Synchronization status reporting
- Multi-tenant configuration isolation

### 5. Module Execution Test Suite (`module_execution_test.go`)

**Purpose**: Validate module execution through steward
**Coverage**:

- Module invocation via MQTT
- Result reporting
- Error handling
- Timeout management

### 6. Load Test Suite (`load_test.go`)

**Purpose**: Validate system performance under load
**Coverage**:

- 1000+ concurrent steward connections
- Message throughput measurement
- Resource utilization monitoring

### 7. Config Signature Test Suite (`config_signature_test.go`)

**Purpose**: Validate configuration signing and verification
**Coverage**:

- Signature generation
- Signature verification
- Tampered configuration detection

### 8. Heartbeat Failover Test Suite (`heartbeat_failover_test.go`)

**Purpose**: Validate failover detection
**Coverage**:

- Heartbeat transmission
- Missed heartbeat detection (<15s requirement)
- Failover triggering

### 9. Multi-Tenant Test Suite (`multi_tenant_test.go`)

**Purpose**: Validate tenant isolation
**Coverage**:

- Topic isolation between tenants
- Cross-tenant message prevention
- Configuration isolation

### 10. QUIC Session Test Suite (`quic_session_test.go`)

**Purpose**: Validate QUIC data plane
**Coverage**:

- QUIC connection establishment
- Stream management
- DNA transfer

### 11. DNA Update Test Suite (`dna_update_test.go`)

**Purpose**: Validate DNA (Desired Network Architecture) updates
**Coverage**:

- DNA push notifications
- Update application
- Version tracking

---

## Troubleshooting

### Tests Fail with "Certificate not found"

**Cause**: Auto-generation failed or certificates not in expected location

**Solution**:

```bash
# Check if certificates were generated
ls test/integration/mqtt_quic/certs/

# If missing, run test setup
make test-mqtt-quic-setup

# Check controller logs for cert generation
docker logs cfgms-controller-standalone | grep -i certificate
```

### Tests Fail with "Connection refused"

**Cause**: Docker infrastructure not running

**Solution**:

```bash
# Verify Docker services are running
docker ps | grep cfgms

# Restart infrastructure
make test-mqtt-quic-cleanup
make test-mqtt-quic-setup
```

### Tests Timeout

**Cause**: Slow container startup or resource constraints

**Solution**:

```bash
# Increase timeout in test (e.g., from 5s to 10s)
require.Eventually(t, func() bool {
    // test condition
}, 10*time.Second, 100*time.Millisecond)

# Check Docker resource limits
docker stats
```

### CI Skips Tests But They Pass Locally

**Cause**: This is expected behavior until Issue #294 is complete

**Solution**: No action needed. Tests are intentionally excluded from CI while E2E framework work is in progress.

---

## Related Documentation

- [Docker E2E Testing Guide](../integration/DOCKER_E2E_TESTING.md)
- [Multi-Tenant Testing Guide](../../test/integration/mqtt_quic/MULTI_TENANT_TESTING.md)
- [MQTT+QUIC Protocol Architecture](../architecture/mqtt-quic-protocol.md)
- [Testing Strategy Overview](testing-strategy.md)
- [Certificate Management](../../pkg/cert/README.md)

---

## Issue References

- **Issue #294**: Complete E2E test framework for MQTT+QUIC mode (v0.8.1)
- **Issue #297**: E2E Test Infrastructure Improvements (completed)
- **Story #109**: Self-contained tests with auto-generated certificates (completed)
- **Story #239**: Dual-CA fix with unified certificate manager (completed)

---

*Last Updated*: January 2026
*Version*: 1.0
*Maintainer*: CFGMS Development Team
