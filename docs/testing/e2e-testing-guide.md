# CFGMS E2E Testing Guide

**Last Updated**: 2026-03-25 (updated for gRPC-over-QUIC transport, Phase 10.12)
**CFGMS Version**: v0.9.x+

## Overview

This guide covers the CFGMS E2E (End-to-End) testing framework that validates the complete
production communication flow over the unified gRPC-over-QUIC transport:

```
REST API → Controller → gRPC control plane → Steward → gRPC data plane → Module Execution → Status Report
```

All E2E tests use **real components** (no mocks) running in Docker containers to ensure production-like validation.

## Table of Contents

1. [Architecture](#architecture)
2. [Test Types](#test-types)
3. [Running E2E Tests](#running-e2e-tests)
4. [Writing New E2E Tests](#writing-new-e2e-tests)
5. [Debugging Failed Tests](#debugging-failed-tests)
6. [CI/CD Integration](#cicd-integration)

## Architecture

### Test Environment

E2E tests use Docker Compose to create a complete CFGMS environment:

```
┌──────────────────────────────────────────────────────┐
│              Test Host (Go test process)              │
│                                                       │
│  ┌────────────────────────────────────────────────┐  │
│  │  E2E Test Runner                               │  │
│  │  - Uploads configs via REST API                │  │
│  │  - Sends gRPC commands via control plane       │  │
│  │  - Subscribes to status events                 │  │
│  │  - Validates results                           │  │
│  └───────┬───────────────────────────────────────-┘  │
│          │ REST API (9080)                            │
└──────────┼────────────────────────────────────────────┘
           │
    ┌──────▼─────────────────────────────────────────┐
    │                                                 │
    │           Controller (Docker)                   │
    │                                                 │
    │  - Config storage (git)                         │
    │  - Config signer                                │
    │  - gRPC-over-QUIC transport server (:4433)      │
    │    ├── ControlPlaneService (heartbeats, cmds)   │
    │    └── DataPlaneService (cfg sync, DNA sync)    │
    └──────────────────┬──────────────────────────────┘
                       │ gRPC-over-QUIC (4433/UDP)
                       │
        ┌──────────────▼──────────────────────────────┐
        │                                             │
        │         Steward (Docker)                    │
        │                                             │
        │  - gRPC transport client                    │
        │  - Config executor (runs modules)           │
        │  - Status publisher (reports results)       │
        └─────────────────────────────────────────────┘
```

### Communication Flow Tested

1. **Config Upload** (Test → Controller REST API)
2. **gRPC Command** (Controller ControlPlane → Steward: SyncConfig)
3. **Config Fetch** (Steward DataPlane → Controller: GetConfig)
4. **Signature Verify** (Steward validates controller's config signature)
5. **Module Execute** (Steward runs file/directory/script modules)
6. **Status Report** (Steward ControlPlane → Controller: ReportStatus → Test listener)

**Critical**: All phases must complete for E2E test to pass. If any phase fails, test times out.

## Test Types

### 1. Network Validation Tests

**Purpose**: Pre-flight checks before running E2E flow tests

**Location**: `test/integration/transport/tls_security_test.go` and related

**Validates**:
- Controller REST API reachability
- Transport port accessibility (4433/UDP)
- Certificate availability
- Steward container running
- Controller container running

**Run**:
```bash
cd test/integration/transport
go test -v -run TestE2ENetworkValidation
```

**Expected Output**:
```
🌐 Controller REST API: Reachable
🐳 Steward container: Running
🐳 Controller container: Running
🔐 Transport endpoint (4433): Accessible
🔐 Certificates: Available
🎉 Network Validation Complete
```

### 2. E2E Flow Diagnostic Test

**Purpose**: Validates each phase of the gRPC-over-QUIC E2E flow independently

**Location**: `test/integration/transport/`

**Validates (6 Phases)**:
1. REST API Connectivity
2. Config Upload
3. Transport Connection
4. Config Sync Command Delivery (gRPC control plane)
5. Config Status Report Reception (gRPC data plane)
6. Module Execution

**Run**:
```bash
cd test/integration/transport
go test -v -run TestE2EFlowDiagnostic
```

**Expected Output**:
```
🌐 Phase 1 PASS: REST API accessible
📤 Phase 2 PASS: Configuration uploaded
🔗 Phase 3 PASS: Transport connection established
🔄 Phase 4 PASS: Config sync command delivered
📥 Phase 5 PASS: Status report received
⚙️  Phase 6 PASS: Module executed and file created
🎉 ALL PHASES PASSED
```

**Failure Analysis**:
- If Phase 1–2 fail: Infrastructure/setup issue
- If Phase 3 fails: Transport (QUIC/TLS) connectivity issue
- If Phase 4–5 fail: gRPC service issue (stream broken, signature mismatch)
- If Phase 6 fails: Module execution issue

### 3. Config Status Reporting Test

**Purpose**: Validates full E2E config distribution and status reporting

**Location**: `test/integration/transport/`

**Validates**:
- Config upload via REST API
- gRPC SyncConfig command delivery
- Config fetch with signature verification
- File and directory module execution
- Status report delivery with accurate data

**Run**:
```bash
cd test/integration/transport
go test -v -run TestConfigStatusReporting
```

**Expected Timing**: < 10 seconds (typically 2–8 seconds)

### 4. Multi-Tenant Isolation Test

**Purpose**: Validates tenant isolation over gRPC transport

**Location**: `test/integration/transport/multi_tenant_test.go`

**Validates**:
- Each steward only receives its own configs
- Cross-tenant command delivery is rejected at gRPC layer
- Certificate identity enforces tenant boundaries

**Run**:
```bash
cd test/integration/transport
go test -v -run TestMultiTenant
```

### 5. TLS Security Test Suite

**Purpose**: Validates mTLS certificate handling for the gRPC-over-QUIC transport

**Location**: `test/integration/transport/tls_security_test.go`

**Validates**:
- CA certificate auto-generation
- Server certificate validation
- Client certificate validation (mTLS)
- Certificate expiration rejection
- Invalid certificate rejection
- Self-signed certificate rejection (non-CA-issued)

**Run**:
```bash
cd test/integration/transport
go test -v -run TestTLS
```

### 6. Additional Module Tests

**Location**: `test/integration/transport/`

**Tests**:
- `TestFileModuleExecution`: File creation validation
- `TestDirectoryModuleExecution`: Directory creation validation
- `TestScriptModuleExecution`: Script execution validation
- `TestIdempotency`: Config applied twice = same result
- `TestMultipleModulesExecution`: Multiple modules in one config

## Running E2E Tests

### Prerequisites

```bash
# Docker and Docker Compose running
docker --version
docker compose version

# CFGMS repository and binaries built
make build

# Infrastructure containers running (no separate broker needed)
docker compose up -d controller steward-standalone
```

### Run All E2E Tests

```bash
cd test/integration/transport
go test -v

# Expected output:
# PASS: TestE2ENetworkValidation
# PASS: TestE2EFlowDiagnostic
# PASS: TestConfigStatusReporting
# PASS: TestMultiTenantIsolation
# PASS: TestTLSSecurity
# ... (additional module tests)
```

### Run Specific Test

```bash
# Run single test by name
go test -v -run TestE2EFlowDiagnostic

# Run tests matching pattern
go test -v -run "TestConfig.*"  # All config-related tests
```

### Run with Timeout Adjustment

```bash
# Increase timeout for slow environments (CI)
go test -v -timeout 30m

# Run with shorter timeout (fails fast if infrastructure is slow)
go test -v -timeout 5m
```

### Run in CI Mode

```bash
# CI environments use container-to-container networking
CFGMS_E2E_MODE=ci go test -v
```

## Writing New E2E Tests

### Test Template

```go
func (s *TransportTestSuite) TestYourFeature() {
    containerName := "steward-standalone"

    // 1. Setup: Get steward ID
    stewardID, err := s.helper.GetStewardIDFromContainer(s.T(), containerName)
    s.NoError(err)

    // 2. Upload configuration via REST API
    testConfig := map[string]any{
        "steward": map[string]any{
            "id":   stewardID,
            "mode": "controller",
        },
        "resources": []map[string]any{
            // Your test resources
        },
    }
    err = s.helper.SendConfiguration(s.T(), stewardID, testConfig)
    s.NoError(err)

    // 3. Subscribe to status updates (gRPC control plane)
    statusReceived := make(chan *StatusReport, 1)
    s.helper.SubscribeToStatus(s.T(), stewardID, func(msg *StatusReport) {
        statusReceived <- msg
    })

    // 4. Trigger sync via gRPC command
    err = s.helper.SendSyncCommand(s.T(), stewardID)
    s.NoError(err)

    // 5. Wait for status report
    select {
    case msg := <-statusReceived:
        s.Equal("OK", msg.Status)

    case <-time.After(30 * time.Second):
        s.T().Fatal("Timeout waiting for status")
    }

    // 6. Verify actual execution (not just status)
    s.helper.CheckFileInContainer(s.T(), containerName, "/test-workspace/yourfile")

    // 7. Cleanup
    s.helper.CleanupTestFiles(s.T(), containerName, "/test-workspace/yourfile")
}
```

### Best Practices

**DO**:
- ✅ Use real components (no mocks)
- ✅ Test actual execution, not just status
- ✅ Clean up test files after each test
- ✅ Use configurable timeouts
- ✅ Validate all phases of the flow
- ✅ Add diagnostic logging for debugging

**DON'T**:
- ❌ Mock CFGMS components
- ❌ Hardcode timeouts (use timeout config)
- ❌ Skip cleanup (can cause test pollution)
- ❌ Test only happy path (test failures too)
- ❌ Depend on previous transport — it has been removed

## Debugging Failed Tests

### Step 1: Identify Failure Point

Run diagnostic test to see which phase fails:

```bash
go test -v -run TestE2EFlowDiagnostic
```

Output shows exactly which phase failed (1–6).

### Step 2: Check Logs

```bash
# Controller logs
docker logs controller | tail -50

# Steward logs
docker logs steward-standalone | tail -50

# Look for transport/gRPC errors specifically:
docker logs controller | grep -i "transport\|grpc\|stream\|error"
docker logs steward-standalone | grep -i "transport\|grpc\|stream\|error"
```

### Step 3: Verify Infrastructure

```bash
# Run network validation
go test -v -run TestE2ENetworkValidation

# Check container status
docker ps

# Check transport port (UDP)
sudo ss -ulnp | grep 4433
```

### Step 4: Test Individual Components

```bash
# Test REST API
curl http://controller:9080/api/v1/health

# Test transport port reachability (UDP)
# Note: nc -zu is unreliable for QUIC; check controller logs instead
docker logs controller | grep "Transport server listening"
```

### Common Failure Patterns

**"Timeout waiting for status report"**:
- Check: Transport connection established (Phase 3)
- Check: gRPC SyncConfig command delivered (Phase 4)
- Check: Signature verification in steward logs
- Check: Steward is connected (heartbeat visible in controller logs)

**"Transport connection failed"**:
- Check: Port 4433/UDP is accessible
- Check: TLS certificates valid and CA fingerprints match
- Check: Firewall allows UDP traffic on 4433

**"Config upload failed"**:
- Check: Controller REST API responding
- Check: Storage backend initialized
- Check: Disk space available
- Fix: Check controller logs for storage errors

**"gRPC stream broken"**:
- Check: Keepalive configuration (increase `keepalive_period` if streams reset)
- Check: Network stability (UDP packet loss causes QUIC connection failure)
- Check: NAT/firewall UDP timeout (some firewalls close UDP flows after 30s)

## CI/CD Integration

### GitHub Actions

E2E tests run in GitHub Actions via the Build Gate workflow:

```yaml
- name: Run Transport E2E Tests
  run: |
    docker compose up -d controller steward-standalone
    sleep 15  # Wait for initialization
    cd test/integration/transport
    go test -v -timeout 30m
```

**Timing**:
- Local: 10–15 minutes (full suite)
- CI: 15–20 minutes (due to Docker overhead)

**Required Checks** (branch protection):
- `unit-tests`: Fast validation
- `Build Gate`: Includes transport E2E tests
- `security-deployment-gate`: Security validation

### Test Reliability

**Current Status**:
- ✅ 100% pass rate locally
- ✅ 100% pass rate in CI
- ✅ No flaky tests
- ✅ No external broker dependency

## Performance Baselines

### Expected Timings (Local)

| Test | Target | Acceptable | Warning |
|------|--------|------------|---------|
| Network Validation | < 5s | < 10s | > 10s |
| Flow Diagnostic | < 10s | < 30s | > 30s |
| Config Status Reporting | < 5s | < 10s | > 10s |
| Multi-Tenant Isolation | < 10s | < 30s | > 30s |

## References

- **Transport Architecture**: [docs/architecture/communication-layer-migration.md](../architecture/communication-layer-migration.md)
- **Deployment Guide**: [docs/deployment/README.md](../deployment/README.md)
- **Troubleshooting**: [docs/troubleshooting/connectivity.md](../troubleshooting/connectivity.md)
