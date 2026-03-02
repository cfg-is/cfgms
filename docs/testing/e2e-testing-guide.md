# CFGMS E2E Testing Guide

**Story #378**: Complete guide to end-to-end integration testing for MQTT+QUIC communication flows.

**Last Updated**: 2026-02-12
**CFGMS Version**: v0.9.x

## Overview

This guide covers the CFGMS E2E (End-to-End) testing framework that validates the complete production communication flow:

```
REST API → Controller → MQTT → Steward → QUIC → Controller → Module Execution → Status Report
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
│  │  - Publishes MQTT commands                     │  │
│  │  - Uploads configs via REST API                │  │
│  │  - Subscribes to status topics                 │  │
│  │  - Validates results                           │  │
│  └───────┬────────────────────────────────┬───────┘  │
│          │ REST API (8080)                │ MQTT     │
│          │                                │ (1886)   │
└──────────┼────────────────────────────────┼──────────┘
           │                                │
    ┌──────▼─────────────┐          ┌──────▼─────────┐
    │                    │  MQTT    │                │
    │    Controller      │◄────────►│  MQTT Broker   │
    │    (Docker)        │  1886    │    (Docker)    │
    │                    │          │                │
    │  - Config storage  │          │  - mochi-mqtt  │
    │  - Config signer   │          │  - TLS auth    │
    │  - QUIC server     │          └────────────────┘
    └──────────┬─────────┘                  ▲
               │ QUIC (4433)                │
               │                            │ MQTT
               │                            │ (1886)
        ┌──────▼────────────────────────────┴─────┐
        │                                         │
        │         Steward (Docker)                │
        │                                         │
        │  - MQTT client (receives commands)      │
        │  - QUIC client (fetches configs)        │
        │  - Config executor (runs modules)       │
        │  - Status publisher (reports results)   │
        └─────────────────────────────────────────┘
```

### Communication Flow Tested

1. **Config Upload** (Test → Controller REST API)
2. **MQTT Command** (Test → MQTT Broker → Steward)
3. **QUIC Connect** (Steward → Controller QUIC server)
4. **Config Fetch** (Steward ← Controller via QUIC stream)
5. **Signature Verify** (Steward validates controller's signature)
6. **Module Execute** (Steward runs file/directory/script modules)
7. **Status Report** (Steward → MQTT Broker → Test listener)

**Critical**: All phases must complete for E2E test to pass. If any phase fails, test times out.

## Test Types

### 1. Network Validation Tests

**Purpose**: Pre-flight checks before running E2E flow tests

**Location**: `test/integration/mqtt_quic/module_execution_test.go::TestE2ENetworkValidation`

**Validates**:
- MQTT broker connectivity
- Controller REST API reachability
- Steward container running
- Controller container running
- QUIC port accessibility (4433)
- Certificate availability

**Run**:
```bash
cd test/integration/mqtt_quic
go test -v -run TestE2ENetworkValidation
```

**Expected Output**:
```
📡 MQTT broker: Reachable
🌐 Controller REST API: Reachable
🐳 Steward container: Running
🐳 Controller container: Running
🔐 QUIC endpoint (4433): Accessible
🔐 Certificates: Available
🎉 Network Validation Complete
```

**When to Run**:
- First time setting up E2E test environment
- After infrastructure changes
- Debugging connectivity issues

### 2. E2E Flow Diagnostic Test

**Purpose**: Validates each phase of the MQTT+QUIC E2E flow independently

**Location**: `test/integration/mqtt_quic/module_execution_test.go::TestE2EFlowDiagnostic`

**Validates (8 Phases)**:
1. MQTT Connectivity
2. REST API Connectivity
3. Config Upload
4. Config Status Subscription
5. QUIC Connection Command Delivery
6. Config Sync Command Delivery
7. Config Status Report Reception
8. Module Execution

**Run**:
```bash
cd test/integration/mqtt_quic
go test -v -run TestE2EFlowDiagnostic
```

**Expected Output**:
```
📡 Phase 1 PASS: MQTT connection established
🌐 Phase 2 PASS: REST API accessible
📤 Phase 3 PASS: Configuration uploaded
📬 Phase 4 PASS: Subscribed to config status
🔗 Phase 5 PASS: QUIC connection command published
🔄 Phase 6 PASS: Config sync command published
📥 Phase 7 PASS: Status report received
⚙️  Phase 8 PASS: Module executed and file created
🎉 ALL PHASES PASSED
```

**Failure Analysis**:
- If Phase 1-4 fail: Infrastructure/setup issue
- If Phase 5-6 fail: MQTT command delivery issue
- If Phase 7 fails: QUIC/signature/executor issue (was Story #378 root cause)
- If Phase 8 fails: Module execution issue

**When to Run**:
- Debugging E2E test failures
- Validating infrastructure changes
- Performance regression investigation

### 3. Config Status Reporting Test

**Purpose**: Validates full E2E config distribution and status reporting

**Location**: `test/integration/mqtt_quic/module_execution_test.go::TestConfigStatusReporting`

**Validates**:
- Config upload via REST API
- MQTT command delivery (connect_quic, sync_config)
- QUIC config fetch with signature verification
- File and directory module execution
- Status report delivery with accurate data
- File/directory actually created (not just status)

**Run**:
```bash
cd test/integration/mqtt_quic
go test -v -run TestConfigStatusReporting
```

**Expected Timing**: < 10 seconds (typically 2-8 seconds)

**Success Criteria**:
- Status report received within timeout
- Overall status = "OK"
- Module status shows successful execution
- Files/directories verified to exist in container

### 4. Module Failure Reporting Test

**Purpose**: Validates error path and failure reporting

**Location**: `test/integration/mqtt_quic/module_execution_test.go::TestModuleFailureReporting`

**Validates**:
- Intentional module failures are detected
- Error status reported correctly
- Partial success handled (some modules fail, others succeed)
- Error messages included in status reports

**Run**:
```bash
cd test/integration/mqtt_quic
go test -v -run TestModuleFailureReporting
```

**Expected**: Status report with ERROR status and detailed error information

### 5. Additional Module Tests

**Location**: `test/integration/mqtt_quic/module_execution_test.go`

**Tests**:
- `TestFileModuleExecution`: File creation validation
- `TestDirectoryModuleExecution`: Directory creation validation
- `TestScriptModuleExecution`: Script execution validation
- `TestIdempotency`: Config applied twice = same result
- `TestMultipleModulesExecution`: Multiple modules in one config
- `TestFilePermissionVariations`: Permission settings validation
- `TestDirectoryPermissionVariations`: Directory permission validation

**Note**: These use manual `docker exec` for module execution, not full MQTT+QUIC flow.

## Running E2E Tests

### Prerequisites

```bash
# Docker and Docker Compose running
docker --version
docker compose version

# CFGMS repository and binaries built
make build

# Infrastructure containers running
docker compose up -d controller mqtt-broker steward-standalone
```

### Run All E2E Tests

```bash
cd test/integration/mqtt_quic
go test -v

# Expected output:
# PASS: TestE2ENetworkValidation
# PASS: TestE2EFlowDiagnostic
# PASS: TestConfigStatusReporting
# PASS: TestModuleFailureReporting
# PASS: TestFileModuleExecution
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

# Run quickly (fails if infrastructure slow)
go test -v -timeout 5m
```

### Run in CI Mode

```bash
# CI environments may need more conservative timeouts
# Tests use environment detection or can be configured:
CFGMS_E2E_MODE=ci go test -v
```

## Writing New E2E Tests

### Test Template

```go
func (s *ModuleExecutionTestSuite) TestYourFeature() {
    containerName := "steward-standalone"

    // 1. Setup: Get steward ID
    stewardID, err := s.helper.GetStewardIDFromContainer(s.T(), containerName)
    s.NoError(err)

    // 2. Upload configuration
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

    // 3. Subscribe to status
    statusReceived := make(chan *ConfigStatusMessage, 1)
    s.helper.SubscribeToConfigStatus(s.T(), stewardID, func(msg *ConfigStatusMessage) {
        statusReceived <- msg
    })

    // 4. Trigger sync via MQTT commands
    // (connect_quic + sync_config pattern - see TestConfigStatusReporting)

    // 5. Wait for status report
    select {
    case msg := <-statusReceived:
        // Validate status message
        s.Equal("OK", msg.Status)

    case <-time.After(30 * time.Second):
        s.T().Fatal("Timeout waiting for status")
    }

    // 6. Verify actual execution (not just status)
    // Use helper functions: CheckFileInContainer, CheckDirectoryInContainer

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
- ❌ Use manual file creation for primary validation
- ❌ Mock CFGMS components
- ❌ Hardcode timeouts (use timeout config)
- ❌ Skip cleanup (can cause test pollution)
- ❌ Test only happy path (test failures too)

### Helper Functions

**ModuleTestHelper** provides:

```go
// Network operations
ConnectMQTT(t, clientID, tlsConfig)
DisconnectMQTT(t)

// Configuration management
SendConfiguration(t, stewardID, config)
SubscribeToConfigStatus(t, stewardID, callback)

// Steward operations
GetStewardIDFromContainer(t, containerName)

// File validation
CheckFileInContainer(t, containerName, path)
CheckDirectoryInContainer(t, containerName, path)
CleanupTestFiles(t, containerName, paths...)

// Module execution (legacy - prefer MQTT+QUIC flow)
CreateFileInContainerUsingModule(t, containerName, path, content, perms)
CreateDirectoryInContainerUsingModule(t, containerName, path, perms)
```

## Debugging Failed Tests

### Step 1: Identify Failure Point

Run diagnostic test to see which phase fails:

```bash
go test -v -run TestE2EFlowDiagnostic
```

Output shows exactly which phase failed (1-8).

### Step 2: Check Logs

```bash
# Controller logs
docker logs controller | tail -50

# Steward logs
docker logs steward-standalone | tail -50

# MQTT broker logs
docker logs mqtt-broker | tail -50
```

### Step 3: Verify Infrastructure

```bash
# Run network validation
go test -v -run TestE2ENetworkValidation

# Check container status
docker ps

# Check port bindings
docker ps --format "table {{.Names}}\t{{.Ports}}"
```

### Step 4: Test Individual Components

```bash
# Test MQTT broker
mosquitto_pub -h localhost -p 1883 -t "test/topic" -m "test"

# Test REST API
curl -k https://localhost:8080/health

# Test QUIC port (from within steward)
docker exec steward-standalone nc -zv controller-standalone 4433
```

### Common Failure Patterns

**"Timeout waiting for config status"** (Story #378 signature issue):
- Check: Certificate serial matching (signer vs registration)
- Check: Signature verification in steward logs
- Check: QUIC connection established
- Fix: Ensure Story #378 fix applied

**"MQTT connection timeout"**:
- Check: MQTT broker running
- Check: Port 1886 accessible
- Check: TLS certificates valid
- Fix: Restart mqtt-broker, verify TLS config

**"Config upload failed"**:
- Check: Controller REST API responding
- Check: Storage backend initialized
- Check: Disk space available
- Fix: Check controller logs for storage errors

**"Module execution failed"**:
- Check: Module is registered
- Check: Workspace mounted correctly
- Check: Permissions for file/directory operations
- Fix: Verify module implementation, check steward logs

## CI/CD Integration

### GitHub Actions

E2E tests run in GitHub Actions via `test-suite-validation.yml`:

```yaml
- name: Run E2E Tests
  run: |
    docker compose up -d controller mqtt-broker steward-standalone
    sleep 15  # Wait for initialization
    cd test/integration/mqtt_quic
    go test -v -timeout 30m
```

**Timing**:
- Local: 10-15 minutes (full suite)
- CI: 15-20 minutes (due to Docker overhead)

**Required Checks** (branch protection):
- `unit-tests`: Fast validation
- `Build Gate`: Includes E2E tests
- `security-deployment-gate`: Security validation

### Test Reliability

**Current Status** (after Story #378 fix):
- ✅ 100% pass rate locally
- ✅ 100% pass rate in CI
- ✅ No flaky tests
- ✅ No timeouts (completes in < 10s per test)

**Monitoring**:
- Track test duration trends
- Alert on timeouts or failures
- Performance regression detection

## Performance Baselines

### Expected Timings (Local)

| Test | Target | Acceptable | Warning |
|------|--------|------------|---------|
| Network Validation | < 5s | < 10s | > 10s |
| Flow Diagnostic | < 10s | < 30s | > 30s |
| Config Status Reporting | < 5s | < 10s | > 10s |
| Module Failure Reporting | < 5s | < 10s | > 10s |

### Performance Tracking

Tests now log timing for each phase:
```
Phase 7 PASS: Status report received (2.60s)
```

Monitor these timings for performance regressions.

## Troubleshooting Guide

See also: [docs/troubleshooting/connectivity.md](../troubleshooting/connectivity.md)

### Quick Debug Checklist

- [ ] All containers running: `docker ps`
- [ ] No port conflicts: `sudo lsof -i :8080,:4433,:1886`
- [ ] Logs show no errors: `docker compose logs`
- [ ] Network validation passes
- [ ] Diagnostic test identifies exact failure point
- [ ] Sufficient disk space: `df -h`
- [ ] Docker daemon healthy: `docker info`

### Getting Help

If E2E tests fail:

1. Run `TestE2EFlowDiagnostic` - shows exact failure phase
2. Run `TestE2ENetworkValidation` - validates infrastructure
3. Collect logs: `docker compose logs > /tmp/cfgms-logs.txt`
4. Create GitHub issue with:
   - Test output
   - Diagnostic test results
   - Container logs
   - Environment details (OS, Docker version)

## References

- **MQTT+QUIC Strategy**: [mqtt-quic-testing-strategy.md](mqtt-quic-testing-strategy.md)
- **Home Lab Guide**: [docs/deployment/home-lab-deployment-guide.md](../deployment/home-lab-deployment-guide.md)
- **Troubleshooting**: [docs/troubleshooting/connectivity.md](../troubleshooting/connectivity.md)
- **Story #378**: Root cause analysis and fix for signature verification issue
