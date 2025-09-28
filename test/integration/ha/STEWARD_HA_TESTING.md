# Steward High Availability Integration Testing

## Overview

This document describes the comprehensive steward HA integration testing framework that validates real-world steward-to-controller failover behavior. This addresses the critical gap in HA testing where previous tests only validated controller-to-controller behavior without actual steward involvement.

## Critical Gap Addressed

### Previous State (Controller-Only Testing)
```
❌ No steward components in test environment
❌ Mock session testing (just health checks)
❌ No real gRPC stream validation
❌ No authentication persistence testing
❌ No configuration push continuity validation
❌ No workflow resilience testing
```

### New State (Real Steward HA Testing)
```
✅ 3 steward containers connecting to controller cluster
✅ Real gRPC session persistence testing
✅ Actual authentication state validation
✅ Configuration push continuity during failover
✅ Workflow execution resilience validation
✅ Steward reconnection timing validation (< 15 seconds)
```

## Test Infrastructure

### Docker Compose Enhancement
```yaml
# Added 3 steward services to docker-compose.ha-test.yml:
steward-east:    # IP: 172.21.1.30
steward-central: # IP: 172.21.1.31
steward-west:    # IP: 172.21.1.32

# Each steward configured with:
- HA-aware controller cluster connections
- Aggressive timing for fast failover testing
- Real authentication and TLS configuration
- Geographic distribution (east/central/west)
```

### New Test Files Created

**1. `steward_ha_test.go`** - Core steward HA behavior
- Real steward-to-controller failover testing
- gRPC session persistence validation
- Steward reconnection timing verification
- Authentication state maintenance testing

**2. `configuration_continuity_test.go`** - Configuration resilience
- Large configuration push surviving controller failover
- Multiple concurrent configuration pushes with failover
- Configuration rollback behavior during failover
- Configuration state consistency across stewards

**3. `authentication_workflow_test.go`** - Auth & workflow resilience
- Certificate validity during controller failover
- Token refresh resilience during failover
- Reconnection authentication flow testing
- Long-running workflow execution during failover
- Multiple workflow coordination during failover
- Workflow state recovery after failover

**4. `Dockerfile.steward`** - Steward container build
- Multi-stage build for optimized testing
- Health checks and proper user permissions
- Aggressive timing configuration support

## Real-World Scenarios Tested

### 1. Steward Connection Failover
```go
// Test sequence:
1. Steward establishes gRPC connection to controller leader
2. Controller leader fails/stops
3. Steward automatically detects failure
4. Steward reconnects to new controller leader
5. All gRPC streams are restored
6. Configuration state remains consistent

// Timing validation:
- Failover detection: < 5 seconds
- Reconnection completion: < 15 seconds
- Session restoration: < 20 seconds
```

### 2. Configuration Push Continuity
```go
// Test sequence:
1. Start large configuration push to stewards
2. Trigger controller failover during push
3. New leader takes over
4. Configuration push completes or is properly retried
5. All stewards have consistent configuration state

// Validated scenarios:
- Large configurations (100+ policies)
- Multiple concurrent pushes
- Configuration rollback during failover
```

### 3. Authentication Persistence
```go
// Test sequence:
1. Stewards authenticate with mTLS certificates
2. Controller failover occurs
3. Stewards maintain authentication with new leader
4. No re-authentication required
5. Certificate validity preserved

// Auth methods tested:
- mTLS certificate validation
- JWT token refresh during failover
- Connection count tracking
```

### 4. Workflow Execution Resilience
```go
// Test sequence:
1. Start long-running workflow on steward
2. Workflow reaches intermediate state
3. Controller failover occurs
4. Workflow either continues or is properly resumed
5. No data loss or corruption

// Workflow types tested:
- Long-running workflows (30+ seconds)
- Multi-step workflows with checkpoints
- Multiple concurrent workflows
```

## Testing Capabilities

### Enhanced Docker Helper
```go
// New helper functions for steward testing:
func (h *DockerComposeHelper) CheckStewardConnection(ctx, stewardName) (bool, string, error)
func (h *DockerComposeHelper) WaitForStewardConnections(ctx, timeout, stewards...) error
func (h *DockerComposeHelper) GetStewardLogs(ctx, stewardName, lines) (string, error)
```

### Mock vs Real Testing
```go
// Previous mock testing:
resp, err := http.Get(fmt.Sprintf("%s/api/v1/health", url))
// Just health checks - not real sessions!

// New real testing:
status, err := getStewardStatus(stewardName)
connected, controller, err := helper.CheckStewardConnection(ctx, stewardName)
// Real gRPC connections and state tracking
```

## Performance Validation

### Aggressive Timing for Local Testing
```bash
# Steward-specific timing (optimized for Docker):
CFGMS_HA_CONNECTION_RETRY_INTERVAL=2s    # vs 10s production
CFGMS_HA_CONNECTION_TIMEOUT=10s          # vs 30s production
CFGMS_HA_HEALTH_CHECK_INTERVAL=5s        # vs 15s production

# Expected steward failover performance:
- Failure detection: < 5 seconds
- Reconnection: < 15 seconds (vs < 60s production)
- Session restoration: < 20 seconds
```

### Real Performance Metrics
```go
// Actual timing measurements in tests:
failoverDuration := failoverComplete.Sub(failoverStart)
assert.Less(t, failoverDuration, 15*time.Second,
    "Steward failover took %v, should be < 15s in local Docker")
```

## Key Benefits

### 1. **Real-World Confidence**
- Tests actual steward-controller communication protocols
- Validates real gRPC stream behavior during failover
- Exercises actual authentication and TLS certificate handling
- Tests real configuration data flow during disruption

### 2. **Comprehensive Coverage**
- **Connection Resilience**: Steward reconnection behavior
- **Data Consistency**: Configuration state across failover
- **Authentication**: Certificate and token persistence
- **Workflow Continuity**: Long-running process resilience
- **Performance**: Timing validation under realistic conditions

### 3. **Development Workflow**
- Fast feedback loop (tests complete in 3-5 minutes)
- Practical for local development and CI/CD
- Identifies steward-specific HA issues early
- Validates end-to-end HA behavior

### 4. **Production Readiness**
- Proves steward HA works with real components
- Validates production failure scenarios
- Tests geographic distribution behavior
- Ensures zero-data-loss during failover

## Usage

### Running Steward HA Tests
```bash
# Run all steward HA tests
go test ./test/integration/ha/ -run "TestSteward" -v

# Run specific steward test scenarios
go test ./test/integration/ha/ -run "TestConfigurationContinuity" -v
go test ./test/integration/ha/ -run "TestAuthenticationPersistence" -v
go test ./test/integration/ha/ -run "TestWorkflowExecutionResilience" -v

# Start cluster manually for debugging
docker-compose -f docker-compose.ha-test.yml up -d --build

# Check steward connections
docker-compose -f docker-compose.ha-test.yml logs steward-east
```

### Test Execution Flow
```
1. Start 3 controllers + 3 stewards + git storage (6 components)
2. Wait for controller cluster formation (< 2 minutes)
3. Wait for steward connections (< 1 minute)
4. Execute steward-specific failover scenarios
5. Validate real gRPC session continuity
6. Test configuration push resilience
7. Verify authentication persistence
8. Validate workflow execution resilience
```

## Future Enhancements

### Planned Improvements
- **Network Latency Simulation**: Add realistic WAN latency between regions
- **Steward Load Testing**: Multiple stewards per region for scale testing
- **Certificate Rotation**: Test certificate renewal during failover
- **Module Execution**: Test actual module execution during failover
- **Performance Benchmarking**: Measure throughput during failover events

### Advanced Scenarios
- **Split-Brain with Stewards**: Steward behavior during network partitions
- **Cross-Region Failover**: Geographic steward failover preferences
- **Cascading Failures**: Multiple controller failures with steward recovery
- **State Synchronization**: Complex state consistency validation

---

This steward HA testing framework provides **real confidence** that the HA system works end-to-end, not just between controllers. It validates the complete steward-to-controller communication flow under failure conditions, ensuring production deployments will maintain steward connectivity and data consistency during controller failover events.