# HA Integration Tests

This directory contains comprehensive integration tests for the High Availability (HA) infrastructure in CFGMS. These tests validate real-world cluster behavior with multiple controller instances running in Docker containers.

## Test Structure

### Core Test Files

**Controller HA Testing:**
- **`cluster_formation_test.go`** - Tests basic cluster formation and initial setup
- **`leader_election_test.go`** - Tests leader election behavior and timing requirements
- **`failover_test.go`** - Tests failover scenarios and session continuity
- **`network_partition_test.go`** - Tests network partition handling and split-brain prevention
- **`geographic_test.go`** - Tests geographic distribution and cross-region behavior

**Steward HA Testing:**
- **`steward_ha_test.go`** - Tests real steward-to-controller HA behavior with gRPC sessions
- **`configuration_continuity_test.go`** - Tests configuration push continuity during failover
- **`authentication_workflow_test.go`** - Tests authentication persistence and workflow resilience

### Helper Files

- **`docker_helper.go`** - Docker Compose management utilities
- **`README.md`** - This documentation file

## Docker Infrastructure

The tests use a complete Docker Compose setup defined in `docker-compose.ha-test.yml`:

### Services

**Controllers:**
- **controller-east** - US East region controller (port 8080)
- **controller-central** - US Central region controller (port 8081)
- **controller-west** - US West region controller (port 8082)

**Stewards:**
- **steward-east** - US East steward (connects to controller cluster)
- **steward-central** - US Central steward (connects to controller cluster)
- **steward-west** - US West steward (connects to controller cluster)

**Infrastructure:**
- **git-server-ha** - Shared Git storage backend (port 3002)
- **chaos-network** - Network simulation tools (optional)
- **test-runner** - Test orchestration container (optional)

### Network Configuration
- Custom bridge network (172.21.1.0/24) with fixed IP addresses
- Controllers: 172.21.1.20-22 (east, central, west)
- Stewards: 172.21.1.30-32 (east, central, west)
- Controllers configured for geographic distribution simulation
- Stewards configured with HA-aware connection management
- Shared Git repository for cluster state synchronization

## Running the Tests

### Prerequisites
- Docker and Docker Compose installed
- Go 1.21+ for running tests
- Make utility (optional, for convenience commands)

### Basic Test Execution

```bash
# Run all HA integration tests
go test ./test/integration/ha/... -v

# Run specific test suite
go test ./test/integration/ha/ -run TestClusterFormation -v

# Run with shorter timeout (excludes long-running tests)
go test ./test/integration/ha/... -short
```

### Docker Management

```bash
# Start the HA cluster manually
docker-compose -f docker-compose.ha-test.yml up -d --build

# View logs from specific controller
docker-compose -f docker-compose.ha-test.yml logs controller-east

# Stop and clean up
docker-compose -f docker-compose.ha-test.yml down -v --remove-orphans
```

## Test Categories

### 1. Cluster Formation Tests
- **Purpose**: Verify basic cluster startup and node discovery
- **Validates**:
  - All controllers start and become healthy
  - Exactly one leader is elected
  - All nodes have unique IDs
  - Geographic distribution is correct
  - Cluster consistency across all nodes

### 2. Leader Election Tests
- **Purpose**: Test leader election behavior and timing
- **Validates**:
  - Initial leader election completes within timeframe
  - Failover triggers new leader election
  - Only one leader exists at any time
  - Minimum quorum requirements work correctly
  - Election timing meets requirements (< 30 seconds)

### 3. Failover Tests
- **Purpose**: Test failover scenarios and session continuity
- **Validates**:
  - Failover completes within 30 seconds
  - Sessions remain valid during failover
  - Load balancer redirects traffic correctly
  - Request distribution continues after failover

### 4. Network Partition Tests
- **Purpose**: Test cluster behavior during network issues
- **Validates**:
  - Minority partition isolation
  - Split-brain prevention
  - Partition recovery
  - Rolling restart recovery
  - Cascading failure recovery

### 5. Geographic Distribution Tests
- **Purpose**: Test geographic awareness and cross-region behavior
- **Validates**:
  - Controllers distributed across regions
  - Latency-aware routing infrastructure
  - Geographic failover preferences
  - Cross-region communication
  - Regional affinity in load balancing
  - Distance calculations

### 6. Steward HA Tests
- **Purpose**: Test real steward-to-controller HA behavior
- **Validates**:
  - Steward connection failover to new controller leader
  - gRPC session persistence during controller failover
  - Real authentication state maintenance
  - Steward reconnection timing (< 15 seconds)

### 7. Configuration Continuity Tests
- **Purpose**: Test configuration push resilience during failover
- **Validates**:
  - Large configuration push surviving controller failover
  - Multiple concurrent configuration pushes with failover
  - Configuration rollback behavior during failover
  - Configuration state consistency across stewards

### 8. Authentication & Workflow Tests
- **Purpose**: Test authentication persistence and workflow resilience
- **Validates**:
  - Certificate validity during controller failover
  - Token refresh resilience during failover
  - Reconnection authentication flow
  - Long-running workflow execution during failover
  - Multiple workflow coordination during failover
  - Workflow state recovery after failover

## Test Configuration

### Environment Variables
The tests respect the following environment variables:

- `CFGMS_HA_TEST_TIMEOUT` - Overall test timeout (default: varies by test)
- `CFGMS_HA_TEST_SKIP_DOCKER` - Skip Docker-dependent tests
- `CFGMS_HA_TEST_KEEP_RUNNING` - Keep cluster running after tests (for debugging)

### Geographic Configuration
Controllers are configured with realistic US geographic distribution:

| Controller | Region | Zone | Location | Coordinates |
|------------|--------|------|----------|-------------|
| East | us-east | us-east-1a | Washington DC | 39.0458, -76.6413 |
| Central | us-central | us-central-1a | Chicago | 41.8781, -87.6298 |
| West | us-west | us-west-1a | San Francisco | 37.7749, -122.4194 |

## Aggressive Timing Configuration

The Docker test environment uses aggressive timing optimized for local testing:

| Parameter | Production Default | Docker Test Value | Speedup |
|-----------|-------------------|------------------|---------|
| Election Timeout | 10 seconds | 3 seconds | 3.3x faster |
| Heartbeat Interval | 2 seconds | 500ms | 4x faster |
| Health Check Interval | 1 second | 250ms | 4x faster |
| Leader Lease Duration | 15 seconds | 2 seconds | 7.5x faster |
| Docker Health Check | 5s interval | 2s interval | 2.5x faster |

### Benefits of Aggressive Timing
- **Faster Test Execution**: Tests complete in minutes instead of tens of minutes
- **Realistic Local Testing**: Network latency in Docker is ~1ms vs production's 10-100ms
- **Quick Feedback**: Developers get rapid feedback on HA behavior
- **CI/CD Friendly**: Integration tests run faster in automated pipelines

## Expected Behavior

### Cluster Formation
1. All 3 controllers start within 90 seconds
2. Leader election completes within 30 seconds of startup
3. All controllers report consistent cluster state
4. Geographic distribution is properly configured

### Failover Requirements (Local Docker)
- **Recovery Time**: < 10 seconds for leader failover (vs < 30s production)
- **Leader Election**: < 15 seconds (vs < 30s production)
- **Session Continuity**: Sessions remain valid across failover
- **Data Consistency**: No data loss during planned failover
- **Split-Brain Prevention**: Never more than 1 leader

### Network Resilience
- **Partition Tolerance**: Majority partition maintains operations
- **Recovery**: Full cluster recovery when partition heals
- **Detection**: Split-brain attempts are prevented
- **Cascading Failure**: Graceful degradation and recovery

## Troubleshooting

### Common Issues

**Tests Timeout**
- Increase Docker resources (memory/CPU)
- Check Docker Compose logs for startup issues
- Verify no port conflicts on test machine

**Cluster Formation Fails**
- Check Git server connectivity (port 3002)
- Verify Docker network configuration
- Review controller logs for authentication issues

**Inconsistent Test Results**
- Clean up previous test runs: `docker system prune -f`
- Check for resource contention on test machine
- Verify stable network connectivity

### Debug Commands

```bash
# Check all container status
docker-compose -f docker-compose.ha-test.yml ps

# Get detailed logs from failed controller
docker-compose -f docker-compose.ha-test.yml logs --tail=100 controller-east

# Inspect cluster network
docker network inspect cfgms-ha-test_ha-cluster

# Check Git server health
curl -f http://localhost:3002/api/healthz

# Manual health checks
curl -f http://localhost:8080/health  # East
curl -f http://localhost:8081/health  # Central
curl -f http://localhost:8082/health  # West
```

## Integration with CI/CD

These tests are designed to run in CI/CD environments:

### GitHub Actions Integration
```yaml
- name: Run HA Integration Tests
  run: |
    # Start services
    docker-compose -f docker-compose.ha-test.yml up -d --build

    # Wait for services
    sleep 60

    # Run tests
    go test ./test/integration/ha/... -v -timeout=5m

    # Cleanup
    docker-compose -f docker-compose.ha-test.yml down -v
```

### Resource Requirements
- **Memory**: 4GB+ available to Docker
- **CPU**: 4+ cores recommended
- **Disk**: 2GB+ free space
- **Network**: No port conflicts on 8080-8082, 3002

## Future Enhancements

### Planned Improvements
- Real network partition simulation using `tc` (traffic control)
- Performance benchmarking during failover
- Chaos engineering integration (random failures)
- Multi-data center simulation
- Security testing with certificate rotation

### Test Coverage Expansion
- Steward to Controller communication during HA events
- Configuration synchronization across regions
- Backup and restore procedures
- Monitoring and alerting validation
- Security audit trail during failover events

---

*For questions or issues with HA integration tests, see the main project documentation or create an issue in the GitHub repository.*