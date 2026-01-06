# Multi-Tenant Isolation Testing (Story 12.5)

## Overview

This test suite validates multi-tenant isolation in the CFGMS MQTT+QUIC architecture. It ensures that multiple tenants can run simultaneously with proper isolation of MQTT topics, configuration routing, DNA collection, and heartbeats.

## Acceptance Criteria

- **AC1**: Multiple tenants run simultaneously in Docker (3 minimum)
- **AC2**: MQTT topics enforce tenant isolation (cfgms/steward/tenant1/* vs tenant2/*)
- **AC3**: Cross-tenant message delivery prevention
- **AC4**: Configuration routing respects tenant boundaries
- **AC5**: DNA collection separated by tenant ID
- **AC6**: Heartbeats isolated per tenant

## Test Infrastructure

### Docker Compose Configuration

The `docker-compose.test.yml` file has been extended with three tenant-specific stewards:

```yaml
steward-tenant1:
  container_name: steward-tenant1
  environment:
    CFGMS_TENANT_ID: "tenant1"
    CFGMS_REGISTRATION_TOKEN: "cfgms_reg_tenant1"
    # TLS configuration...

steward-tenant2:
  container_name: steward-tenant2
  environment:
    CFGMS_TENANT_ID: "tenant2"
    CFGMS_REGISTRATION_TOKEN: "cfgms_reg_tenant2"
    # TLS configuration...

steward-tenant3:
  container_name: steward-tenant3
  environment:
    CFGMS_TENANT_ID: "tenant3"
    CFGMS_REGISTRATION_TOKEN: "cfgms_reg_tenant3"
    # TLS configuration...
```

All three tenant stewards:
- Connect to `controller-standalone` on port 9080
- Use TLS/mTLS for secure MQTT communication
- Have unique tenant IDs and registration tokens
- Share the same test workspace and certificate volumes

## Running the Tests

### Prerequisites

1. **Generate Test Certificates** (if not already done):
   ```bash
   make generate-test-certificates
   ```

2. **Start Docker Environment**:
   ```bash
   docker compose -f docker-compose.test.yml --profile ha up -d
   ```

3. **Verify Containers are Running**:
   ```bash
   docker ps | grep -E "steward-tenant|controller-standalone"
   ```

   You should see:
   - controller-standalone (running)
   - steward-tenant1 (running)
   - steward-tenant2 (running)
   - steward-tenant3 (running)

### Run Multi-Tenant Tests

```bash
# Run all multi-tenant tests
go test -v -run TestMultiTenant ./test/integration/mqtt_quic/

# Run specific acceptance criteria tests
go test -v -run TestMultiTenant/TestSimultaneousTenants ./test/integration/mqtt_quic/
go test -v -run TestMultiTenant/TestMQTTTopicIsolation ./test/integration/mqtt_quic/
go test -v -run TestMultiTenant/TestCrossTenantMessagePrevention ./test/integration/mqtt_quic/
go test -v -run TestMultiTenant/TestConfigurationRoutingBoundaries ./test/integration/mqtt_quic/
go test -v -run TestMultiTenant/TestDNACollectionSeparation ./test/integration/mqtt_quic/
go test -v -run TestMultiTenant/TestHeartbeatIsolation ./test/integration/mqtt_quic/
```

### Environment Variables

The tests use the following environment variables (with defaults):

- `CFGMS_TEST_HTTP_ADDR`: Controller HTTP address (default: `http://localhost:9080`)
- `CFGMS_TEST_MQTT_ADDR`: MQTT broker address (default: `ssl://localhost:1886`)
- `CFGMS_TEST_CERTS_PATH`: Path to test certificates (default: `./certs`)

Example with custom values:
```bash
CFGMS_TEST_HTTP_ADDR=http://localhost:9080 \
CFGMS_TEST_MQTT_ADDR=ssl://localhost:1886 \
CFGMS_TEST_CERTS_PATH=./test/integration/mqtt_quic/certs \
go test -v -run TestMultiTenant ./test/integration/mqtt_quic/
```

## Test Coverage

### AC1: Simultaneous Tenants (TestSimultaneousTenants)

- Registers 3 tenants concurrently using their unique tokens
- Validates all registrations succeed
- Verifies unique steward IDs are assigned

### AC2: MQTT Topic Isolation (TestMQTTTopicIsolation)

- Creates MQTT clients for tenant1 and tenant2
- Subscribes each tenant to its own topic pattern (cfgms/steward/tenant#/*)
- Publishes messages to tenant-specific topics
- Validates tenants only receive their own messages
- Confirms no cross-tenant message leakage

### AC3: Cross-Tenant Message Prevention (TestCrossTenantMessagePrevention)

- Tenant1 attempts to subscribe to tenant3's topic
- Tenant3 publishes a message
- Validates tenant1 does NOT receive tenant3's message
- Ensures MQTT broker enforces tenant boundaries

### AC4: Configuration Routing Boundaries (TestConfigurationRoutingBoundaries)

- Subscribes tenants to configuration topics
- Publishes tenant-specific configuration messages
- Validates each tenant only receives its own configuration
- Verifies configuration routing respects tenant boundaries

### AC5: DNA Collection Separation (TestDNACollectionSeparation)

- Simulates DNA collection from multiple tenants
- Publishes DNA updates with tenant-specific data
- Validates each tenant's DNA is properly isolated
- Ensures tenant_id separation in DNA updates

### AC6: Heartbeat Isolation (TestHeartbeatIsolation)

- Publishes heartbeat messages from different tenants
- Validates heartbeats are isolated per tenant
- Ensures no cross-tenant heartbeat visibility

## Expected Results

All tests should pass with the following output indicators:

```
✅ AC1 PASSED: 3 tenants running simultaneously
✅ AC2 PASSED: MQTT topic isolation enforced
✅ AC3 PASSED: Cross-tenant message delivery prevention enforced
✅ AC4 PASSED: Configuration routing respects tenant boundaries
✅ AC5 PASSED: DNA collection separated by tenant ID
✅ AC6 PASSED: Heartbeats isolated per tenant
```

## Troubleshooting

### Connection Refused Errors

If you see "connection refused" errors:
1. Verify Docker containers are running: `docker ps`
2. Check controller logs: `docker logs controller-standalone`
3. Ensure certificates are generated: `ls test/integration/mqtt_quic/certs/`

### Certificate Errors

If you see TLS/certificate errors:
1. Regenerate certificates: `make generate-test-certificates`
2. Restart Docker containers: `docker compose -f docker-compose.test.yml --profile ha restart`

### Test Timeouts

If tests timeout:
1. Increase timeout in test code (currently 3-5 seconds)
2. Check MQTT broker status in controller logs
3. Verify steward containers are healthy: `docker ps --filter health=healthy`

## Integration with CI/CD

These tests are designed to run in GitHub Actions with the HA profile:

```yaml
- name: Run Multi-Tenant Integration Tests
  run: |
    docker compose -f docker-compose.test.yml --profile ha up -d
    sleep 30  # Wait for services to be ready
    go test -v -run TestMultiTenant ./test/integration/mqtt_quic/
```

## Related Documentation

- [MQTT+QUIC Integration Testing](./README.md)
- [TLS/mTLS Security Validation](./TLS_SECURITY.md)
- [Module Execution Validation](./MODULE_EXECUTION.md)
- [Docker Compose Configuration](../../docker-compose.test.yml)

## Architecture Notes

### MQTT Topic Structure

Tenants are isolated using topic patterns:
- **Tenant 1**: `cfgms/steward/tenant1/<steward-id>/<message-type>`
- **Tenant 2**: `cfgms/steward/tenant2/<steward-id>/<message-type>`
- **Tenant 3**: `cfgms/steward/tenant3/<steward-id>/<message-type>`

The MQTT broker (mochi-mqtt) enforces ACLs based on tenant ID to prevent cross-tenant subscriptions and publications.

### Security Model

- **mTLS**: All MQTT connections use mutual TLS authentication
- **Topic ACLs**: Tenants can only subscribe/publish to their own topic namespace
- **Token-based Registration**: Each tenant has a unique registration token
- **Tenant ID Verification**: Controller validates tenant ID in all operations

## Success Criteria

For Story 12.5 to be considered complete:

1. ✅ All 6 acceptance criteria tests pass
2. ✅ No cross-tenant message leakage detected
3. ✅ Multi-tenant Docker configuration works correctly
4. ✅ Tests are documented and reproducible
5. ✅ CI/CD integration is successful
