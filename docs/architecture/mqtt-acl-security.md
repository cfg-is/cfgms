# MQTT Broker ACL Security

## Overview

CFGMS implements topic-level access control lists (ACLs) in the MQTT broker to enforce multi-tenant isolation and prevent cross-tenant message eavesdropping. This security control was implemented in Story #313.

## Security Model

### Client Identity

Each steward connects to the MQTT broker with a unique client ID that matches their steward ID. This client ID is derived from:

1. **mTLS Certificate CN**: The certificate Common Name used during mTLS authentication
2. **Registration Process**: Assigned during steward registration with the controller

### ACL Enforcement

The MQTT broker enforces the following access control rule:

```
A client with ID {steward_id} can ONLY publish/subscribe to topics matching:
  cfgms/steward/{steward_id}/#
```

**Examples:**

✅ **Allowed:**
- Client `steward-123` subscribes to `cfgms/steward/steward-123/#`
- Client `steward-123` publishes to `cfgms/steward/steward-123/config`
- Client `steward-123` subscribes to `cfgms/steward/steward-123/dna`

❌ **Denied:**
- Client `steward-123` subscribes to `cfgms/steward/steward-456/#` (cross-tenant)
- Client `steward-123` publishes to `cfgms/controller/admin` (unauthorized topic)
- Client `steward-123` subscribes to `cfgms/steward/steward-1234/#` (prefix attack)

## Implementation

### ACL Handler Function

Located in: `features/controller/server/mqtt_acl.go`

The `stewardACLHandler` function:

1. Receives the client ID, topic, and operation (publish/subscribe)
2. Checks if the topic matches the pattern `cfgms/steward/{clientID}/#`
3. Returns `true` to allow access, `false` to deny

### Broker Configuration

The ACL handler is set during MQTT broker initialization in `features/controller/server/server.go`:

```go
// Configure ACL handler for multi-tenant topic isolation (Story #313)
broker.SetACLHandler(stewardACLHandler)
```

### Hook Integration

The mochi-mqtt broker uses the `OnACLCheck` hook (implemented in `pkg/mqtt/providers/mochi/auth.go`) which is called for every publish and subscribe operation before the operation is allowed.

## Testing

### Unit Tests

Location: `features/controller/server/mqtt_acl_test.go`

Tests cover:
- Allowed access to own topics
- Denied access to other steward topics
- Denied access to non-steward topics
- Edge cases (empty client ID, partial matches, wildcards)

### Integration Tests

Location: `test/integration/mqtt_quic/multi_tenant_test.go`

The test suite validates:
- **AC1**: Multiple tenants run simultaneously
- **AC2**: MQTT topic isolation between tenants
- **AC3**: Cross-tenant message delivery prevention (**PRIMARY TEST**)
- **AC4**: Configuration routing respects tenant boundaries
- **AC5**: DNA collection separated by tenant ID
- **AC6**: Heartbeat isolation per tenant

## Production Deployment

### Docker Configuration

The ACL configuration is automatically applied when the controller starts with MQTT enabled. No additional configuration is needed in `docker-compose.test.yml` or production deployments.

### Environment Variables

```bash
CFGMS_MQTT_ENABLED=true
CFGMS_MQTT_REQUIRE_CLIENT_CERT=true  # Required for client ID from certificate CN
```

### Security Best Practices

1. **Always enable mTLS**: `CFGMS_MQTT_REQUIRE_CLIENT_CERT=true`
2. **Use certificate-based client IDs**: Derive client ID from certificate CN
3. **Monitor ACL denials**: Log failed ACL checks for security auditing
4. **Test ACLs**: Run integration tests before deploying to production

## Topic Namespace Design

### Current Structure

```
cfgms/
├── steward/{steward_id}/
│   ├── config              # Configuration delivery
│   ├── dna                 # DNA collection
│   ├── heartbeat           # Heartbeat monitoring
│   ├── commands            # Command execution
│   └── results             # Command results
├── controller/
│   └── (reserved for future use)
└── admin/
    └── (reserved for future use)
```

### Future Enhancements

- Controller-to-steward broadcast topics (e.g., `cfgms/broadcast/all`)
- Role-based ACLs for admin users
- Group-level topic access (e.g., `cfgms/group/{group_id}/#`)

## Troubleshooting

### Symptom: Client cannot subscribe to own topics

**Possible causes:**
1. Client ID doesn't match steward ID
2. Topic pattern doesn't match `cfgms/steward/{client_id}/#`
3. mTLS not configured (client ID not derived from certificate)

**Solution:** Verify client ID matches the steward ID in the topic.

### Symptom: Cross-tenant messages being delivered

**Possible causes:**
1. ACL handler not configured (should never happen in production)
2. Test using incorrect client IDs

**Solution:** Verify ACL handler is set in broker initialization.

## Related Documentation

- [MQTT+QUIC Architecture](./mqtt-quic-architecture.md)
- [Multi-Tenant Security](./multi-tenant-security.md)
- [Certificate Management](../operations/certificate-management.md)
- [Testing Strategy](../testing/mqtt-quic-testing-strategy.md)

---

**Security Level**: Critical
**Implemented**: Story #313 (v0.8.1)
**Status**: Production-Ready
