# CFGMS REST API Documentation

The CFGMS controller provides a REST API for external system integration and management operations. The API runs alongside the gRPC services and provides HTTP endpoints for common operations.

## Base URL

By default, the REST API listens on port 9080. In production the server uses TLS when a certificate manager is configured:

```
https://controller.example.com:9080/api/v1
```

In development (no cert manager, or self-signed cert), use `curl -k` to skip certificate verification:

```bash
curl -k https://localhost:9080/api/v1/health
```

Override the listen address with `CFGMS_HTTP_LISTEN_ADDR` (default: `0.0.0.0:9080`).

## Authentication

All API endpoints (except `/api/v1/health`, `/api/v1/register`, and `/api/v1/webhooks/git-push`) require authentication via API key. The `cfg` CLI authenticates using an mTLS admin bundle (see [mTLS Authentication](#mtls-authentication-admin-bundle) below). Raw API keys are supported for machine-to-machine use cases.

API keys can be provided in two ways:

### X-API-Key Header

```bash
curl -k -H "X-API-Key: your-api-key" https://localhost:9080/api/v1/stewards
```

### Authorization Bearer Token

```bash
curl -k -H "Authorization: Bearer your-api-key" https://localhost:9080/api/v1/stewards
```

### Permission Scopes

Each endpoint requires a specific permission scope. Scopes follow the format `resource:action`. A key must hold the exact permission listed in each endpoint's **Required permission** field. The permission is checked by the `requirePermission(scope, action)` middleware registered in `server.go setupRouter()`.

## Response Format

All API responses follow a standard format:

### Success Response

```json
{
  "data": { ... },
  "timestamp": "2025-01-12T10:30:00Z"
}
```

### Error Response

```json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human readable error message",
    "details": "Optional additional details"
  },
  "timestamp": "2025-01-12T10:30:00Z"
}
```

## Endpoints

### Health Check

#### GET /api/v1/health

Check the health status of the CFGMS controller.

**Authentication:** None required

**Response:**

```json
{
  "data": {
    "status": "healthy",
    "version": "0.2.0",
    "timestamp": "2025-01-12T10:30:00Z",
    "services": {
      "controller": "healthy",
      "configuration": "healthy",
      "rbac": "healthy",
      "certificate_manager": "healthy",
      "tenant_manager": "healthy",
      "rbac_manager": "healthy"
    }
  },
  "timestamp": "2025-01-12T10:30:00Z"
}
```

### Steward Self-Registration

#### POST /api/v1/register

Steward-initiated self-registration. Called by the steward agent on first boot. Uses a pre-issued registration token instead of an API key. The token encodes the target tenant, group membership, and controller URL.

**Authentication:** None required (registration token in request body)

**Request Body:**

```json
{
  "token": "reg-token-value",
  "steward_id": "server-001",
  "hostname": "server-001.example.com"
}
```

**Response:** Returns controller URL, issued mTLS certificate, and tenant assignment.

### Steward Management

All steward management endpoints require an API key. The `cfg steward list/status` CLI (Epic #1501) wraps these endpoints.

#### GET /api/v1/stewards

List all registered stewards.

**Authentication:** Required  
**Required permission:** `steward:list`

**Response:**

```json
{
  "data": [
    {
      "id": "steward-001",
      "status": "connected",
      "last_seen": "2025-01-12T10:29:30Z",
      "version": "0.2.0",
      "metrics": {
        "cpu_usage": "45%",
        "memory_usage": "512MB"
      },
      "dna": {
        "hostname": "server-001",
        "os": "linux",
        "architecture": "x86_64",
        "attributes": {
          "hostname": "server-001",
          "os": "linux",
          "architecture": "x86_64",
          "kernel_version": "5.4.0"
        },
        "collected_at": "2025-01-12T10:25:00Z"
      }
    }
  ],
  "timestamp": "2025-01-12T10:30:00Z"
}
```

#### GET /api/v1/stewards/{id}

Get information about a specific steward, including connection state and active sessions from the connection registry.

**Authentication:** Required  
**Required permission:** `steward:read`

**Parameters:**

- `id` (path): Steward ID

**Response:**

```json
{
  "data": {
    "id": "steward-001",
    "status": "connected",
    "last_seen": "2025-01-12T10:29:30Z",
    "version": "0.2.0",
    "connection_state": "active",
    "active_sessions": 2,
    "metrics": {
      "cpu_usage": "45%",
      "memory_usage": "512MB"
    },
    "dna": {
      "hostname": "server-001",
      "os": "linux",
      "architecture": "x86_64",
      "attributes": {
        "hostname": "server-001",
        "os": "linux",
        "architecture": "x86_64"
      },
      "collected_at": "2025-01-12T10:25:00Z"
    }
  },
  "timestamp": "2025-01-12T10:30:00Z"
}
```

#### GET /api/v1/stewards/{id}/dna

Get DNA information for a specific steward.

**Authentication:** Required  
**Required permission:** `steward:read-dna`

**Parameters:**

- `id` (path): Steward ID

**Response:**

```json
{
  "data": {
    "hostname": "server-001",
    "os": "linux",
    "architecture": "x86_64",
    "attributes": {
      "hostname": "server-001",
      "os": "linux",
      "architecture": "x86_64",
      "kernel_version": "5.4.0",
      "memory_total": "8GB"
    },
    "collected_at": "2025-01-12T10:25:00Z"
  },
  "timestamp": "2025-01-12T10:30:00Z"
}
```

#### POST /api/v1/stewards/{id}/auth/refresh

Refresh the mTLS credentials for a steward. Called when the steward's certificate approaches expiry.

**Authentication:** Required  
**Required permission:** `steward:auth-refresh`

**Parameters:**

- `id` (path): Steward ID

### Configuration Management

#### GET /api/v1/stewards/{id}/config

Get configuration for a specific steward.

**Authentication:** Required  
**Required permission:** `steward:read-config`

**Parameters:**

- `id` (path): Steward ID
- `modules` (query, optional): Comma-separated list of module names to filter

**Response:**

```json
{
  "data": {
    "steward_id": "steward-001",
    "version": "1.0.0",
    "config": {
      "directory": {
        "/etc/app": {
          "owner": "app",
          "group": "app",
          "mode": "755"
        }
      },
      "file": {
        "/etc/app/config.yml": {
          "content": "key: value",
          "owner": "app",
          "group": "app",
          "mode": "644"
        }
      }
    },
    "updated_at": "2025-01-12T10:30:00Z"
  },
  "timestamp": "2025-01-12T10:30:00Z"
}
```

#### PUT /api/v1/stewards/{id}/config

Update configuration for a specific steward.

**Authentication:** Required  
**Required permission:** `steward:write-config`

**Parameters:**

- `id` (path): Steward ID

**Request Body:** Same structure as the GET response `data` field.

#### GET /api/v1/stewards/{id}/config/effective

Get the effective (merged/inherited) configuration for a specific steward, resolving tenant hierarchy inheritance.

**Authentication:** Required  
**Required permission:** `steward:read-config`

**Parameters:**

- `id` (path): Steward ID

#### POST /api/v1/stewards/{id}/config/validate

Validate configuration for a steward without applying it.

**Authentication:** Required  
**Required permission:** `steward:validate-config`

**Parameters:**

- `id` (path): Steward ID

**Request Body:**

```json
{
  "config": {
    "directory": {
      "/etc/app": {
        "owner": "app",
        "group": "app",
        "mode": "755"
      }
    }
  },
  "version": "1.0.0"
}
```

**Response:**

```json
{
  "data": {
    "valid": true,
    "errors": [],
    "metadata": {
      "validation_time": "50ms",
      "modules_validated": "2"
    }
  },
  "timestamp": "2025-01-12T10:30:00Z"
}
```

#### POST /api/v1/config/push

Trigger an immediate fan-out of a configuration version to all currently active stewards. Returns `202 Accepted` immediately; delivery is fire-and-forget in a background goroutine. The leader node returns `503 Service Unavailable` for follower nodes in an HA cluster.

**Authentication:** Required  
**Required permission:** `config:push`

**Request Body:**

```json
{
  "config_id": "cfg-001",
  "version": "1.2.3",
  "tenant_id": "default"
}
```

**Response (202 Accepted):**

```json
{
  "data": {
    "push_id": "push-1705051800000000000",
    "status": "accepted",
    "queued_at": "2025-01-12T10:30:00Z"
  },
  "timestamp": "2025-01-12T10:30:00Z"
}
```

> **[GAP: save=deploy auto-distribution not yet wired to ConfigStore]** The push endpoint fans out `CommandSyncConfig` to active stewards but does not write through the ConfigStore. Once Epic #1501 lands, save=deploy will automatically trigger distribution on config write, making explicit pushes unnecessary for most workflows.

### Script Management

Script execution endpoints let operators inspect and retry steward-side script runs.

#### GET /api/v1/stewards/{id}/scripts/executions

List script executions for a steward.

**Authentication:** Required  
**Required permission:** `steward:read-scripts`

**Parameters:**

- `id` (path): Steward ID

#### GET /api/v1/stewards/{id}/scripts/executions/{execution_id}

Get details of a specific script execution.

**Authentication:** Required  
**Required permission:** `steward:read-scripts`

**Parameters:**

- `id` (path): Steward ID
- `execution_id` (path): Execution ID

#### POST /api/v1/stewards/{id}/scripts/executions/{execution_id}/retry

Retry a failed script execution.

**Authentication:** Required  
**Required permission:** `steward:execute-scripts`

**Parameters:**

- `id` (path): Steward ID
- `execution_id` (path): Execution ID

#### GET /api/v1/stewards/{id}/scripts/metrics

Get script execution metrics for a steward (aggregated counts, success/failure rates).

**Authentication:** Required  
**Required permission:** `steward:read-scripts`

**Parameters:**

- `id` (path): Steward ID

#### GET /api/v1/stewards/{id}/scripts/status

Get the current script execution status for a steward.

**Authentication:** Required  
**Required permission:** `steward:read-scripts`

**Parameters:**

- `id` (path): Steward ID

### Certificate Management

#### GET /api/v1/certificates

List certificates.

**Authentication:** Required  
**Required permission:** `certificate:list`

**Parameters:**

- `steward_id` (query, optional): Filter certificates by steward ID

**Response:**

```json
{
  "data": [
    {
      "serial_number": "123456789",
      "common_name": "steward-001",
      "steward_id": "steward-001",
      "is_valid": true,
      "expires_at": "2026-01-12T10:30:00Z",
      "days_until_expiration": 365,
      "needs_renewal": false
    }
  ],
  "timestamp": "2025-01-12T10:30:00Z"
}
```

#### POST /api/v1/certificates/provision

Provision a new certificate for a steward.

**Authentication:** Required  
**Required permission:** `certificate:provision`

**Request Body:**

```json
{
  "steward_id": "steward-001",
  "common_name": "steward-001.example.com",
  "organization": "Example Org",
  "validity_days": 365
}
```

**Response:**

```json
{
  "data": {
    "certificate_pem": "-----BEGIN CERTIFICATE-----\n...",
    "private_key_pem": "-----BEGIN PRIVATE KEY-----\n...",
    "ca_certificate_pem": "-----BEGIN CERTIFICATE-----\n...",
    "serial_number": "123456789",
    "expires_at": "2026-01-12T10:30:00Z"
  },
  "timestamp": "2025-01-12T10:30:00Z"
}
```

### RBAC Management

#### GET /api/v1/rbac/permissions

List available permissions.

**Authentication:** Required  
**Required permission:** `rbac:list-permissions`

**Parameters:**

- `resource_type` (query, optional): Filter permissions by resource type

**Response:**

```json
{
  "data": [
    {
      "id": "steward.register",
      "name": "Register Steward",
      "description": "Allow steward registration",
      "resource_type": "steward",
      "actions": ["create", "read"]
    }
  ],
  "timestamp": "2025-01-12T10:30:00Z"
}
```

#### GET /api/v1/rbac/permissions/{id}

Get a specific permission by ID.

**Authentication:** Required  
**Required permission:** `rbac:read-permission`

**Parameters:**

- `id` (path): Permission ID

#### GET /api/v1/rbac/roles

List roles.

**Authentication:** Required  
**Required permission:** `rbac:list-roles`

**Parameters:**

- `tenant_id` (query, optional): Filter roles by tenant ID

**Response:**

```json
{
  "data": [
    {
      "id": "admin",
      "name": "Administrator",
      "description": "Full administrative access",
      "permissions": ["steward.register", "config.manage"],
      "tenant_id": "default",
      "created_at": "2025-01-01T00:00:00Z",
      "updated_at": "2025-01-01T00:00:00Z"
    }
  ],
  "timestamp": "2025-01-12T10:30:00Z"
}
```

#### POST /api/v1/rbac/roles

Create a new role.

**Authentication:** Required  
**Required permission:** `rbac:create-role`

**Request Body:**

```json
{
  "name": "Config Manager",
  "description": "Manage configurations",
  "permissions": ["config.read", "config.write"],
  "tenant_id": "default"
}
```

**Response:**

```json
{
  "data": {
    "id": "config-manager",
    "name": "Config Manager",
    "description": "Manage configurations",
    "permissions": ["config.read", "config.write"],
    "tenant_id": "default",
    "created_at": "2025-01-12T10:30:00Z",
    "updated_at": "2025-01-12T10:30:00Z"
  },
  "timestamp": "2025-01-12T10:30:00Z"
}
```

#### GET /api/v1/rbac/roles/{id}

Get a specific role by ID.

**Authentication:** Required  
**Required permission:** `rbac:read-role`

**Parameters:**

- `id` (path): Role ID

#### PUT /api/v1/rbac/roles/{id}

Update an existing role.

**Authentication:** Required  
**Required permission:** `rbac:update-role`

**Parameters:**

- `id` (path): Role ID

**Request Body:** Same structure as POST /api/v1/rbac/roles.

#### DELETE /api/v1/rbac/roles/{id}

Delete a role.

**Authentication:** Required  
**Required permission:** `rbac:delete-role`

**Parameters:**

- `id` (path): Role ID

### API Key Management

#### GET /api/v1/api-keys

List API keys.

**Authentication:** Required  
**Required permission:** `api-key:list`

**Response:**

```json
{
  "data": [
    {
      "id": "key-001",
      "name": "Default Admin Key",
      "permissions": ["stewards:read", "stewards:write"],
      "created_at": "2025-01-12T10:00:00Z",
      "expires_at": null,
      "tenant_id": "default"
    }
  ],
  "timestamp": "2025-01-12T10:30:00Z"
}
```

#### POST /api/v1/api-keys

Create a new API key.

**Authentication:** Required  
**Required permission:** `api-key:create`

**Request Body:**

```json
{
  "name": "Monitoring Key",
  "permissions": ["stewards:read", "health:read"],
  "expires_at": "2026-01-12T10:30:00Z",
  "tenant_id": "default"
}
```

**Response:**

```json
{
  "data": {
    "id": "key-002",
    "name": "Monitoring Key",
    "permissions": ["stewards:read", "health:read"],
    "created_at": "2025-01-12T10:30:00Z",
    "expires_at": "2026-01-12T10:30:00Z",
    "tenant_id": "default",
    "key": "base64-encoded-api-key-here"
  },
  "timestamp": "2025-01-12T10:30:00Z"
}
```

**Note:** The actual API key is only returned upon creation. Store it securely as it cannot be retrieved later.

#### GET /api/v1/api-keys/{id}

Get a specific API key (metadata only — the key value is not returned after creation).

**Authentication:** Required  
**Required permission:** `api-key:read`

**Parameters:**

- `id` (path): API key ID

#### DELETE /api/v1/api-keys/{id}

Delete an API key. The key is immediately invalidated.

**Authentication:** Required  
**Required permission:** `api-key:delete`

**Parameters:**

- `id` (path): API key ID

### Registration Token Management

Registration tokens authorise steward self-registration. The token encodes the target tenant and is consumed by `POST /api/v1/register`.

**Note:** The path is `/api/v1/registration/tokens` — NOT `/admin/registration-tokens`.

#### GET /api/v1/registration/tokens

List registration tokens.

**Authentication:** Required  
**Required permission:** `registration:list-tokens`

#### POST /api/v1/registration/tokens

Create a new registration token.

**Authentication:** Required  
**Required permission:** `registration:create-token`

#### GET /api/v1/registration/tokens/{token}

Get a specific registration token's metadata.

**Authentication:** Required  
**Required permission:** `registration:read-token`

**Parameters:**

- `token` (path): Registration token value

#### DELETE /api/v1/registration/tokens/{token}

Delete a registration token.

**Authentication:** Required  
**Required permission:** `registration:delete-token`

**Parameters:**

- `token` (path): Registration token value

#### POST /api/v1/registration/tokens/{token}/revoke

Revoke a registration token without deleting it. A revoked token remains in the store but is rejected on use.

**Authentication:** Required  
**Required permission:** `registration:revoke-token`

**Parameters:**

- `token` (path): Registration token value

### Monitoring

CFGMS provides monitoring capabilities through dedicated endpoints.

#### GET /api/v1/monitoring/health

System health overview including service status and resource utilisation.

**Authentication:** Required  
**Required permission:** `monitoring:read-health`

**Response:**

```json
{
  "data": {
    "status": "healthy",
    "timestamp": "2025-01-12T10:30:00Z",
    "services": {
      "controller": "healthy",
      "configuration_service": "healthy",
      "monitoring_service": "healthy"
    },
    "resource_usage": {
      "cpu_percent": 25.5,
      "memory_bytes": 134217728,
      "goroutines": 156
    },
    "uptime_seconds": 86400
  },
  "timestamp": "2025-01-12T10:30:00Z"
}
```

#### GET /api/v1/monitoring/metrics

System performance metrics.

**Authentication:** Required  
**Required permission:** `monitoring:read-metrics`

**Response:**

```json
{
  "data": {
    "timestamp": "2025-01-12T10:30:00Z",
    "system": {
      "cpu_percent": 25.5,
      "memory_bytes": 134217728,
      "disk_usage_bytes": 1073741824,
      "goroutines": 156,
      "gc_cycles": 42,
      "heap_objects": 125000
    },
    "application": {
      "stewards_connected": 45,
      "configurations_served": 150,
      "api_requests_total": 1250,
      "grpc_requests_total": 3500,
      "errors_total": 5
    }
  },
  "timestamp": "2025-01-12T10:30:00Z"
}
```

#### GET /api/v1/monitoring/config

Current monitoring system configuration and exporter status.

**Authentication:** Required  
**Required permission:** `monitoring:read-config`

**Response:**

```json
{
  "data": {
    "enabled": true,
    "collection_interval": "30s",
    "retention_period": "7d",
    "exporters": {
      "prometheus": {
        "enabled": true,
        "endpoint": "http://prometheus:9090/api/v1/write",
        "status": "active"
      },
      "otlp": {
        "enabled": false,
        "endpoint": "http://jaeger:14268/api/traces"
      }
    }
  },
  "timestamp": "2025-01-12T10:30:00Z"
}
```

#### GET /api/v1/monitoring/anomalies

Platform-detected anomalies.

**Authentication:** Required  
**Required permission:** `monitoring:read-anomalies`

#### GET /api/v1/monitoring/components/{component}/health

Health status for a specific component.

**Authentication:** Required  
**Required permission:** `monitoring:read-component-health`

**Parameters:**

- `component` (path): Component name (e.g., `controller`, `storage`)

#### GET /api/v1/monitoring/components/{component}/metrics

Metrics for a specific component.

**Authentication:** Required  
**Required permission:** `monitoring:read-component-metrics`

**Parameters:**

- `component` (path): Component name

### High Availability

HA endpoints expose cluster topology and leadership state. These are only meaningful in multi-node deployments; single-node OSS deployments always report as leader.

#### GET /api/v1/ha/status

Overall HA cluster status.

**Authentication:** Required  
**Required permission:** `ha:read-status`

#### GET /api/v1/ha/cluster

Full cluster topology.

**Authentication:** Required  
**Required permission:** `ha:read-cluster`

#### GET /api/v1/ha/leader

Current leader identity.

**Authentication:** Required  
**Required permission:** `ha:read-leader`

#### GET /api/v1/ha/nodes

List of all cluster nodes and their state.

**Authentication:** Required  
**Required permission:** `ha:read-nodes`

#### GET /api/v1/raft/status

Raft consensus state for the local node (operational/debugging endpoint).

**Authentication:** Required  
**Required permission:** `ha:read-status`

### Compliance

#### GET /api/v1/stewards/{id}/compliance

Compliance status for a specific steward.

**Authentication:** Required  
**Required permission:** `steward:read-compliance`

**Parameters:**

- `id` (path): Steward ID

#### GET /api/v1/stewards/{id}/compliance/report

Full compliance report for a specific steward.

**Authentication:** Required  
**Required permission:** `steward:read-compliance`

**Parameters:**

- `id` (path): Steward ID

#### GET /api/v1/compliance/summary

Fleet-wide compliance summary across all stewards.

**Authentication:** Required  
**Required permission:** `compliance:read-summary`

### Tenants

#### POST /api/v1/tenants/{id}/config-source/test

Test connectivity to a tenant's config source (e.g., validate git repository access credentials before saving them).

**Authentication:** Required  
**Required permission:** `tenant:manage`

**Parameters:**

- `id` (path): Tenant ID

### Webhooks

#### POST /api/v1/webhooks/git-push

Receive a git push event from an upstream SCM and trigger a config sync. Registered lazily when a git-sync handler is configured via `SetGitSyncWebhookHandler()`.

**Authentication:** HMAC-SHA256 signature validation (no API key). The signature is checked by the webhook handler, not the standard auth middleware.

**Headers:**

- `X-Hub-Signature-256`: HMAC-SHA256 of the request body using the configured webhook secret.

### Rollback Management

Rollback endpoints are registered only when a `RollbackManager` is wired in (`SetRollbackManager()`). They are available in all deployments that include the rollback feature.

#### GET /api/v1/rollback/points

List available rollback points.

**Authentication:** Required

**Parameters:**

- `target_type` (query, optional): Filter by target type
- `target_id` (query, optional): Filter by target ID
- `limit` (query, optional): Maximum results to return

#### POST /api/v1/rollback/preview

Preview the effect of a rollback before executing it.

**Authentication:** Required

#### POST /api/v1/rollback/execute

Execute a rollback to a specific point.

**Authentication:** Required

#### GET /api/v1/rollback/{rollback_id}/status

Get the status of a running or completed rollback operation.

**Authentication:** Required

**Parameters:**

- `rollback_id` (path): Rollback operation ID

#### POST /api/v1/rollback/{rollback_id}/cancel

Cancel a rollback operation in progress.

**Authentication:** Required

**Parameters:**

- `rollback_id` (path): Rollback operation ID

#### GET /api/v1/rollback/history

List rollback operation history.

**Authentication:** Required

### Reports Engine

Reports endpoints are registered only when a `ReportsHandler` is wired in (`SetReportsHandler()`).

#### POST /api/v1/reports/generate

Generate a report on demand.

**Authentication:** Required

#### GET /api/v1/reports/templates

List available report templates.

**Authentication:** Required

#### GET /api/v1/reports/templates/{template}

Get a specific report template.

**Authentication:** Required

#### GET /api/v1/reports/dashboard/overview

Dashboard overview report.

**Authentication:** Required

#### GET /api/v1/reports/dashboard/trends

Dashboard trend data.

**Authentication:** Required

#### GET /api/v1/reports/dashboard/alerts

Dashboard alert summary.

**Authentication:** Required

#### GET /api/v1/reports/compliance/status

Compliance status report.

**Authentication:** Required

#### GET /api/v1/reports/drift/summary

Configuration drift summary report.

**Authentication:** Required

### Workflow Engine

Workflow endpoints are registered only when a `WorkflowHandler` is wired in (`SetWorkflowHandler()`).

> **[GAP: workflow/trigger route registration]** The workflow handler's `RegisterTriggerRoutes` is called with a subrouter already scoped to `/api/v1/triggers`, but the trigger API's `RegisterRoutes` adds `/triggers` as an additional prefix, producing `/api/v1/triggers/triggers/...` paths. The trigger routes are currently unreachable at their intended paths. See follow-up issue for the code fix.

#### GET /api/v1/workflows

List workflows.

**Authentication:** Required (inherits api subrouter auth middleware)

#### POST /api/v1/workflows

Create a workflow.

**Authentication:** Required

#### GET /api/v1/workflows/{id}

Get a workflow by ID.

**Authentication:** Required

#### PUT /api/v1/workflows/{id}

Update a workflow.

**Authentication:** Required

#### DELETE /api/v1/workflows/{id}

Delete a workflow.

**Authentication:** Required

#### POST /api/v1/workflows/{id}/execute

Execute a workflow immediately.

**Authentication:** Required

#### GET /api/v1/workflows/{id}/executions

List execution history for a workflow.

**Authentication:** Required

### Internal Endpoints (not for external use)

#### POST /raft/message

Internal Raft consensus message endpoint. mTLS peer CN verification is enforced inside the handler. Not accessible via the external API — intentionally omits API-key auth middleware.

## Internal Test Endpoint (not for external use)

`PUT /api/v1/test/stewards/{id}/config` is registered without authentication for integration test use only. It must not be reachable in production deployments. The endpoint is gated by the absence of normal auth middleware and is documented here only to note its existence in the route table.

## Error Codes

| Code | Description |
|------|-------------|
| `MISSING_API_KEY` | API key not provided |
| `INVALID_API_KEY` | API key is invalid |
| `EXPIRED_API_KEY` | API key has expired |
| `MISSING_STEWARD_ID` | Steward ID parameter is required |
| `STEWARD_NOT_FOUND` | Steward with given ID not found |
| `INVALID_JSON` | Request body contains invalid JSON |
| `SERVICE_UNAVAILABLE` | Required service is not available |
| `INTERNAL_ERROR` | Internal server error |
| `NOT_IMPLEMENTED` | Feature not yet implemented |

## Getting Started

1. **Start the controller:**

   ```bash
   ./bin/controller
   ```

2. **Check health (dev mode — self-signed cert):**

   ```bash
   curl -k https://localhost:9080/api/v1/health
   ```

3. **List stewards:**

   ```bash
   curl -k -H "X-API-Key: your-api-key" https://localhost:9080/api/v1/stewards
   ```

## mTLS Authentication (admin bundle)

The `cfg` CLI authenticates to the controller REST API using a mutual TLS (mTLS) admin
bundle file. The bundle contains the client certificate, client private key, CA certificate,
and the controller URL — everything needed for a full mTLS handshake.

### Bundle file location

The `cfg` CLI walks the following lookup chain in order and uses the first bundle it finds:

| Priority | Source |
|----------|--------|
| 1 (highest) | `--bundle <path>` CLI flag |
| 2 | `CFGMS_ADMIN_BUNDLE` environment variable (non-empty) |
| 3 | `$XDG_CONFIG_HOME/cfgms/admin.bundle.yaml` (Linux/macOS: `~/.config/cfgms/admin.bundle.yaml`) |
| 4 (lowest) | `/etc/cfgms/admin.bundle.yaml` (Linux/macOS) · `%ProgramData%\cfgms\admin.bundle.yaml` (Windows) |

### Bundle YAML schema

The bundle file (`admin.bundle.yaml`) is a YAML document with the following fields,
as defined in `pkg/cert/bundle`:

```yaml
cert_pem: |
  -----BEGIN CERTIFICATE-----
  ...
  -----END CERTIFICATE-----
key_pem: |
  -----BEGIN EC PRIVATE KEY-----
  ...
  -----END EC PRIVATE KEY-----
ca_pem: |
  -----BEGIN CERTIFICATE-----
  ...
  -----END CERTIFICATE-----
controller_url: "https://controller.example.com:9443"
audit_subject: "admin:cfgms-admin"
cert_serial: "1234567890"
cert_fingerprint: "sha256:..."
```

### Opting out of bundle discovery

To force API key auth and skip bundle auto-discovery entirely:

```bash
# Explicit flag
cfg --no-bundle token list

# Set env var to empty string (explicit opt-out; unset env var still triggers lookup)
CFGMS_ADMIN_BUNDLE="" cfg token list
```

### Workstation security guidance

**Treat `admin.bundle.yaml` exactly like an SSH private key.** The file contains a
private key that grants administrative access to your controller. Compromise of this
file is a full controller compromise.

**Do not:**
- Commit it to git. Dotfile repos (`~/.config` is frequently committed) are a common
  footgun. Add `admin.bundle.yaml` to your global `.gitignore`.
- Store it in Dropbox, OneDrive, Google Drive, or any cloud-synced folder.
- Store it in a Windows roaming profile — it will be transmitted to every machine
  you log into.
- Email it, paste it into Slack, or store it in a secrets manager that logs values
  (only use secret managers with envelope encryption and audit-only access logs).

**Do:**
- Keep it `chmod 600` on Linux/macOS (the controller writes it this way automatically):
  ```bash
  chmod 600 ~/.config/cfgms/admin.bundle.yaml
  ```
- On Windows, restrict the file to your user account only with `icacls`:
  ```powershell
  icacls "$env:APPDATA\cfgms\admin.bundle.yaml" /inheritance:r /grant:r "${env:USERNAME}:(R,W)"
  ```
- Rotate the bundle by re-running `cfgms-controller --init` or the admin re-enrollment
  procedure when you suspect compromise.

## Configuration

The REST API server can be configured via environment variables:

- `CFGMS_HTTP_LISTEN_ADDR`: HTTP/HTTPS listen address (default: `0.0.0.0:9080`)

## Security Considerations

- The server uses TLS automatically when a certificate manager is configured (`pkg/cert.Manager`). In development without a cert manager, it falls back to plain HTTP — use only on loopback.
- Always use HTTPS in production.
- Rotate API keys regularly.
- Use least-privilege permissions for API keys.
- Monitor API access logs.
- Consider rate limiting for production deployments.
