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

List registered stewards. The returned set depends on the session's tenant scope:

- **Root-scoped session** (web account with `root_scope: true`, or mTLS admin bundle with empty tenant): returns stewards from all tenants.
- **Tenant-scoped session** (web account with a `tenant_id`): returns only stewards in the session tenant's subtree — path-prefix inclusive, not exact-match. For example, a session scoped to `root/msp-a` sees stewards under `root/msp-a`, `root/msp-a/client-1`, etc.

Use the `?q=` selector parameter to narrow further (e.g. `?q=root/msp-a/all` or `?q=hostname:web-01`). The selector grammar is defined in `pkg/fleet/selector`.

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

#### GET /api/v1/stewards/{id}/connection

Get transport-level connection detail for a specific steward: whether it is currently streaming, when it connected, its remote network address, and the last-activity timestamp. Sourced from the live connection registry.

Returns `connected: false` (HTTP 200) for a known steward that is not currently streaming. Returns 404 for an unknown steward ID.

**Authentication:** Required  
**Required permission:** `steward:read`

**Parameters:**

- `id` (path): Steward ID

**Response (connected):**

```json
{
  "data": {
    "steward_id": "steward-001",
    "connected": true,
    "connected_at": "2026-01-12T10:29:00Z",
    "remote_addr": "198.51.100.42:54321",
    "last_activity": "2026-01-12T10:30:00Z"
  },
  "timestamp": "2026-01-12T10:30:05Z"
}
```

**Response (known but not connected):**

```json
{
  "data": {
    "steward_id": "steward-001",
    "connected": false
  },
  "timestamp": "2026-01-12T10:30:05Z"
}
```

#### GET /api/v1/stewards/connections/all

List all currently-connected stewards from the live connection registry, filtered to the authenticated caller's tenant. Returns transport-level connection detail for each connected steward.

**Authentication:** Required  
**Required permission:** `steward:read`

**Response:**

```json
{
  "data": {
    "connections": [
      {
        "steward_id": "steward-001",
        "connected_at": "2026-01-12T10:29:00Z",
        "remote_addr": "198.51.100.42:54321",
        "last_activity": "2026-01-12T10:30:00Z"
      }
    ]
  },
  "timestamp": "2026-01-12T10:30:05Z"
}
```

### Fleet Health

#### GET /api/v1/fleet/health

Return tenant-scoped counts of stewards by health classification.

**Authentication:** Required  
**Required permission:** `steward:list`

**Degraded rule:** A steward with `status == "active"` whose last heartbeat arrived more than 5 minutes ago is counted as Degraded (`DegradedHeartbeatAge = 5m`, defined in `features/controller/api/handlers_fleet.go`).

**Classification:**

| Bucket | Condition |
|--------|-----------|
| `healthy` | `status == "active"` and heartbeat within 5 minutes |
| `degraded` | `status == "active"` and heartbeat older than 5 minutes |
| `unreachable` | `status == "lost"` |

Lifecycle terminal states (registered, deregistered, archived, dormant, revoked) are not counted in any bucket. Scoping includes the caller's full tenant subtree (caller plus all descendants).

**Response:**

```json
{
  "data": {
    "healthy": 42,
    "degraded": 3,
    "unreachable": 1
  },
  "timestamp": "2026-07-18T10:30:05Z"
}
```

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

Trigger an immediate fan-out of a configuration version to the stewards matched by `selector` within the configuration's tenant. Returns `202 Accepted` immediately; delivery is fire-and-forget in a background goroutine. The leader node returns `503 Service Unavailable` for follower nodes in an HA cluster.

A `selector` field is **required** — there is no implicit "all" default. Use the literal string `"all"` to target every steward in `tenant_id`'s fleet. The fan-out is always scoped to `cfg.tenant_id`: an admin pushing a tenant-A-labelled config with `"all"` reaches only tenant-A stewards, never other tenants'.

**Authentication:** Required  
**Required permission:** `config:push`

**Request Body:**

```json
{
  "selector": "all",
  "config_id": "cfg-001",
  "version": "1.2.3",
  "tenant_id": "default"
}
```

`selector` supports the full fleet selector grammar (same as `POST /api/v1/fleet/resolve` and `POST /api/v1/jobs`): `id:`, `name:`, `os:`, `platform:`, `arch:`, `tag:`, `dna.<key>:`. Empty selector → 400. Unknown selector key → 400.

**Error responses:**

| Status | Condition |
|--------|-----------|
| `400` | Missing or empty `selector`, invalid selector expression, missing required config fields |
| `401` | No valid authentication |
| `403` | Tenant-scoped caller submitted a `tenant_id` different from their own |
| `503` | Node is not the HA leader |

**Response (202 Accepted):**

```json
{
  "push_id": "push-1705051800000000000",
  "status": "accepted",
  "queued_at": "2025-01-12T10:30:00Z"
}
```

Use `GET /api/v1/config/push/{push_id}` to poll delivery status after receiving the 202.

> **[GAP: save=deploy auto-distribution not yet wired to ConfigStore]** The push endpoint fans out `CommandSyncConfig` to active stewards but does not write through the ConfigStore. Once Epic #1501 lands, save=deploy will automatically trigger distribution on config write, making explicit pushes unnecessary for most workflows.

#### GET /api/v1/config/push/{id}

Retrieve the status of a single push operation by its `push_id` (returned in the `202` response from `POST /api/v1/config/push`).

**Authentication:** Required  
**Required permission:** `config:push`

**Parameters:**

- `id` (path): The `push_id` from the `POST /api/v1/config/push` response.

**Tenant isolation:** Callers may only read push records owned by their own tenant. A push ID that exists but belongs to a different tenant returns `404` (not `403`) to avoid disclosing cross-tenant push existence. Admin (mTLS) callers may read any push record.

**Error responses:**

| Status | Condition |
|--------|-----------|
| `401` | No valid authentication |
| `404` | Push ID not found, or owned by a different tenant |
| `503` | Push store not configured |

**Response (200 OK):**

```json
{
  "push_id": "push-1705051800000000000",
  "config_id": "cfg-001",
  "tenant_id": "default",
  "version": "1.2.3",
  "status": "completed",
  "initiated_by": "",
  "created_at": "2025-01-12T10:30:00Z",
  "updated_at": "2025-01-12T10:30:05Z"
}
```

`status` values: `pending`, `in_progress`, `completed`, `failed`.

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

### Session Management

Admin auth sessions are zero-standing-privilege bearer-token sessions issued to `cfg` CLI users holding an admin mTLS bundle (ADR-014). The raw token is returned once at creation and never re-stored; the controller holds only a SHA-256 hash. Sessions have an idle TTL (15 min) and an absolute cap (8 h). These endpoints require an admin principal (`IsAdmin == true`).

#### POST /api/v1/sessions

Create a new admin session. The caller must present an admin mTLS certificate. Returns a one-time bearer token — store it securely in the OS keychain.

**Authentication:** admin mTLS certificate

**Request body:**

```json
{
  "connection_name": "my-ctrl"
}
```

**Response (201 Created):**

```json
{
  "session_id": "abc123",
  "token": "<43-char base64url bearer token>",
  "issued_at": "2026-07-07T00:00:00Z",
  "idle_ttl": 900,
  "absolute_expiry": "2026-07-07T08:00:00Z"
}
```

#### GET /api/v1/sessions

List currently active admin sessions. A session is active if it is not revoked and has not exceeded its idle TTL or absolute cap. Tenant-scoped admins see only sessions belonging to their tenant; global admins (no tenant) see all tenants' sessions.

**Authentication:** admin mTLS certificate or bearer token (`Authorization: Bearer <token>`)

**Response (200 OK):**

```json
{
  "sessions": [
    {
      "session_id": "abc123",
      "principal_id": "alice",
      "connection_name": "my-ctrl",
      "issued_at": "2026-07-07T00:00:00Z",
      "last_activity": "2026-07-07T00:10:00Z",
      "absolute_expiry": "2026-07-07T08:00:00Z"
    }
  ]
}
```

Fields returned: `session_id`, `principal_id`, `connection_name`, `issued_at`, `last_activity`, `absolute_expiry`. The bearer token is never included.

#### DELETE /api/v1/sessions/{id}

Revoke a session by ID. Accepts either a valid bearer token or an admin mTLS certificate as credentials, so an admin can revoke sessions even if a token is unavailable.

**Authentication:** admin mTLS certificate or bearer token

**Parameters:**

- `id` (path): session ID

**Response (200 OK):**

```json
{
  "id": "abc123",
  "revoked": true
}
```

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

Workflow endpoints are registered only when a `WorkflowHandler` is wired in via `SetWorkflowHandler()`. All routes inherit the API subrouter's authentication middleware (API key or mTLS). No additional per-route permission scope is enforced beyond valid credentials.

#### GET /api/v1/workflows

List workflow definitions for the calling tenant.

**Authentication:** Required

**Response:**

The `workflows` key is always a JSON array — never `null`. When the tenant has no
workflows, the response is `{"workflows": [], "count": 0}`.

```json
{
  "workflows": [
    {
      "name": "patch-linux-fleet",
      "description": "Apply OS patches to Linux stewards",
      "version": "1.0.0",
      "steps": [
        { "name": "run-patch", "type": "task", "module": "patch" }
      ],
      "semantic_version": { "major": 1, "minor": 0, "patch": 0 }
    }
  ],
  "count": 1
}
```

#### POST /api/v1/workflows

Create a new workflow definition.

**Authentication:** Required

**Request Body:**

```json
{
  "name": "patch-linux-fleet",
  "description": "Apply OS patches to Linux stewards",
  "version": "1.0.0",
  "steps": [
    { "name": "run-patch", "type": "task", "module": "patch" }
  ],
  "variables": { "target_group": "linux-servers" }
}
```

**Response:** `201 Created` — returns the created `VersionedWorkflow` object (same shape as the list entry above).

#### GET /api/v1/workflows/{id}

Get the latest version of a workflow by name.

**Authentication:** Required

**Parameters:**

- `id` (path): Workflow name

**Response:** `200 OK`

```json
{
  "name": "patch-linux-fleet",
  "version": "1.0.0",
  "steps": [ { "name": "run-patch", "type": "task", "module": "patch" } ],
  "semantic_version": { "major": 1, "minor": 0, "patch": 0 }
}
```

#### PUT /api/v1/workflows/{id}

Replace a workflow definition. Creates a new stored version; the `name` field in the body is ignored — the path `{id}` sets the workflow name.

**Authentication:** Required

**Parameters:**

- `id` (path): Workflow name

**Request Body:** Same shape as `POST /api/v1/workflows`.

**Response:** `200 OK` — returns the updated `VersionedWorkflow` object.

#### DELETE /api/v1/workflows/{id}

Delete all stored versions of a workflow.

**Authentication:** Required

**Parameters:**

- `id` (path): Workflow name

**Response:**

```json
{
  "deleted": "patch-linux-fleet",
  "versions": 2
}
```

#### POST /api/v1/workflows/{id}/execute

Trigger immediate execution of a workflow.

**Authentication:** Required

**Parameters:**

- `id` (path): Workflow name

**Request Body (optional):**

```json
{
  "variables": { "target_group": "staging" }
}
```

**Response:** `202 Accepted`

```json
{
  "execution_id": "exec-abc123",
  "workflow_name": "patch-linux-fleet",
  "status": "running",
  "start_time": "2026-07-07T12:00:00Z"
}
```

#### GET /api/v1/workflows/{id}/executions

List all execution records for a workflow.

**Authentication:** Required

**Parameters:**

- `id` (path): Workflow name

**Response:**

```json
{
  "executions": [
    {
      "id": "exec-abc123",
      "workflow_name": "patch-linux-fleet",
      "status": "completed",
      "start_time": "2026-07-07T12:00:00Z",
      "end_time": "2026-07-07T12:05:00Z",
      "step_results": {},
      "variables": {}
    }
  ],
  "count": 1
}
```

#### GET /api/v1/workflows/{id}/executions/{exec_id}

Get the status and details of a specific workflow execution.

**Authentication:** Required  
The requesting tenant must own the workflow — cross-tenant lookups return `403 Forbidden`.

**Parameters:**

- `id` (path): Workflow name
- `exec_id` (path): Execution ID

**Response:** `200 OK`

```json
{
  "id": "exec-abc123",
  "workflow_name": "patch-linux-fleet",
  "status": "running",
  "start_time": "2026-07-07T12:00:00Z",
  "current_step": "run-patch",
  "step_results": {},
  "variables": {}
}
```

**Error responses:**

- `404 Not Found` — execution ID does not exist or does not belong to the named workflow
- `403 Forbidden` — workflow is not visible in the calling tenant's namespace

#### POST /api/v1/workflows/{id}/executions/{exec_id}/cancel

Cancel a running or pending workflow execution.

**Authentication:** Required  
Cross-tenant cancellations return `403 Forbidden`. Already-terminal executions return `409 Conflict`.

**Parameters:**

- `id` (path): Workflow name
- `exec_id` (path): Execution ID

**Response:** `200 OK`

```json
{
  "cancelled": "exec-abc123"
}
```

**Error responses:**

- `404 Not Found` — execution ID does not exist or does not belong to the named workflow
- `403 Forbidden` — workflow is not visible in the calling tenant's namespace
- `409 Conflict` — execution is already in a terminal state (`completed`, `failed`, or `cancelled`)

### Workflow Triggers

Trigger endpoints manage scheduled and event-driven workflow execution. The `/triggers` subrouter is registered alongside `/workflows` when a `WorkflowHandler` is wired in (`server.go:717`). All routes inherit the API subrouter's authentication middleware. Trigger types: `schedule`, `webhook`, `siem`, `manual`.

#### GET /api/v1/triggers/health

Health status of the trigger subsystem.

**Authentication:** Required

**Response:**

```json
{
  "status": "healthy",
  "timestamp": "2026-07-07T12:00:00Z",
  "service": "workflow-trigger-api"
}
```

#### POST /api/v1/triggers

Create a new trigger.

**Authentication:** Required

**Request Body:**

```json
{
  "name": "nightly-patch",
  "description": "Run patch workflow every night at 02:00 UTC",
  "type": "schedule",
  "workflow_name": "patch-linux-fleet",
  "status": "active",
  "tenant_id": "root/msp-a/client-1",
  "schedule": {
    "cron": "0 2 * * *",
    "timezone": "UTC"
  }
}
```

**Response:** `201 Created` — returns the created `Trigger` object.

```json
{
  "id": "trigger-xyz789",
  "name": "nightly-patch",
  "type": "schedule",
  "status": "active",
  "workflow_name": "patch-linux-fleet",
  "tenant_id": "root/msp-a/client-1",
  "created_at": "2026-07-07T12:00:00Z",
  "updated_at": "2026-07-07T12:00:00Z"
}
```

#### GET /api/v1/triggers

List triggers with optional filtering.

**Authentication:** Required

**Query parameters (all optional):**

- `type` — `schedule` | `webhook` | `siem` | `manual`
- `status` — `active` | `inactive` | `paused` | `error` | `deleted`
- `tenant_id` — tenant path prefix filter
- `tags` — comma-separated list
- `created_after` / `created_before` — RFC 3339 timestamps
- `limit` / `offset` — pagination (default limit: server-defined)

**Response:**

The `triggers` key is always a JSON array — never `null`. When the tenant has no
triggers matching the filter, the response includes `"triggers": []`.

```json
{
  "triggers": [ { "id": "trigger-xyz789", "name": "nightly-patch" } ],
  "count": 1,
  "filter": { "type": "schedule", "status": "active" }
}
```

#### GET /api/v1/triggers/{id}

Get a trigger by ID.

**Authentication:** Required

**Parameters:**

- `id` (path): Trigger ID

**Response:** `200 OK` — returns the `Trigger` object (same shape as the `POST /api/v1/triggers` response).

#### PUT /api/v1/triggers/{id}

Update a trigger. The `{id}` path value overrides any `id` field in the body.

**Authentication:** Required

**Parameters:**

- `id` (path): Trigger ID

**Request Body:** Same shape as `POST /api/v1/triggers`.

**Response:** `200 OK` — returns the updated `Trigger` object.

#### DELETE /api/v1/triggers/{id}

Delete a trigger.

**Authentication:** Required

**Parameters:**

- `id` (path): Trigger ID

**Response:** `204 No Content`

```json
{
  "message": "Trigger deleted successfully",
  "trigger_id": "trigger-xyz789"
}
```

#### POST /api/v1/triggers/{id}/enable

Enable a previously disabled trigger.

**Authentication:** Required

**Parameters:**

- `id` (path): Trigger ID

**Response:**

```json
{
  "message": "Trigger enabled successfully",
  "trigger_id": "trigger-xyz789",
  "status": "active"
}
```

#### POST /api/v1/triggers/{id}/disable

Disable an active trigger without deleting it.

**Authentication:** Required

**Parameters:**

- `id` (path): Trigger ID

**Response:**

```json
{
  "message": "Trigger disabled successfully",
  "trigger_id": "trigger-xyz789",
  "status": "inactive"
}
```

#### POST /api/v1/triggers/{id}/execute

Manually fire a trigger immediately, bypassing its schedule or conditions.

**Authentication:** Required

**Parameters:**

- `id` (path): Trigger ID

**Request Body (optional):** Key-value map of execution data passed to the triggered workflow.

```json
{
  "override_target": "staging"
}
```

**Response:** `200 OK` — returns the `TriggerExecution` object.

```json
{
  "id": "texec-def456",
  "trigger_id": "trigger-xyz789",
  "status": "running",
  "start_time": "2026-07-07T12:00:00Z"
}
```

#### GET /api/v1/triggers/{id}/executions

Get execution history for a trigger.

**Authentication:** Required

**Parameters:**

- `id` (path): Trigger ID
- `limit` (query, optional): Maximum records to return (default: 50; must be > 0)

**Response:**

```json
{
  "trigger_id": "trigger-xyz789",
  "executions": [
    {
      "id": "texec-def456",
      "trigger_id": "trigger-xyz789",
      "status": "success",
      "start_time": "2026-07-07T02:00:00Z"
    }
  ],
  "count": 1,
  "limit": 50
}
```

### Cluster Management

Read-only view of the Hyper-V cluster topology derived on demand from steward DNA
attributes. **This API is eventually consistent**: it reflects whatever `cluster:<name>.*`
DNA attributes were last published by each steward's `DNARefreshLoop` ticker (default
30 minutes, configurable via `DNARefreshInterval`). A cluster topology change — a new
member node, a role ownership transfer — can take up to one refresh interval to appear
in these endpoints. This is acceptable because no safety-critical behavior (no-duplicate-VM
enforcement, owner-gated lifecycle actions) depends on this registry; those operations gate
off live PowerShell queries on every convergence tick, not off this read API.

#### GET /api/v1/clusters

List all clusters visible to the authenticated caller. Clusters are derived by parsing
`cluster:<name>.*` keys from each steward's `DNA.Attributes`. Only clusters whose member
stewards belong to the caller's tenant (or a descendant tenant) are returned.

**Required permission:** `cluster:list`

**Tenant scoping:** Caller's tenant from the authenticated context limits which stewards'
DNA is scanned. An admin mTLS principal (empty tenant) has no scope restriction and sees
all clusters.

**Response:**

```json
{
  "data": [
    {
      "name": "cfg-lab",
      "members": ["steward-a", "steward-b"],
      "role_owners": {
        "csv": "CFG-70-02",
        "cno": "CFG-AB-02"
      }
    }
  ],
  "timestamp": "2026-07-08T12:00:00Z"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Cluster name from the `cluster:<name>.*` DNA key prefix |
| `members` | []string | Sorted steward IDs whose DNA carries `cluster:<name>.*` keys |
| `role_owners` | object | Map of role name → owner node, parsed from `cluster:<name>.resource_owner.<role>` keys |

#### GET /api/v1/clusters/{name}

Get the registry entry for a single named cluster.

Returns 404 when the cluster does not exist or all its member stewards are outside
the caller's tenant scope. 404 (not 403) is used to avoid disclosing cluster existence
across tenant boundaries.

**Required permission:** `cluster:read`

**Parameters:**

- `name` (path): Cluster name (e.g., `cfg-lab`)

**Response (200):**

```json
{
  "data": {
    "name": "cfg-lab",
    "members": ["steward-a", "steward-b"],
    "role_owners": {
      "csv": "CFG-70-02",
      "cno": "CFG-AB-02"
    }
  },
  "timestamp": "2026-07-08T12:00:00Z"
}
```

**Error responses:**

| Status | Code | Condition |
|--------|------|-----------|
| 400 | `MISSING_CLUSTER_NAME` | `name` path variable is empty |
| 404 | `CLUSTER_NOT_FOUND` | Cluster does not exist or is outside the caller's tenant |

#### GET /api/v1/clusters/{name}/reconciliation

Reconcile the declared clustered resources for a named cluster against the actual
cluster registry. This is the **controller's accountable-authority** view: it
cross-checks the resource declarations stored in `cluster-policies/<name>` (the
"should exist" side) with the `cluster:<name>.resource_owner.*` DNA attributes
published by member stewards (the "does exist" side).

Returns 404 under the same conditions as `GET /api/v1/clusters/{name}`.

**Required permission:** `cluster:read`

**Parameters:**

- `name` (path): Cluster name (e.g., `cfg-lab`)

**Response (200):**

```json
{
  "data": {
    "cluster_name": "cfg-lab",
    "resources": [
      {
        "role_name": "csv",
        "status": "present-with-live-owner",
        "owner_id": "CFG-70-02"
      },
      {
        "role_name": "vm2",
        "status": "declared-but-missing"
      },
      {
        "role_name": "cno",
        "status": "orphan-dead-owner",
        "owner_id": "CFG-AB-02"
      },
      {
        "role_name": "dfs",
        "status": "split-brain",
        "all_owner_claims": ["CFG-70-02", "CFG-AB-02"]
      }
    ],
    "alerts": [
      {
        "id": "cfg-lab/vm2/declared-but-missing",
        "severity": "critical",
        "title": "Cluster role not created",
        "metric_name": "cluster_role_missing",
        "status": "active"
      }
    ],
    "components": {
      "cfg-lab/csv": { "name": "cfg-lab/csv", "status": "healthy", "message": "owner is live" },
      "cfg-lab/vm2": { "name": "cfg-lab/vm2", "status": "unhealthy", "message": "declared but not created" }
    }
  },
  "timestamp": "2026-07-16T10:00:00Z"
}
```

**Resource status values:**

| Status | Meaning |
|--------|---------|
| `present-with-live-owner` | Declared resource exists in the registry with a heartbeat-live owner. |
| `declared-but-missing` | Declared in `cluster-policies` but no registry entry (create-coverage gap). Non-owner stewards' compliant-by-delegation abstain is **not safe** here. |
| `orphan-dead-owner` | Registry entry exists but owner's last heartbeat exceeds 60 s. |
| `split-brain` | Multiple cluster members report different owner values for the same role; all claims listed in `all_owner_claims`. |

**Alert severity:**

- `critical` — `declared-but-missing` or `split-brain` (resource availability is compromised)
- `warning` — `orphan-dead-owner` (owner offline but registry entry is intact)

**Notes:**

- Detection is on-demand: the endpoint scans the current DNA snapshot and config store on each call; there is no background reconciliation loop.
- When no `cluster-policies` config is stored for the cluster, the declared set is empty and only dead-owner and split-brain can be detected (no missing-resource alerts).
- Owner liveness: `owner_id` is matched to a steward by DNA `hostname` attribute first, then by steward ID; an unknown owner is treated as dead.

**Error responses:**

| Status | Code | Condition |
|--------|------|-----------|
| 400 | `MISSING_CLUSTER_NAME` | `name` path variable is empty |
| 404 | `CLUSTER_NOT_FOUND` | Cluster does not exist or is outside the caller's tenant |

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
| `MISSING_CLUSTER_NAME` | Cluster name path variable is empty |
| `CLUSTER_NOT_FOUND` | Cluster does not exist or is outside the caller's tenant |
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

### Web Accounts

Web accounts are browser-based admin principals backed by an argon2id password and (optionally) WebAuthn passkeys. They are RBAC-equivalent to API-key principals — they carry explicit `permissions` and a tenant scope, and are not implicit global admins.

#### Tenant scope

Each web account has exactly one of:

| Field | Meaning |
|-------|---------|
| `root_scope: true` | Account sees all tenants' data (subtree-inclusive from root). `tenant_id` is empty. |
| `tenant_id: "root/msp-a"` | Account sees only the `root/msp-a` subtree. `root_scope` is false. |
| neither | Account defaults to `"default"` tenant on creation. |

`root_scope` and `tenant_id` are mutually exclusive — supplying both returns `400 INVALID_SCOPE`. An empty `tenant_id` alone **never** grants root scope; `root_scope: true` must be set explicitly (defense-in-depth).

#### POST /api/v1/web/accounts

Create a new web admin account, or reset an existing one (upsert: password replaced, omitted `tenant_id`/`permissions` retained from the existing record).

**Authentication:** Required  
**Required permission:** `web-account:create`  
**Assurance:** Strong session (passkey or elevated mTLS) required

**Request body:**

```json
{
  "username": "alice",
  "password": "change-me-now",
  "root_scope": true,
  "permissions": ["steward:list", "steward:read"]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `username` | string | 3–64 chars, starting alphanumeric, then `[a-zA-Z0-9._-]` |
| `password` | string | Plaintext — hashed server-side with argon2id; never stored or logged |
| `root_scope` | bool | Grant cross-tenant root scope. Mutually exclusive with `tenant_id`. |
| `tenant_id` | string | Scope account to this tenant subtree. Mutually exclusive with `root_scope`. |
| `permissions` | array | Permission IDs (e.g. `"steward:list"`). Unknown IDs are rejected. |

**Response (201 Created or 200 OK on reset):**

```json
{
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "username": "alice",
    "tenant_id": "",
    "root_scope": true,
    "permissions": ["steward:list", "steward:read"],
    "created_at": "2026-01-12T10:30:00Z"
  },
  "timestamp": "2026-01-12T10:30:00Z"
}
```

Root-scoped accounts have `tenant_id: ""` and `root_scope: true` in the response. Tenant-scoped accounts have a non-empty `tenant_id` and `root_scope: false`.

#### GET /api/v1/web/accounts

List all web admin accounts. Password hashes are never included.

**Authentication:** Required  
**Required permission:** `web-account:list`

**Response:**

```json
{
  "data": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "username": "alice",
      "tenant_id": "",
      "root_scope": true,
      "permissions": ["steward:list", "steward:read"],
      "created_at": "2026-01-12T10:30:00Z"
    },
    {
      "id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
      "username": "bob",
      "tenant_id": "root/msp-a",
      "root_scope": false,
      "permissions": ["steward:list"],
      "created_at": "2026-01-10T08:00:00Z"
    }
  ],
  "timestamp": "2026-01-12T10:30:00Z"
}
```

#### DELETE /api/v1/web/accounts/{username}

Delete a web admin account. Removes both the in-memory cache entry and the durable secret-store record.

**Authentication:** Required  
**Required permission:** `web-account:delete`  
**Assurance:** Strong session required

**Parameters:**

- `username` (path): Username of the account to delete

**Response (200 OK):**

```json
{
  "data": {
    "username": "alice",
    "deleted": true
  },
  "timestamp": "2026-01-12T10:30:00Z"
}
```

Returns `404 WEB_ACCOUNT_NOT_FOUND` if the account does not exist.

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
