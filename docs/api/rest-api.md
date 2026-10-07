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

### Tenant Scope

Every authenticated caller is either **root** (a `root_scope` account, or the bootstrap admin certificate) or **bound to one tenant**. A root caller's identity carries the deployment's root tenant; its reach comes from the root flag, never from an empty tenant. A credential that is neither root nor bound to a tenant is refused with `403 NO_TENANT_SCOPE` before any handler runs.

A tenant-scoped caller reaches its own tenant's records. A root caller's lists, and its by-ID reads of records those lists show, span every tenant. For a root caller subject to the tenant-crossing boundary (ADR-025), an action on a record owned by a tenant below root — whether the route names that tenant, names the record by ID (an account, a certificate or cert binding, a token, a registration or credential request, a rollout, a run, a rollback, an API key, a role), or selects stewards with a fleet selector (a batch job, an upgrade, an osquery query, a signed operator payload) — requires an active grant or break-glass crossing, and otherwise returns `401` with `WWW-Authenticate: CFGMS-StepUp realm="cfgms", required="tenant-crossing"` and a body naming the tenant's break-glass endpoint:

```json
{
  "error": "tenant_crossing_required",
  "required_assurance": "tenant-crossing",
  "break_glass_endpoint": "/api/v1/tenants/<tenant>/break-glass"
}
```

Bulk approvals (approve-all, approve-by-CIDR) skip registrations the caller may not act on instead of returning the challenge.

Where an operation needs a tenant the request does not name, it uses the caller's own tenant — the root tenant for a root caller — never a fallback tenant.

## Response Format

All API responses follow a standard format:

### Success Response

```json
{
  "data": { ... },
  "timestamp": "2025-01-12T10:30:00Z"
}
```

Each item carries the steward's operator-assigned `tags` (omitted when the steward has none), read in one batch from the tag store for the rows returned, so the list needs no per-steward `/tags` request. Tags follow the same tenant scope as the rows themselves.

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

**Response:** Returns controller URL, issued mTLS certificate, and tenant assignment. `409` when the controller already holds an active record for the request's device ID; the steward then re-admits through the registration-refresh handshake below.

### Steward Re-admission (Registration Refresh)

A steward whose stored identity cannot reconnect re-admits with its device identity key (ADR-011 and its Amendment 1). The three calls carry no API key: identity is proven by an Ed25519 signature, made with the device key, over `sha256(nonce || device_id || server_ts)`. The three share one per-source rate limit; over it they answer `429`.

#### POST /api/v1/stewards/{device_id}/refresh/challenge

Issues a single-use nonce (60 s) for the device.

**Response:** `200 {"nonce": "<base64url>", "server_ts": <unix nanoseconds>, "expires_in": 60}`. `403` revoked device, `404` unknown device.

#### POST /api/v1/stewards/{device_id}/refresh/complete

Submits the proof and a CSR over a fresh keypair generated on the steward.

**Request Body:** `{"nonce": "...", "issued_at": <server_ts>, "signature": "<base64url>", "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----..."}`

**Response:**
- `200` — issued now (tenant policy `auto_accept`): `client_cert`, `ca_cert`, `issuer_chain`, `signing_cert`/`server_cert`, `steward_id`, `tenant_id`, `transport_address`. No private key is ever returned.
- `202` — queued for approval: `{"status": "queued", "pending_id": "..."}`. A new request from the same device supersedes its open one.
- `401` bad or expired proof, `403` revoked or refused by policy, `404` unknown device.

#### POST /api/v1/stewards/{device_id}/refresh/claim

Collects the outcome of a queued request, with a fresh challenge's proof. The approved certificate is signed from the CSR submitted with the original `/refresh/complete`, so the steward pairs it with the key it kept for that request.

**Request Body:** `{"pending_id": "...", "nonce": "...", "issued_at": <server_ts>, "signature": "<base64url>"}`

**Response:**
- `200` — approved: the same certificate bundle as `/refresh/complete`'s `200`. Delivered exactly once; the entry is then `claimed`.
- `202` — still pending.
- `401` bad or expired proof, `403` rejected or revoked.
- `404` — unknown, expired, already claimed, or belonging to another device: the steward files a new request. A `200` lost in transit therefore costs one more approval under `require_approval`.

Operators approve or reject queued requests with `cfg steward refresh list|approve|reject` (`/api/v1/stewards/refresh/pending`, `/api/v1/stewards/refresh/{pending_id}/approve|reject`).

Each item in the `GET /api/v1/stewards/refresh/pending` array carries `hostname`, the steward-reported hostname for `device_id` resolved within the entry's own tenant. It is an empty string when the device is unknown, and is untrusted text.

### Steward Management

All steward management endpoints require an API key. The `cfg steward list/status` CLI (Epic #1501) wraps these endpoints.

#### GET /api/v1/stewards

List registered stewards. The returned set depends on the session's tenant scope:

- **Root-scoped session** (web account with `root_scope: true`, or mTLS admin bundle with empty tenant): returns stewards from all tenants.
- **Tenant-scoped session** (web account with a `tenant_id`): returns only stewards in the session tenant's subtree — path-prefix inclusive, not exact-match. For example, a session scoped to `root/msp-a` sees stewards under `root/msp-a`, `root/msp-a/client-1`, etc.

Use the `?q=` selector parameter to narrow further (e.g. `?q=root/msp-a/all` or `?q=hostname:web-01`). The selector grammar is defined in `pkg/fleet/selector`.

By default, **operator-hidden** and **quarantined** stewards are excluded from the response. Use the visibility query parameters to re-include them.

**Authentication:** Required  
**Required permission:** `steward:list`

**Query parameters:**

| Parameter | Default | Description |
|-----------|---------|-------------|
| `q` | (none) | Selector string — see `pkg/fleet/selector` |
| `limit` | 50 | Page size |
| `offset` | 0 | Page offset |
| `include_hidden` | `false` | Set `true` to include operator-hidden stewards |
| `include_quarantined` | `false` | Set `true` to include quarantined stewards |
| `include_deregistered` | `false` | Set `true` to include deregistered stewards |

**Response:**

```json
{
  "data": [
    {
      "id": "steward-001",
      "status": "connected",
      "last_seen": "2025-01-12T10:29:30Z",
      "version": "0.2.0",
      "hidden": false,
      "tags": ["prod", "web"],
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

#### PATCH /api/v1/stewards/{id}/visibility

Set the operator-controlled visibility flag on a steward. Hidden stewards are excluded from the default list response and health tile counts, but their count is always surfaced in `GET /api/v1/fleet/health` as the non-suppressible `hidden` field.

**Reversible:** call again with `{"hidden": false}` to restore normal visibility.

**Authentication:** Required (web session or mTLS admin; API keys are rejected with `403`)  
**Required permission:** `steward:visibility` (`AssuranceBasic` minimum — API keys cannot hide stewards)  
**Audit:** emitted at `Medium` severity as `steward.visibility_changed`

**Parameters:**

- `id` (path): Steward ID

**Request body:**

```json
{ "hidden": true }
```

**Response:**

```json
{
  "id": "steward-001",
  "hidden": true
}
```

**Error responses:**

| Code | Condition |
|------|-----------|
| `400` | Malformed request body or invalid steward ID format |
| `403` | API key (machine-assurance) caller — use a web session |
| `404` | Steward not found, or steward belongs to a different tenant |
| `503` | Durable store unavailable |

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
| `hidden` | `hidden == true` (excluded from healthy/degraded/unreachable buckets) |

Lifecycle terminal states (registered, deregistered, archived, dormant, revoked) are not counted in any bucket. Scoping includes the caller's full tenant subtree (caller plus all descendants).

The `hidden` field is **non-suppressible** — it is always present in the response regardless of query parameters. A non-zero value signals that concealment is in effect, so operators are never blind to hidden stewards even when the default list view excludes them.

**Response:**

```json
{
  "data": {
    "healthy": 42,
    "degraded": 3,
    "unreachable": 1,
    "hidden": 2
  },
  "timestamp": "2026-07-18T10:30:05Z"
}
```

### Configuration Management

#### GET /api/v1/stewards/{id}/config

Get configuration for a specific steward.

**Authentication:** Required  
**Required permission:** `steward:read-config`

**Tenant scope:** a scoped caller may read configuration only for a steward
within its own tenant subtree. A steward outside the subtree, or unknown to the
caller, is rejected with `404 STEWARD_NOT_FOUND` — the same response for both
cases, so the endpoint cannot be used to probe steward existence across
tenants. Root/unscoped callers may read any steward's configuration.

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

**Tenant scope:** the configuration is stored under the steward's own tenant
(the caller's own tenant only for a steward not yet known). A scoped caller may
write configuration only for a steward within its own tenant subtree; an
out-of-subtree steward is rejected with `404 STEWARD_NOT_FOUND` (not `403`, to
avoid disclosing that the steward exists in another tenant). Root callers retain
authority across tenants, subject to the tenant-crossing boundary (see
[Tenant Scope](#tenant-scope)). `GET /api/v1/stewards/{id}/config/effective` and
`DELETE /api/v1/stewards/{id}/config` resolve and authorize the steward's tenant
the same way.

**Parameters:**

- `id` (path): Steward ID

**Request Body:** Same structure as the GET response `data` field.

#### GET /api/v1/stewards/{id}/config/effective

Get the effective (merged/inherited) configuration for a specific steward, resolving tenant hierarchy inheritance.

**Authentication:** Required  
**Required permission:** `steward:read-config`

**Tenant scope:** resolved against the steward's own tenant when the steward is
known to the controller's in-memory registry; a caller whose tenant differs
from the steward's owning tenant is rejected, mapped to `500 INTERNAL_ERROR`
(this check does not distinguish a cross-tenant rejection from a genuine
resolution failure, unlike the plain GET endpoint above). A steward not yet in
the registry falls back to resolving under the caller's own tenant, so a
mismatch cannot disclose another tenant's configuration.

**Parameters:**

- `id` (path): Steward ID

#### POST /api/v1/stewards/{id}/config/validate

Validate configuration for a steward without applying it.

**Authentication:** Required  
**Required permission:** `steward:validate-config`

**Tenant scope:** a scoped caller may validate configuration only for a steward
within its own tenant subtree. An out-of-subtree or unknown steward is rejected
with `404 STEWARD_NOT_FOUND`. Root/unscoped callers may validate for any
steward.

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

> Writing configuration through the ConfigStore triggers distribution to the affected stewards (save=deploy; see `features/controller/push` `Fanout`). This endpoint is the explicit re-sync for a targeted set of stewards.

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

### Signed Action Envelope

Steward-action endpoints accept an operator-signed envelope instead of trusting the
caller's session alone. The operator signs `operatorpayload.Envelope` with `shell` set to
`steward-action`, `content` set to the canonical action JSON (`verb`, `target_kind`,
`target_name`, `parameters`), `targets` set to exactly the one steward ID the request
addresses, a single-use `nonce`, and an `expires_at`.

The proof carries one credential block, never both:

- **X.509** (`algorithm`, `value`, `public_key`): the signature is over the canonical
  envelope bytes. The certificate must chain to the controller CA, carry the
  payload-signing marker, and not be revoked. The credential identifier recorded is the
  certificate serial.
- **WebAuthn** (`authenticator_data`, `client_data_json`, `signature`, `credential_id`):
  the raw assertion returned by `POST /api/v1/operator-payload/sign/finish`. The credential
  must be registered to the authenticated caller, and its account must hold
  `operator-payload:sign`. Verification at the API does not re-check or advance the sign
  count, which `sign/finish` has already done.

An envelope whose `expires_at` is past, or more than 5 minutes ahead, is refused, as is one
whose signed `targets` are not exactly the addressed steward. A refused envelope returns
`invalid operator signature` with no further detail.

The controller forwards the signed envelope to the steward unchanged and never re-signs or
strips it. For a WebAuthn proof it also attaches `webauthn_manifest`, a CA-signed roster of
the credentials authorized for that steward's tenant, so the steward can verify the
assertion independently. Nonce single-use is enforced by the steward.

### Certificate Management

#### GET /api/v1/certificates

List certificates.

**Authentication:** Required  
**Required permission:** `certificate:list`

**Tenant scope:** a scoped caller sees only certificates whose owning steward is
within its own tenant subtree; a certificate that cannot be attributed to any
steward (a controller-internal CA/signing/server certificate) remains visible
to every caller. If the steward store needed to evaluate subtree membership is
unavailable, the request fails closed with `503 SERVICE_UNAVAILABLE` rather
than returning an unfiltered list. Root/unscoped callers see every
certificate, unfiltered.

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
      "tenant_id": "acme-corp",
      "is_valid": true,
      "issued_at": "2025-01-12T10:30:00Z",
      "expires_at": "2026-01-12T10:30:00Z",
      "days_until_expiration": 365,
      "needs_renewal": false
    }
  ],
  "timestamp": "2025-01-12T10:30:00Z"
}
```

`tenant_id` is the tenant of the steward that owns the certificate; it is omitted when the certificate has no owning steward or the steward has no fleet record. `issued_at` is the time the certificate was issued.

#### POST /api/v1/certificates/provision

Provision a new certificate for a steward.

**Authentication:** Required  
**Required permission:** `certificate:provision`

**Tenant scope:** a tenant-scoped caller may provision only for a `steward_id` with a
durable steward record inside its own subtree. A `steward_id` registered under another
tenant, and a `steward_id` with no record at all, are both refused with `403 FORBIDDEN`
— without a record the target cannot be attributed to the caller's subtree, and this
endpoint returns a signed certificate together with its private key. New-device
onboarding is therefore a root/unscoped operation, or follows the steward's
registration to a tenant. Root callers may provision for any steward, subject to the
tenant-crossing boundary (see [Tenant Scope](#tenant-scope)) for every existing steward
the certificate would name.

**Certificate subject:** for a tenant-scoped caller, `common_name` is always the
resolved steward's own ID and `organization` is always the steward certificate
organization; an explicit value for either is accepted only when it already matches,
and refused with `403 FORBIDDEN` otherwise. The subject — not `steward_id` — is what
peers authenticate on, so a request-supplied subject would let a caller pass the
containment check with one steward and receive a certificate naming another. A root
caller may choose `common_name`. For every caller, the certificate's organization is
always the steward certificate organization — any other `organization` is refused with
`403 FORBIDDEN` — and a `steward_id` or `common_name` naming a controller cluster node is
refused with `403 FORBIDDEN`, so this endpoint never mints a controller peer identity.

**Validity ceiling:** `validity_days` may not exceed 825. A request above the ceiling
is refused with `400 BAD_REQUEST` — the requested period is never silently clamped
down to the maximum.

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

#### POST /api/v1/certificates/signing/rotate

Rotate the controller's payload/client signing CA certificate, issuing a new one and
retiring the old one after an overlap window.

**Authentication:** Required (mTLS admin certificate, `AssuranceStrong`)  
**Required permission:** `certificate:rotate`

**Caller:** a certificate-authenticated root principal (admin certificate). A root web or
Bearer session is refused with `403 FORBIDDEN`: rotation replaces the chain every steward
verifies operator commands against.

**Tenant scope:** the signing CA is a single fleet-wide resource, not owned by any
one tenant — rotating it replaces the chain every tenant's certificates verify
against. Available to unscoped (root) administrators only; a tenant-scoped caller
receives `403 FORBIDDEN` regardless of the permission grant.

**Request Body (optional):**

```json
{
  "overlap_days": 7,
  "force": false
}
```

**Response:**

```json
{
  "data": {
    "old_serial": "123456789",
    "new_serial": "987654321",
    "overlap_days": 7,
    "stewards_notified": 42,
    "overlap_expires_at": "2026-01-19T10:30:00Z"
  },
  "timestamp": "2025-01-12T10:30:00Z"
}
```

### Signing Credentials

#### POST /api/v1/signing-credential/request

Issue a CSR-based payload-signing certificate (Issue #3693): the caller generates an
ECDSA P-256 keypair locally and submits only the public key here. The CA never sees
a private key for this credential.

**Authentication:** Required (mTLS admin certificate, `AssuranceStrong`)  
**Required permission:** `signing-credential:request`

**Tenant scope:** the issued credential is bound exclusively to the caller's own
identity (`CommonName`/`ClientID` are always the authenticated principal's own, never
request-supplied) — there is no separate target resource to contain. An unset
caller scope is refused with `403 FORBIDDEN` (Issue #4316 fail-closed contract).

**Request Body:**

```json
{
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...ECDSA P-256 SubjectPublicKeyInfo...\n-----END PUBLIC KEY-----"
}
```

**Response (201 Created):**

```json
{
  "data": {
    "certificate_pem": "-----BEGIN CERTIFICATE-----\n...",
    "ca_certificate_pem": "-----BEGIN CERTIFICATE-----\n...",
    "serial_number": "123456789",
    "expires_at": "2027-01-12T10:30:00Z"
  },
  "timestamp": "2026-01-12T10:30:00Z"
}
```

### Credential Renewal

#### POST /api/v1/credential-renewal

Renew an enrolment-issued credential before it expires: the renewing host presents
its expiring certificate over mutual TLS to prove identity and submits a CSR for a
freshly generated keypair. The controller signs, binds, and revokes-and-unbinds the
old certificate in one operation.

**Authentication:** the expiring certificate itself, presented over mutual TLS — no
API key or session credential can substitute for it.  
**Required permission:** none (gated entirely by certificate possession); no route
permission is registered for this endpoint.

**Tenant scope:** renewal is scoped exclusively to the account resolved from the
presented certificate's own serial — there is no separate caller-supplied target.
An unset caller scope, or one that disagrees with the resolved account's own tenant,
is refused with `403 NO_ACCOUNT_BINDING` (Issue #4316 fail-closed contract).

**Request Body:**

```json
{
  "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----"
}
```

**Response (200 OK):**

```json
{
  "data": {
    "certificate_pem": "-----BEGIN CERTIFICATE-----\n...",
    "ca_certificate_pem": "-----BEGIN CERTIFICATE-----\n...",
    "serial_number": "987654321",
    "account_id": "550e8400-e29b-41d4-a716-446655440000",
    "granted_markers": ["admin"],
    "expires_at": "2027-01-12T10:30:00Z"
  },
  "timestamp": "2026-01-12T10:30:00Z"
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

List roles: the authenticated caller's own tenant roles plus system roles.

**Authentication:** Required  
**Required permission:** `rbac:list-roles`

**Tenant scope:** derived from the authenticated session. A `tenant_id` query
parameter is ignored — it cannot be used to read another tenant's roles. Requests
without a session tenant are rejected with `401`.

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

Create a new role in the authenticated caller's tenant.

**Authentication:** Required  
**Required permission:** `rbac:create-role`

**Tenant scope:** derived from the authenticated session. `tenant_id` may be omitted;
when present it must equal the session tenant, otherwise the request is rejected with
`403 TENANT_MISMATCH`. The role `id` is server-assigned (tenant-prefixed) — a body
`id` is ignored.

**Validation:** `name` is required, at most 128 characters; `description` at most 512
characters; neither may contain control characters.

**Request Body:**

```json
{
  "name": "Config Manager",
  "description": "Manage configurations",
  "permissions": ["config.read", "config.write"]
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

**Tenant scope:** readable roles are the session tenant's own roles plus system
roles. Another tenant's role returns `404 ROLE_NOT_FOUND` (the response does not
confirm that it exists).

#### PUT /api/v1/rbac/roles/{id}

Update an existing role owned by the authenticated caller's tenant.

**Authentication:** Required  
**Required permission:** `rbac:update-role`

**Parameters:**

- `id` (path): Role ID

**Tenant scope:** a role owned by another tenant returns `404 ROLE_NOT_FOUND`; a
system role returns `403 SYSTEM_ROLE_IMMUTABLE`. A `tenant_id` that differs from the
session tenant returns `403 TENANT_MISMATCH` — a role's tenant cannot be reassigned
through an update. Tenant scope, system-role status, hierarchy links and creation
time are carried over from the stored role.

**Request Body:** `name`, `description` and `permissions`, validated as for
POST /api/v1/rbac/roles.

#### DELETE /api/v1/rbac/roles/{id}

Delete a role owned by the authenticated caller's tenant.

**Authentication:** Required  
**Required permission:** `rbac:delete-role`

**Parameters:**

- `id` (path): Role ID

**Tenant scope:** a role owned by another tenant returns `404 ROLE_NOT_FOUND`; a
system role returns `403 SYSTEM_ROLE_IMMUTABLE`.

### API Key Management

#### GET /api/v1/api-keys

List API keys.

**Authentication:** Required  
**Required permission:** `api-key:list`

**Tenant scope:** only API keys belonging to the caller's own tenant are
returned — an exact tenant match, not a subtree (unlike most list endpoints in
this document). A request with no resolved tenant is rejected with
`401 AUTHENTICATION_REQUIRED`.

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

**Tenant scope:** the created key's `tenant_id` (explicit, or the caller's own
tenant when omitted) must equal or descend from the caller's own tenant subtree —
a tenant-scoped caller cannot mint a key for a sibling tenant by an out-of-scope
`tenant_id`. Root callers may target any tenant, subject to the tenant-crossing
boundary (see [Tenant Scope](#tenant-scope)). A caller may also only
grant a `permissions` entry it itself holds — a caller cannot mint a key with a
permission it does not have, independent of the tenant check.

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

**Tenant scope:** a key owned by another tenant returns `404 KEY_NOT_FOUND` (not
`403`) — the same response as an unknown ID, so this endpoint cannot be used to
probe for a key's existence across tenants. Root/unscoped callers may read any key.

**Parameters:**

- `id` (path): API key ID

#### DELETE /api/v1/api-keys/{id}

Delete an API key. The key is immediately invalidated.

**Authentication:** Required  
**Required permission:** `api-key:delete`

**Tenant scope:** a key owned by another tenant returns `404 KEY_NOT_FOUND` (not
`403`) and is not deleted — the same response as an unknown ID. Root/unscoped
callers may delete any key.

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

**Show-once secret:** The full token secret is only ever returned in the response body of create and rotate — never on list, get, or revoke. Once that response is dismissed the secret cannot be re-fetched; only a 6-char `token_prefix` remains visible. The secret is never written to the audit trail or server logs — audit events for create/delete/revoke/rotate record `token_prefix` and the stable `token_id` (UUID) only.

**Path parameter, two forms:** `{token}` in the paths below accepts either the full token secret (exact match — used by mTLS admin callers that hold the raw token) or the token's stable `token_id` UUID (used by the web UI, which never receives the raw secret outside the mint/rotate response). Lookup tries an exact match first, then falls back to UUID lookup.

#### GET /api/v1/registration/tokens

List registration tokens. Each entry includes `token_id` (stable UUID, safe to expose) and `token_prefix`, never the secret, plus the optional operator-written `label` (omitted when the token was minted without one).

**Authentication:** Required  
**Required permission:** `registration:list-tokens`

**Tenant scope:** a tenant-scoped caller always sees only its own tenant's
tokens — a `tenant_id` query parameter is ignored for a tenant-scoped caller.
Root/unscoped callers may narrow the list with `?tenant_id=`; omitting it lists
every tenant's tokens. A caller with no resolved tenant scope at all is
rejected with `403 FORBIDDEN`.

#### POST /api/v1/registration/tokens

Create a new registration token. The response includes the full secret (`token`) and the stable `token_id` — this is the only time the secret is returned.

**Request body:** `tenant_id` (required), `controller_url` (required), `group` (optional), `expires_in` (optional), and `label` (optional). `label` is free text for operators — at most 100 characters, printable only; an over-length label or one containing control characters is rejected with `400`. It is stored as-is, returned in the create and list responses, recorded (sanitised) in the creation audit event, and is never part of the token secret or its lookup key. It cannot be edited after mint, and a rotated token does not inherit it.

**Authentication:** Required  
**Required permission:** `registration:create-token`

**Tenant scope:** the token's `tenant_id` must be within the caller's own
tenant subtree, or the request is rejected with `403 FORBIDDEN`.

#### GET /api/v1/registration/tokens/{token}

Get a specific registration token's metadata (redacted — no secret).

**Authentication:** Required  
**Required permission:** `registration:read-token`

**Tenant scope:** a token owned by another tenant returns `404` (the same
response as an unknown token), so this endpoint cannot be used to probe token
existence across tenants. Root/unscoped callers may read any token.

**Parameters:**

- `token` (path): Registration token value or `token_id`

#### DELETE /api/v1/registration/tokens/{token}

Delete a registration token.

**Authentication:** Required  
**Required permission:** `registration:delete-token`

**Tenant scope:** a token owned by another tenant returns `404` (the same
response as an unknown token) and is not deleted. Root/unscoped callers may
delete any token.

**Parameters:**

- `token` (path): Registration token value or `token_id`

#### POST /api/v1/registration/tokens/{token}/revoke

Revoke a registration token without deleting it. A revoked token remains in the store but is rejected on use. Response is redacted (no secret).

**Authentication:** Required  
**Required permission:** `registration:revoke-token`

**Tenant scope:** a token owned by another tenant returns `404` (the same
response as an unknown token) and is not revoked. Root/unscoped callers may
revoke any token.

**Parameters:**

- `token` (path): Registration token value or `token_id`

#### POST /api/v1/registration/tokens/{tenant_id}/rotate

Atomically revoke the active token(s) for a tenant (optionally scoped to `group`) and mint a replacement. The response includes the full secret of the new token — this is a mint window like create.

**Authentication:** Required  
**Required permission:** `registration:rotate-token`

**Tenant scope:** `tenant_id` must be within the caller's own tenant subtree, or
the request is rejected with `403 FORBIDDEN` before any token is minted.
Root/unscoped callers may rotate tokens for any tenant.

**Parameters:**

- `tenant_id` (path): Tenant to rotate tokens for
- `group` (body, optional): Restrict rotation to tokens in this group

#### GET /api/v1/registration/pending

List devices quarantined at registration and awaiting approval. Approved, denied, claimed and expired entries are not returned. The response is a bare JSON array.

**Authentication:** Required  
**Required permission:** `registration:list-pending`

**Tenant scope:** a tenant-scoped caller sees only its own tenant's entries; an unscoped caller sees all tenants.

Each item:

```json
{
  "pending_id": "pending-1730000000000000000",
  "steward_id": "stwd-abc123",
  "tenant_id": "acme-corp",
  "source_ip": "10.0.0.5",
  "hostname": "web-07.acme.lan",
  "key_fingerprint": "9c4a1f0e77b2d3a85c6e4f1029ab38d7e5c1f6a0b49d82e3c7f15a60d4b2e1ff",
  "registered_at": "2026-07-25T10:00:00Z"
}
```

- `hostname` — reported by the device itself and not authenticated. It is sanitised on write (control characters and `<>&"'` and backtick removed, capped at 253 characters). Treat it as a hint and render it as text.
- `key_fingerprint` — lowercase hex SHA-256 of the public key in the device's certificate signing request (DER SubjectPublicKeyInfo), computed by the controller. This is the value to verify against the device.
- Both fields are omitted for entries created before they were recorded.

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

**Listener:** Private metrics HTTPS listener only; the public product listener returns `404`

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

- `component` (path): One of `grpc_server`, `storage`, `certificate_ca`, `rbac_service`, `transport`

**Response (200):** `status` (`healthy`, `degraded` or `unhealthy`), `message`, and
`last_checked` (RFC 3339). Nothing else is returned. A component whose probe fails reports
`unhealthy` with the message `Health check failed`; the underlying error is logged, never served.

**Errors:** `404` for a component name that is not monitored.

#### GET /api/v1/monitoring/components/{component}/metrics

Metrics for a specific component.

**Listener:** Private metrics HTTPS listener only; the public product listener returns `404`

**Authentication:** Required  
**Required permission:** `monitoring:read-component-metrics`

**Parameters:**

- `component` (path): Same component names as the health endpoint

**Response (200):** the component's metrics as a JSON object (fields vary by component).

**Errors:** `404` for a component name that is not monitored; `503` when that component's
metrics are currently unavailable.

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

### Compliance

Compliance status is derived from real drift/convergence signal (DNA delta
detection), not from agent liveness. A rendered "94% compliant" means "94% of
fleet DNA matches desired state," not "94% of agents are currently connected."
Liveness/connectivity is exposed as a separate `connection_status` field on
per-steward responses so operators can distinguish "drifted but online" from
"offline."

Compliance buckets map from `DeviceStats.RiskLevel` (computed by the reports
engine): `low` → compliant, `medium` → warning, `high`/`critical` → critical.
`RiskLevel` includes a critical-event override (`criticalCount > 0` forces
Critical regardless of aggregate score) that score-only thresholds would drop.

#### GET /api/v1/stewards/{id}/compliance

Compliance status for a specific steward.

**Authentication:** Required  
**Required permission:** `steward:read-compliance`

**Tenant scope:** Non-root callers are restricted to stewards within their own tenant subtree. A request for a steward outside the caller's tenant returns 404 (not 403, to avoid disclosing steward existence across tenants).

**Parameters:**

- `id` (path): Steward ID

**Response fields:**

- `status`: compliance status derived from drift signal — `"compliant"`, `"warning"`, or `"critical"`.
- `connection_status`: liveness/connectivity state — `"online"`, `"offline"`, etc. Never used to compute `status`.
- `alert_level`: mirrors severity of `status` — `"info"`, `"warning"`, or `"critical"`.
- `last_checked`: ISO 8601 timestamp of the most recent DNA snapshot, or the last heartbeat if no snapshot exists.
- `days_until_breach`: reserved for future patch-deadline integration; currently always `0`.

**Error responses:**

- `503 Service Unavailable`: DNA data provider not yet wired (controller startup in progress).

#### GET /api/v1/stewards/{id}/compliance/report

Full compliance report for a specific steward.

**Authentication:** Required  
**Required permission:** `steward:read-compliance`

**Tenant scope:** Non-root callers are restricted to stewards within their own tenant subtree. A request for a steward outside the caller's tenant returns 404 (not 403, to avoid disclosing steward existence across tenants).

**Parameters:**

- `id` (path): Steward ID

**Response fields:**

- `status`: compliance status derived from drift signal — same semantics as the `/compliance` endpoint.
- `connection_status`: liveness/connectivity state — separate from `status`, never used to compute it.
- `missing_patches`, `days_until_breach`: reserved for future patch module integration; currently empty/zero.

**Error responses:**

- `503 Service Unavailable`: DNA data provider not yet wired.

#### GET /api/v1/compliance/summary

Fleet-wide compliance summary across all stewards.

**Authentication:** Required  
**Required permission:** `compliance:read-summary`

**Tenant scope:** Non-root callers are forced to their own tenant (and its descendant tenants) regardless of any `tenant_id` query parameter value. Root/unscoped callers may use `tenant_id` as an optional filter.

**Response fields:**

- `compliant_devices`, `warning_devices`, `critical_devices`: counts derived from drift signal, not liveness. An offline steward with no detected drift is counted as compliant.
- `by_tenant`: per-tenant breakdown using the same drift-based buckets.

**Error responses:**

- `503 Service Unavailable`: DNA data provider not yet wired.

#### GET /api/v1/compliance/tenants/{id}/devices

Per-device compliance list for one tenant — the drill-down behind a By-tenant row on the Compliance summary.

**Authentication:** Required  
**Required permission:** `compliance:read-summary`

**Parameters:**

- `id` (path): Tenant ID (a tenant path such as `root/msp-a/client-1` is accepted)
- `limit` (query, optional): Page size, 1–500, default 50
- `offset` (query, optional): Page offset, default 0

**Response fields:**

- `devices`: array of `{steward_id, hostname, status}` sorted by steward ID. `status` is `compliant`, `warning` or `critical`, derived from the drift signal exactly as in the summary.
- `total`, `limit`, `offset`: pagination envelope; `total` is the tenant's full device count.

Per-device policy deadlines and outstanding patches are on the steward's Compliance tab, not here.

**Tenant scope:** The tenant must be within the caller's scope. A tenant outside it returns `404` without disclosing whether it exists; a root caller subject to the ADR-025 crossing boundary receives the crossing challenge for a client tenant.

**Error responses:**

- `400 Bad Request`: invalid `limit` or `offset`.
- `404 Not Found`: tenant outside the caller's scope.
- `503 Service Unavailable`: DNA data provider not yet wired.

### Tenants

#### GET /api/v1/tenants

List the tenants visible to the caller.

**Authentication:** Required  
**Required permission:** `tenant:list`

Each item is the tenant record plus an additive `device_count` field: the number of
stewards in the tenant's subtree (the tenant itself and every descendant tenant visible
to the caller). Registered, active and lost stewards count, as do hidden stewards;
stewards in a terminal state (deregistered, revoked, archived, dormant) do not. Stewards
in tenants the caller cannot see are never included, so a scoped caller never counts a
sibling's stewards.

Every full row also carries `boundary: false` and `accessible: true`.

**Boundary rows.** A root-scoped caller also receives one boundary row for each MSP (a
direct child of the root tenant) it holds no active grant or break-glass crossing for.
A boundary row is marked `boundary: true`, `accessible: false` and carries only `id`,
`name`, `parent_id`, `status` (`active` or `suspended` only, never a suspension reason),
`tech_count`, `device_count` and `client_count`. `client_count` is the number of direct
client tenants of the MSP; no client is named or identified, and tenants below an MSP
never appear in the list. The row grants nothing: `GET /api/v1/tenants/{id}` on it still
returns the tenant-crossing challenge, and the row exists so break-glass has a target. An
MSP the caller holds a crossing for appears only as its full row, never also as a
boundary row. Callers that are not root-scoped never receive boundary rows.

Counts exclude stewards in a terminal state (deregistered, archived, dormant, revoked)
and disabled accounts. `tech_count` counts the MSP's accounts across its whole subtree.
The list calls the steward count `device_count`; the billing reports call the same fact
`endpoint_count`.

```json
{"success": true, "data": [
  {"id": "root", "name": "root", "status": "active", "device_count": 0, "boundary": false, "accessible": true},
  {"id": "msp-a", "name": "msp-a", "parent_id": "root", "status": "active", "boundary": true, "accessible": false, "tech_count": 4, "device_count": 214, "client_count": 12}
]}
```

#### POST /api/v1/tenants/{id}/config-source/test

Test connectivity to a tenant's config source (e.g., validate git repository access credentials before saving them).

**Authentication:** Required  
**Required permission:** `tenant:manage`

**Parameters:**

- `id` (path): Tenant ID

#### DELETE /api/v1/tenants/{id}/access-grants/{crossing_id}

End an active tenant crossing (a client-granted access grant or a break-glass elevation) early. The crossing stops granting access immediately.

**Authentication:** Required  
**Required permission:** `tenant:crossing-end` (Strong assurance; step-up challenge otherwise)

**Parameters:**

- `id` (path): Tenant that owns the crossing
- `crossing_id` (path): Crossing ID

**Who may end what:**

- A grant: an administrator of the granting tenant. A root-scoped caller never ends a grant (`403`, `ROOT_SCOPED_CANNOT_END_GRANT`).
- A break-glass crossing: the root principal that invoked it, or an administrator of the owning tenant. Any other root-scoped caller gets `403` (`NOT_CROSSING_OWNER`).

**Responses:**

- `200 OK`: the crossing after the call. Ending an already revoked or expired crossing is idempotent and returns its current state.
- `403 Forbidden`: the caller may not end this crossing.
- `404 Not Found`: unknown tenant, or the crossing does not belong to `{id}` (no disclosure which).

An audit event is recorded with the actor, crossing ID and kind (High severity for a grant, Critical for break-glass).

### Webhooks

#### POST /api/v1/webhooks/git-push

Receive a git push event from an upstream SCM and trigger a config sync. The route is always registered at server startup and returns `503 Service Unavailable` until a git-sync handler is configured via `SetGitSyncWebhookHandler()`.

**Authentication:** HMAC-SHA256 signature validation (no API key). The signature is checked by the webhook handler, not the standard auth middleware. Validation is mandatory and fails closed: a push event that matches a scope binding is synced only when `X-Hub-Signature-256` validates against that binding's configured webhook secret. A matched binding with no `webhook_secret_ref` has no credential to authenticate the caller and is rejected with the same `401` as an invalid signature — it is not webhook-triggerable and syncs on its polling interval only.

**Headers:**

- `X-Hub-Signature-256`: HMAC-SHA256 of the request body using the configured webhook secret.

**Responses:**

- `202 Accepted`: signature validated; sync triggered for one or more bindings.
- `204 No Content`: no binding matches the pushed repository and branch.
- `400 Bad Request`: unreadable or unparseable payload.
- `401 Unauthorized`: signature invalid, missing, or the matched binding has no webhook secret configured.
- `405 Method Not Allowed`: non-POST request.
- `503 Service Unavailable`: no git-sync handler wired.

### Rollback Management

Rollback endpoints are registered only when a `RollbackManager` is wired in (`SetRollbackManager()`). They are available in all deployments that include the rollback feature.

Every rollback endpoint is bounded to the caller's tenant subtree by the rollback manager, which resolves the target's owning tenant from the steward registry — the same device→tenant authority the reports endpoints use. A tenant-scoped caller receives `403 Forbidden` for a target owned outside its subtree and for a target the registry does not own at all; the response names no target, so it neither confirms nor denies the existence of another tenant's steward. `GET /api/v1/rollback/history` filters instead of failing: it returns only the operations inside the caller's subtree. A manager wired without an ownership authority fails closed — a tenant-scoped caller receives `503 Service Unavailable`, never unauthorized data. Root-scoped admin certificates are unrestricted.

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

Device selectors (`device_id`, `device_ids`, and `device_ids` in the generate request body) are the selector the report data path actually resolves, so they are authorized against the steward registry before reaching the report engine. A handler wired without a device→tenant authority fails closed: a tenant-scoped caller supplying a device selector receives 503, never unauthorized data.

#### POST /api/v1/reports/generate

Generate a report on demand.

**Authentication:** Required

**Tenant scope:** The request body's `tenant_ids` is advisory — for a non-root caller it is replaced with the caller's own tenant — and each `device_ids` entry is authorized against the caller's tenant subtree, returning 404 for a device owned by another tenant or unknown to the steward registry. Root/unscoped callers may supply any `tenant_ids`/`device_ids`.

#### GET /api/v1/reports/templates

List available report templates.

**Authentication:** Required

#### GET /api/v1/reports/templates/{template}

Get a specific report template.

**Authentication:** Required

#### GET /api/v1/reports/dashboard/overview

Dashboard overview report.

**Authentication:** Required

**Tenant scope:** Non-root callers are forced to their own tenant regardless of any `tenant_id`/`tenant_ids` query parameter, and every `device_id`/`device_ids` value is authorized against the caller's tenant subtree using the steward registry — a device owned by another tenant, or unknown to the registry, returns 404 (not 403, to avoid disclosing device existence across tenants) and the whole request is rejected rather than partially served. Root/unscoped callers may supply `tenant_id` as an optional filter and may select any device.

#### GET /api/v1/reports/dashboard/trends

Dashboard trend data.

**Authentication:** Required

**Tenant scope:** Non-root callers are forced to their own tenant regardless of any `tenant_id`/`tenant_ids` query parameter, and every `device_id`/`device_ids` value is authorized against the caller's tenant subtree using the steward registry — a device owned by another tenant, or unknown to the registry, returns 404 (not 403, to avoid disclosing device existence across tenants) and the whole request is rejected rather than partially served. Root/unscoped callers may supply `tenant_id` as an optional filter and may select any device.

#### GET /api/v1/reports/dashboard/alerts

Dashboard alert summary. Returns drift-derived alerts with per-alert acknowledgement and silence state from `AlertStore`. Actively silenced alerts (silence window still open) are excluded from the response unless `include_silenced=true` is passed.

**Authentication:** Required

**Tenant scope:** Non-root callers are forced to their own tenant regardless of any `tenant_id`/`tenant_ids` query parameter, and every `device_id`/`device_ids` value is authorized against the caller's tenant subtree using the steward registry — a device owned by another tenant, or unknown to the registry, returns 404 (not 403, to avoid disclosing device existence across tenants) and the whole request is rejected rather than partially served. Root/unscoped callers may supply `tenant_id` as an optional filter and may select any device.

**Query parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `severity` | string | `warning,critical` | Comma-separated severity filter. Valid values: `critical`, `warning`, `info`. Defaults to `warning,critical` when absent, returning both warning and critical alerts. |
| `include_silenced` | boolean | `false` | When `true`, alerts whose silence window is still open are included, with `silenced: true`. Absent or any other value keeps the default (actively silenced alerts excluded). |

**Alert identity:** Each alert row is identified by a stable `alertID` derived as `hex(SHA-256(deviceID + "|" + description))`. This ID is stable across report regenerations for the same logical alert and matches the `alertID` used by `POST /api/v1/alerts/{alertID}/acknowledge` and `POST /api/v1/alerts/{alertID}/silence`.

**Response fields per alert:**

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | string | Event timestamp |
| `device_id` | string | Steward ID of the affected device |
| `severity` | string | `critical`, `warning`, or `info` |
| `description` | string | Human-readable description of the drift event |
| `acknowledged` | boolean | Whether the alert has been acknowledged |
| `silenced` | boolean | `true` only for an actively silenced alert returned because `include_silenced=true`; otherwise `false` |
| `acknowledged_by` | string | Principal that acknowledged the alert. Present only when known |
| `silenced_by` | string | Principal that silenced the alert. Present only when known |

#### GET /api/v1/reports/compliance/status

Compliance status report.

**Authentication:** Required

**Tenant scope:** Non-root callers are forced to their own tenant regardless of any `tenant_id`/`tenant_ids` query parameter, and every `device_id`/`device_ids` value is authorized against the caller's tenant subtree using the steward registry — a device owned by another tenant, or unknown to the registry, returns 404 (not 403, to avoid disclosing device existence across tenants) and the whole request is rejected rather than partially served. Root/unscoped callers may supply `tenant_id` as an optional filter and may select any device.

#### GET /api/v1/reports/drift/summary

Configuration drift summary report.

**Authentication:** Required

**Tenant scope:** Non-root callers are forced to their own tenant regardless of any `tenant_id`/`tenant_ids` query parameter, and every `device_id`/`device_ids` value is authorized against the caller's tenant subtree using the steward registry — a device owned by another tenant, or unknown to the registry, returns 404 (not 403, to avoid disclosing device existence across tenants) and the whole request is rejected rather than partially served. Root/unscoped callers may supply `tenant_id` as an optional filter and may select any device.

### Workflow Engine

Workflow endpoints are registered only when a `WorkflowHandler` is wired in via `SetWorkflowHandler()`. All routes inherit the API subrouter's authentication middleware and each is gated by a `workflow:<action>` permission.

**Tenant scope:** A tenant-scoped caller's workflows live in its own tenant. A root-scoped caller's workflows live in the deployment's root tenant; it may select another tenant with the `tenant` query parameter (`?tenant=<id>`) on any workflow route, and a client tenant selected that way requires an active tenant crossing (`401` with `WWW-Authenticate: ... required="tenant-crossing"` otherwise; `404` for an unknown tenant). When no root tenant can be resolved, a root-scoped request without `?tenant=` returns `400`. An execution runs under the tenant its workflow was resolved in, so its tenant-scoped steps (script dispatch, config writes) act on that tenant's own devices only. The crossing is checked when the execution starts; an execution already running continues to completion if the crossing expires meanwhile, and later requests for that tenant are challenged again.

**Composed workflows:** a nested `workflow` step, a step's `error_workflow` and a composite component reference another workflow by `workflow_name`, which resolves to the latest version stored in the executing tenant — never another tenant's workflow. A definition that references a workflow by `workflow_path` is refused with `400`; the controller never loads workflow definitions from its filesystem.

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
  "variables": { "target_group": "staging" },
  "inputs": { "environment": "prod" }
}
```

`inputs` supplies values for the workflow's declared `inputs` (see
[Workflow Engine](../architecture/workflow-engine.md)); they are merged with
`variables`, and an input wins on a name clash.

**Response:** `202 Accepted`

```json
{
  "execution_id": "exec-abc123",
  "workflow_name": "patch-linux-fleet",
  "status": "running",
  "start_time": "2026-07-07T12:00:00Z"
}
```

**Response:** `400 Bad Request` when the supplied inputs violate the workflow's
declared inputs. No execution is started. Each entry in `fields` names the
input and the rule it broke; the supplied value is never echoed.

```json
{
  "error": "invalid workflow inputs",
  "fields": [
    { "field": "host", "message": "is required" },
    { "field": "environment", "message": "must be one of the declared options" }
  ]
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

### Validate a Workflow

#### POST /api/v1/workflows/validate

Validate a workflow definition without saving or running it. The body has the same shape as workflow create. Requires `workflow:read`; no step-up is needed. Returns `200 OK` for any well-formed body, with every issue found rather than only the first. Caller-supplied values echoed in messages are truncated.

**Response:** `200 OK`

```json
{
  "valid": false,
  "issues": [
    {"path": "steps[1].config", "step_name": "install", "message": "config is required for task steps"}
  ]
}
```

An approval step nested inside a parallel, loop, try, switch or conditional block is reported at its own path with "approval steps must be top-level". A valid definition returns `{"valid": true, "issues": []}`. A body that is not valid JSON returns `400 Bad Request`.

### Workflow Approvals

An approval step suspends a run until an operator decides it. Both endpoints are scoped to the caller's tenant, resolved as for the workflow endpoints; an approval in another tenant is indistinguishable from an unknown ID and returns `404`.

#### GET /api/v1/workflows/approvals

List the caller's tenant's pending approvals, oldest first. Requires `workflow:read`.

**Response:** `200 OK`

```json
{
  "approvals": [
    {
      "approval_id": "appr-exec-123-gate",
      "workflow_name": "deploy-prod",
      "execution_id": "exec-123",
      "step_id": "gate",
      "step_name": "gate",
      "message": "ship it?",
      "approver_permission": "workflow:approve",
      "requested_by": "alice",
      "status": "pending",
      "requested_at": "2026-07-07T12:00:00Z",
      "expires_at": "2026-07-07T13:00:00Z"
    }
  ],
  "total": 1
}
```

#### POST /api/v1/workflows/approvals/{approval_id}/decision

Approve or reject a pending approval. Approving resumes the suspended run; rejecting fails it.

**Authentication:** Required. The `workflow:approve` permission requires strong assurance: a caller below it receives `401` with a `WWW-Authenticate: CFGMS-StepUp` challenge. If the approval step names an `approver_permission`, the caller must also hold that permission.

**Request:**

```json
{
  "decision": "approve",
  "justification": "change window confirmed"
}
```

`decision` is `approve` or `reject`.

**Response:** `200 OK`

```json
{
  "approval_id": "appr-exec-123-gate",
  "decision": "approve",
  "execution_id": "exec-123",
  "resumed": true,
  "execution_status": "running"
}
```

`resumed` is `false` when the decision was recorded but the resume could not start immediately; engine recovery resumes it.

**Error responses:**

- `400 Bad Request` — `decision` is not `approve` or `reject`
- `401 Unauthorized` — step-up required
- `403 Forbidden` — the caller lacks the step's `approver_permission`, or started the run (`code: SELF_APPROVAL`)
- `404 Not Found` — no such approval in the caller's tenant
- `409 Conflict` — the approval was already decided or has expired

Every decision writes a `workflow.approval_decided` audit event recording the principal, approval, decision and justification.

### Workflow Triggers

Trigger endpoints manage scheduled and event-driven workflow execution. The `/triggers` subrouter is registered alongside `/workflows` when a `WorkflowHandler` is wired in (`server.go:717`). All routes inherit the API subrouter's authentication middleware. Trigger types: `schedule`, `webhook`, `siem`, `manual`.

**Tenant scope (applies to every endpoint below):** every trigger operation is
scoped strictly to one resolved tenant, resolved exactly as for the workflow
endpoints: a tenant-scoped caller's own tenant; for a root-scoped caller the
deployment's root tenant, or a tenant selected with `?tenant=<id>`, which for a
client tenant requires an active tenant crossing (`401` challenge otherwise).
There is no all-tenants view. A trigger runs its workflow from the same tenant,
and the execution acts on that tenant's devices only. Triggers persist in the
controller's trigger store (credentials in the secret store) and survive a
restart. `POST /api/v1/triggers` always stores the trigger under the
resolved tenant; a `tenant_id` in the request body is accepted but ignored
(overwritten server-side) — the example bodies below show it only because the
field is echoed back, not because it is honoured. `GET /api/v1/triggers`
returns only the caller's own tenant's triggers; the `tenant_id` query
parameter narrows further within that set — an exact match, not a path prefix
— and can never broaden it to another tenant. Every other operation
(`GET`/`PUT`/`DELETE /{id}`, `.../enable`, `.../disable`, `.../execute`,
`.../executions`) treats a trigger outside the caller's tenant identically to
an unknown ID and returns `404`. A request with no resolved tenant at all is
rejected outright on create/list; per-ID operations simply match no trigger.

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
fragments. **This API is eventually consistent**: it reflects whatever `cluster:<name>`
DNA fragments were last published by each steward's `DNARefreshLoop` ticker (default
30 minutes, configurable via `DNARefreshInterval`). A cluster topology change — a new
member node, a role ownership transfer — can take up to one refresh interval to appear
in these endpoints. This is acceptable because no safety-critical behavior (no-duplicate-VM
enforcement, owner-gated lifecycle actions) depends on this registry; those operations gate
off live PowerShell queries on every convergence tick, not off this read API.

#### GET /api/v1/clusters

List all clusters visible to the authenticated caller. Clusters are derived by decoding
the `cluster:<name>` fragments in each steward's `DNA.Fragments` (ADR-017). Only clusters
whose member stewards belong to the caller's tenant (or a descendant tenant) are returned.

**Required permission:** `cluster:list`

**Tenant scoping:** Caller's tenant from the authenticated context limits which stewards'
DNA is scanned. An admin mTLS principal (empty tenant) has no scope restriction and sees
all clusters.

**Response:**

```json
{
  "data": [
    {
      "name": "example-cluster",
      "members": ["steward-a", "steward-b"],
      "role_owners": {
        "csv": "HV-HOST-01",
        "cno": "HV-HOST-02"
      }
    }
  ],
  "timestamp": "2026-07-08T12:00:00Z"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Cluster name from the `cluster:<name>` DNA fragment ID |
| `members` | []string | Sorted steward IDs whose DNA carries a `cluster:<name>` fragment |
| `role_owners` | object | Map of role name → owner node, from the fragment's `resource_owner` field |

#### GET /api/v1/clusters/{name}

Get the registry entry for a single named cluster.

Returns 404 when the cluster does not exist or all its member stewards are outside
the caller's tenant scope. 404 (not 403) is used to avoid disclosing cluster existence
across tenant boundaries.

**Required permission:** `cluster:read`

**Parameters:**

- `name` (path): Cluster name (e.g., `example-cluster`)

**Response (200):**

```json
{
  "data": {
    "name": "example-cluster",
    "members": ["steward-a", "steward-b"],
    "role_owners": {
      "csv": "HV-HOST-01",
      "cno": "HV-HOST-02"
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
"should exist" side) with the `resource_owner` field of the `cluster:<name>` DNA
fragments published by member stewards (the "does exist" side).

Returns 404 under the same conditions as `GET /api/v1/clusters/{name}`.

**Required permission:** `cluster:read`

**Parameters:**

- `name` (path): Cluster name (e.g., `example-cluster`)

**Response (200):**

```json
{
  "data": {
    "cluster_name": "example-cluster",
    "resources": [
      {
        "role_name": "csv",
        "status": "present-with-live-owner",
        "owner_id": "HV-HOST-01"
      },
      {
        "role_name": "vm2",
        "status": "declared-but-missing"
      },
      {
        "role_name": "cno",
        "status": "orphan-dead-owner",
        "owner_id": "HV-HOST-02"
      },
      {
        "role_name": "dfs",
        "status": "split-brain",
        "all_owner_claims": ["HV-HOST-01", "HV-HOST-02"]
      }
    ],
    "alerts": [
      {
        "id": "example-cluster/vm2/declared-but-missing",
        "severity": "critical",
        "title": "Cluster role not created",
        "metric_name": "cluster_role_missing",
        "status": "active"
      }
    ],
    "components": {
      "example-cluster/csv": { "name": "example-cluster/csv", "status": "healthy", "message": "owner is live" },
      "example-cluster/vm2": { "name": "example-cluster/vm2", "status": "unhealthy", "message": "declared but not created" }
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

### Entity Graph

Read-only access to the entity graph (ADR-022/ADR-023): the accumulation point for
every typed entity, relationship, observation history, drift record, and change
event CFGMS knows about. This is the model surface the Web UI renders and the
external integration surface for the twin.

**Response format differs from the rest of this API.** These endpoints return the
requested object directly as the JSON body (no `data`/`timestamp` envelope), and
error bodies are plain text (no `error.code` envelope) — the response and error
formats documented under [Response Format](#response-format) do not apply here.

**Tenant scoping and non-disclosure (ADR-022 §7):** every handler derives the
caller's tenant subtree from the authenticated session (`X-API-Key`/Bearer token),
never from a request parameter. A read for an entity, edge, history record, diff,
timeline event, or drift record outside the caller's tenant subtree returns
**404, not 403** — cross-tenant existence is not disclosed. For endpoints whose
provider method takes no tenant parameter (`GetHistory`, `Diff`, `GetNeighborhood`,
`GetTimeline`, `GetDriftState`), the handler performs a `GetEntity` access check
against the root/subject EID before calling the provider.

**Entity ID (EID) format:** `authority_type:authority_name[/local_id]`, e.g.
`host:SRV-001` or `host:SRV-001/disk0`. Path segments use `{eid:.+}` so
an EID containing `/` is matched in full; URL-encode the EID when building request
paths from untrusted input.

**Required permission** for every endpoint below is `entity:list` (collection
endpoints) or `entity:read` (single-entity and sub-resource endpoints).

#### GET /api/v1/entities

List entities matching a filter, paginated.

**Required permission:** `entity:list`

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `kind` | string | Filter by entity kind (e.g. `steward`, `service`) |
| `text_query` | string | Free-text match against entity attributes |
| `as_of` | RFC 3339 | Project entity state as of this timestamp |
| `page_token` | string | Opaque continuation cursor from a prior response's `NextToken` |
| `page_size` | int | 1–1000 (default provider-defined); 400 if out of range |

**Response (200):** `EntityPage`

```json
{
  "Entities": [
    { "Entity": { "EID": "host:SRV-001", "Kind": "host", "Attributes": {}, "OwningTenant": "root/msp-a" },
      "Sources": [], "Freshness": { "ObservedAt": "2026-08-08T10:00:00Z", "RecordedAt": "2026-08-08T10:00:01Z", "Stale": false },
      "CollapseGroup": null }
  ],
  "NextToken": ""
}
```

Tenant scoping: only entities in the caller's tenant subtree are returned; an
admin mTLS principal (empty tenant) sees all entities.

#### GET /api/v1/entities/{eid}

Get the current state, provenance, and freshness for a single entity.

**Required permission:** `entity:read`

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `as_of` | RFC 3339 | Project entity state as of this timestamp |
| `collapse_group` | `true` | Include the merged same-as group view (`CollapseGroup`) |

**Response (200):** `EntityView` (see example fields above)

**Error responses:**

| Status | Condition |
|--------|-----------|
| 400 | Malformed EID, or `as_of` not RFC 3339 |
| 404 | Entity does not exist, or is outside the caller's tenant subtree |

#### GET /api/v1/entities/{eid}/edges

List edges attached to an entity.

**Required permission:** `entity:read`

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `edge_type` | string, repeatable | Filter by edge type (e.g. `?edge_type=contains&edge_type=runs-on`) |
| `source` | string | Filter by asserting source identity |
| `direction` | `outbound` \| `inbound` | Which side of the edge `{eid}` occupies (default `outbound`: edges where `{eid}` is `From`) |

**Response (200):** `[]EdgeView`, each `{ "Edge": {...}, "Freshness": {...} }`

This endpoint does not pre-check entity existence — an unknown or cross-tenant
`{eid}` returns an empty list (`[]`), not 404, because `GetEdges` filters by the
EID's `owning_tenant` at the storage layer.

#### POST /api/v1/entities/edges

Assert a manual operator edge (e.g. a `depends-on` relationship) through the
standard observation path — no privileged side door (ADR-022 §9). The edge is
recorded as an ordinary provenanced observation sourced
`operator-assertion:<caller>` and is readable through `GET /api/v1/entities/{eid}/edges`
like any other source's edges.

**Required permission:** `entity:write`

**Request body:**

```json
{
  "edge_type": "depends-on",
  "from_eid": "host:SRV-001",
  "to_eid": "host:SRV-002",
  "attributes": {}
}
```

| Field | Type | Description |
|-------|------|-------------|
| `edge_type` | string | A known taxonomy edge kind, or an open `related:<discriminator>` subtype (ADR-022 §2). Must not contain `\|`. |
| `from_eid` | string | Source endpoint EID. Must parse and resolve within the caller's tenant subtree. |
| `to_eid` | string | Target endpoint EID. Must parse and resolve within the caller's tenant subtree. |
| `attributes` | object | Optional opaque edge attributes. Provider-reserved metadata keys (`tenant_path`, `owning_tenant`, `entity_kind`, `hostname`, `mac_addrs`, `machine_sid`, `dir_object_guid`, `serial_number`, `cloud_object_id`) are rejected. |

**Response (201):** empty body.

**Error responses:**

| Status | Condition |
|--------|-----------|
| 400 | Malformed request body, invalid `edge_type` (unknown kind, not a `related:*` subtype, or contains `\|`), reserved attribute key present, or either EID fails to parse |
| 404 | `from_eid` or `to_eid` does not exist, or is outside the caller's tenant subtree (ADR-022 §7 — not 403, to avoid disclosing cross-tenant existence) |
| 503 | Entity graph provider unavailable |

Tenant scoping: both endpoint EIDs are resolved against the caller's tenant
subtree before the edge is written; a cross-tenant `from_eid` or `to_eid`
returns 404 with no partial write, matching the read-path convention above.

#### GET /api/v1/entities/{eid}/neighborhood

Depth-bounded connected subgraph starting at `{eid}`.

**Required permission:** `entity:read`

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `depth` | int | 1–3 (default 1); 400 outside this range — access-contract cap (ADR-022 §9) |
| `direction` | `outbound` \| `inbound` \| `both` | Traversal direction (default `outbound`) |
| `edge_type` | string, repeatable | Restrict traversal to these edge types |

**Response (200):** `Neighborhood`

```json
{ "Root": "host:SRV-001", "Nodes": [ { "EID": "host:SRV-001", "Kind": "host", "Attributes": {}, "OwningTenant": "root/msp-a" } ], "Edges": [] }
```

**Error responses:**

| Status | Condition |
|--------|-----------|
| 400 | Malformed EID, `depth` out of 1–3, or invalid `direction` |
| 404 | Root entity does not exist, or is outside the caller's tenant subtree |

#### GET /api/v1/entities/{eid}/history

Versioned observation log for an entity over a time range.

**Required permission:** `entity:read`

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `from` | RFC 3339 (required) | Range start |
| `to` | RFC 3339 (required), must be after `from` | Range end |

**Response (200):** `[]ObservationRecord`, each `{ "Observation": {...}, "Version": 3 }`

**Error responses:**

| Status | Condition |
|--------|-----------|
| 400 | Malformed EID, or `from`/`to` missing, malformed, or `to` not after `from` |
| 404 | Entity does not exist, or is outside the caller's tenant subtree |

#### GET /api/v1/entities/{eid}/diff

Attribute-level delta between two points in time for an entity (ADR-022 §5).

**Required permission:** `entity:read`

**Query parameters:** same as `/history` (`from`, `to`, both required RFC 3339).

**Response (200):** `StateDiff`

```json
{
  "Subject": "host:SRV-001",
  "T1": "2026-08-01T00:00:00Z",
  "T2": "2026-08-08T00:00:00Z",
  "Changes": [
    { "Attribute": "os_version", "Before": "10.0.19045", "After": "10.0.22631", "Source": "enforcing-module:os-info" }
  ]
}
```

**Error responses:** same as `/history`.

#### GET /api/v1/entities/timeline

Merged change-event stream across one or more entities.

**Required permission:** `entity:list`

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `eid` | string, repeatable, required | Subject EID(s); at least one required |
| `from` | RFC 3339 (required) | Range start |
| `to` | RFC 3339 (required), must be after `from` | Range end |

**Response (200):** `[]TimelineEvent`, each `{ "Subject": "...", "OccurredAt": "...", "Kind": "state-change", "Detail": {} }`

Each `eid` is access-checked individually before the timeline is fetched: if
**any** requested EID does not exist or is outside the caller's tenant subtree,
the whole request returns 404 and no data for the other EIDs is disclosed.

**Error responses:**

| Status | Condition |
|--------|-----------|
| 400 | No `eid` given, a malformed `eid`, or `from`/`to` missing, malformed, or out of order |
| 404 | Any requested `eid` does not exist, or is outside the caller's tenant subtree |

#### GET /api/v1/entities/{eid}/drift

Persisted desired-vs-actual drift record for one entity (ADR-022 §6).

**Required permission:** `entity:read`

**Response (200):** `DriftState`

```json
{
  "EID": "host:SRV-001",
  "DetectedAt": "2026-08-08T09:00:00Z",
  "Fields": [
    { "Attribute": "firewall.enabled", "Desired": true, "Actual": false, "Matching": false }
  ],
  "ConfigRevision": "a1b2c3d",
  "LifecycleStatus": "detected"
}
```

**Error responses:**

| Status | Condition |
|--------|-----------|
| 400 | Malformed EID |
| 404 | Entity does not exist, is outside the caller's tenant subtree, or has no drift record |

#### GET /api/v1/entities/drifted

List entities with active drift matching a filter.

**Required permission:** `entity:list`

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `lifecycle_status` | `detected` \| `acknowledged` \| `resolved` \| `ignored` | 400 if any other value |
| `kind` | string | Filter by entity kind |

**Response (200):** `[]DriftState` (see `/drift` example above for shape)

Tenant scoping: only drift records for entities in the caller's tenant subtree
are returned.

## Internal Test Endpoints (not for external use)

Three routes exist solely for integration-test setup and carry no normal
authentication. They are not reachable in a production build — not because of
policy, but because of five controls that must all hold simultaneously:

- `PUT /api/v1/test/stewards/{id}/config`
- `PUT /api/v1/test/stewards/{id}/status`
- `GET /api/v1/test/audit/count`

1. **Build tag.** The routes are registered only in
   `features/controller/api/test_endpoints_enabled.go`, gated by
   `//go:build cfgms_test_endpoints`.
2. **Paired negative-tag file.** `features/controller/api/test_endpoints_disabled.go`
   carries the inverse tag (`//go:build !cfgms_test_endpoints`) and defines
   `registerTestRoutes` as a no-op. The default build of every binary compiles
   this file, not the one above, so the handlers do not exist in the compiled
   binary at all — not merely disabled at runtime.
3. **Environment gate.** Even in a binary built with the tag, each request is
   checked at runtime against `CFGMS_ENABLE_TEST_ENDPOINTS`; unset, or set to
   anything other than exactly `"true"`, returns a rejection instead of
   invoking the handler.
4. **Test-only wrapper.** The config/status routes are wrapped by a `testOnly`
   closure (in `test_endpoints_enabled.go`) that performs the environment
   check before delegating to the real handler; `handleTestSetStewardStatus`
   independently re-checks the same variable as defense-in-depth.
5. **Absent from release build targets.** No production `go build` or Docker
   build in this repository passes `-tags cfgms_test_endpoints`. The only
   places that set it are `docker-compose.test.yml` (a test-only compose file)
   and the `test-fast` Makefile target's `go vet` step, which vets the
   tag-gated code for compile errors without producing a binary.
   `cmd/controller/Dockerfile`'s `GO_BUILD_TAGS` build argument defaults to
   empty and is not overridden by any release or CI image-build workflow.

`registerTestRoutes(s)` is called unconditionally from `server.go`; which of
the two build-tag files above satisfies that call — the real registrations or
the no-op — is decided entirely at compile time, before the binary exists.

## Error Codes

| Code | Description |
|------|-------------|
| `MISSING_API_KEY` | API key not provided |
| `NO_TENANT_SCOPE` | The credential is neither root nor bound to a tenant |
| `TENANT_MISMATCH` | A `tenant_id` filter names a tenant outside the caller's scope |
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
- Store it in a cloud-synced folder (any provider that mirrors local files to a
  remote drive).
- Store it in a Windows roaming profile — it will be transmitted to every machine
  you log into.
- Email it, paste it into a chat tool, or store it in a secrets manager that logs
  values (only use secret managers with envelope encryption and audit-only access
  logs).

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

Web accounts are browser-based admin principals authenticated via WebAuthn passkeys (Issue #2993 / ADR-021 Amendment 1) — human web login has no password credential. They are RBAC-equivalent to API-key principals — they carry explicit `permissions` and a tenant scope, and are not implicit global admins.

#### Passkey login finish response

`POST /api/v1/web/passkey/login/finish` issues the web session as HttpOnly cookies. The response body (inside the standard `data` envelope) identifies the principal and reports when the session ends:

```json
{
  "data": {
    "ok": true,
    "username": "admin@msp-a",
    "tenant_id": "root/msp-a",
    "root_scope": false,
    "expires_at": "2026-10-08T04:00:00Z"
  }
}
```

`expires_at` (RFC 3339) is the session's absolute expiry. The browser cannot read the HttpOnly session cookie, so this field is how the web UI shows the time remaining. It is informational only — the server enforces expiry. The body never contains the session or CSRF token.

#### Tenant scope

Each web account has exactly one of:

| Field | Meaning |
|-------|---------|
| `root_scope: true` | Account sees all tenants' data (subtree-inclusive from root). `tenant_id` is empty. |
| `tenant_id: "root/msp-a"` | Account sees only the `root/msp-a` subtree. `root_scope` is false. |
| neither | Account defaults to `"default"` tenant on creation. |

`root_scope` and `tenant_id` are mutually exclusive — supplying both returns `400 INVALID_SCOPE`. An empty `tenant_id` alone **never** grants root scope; `root_scope: true` must be set explicitly (defense-in-depth).

#### POST /api/v1/accounts

Create a new web admin account, or reset an existing one (upsert: omitted `tenant_id`/`permissions` retained from the existing record). This endpoint provisions the account identity and scope only — there is no password. Passkey credentials are enrolled separately via the WebAuthn registration ceremony (Issue #2782).

A newly created account (or one reset back to zero registered passkeys) has no
credentials yet, so the response also mints a single-use, TTL-bounded
**enrollment magic link** that the account's first passkey enrollment redeems
(Issue #2974). Resetting an account that already holds passkeys does not mint
a new link.

**Authentication:** Required  
**Required permission:** `account:create`  
**Assurance:** Strong session (passkey or elevated mTLS) required

**Tenant scope:** both the account being replaced (on reset) and the requested
destination scope must be within the caller's own tenant subtree — a tenant-scoped
caller receives `403 FORBIDDEN` targeting a username outside its subtree, or
requesting `root_scope: true` (root scope is inside no tenant-scoped caller's
subtree). An account created with neither `root_scope` nor `tenant_id` belongs to the
caller's own tenant. Root callers may create or reset any account, subject to the
tenant-crossing boundary (see [Tenant Scope](#tenant-scope)).

**Permission ceiling:** the caller must itself hold every permission in the account's
*resulting* permission set, or the request is refused with `403 PERMISSION_ESCALATION`.
Because this endpoint is an upsert, that set is the retained one when `permissions` is
omitted on a reset — so a caller cannot reset an account more privileged than itself
and collect the enrollment link for it. Checked independently of the tenant check.

**Request body:**

```json
{
  "username": "alice",
  "root_scope": true,
  "permissions": ["steward:list", "steward:read"]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `username` | string | 3–64 chars, starting alphanumeric, then `[a-zA-Z0-9._-]` |
| `root_scope` | bool | Grant cross-tenant root scope. Mutually exclusive with `tenant_id`. |
| `tenant_id` | string | Scope account to this tenant subtree. Mutually exclusive with `root_scope`. |

A root-scope account belongs to the deployment's root tenant (the single tenant with no
parent): responses report that tenant's ID in `tenant_id` alongside `root_scope: true`.
Root authority comes only from `root_scope`; an empty tenant never means root.
| `permissions` | array | Permission IDs (e.g. `"steward:list"`). Unknown IDs are rejected. |

**Response (201 Created or 200 OK on reset):**

```json
{
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "username": "alice",
    "tenant_id": "root",
    "root_scope": true,
    "permissions": ["steward:list", "steward:read"],
    "created_at": "2026-01-12T10:30:00Z",
    "has_outstanding_enrollment_link": true,
    "enrollment_magic_link": "<160-bit random token, opaque string>"
  },
  "timestamp": "2026-01-12T10:30:00Z"
}
```

Root-scoped accounts have `tenant_id: ""` and `root_scope: true` in the response. Tenant-scoped accounts have a non-empty `tenant_id` and `root_scope: false`.

| Field | Type | Description |
|-------|------|-------------|
| `data.has_outstanding_enrollment_link` | bool | True when the account has an unredeemed, unexpired, unrevoked enrollment link. |
| `data.enrollment_magic_link` | string | The raw enrollment token. Present **only** in this response, when a link was minted (zero-credential account) — omitted otherwise. The server stores only a SHA-256 hash of this value and never returns or logs the raw token again; the admin UI shows it once for copy-to-clipboard handoff. Single-use and expires 72 hours after minting. |

#### POST /api/v1/accounts/{username}/enrollment-link/revoke

Revoke an outstanding (unredeemed) enrollment magic link, invalidating it before
it can be used — for a wrong recipient, a departed employee, or a suspected leak
(Issue #2974). Does not delete or otherwise modify the account itself.

**Authentication:** Required  
**Required permission:** `account:revoke-enrollment-link`  
**Assurance:** Strong session (passkey or elevated mTLS) required

Callers are authorized only within their own tenant subtree: a caller scoped to
a tenant that does not contain the target account's tenant receives `403
FORBIDDEN`, checked before the link's outstanding/expired state is evaluated so
an out-of-subtree caller cannot use this endpoint to probe an account's
enrollment status.

**Parameters:**

- `username` (path): Username of the account whose enrollment link should be revoked

**Response (200 OK):**

```json
{
  "data": {
    "username": "alice",
    "revoked": true
  },
  "timestamp": "2026-01-12T10:30:00Z"
}
```

**Errors:**

| Status | Code | Condition |
|--------|------|-----------|
| 403 | `FORBIDDEN` | Caller's tenant scope does not contain the account's tenant |
| 404 | `ACCOUNT_NOT_FOUND` | No account with that username |
| 409 | `NO_OUTSTANDING_LINK` | No unredeemed, unexpired, unrevoked link exists for this account |

#### GET /api/v1/accounts

List all web admin accounts. No credential material (registered passkey public keys) is included.

**Authentication:** Required  
**Required permission:** `account:list`

**Tenant scope:** a scoped caller sees only accounts within its own tenant
subtree (filtered silently — out-of-subtree accounts are simply omitted, not
rejected). Root/unscoped callers see every tenant's accounts.

**Roles:** each item carries `roles`, the names of the RBAC roles bound to the
account (an empty array when it holds none). Roles are resolved per returned
account and only for callers holding `rbac:list-subject-roles` — the permission
that gates `GET /api/v1/rbac/subjects/{id}/roles`. Without it the `roles` field is
omitted and the list still succeeds.

**Response:**

```json
{
  "data": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "username": "alice",
      "tenant_id": "root",
      "root_scope": true,
      "permissions": ["steward:list", "steward:read"],
      "roles": ["fleet-admin"],
      "created_at": "2026-01-12T10:30:00Z"
    },
    {
      "id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
      "username": "bob",
      "tenant_id": "root/msp-a",
      "root_scope": false,
      "permissions": ["steward:list"],
      "roles": [],
      "created_at": "2026-01-10T08:00:00Z"
    }
  ],
  "timestamp": "2026-01-12T10:30:00Z"
}
```

#### PUT /api/v1/accounts/{username}

Update an existing web admin account. All request fields are optional — omitted
fields retain their existing values, allowing independent update of permissions,
disabled state, and credentials.

**Authentication:** Required  
**Required permission:** `account:update`  
**Assurance:** Strong session required

**Tenant scope:** an account owned by another tenant returns `404 ACCOUNT_NOT_FOUND`
(not `403`) — the same response as an unknown username, so this endpoint cannot be
used to probe for account existence across tenants. Root/unscoped callers may update
any account. A caller may also only grant a `permissions` entry it itself holds —
independent of the tenant check.

**Request body:**

```json
{
  "permissions": ["steward:list", "steward:read"],
  "disabled": false,
  "reset_credentials": false
}
```

**Response (200 OK):** the updated `AccountInfo`, plus `enrollment_magic_link` when
`reset_credentials: true` minted a fresh one.

#### POST /api/v1/accounts/{username}/certs/bind

Bind an mTLS admin certificate to the account by serial number. The serial is the binding and lookup key — it matches what `extractAdminPrincipal` already checks via `certManager.IsRevoked(serial)` on every mTLS admin request.

**Authentication:** Required  
**Required permission:** `cert-binding:bind`  
**Assurance:** Strong session required

**Tenant scope:** the target account must be within the caller's own tenant
subtree, checked after confirming the account exists — an unknown username
returns `404 ACCOUNT_NOT_FOUND` first, an existing but out-of-subtree account
returns `403 FORBIDDEN`. Root/unscoped callers may bind a certificate to any
account.

**Parameters:**

- `username` (path): Username of the account to bind the certificate to

**Request body:**

```json
{
  "serial": "3a:2f:…",
  "fingerprint": "sha256:abc123…",
  "label": "primary laptop bundle"
}
```

- `serial` (required): Certificate serial number (the binding key).
- `fingerprint` (optional): Certificate fingerprint for audit correlation.
- `label` (optional): Admin-supplied free text description.

**Response (201 Created):**

```json
{
  "data": {
    "serial": "3a:2f:…",
    "fingerprint": "sha256:abc123…",
    "label": "primary laptop bundle",
    "bound_at": "2026-01-12T10:30:00Z"
  },
  "timestamp": "2026-01-12T10:30:00Z"
}
```

**Errors:**

| Status | Code | Condition |
|--------|------|-----------|
| 400 | `MISSING_SERIAL` | `serial` is absent from the request body |
| 404 | `ACCOUNT_NOT_FOUND` | No account with that username |
| 409 | `SERIAL_CONFLICT` | Serial is already bound to this or a different account |

#### GET /api/v1/accounts/{username}/certs

List all mTLS admin certificates bound to the account. Returns public metadata only — no private key material is ever stored.

**Authentication:** Required  
**Required permission:** `cert-binding:list`

**Tenant scope:** same rule as bind above — an unknown username returns
`404 ACCOUNT_NOT_FOUND`; an existing but out-of-subtree account returns
`403 FORBIDDEN`. Root/unscoped callers may list any account's bound
certificates.

**Parameters:**

- `username` (path): Username of the account to list certificates for

**Response (200 OK):**

```json
{
  "data": [
    {
      "serial": "3a:2f:…",
      "fingerprint": "sha256:abc123…",
      "label": "primary laptop bundle",
      "bound_at": "2026-01-12T10:30:00Z"
    }
  ],
  "timestamp": "2026-01-12T10:30:00Z"
}
```

Returns an empty array when no certificates are bound.

#### POST /api/v1/accounts/{username}/certs/revoke/{serial}

Remove a certificate binding from the account **and** revoke the certificate via `certManager.Revoke(serial)` in the same operation. A certificate cannot be left unbound from every account while still able to authenticate — the two steps are always coupled.

**Authentication:** Required  
**Required permission:** `cert-binding:revoke`  
**Assurance:** Strong session required

**Tenant scope:** same rule as bind above — an unknown username returns
`404 ACCOUNT_NOT_FOUND`; an existing but out-of-subtree account returns
`403 FORBIDDEN`. Root/unscoped callers may revoke a binding on any account.

**Parameters:**

- `username` (path): Username of the account
- `serial` (path): Serial number of the certificate to revoke

**Response (200 OK):**

```json
{
  "data": {
    "username": "alice",
    "serial": "3a:2f:…",
    "revoked": true
  },
  "timestamp": "2026-01-12T10:30:00Z"
}
```

**Errors:**

| Status | Code | Condition |
|--------|------|-----------|
| 404 | `ACCOUNT_NOT_FOUND` | No account with that username |
| 404 | `BINDING_NOT_FOUND` | No binding for that serial on this account |

#### POST /api/v1/accounts/{username}/certs/rotate/{old_serial}

Atomically bind a new certificate and revoke the old one as a single resumable operation. The operation is safe to retry: if interrupted after binding the new certificate but before revoking the old one, the account temporarily holds two valid credentials; a repeated call with the same arguments completes the revocation without re-binding or erroring. A repeated call after a fully completed rotation is also idempotent (returns 200, no duplicate binding, no second revocation attempt).

**Authentication:** Required  
**Required permission:** `cert-binding:rotate`  
**Assurance:** Strong session required

**Tenant scope:** same rule as bind above — an unknown username returns
`404 ACCOUNT_NOT_FOUND`; an existing but out-of-subtree account returns
`403 FORBIDDEN`. Root/unscoped callers may rotate a binding on any account.

**Parameters:**

- `username` (path): Username of the account whose certificate is being rotated
- `old_serial` (path): Serial number of the certificate to revoke

**Request body:**

```json
{
  "serial": "new-certificate-serial",
  "fingerprint": "sha256:newcertfingerprint…"
}
```

- `serial` (required): Serial number of the new certificate to bind (must differ from `old_serial`).
- `fingerprint` (optional): New certificate fingerprint for audit correlation.

**Response (200 OK):**

```json
{
  "data": {
    "username": "alice",
    "old_serial": "old-serial-value",
    "new_serial": "new-serial-value",
    "rotated": true
  },
  "timestamp": "2026-01-12T10:30:00Z"
}
```

**Resumability:** The two-phase sequence is bind-new-then-revoke-old. A partial failure between the two steps leaves both certificates valid (no lockout window). A repeated call with the same arguments completes step 2 without re-doing step 1.

**Errors:**

| Status | Code | Condition |
|--------|------|-----------|
| 400 | `MISSING_SERIAL` | `serial` (new certificate) is absent from the request body |
| 400 | `SERIAL_UNCHANGED` | `serial` (new) equals `old_serial` (old) |
| 404 | `ACCOUNT_NOT_FOUND` | No account with that username |
| 404 | `BINDING_NOT_FOUND` | `old_serial` is not bound to this account and the new serial is also not yet bound (not a valid rotation call) |
| 409 | `SERIAL_CONFLICT` | New certificate serial is already bound to a different account |
| 503 | `CERT_MANAGER_UNAVAILABLE` | Certificate management is not configured; the old certificate cannot be revoked |

#### DELETE /api/v1/accounts/{username}

Delete a web admin account. Removes both the in-memory cache entry and the durable secret-store record.

**Authentication:** Required  
**Required permission:** `account:delete`  
**Assurance:** Strong session required

**Tenant scope:** an account owned by another tenant returns `404 ACCOUNT_NOT_FOUND`
(not `403`) — the same response as an unknown username, so this endpoint cannot be
used to probe for account existence across tenants. Root/unscoped callers may
delete any account.

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

Returns `404 ACCOUNT_NOT_FOUND` if the account does not exist.

## Alerts

Server-side durable state for alert acknowledgement and silencing. Alert records are created on first write (upsert semantics) — a pre-existing alert-manager record is not required.

**Required permission:** `alert:acknowledge` (acknowledge), `alert:silence` (silence) or `alert:unsilence` (unsilence)  
**Assurance:** Any for acknowledge; Strong for silence and unsilence.

#### POST /api/v1/alerts/{id}/acknowledge

Record that an alert has been acknowledged by the calling principal.

**Authentication:** Required  
**Required permission:** `alert:acknowledge`  
**Assurance:** Any (Machine-level API key accepted)

**Parameters:**

- `id` (path): Alert identifier (opaque string; typically the alerting system's alert ID)

**Request body (optional):**

```json
{
  "reason": "investigating spike in error rate"
}
```

**Response (204 No Content):** Alert state recorded. Body is empty.

Returns `503 Service Unavailable` when the alert store is not configured.

#### POST /api/v1/alerts/{id}/silence

Silence an alert until a specified time. The calling principal and expiry are recorded.

**Authentication:** Required  
**Required permission:** `alert:silence`  
**Assurance:** Strong session required (silencing can suppress alerts fleet-wide)

**Parameters:**

- `id` (path): Alert identifier

**Request body:**

```json
{
  "until": "2026-08-18T00:00:00Z"
}
```

- `until` (required): RFC3339 timestamp when the silence expires.

**Response (204 No Content):** Alert state recorded. Body is empty.

Returns `400 Bad Request` when `until` is missing or zero. Returns `503 Service Unavailable` when the alert store is not configured.

#### POST /api/v1/alerts/{id}/unsilence

Reverse a silence. Clears the silence flag, its expiry and the silencing principal; the acknowledgement is unaffected. The alert reappears in the default alerts feed.

**Authentication:** Required  
**Required permission:** `alert:unsilence`  
**Assurance:** Strong session required (same gate as silence)

**Parameters:**

- `id` (path): Alert identifier

**Request body:** none.

**Response (200 OK):** The updated alert state.

```json
{
  "alert_id": "9f2c...",
  "acknowledged": true,
  "acknowledged_by": "alice",
  "acknowledged_at": "2026-08-17T09:00:00Z",
  "silenced": false
}
```

Idempotent: unsilencing an alert that is not silenced returns `200` with its current state. Returns `404 Not Found` when the caller's tenant holds no state for the alert (other tenants' alerts are not disclosed). Returns `503 Service Unavailable` when the alert store is not configured.

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
