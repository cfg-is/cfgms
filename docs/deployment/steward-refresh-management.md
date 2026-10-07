# Steward Registration-Refresh Management

When a steward's mTLS certificate expires while the device has been offline, it must
complete a **registration-refresh** challenge to regain fleet membership. Depending on
the tenant's configured refresh policy, these requests may be queued for manual
operator review.

This guide covers the `cfg steward refresh` commands for managing the refresh approval
queue and the per-tenant refresh policy.

## Prerequisites

- `cfg` CLI installed and authenticated (see [fleet walkthrough](fleet/walkthrough.md))
- An API key with the appropriate `refresh:*` permissions

## Commands

### List pending refresh requests

```bash
# All tenants
cfg steward refresh list

# Specific tenant
cfg steward refresh list --tenant acme-corp
```

Output:

```
Pending refresh requests (2):

PENDING ID              DEVICE ID          TENANT ID   SOURCE IP   STATUS   CREATED AT
refresh-1750001234567   aabbccddeeff0011…  acme-corp   10.0.1.5    pending  2026-06-20T09:00:00Z
refresh-1750009876543   aabbccddeeff0022…  acme-corp   10.0.1.6    pending  2026-06-20T09:05:00Z
```

### Approve a pending refresh request

Approves the request, generates a new mTLS certificate for the steward, and stores
the certificate bundle. The steward receives the bundle on its next poll.

```bash
cfg steward refresh approve refresh-1750001234567
```

### Reject a pending refresh request

Rejects the request. The steward must re-initiate the challenge flow to get a new
pending ID.

```bash
cfg steward refresh reject refresh-1750001234567
cfg steward refresh reject refresh-1750001234567 --reason "Device decommissioned"
```

## Refresh Policy

The refresh policy controls how the controller handles incoming refresh requests for
a given tenant. It can be set per-tenant.

### Policy modes

| Mode               | Behaviour                                                                    |
|--------------------|------------------------------------------------------------------------------|
| `require_approval` | Queue all requests for manual operator review (default).                     |
| `auto_accept`      | Approve automatically when the steward's provenance score is sufficient.     |
| `reject`           | Deny all refresh requests for this tenant.                                   |

### Get the current policy

```bash
cfg steward refresh policy get --tenant acme-corp
```

Output:

```
Tenant:           acme-corp
Mode:             require_approval
Max Dormancy:     disabled
```

### Set the policy

```bash
# Require manual approval (default)
cfg steward refresh policy set --mode require_approval --tenant acme-corp

# Auto-accept when provenance matches
cfg steward refresh policy set --mode auto_accept --tenant acme-corp

# Auto-accept with a 90-day dormancy backstop
cfg steward refresh policy set --mode auto_accept --max-dormancy-days 90 --set-dormancy --tenant acme-corp

# Reject all refresh requests
cfg steward refresh policy set --mode reject --tenant acme-corp
```

### Max dormancy days

`--max-dormancy-days` sets a cap on how long a steward may remain offline before its
refresh request is auto-rejected regardless of mode. When `0` or not set, the dormancy
backstop is disabled.

To explicitly disable a previously set dormancy limit, pass `--max-dormancy-days 0
--set-dormancy`.

## REST API

These commands communicate with the following authenticated REST endpoints. All
endpoints require a valid API key with the matching permission.

| Method | Path                                              | Permission           | Description                    |
|--------|---------------------------------------------------|----------------------|--------------------------------|
| GET    | `/api/v1/stewards/refresh/pending`                | `refresh:list-pending` | List pending refresh requests  |
| POST   | `/api/v1/stewards/refresh/{pending_id}/approve`   | `refresh:approve`    | Approve a pending request      |
| POST   | `/api/v1/stewards/refresh/{pending_id}/reject`    | `refresh:reject`     | Reject a pending request       |
| GET    | `/api/v1/tenants/{tenant_id}/refresh-policy`      | `refresh:get-policy` | Get the per-tenant policy      |
| PUT    | `/api/v1/tenants/{tenant_id}/refresh-policy`      | `refresh:set-policy` | Set the per-tenant policy      |

### Example: approve via REST

```bash
curl -s -X POST \
  -H "X-API-Key: $CFGMS_API_KEY" \
  https://controller.example.com/api/v1/stewards/refresh/refresh-1750001234567/approve \
  | jq '{status, pending_id, client_cert_present: (.client_cert != null)}'
```

### Example: set policy via REST

```bash
curl -s -X PUT \
  -H "X-API-Key: $CFGMS_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"mode":"auto_accept","max_dormancy_days":90}' \
  https://controller.example.com/api/v1/tenants/acme-corp/refresh-policy
```

## Global flags

All `cfg steward refresh` subcommands accept these flags (or the equivalent
environment variables):

| Flag              | Env var              | Description                               |
|-------------------|----------------------|-------------------------------------------|
| `--api-url`       | `CFGMS_API_URL`      | Controller REST API URL                   |
| `--bundle`        | `CFGMS_ADMIN_BUNDLE` | Path to admin mTLS bundle                 |
| `--tls-ca-cert`   | `CFGMS_TLS_CA_CERT`  | Path to CA certificate for TLS            |
| `--tls-insecure`  | `CFGMS_TLS_INSECURE` | Skip TLS verification (development only)  |
