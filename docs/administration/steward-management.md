# Steward Management

Operational reference for managing registered stewards from the `cfg` CLI.

---

## cfg steward move

Move a steward to a different tenant.

```
cfg steward move <steward-id> --to-tenant <tenant-path>
```

**Flags**

| Flag | Description |
|------|-------------|
| `--to-tenant` | Destination tenant path (required). Accepts flat IDs (`corp`) or slash-separated hierarchical paths (`msp-a/client-1`). |
| `--url` | Controller base URL. Falls back to `CFGMS_API_URL`. |
| `--bundle` | Path to admin mTLS bundle. Falls back to `CFGMS_ADMIN_BUNDLE`. |
| `--tls-ca-cert` | Path to CA certificate for TLS verification. Falls back to `CFGMS_TLS_CA_CERT`. |
| `--tls-insecure` | Skip TLS verification (development only). |

**Authentication**

`cfg steward move` requires AssuranceStrong (admin mTLS cert, ADR-021). The CLI resolves the
controller session per ADR-014. `cfg` itself never sends an API key — a direct REST caller
presenting one is rejected with 403 (Machine assurance is insufficient).

**Authorization**

| Admin type | Rule |
|------------|------|
| Unscoped (root) admin — `TenantID=""` | Always permitted. The move is fully audited as a privileged cross-tenant action. |
| Scoped admin | Permitted only if the caller's scope is an ancestor of (or equal to) **both** the source and destination tenant, using the anchored-prefix form (`t == scope \|\| strings.HasPrefix(t, scope+"/")`). |

A scoped admin with insufficient scope on either side is denied with HTTP 403.
Every denied move is emitted as a Critical-severity security audit event.

**Source status restrictions**

Moves are accepted from the following statuses: `registered`, `active`, `lost`,
`archived`, `dormant`, `deregistered`. Revoked stewards cannot be moved — accepting
a move would silently re-admit a revoked device into a new tenant without going through
the registration-refresh approval flow.

**Destination tenant requirements**

The destination tenant must exist and have status `active`.

**Identity-continuity guarantee**

A steward's cryptographic identity (device key, certificate) is **not** reissued on
move. The steward retains its existing mTLS credential and steward ID across tenants.

However, the trust context changes **immediately and completely** to the destination
tenant:

- The steward is subject to the **destination** tenant's refresh policy. The source
  tenant's refresh schedule is no longer applied.
- Module trust and publisher trust are resolved from the **destination** tenant's
  configuration. No trust decision from the source tenant is carried over.
- Nothing keys trust on an `(old-tenant, device-key)` tuple. The old-tenant context
  is fully discarded once the move completes.

This means operators should verify that the destination tenant's `module_trust.mode`
and trusted publisher set are correct before moving production stewards.

**Audit trail**

Every move attempt — success or denial — produces an audit record containing:

- Source and destination tenant paths
- Admin identity (certificate CN, serial, and fingerprint)
- Source IP and request ID
- Before → after `tenant_id` diff
- Outcome (`success` / `denied`) and severity (`high` for success, `critical` for denial)

**Examples**

```sh
# Move steward-abc to dest-tenant (uses admin bundle from CFGMS_ADMIN_BUNDLE)
cfg steward move steward-abc --to-tenant dest-tenant

# Move with an explicit controller URL
cfg steward move steward-abc --to-tenant msp-a/client-1 --url https://controller.example.com
```

**Web console**

Move is available from the per-row action menu (kebab → Move to tenant) and the bulk selection bar.
Both paths use the browser session and require AssuranceStrong (ADR-021 §S3). If the current
session is below Strong, the web client triggers an elevation step-up ceremony before the request
is issued — no explicit step-up button is needed.

Bulk move fans out one `POST /api/v1/stewards/:id/move` call per selected steward. Each call is
individually authorized and audited server-side; there is no batch endpoint that would bypass
per-steward tenant scoping. Per-item success and failure are reported inline.

---

## Steward Decommission

Permanently decommission (tombstone) a steward. The steward's durable record is tombstoned,
its in-memory status is set to `deregistered`, and its active QUIC/gRPC session is dropped.

**Authentication and authorization**

Decommission requires AssuranceStrong (ADR-021). The caller must have `steward:decommission`
permission on the steward's tenant.

**Audit trail**

Every decommission produces an audit record with severity `high`, containing the steward ID,
admin identity, source IP, and request ID.

**Web console**

Decommission is available from the per-row action menu (kebab → Decommission) and the bulk
selection bar (Decommission selected → Confirm decommission). Both paths require
AssuranceStrong; the step-up elevation ceremony fires automatically if the current session
is below Strong.

Bulk decommission fans out one `DELETE /api/v1/stewards/:id` call per selected steward. Each
call is individually authorized and audited server-side; no batch endpoint is used. Per-item
success and failure are reported inline.
