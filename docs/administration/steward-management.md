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
| `--api-key` | API key. Falls back to `CFGMS_API_KEY`. Not accepted on this endpoint — Tier-3 requires admin mTLS. |
| `--tls-ca-cert` | Path to CA certificate for TLS verification. Falls back to `CFGMS_TLS_CA_CERT`. |
| `--tls-insecure` | Skip TLS verification (development only). |

**Authentication**

`cfg steward move` is a Tier-3 endpoint (admin mTLS only). The CLI resolves the
controller session per ADR-014. An API key is rejected with 403.

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
