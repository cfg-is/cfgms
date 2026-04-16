# OpenBao Secrets Provider

Apache 2.0-licensed secrets provider backed by [OpenBao](https://github.com/openbao/openbao)
(an Apache 2.0 fork of HashiCorp Vault). Implements both `interfaces.SecretStore`
(full CRUD, versioning, rotation, metadata, health) and `interfaces.LeasedSecret`
(lease mint, renew, revoke) against OpenBao's **KV v2** engine.

## Dev-Mode Quickstart

### 1. Start OpenBao

```bash
docker compose --profile openbao -f docker-compose.test.yml up -d openbao-test
```

OpenBao is available on **host port 8201** to avoid conflicts with any local
Vault/OpenBao instance running on 8200.

### 2. Run integration tests

```bash
OPENBAO_ADDR=http://localhost:8201 \
OPENBAO_TOKEN=root \
go test -v -tags integration ./pkg/secrets/providers/openbao/...
```

### 3. Stop the container

```bash
docker compose --profile openbao -f docker-compose.test.yml down
```

## Configuration Reference

| Key          | Type   | Default                   | Description                                        |
|--------------|--------|---------------------------|----------------------------------------------------|
| `address`    | string | `http://127.0.0.1:8200`   | OpenBao server URL                                 |
| `token`      | string | (env `OPENBAO_TOKEN`)     | Root or service token                              |
| `mount_path` | string | `secret`                  | KV v2 mount path                                   |
| `tls_cert`   | string | _(none)_                  | Path to PEM CA certificate for TLS verification   |
| `namespace`  | string | _(none)_                  | OpenBao namespace (optional)                       |

Environment variable fallbacks (checked when the config key is absent or empty):

| Env var        | Maps to      |
|----------------|--------------|
| `OPENBAO_ADDR` | `address`    |
| `OPENBAO_TOKEN`| `token`      |
| `BAO_TOKEN`    | `token`      |

## KV v2 Path Mapping

Secrets are stored at `<mount_path>/data/<tenantID>/<key>`.

- `TenantID` is **required** on every write. Empty `TenantID` returns
  `interfaces.ErrTenantRequired`.
- `ListSecrets` scopes to `<mount_path>/metadata/<tenantID>` ensuring tenant
  isolation.

## Versioning

OpenBao KV v2 provides native versioning:

- `StoreSecret` / `RotateSecret` each write a new version.
- `GetSecretVersion(ctx, "tenantID/key", N)` retrieves version N.
- `ListSecretVersions` returns all versions via the KV v2 metadata endpoint.
- Deleted secrets (via `DeleteSecret` / `ExpireSecret`) use
  `DeleteMetadata`, which removes all versions permanently.

## Leasing (`LeasedSecret`)

`OpenBaoSecretStore` implements `interfaces.LeasedSecret`:

| Method        | Behaviour                                                                         |
|---------------|-----------------------------------------------------------------------------------|
| `LeaseSecret` | Always returns `ErrLeaseNotSupported` for KV v2 (static secrets have no leases). |
| `RenewLease`  | Calls `/sys/leases/renew` — use with dynamic engines (database, PKI, AWS).        |
| `RevokeLease` | Calls `/sys/leases/revoke` — immediately invalidates the lease.                   |

## Production Guard

The provider **refuses to start** when **both** conditions hold:

1. A dev-mode indicator is present:
   - Token is `"root"`, OR
   - `VAULT_DEV_MODE=true`, OR
   - `BAO_DEV_MODE=true`
2. `CFGMS_TELEMETRY_ENVIRONMENT=production`

**Error message:**

```
OpenBao provider refused to start:
  Reason: dev-mode token or flag detected in a production environment.
  Token "root" and VAULT_DEV_MODE/BAO_DEV_MODE=true are only valid in
  OpenBao dev mode, which stores data in memory and is wiped on restart.
  Fix: use a proper OpenBao service token and ensure dev mode is not enabled.
  See: pkg/secrets/providers/openbao/README.md
```

**Why:** OpenBao dev mode stores all data in memory. Restarting the process
wipes every secret. Using dev mode in production would silently lose credentials
on any restart or upgrade.

## Security Notes

- Token values are **never** logged.
- Secret values (`Secret.Value`) are **never** logged.
- All key paths and tenant IDs are passed through `logging.SanitizeLogValue()`
  before appearing in log lines (CWE-117 prevention).
- The `root` token is only valid in dev mode. Production deployments must use
  a scoped service token with minimal permissions.
- For mutual TLS, set `tls_cert` to the CA certificate path. All traffic to
  OpenBao uses HTTPS in production environments.
