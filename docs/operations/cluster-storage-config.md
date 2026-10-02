# Cluster Storage Configuration

Cluster mode (`ha.mode: cluster`) directs the controller to use shared external backends
(Postgres for business stores) so that every node in the cluster reads and writes the same
fleet state. A second node pointed at the same Postgres DSN and initialized with
`controller --init` begins serving the existing fleet immediately.

## Configuration keys

```yaml
ha:
  mode: cluster          # enables cluster storage selection

storage:
  cluster:
    postgres_dsn: "host=pg.internal port=5432 dbname=cfgms user=cfgms password=... sslmode=require"
    session_hmac_key: "..."  # required — see below
    s3:                  # optional — blob store config passed through to the S3 provider
      bucket: cfgms-installers
      region: us-east-1
```

**`session_hmac_key` is required, not optional**, despite the YAML tag not
being marked as such: `DatabaseSessionStore` fails closed (rejects all
sessions) when it is empty. It backs bearer-token hashing for the shared
Postgres-backed session store and **must be identical across every node in
the cluster** — a token issued on one node must validate on any peer node.
Generate it once (`openssl rand -hex 32`) and distribute the same value to
every node; do not let each node generate its own.

Cluster mode also requires `CFGMS_S3_INSTALLER_BUCKET` to be set (checked by
`assertClusterBackendsReady` at startup, independent of `storage.cluster.s3`
above) — cluster mode refuses to start without an S3-compatible blob store
configured for installer artifacts.

## Environment variables

| Variable | Equivalent YAML key |
|----------|---------------------|
| `CFGMS_HA_MODE` | `ha.mode` |
| `CFGMS_STORAGE_CLUSTER_POSTGRES_DSN` | `storage.cluster.postgres_dsn` |
| `CFGMS_STORAGE_CLUSTER_SESSION_HMAC_KEY` | `storage.cluster.session_hmac_key` |
| `CFGMS_S3_INSTALLER_BUCKET` | (no YAML equivalent — read directly at startup by `assertClusterBackendsReady`) |

Environment variables override YAML values when both are present.

See also [`cluster-ca.md`](cluster-ca.md) — a real cluster-mode deployment
also needs `certificate.cluster_ca` configured so every node loads the same
CA from the shared OpenBao vault; this doc only covers storage.

## Behaviour

When `ha.mode: cluster`:

- `controller --init` and normal controller startup both call `CreateClusterStorageManager`,
  which obtains the registered `database` provider and wires all business stores (steward,
  audit, RBAC, client/tenant) to the same Postgres DSN.
- The init marker records `storage_provider: database` so second-node bootstrap can confirm
  the expected backend.
- S3 configuration in `storage.cluster.s3` is accepted and passed through to the blob store
  factory in `server.go` (blob store creation is handled there, not in the cluster storage
  manager itself).

## Single-server fallback

When `ha.mode` is absent or set to `single`, the controller uses the OSS composite backend
(flatfile + SQLite). The `storage.cluster.*` keys are ignored in this mode.
