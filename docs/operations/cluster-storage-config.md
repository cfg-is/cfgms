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
    s3:                  # optional — blob store config passed through to the S3 provider
      bucket: cfgms-installers
      region: us-east-1
```

## Environment variables

| Variable | Equivalent YAML key |
|----------|---------------------|
| `CFGMS_HA_MODE` | `ha.mode` |
| `CFGMS_STORAGE_CLUSTER_POSTGRES_DSN` | `storage.cluster.postgres_dsn` |

Environment variables override YAML values when both are present.

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
