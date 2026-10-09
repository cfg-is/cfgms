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
    postgres_dsn: "host=pg.internal port=5432 dbname=cfgms user=cfgms password=${CFGMS_STORAGE_DB_PASSWORD} sslmode=require"
    session_hmac_key: "${CFGMS_SESSION_HMAC_KEY}"  # required — see below
    s3:                  # installer artifact blob store (S3-compatible)
      bucket: cfgms-installers
      region: us-east-1
      endpoint_url: "https://objects.internal:9000"   # omit for AWS S3
      access_key_id: "${CFGMS_S3_ACCESS_KEY_ID}"        # omit to use the AWS credential chain
      secret_access_key: "${CFGMS_S3_SECRET_ACCESS_KEY}"
```

**`session_hmac_key` is required, not optional**, despite the YAML tag not
being marked as such: `DatabaseSessionStore` fails closed (rejects all
sessions) when it is empty. It backs bearer-token hashing for the shared
Postgres-backed session store and **must be identical across every node in
the cluster** — a token issued on one node must validate on any peer node.
Generate it once (`openssl rand -hex 32`) and distribute the same value to
every node; do not let each node generate its own.

The controller refuses literal values in `postgres_dsn` (a literal password),
`session_hmac_key`, and the S3 `access_key_id` / `secret_access_key`: deliver
them as `${VAR}` references (resolved from `<VAR>` or the sealed `<VAR>_FILE`
credential). `${VAR:-default}` is refused as well. A DSN with no password
(certificate or `.pgpass` authentication) is allowed. See the secret-bearing key
table in the [config schema](../reference/config-schema.md#environment-variable-reference-syntax).

Cluster mode also requires an S3-compatible blob store for installer artifacts,
shared by every node: cluster mode refuses to start unless a bucket is set in
`storage.cluster.s3.bucket` or `CFGMS_S3_INSTALLER_BUCKET` (checked by
`assertClusterBackendsReady`). `storage.cluster.s3` accepts `bucket`, `region`
(default `us-east-1`), `endpoint_url` (an S3-compatible endpoint other than AWS;
path-style addressing is used), `prefix`, `access_key_id` and
`secret_access_key`.

**Credentials never go in the file as values.** Either reference them as
`${VAR}` (as above) and deliver each through the `<VAR>_FILE` sealed-credential
pattern — e.g. `LoadCredentialEncrypted=cfgms-s3-access-key:/etc/cfgms/s3-access-key.cred`
with `Environment=CFGMS_S3_ACCESS_KEY_ID_FILE=%d/cfgms-s3-access-key` — or omit
both keys and let the AWS default credential chain supply them (for example a
sealed shared-credentials file named by `AWS_SHARED_CREDENTIALS_FILE=%d/<credential>`,
or an instance role).

## Environment variables

| Variable | Equivalent YAML key |
|----------|---------------------|
| `CFGMS_HA_MODE` | `ha.mode` |
| `CFGMS_STORAGE_CLUSTER_POSTGRES_DSN` | `storage.cluster.postgres_dsn` |
| `CFGMS_STORAGE_CLUSTER_SESSION_HMAC_KEY` | `storage.cluster.session_hmac_key` |
| `CFGMS_S3_INSTALLER_BUCKET` | `storage.cluster.s3.bucket` |
| `CFGMS_S3_INSTALLER_REGION` | `storage.cluster.s3.region` |
| `CFGMS_S3_INSTALLER_ENDPOINT_URL` | `storage.cluster.s3.endpoint_url` |

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
- The installer blob store is created from `storage.cluster.s3`, with each
  `CFGMS_S3_INSTALLER_*` variable overriding its key (blob store creation is handled in
  `server.go`, not in the cluster storage manager itself).

## Single-server fallback

When `ha.mode` is absent or set to `single`, the controller uses the OSS composite backend
(flatfile + SQLite). The `storage.cluster.*` keys are ignored in this mode.
