# Configuration Schema Reference

Field-by-field reference for `controller.cfg` and steward `<hostname>.cfg` formats. Both
files are YAML. Every key below is derived from a Go struct tag; every code reference is
given as `<file>` `<symbol>` so it stays valid when line numbers move.

| Component | Struct file | Loader |
|---|---|---|
| Controller | `features/controller/config/config.go` `Config` | `features/controller/config/config.go` `LoadWithPath` |
| Steward | `features/config/stewardtypes/types.go` `StewardConfig` | `features/steward/config/config.go` `LoadConfiguration` |

`features/steward/config/config.go` re-exports every `stewardtypes` type under the same name,
so steward code refers to `config.StewardConfig` and the controller refers to
`stewardtypes.StewardConfig`; both are the same struct.

**Canonical working examples:**
- Controller: [`docs/deployment/controller.cfg`](../deployment/controller.cfg)
- Steward: [`docs/deployment/steward.cfg`](../deployment/steward.cfg)

---

## Controller config (`controller.cfg`)

All keys in this section are read by the controller process. `LoadWithPath` applies
`DefaultConfig`, overlays the file, applies environment overrides, then runs the load-time
validators listed under [Controller validation](#controller-validation).

The controller searches for its config file in this order (`findConfigFile`):

1. Explicit path supplied via CLI flag
2. `CFGMS_CONTROLLER_CONFIG` environment variable
3. `/etc/cfgms/controller.cfg` (Linux) or `C:\ProgramData\cfgms\controller.cfg` (Windows)
4. `./controller.cfg` (current working directory)

If no file is found, built-in defaults are used and environment variable overrides still apply.
The controller decoder does not reject unknown keys: a misspelled key is silently ignored.

### Top-level fields

`features/controller/config/config.go` `Config`. Defaults: `DefaultConfig`.

| YAML field | Type | Default | Req | Description |
|---|---|---|---|---|
| `security_profile` | string | `"development"` | optional | Deployment security profile: `development`, `test`, or fail-closed `public-beta`. See [`ValidateExecutionSecurity`](#controller-validation) for what `public-beta` enforces. |
| `execution` | object | `{}` | optional | Controller-issued execution security policy (`ExecutionSecurityConfig`); one key, below |
| `execution.require_signed_adhoc` | boolean | `false` | required `true` in `public-beta` | Require operator content signatures and controller-signed command envelopes for ad-hoc execution |
| `listen_addr` | string | `"127.0.0.1:8080"` | optional | REST API (HTTPS) listen address |
| `metrics_listen_addr` | string | `""` | **required** | Dedicated HTTPS listener for product metrics. Deliberately has no default: must be an explicit loopback or private IP literal plus a fixed numeric port (`ValidatePrivateListenerAddress`). Startup fails when absent. |
| `internal_listen_addr` | string | `""` | required for `ha.mode: cluster` | Private HTTPS listener for controller-to-controller Raft traffic. Same loopback-or-private rule as `metrics_listen_addr`; never Internet-published. Ignored outside cluster mode. |
| `internal_delivery_listen_addr` | string | `""` | optional (cluster mode) | Private mTLS gRPC listener for the internal controller-to-controller delivery service (ADR-031 Decision 3). Separate port from `internal_listen_addr`. Unset leaves the delivery listener unstarted. |
| `external_url` | string | `""` | **required** | Externally reachable HTTPS address used in admin bundles and upgrade URLs (e.g. `https://controller.acme-corp.example:8080`); admin bundle issuance fails if unset |
| `cert_path` | string | `"certs/"` | optional | Legacy TLS certificate directory holding `server.crt` / `server.key` (superseded by the `certificate` block). **A relative value is resolved against the directory containing the config file, not the process working directory**, so the default `certs/` means `<config-file-dir>/certs`. An absolute value is used unchanged. See the note below for the `CFGMS_CERT_PATH` exception. |
| `data_dir` | string | `"data/"` | optional | Data storage root directory |
| `log_level` | string | `"info"` | optional | Log verbosity shorthand; `logging.level` wins if both are set |
| `certificate` | object | see [`certificate`](#certificate) | optional | Certificate lifecycle config |
| `storage` | object | see [`storage`](#storage) | optional | Storage provider config |
| `audit` | object | see [`audit`](#audit) | optional | Audit sink selection (ADR-033). Absent resolves to the `local` sink. |
| `logging` | object | see [`logging`](#logging-controller) | optional | Logging provider config |
| `transport` | object | see [`transport`](#transport) | optional | gRPC-over-QUIC transport config |
| `registration` | object | see [`registration`](#registration) | optional | Steward registration approval workflow and IP-trust timings |
| `admin_bundle_path` | string | `""` | optional | Path where `--init` writes the admin credential bundle (mode 0600). Empty resolves to `/etc/cfgms/admin.bundle.yaml` (Linux) or `%ProgramData%\cfgms\admin.bundle.yaml` (Windows) via `features/controller/initialization/bundle_marker.go` `defaultAdminBundlePath`. |
| `blob_storage` | object | see [`blob_storage`](#blob_storage) | optional | Installer artifact blob store location |
| `ha` | object | see [`ha`](#ha) | optional | Deployment mode selection |
| `deployment_rings` | object | see [`deployment_rings`](#deployment_rings) | optional | Ordered deployment ring set for fleet version management. Absent applies the built-in four-ring set. |
| `tenant_admin` | object | see [`tenant_admin`](#tenant_admin) | optional | Global tenant-administration policy (ADR-027) |
| `webauthn` | object | see [`webauthn`](#webauthn) | optional | Browser passkey relying party. Absent leaves the passkey endpoints answering 503. |
| `realm_id` | string | `""` | required for `ha.mode: cluster` in production | Deployment-wide realm qualifier naming this cell (ADR-032 Decision 3). Must be a single DNS label (lowercase alphanumeric and hyphens, no leading/trailing hyphen, at most 63 chars). A malformed value refuses to start on any deployment shape; a `CFGMS_TELEMETRY_ENVIRONMENT=production` controller with `ha.mode: cluster` also refuses to start when unset (`tenant.EnforceRealmGuard`). |

**Environment overrides for top-level fields** (applied in `LoadWithPath` after the file is read):

| Env var | Overrides field |
|---|---|
| `CFGMS_SECURITY_PROFILE` | `security_profile` (cannot downgrade a configured `public-beta`) |
| `CFGMS_EXECUTION_REQUIRE_SIGNED_ADHOC` | `execution.require_signed_adhoc` |
| `CFGMS_LISTEN_ADDR` | `listen_addr` |
| `CFGMS_HTTP_LISTEN_ADDR` | `listen_addr` (same field, applied later, so it wins) |
| `CFGMS_METRICS_LISTEN_ADDR` | `metrics_listen_addr` |
| `CFGMS_EXTERNAL_URL` | `external_url` |
| `CFGMS_CERT_PATH` | `cert_path` (**must be absolute**, see note below) |
| `CFGMS_DATA_DIR` | `data_dir` |
| `CFGMS_LOG_LEVEL` | `log_level` and `logging.level` |
| `CFGMS_HA_MODE` | `ha.mode` (lower-cased) |
| `CFGMS_REGISTRATION_WORKFLOW` | `registration.workflow` |
| `CFGMS_AUDIT_SINK` | `audit.sink` (lower-cased) |

`internal_listen_addr`, `internal_delivery_listen_addr`, `admin_bundle_path`, `blob_storage`,
`deployment_rings`, `tenant_admin`, `webauthn` and `realm_id` have no environment override.

> **`cert_path` resolution (Issue #3197).** A relative `cert_path` read *from a config
> file* is anchored to that file's directory as the file is loaded, which is what makes it
> independent of the working directory the controller is started from.
>
> `CFGMS_CERT_PATH` does **not** get this treatment. The environment override is applied
> after the config file has been resolved, so its value is used exactly as given: a
> relative value stays relative and is interpreted against the process working directory.
> Always set `CFGMS_CERT_PATH` to an absolute path.
>
> The same caveat applies when the config file itself is located via a relative
> `--config` / `CFGMS_CONTROLLER_CONFIG` value: the anchor is then relative too, so
> `cert_path` remains working-directory dependent. Prefer an absolute `--config` path.

---

### `certificate`

`features/controller/config/config.go` `CertificateConfig`

| YAML field | Type | Default | Req | Description |
|---|---|---|---|---|
| `enable_cert_management` | boolean | `true` | optional (required `true` in `public-beta`) | Automate the full certificate lifecycle (generate, load, validate, renew, distribute) |
| `ca_path` | string | `"certs/ca"` | optional | Directory for CA certificate storage. The final path component must be `ca` (`ValidateCAPath`). |
| `renewal_threshold_days` | integer | `30` | optional | Days before expiry at which certificates are renewed |
| `server_cert_validity_days` | integer | `365` | optional | Server certificate validity period in days |
| `client_cert_validity_days` | integer | `365` | optional | Steward client certificate validity period in days |
| `server` | object | see [`certificate.server`](#certificateserver) | optional | Server certificate identity settings |
| `architecture` | string | `""` | leave unset | Legacy key retained only so a stale `unified` value can be rejected. Separated architecture is mandatory; `architecture: unified` fails startup (`ValidateCertificateArchitecture`). |
| `signing_cert_validity_days` | integer | `0` | optional | Config signing cert validity; `0` lets the cert manager use its built-in default (1095 days) |
| `internal_cert_validity_days` | integer | `0` | optional | Internal mTLS cert validity; `0` lets the cert manager use its built-in default (365 days) |
| `public_api` | object | absent | optional | Public API cert config, see [`certificate.public_api`](#certificatepublic_api) |
| `internal` | object | absent | optional | Internal mTLS cert config, see [`certificate.internal`](#certificateinternal) |
| `signing` | object | absent | optional | Config signing cert config, see [`certificate.signing`](#certificatesigning) |
| `cluster_ca` | object | absent | required for `ha.mode: cluster` | CA material sourced from the shared secret store, see [`certificate.cluster_ca`](#certificatecluster_ca) |

**Environment overrides for `certificate`:**

| Env var | Overrides field |
|---|---|
| `CFGMS_CERT_ENABLE_MANAGEMENT` | `certificate.enable_cert_management` |
| `CFGMS_CERT_CA_PATH` | `certificate.ca_path` |
| `CFGMS_CERT_RENEWAL_THRESHOLD_DAYS` | `certificate.renewal_threshold_days` |
| `CFGMS_CERT_SERVER_VALIDITY_DAYS` | `certificate.server_cert_validity_days` |
| `CFGMS_CERT_CLIENT_VALIDITY_DAYS` | `certificate.client_cert_validity_days` |
| `CFGMS_CERT_ARCHITECTURE` | `certificate.architecture` |
| `CFGMS_CERT_SIGNING_VALIDITY_DAYS` | `certificate.signing_cert_validity_days` |
| `CFGMS_CERT_SERVER_COMMON_NAME` | `certificate.server.common_name` |
| `CFGMS_CERT_SERVER_ORGANIZATION` | `certificate.server.organization` |
| `CFGMS_CERT_PUBLIC_API_SOURCE` | `certificate.public_api.source` |
| `CFGMS_CERT_PUBLIC_API_CERT_PATH` | `certificate.public_api.cert_path` |
| `CFGMS_CERT_PUBLIC_API_KEY_PATH` | `certificate.public_api.key_path` |

#### `certificate.server`

`features/controller/config/config.go` `ServerCertificateConfig`

| YAML field | Type | Default | Req | Description |
|---|---|---|---|---|
| `common_name` | string | `"cfgms-controller"` | optional | CN embedded in the generated server certificate |
| `dns_names` | list[string] | `["localhost","cfgms-controller","controller-standalone"]` | optional | Subject Alternative Name DNS entries |
| `ip_addresses` | list[string] | `["127.0.0.1"]` | optional | Subject Alternative Name IP entries |
| `organization` | string | `"CFGMS"` | optional | Organization name embedded in the certificate |

#### `certificate.public_api`

`features/controller/config/config.go` `PublicAPICertConfig`

| YAML field | Type | Default | Req | Description |
|---|---|---|---|---|
| `source` | string | `"internal"` (via `GetPublicAPISource`) | optional | `internal` (CA-generated) or `external` (load from files) |
| `cert_path` | string | `""` | cond | Certificate file path, required when `source: external` |
| `key_path` | string | `""` | cond | Private key file path, required when `source: external` |
| `common_name` | string | `""` | optional | CN for the public API certificate |
| `dns_names` | list[string] | `[]` | optional | Subject Alternative Name DNS entries |

#### `certificate.internal`

`features/controller/config/config.go` `InternalCertConfig`

| YAML field | Type | Default | Req | Description |
|---|---|---|---|---|
| `common_name` | string | `"cfgms-internal"` | optional | CN for the internal mTLS certificate |
| `dns_names` | list[string] | `[]` | optional | Subject Alternative Name DNS entries |
| `ip_addresses` | list[string] | `[]` | optional | Subject Alternative Name IP entries |

#### `certificate.signing`

`features/controller/config/config.go` `SigningCertificateConfig`

| YAML field | Type | Default | Req | Description |
|---|---|---|---|---|
| `common_name` | string | `"cfgms-config-signer"` | optional | CN for the config signing certificate |
| `organization` | string | `""` | optional | Organization name embedded in the certificate |

#### `certificate.cluster_ca`

`features/controller/config/config.go` `ClusterCAConfig`. Only used when `ha.mode: cluster`;
see [Cluster CA Trust Anchor Configuration](../operations/cluster-ca.md) for the full
operational picture. The vault token is never a config key: supply it via the
`OPENBAO_TOKEN` or `BAO_TOKEN` environment variable.

| YAML field | Type | Default | Req | Description |
|---|---|---|---|---|
| `vault_address` | string | `""` | required | OpenBao server URL; must be HTTPS in production |
| `vault_key_path` | string | `""` | required | KV v2 path in `"tenantID/key-name"` format; the cert is stored at this path, the key at `<path>-key`, and an imported intermediate's issuer chain at `<path>-chain` |
| `vault_tls_cert` | string | `""` | optional | Path to a PEM CA cert for verifying the vault's TLS certificate; required when the vault uses a private CA |
| `vault_mount_path` | string | `"secret"` | optional | KV v2 mount path |
| `external_intermediate_cert_path` | string | `""` | optional | Path to a regional intermediate CA certificate obtained out-of-band from an offline root ceremony (ADR-032 Decision 2); when set, all three `external_intermediate_*_path` fields must be set together |
| `external_intermediate_key_path` | string | `""` | optional | Path to the intermediate's private key; read once at import time and never written to any node's disk |
| `external_intermediate_chain_path` | string | `""` | optional | Path to the issuer chain from the intermediate up to and including the offline root (root-terminal order) |

**Environment overrides for `certificate.cluster_ca`:**

| Env var | Overrides field |
|---|---|
| `CFGMS_CLUSTER_CA_VAULT_ADDRESS` | `certificate.cluster_ca.vault_address` |
| `CFGMS_CLUSTER_CA_VAULT_KEY_PATH` | `certificate.cluster_ca.vault_key_path` |

The `external_intermediate_*_path` fields have no environment variable override; set them in
`controller.cfg` only. When omitted (all three), cluster CA init self-generates and stores a
root CA in the vault. Pointing them at material that differs from what the vault already
holds fails closed at startup rather than replacing the cluster's published CA identity; see
[Cluster CA Trust Anchor Configuration](../operations/cluster-ca.md#regional-intermediate-saas).

---

### `storage`

`features/controller/config/config.go` `StorageConfig`

| YAML field | Type | Default | Req | Description |
|---|---|---|---|---|
| `provider` | string | `"flatfile"` | optional | Storage backend: `flatfile`, `sqlite`, or `database`. The registered provider names are the `Name()` methods of `pkg/storage/providers/flatfile` `FlatFileProvider`, `pkg/storage/providers/sqlite` `SQLiteProvider` and `pkg/storage/providers/database` (see its `Name()` method). |
| `config` | map | `{}` | optional | Provider-specific key/value configuration passed verbatim |
| `flatfile_root` | string | `"data/cfgms-config"` | cond | Root directory for flat-file storage; enables the OSS composite manager when set |
| `sqlite_path` | string | `"data/cfgms.db"` | cond | SQLite file path for the OSS composite manager; required when `flatfile_root` is set |
| `cluster` | object | absent | required for `ha.mode: cluster` | Shared Postgres and S3-compatible store settings, see [`storage.cluster`](#storagecluster). Ignored in single-node deployments. |

Setting `flatfile_root` and `sqlite_path` together activates the OSS composite storage manager
(flat-file + SQLite). If only one is set the provider falls through to the single-provider path.

The `git` provider is no longer supported and no longer ships in `pkg/storage/providers`.
An existing git-backed deployment is migrated once with
`cfg migrate --provider storage --from git --to flatfile` (`cmd/cfg/cmd/migrate.go`
`migrateCmd`) or the legacy alias `cfg storage migrate --from git --to flatfile`
(`cmd/cfg/cmd/storage.go`).

**Environment overrides for `storage`:**

| Env var | Overrides field |
|---|---|
| `CFGMS_STORAGE_PROVIDER` | `storage.provider` |
| `CFGMS_STORAGE_DATABASE_HOST` / `CFGMS_DB_HOST` | `storage.config["host"]` (database provider) |
| `CFGMS_STORAGE_DATABASE_PORT` / `CFGMS_DB_PORT` | `storage.config["port"]` (database provider) |
| `CFGMS_STORAGE_DATABASE_NAME` / `CFGMS_DB_NAME` | `storage.config["database"]` (database provider) |
| `CFGMS_STORAGE_DATABASE_USER` / `CFGMS_DB_USER` | `storage.config["username"]` (database provider) |
| `CFGMS_STORAGE_DATABASE_PASSWORD` / `CFGMS_DB_PASSWORD` | `storage.config["password"]` (database provider) |
| `CFGMS_STORAGE_DATABASE_SSLMODE` / `CFGMS_DB_SSLMODE` | `storage.config["sslmode"]` (database provider) |
| `CFGMS_STORAGE_CLUSTER_POSTGRES_DSN` | `storage.cluster.postgres_dsn` |
| `CFGMS_STORAGE_CLUSTER_SESSION_HMAC_KEY` | `storage.cluster.session_hmac_key` |

The `CFGMS_STORAGE_DATABASE_*` pair is read first; the shorter `CFGMS_DB_*` form is a fallback.

#### `storage.cluster`

`features/controller/config/config.go` `ClusterStorageConfig`

| YAML field | Type | Default | Req | Description |
|---|---|---|---|---|
| `postgres_dsn` | string | `""` | required (cluster) | libpq connection string for the shared Postgres backend. Every node in the cluster must point at the same instance. |
| `session_hmac_key` | string | `""` | required (cluster) | Key backing the Postgres session store's bearer-token hashing. The store fails closed when empty; all nodes must share one key. Deliver it through `${VAR}` or `<VAR>_FILE` (see [Environment variable reference syntax](#environment-variable-reference-syntax)), never as a literal. |
| `s3` | map | `{}` | optional | S3-compatible blob store keys for installer artifacts: `bucket` (required), `region`, `endpoint_url`, `access_key_id`, `secret_access_key`. When empty, the bucket name is read from `CFGMS_S3_INSTALLER_BUCKET` at startup. |

---

### `audit`

`features/controller/config/config.go` `AuditSinkConfig`. `ResolvedSink` returns `local` when
the block is absent or `sink` is empty.

| YAML field | Type | Default | Req | Description |
|---|---|---|---|---|
| `sink` | string | `"local"` | optional | `local` (zero extra infrastructure) or `worm` (recommended production sink: an append-only object-lock target outside the controller's trust boundary) |
| `worm` | map | `{}` | required when `sink: worm` | WORM target connection details. Same key shape as `storage.cluster.s3` (`bucket`, `region`, `endpoint_url`, `access_key_id`, `secret_access_key`). Credentials follow the `${VAR}` / `<VAR>_FILE` pattern. Ignored unless `sink: worm`. |
| `marker_root` | string | `""` | optional | Directory for the WORM sink's local pending-entry marker store (entry IDs only, never audit content). Empty resolves to `<data_dir>/audit-worm-pending` (`features/controller/server/server.go` `resolveWORMMarkerRoot`). Ignored unless `sink: worm`. |

A WORM outage never blocks a caller: entries stay durable in the local sequence authority and a
background reconciliation loop ships whatever the WORM target is missing once it recovers.

---

### `logging` (controller)

`features/controller/config/config.go` `LoggingConfig`

| YAML field | Type | Default | Req | Description |
|---|---|---|---|---|
| `provider` | string | `"file"` | optional | Logging backend: `file` or `timescale` (the providers registered under `pkg/logging/providers/`) |
| `config` | map | see note | optional | Provider-specific key/value configuration passed verbatim |
| `level` | string | `"INFO"` | optional | Minimum log level: `DEBUG`, `INFO`, `WARN`, `ERROR`, `FATAL` |
| `service_name` | string | `"cfgms-controller"` | optional | Service identifier attached to every log record |
| `component` | string | `"controller"` | optional | Component identifier attached to every log record |
| `batch_size` | integer | `100` | optional | Number of entries per write batch |
| `flush_interval` | string | `"5s"` | optional | Auto-flush interval (Go duration string) |
| `async_writes` | boolean | `true` | optional | Write log entries asynchronously |
| `buffer_size` | integer | `1000` | optional | Internal write-buffer capacity |
| `retention_days` | integer | `30` | optional | Log retention period in days (provider-dependent) |
| `compress_logs` | boolean | `true` | optional | Compress rotated log files |
| `tenant_isolation` | boolean | `true` | optional | Enable per-tenant log namespace isolation |
| `enable_correlation` | boolean | `true` | optional | Attach automatic correlation IDs to log records |
| `enable_tracing` | boolean | `true` | optional | Enable OpenTelemetry trace integration |
| `subscribers` | list[object] | `[]` | optional | Real-time event forwarding targets |

Default `logging.config` for the `file` provider (`DefaultConfig`):
```yaml
directory: "/var/log/cfgms"
file_prefix: "cfgms"
max_file_size: 104857600   # 100 MB
max_files: 10
retention_days: 30
compress_rotated: true
```

**Environment overrides for `logging`:**

| Env var | Overrides field |
|---|---|
| `CFGMS_LOGGING_PROVIDER` | `logging.provider` |
| `CFGMS_LOG_LEVEL` | `logging.level` |
| `CFGMS_LOGGING_SERVICE_NAME` | `logging.service_name` |
| `CFGMS_LOGGING_COMPONENT` | `logging.component` |

#### `logging.subscribers[]` entries

`features/controller/config/config.go` `SubscriberConfig`

| YAML field | Type | Default | Req | Description |
|---|---|---|---|---|
| `type` | string | `""` | required | Subscriber type: `syslog` or `webhook` |
| `config` | map | `{}` | optional | Subscriber-specific key/value configuration |
| `enabled` | boolean | `false` | optional | Enable or disable this subscriber |

---

### `transport`

`features/controller/config/config.go` `TransportConfig`

| YAML field | Type | Default | Req | Description |
|---|---|---|---|---|
| `listen_addr` | string | `"0.0.0.0:4433"` | **required** | gRPC-over-QUIC listen address (UDP); must not be empty |
| `external_address` | string | `""` | cond | Hostname or IP advertised to stewards when `listen_addr` binds `0.0.0.0`. Required in that case unless `CFGMS_EXTERNAL_HOSTNAME` is set. Also merged into the transport certificate SANs (`features/controller/initialization/transport_sans.go`). |
| `use_cert_manager` | boolean | `true` | optional (required `true` in `public-beta`) | Use the controller's certificate manager for TLS |
| `max_connections` | integer | `50000` | optional | Maximum number of concurrent steward connections; must be at least 1 |
| `keepalive_period` | duration | `"30s"` | optional | Interval for keepalive probes to detect dead connections; must be at least `1s` |
| `idle_timeout` | duration | `"5m"` | optional | How long a connection may remain idle before the controller closes it |

**Environment overrides for `transport`:**

| Env var | Overrides field |
|---|---|
| `CFGMS_TRANSPORT_LISTEN_ADDR` | `transport.listen_addr` |
| `CFGMS_TRANSPORT_USE_CERT_MANAGER` | `transport.use_cert_manager` |
| `CFGMS_TRANSPORT_MAX_CONNECTIONS` | `transport.max_connections` |
| `CFGMS_TRANSPORT_KEEPALIVE_PERIOD` | `transport.keepalive_period` |
| `CFGMS_TRANSPORT_IDLE_TIMEOUT` | `transport.idle_timeout` |
| `CFGMS_EXTERNAL_HOSTNAME` | Read alongside `transport.external_address` (not an override; both are consulted, the env var first) |

---

### `registration`

`features/controller/config/config.go` `RegistrationConfig`. Defaults for the duration fields are
applied by the `Get*` accessors on that type, not by `DefaultConfig`.

| YAML field | Type | Default | Req | Description |
|---|---|---|---|---|
| `workflow` | string | `"ip-trust"` | optional | Built-in approval workflow: `ip-trust` (auto-approve when the source IP is trusted for the tenant, quarantine otherwise), `manual-review` (quarantine until `cfg registration approve`), or `auto-approve` (deprecated, dev/test only, logs a startup warning) |
| `trusted_proxies` | list[string] | `[]` | optional | CIDR ranges of reverse proxies trusted to append to `X-Forwarded-For`. When empty the TCP peer address is always used. |
| `approval_mode` | string | `""` | optional | Approval hook implementation: empty uses the workflow-engine hook; `manual-review` stores requests in the pending-registration store until an operator acts |
| `ip_trust_threshold` | duration | `"30m"` (`GetIPTrustThreshold`) | optional | Minimum continuous liveness before an IP is promoted to trusted |
| `ip_trust_dark_window` | duration | `"720h"` (30 days, `GetIPTrustDarkWindow`) | optional | Consecutive inactivity after which a non-pre-seeded trusted IP range is auto-revoked |
| `pending_review_timeout` | duration | `"120h"` (5 days, `GetPendingReviewTimeout`) | optional | Maximum time a pending registration waits for operator action before it expires |
| `enrollment_link_ttl` | duration | `"72h"` (`GetEnrollmentLinkTTL`) | optional | Validity window for a single-use passkey enrollment link minted on web-account creation or reset |

---

### `blob_storage`

`features/controller/config/config.go` `BlobStorageConfig`

| YAML field | Type | Default | Req | Description |
|---|---|---|---|---|
| `root` | string | `""` | optional | Filesystem directory for installer artifacts. Empty derives `<dir of storage.flatfile_root>/installers`, else `<dir of storage.sqlite_path>/installers`, else `<data_dir>/installers` (`features/controller/server/server.go` `resolveInstallerBlobRoot`). |

---

### `ha`

`features/controller/config/config.go` `HAConfig`. Only `mode` lives here; full cluster
coordination settings are owned by `pkg/ha`.

| YAML field | Type | Default | Req | Description |
|---|---|---|---|---|
| `mode` | string | `"single"` | optional | Deployment mode: `single`, `blue-green`, or `cluster` (`pkg/ha/config.go` `ModeFromString`, case-insensitive). `cluster` activates shared Postgres and S3 storage and requires `internal_listen_addr`, `storage.cluster`, `certificate.cluster_ca` and, in production, `realm_id`. |

---

### `deployment_rings`

`features/controller/config/config.go` `DeploymentRingConfig`. `Config.EffectiveRings` returns the
built-in set when the block is absent or `rings` is empty; `ValidateDeploymentRingConfig` runs at
startup otherwise.

| YAML field | Type | Default | Req | Description |
|---|---|---|---|---|
| `rings` | list[object] | `pre-release`, `early`, `default`, `stable` (`DefaultRingNames`) | optional | Ordered ring specs; earlier rings receive updates first. Each entry is a [`RingSpec`](#deployment_ringsrings-entries). |
| `fallback_ring` | string | `"default"` (`DefaultFallbackRing`) | optional | Ring used when a steward has no or an invalid `deployment_ring` DNA attribute. Must name a declared ring. |

#### `deployment_rings.rings[]` entries

`features/controller/config/config.go` `RingSpec`

| YAML field | Type | Default | Req | Description |
|---|---|---|---|---|
| `name` | string | — | required | Ring identifier matched against the `deployment_ring` DNA attribute. Must match `^[a-z][a-z0-9-]{0,31}$` and be unique. |
| `desired_version` | string | `""` | optional | Target steward binary version for this ring (e.g. `v0.5.21`). Overrides any tenant-path `desired_version`. |
| `soak` | duration | `0` | optional | Minimum time a version must run in this ring before promotion advances it |
| `halt_threshold` | float | `0` | optional | Error rate (0.0 to 1.0) above which promotion halts |
| `concurrency_limit` | integer | `0` | optional | Cap on simultaneous steward upgrades in this ring |

---

### `tenant_admin`

`features/controller/config/config.go` `TenantAdminConfig`

| YAML field | Type | Default | Req | Description |
|---|---|---|---|---|
| `delete_hold_period` | duration | `"720h"` (30 days, `GetDeleteHoldPeriod`) | optional | Minimum time between a tenant deletion request and its approval |
| `delete_requires_dual_control` | boolean | `true` (`GetDeleteRequiresDualControl`) | optional | Whether the operator who requested a tenant deletion may also approve it (`true` means they may not) |

---

### `webauthn`

`features/controller/config/config.go` `WebAuthnConfig`. Validated at load by `Config.ValidateWebAuthn`.
There is no default and no local-development bypass: with `rp_id` unset, browser passkey login
and passkey step-up answer 503.

| YAML field | Type | Default | Req | Description |
|---|---|---|---|---|
| `rp_id` | string | `""` | optional | Relying-party identifier: the controller's effective domain (e.g. `cfgms.acme-corp.example`). No scheme, no port. |
| `rp_display_name` | string | `rp_id` | optional | Human-readable name shown by the authenticator during the ceremony |
| `rp_origins` | list[string] | `[]` | required when `rp_id` is set | Fully qualified origins allowed to complete a ceremony (e.g. `https://cfgms.acme-corp.example`). Every entry must start with `https://`. Setting origins without `rp_id` is rejected. |

---

## Steward config (`<hostname>.cfg`)

The steward uses the current hostname as its config filename (e.g., `web-01.cfg`).
When no explicit path is supplied, `features/steward/config/config.go` `getConfigSearchPaths`
searches these locations in order:

**Linux:**
1. `./<hostname>.cfg` (CWD)
2. `/etc/cfgms/<hostname>.cfg`
3. `/usr/local/etc/cfgms/<hostname>.cfg`
4. `$HOME/.config/cfgms/<hostname>.cfg`
5. `$HOME/.cfgms/<hostname>.cfg`

**macOS:**
1. `./<hostname>.cfg` (CWD)
2. `/Library/Application Support/cfgms/<hostname>.cfg`
3. `/usr/local/etc/cfgms/<hostname>.cfg`
4. `$HOME/Library/Application Support/cfgms/<hostname>.cfg`
5. `$HOME/.cfgms/<hostname>.cfg`

**Windows:**
1. `./<hostname>.cfg` (CWD)
2. `%PROGRAMDATA%\cfgms\<hostname>.cfg`
3. `%USERPROFILE%\.cfgms\<hostname>.cfg`

`loadFromPath` decodes with unknown keys rejected, so a misspelled key fails the load.
The steward has no per-key environment variable overrides; only the
[`${VAR}` expansion](#environment-variable-reference-syntax) applies.

The same `StewardConfig` shape is what the controller stores per tenant path and delivers to a
connected steward, so the controller reads some keys too. The **Read by** column records who
acts on each key.

### Top-level fields

`features/config/stewardtypes/types.go` `StewardConfig`

| YAML field | Type | Default | Req | Read by | Description |
|---|---|---|---|---|---|
| `steward` | object | see [`steward`](#steward-section) | **required** | steward | Steward identity and runtime settings |
| `resources` | list[object] | `[]` | **required** | steward | Resources to manage (an empty list is valid for a controller-connected steward) |
| `modules` | map[string]string | `{}` | optional | steward | Custom module paths: `module_name: /path/to/binary` |
| `required_modules` | list[object] | `[]` | optional | controller | Module bundles that must be present and approved in the controller cache before this cfg can be deployed (`features/controller/modules/resolution/resolution.go` `ResolveCfgRequiredModules`). Each entry is a [`RequiredModule`](#required_modules-entries). |

#### `required_modules[]` entries

`features/config/stewardtypes/types.go` `RequiredModule`

| YAML field | Type | Default | Req | Description |
|---|---|---|---|---|
| `name` | string | — | required | Full `publisher/name` module identifier |
| `version` | string | — | required | Semver constraint the approved bundle must satisfy |

---

### `steward` section

`features/config/stewardtypes/types.go` `StewardSettings`. Defaults: `features/steward/config/config.go`
`applyDefaults`.

| YAML field | Type | Default | Req | Read by | Description |
|---|---|---|---|---|---|
| `id` | string | `<hostname>` | **required** | steward, controller | Unique steward identifier; the controller uses it to route pushed configs |
| `module_paths` | list[string] | `[]` | optional | steward | Additional directories searched for module binaries |
| `logging` | object | see [`steward.logging`](#stewardlogging) | optional | steward | Log verbosity |
| `error_handling` | object | see [`steward.error_handling`](#stewarderror_handling) | optional | steward | Per-condition error response policies |
| `secrets` | object | see [`steward.secrets`](#stewardsecrets) | optional | steward | Secret store configuration |
| `converge_interval` | duration string | `"30m"` | optional | steward | How often the steward re-converges desired state (`GetConvergeInterval`) |
| `script_signing` | object | see [`steward.script_signing`](#stewardscript_signing) | optional | steward, controller | Script signature policy and trusted key allowlist. The controller merges parent and child tenant values (`MergeScriptSigningConfig`). |
| `module_trust` | object | see [`steward.module_trust`](#stewardmodule_trust) | optional | steward | Module bundle trust policy. **Security control:** bounds what a compromised controller or admin can push to the endpoint. |
| `signed_command_replay_window` | duration | `5m` (zero applies `features/steward/commands/handler.go` `defaultReplayWindow`) | optional | steward | Max age of an accepted signed command timestamp; shorter is stricter replay protection |
| `signed_command_max_params_bytes` | integer | `65536` (zero applies the commands handler default) | optional | steward | Max JSON-serialized size of a command's parameters |
| `drift_mode` | string | `"apply"` | optional | steward (controller-delivered only) | How the steward responds to detected drift: `apply` (re-converge) or `monitor` (report only). `loadFromPath` clears any value found in the local file; only the controller-delivered cfg sets it (`features/steward/client/client_transport.go` `applyDriftModeDefault`). |
| `upgrade` | object | see [`steward.upgrade`](#stewardupgrade) | optional | steward | Steward binary upgrade policy |
| `registration_poll_timeout` | duration | `24h` | optional | steward | Max time to wait for manual registration approval when the controller uses `registration.workflow: manual-review`. Zero applies the default. |
| `dna_refresh_interval` | duration string | `"30m"` | optional | steward | How often a connected steward re-collects and publishes DNA attribute deltas (`GetDNARefreshInterval`). Must be a positive duration. |
| `observe_sweep_n` | integer | `10` (`DefaultObserveSweepN`) | optional | steward | Run the whole-domain observe sweep on every Nth convergence tick (ADR-024 Amendment 1). `0` disables the sweep; `1` runs it every tick; negative is rejected. Absent and `0` are distinguished. |
| `tenant_default_timezone` | string | `""` | optional | steward, controller | IANA timezone applied when a `reboot_window` declares none. Set on a tenant path through the controller reboot-window API (`features/controller/api/handlers_reboot_window.go`). |
| `reboot_window` | object | absent | optional | steward, controller | Maintenance window during which reboots are permitted, see [`steward.reboot_window`](#stewardreboot_window). Cascades MSP to Client to Group to Cluster to Role to Device with free override in either direction. |

#### `steward.logging`

`features/config/stewardtypes/types.go` `LoggingConfig`

| YAML field | Type | Default | Req | Description |
|---|---|---|---|---|
| `level` | string | `"info"` | optional | Verbosity: `debug`, `info`, `warn`, or `error` (validated) |

#### `steward.error_handling`

`features/config/stewardtypes/types.go` `ErrorHandlingConfig`

| YAML field | Type | Default | Req | Description |
|---|---|---|---|---|
| `module_load_failure` | string | `"continue"` | optional | Action when a module cannot be loaded |
| `resource_failure` | string | `"warn"` | optional | Action when a resource execution fails |
| `configuration_error` | string | `"fail"` | optional | Action when config validation fails |

**Valid `ErrorAction` values:**

| Value | Behavior |
|---|---|
| `continue` | Log the error and proceed with remaining resources |
| `warn` | Log a warning and proceed with remaining resources |
| `fail` | Log the error and halt execution |

#### `steward.secrets`

`features/config/stewardtypes/types.go` `SecretsConfig`

| YAML field | Type | Default | Req | Description |
|---|---|---|---|---|
| `secrets_dir` | string | `""` (platform default) | optional | Override the platform-specific secrets storage directory |
| `provider` | string | `"steward"` (applied in `features/steward/steward.go`) | optional | Secrets provider name. Registered providers live under `pkg/secrets/providers/` (`steward`, `oskeychain`, `openbao`, `sops`). |

#### `steward.script_signing`

`features/config/stewardtypes/types.go` `ScriptSigningConfig`. Validated by
`ValidateScriptSigningConfig`.

Child tenants inherit the parent's script signing config. Policy may only be **tightened**
(none to optional to required); a child cannot loosen what a parent has set.

| YAML field | Type | Default | Req | Description |
|---|---|---|---|---|
| `policy` | string | `""` (none) | optional | Enforcement level: `none`, `optional`, or `required` |
| `trust_mode` | string | `""` | optional | Which signing keys are accepted: `any_valid`, `trusted_keys`, or `trusted_keys_and_public` |
| `trusted_keys` | list[object] | `[]` | cond | Trusted signing keys, required when `trust_mode` is `trusted_keys` or `trusted_keys_and_public` |
| `allow_public_ca` | boolean | `false` | optional | Also accept signatures from public CAs when `trust_mode: trusted_keys_and_public` |
| `require_signed_adhoc` | boolean | `false` | optional | Require a valid signature on every ad-hoc script command. Rejected when `policy` is `none` or empty. Inherited from the parent when the parent sets it. |

**`trusted_keys[]` entries:** `features/config/stewardtypes/types.go` `TrustedKeyRef`

| YAML field | Type | Default | Req | Description |
|---|---|---|---|---|
| `name` | string | `""` | optional | Human-readable label for this key entry |
| `thumbprint` | string | `""` | cond | Certificate thumbprint identifying the key (`thumbprint` or `public_key_ref` required) |
| `public_key_ref` | string | `""` | cond | Opaque reference to a public key in the secrets provider (`thumbprint` or `public_key_ref` required) |

#### `steward.module_trust`

`features/config/stewardtypes/types.go` `ModuleTrustConfig`. Validated by
`ValidateModuleTrustConfig`; consumed by `features/steward/modules/trust/trust.go`.

| YAML field | Type | Default | Req | Description |
|---|---|---|---|---|
| `mode` | string | `"controller"` | optional | How module bundle signatures are verified: `strict` (the steward verifies publisher signatures itself, using the baked-in CFGMS publisher identity plus `additional_publishers`), `controller` (accept any bundle the controller approved), or `bypass` (no trust enforcement; development only) |
| `additional_publishers` | list[string] | `[]` | optional | Publisher identifiers trusted in addition to the CFGMS publisher identity baked into the steward binary. Consulted only when `mode: strict`. |

The CFGMS publisher identity is fixed at build time and cannot be changed by a cfg push. See
ADR-006 for the end-to-end module signing model.

#### `steward.upgrade`

`features/config/stewardtypes/types.go` `UpgradeConfig`

| YAML field | Type | Default | Req | Description |
|---|---|---|---|---|
| `allow_downgrade` | boolean | `false` | optional | Permit installing a version older than or equal to the running version |
| `desired_version` | string | `""` | optional | Controller-declared target steward binary version (e.g. `v0.5.21`). When set and different from the running version, the convergence loop retries the launcher swap for the staged binary. Empty disables version-convergence auto-upgrade. |

#### `steward.reboot_window`

`pkg/maintenance/schedule/parse.go` `rawConfig`; parsed and validated by `Parse` in that package.

| YAML field | Type | Default | Req | Description |
|---|---|---|---|---|
| `timezone` | string | `steward.tenant_default_timezone` | optional | IANA timezone name for the schedule entries |
| `schedules` | list[object] | `[]` | required | Window entries; each is a [schedule entry](#stewardreboot_windowschedules-entries) |

##### `steward.reboot_window.schedules[]` entries

`pkg/maintenance/schedule/parse.go` `rawSchedule`

| YAML field | Type | Req | Description |
|---|---|---|---|
| `freq` | string | required | `monthly` or `weekly` |
| `days` | list[string] | required for `weekly` | Weekday names (`sunday` to `saturday`); only valid with `freq: weekly` |
| `weekday` | string | cond | Weekday name used together with `nth` |
| `nth` | integer | cond | Nth occurrence of `weekday` in the month; only valid with `freq: monthly` |
| `after` | object | cond | Anchor (`weekday`, `nth`) after which the window opens; only valid with `freq: monthly` |
| `before` | object | cond | Anchor (`weekday`, `nth`) before which the window opens; only valid with `freq: monthly` |
| `start` | string | required | Window start time of day |
| `end` | string | required | Window end time of day |

`nth`, `after` and `before` are mutually exclusive; exactly one is required for a monthly entry.

---

### `resources[]` entries

`features/config/stewardtypes/types.go` `ResourceConfig`

| YAML field | Type | Default | Req | Description |
|---|---|---|---|---|
| `name` | string | — | **required** | Unique resource identifier across all entries |
| `module` | string | — | **required** | Module that manages this resource (e.g., `file`, `package`, `firewall`) |
| `config` | map | — | **required** | Module-specific key/value configuration passed verbatim to the module |

Resource names must be unique. Duplicate names are rejected at validation time.

---

## Common types

### Duration strings

Both controller and steward configs accept Go duration strings wherever the type is noted as
`duration` or `duration string`. Controller keys typed `duration` decode through
`features/controller/config/config.go` `Duration`. Accepted time units:

| Unit | Meaning |
|---|---|
| `ns` | nanoseconds |
| `us` | microseconds |
| `ms` | milliseconds |
| `s` | seconds |
| `m` | minutes |
| `h` | hours |

Examples: `"30s"`, `"5m"`, `"1h30m"`, `"5m30s"`

### Storage providers (controller)

The `storage.provider` field selects the backend. `storage.config` is passed verbatim to the
chosen provider.

| Provider | Status | Primary `config` keys |
|---|---|---|
| `flatfile` | Default (OSS) | Controlled via top-level `flatfile_root` and `sqlite_path` |
| `sqlite` | Supported | Provider-specific (see provider documentation) |
| `database` | Supported; the only cluster-capable backend | `host`, `port`, `database`, `username`, `password`, `sslmode` |

### Logging providers (controller)

| Provider | Common `logging.config` keys |
|---|---|
| `file` | `directory`, `file_prefix`, `max_file_size`, `max_files`, `retention_days`, `compress_rotated` |
| `timescale` | Provider-specific |

### Environment variable reference syntax

Both controller and steward configs expand environment variable references at load time,
before YAML parsing: `features/controller/config/config.go` `expandEnvWithDefaults` and
`features/steward/config/config.go` `expandEnvWithDefaults`.

| Syntax | Behavior |
|---|---|
| `${VAR}` | Expands to the value of `VAR`. If `VAR` is unset, config loading **fails immediately** with a list of missing variables (`validateEnvVars`). |
| `${VAR:-default}` | Expands to `VAR`'s value if set, otherwise `default`. |
| `$VAR` | Expands like `${VAR}` but is not checked by `validateEnvVars`; an unset `VAR` expands to an empty string. Prefer the braced form. |

Supported forms: `${VAR}` and `${VAR:-default}`.

**Controller only:** a `${VAR}` reference also resolves from a companion file variable
`<VAR>_FILE` (`EnvFileSuffix`, `resolveEnvValue`). When `VAR` is unset and `VAR_FILE` names a
readable file, the file's contents are used. This is how a secret reaches the controller
without entering the process environment (ADR-030). The steward loader has no `_FILE`
resolution.

Example:

```yaml
certificate:
  ca_path: "${CFGMS_CA_PATH:-/var/lib/cfgms/certs/ca}"
storage:
  cluster:
    session_hmac_key: "${CFGMS_STORAGE_CLUSTER_SESSION_HMAC_KEY}"   # fails fast if unset and no _FILE
```

---

## Validation rules

### Controller validation

Run inside `LoadWithPath` at startup, in this order:

| Validator | Constraint |
|---|---|
| `Config.ValidateDeploymentRings` | Ring names match `^[a-z][a-z0-9-]{0,31}$`, are unique, and `fallback_ring` names a declared ring |
| `Config.ValidateExecutionSecurity` | `security_profile` is `development`, `test`, or `public-beta`. `public-beta` additionally requires `execution.require_signed_adhoc: true`, a `transport` block, `certificate.enable_cert_management: true`, and `transport.use_cert_manager: true`. |
| `ValidateCAPath` | The final component of `certificate.ca_path` is `ca` |
| `Config.ValidateWebAuthn` | `rp_origins` non-empty and all `https://` when `rp_id` is set; `rp_origins` without `rp_id` is rejected |

Run later, at server start:

| Validator | Constraint |
|---|---|
| `TransportConfig.Validate` | `transport.listen_addr` not empty; `max_connections` at least 1; `keepalive_period` at least 1 second; a nil transport block fails |
| `ValidatePrivateListenerAddress` (`features/controller/api/server.go` `Server.Start`) | `metrics_listen_addr` and, in cluster mode, `internal_listen_addr` are `host:port` with an IP literal that is loopback or private and a numeric port 1 to 65535 |
| `CertificateConfig.ValidateCertificateArchitecture` | `certificate.architecture` is not `unified` |
| `tenant.EnforceRealmGuard` | `realm_id` well-formed; set when `ha.mode: cluster` in production |

### Steward validation

`features/config/stewardtypes/validation.go` `ValidateConfiguration`, called from `loadFromPath`
after `applyDefaults`.

| Field / rule | Constraint |
|---|---|
| `steward.id` | Must not be empty after applying defaults |
| `steward.logging.level` | Must be `debug`, `info`, `warn`, or `error` |
| `steward.converge_interval` | When set, must be a valid Go duration string and greater than zero |
| `steward.dna_refresh_interval` | When set, must be a valid Go duration string and greater than zero |
| `steward.observe_sweep_n` | Must be `0` or positive |
| `steward.script_signing.policy` | Must be `none`, `optional`, `required`, or empty |
| `steward.script_signing.trust_mode` | Must be `any_valid`, `trusted_keys`, `trusted_keys_and_public`, or empty |
| `steward.script_signing.trusted_keys` | Must be non-empty when `trust_mode` is `trusted_keys` or `trusted_keys_and_public` |
| `trusted_keys[i]` | Each entry must have at least one of `thumbprint` or `public_key_ref` |
| `steward.script_signing.require_signed_adhoc` | Requires `policy` `optional` or `required` |
| `steward.module_trust.mode` | Must be `strict`, `controller`, `bypass`, or empty |
| `steward.reboot_window` | When set, must pass `pkg/maintenance/schedule` `Validate` |
| `resources[i].name` | Must not be empty |
| `resources[i].module` | Must not be empty |
| `resources[i].config` | Must not be nil |
| resource names | Must be unique across all `resources[]` entries |

### Script signing inheritance

`features/config/stewardtypes/validation.go` `MergeScriptSigningConfig`

Child tenants inherit the parent's `script_signing` block. Policy strictness moves in one
direction only:

```
none  ->  optional  ->  required     (allowed: child tightens or keeps parent policy)
required  ->  optional               (rejected: child cannot loosen parent policy)
```

Unset fields in the child inherit from the parent. `trusted_keys` are inherited wholesale
when the child list is empty. `allow_public_ca` and `require_signed_adhoc` inherit a parent
`true`.
