# Configuration Schema Reference

Field-by-field reference for `controller.cfg` and steward `<hostname>.cfg` formats,
derived from the Go struct definitions in `features/controller/config/config.go` and
`features/steward/config/config.go`.

**Canonical working examples:**
- Controller: [`docs/deployment/controller.cfg`](../deployment/controller.cfg)
- Steward: [`docs/deployment/steward.cfg`](../deployment/steward.cfg)

---

## Controller config (`controller.cfg`)

The controller searches for its config file in this order:

1. Explicit path supplied via CLI flag
2. `CFGMS_CONTROLLER_CONFIG` environment variable
3. `/etc/cfgms/controller.cfg` (Linux) or `C:\ProgramData\cfgms\controller.cfg` (Windows)
4. `./controller.cfg` (current working directory)

If no file is found, built-in defaults are used and environment variable overrides still apply.

### Top-level fields

`Config` — `features/controller/config/config.go:70`

| YAML field | Type | Default | Req | Description | Code ref |
|---|---|---|---|---|---|
| `listen_addr` | string | `"127.0.0.1:8080"` | optional | REST API (HTTPS) listen address | config.go:72 |
| `external_url` | string | `"https://localhost:8080"` | optional | External URL for API callbacks | config.go:75 |
| `cert_path` | string | `"certs/"` | optional | Legacy TLS certificate directory (superseded by `certificate` block) | config.go:78 |
| `data_dir` | string | `"data/"` | optional | Data storage root directory | config.go:81 |
| `log_level` | string | `"info"` | optional | Log verbosity shorthand; overridden by `logging.level` if both set | config.go:84 |
| `certificate` | object | see [`certificate`](#certificate) | optional | Certificate lifecycle config | config.go:87 |
| `storage` | object | see [`storage`](#storage) | optional | Storage provider config | config.go:90 |
| `logging` | object | see [`logging`](#logging-controller) | optional | Logging provider config | config.go:93 |
| `transport` | object | see [`transport`](#transport) | optional | gRPC-over-QUIC transport config | config.go:96 |
| `admin_bundle_path` | string | `""` | optional | Path where `--init` writes the admin credential bundle (mode 0600) | config.go:101 |

**Environment overrides for top-level fields:**

| Env var | Overrides field |
|---|---|
| `CFGMS_LISTEN_ADDR` | `listen_addr` |
| `CFGMS_HTTP_LISTEN_ADDR` | `listen_addr` (same field, last one wins) |
| `CFGMS_EXTERNAL_URL` | `external_url` |
| `CFGMS_CERT_PATH` | `cert_path` |
| `CFGMS_DATA_DIR` | `data_dir` |
| `CFGMS_LOG_LEVEL` | `log_level` and `logging.level` |

---

### `certificate`

`CertificateConfig` — `features/controller/config/config.go:105`

| YAML field | Type | Default | Req | Description | Code ref |
|---|---|---|---|---|---|
| `enable_cert_management` | boolean | `true` | optional | Automate full certificate lifecycle (generate, load, validate, renew, distribute) | config.go:121 |
| `ca_path` | string | `"certs/ca"` | optional | Directory for CA certificate storage | config.go:124 |
| `renewal_threshold_days` | integer | `30` | optional | Days before expiry at which certificates are renewed | config.go:128 |
| `server_cert_validity_days` | integer | `365` | optional | Server certificate validity period in days | config.go:132 |
| `client_cert_validity_days` | integer | `365` | optional | Steward client certificate validity period in days | config.go:136 |
| `server` | object | see [`certificate.server`](#certificateserver) | optional | Server certificate identity settings | config.go:139 |
| `architecture` | string | `""` (unified) | optional | Certificate deployment mode: `unified` or `separated` | config.go:146 |
| `signing_cert_validity_days` | integer | `0` | optional | Config signing cert validity; `0` lets the cert manager use its built-in default (~1095 days) | config.go:149 |
| `internal_cert_validity_days` | integer | `0` | optional | Internal mTLS cert validity; `0` lets the cert manager use its built-in default (~365 days) | config.go:152 |
| `public_api` | object | `nil` | optional | Public API cert config — only used when `architecture: separated` | config.go:155 |
| `internal` | object | `nil` | optional | Internal mTLS cert config — only used when `architecture: separated` | config.go:158 |
| `signing` | object | `nil` | optional | Config signing cert config — only used when `architecture: separated` | config.go:161 |

**`architecture` values:**
- `unified` (default when unset): a single server certificate is used for all purposes
- `separated`: purpose-specific certificates for public API, internal mTLS, and config signing

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

`ServerCertificateConfig` — `features/controller/config/config.go:206`

| YAML field | Type | Default | Req | Description | Code ref |
|---|---|---|---|---|---|
| `common_name` | string | `"cfgms-controller"` | optional | CN embedded in the generated server certificate | config.go:208 |
| `dns_names` | list[string] | `["localhost","cfgms-controller","controller-standalone"]` | optional | Subject Alternative Name DNS entries | config.go:211 |
| `ip_addresses` | list[string] | `["127.0.0.1"]` | optional | Subject Alternative Name IP entries | config.go:214 |
| `organization` | string | `"CFGMS"` | optional | Organization name embedded in the certificate | config.go:217 |

#### `certificate.public_api` (separated architecture)

`PublicAPICertConfig` — `features/controller/config/config.go:165`

| YAML field | Type | Default | Req | Description | Code ref |
|---|---|---|---|---|---|
| `source` | string | `"internal"` | optional | `internal` (CA-generated) or `external` (load from files) | config.go:169 |
| `cert_path` | string | `""` | cond | Certificate file path — required when `source: external` | config.go:172 |
| `key_path` | string | `""` | cond | Private key file path — required when `source: external` | config.go:175 |
| `common_name` | string | `""` | optional | CN for the public API certificate | config.go:178 |
| `dns_names` | list[string] | `[]` | optional | Subject Alternative Name DNS entries | config.go:181 |

#### `certificate.internal` (separated architecture)

`InternalCertConfig` — `features/controller/config/config.go:185`

| YAML field | Type | Default | Req | Description | Code ref |
|---|---|---|---|---|---|
| `common_name` | string | `"cfgms-internal"` | optional | CN for the internal mTLS certificate | config.go:187 |
| `dns_names` | list[string] | `[]` | optional | Subject Alternative Name DNS entries | config.go:190 |
| `ip_addresses` | list[string] | `[]` | optional | Subject Alternative Name IP entries | config.go:193 |

#### `certificate.signing` (separated architecture)

`SigningCertificateConfig` — `features/controller/config/config.go:197`

| YAML field | Type | Default | Req | Description | Code ref |
|---|---|---|---|---|---|
| `common_name` | string | `"cfgms-config-signer"` | optional | CN for the config signing certificate | config.go:199 |
| `organization` | string | `""` | optional | Organization name embedded in the certificate | config.go:202 |

---

### `storage`

`StorageConfig` — `features/controller/config/config.go:221`

| YAML field | Type | Default | Req | Description | Code ref |
|---|---|---|---|---|---|
| `provider` | string | `"flatfile"` | required | Storage backend: `flatfile`, `database`, or `sqlite` | config.go:225 |
| `config` | map | `{}` | optional | Provider-specific key/value configuration passed verbatim | config.go:229 |
| `flatfile_root` | string | `"data/cfgms-config"` | cond | Root directory for flat-file storage; enables OSS composite manager when set | config.go:235 |
| `sqlite_path` | string | `"data/cfgms.db"` | cond | SQLite file path for OSS composite manager; required when `flatfile_root` is set | config.go:240 |

Setting `flatfile_root` and `sqlite_path` together activates the OSS composite storage manager
(flat-file + SQLite). If only one is set the provider falls through to the single-provider path.

The `git` provider is deprecated. Migrate with: `cfg storage migrate --from git --to flatfile`

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
| `CFGMS_STORAGE_GIT_PATH` | `storage.config["path"]` (git provider — deprecated) |
| `CFGMS_STORAGE_GIT_URL` | `storage.config["url"]` (git provider — deprecated) |
| `CFGMS_STORAGE_GIT_BRANCH` | `storage.config["branch"]` (git provider — deprecated) |
| `CFGMS_STORAGE_GIT_USERNAME` | `storage.config["username"]` (git provider — deprecated) |
| `CFGMS_STORAGE_GIT_PASSWORD` | `storage.config["password"]` (git provider — deprecated) |
| `CFGMS_STORAGE_GIT_TOKEN` | `storage.config["token"]` (git provider — deprecated) |

---

### `logging` (controller)

`LoggingConfig` — `features/controller/config/config.go:244`

| YAML field | Type | Default | Req | Description | Code ref |
|---|---|---|---|---|---|
| `provider` | string | `"file"` | required | Logging backend: `file`, `timescale`, or `clickhouse` | config.go:246 |
| `config` | map | see note | optional | Provider-specific key/value configuration passed verbatim | config.go:250 |
| `level` | string | `"INFO"` | optional | Minimum log level: `DEBUG`, `INFO`, `WARN`, `ERROR`, `FATAL` | config.go:253 |
| `service_name` | string | `"cfgms-controller"` | optional | Service identifier attached to every log record | config.go:254 |
| `component` | string | `"controller"` | optional | Component identifier attached to every log record | config.go:255 |
| `batch_size` | integer | `100` | optional | Number of entries per write batch | config.go:258 |
| `flush_interval` | string | `"5s"` | optional | Auto-flush interval (Go duration string) | config.go:259 |
| `async_writes` | boolean | `true` | optional | Write log entries asynchronously | config.go:260 |
| `buffer_size` | integer | `1000` | optional | Internal write-buffer capacity | config.go:261 |
| `retention_days` | integer | `30` | optional | Log retention period in days (provider-dependent) | config.go:264 |
| `compress_logs` | boolean | `true` | optional | Compress rotated log files | config.go:265 |
| `tenant_isolation` | boolean | `true` | optional | Enable per-tenant log namespace isolation | config.go:268 |
| `enable_correlation` | boolean | `true` | optional | Attach automatic correlation IDs to log records | config.go:271 |
| `enable_tracing` | boolean | `true` | optional | Enable OpenTelemetry trace integration | config.go:272 |
| `subscribers` | list[object] | `[]` | optional | Real-time event forwarding targets | config.go:275 |

Default `logging.config` for the `file` provider:
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

`SubscriberConfig` — `features/controller/config/config.go:279`

| YAML field | Type | Default | Req | Description | Code ref |
|---|---|---|---|---|---|
| `type` | string | `""` | required | Subscriber type: `syslog` or `webhook` | config.go:280 |
| `config` | map | `{}` | optional | Subscriber-specific key/value configuration | config.go:281 |
| `enabled` | boolean | `false` | optional | Enable or disable this subscriber | config.go:282 |

---

### `transport`

`TransportConfig` — `features/controller/config/config.go:312`

| YAML field | Type | Default | Req | Description | Code ref |
|---|---|---|---|---|---|
| `listen_addr` | string | `"0.0.0.0:4433"` | **required** | gRPC-over-QUIC listen address (UDP); must not be empty | config.go:314 |
| `use_cert_manager` | boolean | `true` | optional | Use the controller's certificate manager for TLS; set `CFGMS_TRANSPORT_USE_CERT_MANAGER=true` in production | config.go:318 |
| `max_connections` | integer | `50000` | optional | Maximum number of concurrent steward connections; must be ≥ 1 | config.go:321 |
| `keepalive_period` | duration | `"30s"` | optional | Interval for keepalive probes to detect dead connections; must be ≥ 1s | config.go:325 |
| `idle_timeout` | duration | `"5m"` | optional | How long a connection may remain idle before the controller closes it | config.go:329 |

**Environment overrides for `transport`:**

| Env var | Overrides field |
|---|---|
| `CFGMS_TRANSPORT_LISTEN_ADDR` | `transport.listen_addr` |
| `CFGMS_TRANSPORT_USE_CERT_MANAGER` | `transport.use_cert_manager` |
| `CFGMS_TRANSPORT_MAX_CONNECTIONS` | `transport.max_connections` |
| `CFGMS_TRANSPORT_KEEPALIVE_PERIOD` | `transport.keepalive_period` |
| `CFGMS_TRANSPORT_IDLE_TIMEOUT` | `transport.idle_timeout` |

---

## Steward config (`<hostname>.cfg`)

The steward uses the current hostname as its config filename (e.g., `web-01.cfg`).
When no explicit path is supplied it searches these locations in order:

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

### Top-level fields

`StewardConfig` — `features/steward/config/config.go:120`

| YAML field | Type | Default | Req | Description | Code ref |
|---|---|---|---|---|---|
| `steward` | object | see [`steward`](#steward-section) | **required** | Steward identity and runtime settings | config.go:122 |
| `resources` | list[object] | `[]` | **required** | Resources to manage (empty list is valid for controller-connected mode) | config.go:125 |
| `modules` | map[string]string | `{}` | optional | Custom module paths: `module_name: /path/to/binary` | config.go:128 |

---

### `steward` section

Fields from `StewardSettings` embedded in `StewardConfig.Steward` —
`features/steward/config/config.go:131`

| YAML field | Type | Default | Req | Description | Code ref |
|---|---|---|---|---|---|
| `id` | string | `<hostname>` | **required** | Unique steward identifier; the controller uses this to route pushed configs | config.go:137 |
| `mode` | string | `"standalone"` | optional | Operation mode: `standalone` (local cfg) or `controller` (legacy push mode) | config.go:140 |
| `module_paths` | list[string] | `[]` | optional | Additional directories searched for module binaries | config.go:143 |
| `logging` | object | see [`steward.logging`](#stewardlogging) | optional | Log verbosity and output format | config.go:146 |
| `error_handling` | object | see [`steward.error_handling`](#stewarderror_handling) | optional | Per-condition error response policies | config.go:149 |
| `secrets` | object | see [`steward.secrets`](#stewardsecrets) | optional | Secret store configuration | config.go:152 |
| `converge_interval` | duration string | `"30m"` | optional | How often the steward re-converges desired state; omit to run once and exit | config.go:156 |
| `script_signing` | object | see [`steward.script_signing`](#stewardscript_signing) | optional | Script signature policy and trusted key allowlist | config.go:160 |
| `signed_command_replay_window` | duration | `5m` (zero → default) | optional | Max age for accepted signed command timestamps; shorter = stricter replay protection | config.go:166 |
| `signed_command_max_params_bytes` | integer | `65536` (zero → default) | optional | Max JSON-serialized size of `Command.Params` in bytes | config.go:171 |

#### `steward.logging`

`LoggingConfig` — `features/steward/config/config.go:275`

| YAML field | Type | Default | Req | Description | Code ref |
|---|---|---|---|---|---|
| `level` | string | `"info"` | optional | Verbosity: `debug`, `info`, `warn`, or `error` | config.go:277 |
| `format` | string | `"text"` | optional | Output format: `text` or `json` | config.go:280 |

#### `steward.error_handling`

`ErrorHandlingConfig` — `features/steward/config/config.go:287`

| YAML field | Type | Default | Req | Description | Code ref |
|---|---|---|---|---|---|
| `module_load_failure` | string | `"continue"` | optional | Action when a module cannot be loaded | config.go:289 |
| `resource_failure` | string | `"warn"` | optional | Action when a resource execution fails | config.go:292 |
| `configuration_error` | string | `"fail"` | optional | Action when config validation fails | config.go:295 |

**Valid `ErrorAction` values:**

| Value | Behavior |
|---|---|
| `continue` | Log the error and proceed with remaining resources |
| `warn` | Log a warning and proceed with remaining resources |
| `fail` | Log the error and halt execution |

#### `steward.secrets`

`SecretsConfig` — `features/steward/config/config.go:176`

| YAML field | Type | Default | Req | Description | Code ref |
|---|---|---|---|---|---|
| `secrets_dir` | string | `""` (platform default) | optional | Override the platform-specific secrets storage directory | config.go:178 |
| `provider` | string | `"steward"` | optional | Secrets provider selection | config.go:181 |

#### `steward.script_signing`

`ScriptSigningConfig` — `features/steward/config/config.go:228`

Child tenants inherit the parent's script signing config. Policy may only be **tightened**
(none → optional → required); a child cannot loosen what a parent has set.

| YAML field | Type | Default | Req | Description | Code ref |
|---|---|---|---|---|---|
| `policy` | string | `""` (none) | optional | Enforcement level: `none`, `optional`, or `required` | config.go:230 |
| `trust_mode` | string | `""` | optional | Which signing keys are accepted: `any_valid`, `trusted_keys`, or `trusted_keys_and_public` | config.go:233 |
| `trusted_keys` | list[object] | `[]` | cond | Trusted signing keys — required when `trust_mode` is `trusted_keys` or `trusted_keys_and_public` | config.go:237 |
| `allow_public_ca` | boolean | `false` | optional | Also accept signatures from public CAs when `trust_mode: trusted_keys_and_public` | config.go:241 |
| `script_repo_url` | string | `""` | optional | MSP-level Git repository URL for the tenant's script store; child tenants may override | config.go:245 |

**`trusted_keys[]` entries — `TrustedKeyRef`** — `features/steward/config/config.go:212`

| YAML field | Type | Default | Req | Description | Code ref |
|---|---|---|---|---|---|
| `name` | string | `""` | optional | Human-readable label for this key entry | config.go:214 |
| `thumbprint` | string | `""` | cond | Certificate thumbprint identifying the key (thumbprint or `public_key_ref` required) | config.go:217 |
| `public_key_ref` | string | `""` | cond | Opaque reference to a public key in the secrets provider (thumbprint or `public_key_ref` required) | config.go:220 |

---

### `resources[]` entries

`ResourceConfig` — `features/steward/config/config.go:252`

| YAML field | Type | Default | Req | Description | Code ref |
|---|---|---|---|---|---|
| `name` | string | — | **required** | Unique resource identifier across all entries | config.go:254 |
| `module` | string | — | **required** | Module that manages this resource (e.g., `directory`, `packages`, `firewall`) | config.go:257 |
| `config` | map | — | **required** | Module-specific key/value configuration passed verbatim to the module | config.go:260 |

Resource names must be unique. Duplicate names are rejected at validation time.

---

## Common types

### Duration strings

Both controller and steward configs accept Go duration strings wherever the type is noted as
`duration` or `duration string`. Accepted time units:

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
| `database` | Supported | `host`, `port`, `database`, `username`, `password`, `sslmode` |
| `sqlite` | Supported | Provider-specific (see provider documentation) |
| `git` | **Deprecated** | `path`, `url`, `branch`, `username`, `password`, `token` |

Migrate away from git: `cfg storage migrate --from git --to flatfile`

### Logging providers (controller)

| Provider | Common `logging.config` keys |
|---|---|
| `file` | `directory`, `file_prefix`, `max_file_size`, `max_files`, `retention_days`, `compress_rotated` |
| `timescale` | Provider-specific |
| `clickhouse` | Provider-specific |

### Environment variable reference syntax

Both controller and steward configs expand environment variable references at load time,
before YAML parsing. The expansion is implemented in both config packages:
`features/controller/config/config.go:50` and `features/steward/config/config.go:96`

| Syntax | Behavior |
|---|---|
| `${VAR}` | Expands to the value of `VAR`. If `VAR` is unset, config loading **fails immediately** with a list of missing variables. |
| `${VAR:-default}` | Expands to `VAR`'s value if set, otherwise `default`. |
| `${VAR:=default}` | Same expansion behavior as `:-` in this config context. |

Example:

```yaml
certificate:
  ca_path: "${CFGMS_CA_PATH:-/var/lib/cfgms/certs/ca}"
storage:
  config:
    password: "${DB_PASSWORD}"   # fails fast if DB_PASSWORD is unset
```

---

## Validation rules

### Controller validation

`TransportConfig.Validate()` — `features/controller/config/config.go:334`

| Field | Constraint |
|---|---|
| `transport.listen_addr` | Must not be empty |
| `transport.max_connections` | Must be ≥ 1 |
| `transport.keepalive_period` | Must be ≥ 1 second |

Validation runs at startup. A nil `TransportConfig` also fails validation.

### Steward validation

`ValidateConfiguration()` — `features/steward/config/config.go:586`

| Field / rule | Constraint |
|---|---|
| `steward.id` | Must not be empty after applying defaults |
| `steward.mode` | Must be `standalone` or `controller` |
| `steward.logging.level` | Must be `debug`, `info`, `warn`, or `error` |
| `steward.converge_interval` | When set, must be a valid Go duration string and greater than zero |
| `steward.script_signing.policy` | Must be `none`, `optional`, `required`, or empty |
| `steward.script_signing.trust_mode` | Must be `any_valid`, `trusted_keys`, `trusted_keys_and_public`, or empty |
| `steward.script_signing.trusted_keys` | Must be non-empty when `trust_mode` is `trusted_keys` or `trusted_keys_and_public` |
| `trusted_keys[i]` | Each entry must have at least one of `thumbprint` or `public_key_ref` |
| `resources[i].name` | Must not be empty |
| `resources[i].module` | Must not be empty |
| `resources[i].config` | Must not be nil |
| resource names | Must be unique across all `resources[]` entries |

### Script signing inheritance

`MergeScriptSigningConfig()` — `features/steward/config/config.go:537`

Child tenants inherit the parent's `script_signing` block. Policy strictness moves in one
direction only:

```
none  →  optional  →  required     (allowed: child tightens or keeps parent policy)
required  →  optional              (rejected: child cannot loosen parent policy)
```

Unset fields in the child inherit from the parent. `trusted_keys` are inherited wholesale
when the child list is empty.
