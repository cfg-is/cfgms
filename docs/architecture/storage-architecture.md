# Storage Architecture

> **Source of truth**: [ADR-003: Storage Data Taxonomy](decisions/003-storage-data-taxonomy.md).
> This document is the operator-facing walk-through of the decision recorded in ADR-003.

## Summary

CFGMS controller storage is partitioned into five data types. Each type has its own interfaces and its own backend selection. Deployments compose one provider per type rather than choosing a single global backend.

Git is not a storage backend. For OSS, file-based storage is served by a flat-file provider; the admin is responsible for backups. Git re-enters the architecture as an *optional sync source* for admin-designated config scopes, implemented by a single git-sync component that works against both flat-file (OSS) and PostgreSQL (commercial) backends.

> **Scope note**: This document covers controller-side storage. Steward persistence (local config file, OS keychain, in-memory state between convergence runs) is a separate, simpler concern.

## The Five Data Types

| Type | OSS default | Commercial/SaaS default |
|------|-------------|-------------------------|
| Business data | SQLite | PostgreSQL |
| Config storage | Flat file | PostgreSQL |
| Config *git sync* (optional, per-scope) | Flat file ⇄ external git origin | PostgreSQL ⇄ external git origin |
| Secrets | SOPS files / OpenBao (dev-mode) | Key vault (AWS Secrets Manager / HashiCorp Vault / OpenBao cluster / Azure Key Vault) |
| Timeseries | Local log files | ClickHouse / Timescale / Influx |
| Blobs | Local filesystem | S3-compatible object storage |

**OSS column shows defaults, not limits.** Any backend listed in the Commercial column is available to OSS deployments — the licensing boundary is single-root tenant tree shape, not backend choice. An OSS single-root MSP is welcome to run PostgreSQL, Vault, and S3 if that's what fits the environment. See [LICENSING.md](../../LICENSING.md).

### What belongs where

- **Business data**: tenants, stewards, commands, RBAC, sessions, audit logs, registration tokens, client-tenant records. Transactional, queryable, must survive restart.
- **Config storage**: human-editable configs (templates, policy, firewall rules). May be edited in the backend directly or imported from an external git origin via git-sync.
- **Secrets**: credentials, API keys, certificates. Always encrypted at rest.
- **Timeseries**: metrics and logs. Append-only, retention-driven, purged by age.
- **Blobs**: installer binaries, script bodies, report exports. Large, cheap, immutable.

## Git Is a Sync Source, Not a Backend

The previous architecture treated Git as a first-class storage backend (one commit per write, history-as-audit). That has been retired. Git now enters the architecture only as an *external source* that the admin binds to specific config scopes.

### The model

1. The admin designates one or more **scopes** (tenant path + namespace, e.g., `root/msp-a/client-1/firewall`) as git-synced.
2. Each scope binds to an external git origin: URL, branch, credentials reference.
3. The git-sync component pulls from each bound origin on webhook (push event) with a polling fallback.
4. Imported configs write through to the controller's config backend — flat-file for OSS, PostgreSQL for commercial.
5. Unbound scopes live natively in the backend.
6. The read path is always the backend. Git is the *editing surface* for bound scopes, not a query target.

**v1 is strictly one-way, read-only** (git → backend). The controller never writes to the git origin. For bound scopes, all edits happen at the git origin — the admin opens a PR, merges it, and git-sync pulls the result. UI-initiated edits on bound scopes are not supported in v1; they either fail or fall through to unbound scopes. Bidirectional sync is out of scope for v1 and will be a future ADR if demand emerges.

### Why one component, two backends

The same git-sync code path serves both OSS and commercial deployments. The only variable is the backend adapter it writes through to. This avoids the fork that would result from git-as-backend-for-OSS and git-sync-for-SaaS existing side-by-side.

### Implementation: `pkg/gitsync`

The git-sync component lives in `pkg/gitsync/` and is wired into the controller server at startup.

**Key types:**

| Type | Purpose |
|------|---------|
| `ScopeBinding` | Binds a tenant path + namespace to an external git origin (URL, branch, credential ref, polling interval) |
| `BindingStore` | Persists bindings to `<data-dir>/.gitsync/bindings.json`; tracks last-synced SHA per scope |
| `Syncer` | Orchestrates clone/pull, idempotency checks, and write-through to `ConfigStore` |
| `WebhookHandler` | HTTP handler for push-event webhooks; validates HMAC-SHA256; dispatches `TriggerSync` |

**Scope binding fields:**

| Field | Description |
|-------|-------------|
| `TenantPath` | CFGMS tenant path, e.g. `root/msp-a/client-1` |
| `Namespace` | Config namespace supplied by the bound origin, e.g. `firewall` |
| `OriginURL` | External git repository URL |
| `Branch` | Branch to track (default: `main`) |
| `CredentialsRef` | Credential reference: `""` = anonymous, `"env:<VAR>"` = env var, path = file |
| `WebhookSecretRef` | Webhook HMAC-SHA256 secret reference (same format as CredentialsRef); required for the binding to be webhook-triggerable |
| `PollingInterval` | Polling frequency; minimum 60 s; zero disables polling |

**Credentials (v1):** `CredentialsRef` and `WebhookSecretRef` accept an environment-variable name (prefix `env:`) or a filesystem path to a file containing the credential. TODO: migrate to `pkg/secrets` `SecretStore` once sub-story H lands.

**Webhook endpoint:** `POST /api/v1/webhooks/git-push`. Accepts GitHub and GitLab push-event payloads. The HMAC-SHA256 signature is the endpoint's only credential, so validation is mandatory and fails closed: every binding matched by a push event must carry a `WebhookSecretRef`, and `X-Hub-Signature-256` must validate against it. Requests with an invalid or missing signature — and requests matching a binding that has no `WebhookSecretRef` — are rejected with HTTP 401. A binding without a webhook secret is not webhook-triggerable; it still syncs on its `PollingInterval`.

**Polling:** Minimum interval is 60 seconds. Polling goroutines are per-scope; a failure in one scope does not block others.

**Idempotency:** The syncer tracks the last-synced commit SHA per scope in the `BindingStore`. Re-syncing the same commit is a no-op — `ConfigStore.StoreConfig` is not called a second time.

**Conflict detection:** v1 does not merge; if the remote has diverged from the last-synced commit in a non-fast-forward way, the sync is logged and skipped for that scope.

**Scope isolation:** A failure syncing one scope (origin unreachable, auth failure, branch not found) does not stop other scopes from syncing. Errors are logged with origin URL sanitized (`logging.SanitizeLogValue`).

## MSP GitOps Example

An MSP hosting configs on GitHub with PR-based change management continues to work exactly as today:

1. MSP keeps config repo on `github.com:msp-corp/cfgms-configs`.
2. Admin binds scope `root/msp-corp` to that origin, branch `main`.
3. Config author opens a PR on GitHub.
4. Reviewer approves and merges.
5. GitHub sends webhook → CFGMS git-sync imports the merged tree.
6. Scopes not under `root/msp-corp` (e.g., fleet-wide policy set by the platform admin) stay in the backend, unaffected.

OSS deployments: the imported configs land in flat-file storage. Admin runs their own backup.
Commercial deployments: the imported configs land in PostgreSQL. HA, replication, PITR come from the database.

## Flat-File Provider (OSS)

The flat-file provider (`pkg/storage/providers/flatfile`) is the OSS default for config storage. It stores configs and audit logs as files under a configured root directory.

**File layout**:

```
<root>/
  <tenantID>/
    configs/
      <namespace>/
        <name>.<format>    # JSON-encoded ConfigEntry; extension = data format
    audit/
      <YYYY-MM-DD>.jsonl   # Append-only JSONL; one entry per line
```

**Admin responsibilities**:
- Backups. CFGMS does not version at the storage layer. Use filesystem snapshots, rsync, restic, or an equivalent. A `cfg backup` CLI helper is planned (sub-story B).
- Filesystem durability. SSD + regular snapshots is sufficient for single-controller OSS.
- Access control. Directory is readable/writable only by the controller process.

**What the flat-file provider implements**:
- `ConfigStore`: store, retrieve, list, delete configs; inheritance resolution via tenant path
- `AuditStore`: append-only JSONL per day per tenant; immutable entries; purge/archive by date

**What the flat-file provider does not do**:
- Automatic version history. (`GetConfigHistory` returns the current version only. Use git-sync if you want PR-based change management.)
- Replication. (Use PostgreSQL if you need HA.)
- Arbitration. (Single-writer; not safe for multiple controllers to share the same root.)
- Business-data stores (`RBACStore`, `TenantStore`, `SessionStore`, etc.) — these belong in SQLite/PostgreSQL.

**Registration**: The provider auto-registers on import via `init()`. A blank import is sufficient:

```go
import _ "github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
```

## Migration from the git provider

The git storage provider was removed in Issue #664. Existing deployments running on the git backend must migrate to `flatfile` (config + audit) plus `sqlite` (business data) before upgrading. The controller rejects `provider: git` at startup with a message pointing here.

**One-shot migration command:**

Use the general-purpose migration path (`cfg migrate --provider storage`) or the legacy alias
`cfg storage migrate`; both delegate through the same provider-agnostic migration seam (Issue #2258):

```bash
cfg migrate --provider storage \
  --from git \
  --to flatfile \
  --git-root  /var/lib/cfgms/git-storage \
  --flatfile-root /var/lib/cfgms/flatfile
```

`cfg storage migrate` also works and delegates to the same seam when a `storage` migrator is registered.

What this does:

- Reads every config and audit entry from the git-backed store at `--git-root`
- Writes them into the flatfile layout at `--flatfile-root` using upsert semantics
- Reports per-store counts (configs migrated, audit entries migrated)
- Leaves the source repository untouched — safe to re-run for verification

**Idempotent**: running the command twice against the same target produces the same record count with no duplicates. Safe to rehearse against a copy of production data before cutting over.

**Dry-run preview**: pass `--dry-run` to read all source records and report per-store counts without writing anything to the target. Use this to confirm expected counts before scheduling downtime:

```bash
cfg storage migrate --from git --to flatfile \
  --git-root /var/lib/cfgms/git-storage \
  --flatfile-root /var/lib/cfgms/flatfile \
  --dry-run
```

See [docs/operations/backend-migration.md](../operations/backend-migration.md) for the full offline-cutover procedure and downtime envelope.

### Stores covered by the storage migrator

The `cfg migrate --provider storage` pathway covers the following store kinds. Each row shows whether the OSS (flatfile+SQLite) and database (PostgreSQL) backends support export and import for that kind.

| Store kind | OSS | PostgreSQL | Notes |
|---|---|---|---|
| `tenant` | ✓ | ✓ | Tenant tree |
| `config` | ✓ | ✓ | Config entries |
| `audit` | ✓ | ✓ | Audit log entries |
| `registration_token` | ✓ | ✓ | Steward registration tokens |
| `session` | ✓ | ✓ | Admin sessions |
| `steward` | ✓ | ✓ | Steward fleet records |
| `command` | ✓ | ✓ | Command records |
| `trigger` | ✓ | ✓ | Workflow trigger records; PostgreSQL store added in Issue #3402 |
| `push` | ✓ | ✓ | Push-state records for failover replay; PostgreSQL store added in Issue #3402 — enables `resumePendingPushes` in cluster mode |
| `ip_trust` | ✓ | ✓ | Trusted IP ranges per tenant |
| `refresh_policy` | ✓ | ✓ | Per-tenant DNA refresh approval policy (Issue #2329) |
| `pending_refresh` | ✓ | ✓ | Pending DNA refresh requests (Issue #2329) |
| `pending_registration` | ✓ | ✓ | In-flight steward registration requests (Issue #3224); the PostgreSQL store is reachable through `DatabaseProvider.CreatePendingRegistrationStore` as of Issue #3401 |

**Running the PostgreSQL store tests.** The `pkg/storage/providers/database` tests, and the
Postgres-backed tests in `pkg/storage/interfaces` and `features/controller/api`, skip
themselves when no test database is reachable. `make test-integration-setup && make
test-integration-db` is their run path; no CI workflow provisions PostgreSQL, so a green
CI run is not evidence that any of them executed.

**Fail-loud on unmigratable kinds (Issue #3404).** Kinds marked `—` in the table above would
cause the migration to **fail** when the source has records of that kind and the destination
backend does not support the store — the migration does not silently drop records and report
success. This applies to both `Plan` (dry-run) and `Run` — the dry run surfaces unmigratable
kinds before any writes are attempted, so an operator learns about a destination gap before
committing to a maintenance window. As of Issue #3402, `trigger` and `push` are fully
supported on both OSS and PostgreSQL, so no kind currently triggers this path — but the
mechanism remains in place for any future kind that is backend-specific.

To acknowledge data loss for a kind the destination genuinely does not support, pass
`WithSkippedKinds` explicitly:

```go
m := storage.NewStorageMigrator(src, dst,
    storage.WithSkippedKinds("some_kind"))
```

The acknowledged kinds and their source counts appear in
`MigrationReport.SkippedKinds`. The default path (without the option) fails; there is
no silent drop.

The per-kind integrity check at the end of `Run` compares counts for all kinds the
destination supports (and that are not explicitly skipped). An idempotent re-run after a
partial migration converges: already-imported records are upserted without duplicates.

**Not yet covered:** `AlertStore` (tenant-scoped alert acknowledgement and silence records, Issue #3266) has no entry in this table because `pkg/migrate/storage/migrate.go` does not define a kind constant or export/import case for it yet — a `cfg migrate --provider storage` run does not transfer alert acknowledge/silence state in either direction. Wire it into the migrator (kind constant, export/import case, kind-availability map entry) before relying on migration to carry this state.

**Config update required after migration.** Replace the old single-provider block with OSS composite:

```yaml
# Before (git — no longer supported)
storage:
  provider: git
  config:
    repository_path: /var/lib/cfgms/git-storage

# After (flatfile + sqlite composite)
storage:
  provider: flatfile
  flatfile_root: /var/lib/cfgms/flatfile
  sqlite_path: /var/lib/cfgms/cfgms.db
```

Business-data tables (tenants, RBAC, sessions, registration tokens) are created fresh in the new SQLite file — they weren't persisted by the git provider in a migratable form. Plan a short re-seeding window (re-issue registration tokens, re-apply RBAC bindings) as part of the cutover.

## Interface Layout

Target layout (tracked under the ADR-003 epic):

```
pkg/storage/interfaces/
  business/       # TenantStore, ClientTenantStore, StewardStore, CommandStore,
                  # AuditStore, RBACStore, SessionStore, RegistrationTokenStore
  config/         # ConfigStore
  secrets/        # SecretStore
  timeseries/     # MetricsStore, LogStore
  blob/           # BlobStore
```

**Naming rule**: anything ending in `*Store` is durable. Anything ephemeral (resolved configs, inheritance memoization, rebuildable-on-restart state) is named `*Cache` and lives under [`pkg/cache/`](../../pkg/cache/). The old `RuntimeStore` mixed both and has been retired — its durable parts moved to `business/SessionStore`, its ephemeral parts moved to `pkg/cache`.

**`ClientTenantStore` is unified.** The former `M365ClientTenantStore` folds in. Provider-specific data (M365 consent state, AD domain binding, Intune enrollment) is carried as extension fields so that a single endpoint or user can be correlated across steward, Intune, and AD.

Interfaces are organized into five sub-packages under `pkg/storage/interfaces/`: `business/`, `config/`, `blob/`, `secrets/`, and `timeseries/`. See [`pkg/storage/interfaces/README.md`](../../pkg/storage/interfaces/README.md) for the layout and import paths.

## Configuration Example

```yaml
# cfgms.yaml — five-type storage composition (commercial/SaaS example)
controller:
  storage:
    business:
      provider: postgres
      config:
        host: cfgms-postgres.internal
        database: cfgms
        max_open_connections: 100

    config:
      provider: postgres
      config:
        host: cfgms-postgres.internal
        database: cfgms

    secrets:
      provider: vault
      config:
        address: https://vault.internal
        mount: cfgms

    timeseries:
      provider: clickhouse
      config:
        host: clickhouse.internal

    blobs:
      provider: s3
      config:
        bucket: cfgms-blobs
        region: us-east-1

  # Optional: scopes that should be imported from external git
  git_sync:
    - scope: root/msp-corp
      origin: git@github.com:msp-corp/cfgms-configs.git
      branch: main
      credentials_ref: secrets/git/msp-corp
```

```yaml
# cfgms.yaml — OSS single-controller example
controller:
  storage:
    business:
      provider: sqlite
      config:
        path: /var/lib/cfgms/business.db

    config:
      provider: flatfile
      config:
        root: /var/lib/cfgms/configs

    secrets:
      provider: sops
      config:
        root: /var/lib/cfgms/secrets

    timeseries:
      provider: filelog
      config:
        root: /var/lib/cfgms/timeseries

    blobs:
      provider: filesystem
      config:
        root: /var/lib/cfgms/blobs
```

## Blob Storage

Blobs are large, immutable artifacts: installer binaries, script bodies, report exports, DNA snapshots. They are not embedded in config entries; they live in a dedicated `BlobStore` provider.

### Interface

`pkg/storage/interfaces/blob/blob_store.go` defines the `BlobStore` interface and associated types:

```go
// BlobKey uniquely identifies a blob within CFGMS.
type BlobKey struct {
    TenantID  string // Mandatory. Multi-tenant isolation.
    Namespace string // Category partition (e.g., "installers", "reports", "dna-snapshots").
    Name      string // Blob name within the namespace.
}

// BlobStore methods: PutBlob, GetBlob, DeleteBlob, ListBlobs, BlobExists, HealthCheck
```

`BlobStore` is **not** part of the general `StorageProvider` interface. It has its own registry in `blob_provider.go` (`RegisterBlobProvider` / `GetBlobProvider` / `CreateBlobStoreFromConfig`) following the same auto-registration pattern.

### Providers

| Provider | Package | OSS default | Notes |
|----------|---------|-------------|-------|
| `filesystem` | `pkg/storage/providers/blobstore/filesystem/` | Yes | Streams via `io.Copy`; atomic temp+rename writes; SHA-256 sidecar |
| `s3` | `pkg/storage/providers/blobstore/s3/` | No (operator choice) | AWS SDK v2; bucket + prefix key mapping; JSON sidecar object |

Both providers:
- Validate that `BlobKey.TenantID` is non-empty (`ErrBlobTenantRequired`).
- Store a JSON metadata sidecar (`<key>.meta.json`) alongside each blob holding `ContentType`, `Size`, `Checksum` (SHA-256 hex), `CreatedAt`, and `Labels`.
- Compute SHA-256 during the write pass (no re-read required).

**Filesystem provider specifics**:
- Blob path: `<root>/<tenantID>/<namespace>/<name>`
- Writes are streamed through `io.TeeReader` into a temp file; SHA-256 is computed inline; the temp file is renamed atomically to the final path (`os.Rename`).
- On `GetBlob`, the returned `io.ReadCloser` is a `checksumVerifyingReader` that computes SHA-256 during reads and returns `ErrBlobChecksumMismatch` at EOF if the digest does not match the stored checksum.

**S3 provider specifics**:
- Object key: `[prefix/]<tenantID>/<namespace>/<name>`; metadata sidecar: `<key>.meta.json`
- Configured via `bucket` (required), `region`, `endpoint_url` (for MinIO/local dev), `prefix`, `access_key_id`, `secret_access_key`.
- Uses an injectable `s3API` interface so tests run against an in-memory implementation without requiring a real S3/MinIO endpoint.

### Configuration example

```yaml
# OSS single-controller
blobs:
  provider: filesystem
  config:
    root: /var/lib/cfgms/blobs

# Commercial/SaaS
blobs:
  provider: s3
  config:
    bucket: cfgms-blobs
    region: us-east-1
    # endpoint_url: http://minio.internal:9000  # optional: MinIO or local dev
    # prefix: cfgms                              # optional: global key prefix
```

### Multi-tenant isolation

`BlobKey.TenantID` is mandatory and maps directly to a path segment (filesystem) or key prefix (S3). An empty `TenantID` returns `ErrBlobTenantRequired`. The filesystem provider additionally rejects key components containing `..` or `/` to prevent path traversal.

## Implementation Status

Per ADR-003, the providers and interfaces above are **not all implemented today**. The ADR ratifies the direction; implementation is tracked by the **Storage Architecture: Five-Type Data Taxonomy (ADR-003)** epic and its sub-stories. See the ADR's [Code Changes Required](decisions/003-storage-data-taxonomy.md#code-changes-required) section for the authoritative sub-story list and priorities.

### Completed (as of Epic #647)

| Provider | Story | Stores implemented |
|----------|-------|--------------------|
| `pkg/storage/providers/sqlite` | #662 | `TenantStore`, `ClientTenantStore`, `AuditStore`, `RBACStore`, `RegistrationTokenStore`, `SessionStore` |
| `pkg/storage/providers/flatfile` | #661 | `ConfigStore`, `AuditStore` |
| `pkg/storage/providers/sqlite` | #663 | `StewardStore` |
| `pkg/storage/providers/flatfile` | #663 | `StewardStore` |
| `pkg/storage/providers/sqlite` | #665 | `CommandStore` |

### StewardStore (Issue #663)

`StewardStore` is the durable fleet registry. The controller persists per-steward data (ID, hostname, platform, arch, version, IP address, status, `registered_at`, `last_seen`, `last_heartbeat_at`) so the fleet view survives controller restarts without waiting for all stewards to re-register.

**Status values**: `registered` → `active` → `lost` / `deregistered`. Records are never deleted; `lost` and `deregistered` stewards are retained for audit history.

**Implementations**:
- `pkg/storage/providers/flatfile`: one JSON file per steward at `<root>/stewards/<stewardID>.json`. `ListStewards` is O(n) in the number of stewards — a known limitation for large fleets; prefer SQLite for fleets where query performance matters.
- `pkg/storage/providers/sqlite`: stewards stored in the `stewards` table; `ListStewardsByStatus` uses an indexed query on `status`.

**Fleet tracker**: `features/controller/fleet/fleet.HealthTracker` wraps a `StewardStore` for durable fields and keeps ephemeral per-process metrics (`HealthMetrics`) in-memory via a `sync.Map`.

`SessionStore` is implemented in story #662. It stores only `Persistent=true` sessions; ephemeral state (non-persistent sessions, rebuildable runtime values) uses `pkg/cache`. The `ConfigStore` interface returns `ErrNotSupported` from the SQLite provider — config storage targets the flat-file provider (OSS) and PostgreSQL (commercial).

### CommandStore (Issue #665; delivery lifecycle: Issue #3757, ADR-031 Decision 2)

`CommandStore` is the durable command dispatch state backend. It persists two
independent lifecycles on the same `CommandRecord`:

- **Execution status** (`Status`, Issue #665) — whether the *receiving steward*
  has executed the command: `pending` → `executing` → `completed` / `failed` /
  `cancelled`. Owned and transitioned by `features/steward/commands.Handler` on
  the steward side.
- **Delivery status** (`DeliveryStatus`, Issue #3757) — whether the *dispatching
  controller* has gotten the command onto the wire to that steward at all:
  `pending` → `delivered` → `acknowledged`, with terminal failures recorded
  distinctly as `failed`. Owned and transitioned by the controller (e.g.
  `handleConfigPush` in `features/controller/api`).

The two are orthogonal: a record can be execution-`pending` and
delivery-`delivered` (the steward has it but hasn't started on it yet), or
execution-`completed` with delivery history irrelevant on the steward's own
copy of the record (a steward only ever writes its own execution status).

**Key design decisions**:
- Two tables: `commands`/`command_records` (current state) and
  `command_transitions` (immutable audit log of every *execution* status
  change, including initial creation as `pending`). `DeliveryStatus` changes are
  **not** written to `command_transitions` — that trail is scoped to
  `CommandStatus` only; `UpdateDeliveryStatus` updates `delivery_status` /
  `delivery_detail` in place.
- `GetCommandAuditTrail(commandID)` returns all execution-status transitions in
  chronological order — this record is immutable; only `PurgeExpiredRecords`
  can delete it (by age).
- `PurgeExpiredRecords(ctx, olderThan)` removes `completed`, `failed`, and
  `cancelled` records older than the threshold. `executing` and `pending`
  records are never purged.
- `CreateCommandRecords(ctx, records)` creates a batch of records in a single
  database transaction — every record commits, or none do. `handleConfigPush`
  uses this so a fan-out to N stewards produces one durable fact (all N
  delivery rows), never a partial set silently missing some stewards.
- `ListPendingDeliveries(ctx, stewardID)` returns every record targeting a
  steward whose `DeliveryStatus` is still `pending` — the set a steward drains
  on reconnect. Delivery to an offline endpoint is deferred, never lost.
- **Startup sweep — inverted under ADR-031 Decision 2.** Previously, restarting
  `features/steward/commands.Handler` with a configured `CommandStore` flipped
  *every* `executing` record to `failed` with error `"controller_restart"`,
  unconditionally. This inverted the "a restart never fails a queued delivery"
  requirement in spirit even though it operated on execution status, not
  delivery status, so the behavior is now bounded: only `executing` records
  whose `StartedAt` is older than `ExecutingRestartTimeout` (default 5 minutes)
  are failed; a record that started executing more recently than the timeout is
  left alone, since a fast restart may not have genuinely interrupted it.
  `pending` records are **never** queried or touched by the sweep at all — they
  were never mid-attempt, so a restart cannot have interrupted anything to fail.
  This is the steward-side half of "a controller restart never fails a queued
  delivery"; the controller-side half is structural: neither the `database` nor
  `sqlite` `CommandStore` implementation runs any sweep on its own — a `pending`
  `DeliveryStatus` row survives a controller restart unmodified because nothing
  ever touches it until a real delivery attempt or an explicit
  `UpdateDeliveryStatus` call changes it.
- The in-memory `executing` map in `Handler` retains only `context.CancelFunc`
  for in-flight cancellation — durable state is entirely in the store.

**Status values**: execution `pending` → `executing` → `completed` / `failed` /
`cancelled`. Delivery `pending` → `delivered` → `acknowledged`, or `pending` →
`failed` (terminal).

**Implementations**:
- `pkg/storage/providers/sqlite`: `commands` and `command_transitions` tables in
  the shared SQLite schema, including `delivery_status`/`delivery_detail`
  columns. Used both by the OSS controller composite and by each steward's own
  local command-execution store.
- `pkg/storage/providers/database`: `command_records` and `command_transitions`
  tables with tenant-scoped RLS, including `delivery_status`/`delivery_detail`
  columns. The controller-side outbox for deployments on the PostgreSQL
  business-data tier.
- `pkg/storage/providers/flatfile`, `git`: return `ErrNotSupported` — command
  dispatch/delivery state is business data, not config data, and flatfile is
  git-backed config storage only (`pkg/README.md` decision tree).

## Cluster Mode Provider Compatibility

Controllers in cluster mode require a storage backend that supports shared state across multiple concurrent controller nodes. Each storage provider and secrets provider declares this via `ClusterCapable() bool` on its respective interface (`StorageProvider`, `SecretProvider`).

### Storage providers

| Provider | `ClusterCapable()` | Reason |
|----------|--------------------|--------|
| `pkg/storage/providers/database` (PostgreSQL) | `true` | Postgres handles concurrent writers from multiple controller nodes via its transaction and locking model; the same DSN is accessible from all nodes. Also backs `pkg/session.Store` (`DatabaseSessionTokenStore`) for cluster-wide `cfg`/web session token validation (Issue #2775). |
| `pkg/storage/providers/flatfile` | `false` | Local filesystem — concurrent writes across nodes are not coordinated; last-writer-wins semantics are unsafe for multi-active cluster mode |
| `pkg/storage/providers/sqlite` | `false` | Single-file SQLite is node-local; no cross-node access or coordination |

### Secrets providers

| Provider | `ClusterCapable()` | Reason |
|----------|--------------------|--------|
| `pkg/secrets/providers/openbao` | `true` | OpenBao cluster exposes a shared KV service reachable by all controller nodes |
| `pkg/secrets/providers/sops` | `false` | Git-backed file store is node-local at runtime; no shared-state coordination |
| `pkg/secrets/providers/oskeychain` | `false` | Host OS keychain — per-host only, inaccessible from other nodes |
| `pkg/secrets/providers/steward` | `false` | Steward-local encrypted store on the endpoint host, not a controller backend |

The startup gate (sibling Story B) uses `ClusterCapable()` to reject misconfigured cluster deployments early, before any state is written.

## References

- [ADR-003: Storage Data Taxonomy](decisions/003-storage-data-taxonomy.md) — authoritative design document
- [LICENSING.md](../../LICENSING.md) — licensing details and commercial FAQ
- [`pkg/storage/interfaces/README.md`](../../pkg/storage/interfaces/README.md) — current interface layout and reorganization plan
- [ADR-001: Central Provider Compliance Enforcement](decisions/001-central-provider-compliance-enforcement.md) — pluggable-by-default principle
