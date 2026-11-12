# Storage Architecture

> **Source of truth**: [ADR-003: Storage Data Taxonomy](decisions/003-storage-data-taxonomy.md).
> This document is the operator-facing walk-through of the decision recorded in ADR-003.

## Summary

CFGMS controller storage is partitioned into five data types. Each type has its own interfaces and its own backend selection. Deployments compose one provider per type rather than choosing a single global backend.

Git is not a storage backend. File-based storage is served by a flat-file provider; the operator is responsible for backups. Git re-enters the architecture as an *optional sync source* for admin-designated config scopes, implemented by a single git-sync component that works against both flat-file and PostgreSQL backends.

> **Scope note**: This document covers controller-side storage. Steward persistence (local config file, OS keychain, in-memory state between convergence runs) is a separate, simpler concern.

## The Five Data Types

| Type | Local deployment examples | Hosted deployment options |
|------|-------------|-------------------------|
| Business data | SQLite | PostgreSQL |
| Config storage | Flat file | PostgreSQL |
| Config *git sync* (optional, per-scope) | External git origin → flat file | External git origin → PostgreSQL |
| Secrets | SOPS files | SOPS or OpenBao; select an implemented provider |
| Timeseries | File logging provider | Timescale logging provider |
| Blobs | Local filesystem | S3-compatible object storage |

**Deployment columns are examples, not licensing tiers.** Backend choice and
single-root/multi-root topology do not create separate license tiers. All CFGMS
code is AGPL-3.0; commercial embedding terms concern incorporation into
proprietary products. The implemented secrets providers are under
`pkg/secrets/providers/`, and logging providers under `pkg/logging/providers/`.
See [LICENSING.md](../../LICENSING.md).

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
4. Imported configs write through to the controller's config backend — the selected flat-file or PostgreSQL backend.
5. Unbound scopes live natively in the backend.
6. The read path is always the backend. Git is the *editing surface* for bound scopes, not a query target.

**v1 is strictly one-way, read-only** (git → backend). The controller never writes to the git origin. For bound scopes, all edits happen at the git origin — the admin opens a PR, merges it, and git-sync pulls the result. A config file deleted or renamed at the origin is removed from the store on the next sync; only entries written by git-sync are removed. UI-initiated edits on bound scopes are not supported in v1; they either fail or fall through to unbound scopes. Bidirectional sync is out of scope for v1 and will be a future ADR if demand emerges.

### One sync path across storage backends

The same git-sync code path serves local and hosted deployments. The only variable is the backend adapter it writes through to. This avoids the fork that would result from git-as-backend-for-OSS and git-sync-for-SaaS existing side-by-side.

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

**Credentials (v1):** `CredentialsRef` and `WebhookSecretRef` accept a `pkg/secrets` `SecretStore` key (prefix `secret:`, resolved through `gitsync.WithSecretStore`), an environment-variable name (prefix `env:`), or a filesystem path to a file containing the credential.

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

Imported configs land in the selected flatfile or PostgreSQL backend. Backup,
replication and point-in-time recovery depend on that backend and its operating
procedures, not a separate license tier.

## Flat-File Provider

The flat-file provider (`pkg/storage/providers/flatfile`) is the local composite default for config storage. It stores configs and audit logs as files under a configured root directory.

On Linux and macOS the provider creates every directory `0700` and every file `0600`, so stored data is readable only by the owning account. Directories and files that already exist keep their current mode.

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
- Backups. CFGMS does not version at the storage layer. Use filesystem snapshots, rsync, restic, or an equivalent.
- Filesystem durability. Choose and verify filesystem persistence and a backup/restore procedure for the
  deployment; a disk type alone is not a durability guarantee.
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

## Retired Git backend

The current controller rejects the retired Git backend. Git sync is a separate
editing/import path, not a storage backend. The
[backend migration guide](../operations/backend-migration.md) owns
exclusive-write cutover between the supported backends.

## Interface Layout

[Storage interfaces](../../pkg/storage/interfaces/README.md) owns the current
five-type package layout and store contracts. Durable stores and rebuildable
caches are distinct; do not infer persistence from an in-memory cache field.

## Configuration Example

Use [the boot schema](../reference/config-schema.md),
[canonical controller config](../deployment/controller.cfg) and
[cluster storage](../operations/cluster-storage-config.md) for exact field
placement. Backend choice is per data type, not a fabricated nested business
configuration tree.

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

| Provider | Package | Local default | Notes |
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

For a local controller, the actual `BlobStorageConfig` boot shape is:

```yaml
blob_storage:
  root: /var/lib/cfgms/installers
```

When omitted, the root defaults to `<data_dir>/installers`. This is not a
`blobs.provider` block. Cluster deployments obtain the shared S3 configuration
through `storage.cluster`; use the [cluster walkthrough](../deployment/controller-cluster/walkthrough.md)
and the current `ClusterStorageConfig` in `features/controller/config/config.go`.
The provider registry's S3 configuration is a Go factory contract, not a second
public YAML schema.

### Multi-tenant isolation

`BlobKey.TenantID` is mandatory and maps directly to a path segment (filesystem) or key prefix (S3). An empty `TenantID` returns `ErrBlobTenantRequired`. The filesystem provider additionally rejects key components containing `..` or `/` to prevent path traversal.

## Implementation Status

Per ADR-003, the providers and interfaces above are **not all implemented today**. The ADR ratifies the direction; implementation is tracked by the **Storage Architecture: Five-Type Data Taxonomy (ADR-003)** epic and its sub-stories. See the ADR's [Code Changes Required](decisions/003-storage-data-taxonomy.md#code-changes-required) section for the authoritative sub-story list and priorities.

### Completed (as of Epic #647)

| Provider | Story | Stores implemented |
|----------|-------|--------------------|
| `pkg/storage/providers/sqlite` | #662 | `TenantStore`, `AuditStore`, `RBACStore`, `RegistrationTokenStore`, `SessionStore` |
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

`SessionStore` is implemented in story #662. It stores only `Persistent=true` sessions; ephemeral state (non-persistent sessions, rebuildable runtime values) uses `pkg/cache`. The `ConfigStore` interface returns `ErrNotSupported` from the SQLite provider — config storage targets the flat-file and PostgreSQL providers.

On Linux and macOS the SQLite provider creates the database file and its `-wal` / `-shm` side files `0600`. An existing database file keeps its current mode. The controller's other SQLite databases (fleet DNA, run store, tag store, entity graph) are created with the same modes through `pkg/storage/sqlitefile`; the fleet DNA data directory is created `0700`.

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
- `CreatePushAndCommandRecords(ctx, push, records)` extends that batch
  transaction to also write `push` (the `PushRecord` — the "config write") in
  the same commit: ADR-031 Decision 2's "a command/notification row commits in
  the same transaction as the state change that requires it." This is possible
  because `PushRecord` and `CommandRecord` are both persisted by the same SQL
  storage tier (the `database`/`sqlite` providers each open their own
  connection pool, but both point at the same physical database, so a
  transaction opened by either can write either table). Writes that live in a
  genuinely different pluggable provider — e.g. the entity-graph desired-state
  observation `handleConfigPush` also records — remain outside this seam and
  stay best-effort by design; central-provider pluggability means a SQL
  transaction cannot in general span an arbitrary second backend (the entity
  graph, or a git-backed `ConfigStore`), so the outbox's joint-commit guarantee
  is scoped to writes that share its own SQL tier. `handleConfigPush` passes
  `push` (nil when no `PushStore` is configured) and the per-steward delivery
  `records` (empty when no steward matched) to this single call instead of two
  independently-committing writes.
- `ListPendingDeliveries(ctx, stewardID, stewardTenant)` returns every record
  targeting a steward whose `DeliveryStatus` is still `pending` — the set a
  steward drains on reconnect. Delivery to an offline endpoint is deferred,
  never lost. `stewardTenant` is mandatory and implementations must apply it in
  the query: results are limited to records stamped with the steward's current
  tenant or one of its ancestors (`business.TenantPathChain`), the only tenants
  a subtree push targeting that steward can have been issued under. `steward_id`
  alone is not a tenant boundary — the binding is mutable (steward move), so
  rows written under a previous tenant stay attached to the same `steward_id`,
  and neither backend compensates (the Postgres read path does not set
  `app.current_tenant`, whose absence makes the `command_records` SELECT policy
  permissive; SQLite has no RLS). An empty `stewardTenant` is refused with
  `ErrCommandTenantIDRequired` rather than widening the query.
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

## Schema evolution (N / N-1)

This section applies to the PostgreSQL provider (`pkg/storage/providers/database`)
only. The flat-file and SQLite providers are outside this contract.

During a rolling controller upgrade two revisions share one database: the revision
being rolled out (N) and the previous one (N-1). N-1 means the previous revision on
`develop`, not a release tag. Every schema change is built so both revisions run
against the same database at the same time, and so one version of rollback needs no
schema rollback.

### Versions and the floor

Each build carries two constants in `schema_version.go`, and the database records two
matching numbers in the single-row table `cfgms_schema_version`:

| Name | Where | Meaning |
|------|-------|---------|
| `SchemaVersion` | build constant | The schema version this build creates and expects. |
| `MinToleratedSchemaVersion` | build constant | The oldest recorded schema version this build still starts against. |
| `version` | `cfgms_schema_version` | The highest `SchemaVersion` any node has applied. It only rises. |
| `min_node_version` | `cfgms_schema_version` | The floor: the lowest node `SchemaVersion` that may still use the database. Only a contract step raises it. |

Each node also reports its own `SchemaVersion` and `MinToleratedSchemaVersion` in the
shared node registry (`cfgms_node_registry.schema_required` and
`schema_min_tolerated`). `GET /api/v1/ha/cluster` returns them per node as
`schema_required` and `schema_min_tolerated` (see the
[REST API reference](../api/rest-api.md#get-apiv1hacluster)).

### The gate

`checkSchemaVersion` runs when the provider opens its connection pool, before any store
is created. In one transaction it creates the version record if absent, locks the row,
and refuses to continue when:

- the recorded `version` is below this build's `MinToleratedSchemaVersion`, or
- `min_node_version` is above this build's `SchemaVersion`.

A refusal returns an error wrapping `ErrSchemaVersionOutOfRange`; the pool is closed
and not cached, so the node does not start. Otherwise the gate raises `version` to this
build's `SchemaVersion` (never lowers it) and records that the node passed the gate
(`recent_gate_required`, `recent_gate_at`), so the contract guard can see a node that
has passed the gate but has not yet registered. A database with no recorded row counts
as version 0.

### The expand/contract rule

A schema change is one of two kinds. An expansion adds schema. A contraction removes,
renames or narrows it. The contract has four rules:

1. **Expand first, compatibly.** An expansion (a new table, a nullable or defaulted
   column, a new index, a new constraint added `NOT VALID`) ships first and must be
   readable and writable by the previous revision.
2. **Contract later.** A column, table, constraint, index or enum value is removed,
   renamed or narrowed only in a later schema version, as a `ContractStep`
   (`schema_contract.go`), after the last revision that reads or writes it.
3. **Backfill online.** Backfills run in small batches, are idempotent and resumable by
   selecting only unfilled rows, and are never one long transaction.
4. **No blocking locks.** No schema change takes a table lock that blocks live traffic
   across a rolling deploy:
   - a new index on an existing table uses `CREATE INDEX CONCURRENTLY`, as its own
     statement and never inside a transaction, because Postgres refuses
     `CREATE INDEX CONCURRENTLY` inside a transaction block;
   - a new foreign key or check constraint is added `NOT VALID` and validated in a later
     statement; a unique or primary key constraint uses `USING INDEX` on an index built
     beforehand with `CONCURRENTLY`;
   - a table created in the same schema version is exempt (it was empty when the
     statement ran), declared with a `schema:new-table` marker;
   - start-up DDL on row-level-security tables issues no policy DDL when nothing
     changed.

A failed `CREATE INDEX CONCURRENTLY` leaves an INVALID index. `CREATE INDEX IF NOT
EXISTS` then skips it, because the name exists. An invalid index must be dropped and
rebuilt as its own contract-class change; start-up does not repair it.

### Contract steps and the floor

A `ContractStep` carries `Version`, `UnusedSince` (the contract marker), a description
and the statements. It is valid only when `1 <= UnusedSince < Version <= SchemaVersion`.
`ApplyContractSteps` runs after the gate, in ascending `Version` order, each step in its
own transaction under a 5 second `lock_timeout`. The production list `contractSteps` is
empty today.

The floor is the marker. A step is applied only when no live node has a schema version
below `UnusedSince`. A node exactly at `UnusedSince` does not block, so N-1 beside N
keeps running and rollback by one version works. Applying a step raises
`min_node_version` to `UnusedSince`, so a node below the marker that starts later is
refused by the gate.

A step is blocked by:

- a live row in `cfgms_node_registry` with `schema_required` below `UnusedSince` (a row
  of 0, from a node that predates the column, blocks: the check fails closed), and
- a node that passed the gate within `business.NodeRegistryStaleAfter` (90 seconds)
  but has not registered yet.

A blocked step changes nothing, logs a warning and lets the node start. Nothing retries
it on a timer. It is retried on a later node start, once the older nodes' registry rows
have gone stale; the restarting node's own pre-restart row also blocks it for up to the
staleness window. A contract therefore ships a release after the expansion it follows.
Any other step failure (a statement error, a lock timeout) rolls the step back and
refuses the pool.

### Markers

| Marker | Form | Meaning |
|--------|------|---------|
| Contract (Go) | the statement is an element of the `Statements` field of a `ContractStep` literal | Declares a destructive statement with an integer-literal `UnusedSince`. |
| Contract (SQL) | `-- schema:contract unused-since=<n>` on the line before the statement in `migrations/*.sql` | Declares a destructive statement, with `1 <= n < SchemaVersion`. |
| New table | `// schema:new-table <table> since=<n>` (Go) or `-- schema:new-table <table> since=<n>` (SQL) directly above the statement | Exempts a statement on a table created in the same schema version from the lock-hazard rules. |

A new-table marker is valid only when `testdata/table_versions_baseline.txt` records the
table at version `n`, `n <= SchemaVersion`, and the statement targets that table. A new
`CREATE TABLE` adds its own line with the current `SchemaVersion` in the same change;
existing lines are never edited, so a table recorded at an earlier version can not be
claimed new later.

### Grandfathering

Two frozen baselines in `pkg/storage/providers/database/testdata` record the statements
that existed before the checks did:

- `destructive_baseline.txt`: three destructive statements.
- `lock_hazard_baseline.txt`: the existing `CREATE INDEX` statements that do not use
  `CONCURRENTLY`.

Both may only shrink. A line that matches no statement fails the check, so removing or
rewriting a statement forces removing its line. Adding a line is a reviewed exception. A
moved or edited statement is a new statement and needs a marker or the online form.

### How each control is enforced

Automatic:

| Control | Mechanism |
|---------|-----------|
| Version gate | `checkSchemaVersion` on every node start; refuses a node outside the recorded range. |
| Contract guard | `ApplyContractSteps` on every node start; blocks a step while a live or just-admitted older node needs the old shape. |
| Destructive-statement check | `TestSchemaContractCheck_CurrentTreePasses` scans every non-test `.go` file of the package and every `migrations/*.sql` file; a destructive statement without a contract marker, or not in the baseline, fails. |
| Lock-hazard check | `TestSchemaLockCheck_CurrentTreePasses` scans the same files for `CREATE INDEX` without `CONCURRENTLY`, `ADD CONSTRAINT` without `NOT VALID` or `USING INDEX`, and `CONCURRENTLY` inside a multi-statement literal or after `Begin`/`BeginTx`. A `CREATE TABLE` with no line in the table baseline also fails. |
| Lock-safe re-apply | `lockSafe` in `lock_safe_db.go` reads the catalog before `ADD COLUMN IF NOT EXISTS`, `CREATE INDEX IF NOT EXISTS` and `SET NOT NULL`, and issues nothing when it would change nothing. An up-to-date database re-apply takes none of these locks. |
| Policy re-apply | `applyTenantRLS` in `rls_apply.go` compares a hash stored on each policy and issues no DDL in steady state; a real change runs in one transaction with `ALTER POLICY`. A node still running the older inline drop-and-create can open the deny-all window when it restarts. |
| Mixed-revision compat run | `scripts/check-schema-compat.sh` runs the base revision's database suite against the head revision's schema, and the head revision's suite against the base revision's schema. |

The compat run executes in the `postgres-integration` job of
`.github/workflows/cross-platform-build.yml`, which runs for a merge group and for a
manual dispatch, not on every pull request push. The static checks are Go tests in the
database provider package and run with its test suite.

Review-only:

- Rule 3 (backfills): batch size, idempotence and resumability are not checked by any
  tool.
- Rule 1 beyond what the existing test suites exercise: the compat run proves the two
  revisions pass each other's tests, not that every column access is compatible.
- Whether a contract step's `UnusedSince` names the right version.

The operator view of this contract is in the
[rolling cluster upgrade runbook](../operations/rolling-cluster-upgrade.md#mixed-version-rollout-n-and-n-1).

## References

- [ADR-003: Storage Data Taxonomy](decisions/003-storage-data-taxonomy.md) — authoritative design document
- [LICENSING.md](../../LICENSING.md) — licensing details and commercial FAQ
- [`pkg/storage/interfaces/README.md`](../../pkg/storage/interfaces/README.md) — current interface layout and reorganization plan
- [ADR-001: Central Provider Compliance Enforcement](decisions/001-central-provider-compliance-enforcement.md) — pluggable-by-default principle
