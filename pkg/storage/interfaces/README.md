# CFGMS Storage Interfaces

This package defines the storage interfaces used by controller-side business
logic. Modules import only these interfaces, never specific providers.

> **Scope**: Controller-side storage only. Steward persistence (local config
> file, OS keychain, in-memory state between convergence runs) is separate.

Per [ADR-003: Storage Data Taxonomy](../../../docs/architecture/decisions/003-storage-data-taxonomy.md),
the storage contracts are organized into a **five-type taxonomy**. Each type
lives in its own sub-package so that callers pull in only the types they need.

## Five-Type Layout

```
pkg/storage/interfaces/
  business/     // durable business data (tenants, RBAC, audit, sessions, stewards, commands, tokens)
  config/       // human-editable configuration data (YAML/JSON, inheritance)
  secrets/      // (placeholder) future storage-layer secret integration
  timeseries/   // (placeholder) metrics and structured log persistence
  blob/         // large binary objects (installers, reports, DNA snapshots)
```

**Naming rule**: `*Store` = durable. Ephemeral/rebuildable state goes to
`pkg/cache/` as `*Cache`, with no storage interface. The historical
`RuntimeStore` is retired per ADR-003 — it conflated durable session state
(now `business.SessionStore`) with ephemeral runtime state (which belongs in
`pkg/cache`).

## Sub-Package Contents

### `business/` — Business Data Tier

| File | Interface(s) | Purpose |
|------|--------------|---------|
| `tenant_store.go` | `TenantStore`, `TenantData`, `TenantHierarchy` | Recursive tenant hierarchy |
| `client_tenant_store.go` | `ClientTenantStore`, `ClientTenant`, `ClientTenantStatus`, `AdminConsentRequest` | MSP client tenant data (absorbs M365 consent state) |
| `audit_store.go` | `AuditStore`, `AuditEntry`, `AuditFilter`, `AuditStats` | Immutable audit events |
| `rbac_store.go` | `RBACStore` | RBAC policy and role data |
| `registration_store.go` | `RegistrationTokenStore`, `RegistrationTokenData` | Steward registration tokens |
| `session_store.go` | `SessionStore`, `Session`, `SessionType`, `SessionStatus`, `ClientInfo`, `SessionFilter`, `RuntimeStoreStats`, plus typed session-data payloads (terminal, JIT, API, websocket) | Durable session state |
| `steward_store.go` | `StewardStore`, `StewardRecord`, `StewardStatus` | Durable fleet registry |
| `command_store.go` | `CommandStore`, `CommandRecord`, `CommandStatus`, `CommandTransition` | Durable command dispatch state |
| `dna_history_store.go` | `DNAHistoryStore` | DNA history access interface used by drift detection |
| `batch_job_store.go` | `BatchJobStore`, `ErrBatchJobNotFound` | Fleet rolling-batch update job persistence (types in `features/controller/batchjob`) |
| `case_store.go` | `CaseStore`, `Case`, `Ticket`, `TicketField`, `Pin`, `PinRef`, `ContentEntry` | Cockpit investigation cases: per-field-provenanced ticket, graph-reference pins, typed content entries (ADR-022 §8). `Case.Version` + `CaseStore.UpdateCaseCAS` are the compare-and-swap update path (Issue #3895) — see "Compare-and-Swap Writes" below |

Sentinel errors live in the sub-packages: `business.ErrNotSupported`,
`business.ErrImmutable`, `business.ErrStewardNotFound`,
`business.ErrStewardAlreadyExists`, and validation errors for audit, client
tenant, and command stores.

### `config/` — Configuration Data Tier

| File | Interface(s) | Purpose |
|------|--------------|---------|
| `config_store.go` | `ConfigStore`, `ConfigKey`, `ConfigEntry`, `ConfigFormat`, `ConfigFilter`, `ConfigStats` | Human-editable configuration (YAML/JSON with inheritance) |

### `blob/` — Large Binary Objects

| File | Interface(s) | Purpose |
|------|--------------|---------|
| `blob_store.go` | `BlobStore`, `BlobKey`, `BlobMeta`, `BlobInfo`, `BlobProvider`, registry helpers | Stream-oriented blob storage (installers, reports, DNA snapshots). `PutBlobIfAbsent` is the conditional-create write (Issue #3895) — see "Compare-and-Swap Writes" below |

### `secrets/` — Placeholder

Reserved for a future storage-layer integration. Today, secret persistence is
defined in `pkg/secrets/interfaces`. The placeholder exists so that ADR-003's
five-type taxonomy is visible even while secrets remain in their dedicated
package.

### `timeseries/` — Placeholder

Reserved for a future `MetricsStore` and `LogStore` contract (separate ADR).

## Root Package — Provider Registry

`pkg/storage/interfaces` (this package) now owns only the provider registry
and composite `StorageManager`. It imports the sub-packages above and exposes:

| Symbol | Purpose |
|--------|---------|
| `StorageProvider` | Provider contract — returns sub-package store types |
| `StorageManager` | Composite manager bundling all store types for a deployment |
| `HybridStorageManager` | Mixed-backend composition (operational vs configuration) |
| `ProviderCapabilities`, `ProviderInfo`, `ProviderInfoV2` | Provider metadata |
| `RegisterStorageProvider`, `GetStorageProvider`, `UnregisterStorageProvider`, ... | Registry operations |
| `CreateOSSStorageManager` | Factory for the OSS composite (flatfile + SQLite) |
| `NewStorageManagerFromStores` | Build a StorageManager from individually-wired stores |
| `CreateAllStoresFromConfig` | Deprecated — single-provider composition; retained for backward compatibility |
| `CreateXxxStoreFromConfig` | Per-type factory helpers returning sub-package types |

## Optional `StorageProvider` Extensions (`*StoreCreator`)

A handful of stores are not part of the core `StorageProvider` interface
because only clustered deployments need them. Each is its own tiny interface
— `CreateXxxStore(config map[string]interface{}) (XxxStore, error)` — that a
provider implements optionally; `CreateClusterStorageManager` wires one in via
a type assertion (`if xsc, ok := provider.(XxxStoreCreator); ok { ... }`) and
leaves the corresponding `StorageManager` getter nil when the assertion fails
or the store itself comes back nil. Callers must always nil-check before use
and fall back to a node-local default:

| Extension | Store | Falls back to (single-node / unsupported provider) |
|-----------|-------|------------------------------------------------------|
| `CertRevocationStoreCreator` | `certinterfaces.RevocationStore` | `pkg/cert`'s node-local file-backed revocation list (ADR-031 Decision 1, Issue #3852) |
| `SigningCursorStoreCreator` | `certinterfaces.SigningCursorStore` | `pkg/cert`'s node-local file-backed signing cursor (ADR-031 Decision 1, Issue #3852) |
| `ModuleApprovalStoreCreator` | `business.ModuleApprovalStore` | `ModuleCache`'s node-local file-backed `approval.yaml` (ADR-031 Decision 1, Issue #3886) |
| `RateCounterStoreCreator` | `business.RateCounterStore` | the per-source rate limiters' and the operator-payload sign throttle's node-local in-memory counters (ADR-031 Decision 1, Issue #3896) |

`RateCounterStoreCreator` backs cluster-visible, fixed-window abuse-budget
counters — the durable replacement for Issue #3761's `clusterBudgetDivisor`,
which approximated a shared counter by dividing the configured limit across
live cluster nodes and could be defeated by an adversary deliberately
targeting one node. `business.RateCounterStore` exposes two methods:

- `Increment(ctx, key, window) (count, retryAfter, err)` — atomically records
  one attempt and returns the resulting count, starting a fresh window
  whenever the previous one has fully elapsed. Used by the per-source rate
  limiters' check-and-increment call.
- `Peek(ctx, key, window) (count, retryAfter, found, err)` — reads the current
  count without recording an attempt. Used by the operator-payload
  sign-ceremony throttle, which must check whether a key is already
  throttled *before* an attempt occurs.

The window passed to both methods should match the caller's own configured
budget window (all five `sourceRateLimiter` instances wired in
`features/controller/api/server.go` use one minute) rather than an
independently chosen TTL, so the counter store's row lifetime tracks the
budget it enforces. Callers key by `"<namespace>:<identity>"` (e.g.
`"<route-name>:<source-address>"`) so multiple counters sharing one store's
table never collide.

Because the keys are attacker-chosen — the source address of unauthenticated
routes among them — an implementation must bound its own growth the way the
in-memory limiter it replaces does, on both axes:

- **Reclaim elapsed windows.** Overwriting a row in place only reclaims a key
  that recurs, and an attacker rotating source addresses never repeats one.
  `DatabaseRateCounterStore` records each row's `expires_at` and sweeps them
  (`PruneExpired`, driven opportunistically from `Increment`).
- **Cap the keys tracked at once.** Past the cap, `Increment` declines a
  brand-new key with an error wrapping `business.ErrRateCounterCapacityExhausted`
  while continuing to serve keys already tracked. Callers **fail closed** on that
  error — `sourceRateLimiter.allowShared` denies the request, mirroring the
  in-memory `maxTrackedKeys` backstop, and does not substitute a fresh node-local
  bucket, since a rotating source address is what filled the store.

An ordinary store error (pool exhaustion, statement timeout, failover) is an
outage rather than an abuse signal, so callers **degrade to their node-local
counter** instead — `sourceRateLimiter.allowShared` falls through to its
in-memory fixed-window path and `recordSignFailure` to its in-memory throttle
record, both logging the reversion once per window. Neither allows the call
unmetered: these counters are the only abuse control on unauthenticated routes
(enrolment-token mint, credential-request and cli-login lodge/collect), and
flooding those routes is itself what exhausts a shared database pool, so an
"allow on error" would be attacker-reachable and self-reinforcing. Degrading
keeps a real, if per-node, budget in force while keeping the route available.

## Provider Inventory

| Provider | Package | Implements | Status |
|----------|---------|------------|--------|
| `flatfile` | `pkg/storage/providers/flatfile` | `config.ConfigStore`, `business.AuditStore`, `business.StewardStore` | Available — OSS default for config storage and fleet registry |
| `sqlite` | `pkg/storage/providers/sqlite` | Business-data stores + `business.StewardStore` | Available — OSS default for business-data tier |
| `database` | `pkg/storage/providers/database` | All stores | Available — commercial PostgreSQL backend |
| `filesystem` (blob) | `pkg/storage/providers/blobstore/filesystem` | `blob.BlobStore` | Available |
| `s3` (blob) | `pkg/storage/providers/blobstore/s3` | `blob.BlobStore` | Available |

## Backend Selection (per type)

Per ADR-003, deployments compose one provider per type:

| Type | OSS backend | Commercial/SaaS backend |
|------|-------------|-------------------------|
| Business data | SQLite | PostgreSQL |
| Config storage | Flat file (`flatfile`) | PostgreSQL (`database`) |
| Secrets | SOPS files | Key vault |
| Timeseries | Local log files | ClickHouse / Timescale / Influx |
| Blobs | Local filesystem | S3-compatible object storage |

The OSS column is the zero-config default, not a limit. Any commercial backend
is available to OSS deployments — the licensing boundary is tenant-tree shape,
not backend choice.

Git is **not** a backend. It is an optional sync source bound to
admin-designated config scopes; see ADR-003. `pkg/gitsync` is a write-through
adapter, not a storage provider.

## Composite Storage Manager (OSS Factory)

### `CreateOSSStorageManager`

```go
func CreateOSSStorageManager(flatfileRoot, sqliteConnStr string) (*StorageManager, error)
```

Creates the OSS composite by wiring stores from the flatfile and SQLite
providers per the ADR-003 mapping:

| Store | Provider |
|-------|----------|
| `config.ConfigStore` | flatfile |
| `business.AuditStore` | flatfile |
| `business.StewardStore` | flatfile |
| `business.TenantStore` | SQLite |
| `business.ClientTenantStore` | SQLite |
| `business.RBACStore` | SQLite |
| `business.RegistrationTokenStore` | SQLite |
| `business.SessionStore` | SQLite |
| `business.CommandStore` | SQLite |

`sqliteConnStr` is a caller-controlled DSN:
- Production: `"/var/lib/cfgms/cfgms.db"` (file path)
- Tests: `t.TempDir() + "/test.db"` (per-test isolation)
- Do NOT use `":memory:"` — parallel tests sharing
  `file::memory:?cache=shared` collide on schema migration.

Both the `"flatfile"` and `"sqlite"` providers must be registered via blank
imports before calling this function.

### `NewStorageManagerFromStores`

```go
func NewStorageManagerFromStores(
    configStore cfgconfig.ConfigStore,
    auditStore business.AuditStore,
    rbacStore business.RBACStore,
    tenantStore business.TenantStore,
    clientTenantStore business.ClientTenantStore,
    registrationTokenStore business.RegistrationTokenStore,
    sessionStore business.SessionStore,
    stewardStore business.StewardStore,
    commandStore business.CommandStore,
) *StorageManager
```

Composes a `StorageManager` from individually-supplied store implementations.
Any parameter may be nil; the caller is responsible for providing the stores
it needs. The resulting manager has `GetProviderName() == "composite"` and
`GetProvider() == nil`. `GetCapabilities()` returns a zero value and
`GetVersion()` returns `"composite"`.

## Module Usage Pattern

Modules receive sub-package interfaces directly:

```go
import (
    "context"

    cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

type TemplateModule struct {
    configStore cfgconfig.ConfigStore
}

func NewTemplateModule(configStore cfgconfig.ConfigStore) *TemplateModule {
    return &TemplateModule{configStore: configStore}
}

func (tm *TemplateModule) SaveTemplate(ctx context.Context, template Template) error {
    return tm.configStore.StoreConfig(ctx, &cfgconfig.ConfigEntry{
        Key: &cfgconfig.ConfigKey{
            TenantID:  template.TenantID,
            Namespace: "templates",
            Name:      template.Name,
        },
        Data:   template.YAMLData,
        Format: cfgconfig.ConfigFormatYAML,
    })
}
```

Similarly, business-data callers import
`github.com/cfgis/cfgms/pkg/storage/interfaces/business`, blob callers import
`github.com/cfgis/cfgms/pkg/storage/interfaces/blob`.

## Testing

Use real providers with a temporary directory:

- OSS path: call `interfaces.CreateOSSStorageManager(t.TempDir(), t.TempDir()+"/test.db")`
- Do NOT use `":memory:"` for SQLite in tests.
- Commercial path: PostgreSQL via testcontainers.

CFGMS does not mock storage interfaces in tests (per CLAUDE.md
"Real Component Testing").

## Compare-and-Swap Writes

Under ADR-031 Decision 1 (any-node service), every cluster node accepts every
read and write — there is no leadership gate serializing concurrent writers to
the same record anymore. Several stores therefore need to guard a write against
a lost race explicitly, rather than relying on one node's exclusive ownership.
The established pattern, and where each variant lives:

- **Optimistic version CAS** — a record carries a `Version` field, read
  alongside the record and passed back unchanged to a CAS write method. The
  write applies only if the store's current version still matches; a mismatch
  reports a clean "lost the race" outcome (`ok=false`, no error), never a
  silent overwrite.
  - `secretsif.SecretStore.CompareAndSwapSecret` (`pkg/secrets/interfaces`) is
    the original of this pattern; `handlers_accounts.go`'s `persistAccountCAS`
    is the reference caller-side wrapper.
  - `business.CaseStore.UpdateCaseCAS` (Issue #3895) mirrors it for cockpit
    cases: `Case.Version` is populated by `CreateCase`/`GetCase`/`ListCases`,
    and `UpdateCaseCAS(ctx, c, expectedVersion)` returns `(newVersion int, ok
    bool, err error)`.
- **Expected-old-value guard** — no version column; the write's `WHERE` clause
  is guarded on the field's expected current value instead (`AND status =
  'pending'`, `AND tenant_id = $expected`). Same lost-race contract: a
  mismatch means zero rows affected, surfaced as the same not-found sentinel
  the store already uses, which callers that already confirmed existence via
  their own prior read should treat as a conflict.
  - `business.PendingRegistrationStore.UpdateStatus`'s `claimed` transition
    (`pkg/storage/providers/{sqlite,database}/pending_registration_store.go`)
    established this; the `approved`/`denied` transitions extend it
    (Issue #3895).
  - `business.StewardStore.UpdateStewardTenant(ctx, stewardID,
    expectedTenantID, newTenantID)` (Issue #3895) applies the same guard to
    steward tenant moves.
- **Conditional-create write** — no existing record to version; the write
  itself must be atomic with the "does not exist" check, rather than a
  separate existence read followed by an unconditional write (a TOCTOU gap).
  - `blob.BlobStore.PutBlobIfAbsent` (Issue #3895) returns
    `ErrBlobAlreadyExists` without writing if the key already exists at the
    instant the provider evaluates the condition — the filesystem provider
    uses an `O_CREATE|O_EXCL` sidecar create as the atomicity point, the S3
    provider uses `PutObject` with `IfNoneMatch: "*"`.

Pick the shape that fits the record, not a one-size-fits-all abstraction: a
record that already has natural read-then-write callers wants version CAS: a
transition between named states wants a value guard; a "create if it doesn't
exist yet" write wants a conditional-create primitive.

## References

- [ADR-003: Storage Data Taxonomy](../../../docs/architecture/decisions/003-storage-data-taxonomy.md) — the authoritative plan
- [Storage Architecture](../../../docs/architecture/storage-architecture.md) — operator walk-through
- [`pkg/README.md`](../../README.md) — central provider rules (pluggable by default)
