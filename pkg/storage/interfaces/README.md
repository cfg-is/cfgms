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
| `blob_store.go` | `BlobStore`, `BlobKey`, `BlobMeta`, `BlobInfo`, `BlobProvider`, registry helpers | Stream-oriented blob storage (installers, reports, DNA snapshots) |

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

## References

- [ADR-003: Storage Data Taxonomy](../../../docs/architecture/decisions/003-storage-data-taxonomy.md) — the authoritative plan
- [Storage Architecture](../../../docs/architecture/storage-architecture.md) — operator walk-through
- [`pkg/README.md`](../../README.md) — central provider rules (pluggable by default)
