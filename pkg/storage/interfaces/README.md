# CFGMS Storage Interfaces

This package defines the storage interfaces used by controller-side business logic. Modules import only these interfaces, never specific providers.

> **Scope**: Controller-side storage only. Steward persistence (local config file, OS keychain, in-memory state between convergence runs) is separate.

> **Direction**: This layout is being reorganized into a five-type taxonomy. See [ADR-003: Storage Data Taxonomy](../../../docs/architecture/decisions/003-storage-data-taxonomy.md) for the authoritative plan. The git storage provider has been removed (Issue #664); use the flat-file provider plus the git-sync component.

## Current Interfaces (flat layout)

The files in this directory today:

| File | Interface(s) | Purpose |
|------|--------------|---------|
| `provider.go` | `StorageProvider` | Provider registration and capability reporting |
| `blob_store.go` | `BlobStore` | Large binary object storage (installers, reports, DNA snapshots) |
| `blob_provider.go` | `BlobProvider` | BlobStore provider registry (separate from `StorageProvider`) |
| `client_tenant.go` | `ClientTenantStore` | MSP client tenant data |
| `m365_client_tenant_store.go` | `M365ClientTenantStore` | M365-specific consent state (will fold into `ClientTenantStore`) |
| `tenant_store.go` | `TenantStore` | Recursive tenant hierarchy |
| `config_store.go` | `ConfigStore` | Configuration data (YAML/JSON, inheritance) |
| `audit_store.go` | `AuditStore` | Immutable audit events |
| `rbac_store.go` | `RBACStore` | RBAC policy and role data |
| `registration_store.go` | `RegistrationStore` (tokens) | Steward registration tokens |
| `runtime_store.go` | `RuntimeStore` | Ephemeral/session runtime state |
| `session_store.go` | `SessionStore` | Durable session state (persistent sessions only; ephemeral state lives in `pkg/cache`) |
| `steward_store.go` | `StewardStore` | Durable fleet registry (steward status, last_seen, heartbeat); implemented by flat-file and SQLite providers |
| `command_store.go` | `CommandStore` | Durable command dispatch state (status, audit trail); implemented by SQLite provider (Issue #665) |
| `hybrid_manager.go` | `HybridStorageManager` | Composes multiple provider instances |

## Target Layout (per ADR-003)

```
pkg/storage/interfaces/
  business/       # TenantStore, ClientTenantStore, StewardStore (new), CommandStore (new),
                  # AuditStore, RBACStore, SessionStore (new), RegistrationTokenStore
  config/         # ConfigStore
  secrets/        # SecretStore (new — unifies SOPS and key vaults)
  timeseries/     # MetricsStore (new), LogStore (new)
  blob/           # BlobStore (new)
```

**Naming rule**: `*Store` = durable. Ephemeral/rebuildable state goes to `pkg/cache/` as `*Cache`, with no storage interface. `RuntimeStore` is retired — it mixed both.

### Current → Target Mapping

| Current interface | Target location | Notes |
|-------------------|-----------------|-------|
| `TenantStore` | `business/` | |
| `ClientTenantStore` | `business/` | Absorbs `M365ClientTenantStore`; provider-specific data (M365 consent, AD binding, Intune enrollment) as extension fields |
| `M365ClientTenantStore` | **folded into `ClientTenantStore`** | Removed as separate interface |
| `AuditStore` | `business/` | |
| `RBACStore` | `business/` | |
| `RegistrationStore` | `business/` | Renames to `RegistrationTokenStore` |
| `ConfigStore` | `config/` | |
| `RuntimeStore` | **retired** | Durable session state → `business/SessionStore`; ephemeral/derived state → `pkg/cache` |
| *(new)* `StewardStore` | `business/` | Replaces in-memory fleet state in `features/steward/health.go` |
| *(new)* `CommandStore` | `business/` | Replaces in-memory dispatch map in `features/steward/commands/handler.go` |
| *(new)* `SessionStore` | `business/` | Durable session state extracted from the retired `RuntimeStore` |
| *(new)* `SecretStore` | `secrets/` | Unifies SOPS and vault providers |
| *(new)* `MetricsStore` | `timeseries/` | |
| *(new)* `LogStore` | `timeseries/` | |
| *(new→implemented)* `BlobStore` | flat layout (`blob_store.go`) | **Implemented** in `providers/blobstore/filesystem/` (OSS) and `providers/blobstore/s3/` (commercial). Full reorganization into `blob/` subdirectory tracked under the ADR-003 epic. |

### Controller Interfaces Misplaced Under `features/steward/*`

Per ADR-003, no controller-side storage/logging interface may remain under `features/steward/` when the epic closes. Known offenders the reorganization story (sub-story I) must relocate:

- `features/steward/dna/events/drift_subscriber.go` — `StorageManager` interface (controller-side drift event persistence); move under the appropriate type directory here.
- `features/modules/m365/auth/admin_consent_flow.go` — duplicate `ClientTenantStore` interface; consolidate with the canonical `ClientTenantStore` in this package.

## Provider Inventory

| Provider | Package | Implements | Status |
|----------|---------|------------|--------|
| `flatfile` | `pkg/storage/providers/flatfile` | `ConfigStore`, `AuditStore`, `StewardStore` | Available — OSS default for config storage and fleet registry |
| `sqlite` | `pkg/storage/providers/sqlite` | Business-data stores + `StewardStore` | Available — OSS default for business-data tier |
| `database` | `pkg/storage/providers/database` | All stores | Available — commercial PostgreSQL backend |
| `git` | *(removed)* | *(removed)* | Removed in Issue #664 — use `flatfile` + git-sync |

## Backend Selection (per type)

Per ADR-003, deployments compose one provider per type:

| Type | OSS backend | Commercial/SaaS backend |
|------|-------------|-------------------------|
| Business data | SQLite | PostgreSQL |
| Config storage | **Flat file** (`flatfile`) | PostgreSQL (`database`) |
| Secrets | SOPS files | Key vault (AWS Secrets Manager / Vault / Azure Key Vault) |
| Timeseries | Local log files | ClickHouse / Timescale / Influx |
| Blobs | Local filesystem | S3-compatible object storage |

The OSS column is the zero-config default, not a limit. Any Commercial backend is available to OSS deployments — licensing boundary is tenant-tree shape, not backend choice.

Git is **not** a backend. It is an optional sync source bound to admin-designated config scopes; see ADR-003 for the sync model.

**`pkg/gitsync` is a write-through adapter, not a storage provider.** It sits in front of a `ConfigStore` (flat-file for OSS, PostgreSQL for commercial) and forwards imported configs via `ConfigStore.StoreConfig`. It does not implement the `ConfigStore` interface itself, and it is not registered through the provider system. Modules that read config data always target the `ConfigStore` directly — git-sync is invisible at read time. The adapter is wired at controller startup when `cfg.DataDir` is set and scope bindings exist.

## Composite Storage Manager (OSS Factory)

### `NewStorageManagerFromStores`

```go
func NewStorageManagerFromStores(
    configStore ConfigStore,
    auditStore AuditStore,
    rbacStore RBACStore,
    runtimeStore RuntimeStore,  // always nil — RuntimeStore is being retired per ADR-003
    tenantStore TenantStore,
    clientTenantStore ClientTenantStore,
    registrationTokenStore RegistrationTokenStore,
    sessionStore SessionStore,
    stewardStore StewardStore,
    commandStore CommandStore,
) *StorageManager
```

Composes a `StorageManager` from individually-supplied store implementations. The resulting
manager has `GetProviderName() == "composite"` and `GetProvider() == nil`. Any parameter may
be nil; the caller is responsible for providing the stores it needs.

`GetCapabilities()` returns a zero-value `ProviderCapabilities{}` for composite managers —
callers must not rely on capability flags when using composites. `GetVersion()` returns
`"composite"`.

### `CreateOSSStorageManager`

```go
func CreateOSSStorageManager(flatfileRoot, sqliteConnStr string) (*StorageManager, error)
```

Creates the OSS composite storage tier by wiring stores from the flatfile and SQLite
providers per the ADR-003 store-to-provider mapping:

| Store | Provider |
|-------|----------|
| `ConfigStore` | flatfile |
| `AuditStore` | flatfile |
| `StewardStore` | flatfile |
| `TenantStore` | SQLite |
| `ClientTenantStore` | SQLite |
| `RBACStore` | SQLite |
| `RegistrationTokenStore` | SQLite |
| `SessionStore` | SQLite |
| `CommandStore` | SQLite |
| `RuntimeStore` | nil (retired per ADR-003) |

**`sqliteConnStr`** is a caller-controlled DSN:
- Production: `"/var/lib/cfgms/cfgms.db"` (file path)
- Tests: `t.TempDir() + "/test.db"` (per-test isolation)
- Do NOT use `":memory:"` — parallel tests sharing `file::memory:?cache=shared` collide on schema.

Both the `"flatfile"` and `"sqlite"` providers must be registered via blank imports before
calling this function:

```go
import (
    _ "github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
    _ "github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
)
```

**`CreateAllStoresFromConfig` is deprecated** and retained only for backward compatibility with
single-provider deployments (e.g., `provider: database`). New deployments should use
`CreateOSSStorageManager`.

## Module Usage Pattern

Modules receive interfaces, never specific providers:

```go
type TemplateModule struct {
    configStore interfaces.ConfigStore
}

func NewTemplateModule(configStore interfaces.ConfigStore) *TemplateModule {
    return &TemplateModule{configStore: configStore}
}

func (tm *TemplateModule) SaveTemplate(ctx context.Context, template Template) error {
    return tm.configStore.StoreConfig(ctx, &interfaces.ConfigEntry{
        Key: &interfaces.ConfigKey{
            TenantID:  template.TenantID,
            Namespace: "templates",
            Name:      template.Name,
        },
        Data:   template.YAMLData,
        Format: interfaces.ConfigFormatYAML,
    })
}
```

## Testing

Use real providers with a temporary directory:

- OSS path: call `interfaces.CreateOSSStorageManager(t.TempDir(), t.TempDir()+"/test.db")` — or use `pkg/testing.SetupTestStorage(t)` which wraps this for you.
- Do NOT use `":memory:"` for SQLite in tests — parallel tests sharing `file::memory:?cache=shared` collide on schema migrations.
- Commercial path: PostgreSQL via testcontainers or the repo's existing docker-compose fixture.

CFGMS does not mock storage interfaces in tests (per CLAUDE.md "Real Component Testing").

## References

- [ADR-003: Storage Data Taxonomy](../../../docs/architecture/decisions/003-storage-data-taxonomy.md) — the authoritative plan
- [Storage Architecture](../../../docs/architecture/storage-architecture.md) — operator walk-through
- [`pkg/README.md`](../../README.md) — central provider rules (pluggable by default)
