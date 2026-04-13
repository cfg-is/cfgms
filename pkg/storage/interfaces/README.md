# CFGMS Storage Interfaces

This package defines the storage interfaces used by controller-side business logic. Modules import only these interfaces, never specific providers.

> **Scope**: Controller-side storage only. Steward persistence (local config file, OS keychain, in-memory state between convergence runs) is separate.

> **Direction**: This layout is being reorganized into a five-type taxonomy. See [ADR-003: Storage Data Taxonomy](../../../docs/architecture/decisions/003-storage-data-taxonomy.md) for the authoritative plan. The existing `pkg/storage/providers/git/` is deprecated and will be removed in favor of a new flat-file provider plus a git-sync component.

## Current Interfaces (flat layout)

The files in this directory today:

| File | Interface(s) | Purpose |
|------|--------------|---------|
| `provider.go` | `StorageProvider` | Provider registration and capability reporting |
| `client_tenant.go` | `ClientTenantStore` | MSP client tenant data |
| `m365_client_tenant_store.go` | `M365ClientTenantStore` | M365-specific consent state |
| `tenant_store.go` | `TenantStore` | Recursive tenant hierarchy |
| `config_store.go` | `ConfigStore` | Configuration data (YAML/JSON, inheritance) |
| `audit_store.go` | `AuditStore` | Immutable audit events |
| `rbac_store.go` | `RBACStore` | RBAC policy and role data |
| `registration_store.go` | `RegistrationStore` (tokens) | Steward registration tokens |
| `runtime_store.go` | `RuntimeStore` | Ephemeral/session runtime state |
| `hybrid_manager.go` | `HybridStorageManager` | Composes multiple provider instances |

## Target Layout (per ADR-003)

```
pkg/storage/interfaces/
  business/       # TenantStore, ClientTenantStore, StewardStore (new), CommandStore (new),
                  # AuditStore, RBACStore, SessionStore, RegistrationTokenStore
  config/         # ConfigStore, RuntimeStore
  secrets/        # SecretStore (new — unifies SOPS and key vaults)
  timeseries/     # MetricsStore (new), LogStore (new)
  blob/           # BlobStore (new)
```

### Current → Target Mapping

| Current interface | Target type directory | Notes |
|-------------------|-----------------------|-------|
| `TenantStore` | `business/` | |
| `ClientTenantStore` | `business/` | |
| `M365ClientTenantStore` | `business/` | M365-specific variant |
| `AuditStore` | `business/` | |
| `RBACStore` | `business/` | |
| `RegistrationStore` | `business/` | Renames to `RegistrationTokenStore` |
| `ConfigStore` | `config/` | |
| `RuntimeStore` | `config/` | Durable impls only (see below) |
| *(new)* `StewardStore` | `business/` | Replaces in-memory fleet state in `features/steward/health.go` |
| *(new)* `CommandStore` | `business/` | Replaces in-memory dispatch map in `features/steward/commands/handler.go` |
| *(new)* `SessionStore` | `business/` | Extracted from current `RuntimeStore` usage where applicable |
| *(new)* `SecretStore` | `secrets/` | Unifies SOPS and vault providers |
| *(new)* `MetricsStore` | `timeseries/` | |
| *(new)* `LogStore` | `timeseries/` | |
| *(new)* `BlobStore` | `blob/` | |

## Backend Selection (per type)

Per ADR-003, deployments compose one provider per type:

| Type | OSS backend | Commercial/SaaS backend |
|------|-------------|-------------------------|
| Business data | SQLite | PostgreSQL |
| Config storage | Flat file or PostgreSQL | PostgreSQL |
| Secrets | SOPS files | Key vault (AWS Secrets Manager / Vault / Azure Key Vault) |
| Timeseries | Local log files | ClickHouse / Timescale / Influx |
| Blobs | Local filesystem | S3-compatible object storage |

Git is **not** a backend. It is an optional sync source bound to admin-designated config scopes; see ADR-003 for the sync model.

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

Use real providers with a temporary root or in-memory database:

- OSS path: flat-file provider under `t.TempDir()`, SQLite under `file::memory:?cache=shared`.
- Commercial path: PostgreSQL via testcontainers or the repo's existing docker-compose fixture.

CFGMS does not mock storage interfaces in tests (per CLAUDE.md "Real Component Testing").

## References

- [ADR-003: Storage Data Taxonomy](../../../docs/architecture/decisions/003-storage-data-taxonomy.md) — the authoritative plan
- [Storage Architecture](../../../docs/architecture/hybrid-storage-solution.md) — operator walk-through
- [`pkg/README.md`](../../README.md) — central provider rules (pluggable by default)
