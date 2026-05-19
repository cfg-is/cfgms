# CFGMS Plugin Architecture Guide

## Overview

CFGMS implements a **Salt-inspired pluggable architecture** that separates interface definitions from implementations, enabling runtime plugin discovery and configuration-driven backend selection.

## Design Principles

Based on CFGMS's documented "Pluggable Infrastructure Design Paradigm":

> *Any infrastructure component that could reasonably have multiple implementations should be designed with a provider interface from the start.*

### Core Principles

1. **Interface-First Development** - Define contracts before implementations
2. **Runtime Discovery** - Plugins register themselves at startup via `init()`
3. **Configuration-Driven Selection** - Users choose backends via YAML config
4. **Graceful Degradation** - Missing plugins don't break the system
5. **Clear Separation** - Business logic never imports specific providers

## Directory Structure

Storage interfaces are organized into five sub-packages (the five-type taxonomy from ADR-003):

```
pkg/
├── storage/
│   ├── interfaces/           # Storage contracts (used by all features)
│   │   ├── business/         # Business data: TenantStore, ClientTenantStore,
│   │   │                     #   StewardStore, CommandStore, AuditStore,
│   │   │                     #   RBACStore, SessionStore, RegistrationTokenStore,
│   │   │                     #   TriggerStore, PushStore, DNAHistoryStore
│   │   ├── config/           # ConfigStore — human-editable configs
│   │   ├── blob/             # BlobStore — installer binaries, script bodies
│   │   ├── secrets/          # SecretStore — credentials, API keys
│   │   └── timeseries/       # MetricsStore, LogStore — append-only metrics
│   └── providers/            # Storage implementations (one per type)
│       ├── sqlite/           # Business data OSS default
│       ├── flatfile/         # Config + audit OSS default
│       ├── database/         # PostgreSQL (commercial/SaaS)
│       └── blobstore/
│           ├── filesystem/   # Blob storage OSS default
│           └── s3/           # Blob storage commercial/SaaS
features/
├── controller/               # Controller wires storage providers
├── modules/m365/auth/        # Uses pkg/storage/interfaces only
└── modules/firewall/         # Uses pkg/storage/interfaces only
```

## Implementation Pattern

### Step 1: Define Global Storage Interfaces

```go
// pkg/storage/interfaces/client_tenant.go
package interfaces

// ClientTenantStore defines storage for MSP client tenant data
type ClientTenantStore interface {
    StoreClient(client *ClientTenant) error
    GetClient(id string) (*ClientTenant, error)
    ListClients(filter ClientFilter) ([]*ClientTenant, error)
    DeleteClient(id string) error
}

// pkg/storage/interfaces/config.go
// ConfigStore defines storage for CFGMS configuration data
type ConfigStore interface {
    StoreConfig(tenantID, key string, config interface{}) error
    GetConfig(tenantID, key string) (interface{}, error)
    DeleteConfig(tenantID, key string) error
}

// pkg/storage/interfaces/plugin.go
// StorageProvider implements ALL storage interfaces for a backend
type StorageProvider interface {
    Name() string
    Available() (bool, error)
    
    // Create all storage interfaces for this provider
    CreateClientTenantStore(config map[string]interface{}) (ClientTenantStore, error)
    CreateConfigStore(config map[string]interface{}) (ConfigStore, error)
    CreateAuditStore(config map[string]interface{}) (AuditStore, error)
    
    Description() string
}
```

### Step 2: Provider Implementation (One Provider = All Storage Types)

```go
// pkg/storage/providers/database/plugin.go
package database

import "your.domain/cfgms/pkg/storage/interfaces"

type DatabaseProvider struct{}

func (p *DatabaseProvider) Name() string { return "database" }

func (p *DatabaseProvider) Available() (bool, error) {
    return true, nil // Check database connectivity
}

func (p *DatabaseProvider) CreateClientTenantStore(config map[string]interface{}) (interfaces.ClientTenantStore, error) {
    return NewDatabaseClientTenantStore(), nil
}

func (p *DatabaseProvider) CreateConfigStore(config map[string]interface{}) (interfaces.ConfigStore, error) {
    return NewDatabaseConfigStore(), nil
}

func (p *DatabaseProvider) CreateAuditStore(config map[string]interface{}) (interfaces.AuditStore, error) {
    return NewDatabaseAuditStore(), nil
}

func (p *DatabaseProvider) Description() string {
    return "PostgreSQL-backed storage for production and commercial deployments"
}

// Salt-style auto-registration
func init() {
    interfaces.RegisterStorageProvider(&DatabaseProvider{})
}
```

### Step 3: Modules Use Global Storage Interfaces Only

```go
// features/modules/m365/auth/admin_consent.go
package auth

import (
    "your.domain/cfgms/pkg/storage/interfaces"
    // ❌ NEVER import specific providers like:
    // "your.domain/cfgms/pkg/storage/providers/database"
)

type AdminConsentFlow struct {
    clientStore interfaces.ClientTenantStore  // Global interface!
}

// Controller injects the storage interface - module doesn't care which provider
func NewAdminConsentFlow(clientStore interfaces.ClientTenantStore) *AdminConsentFlow {
    return &AdminConsentFlow{clientStore: clientStore}
}
```

### Step 4: Controller-Level Storage Configuration

Storage is configured per data type (five-type composition). See [Storage Architecture](storage-architecture.md) for the full reference.

```yaml
# cfgms.yaml - Controller configuration (OSS example)
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

The actual `StorageManager` in `pkg/storage/interfaces` composes providers for each data type. Features receive the specific store interface they need — they never import providers directly.

See `pkg/storage/interfaces/provider.go` for the `StorageManager` and `CreateOSSStorageManager` wiring.

## Plugin Discovery and Management

### List Available Plugins

```bash
cfg plugins list storage
```

```
Available Storage Plugins (business data):
  ✅ sqlite      - SQLite storage (OSS default)
  ✅ database    - PostgreSQL storage (requires: postgresql client)

Available Storage Plugins (config storage):
  ✅ flatfile    - Flat-file storage (OSS default)
  ✅ database    - PostgreSQL storage (commercial/SaaS)

Available Storage Plugins (blob storage):
  ✅ filesystem  - Local filesystem (OSS default)
  ✅ s3          - S3-compatible object storage
```

### Runtime Plugin Information

```go
// Get all registered storage providers
available := interfaces.GetRegisteredProviders()

// Check specific provider by name
provider, err := interfaces.GetStorageProvider("sqlite")
if err != nil {
    log.Printf("SQLite provider unavailable: %v", err)
    // Fall back to database provider
    provider, _ = interfaces.GetStorageProvider("database")
}
```

## Testing Strategy

### Interface Compliance Testing

```go
// features/storage/interfaces/compliance_test.go
func TestStoragePluginCompliance(t *testing.T) {
    plugins := interfaces.GetAvailableStoragePlugins()
    
    for name, plugin := range plugins {
        t.Run(name, func(t *testing.T) {
            store, err := plugin.Create(map[string]interface{}{})
            require.NoError(t, err)
            
            // Test all interface methods
            testStoreCompliance(t, store)
        })
    }
}
```

### Business Logic Testing

Business logic tests use real CFGMS provider implementations (e.g. SQLite for business data, flat-file for config storage) — never in-memory substitutes or mocks. The pluggable interface makes it trivial to inject the appropriate real provider in tests:

```go
// features/modules/m365/auth/admin_consent_test.go
func TestAdminConsentFlow(t *testing.T) {
    // Use a real storage provider (sqlite) — no mocks or in-memory substitutes
    provider, err := interfaces.GetStorageProvider("sqlite")
    require.NoError(t, err)
    bundle, err := provider.OpenBusinessStores(t.TempDir() + "/test.db")
    require.NoError(t, err)

    flow := NewAdminConsentFlow(bundle.ClientTenant)
    // Test business logic with a real provider; isolation via t.TempDir()
}
```

## Plugin Development Guidelines

### 1. Plugin Naming Convention

- Plugin names should be lowercase, descriptive
- Use hyphens for multi-word names: `azure-sql`, `s3-bucket`

### 2. Dependency Management

- Check dependencies in `Available()` method
- Return descriptive errors: `"requires postgresql client library"`

### 3. Configuration Schema

- Use simple `map[string]interface{}` for flexibility
- Document required/optional fields in plugin description

### 4. Error Handling

- Return wrapped errors with plugin context
- Use consistent error formats across plugins

### 5. Documentation

- Each plugin must have a README.md in its directory
- Document configuration options and examples

## Migration from Existing Patterns

### Current State (DNA Storage)

```go
// features/steward/dna/storage/backends.go - Multiple implementations in one file
func NewBackend(backendType BackendType, config *Config, logger Logger) (Backend, error) {
    switch backendType {
    case BackendMemory:
        return NewDatabaseBackend(config, logger)
    case BackendFile:
        return NewFileBackend(config, logger)
    // ...
    }
}
```

### Target State (Plugin Pattern)

```go
// Features automatically discover plugins via init() registration
func CreateStorageFromConfig(backendType string, config map[string]interface{}) (Backend, error) {
    plugin, err := GetStoragePlugin(backendType)
    if err != nil {
        available := GetAvailableStoragePlugins()
        return nil, fmt.Errorf("backend '%s' unavailable. Available: %v", backendType, available)
    }
    return plugin.Create(config)
}
```

## Architecture Summary

### Key Concept: Five-Type Storage Composition

Per [ADR-003](decisions/003-storage-data-taxonomy.md), storage is split into five independent data types. Each type is configured with its own provider — there is no single global storage backend.

- **Business data** (tenants, RBAC, sessions, commands, audit): `sqlite` (OSS), `database`/PostgreSQL (commercial)
- **Config storage** (templates, policies, firewall rules): `flatfile` (OSS), `database`/PostgreSQL (commercial)
- **Secrets** (credentials, certificates): `sops` (OSS), key vault (commercial)
- **Timeseries** (metrics, logs): local files (OSS), ClickHouse/Timescale (commercial)
- **Blobs** (installers, script bodies): `filesystem` (OSS), `s3` (commercial)

### Configuration Flow

```
cfgms.yaml (controller.storage.* with per-type providers)
    ↓
Controller creates one provider per data type:
  ├── business.provider: sqlite  → SQLite tables for tenants, RBAC, etc.
  ├── config.provider: flatfile  → Flat files for human-editable configs
  ├── secrets.provider: sops     → SOPS-encrypted files
  ├── timeseries.provider: filelog → Append-only log files
  └── blobs.provider: filesystem → Local filesystem blobs
    ↓
Modules get injected with the specific interface they need
(don't know which backend serves it)
```

## Benefits

1. **Consistency**: All data in same storage system (no mixed backends)
2. **Simplicity**: One storage decision affects entire system
3. **Developer Experience**: Clear separation between plugin development and usage
4. **Testing**: Easy to test against all available backends
5. **Deployment Flexibility**: Runtime plugin discovery based on environment
6. **User Experience**: Simple configuration with automatic capability detection
7. **Maintainability**: Plugins can be developed/tested independently

## Examples in Codebase

Current implementations following this pattern:

- **Business data**: `pkg/storage/providers/sqlite` (TenantStore, ClientTenantStore, AuditStore, RBACStore, SessionStore, CommandStore, StewardStore, RegistrationTokenStore, TriggerStore, PushStore)
- **Config storage**: `pkg/storage/providers/flatfile` (ConfigStore, AuditStore, StewardStore)
- **Blob storage**: `pkg/storage/providers/blobstore/filesystem` and `blobstore/s3`
- **PostgreSQL**: `pkg/storage/providers/database` (business + config stores for commercial)
- **Git sync**: `pkg/gitsync` — optional read-only import from external git repos into ConfigStore
- **Control/data plane**: `pkg/controlplane/providers/grpc`, `pkg/dataplane/providers/grpc`
- **Secrets**: `pkg/secrets` (SOPS-based for OSS)
- **Logging**: `pkg/logging` (file, timescale)

Future:
- **KMS Providers**: Vault, AWS KMS, Azure Key Vault
- **Timeseries backends**: ClickHouse, InfluxDB, Timescale
