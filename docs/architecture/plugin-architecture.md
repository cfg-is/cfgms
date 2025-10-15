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

```
pkg/
├── storage/                   # Global storage system
│   ├── interfaces/           # Storage contracts (used by all modules)
│   │   ├── client_tenant.go # MSP client tenant storage interface
│   │   ├── config.go        # Configuration storage interface
│   │   └── audit.go         # Audit log storage interface
│   └── providers/           # Storage implementations (controller selects one)
│       ├── memory/
│       │   ├── plugin.go    # Plugin registration
│       │   ├── client_tenant.go
│       │   ├── config.go
│       │   └── audit.go
│       ├── file/
│       ├── database/
│       └── git/
features/
├── controller/              # Controller configures global storage
├── modules/m365/auth/       # Uses pkg/storage/interfaces only
└── modules/firewall/        # Uses pkg/storage/interfaces only
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
    return "In-memory storage for development and testing"
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

```yaml
# cfgms.yaml - Controller configuration
controller:
  storage:
    provider: memory  # Single choice for ALL storage needs
    config:
      # Provider-specific config
      database_url: postgresql://...  # for database provider
      file_path: /var/lib/cfgms       # for file provider  
      git_repository: https://...     # for git provider
```

```go
// features/controller/storage.go
type StorageManager struct {
    provider          interfaces.StorageProvider
    clientTenantStore interfaces.ClientTenantStore
    configStore       interfaces.ConfigStore
    auditStore        interfaces.AuditStore
}

func NewStorageManager(providerName string, config map[string]interface{}) (*StorageManager, error) {
    // Get the configured provider
    provider, err := interfaces.GetStorageProvider(providerName)
    if err != nil {
        return nil, fmt.Errorf("storage provider '%s' not available: %v", providerName, err)
    }
    
    // Create ALL storage interfaces from the same provider
    clientStore, err := provider.CreateClientTenantStore(config)
    if err != nil {
        return nil, err
    }
    
    configStore, err := provider.CreateConfigStore(config)
    if err != nil {
        return nil, err
    }
    
    auditStore, err := provider.CreateAuditStore(config)
    if err != nil {
        return nil, err
    }
    
    return &StorageManager{
        provider:          provider,
        clientTenantStore: clientStore,
        configStore:       configStore,
        auditStore:        auditStore,
    }, nil
}

// Modules get injected with the specific interface they need
func (sm *StorageManager) GetClientTenantStore() interfaces.ClientTenantStore {
    return sm.clientTenantStore
}
```

## Plugin Discovery and Management

### List Available Plugins

```bash
cfgcli plugins list storage
```

```
Available Storage Plugins:
  ✅ memory      - In-memory storage (development/testing)
  ✅ file        - Local file storage (simple deployments)
  ❌ database    - PostgreSQL storage (requires: postgresql client)
  ❌ git         - Git-based storage (requires: git, mozilla-sops)
```

### Runtime Plugin Information

```go
// Get all available plugins
available := interfaces.GetAvailableStoragePlugins()

// Check specific plugin
plugin, err := interfaces.GetStoragePlugin("database")
if err != nil {
    log.Printf("Database plugin unavailable: %v", err)
    // Fall back to file storage
    plugin, _ = interfaces.GetStoragePlugin("file")
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

```go
// features/modules/m365/auth/admin_consent_test.go
func TestAdminConsentFlow(t *testing.T) {
    // Use any available storage plugin
    plugin, _ := interfaces.GetStoragePlugin("memory")
    store, _ := plugin.Create(nil)
    
    flow := NewAdminConsentFlow(store)
    // Test business logic without caring about storage implementation
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

### Key Concept: Global Storage Decision
- **Controller** chooses ONE storage provider for the entire system
- **All modules** use the same storage backend automatically  
- **Users** configure storage once at the controller level
- **No per-module storage decisions** - everything is consistent

### Configuration Flow
```
cfgms.yaml (controller.storage.provider: "database")
    ↓
Controller creates DatabaseProvider 
    ↓  
All storage interfaces use database:
  ├── ClientTenantStore → PostgreSQL tables
  ├── ConfigStore → PostgreSQL tables  
  └── AuditStore → PostgreSQL tables
    ↓
Modules get injected with interfaces (don't know it's PostgreSQL)
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
- **Storage Backends**: DNA storage (interfaces.go + backends.go) 
- **Compression**: GZIP, ZSTD, LZ4 compressors
- **Git Providers**: GitHub, GitLab, Bitbucket integration

Future implementations:
- **MSP Client Storage**: Memory, File, Git, Database backends
- **KMS Providers**: Vault, AWS KMS, Azure Key Vault
- **Database Providers**: PostgreSQL, MySQL, SQLite adapters