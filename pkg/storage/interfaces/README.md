# CFGMS Global Storage Interfaces

This package defines the global storage interfaces that unify CFGMS storage architecture. All modules import only these interfaces, never specific storage providers, enabling flexible deployment configurations.

## Overview

The global storage system provides three main storage interfaces:

1. **ClientTenantStore** - MSP client tenant management (M365 consent, client data)
2. **ConfigStore** - All configuration data (templates, certificates, settings) 
3. **AuditStore** - All audit logs and compliance data (immutable events)

## Core Concept: "One Storage Decision"

```yaml
# Single configuration affects entire system
controller.storage.provider: database  # Everything uses PostgreSQL
# OR
controller.storage.provider: git       # Everything uses Git + SOPS
```

## Architecture

### StorageProvider Interface

All storage providers must implement:
- `CreateClientTenantStore()` - Create client tenant storage
- `CreateConfigStore()` - Create configuration storage  
- `CreateAuditStore()` - Create audit storage
- `GetCapabilities()` - Describe provider features
- `Available()` - Check if provider is ready

### Auto-Registration System

Providers register themselves via `init()` functions:

```go
// In provider package
func init() {
    interfaces.RegisterStorageProvider(&MyProvider{})
}
```

### StorageManager

Unified access to all storage interfaces:

```go
manager, err := interfaces.CreateAllStoresFromConfig("database", config)
if err != nil {
    return err
}

// Access any storage interface
configStore := manager.GetConfigStore()
auditStore := manager.GetAuditStore()
clientStore := manager.GetClientTenantStore()
```

## Storage Interfaces

### ConfigStore

Handles human-editable configurations with YAML/JSON support:

```go
// Store configuration
config := &interfaces.ConfigEntry{
    Key: &interfaces.ConfigKey{
        TenantID:  "client1",
        Namespace: "templates", 
        Name:      "firewall",
    },
    Data:   []byte("firewall:\n  rules:\n    - allow: 443"),
    Format: interfaces.ConfigFormatYAML,
}
err := store.StoreConfig(ctx, config)

// Retrieve with inheritance
resolved, err := store.ResolveConfigWithInheritance(ctx, key)
```

**Key Features:**
- YAML for human-editable configs (firewall rules, templates)
- JSON for system configs (metadata, settings)
- Version history and rollback
- Multi-tenant isolation via TenantID
- Template inheritance resolution
- Batch operations for performance

### AuditStore

Handles immutable audit logs for compliance:

```go
// Store audit event
entry := &interfaces.AuditEntry{
    TenantID:     "client1",
    EventType:    interfaces.AuditEventAuthentication,
    Action:       "login",
    UserID:       "admin@client1.com",
    UserType:     interfaces.AuditUserTypeHuman,
    Result:       interfaces.AuditResultSuccess,
    ResourceType: "terminal_session",
    ResourceID:   "session-123",
    Severity:     interfaces.AuditSeverityMedium,
}
err := store.StoreAuditEntry(ctx, entry)

// Query for compliance reports
failed := store.GetFailedActions(ctx, timeRange, 100)
```

**Key Features:**
- Immutable audit events (no updates/deletes)
- Rich event categorization and filtering
- Security monitoring queries
- Compliance reporting
- Batch operations for high-volume logging
- Retention and archival policies

### ClientTenantStore

Handles MSP client tenant data (M365 consent, client information):

```go
// Store client tenant
client := &interfaces.ClientTenant{
    TenantID:    "12345-abcd-efgh",
    TenantName:  "Contoso Ltd",
    DomainName:  "contoso.com", 
    AdminEmail:  "admin@contoso.com",
    Status:      interfaces.ClientTenantStatusActive,
}
err := store.StoreClientTenant(client)
```

## Data Formats

### Configuration Data Strategy

**YAML for Human-Editable:**
```yaml
# configs/client1/firewall.yaml
firewall:
  rules:
    - name: web
      action: allow 
      port: 443
      source: any
```

**JSON for System-Managed:**
```json
// clients/client1.json
{
  "tenant_id": "12345-abcd",
  "tenant_name": "Contoso Ltd",
  "consented_at": "2025-01-15T10:30:00Z",
  "status": "active"
}
```

## Provider Capabilities

Providers declare their capabilities:

```go
type ProviderCapabilities struct {
    SupportsTransactions    bool // ACID transactions
    SupportsVersioning      bool // Config versioning  
    SupportsFullTextSearch  bool // Full-text search
    SupportsEncryption      bool // At-rest encryption
    SupportsCompression     bool // Data compression
    SupportsReplication     bool // HA replication
    SupportsSharding        bool // Horizontal scaling
    MaxBatchSize           int  // Max batch operations
    MaxConfigSize          int  // Max single config size
    MaxAuditRetentionDays  int  // Max audit retention
}
```

## Usage Examples

### Controller Integration

```go
// Create unified storage from config
config := map[string]interface{}{
    "database_url": "postgresql://...",
}

manager, err := interfaces.CreateAllStoresFromConfig("database", config)
if err != nil {
    log.Fatal(err)
}

// Use throughout application
configSvc := NewConfigService(manager.GetConfigStore())
auditSvc := NewAuditService(manager.GetAuditStore()) 
clientSvc := NewClientService(manager.GetClientTenantStore())
```

### Module Integration

```go
// Modules receive interfaces, never specific providers
type TemplateModule struct {
    configStore interfaces.ConfigStore
}

func NewTemplateModule(configStore interfaces.ConfigStore) *TemplateModule {
    return &TemplateModule{configStore: configStore}
}

func (tm *TemplateModule) SaveTemplate(ctx context.Context, template Template) error {
    config := &interfaces.ConfigEntry{
        Key: &interfaces.ConfigKey{
            TenantID:  template.TenantID,
            Namespace: "templates",
            Name:      template.Name,
        },
        Data:   template.YAMLData,
        Format: interfaces.ConfigFormatYAML,
    }
    
    return tm.configStore.StoreConfig(ctx, config)
}
```

## Error Handling

All interfaces define standard error types:

```go
// Config errors
var (
    ErrConfigNotFound    = &ConfigValidationError{...}
    ErrInvalidFormat     = &ConfigValidationError{...}
    ErrChecksumMismatch  = &ConfigValidationError{...}
)

// Audit errors
var (
    ErrAuditNotFound      = &AuditValidationError{...} 
    ErrInvalidTimeRange   = &AuditValidationError{...}
    ErrUserIDRequired     = &AuditValidationError{...}
)

// Client tenant errors
var (
    ErrTenantNotFound = &ClientTenantValidationError{...}
    ErrTenantExists   = &ClientTenantValidationError{...}
    ErrConsentExpired = &ClientTenantValidationError{...}
)
```

## Testing

The package provides comprehensive mock implementations:

```go
func TestMyFeature(t *testing.T) {
    provider := interfaces.NewMockStorageProvider()
    manager, err := interfaces.CreateAllStoresFromConfig("mock", nil)
    require.NoError(t, err)
    
    // Test with real interfaces, mock backend
    configStore := manager.GetConfigStore()
    // ... test implementation
}
```

## Migration from Existing Storage

When migrating existing storage patterns to global interfaces:

1. **Replace direct storage imports** with interface imports
2. **Update constructors** to receive interfaces via dependency injection  
3. **Adapt data models** to use ConfigEntry/AuditEntry formats
4. **Test with multiple providers** to ensure portability

Example migration:
```go
// Before: Direct storage dependency
type CertificateManager struct {
    storage *cert.FileStore  // Direct dependency
}

// After: Interface dependency 
type CertificateManager struct {
    configStore interfaces.ConfigStore  // Interface dependency
}
```

This enables the same certificate manager to work with any storage provider (git, database, memory) without code changes.