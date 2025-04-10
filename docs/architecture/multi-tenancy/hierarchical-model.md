# Hierarchical Multi-Tenant Model

## Overview

CFGMS implements a hierarchical multi-tenant model where each tenant can have child tenants, creating a tree-like structure. For security and simplicity, tenants are stored in a flat directory structure with relationships managed through configuration.

## Tenant Relationship Management

### Root-Level Configuration

```yaml
# /cfgms/system/meta/tenants.yaml (root-only access)
tenants:
  acme:
    id: "acme"
    name: "ACME Corporation"
    parent: null        # Root tenant
    children:
      - "bravo"
      - "charlie"
    
  bravo:
    id: "bravo"
    name: "Bravo Division"
    parent: "acme"
    children: []
```

## Implementation

```go
type TenantManager struct {
    // Root-owned tenant relationship graph
    relationships *TenantRelationships
    rbac         *RBACManager
}

type TenantRelationships struct {
    tenants map[string]*Tenant
    mutex   sync.RWMutex
}

type Tenant struct {
    ID       string
    Name     string
    Parent   string
    Children []string
}
```

## Administrative Operations

### Tenant Admin Interface

```go
type TenantAdmin interface {
    // View Operations (Available to tenant admins)
    GetMyTenant() (*TenantView, error)
    ListMyChildren() ([]*TenantView, error)
    GetParentTenant() (*TenantView, error)
    
    // Management Operations (Available to tenant admins)
    CreateChildTenant(child *TenantConfig) error
    UpdateChildTenant(childID string, updates *TenantUpdates) error
    RemoveChildTenant(childID string) error
    
    // Config Operations
    GetInheritedConfig(path string) (*Config, error)
    UpdateTenantConfig(path string, config *Config) error
}

// Limited view for non-root users
type TenantView struct {
    ID   string
    Name string
}
```

### Root Admin Interface

```go
type RootAdmin interface {
    TenantAdmin            // Inherit tenant admin capabilities
    
    // Root-only operations
    CreateTenant(tenant *TenantConfig) error
    UpdateTenantRelationships(changes *RelationshipChanges) error
    MoveTenant(tenantID, newParentID string) error
    GetFullTenantTree() (*TenantTree, error)
}
```

## CLI/API Access

### Command Line Interface

```bash
# View operations
cfgms tenant get              # Get current tenant info
cfgms tenant list-children    # List child tenants
cfgms tenant get-parent       # Get parent tenant info

# Admin operations
cfgms tenant create-child <name> [flags]
cfgms tenant update-child <id> [flags]
cfgms tenant remove-child <id>

# Root-only operations
cfgms tenant create <name> [flags]
cfgms tenant move <id> <new-parent-id>
cfgms tenant tree             # View full tenant tree
```

### API Endpoints

```go
type TenantAPI struct {
    // View endpoints
    router.Get("/api/tenant", tm.GetMyTenant)
    router.Get("/api/tenant/children", tm.ListChildren)
    router.Get("/api/tenant/parent", tm.GetParent)
    
    // Admin endpoints
    router.Post("/api/tenant/children", tm.CreateChild)
    router.Put("/api/tenant/children/:id", tm.UpdateChild)
    router.Delete("/api/tenant/children/:id", tm.RemoveChild)
    
    // Root-only endpoints
    router.Post("/api/admin/tenants", tm.CreateTenant)
    router.Put("/api/admin/tenants/:id/parent", tm.MoveTenant)
    router.Get("/api/admin/tenants/tree", tm.GetTenantTree)
}
```

## Directory Structure

```txt
cfgms/
├─system/              # Root system configuration
│ ├─meta/              # System component configuration
│ │ └─tenants.yaml     # Tenant relationships (root-only access)
│
├─tenants/             # Flat tenant structure
│ ├─acme/              # Each tenant gets same structure
│ │ ├─system/          # Compiled system configs inherited from parent
│ │ ├─endpoints/       # Tenant-specific endpoint configs
│ │ ├─workflows/       # Tenant-specific workflows
│ │ └─modules/         # Tenant-specific modules
│ │
│ └─bravo/             # Child of ACME
│   ├─system/
│   ├─endpoints/
│   ├─meta/
│   ├─workflows/
│   └─modules/
```

## Security Considerations

### Core Principles

1. Tenant isolation
2. Hierarchical access control
3. No lateral visibility
4. Root-managed relationships

### Access Control

- System directory: Root access only
- Tenant directories: Tenant admin access
- Compiled directory: Read-only for endpoints

### Tenant Isolation

- Flat tenant structure
- No direct tenant-to-tenant access
- Relationship management through root

## Version Information

- **Document Version:** 1.0
- **Last Updated:** 2024-04-07
- **Status:** Draft
