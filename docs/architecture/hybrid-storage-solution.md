# Hybrid Storage Architecture Solution

## Problem Statement

You asked an important architectural question:

> "How should we handle a large deployment where we want to use Postgres, but the MSP wants to use more of a git-ops workflow to manage cfg files and/or we want to be able to back up all cfg versions with change history and comments to one or more git repos? We initially started down this path saying we want one global setting for storage backend, but do we want to either have tenant level overrides or maybe split config storage and other storage into two different global settings so that we can still support git for some things even in a DB backed deployment?"

## Solution: Hybrid Storage Architecture

Our hybrid storage architecture addresses this by splitting storage responsibilities based on data characteristics and access patterns:

### Architecture Overview

```yaml
controller:
  storage:
    # Operational Data → PostgreSQL (Performance Critical)
    operational:
      provider: "database"
      config: { ... }  # High-performance operations, ACID transactions
      
    # Configuration Data → Git (GitOps Workflow)  
    configuration:
      provider: "git"
      config: { ... }  # Version control, peer review, audit trail
```

### Data Separation by Purpose

| Data Type | Storage Backend | Rationale |
|-----------|----------------|-----------|
| **Operational Data** | PostgreSQL | Performance, ACID transactions, complex queries |
| - Audit logs | Database | High write volume, compliance queries |
| - Client tenant data | Database | Relational data, fast lookups |
| - Session management | Database | Real-time access patterns |
| - Registration tokens | Database/Git | Token persistence across restarts |
| **Configuration Data** | Git Repository | GitOps workflow, change management |
| - Configuration templates | Git | Version control, peer review |
| - Certificate management | Git | Audit trail via Git history |
| - Policy configurations | Git | GitOps deployment pipeline |

### Key Benefits

#### 1. GitOps Workflow Support
- **Pull Request Process**: All configuration changes require PR approval
- **Peer Review**: Critical changes reviewed by team members  
- **Audit Trail**: Complete history via Git commits with author/timestamp
- **Rollback Capability**: Easy rollback via `git revert`
- **Branch-based Environments**: `dev`, `staging`, `production` branches
- **SOPS Integration**: Encrypted sensitive configurations

#### 2. Performance for Operational Data
- **ACID Transactions**: Database ensures data consistency for audit logs
- **Optimized Queries**: PostgreSQL indexing for compliance reporting
- **High Throughput**: Efficient handling of high-volume audit ingestion
- **Relational Integrity**: Foreign key constraints for tenant relationships

#### 3. Security and Compliance
- **Separation of Concerns**: Different security models for different data types
- **SOPS Encryption**: Git-stored configs encrypted with Mozilla SOPS
- **Git Access Controls**: Repository-level permissions and branch protection
- **Immutable Audit**: Both Git commits and database provide audit trails

#### 4. Migration Support
- **Gradual Migration**: Existing deployments can migrate incrementally
- **Configuration Detection**: System automatically handles both storage formats
- **Migration Planning**: Built-in migration strategy recommendations

## Implementation Details

### Configuration Example

```yaml
# cfgms.yaml - Simplified Hybrid Storage Configuration
controller:
  storage:
    operational:
      provider: "database"
      config:
        host: "cfgms-postgres.internal"
        database: "cfgms_ops"
        max_open_connections: 50
        
    configuration:
      provider: "git"
      config:
        repository_path: "/data/cfgms-configs"
        remote_url: "git@github.com:msp-corp/cfgms-configs.git"
        require_pull_request: true
        sops_enabled: true
```

### Core Components

1. **HybridStorageManager** (`pkg/storage/interfaces/hybrid_manager.go`)
   - Manages both operational and configuration providers
   - Routes storage operations to appropriate backend
   - Provides unified interface to business logic

2. **Storage Provider Registry** (`pkg/storage/interfaces/provider.go`)
   - Auto-discovery of available storage providers
   - Validation and health checking
   - Provider capability reporting

3. **Migration Support** (`hybrid_manager.go`)
   - Migration planning from single to hybrid storage
   - Configuration preservation during migration
   - Backup and rollback strategies

### API Integration

The hybrid storage is transparent to existing APIs:

```go
// Business logic remains unchanged
manager := storage.NewHybridStorageManager(config)

// Operational data goes to PostgreSQL
auditStore := manager.GetAuditStore()
tenantStore := manager.GetClientTenantStore()

// Configuration data goes to Git
configStore := manager.GetConfigStore()
```

## Alternative Approaches Considered

### 1. Tenant-Level Storage Overrides
**Rejected because:**
- Complexity: Each tenant would need storage configuration
- Management overhead: Multiple storage backends per deployment
- Data consistency: Cross-tenant operations become complex
- Security: More attack surface with multiple backends

### 2. Global Setting with Git Backup
**Rejected because:**
- Limited GitOps workflow: Database remains primary
- No peer review process: Changes bypass Git workflow
- Backup lag: Git becomes eventually consistent copy
- Complexity: Synchronization between database and Git

## Real-World Deployment Examples

### Large MSP Scenario
```yaml
# 5,000+ endpoints, multiple teams, compliance requirements
controller:
  storage:
    operational:
      provider: "database"
      config:
        host: "postgres-cluster.internal"
        database: "cfgms_production"
        max_open_connections: 100  # High performance
        
    configuration:
      provider: "git"  
      config:
        remote_url: "git@github.com:acme-msp/cfgms-production.git"
        branch: "main"
        require_pull_request: true
        protected_branches: ["main", "production"]
        sops_enabled: true
```

### Development/Testing Environment
```yaml
# Lightweight setup for development
controller:
  storage:
    operational:
      provider: "database"
      config:
        host: "localhost"
        database: "cfgms_dev"
        
    configuration:
      provider: "git"
      config:
        repository_path: "/tmp/cfgms-dev-configs"
        branch: "develop"
        require_pull_request: false  # Faster dev cycle
```

## Migration Path

### Phase 1: Assessment
```bash
# Detect current configuration type
make migration-assessment
# Output: "Current: single-database, Recommended: hybrid"
```

### Phase 2: Add Git Provider
```yaml
# Gradually add Git for configurations only
# Existing operational data remains in database
controller:
  storage:
    operational:
      provider: "database"  # Existing config preserved
      config: { ... }
    configuration:
      provider: "git"       # New Git workflow
      config: { ... }
```

### Phase 3: Data Migration
```bash
# Export configurations from database to Git
cfg config export --format git --target /data/cfgms-configs

# Initialize Git repository with existing configs
git init /data/cfgms-configs
git add .
git commit -m "Initial configuration migration from database"
```

## Testing and Validation

All hybrid storage functionality is fully tested:

```bash
# Run hybrid storage tests
go test -v ./pkg/storage/interfaces/ -run TestHybrid

# Validate complete integration
make test

# Security validation
make security-scan
```

## Conclusion

The hybrid storage architecture provides the best of both worlds:

- **PostgreSQL** for operational data requiring performance and ACID transactions
- **Git** for configuration data requiring GitOps workflow and change management

This approach directly addresses your MSP GitOps workflow requirements while maintaining the database performance benefits for operational data.

The solution is production-ready with comprehensive testing, security validation, and migration support for existing deployments.