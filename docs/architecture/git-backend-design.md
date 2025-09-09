# Git Backend Architecture Design

## Overview

The CFGMS Git backend implements a hybrid repository structure that balances security, scalability, and operational efficiency for MSP configuration management. This design uses separate repositories per client with a global MSP repository for templates and policies.

## Repository Structure

### MSP Global Repository
```
cfgms-msp-global/
├── .cfgms/
│   └── repo-metadata.yaml      # Repository type: msp-global
├── templates/                  # Reusable configuration templates
│   ├── security/
│   │   ├── baseline.yaml
│   │   └── hardened.yaml
│   ├── applications/
│   │   ├── nginx.yaml
│   │   └── docker.yaml
│   └── compliance/
│       ├── hipaa.yaml
│       └── pci-dss.yaml
├── policies/                   # MSP-wide policies
│   ├── patch-management.yaml
│   ├── backup-retention.yaml
│   └── access-control.yaml
├── defaults/                   # Default configurations
│   ├── steward-defaults.yaml
│   └── module-defaults.yaml
└── hooks/                      # Git hooks for validation
    ├── pre-commit
    └── pre-receive
```

### Client Repository Structure
```
cfgms-client-{client-id}/
├── .cfgms/
│   ├── repo-metadata.yaml      # Repository type: client
│   └── inheritance.yaml        # References to parent templates
├── config.yaml                 # Client-level configuration
├── groups/                     # Group configurations
│   ├── production/
│   │   ├── config.yaml
│   │   └── devices/
│   │       ├── web-server-01.yaml
│   │       └── db-server-01.yaml
│   ├── staging/
│   │   └── config.yaml
│   └── development/
│       └── config.yaml
├── templates/                  # Client-specific templates
│   └── custom-app.yaml
├── variables/                  # Environment variables
│   ├── global.yaml
│   ├── production.yaml
│   └── staging.yaml
└── hooks/                      # Client-specific hooks
    └── pre-commit
```

## Implementation Architecture

### Core Components

```
features/config/git/
├── manager.go              # Main Git manager interface
├── repository.go           # Repository operations
├── provider.go            # Git provider abstraction
├── sync.go                # Cross-repository synchronization
├── hooks.go               # Git hooks management
├── types.go               # Common types and interfaces
├── providers/
│   ├── github.go
│   ├── gitlab.go
│   └── bitbucket.go
├── operations/
│   ├── commit.go
│   ├── branch.go
│   ├── merge.go
│   └── diff.go
└── storage/
    ├── local.go           # Local git operations
    └── remote.go          # Remote repository operations
```

### Key Interfaces

```go
// GitManager orchestrates all Git operations
type GitManager interface {
    // Repository management
    CreateRepository(ctx context.Context, repo RepositoryConfig) (*Repository, error)
    GetRepository(ctx context.Context, repoID string) (*Repository, error)
    ListRepositories(ctx context.Context, filter RepositoryFilter) ([]*Repository, error)
    
    // Configuration operations
    GetConfiguration(ctx context.Context, ref ConfigurationRef) (*Configuration, error)
    SaveConfiguration(ctx context.Context, ref ConfigurationRef, config *Configuration) error
    
    // Branch management
    CreateBranch(ctx context.Context, repoID, branchName, fromRef string) error
    MergeBranch(ctx context.Context, repoID, source, target string) error
    
    // Synchronization
    SyncTemplates(ctx context.Context, clientRepoID string) error
    PropagateChange(ctx context.Context, change ChangeSet) error
}

// Repository represents a Git repository
type Repository interface {
    // Basic operations
    Clone(ctx context.Context) error
    Pull(ctx context.Context) error
    Push(ctx context.Context) error
    
    // Configuration operations
    ReadConfig(path string) (*Configuration, error)
    WriteConfig(path string, config *Configuration, message string) error
    
    // Branch operations
    ListBranches() ([]string, error)
    CheckoutBranch(name string) error
    CreateBranch(name string) error
    
    // History operations
    GetHistory(path string, limit int) ([]*Commit, error)
    GetDiff(fromRef, toRef string) (*Diff, error)
}

// GitProvider abstracts different Git providers
type GitProvider interface {
    CreateRepository(ctx context.Context, config RepositoryConfig) (*RemoteRepository, error)
    GetRepository(ctx context.Context, owner, name string) (*RemoteRepository, error)
    CreateWebhook(ctx context.Context, repo *RemoteRepository, config WebhookConfig) error
    CreatePullRequest(ctx context.Context, repo *RemoteRepository, pr PullRequestConfig) error
}
```

## Multi-Tenant Design

### Repository Naming Convention
- MSP Global: `cfgms-{msp-id}-global`
- Client: `cfgms-{msp-id}-client-{client-id}`
- Shared Resources: `cfgms-{msp-id}-shared-{resource-type}`

### Access Control
```yaml
# Repository access mapping
access_control:
  msp_global:
    read: ["msp_admin", "msp_operator"]
    write: ["msp_admin"]
  
  client_repo:
    read: ["msp_admin", "msp_operator", "client_admin:{client_id}"]
    write: ["msp_admin", "client_admin:{client_id}"]
    
  branch_protection:
    main:
      require_review: true
      required_reviewers: 1
      dismiss_stale_reviews: true
    production/*:
      require_review: true
      required_reviewers: 2
```

### Template Inheritance
```yaml
# Client repository .cfgms/inheritance.yaml
inheritance:
  - repository: cfgms-msp-global
    templates:
      - path: templates/security/baseline.yaml
        override_allowed: false
      - path: templates/compliance/hipaa.yaml
        override_allowed: true
    policies:
      - path: policies/patch-management.yaml
        merge_strategy: deep
```

## Synchronization Strategy

### Template Propagation Flow
1. Change made to MSP global template
2. System identifies affected client repositories
3. Creates pull requests in each client repository
4. Applies changes based on inheritance rules
5. Triggers validation hooks
6. Notifies relevant stakeholders

### Cross-Repository Operations
```go
// Example: Propagate security baseline update
func (m *GitManager) PropagateSecurityBaseline(ctx context.Context) error {
    // Get all client repositories
    clients, err := m.ListRepositories(ctx, RepositoryFilter{Type: "client"})
    if err != nil {
        return err
    }
    
    // For each client using the baseline
    for _, client := range clients {
        if client.UsesTemplate("templates/security/baseline.yaml") {
            // Create update branch
            branch := fmt.Sprintf("update-security-baseline-%s", time.Now().Format("20060102"))
            client.CreateBranch(branch)
            
            // Apply template changes
            m.SyncTemplates(ctx, client.ID)
            
            // Create pull request
            m.CreatePullRequest(ctx, client, PullRequestConfig{
                Title: "Security Baseline Update",
                Branch: branch,
                Target: "main",
            })
        }
    }
    return nil
}
```

## Configuration Commit Structure

### Commit Message Format
```
[MODULE] Action: Brief description

Changed: path/to/config.yaml
Actor: user@example.com
Tenant: client-id/group-id
Timestamp: 2024-01-15T10:30:00Z
Change-ID: uuid

Detailed changes:
- Updated firewall rules
- Added new package requirement
```

### Metadata Storage
```yaml
# .cfgms/commits/[change-id].yaml
change_metadata:
  id: "550e8400-e29b-41d4-a716-446655440000"
  timestamp: "2024-01-15T10:30:00Z"
  actor:
    user: "admin@msp.com"
    role: "msp_admin"
    ip: "192.168.1.100"
  affected_resources:
    - type: "firewall"
      id: "fw-001"
      changes: ["rules.inbound", "rules.outbound"]
  validation:
    pre_commit: "passed"
    syntax_check: "passed"
    policy_check: "passed"
  rollback:
    previous_commit: "abc123"
    can_rollback: true
```

## Git Hooks Implementation

### Pre-Commit Hook
```bash
#!/bin/bash
# Validate configuration syntax
cfgctl validate --file="$1"

# Check against MSP policies
cfgctl policy check --file="$1" --policies=/etc/cfgms/policies

# Ensure metadata is present
cfgctl metadata verify --file="$1"
```

### Pre-Receive Hook (Server-side)
```bash
#!/bin/bash
# Verify actor permissions
cfgctl auth verify --actor="$GIT_AUTHOR" --repository="$GIT_REPO"

# Run security scans
cfgctl security scan --changes="$GIT_DIFF"

# Check resource limits
cfgctl limits check --tenant="$TENANT_ID"
```

## Branch Strategy

### Environment Mapping
- `main` → Production configuration
- `staging` → Staging environment
- `develop` → Development environment
- `feature/*` → Feature branches for changes
- `hotfix/*` → Emergency fixes

### Promotion Flow
```
feature/update-nginx → develop → staging → main
                         ↓         ↓         ↓
                       [Test]   [Validate] [Deploy]
```

## Performance Considerations

### Repository Size Management
- Implement configuration file chunking for large deployments
- Use Git LFS for binary artifacts
- Regular repository maintenance (gc, prune)
- Archive old configurations after retention period

### Caching Strategy
- Local repository cache for frequently accessed configs
- In-memory cache for active configurations
- Redis cache for distributed deployments

## Security Considerations

### Encryption
- Encrypt sensitive values in Git using age or sops
- Store encryption keys in separate key management system
- Rotate encryption keys periodically

### Audit Trail
- All Git operations logged to audit system
- Webhook notifications for repository changes
- Integration with SIEM systems

## Implementation Phases

### Phase 1: Core Git Operations (Week 1-2)
- [ ] Basic repository management
- [ ] Local Git operations using go-git
- [ ] Configuration read/write
- [ ] Basic commit functionality

### Phase 2: Provider Integration (Week 2-3)
- [ ] GitHub provider implementation
- [ ] GitLab provider implementation
- [ ] Webhook management
- [ ] Authentication handling

### Phase 3: Multi-Repository Support (Week 3-4)
- [ ] Repository discovery
- [ ] Cross-repository operations
- [ ] Template synchronization
- [ ] Inheritance system

### Phase 4: Advanced Features (Week 4-5)
- [ ] Branch protection rules
- [ ] Git hooks framework
- [ ] Automated pull requests
- [ ] Rollback capabilities

### Phase 5: Performance & Security (Week 5-6)
- [ ] Caching implementation
- [ ] Encryption integration
- [ ] Performance optimization
- [ ] Security hardening