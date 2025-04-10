# Configuration Inheritance

## Overview

CFGMS implements a hierarchical configuration inheritance model where child tenants inherit configuration from their parent tenants. This inheritance is managed through a compilation process that merges configurations based on the tenant hierarchy.

## Inheritance Rules

1. Child configurations override parent configurations
2. Inheritance is depth-first (deepest override wins)
3. Arrays are merged based on key fields
4. Inheritance is explicit and traceable
5. Compilation happens at runtime

## Configuration Structure

### Base Configuration

```yaml
# /cfgms/tenants/acme/system/base.yaml
system:
  security:
    password_policy:
      min_length: 12
      require_special: true
      require_numbers: true
    mfa:
      enabled: true
      methods:
        - type: "totp"
          issuer: "ACME Corp"
  
  monitoring:
    intervals:
      health_check: "5m"
      config_check: "15m"
    alerts:
      channels:
        - type: "email"
          address: "ops@acme.com"
```

### Child Configuration

```yaml
# /cfgms/tenants/bravo/system/base.yaml
system:
  security:
    password_policy:
      min_length: 14  # Override parent
    mfa:
      methods:
        - type: "sms"  # Add new method
          number: "+1234567890"
  
  monitoring:
    alerts:
      channels:
        - type: "slack"  # Add new channel
          webhook: "https://hooks.slack.com/..."
```

## Compilation Process

### Implementation

```go
type ConfigCompiler struct {
    tenantManager *TenantManager
    configStore   *ConfigStore
}

type CompiledConfig struct {
    TenantID    string
    ParentID    string
    Config      *Config
    Overrides   map[string]interface{}
    Inherited   map[string]interface{}
    Timestamp   time.Time
}

func (cc *ConfigCompiler) CompileTenantConfig(tenantID string) (*CompiledConfig, error) {
    // Get tenant hierarchy
    hierarchy, err := cc.tenantManager.GetTenantHierarchy(tenantID)
    if err != nil {
        return nil, fmt.Errorf("failed to get tenant hierarchy: %w", err)
    }
    
    // Start with root config
    config := &Config{}
    
    // Apply each level's config
    for _, tid := range hierarchy {
        tenantConfig, err := cc.configStore.GetConfig(tid)
        if err != nil {
            return nil, fmt.Errorf("failed to get config for tenant %s: %w", tid, err)
        }
        
        // Merge configs
        if err := config.Merge(tenantConfig); err != nil {
            return nil, fmt.Errorf("failed to merge config for tenant %s: %w", tid, err)
        }
    }
    
    return &CompiledConfig{
        TenantID:  tenantID,
        ParentID:  hierarchy[len(hierarchy)-2], // Second to last is parent
        Config:    config,
        Timestamp: time.Now(),
    }, nil
}
```

## Configuration Access

### API Interface

```go
type ConfigAPI struct {
    // Get compiled config for current tenant
    router.Get("/api/config", api.GetCurrentConfig)
    
    // Get raw config for current tenant
    router.Get("/api/config/raw", api.GetRawConfig)
    
    // Update config for current tenant
    router.Put("/api/config", api.UpdateConfig)
    
    // View inheritance chain
    router.Get("/api/config/inheritance", api.GetInheritanceChain)
}
```

### CLI Commands

```bash
# View compiled config
cfgms config get

# View raw config
cfgms config get --raw

# Update config
cfgms config set <path> <value>

# View inheritance
cfgms config inheritance
```

## Inheritance Visualization

### Example Output

```yaml
# Compiled config for tenant "bravo"
system:
  security:
    password_policy:
      min_length: 14        # From bravo
      require_special: true # From acme
      require_numbers: true # From acme
    mfa:
      enabled: true         # From acme
      methods:
        - type: "totp"      # From acme
          issuer: "ACME Corp"
        - type: "sms"       # From bravo
          number: "+1234567890"
  
  monitoring:
    intervals:
      health_check: "5m"    # From acme
      config_check: "15m"   # From acme
    alerts:
      channels:
        - type: "email"     # From acme
          address: "ops@acme.com"
        - type: "slack"     # From bravo
          webhook: "https://hooks.slack.com/..."
```

## Best Practices

1. **Minimal Overrides**
   - Only override what needs to be different
   - Keep inherited values when possible

2. **Documentation**
   - Document why overrides are needed
   - Maintain change history

3. **Validation**
   - Validate configs before applying
   - Ensure compatibility with parent configs

4. **Testing**
   - Test inheritance chains
   - Verify override behavior

## Version Information

- **Document Version:** 1.0
- **Last Updated:** 2024-04-07
- **Status:** Draft
