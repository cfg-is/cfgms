# Configuration Resolution

## Overview

Configuration resolution is the process of determining which configurations apply to a specific endpoint and how they are merged to produce a final configuration. CFGMS uses a sophisticated resolution process that takes into account DNA matching, tenant inheritance, and configuration specificity.

For a high-level overview of the configuration management system, see [Configuration Management Overview](./overview.md).
For information about configuration types, see [Configuration Types](./configuration-types.md).

## DNA-Based Matching

DNA (eg Deoxyribonucleic acid in living organisms) is a set of attributes that describe an endpoint, such as its role, environment, location, or any other metadata. DNA is used to match configurations to endpoints.

```go
type DNAMatcher struct {
    Attributes map[string]string
}

func (m *DNAMatcher) Matches(dna DNA) bool {
    for key, value := range m.Attributes {
        if dna[key] != value {
            return false
        }
    }
    return true
}
```

### DNA Matching Rules

1. **Exact Match** - All specified attributes must match exactly
2. **Partial Match** - Configurations can specify a subset of attributes
3. **Wildcard Match** - Configurations can use wildcards for attribute values
4. **Regex Match** - Configurations can use regular expressions for attribute values

## Inheritance Resolution

Configurations can inherit from parent tenants, with child configurations overriding parent configurations. The inheritance resolution process determines the inheritance chain and merges configurations according to precedence rules.

```go
type ConfigResolver struct {
    tenantMgr *TenantManager
    store     ConfigStorage
}

func (r *ConfigResolver) ResolveConfig(endpoint *Endpoint) (*Config, error) {
    // 1. Get inheritance chain
    chain := r.tenantMgr.getInheritanceChain(endpoint.TenantID)
    
    // 2. Collect matching configs
    var matches []*Config
    for _, tenantID := range chain {
        configs := r.findMatchingConfigs(tenantID, endpoint.DNA)
        matches = append(matches, configs...)
    }
    
    // 3. Sort by specificity
    sort.Sort(BySpecificity(matches))
    
    // 4. Merge configs
    return r.mergeConfigs(matches), nil
}
```

### Inheritance Resolution Rules

1. **Depth-First** - Configurations are resolved from root to leaf
2. **Specificity** - More specific configurations override less specific ones
3. **Explicit Override** - Child configurations can explicitly override parent configurations
4. **Implicit Inheritance** - Child configurations inherit from parent configurations unless explicitly overridden

## Configuration Merging

Configurations are merged according to a set of rules that determine how different configuration types are combined.

```go
func mergeConfigs(configs []*Config) *Config {
    result := &Config{}
    
    for _, cfg := range configs {
        result = mergeSingle(result, cfg)
    }
    
    return result
}

func mergeSingle(base, override *Config) *Config {
    // Deep merge objects
    merged := make(map[string]interface{})
    
    // Copy base values
    for k, v := range base.Data {
        merged[k] = v
    }
    
    // Apply overrides
    for k, v := range override.Data {
        if v == nil {
            delete(merged, k)
        } else if baseObj, ok := merged[k].(map[string]interface{}); ok {
            if overrideObj, ok := v.(map[string]interface{}); ok {
                merged[k] = mergeMaps(baseObj, overrideObj)
                continue
            }
        }
        merged[k] = v
    }
    
    return &Config{Data: merged}
}
```

### Merging Rules

1. **Later Overrides Earlier** - Later configurations override earlier ones
2. **Arrays Are Replaced** - Arrays are replaced, not merged
3. **Objects Are Merged Recursively** - Objects are merged recursively
4. **Null Values Remove Properties** - Null values remove properties

## Configuration Specificity

Configurations are sorted by specificity to determine which ones take precedence during merging.

```go
type BySpecificity []*Config

func (a BySpecificity) Len() int { return len(a) }
func (a BySpecificity) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a BySpecificity) Less(i, j int) bool {
    // Calculate specificity scores
    scoreI := calculateSpecificity(a[i])
    scoreJ := calculateSpecificity(a[j])
    
    // Higher score = more specific
    return scoreI > scoreJ
}

func calculateSpecificity(cfg *Config) int {
    score := 0
    
    // More DNA attributes = more specific
    score += len(cfg.DNA) * 10
    
    // Deeper in tenant hierarchy = more specific
    score += cfg.TenantDepth * 5
    
    // Explicit overrides = more specific
    if cfg.IsExplicitOverride {
        score += 20
    }
    
    return score
}
```

### Specificity Factors

1. **DNA Attributes** - More DNA attributes = more specific
2. **Tenant Depth** - Deeper in tenant hierarchy = more specific
3. **Explicit Overrides** - Explicit overrides = more specific
4. **Configuration Type** - Some configuration types are more specific than others

## Resolution Process

The complete resolution process involves:

1. **DNA Matching** - Find configurations that match the endpoint's DNA
2. **Inheritance Resolution** - Determine the inheritance chain
3. **Specificity Sorting** - Sort configurations by specificity
4. **Configuration Merging** - Merge configurations according to rules
5. **Validation** - Validate the resulting configuration

For information about configuration validation, see [Configuration Validation](./configuration-validation.md).

## Related Documentation

- [Configuration Management Overview](./overview.md): Introduction to configuration management in CFGMS
- [Configuration Types](./configuration-types.md): Different types of configurations and their purposes
- [Configuration Validation](./configuration-validation.md): Schema validation and error handling
- [Configuration Storage](./configuration-storage.md): How configurations are stored and versioned

## Version Information

- **Document Version:** 1.0
- **Last Updated:** 2024-04-07
- **Status:** Draft
