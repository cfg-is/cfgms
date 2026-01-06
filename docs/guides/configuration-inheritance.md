# Configuration Inheritance User Guide

## Overview

CFGMS implements a hierarchical configuration inheritance system that allows MSPs to define organization-wide policies while enabling customization at lower levels. This guide explains how to effectively use configuration inheritance for multi-tenant management.

## Table of Contents

- [Hierarchy Levels](#hierarchy-levels)
- [Inheritance Rules](#inheritance-rules)
- [Configuration Format](#configuration-format)
- [Practical Examples](#practical-examples)
- [Best Practices](#best-practices)
- [API Usage](#api-usage)
- [Troubleshooting](#troubleshooting)

## Hierarchy Levels

CFGMS uses a four-tier hierarchy for configuration inheritance:

```
MSP (Level 0)
├── Client (Level 1)
│   ├── Group (Level 2)
│   │   └── Device (Level 3)
│   └── Group (Level 2)
│       └── Device (Level 3)
└── Client (Level 1)
    └── Device (Level 3)  # Direct client-device relationship
```

### Level Definitions

| Level | Name | Description | Use Cases |
|-------|------|-------------|-----------|
| 0 | MSP | Service provider defaults | Security baselines, compliance policies |
| 1 | Client | Customer organization | Client-specific policies, branding |
| 2 | Group | Device groupings | Department policies, environment configs |
| 3 | Device | Individual endpoints | Device-specific overrides, local settings |

## Inheritance Rules

### 1. Declarative Block Merging

Configuration inheritance uses **declarative block replacement**, not field-level merging:

```yaml
# MSP Level (Level 0)
firewall:
  rules:
    web:
      protocol: tcp
      port: 80
      action: allow
    ssh:
      protocol: tcp
      port: 22
      action: deny

# Client Level (Level 1) - Overrides entire 'web' block
firewall:
  rules:
    web:
      protocol: tcp
      port: 443
      action: allow
      source: "10.0.0.0/8"
```

**Result**: The client's web rule completely replaces the MSP's web rule. SSH rule inherited unchanged.

### 2. First Valid Configuration Wins

Configuration values are resolved in hierarchy order:

1. Device (Level 3) - highest priority
2. Group (Level 2)
3. Client (Level 1)
4. MSP (Level 0) - lowest priority

### 3. Source Tracking

Every configuration value includes metadata about its source:

```json
{
  "firewall": {
    "rules": {
      "web": {
        "value": {
          "protocol": "tcp",
          "port": 443,
          "action": "allow"
        },
        "source": "client",
        "level": 1
      },
      "ssh": {
        "value": {
          "protocol": "tcp",
          "port": 22,
          "action": "deny"
        },
        "source": "msp",
        "level": 0
      }
    }
  }
}
```

## Configuration Format

### Hierarchical Naming

Use structured naming to prevent conflicts and enable clean inheritance:

```yaml
# Good: Hierarchical structure
modules:
  firewall:
    rules:
      web_http:
        port: 80
        action: allow
      web_https:
        port: 443
        action: allow
  
  users:
    admin:
      permissions: ["read", "write", "admin"]
    operator:
      permissions: ["read", "write"]

# Avoid: Flat structure that causes conflicts
firewall_rule_1: "allow port 80"
firewall_rule_2: "allow port 443"
```

### Module Configuration

Each module can have configuration at any hierarchy level:

```yaml
# MSP Level - Security baseline
modules:
  package:
    policy: "auto_update"
    allowed_sources: ["official"]
  
  script:
    signing_policy: "required"
    timeout: "300s"

# Client Level - Client-specific requirements  
modules:
  package:
    allowed_sources: ["official", "client-repo.example.com"]
  
  backup:
    schedule: "0 2 * * *"
    retention: "30d"
```

## Practical Examples

### Example 1: Security Policy Inheritance

#### MSP Level Configuration

```yaml
# /config/msp/security-baseline.yaml
modules:
  firewall:
    default_action: deny
    rules:
      ssh_management:
        protocol: tcp
        port: 22
        source: "10.0.0.0/8"
        action: allow
      
      web_services:
        protocol: tcp
        ports: [80, 443]
        action: allow
  
  script:
    signing_policy: required
    timeout: "300s"
  
  package:
    policy: "security_updates_only"
    auto_update: true
```

#### Client Level Customization

```yaml
# /config/client/acme-corp/web-policy.yaml
modules:
  firewall:
    rules:
      web_services:
        protocol: tcp
        ports: [80, 443, 8080, 8443]  # Add development ports
        action: allow
      
      database:
        protocol: tcp
        port: 3306
        source: "192.168.1.0/24"  # Internal network only
        action: allow
  
  backup:
    schedule: "0 1 * * *"  # 1 AM daily
    destination: "s3://acme-backups/"
```

#### Group Level Specialization

```yaml
# /config/client/acme-corp/group/development/dev-overrides.yaml
modules:
  script:
    signing_policy: optional  # Relaxed for development
  
  package:
    policy: "all_updates"  # Allow all packages in dev
    allowed_sources: ["official", "dev-repos.acme.com"]
```

#### Device Level Specifics

```yaml
# /config/device/dev-server-01/local-config.yaml
modules:
  firewall:
    rules:
      debug_port:
        protocol: tcp
        port: 9229  # Node.js debug port
        source: "192.168.1.100"  # Developer workstation
        action: allow
  
  monitoring:
    metrics_endpoint: "http://localhost:9090/metrics"
    log_level: "debug"
```

### Example 2: Multi-Environment Setup

#### MSP: Base Monitoring

```yaml
modules:
  monitoring:
    agent: "cfgms-agent"
    interval: "60s"
    metrics:
      - "cpu"
      - "memory" 
      - "disk"
```

#### Client: Production Environment

```yaml
modules:
  monitoring:
    metrics:
      - "cpu"
      - "memory"
      - "disk"
      - "network"
      - "services"
    alerts:
      cpu_threshold: 80
      memory_threshold: 85
    
  backup:
    schedule: "0 2 * * *"
    retention: "90d"
    encryption: true
```

#### Group: Database Servers

```yaml
modules:
  monitoring:
    metrics:
      - "cpu"
      - "memory"
      - "disk"
      - "network"
      - "services"
      - "database_performance"
    
  backup:
    schedule: "0 0,12 * * *"  # Twice daily
    retention: "180d"  # Longer retention for DB
```

### Example 3: Effective Configuration Result

Given the above configurations, the effective configuration for `dev-server-01` would be:

```json
{
  "modules": {
    "firewall": {
      "default_action": {
        "value": "deny",
        "source": "msp",
        "level": 0
      },
      "rules": {
        "ssh_management": {
          "value": {
            "protocol": "tcp",
            "port": 22,
            "source": "10.0.0.0/8",
            "action": "allow"
          },
          "source": "msp",
          "level": 0
        },
        "web_services": {
          "value": {
            "protocol": "tcp",
            "ports": [80, 443, 8080, 8443],
            "action": "allow"
          },
          "source": "client",
          "level": 1
        },
        "database": {
          "value": {
            "protocol": "tcp",
            "port": 3306,
            "source": "192.168.1.0/24",
            "action": "allow"
          },
          "source": "client",
          "level": 1
        },
        "debug_port": {
          "value": {
            "protocol": "tcp",
            "port": 9229,
            "source": "192.168.1.100",
            "action": "allow"
          },
          "source": "device",
          "level": 3
        }
      }
    },
    "script": {
      "signing_policy": {
        "value": "optional",
        "source": "group",
        "level": 2
      },
      "timeout": {
        "value": "300s",
        "source": "msp",
        "level": 0
      }
    }
  }
}
```

## Best Practices

### 1. Configuration Organization

#### Use Semantic Naming

```yaml
# Good
modules:
  security:
    policies:
      password_complexity: "high"
      mfa_required: true
  
  compliance:
    standards:
      pci_dss: true
      hipaa: false

# Avoid
security_policy_1: "complex_passwords"
compliance_setting_a: true
```

#### Group Related Settings

```yaml
# Good - Related settings grouped
modules:
  web_server:
    apache:
      max_connections: 500
      timeout: 30
      ssl_protocols: ["TLSv1.2", "TLSv1.3"]
    
    nginx:
      worker_processes: "auto"
      client_max_body_size: "10M"

# Avoid - Scattered configuration
apache_max_connections: 500
nginx_workers: "auto"
ssl_protocols: ["TLSv1.2", "TLSv1.3"]
```

### 2. Inheritance Strategy

#### Start with Restrictive Defaults

```yaml
# MSP Level - Secure by default
modules:
  firewall:
    default_action: deny
    
  script:
    signing_policy: required
    
  package:
    auto_update: false
    policy: "security_only"
```

#### Allow Controlled Relaxation

```yaml
# Development Group - Relaxed for development
modules:
  script:
    signing_policy: optional
    
  package:
    policy: "all_updates"
```

### 3. Documentation and Validation

#### Document Configuration Purpose

```yaml
modules:
  backup:
    # Production backup policy - daily with 90-day retention
    schedule: "0 2 * * *"
    retention: "90d"
    
    # Encrypt all backups for compliance
    encryption: true
    encryption_key_id: "backup-key-prod"
```

#### Use Configuration Validation

```bash
# Validate configuration before applying
curl -X POST /api/v1/stewards/{id}/config/validate \
  -H "Content-Type: application/json" \
  -d @new-config.json
```

### 4. Version Control

#### Track Configuration Changes

```bash
# Store configurations in version control
git add config/client/acme-corp/
git commit -m "feat: add development environment config for ACME Corp"
```

#### Use Branching for Testing

```bash
# Test configuration changes in branches
git checkout -b feature/acme-corp-security-update
# Make changes, test, then merge
```

## API Usage

### Retrieve Effective Configuration

Get the final merged configuration for a steward:

```bash
curl -X GET /api/v1/stewards/{steward-id}/config/effective \
  -H "X-API-Key: your-api-key" \
  -H "Accept: application/json"
```

Response includes source tracking:

```json
{
  "steward_id": "steward-123",
  "version": "1.0.0",
  "config": {
    "modules": {
      "firewall": {
        "rules": {
          "web": {
            "value": {"port": 443, "action": "allow"},
            "source": "client",
            "level": 1
          }
        }
      }
    }
  },
  "inheritance_metadata": {
    "msp_id": "msp-456",
    "client_id": "client-789",
    "group_id": "group-101",
    "resolved_at": "2025-07-28T10:30:00Z"
  }
}
```

### Query Configuration by Level

```bash
# Get MSP-level configuration
curl -X GET /api/v1/config/msp/{msp-id}

# Get client-level configuration  
curl -X GET /api/v1/config/client/{client-id}

# Get group-level configuration
curl -X GET /api/v1/config/group/{group-id}

# Get device-specific configuration
curl -X GET /api/v1/config/device/{device-id}
```

### Update Configuration

```bash
# Update client-level configuration
curl -X PUT /api/v1/config/client/{client-id} \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "modules": {
      "firewall": {
        "rules": {
          "new_rule": {
            "protocol": "tcp",
            "port": 8080,
            "action": "allow"
          }
        }
      }
    }
  }'
```

## Troubleshooting

### Common Issues

#### 1. Configuration Not Inherited

**Problem**: Device not receiving expected configuration

**Solution**:

1. Check hierarchy relationships:

   ```bash
   curl -X GET /api/v1/stewards/{id}/hierarchy
   ```

2. Verify configuration at each level:

   ```bash
   curl -X GET /api/v1/config/effective/{steward-id}?debug=true
   ```

3. Check for naming conflicts:

   ```bash
   # Look for similar block names
   grep -r "firewall.rules" config/
   ```

#### 2. Unexpected Configuration Override

**Problem**: Lower-level configuration not taking effect

**Solution**:

1. Check configuration syntax:

   ```bash
   curl -X POST /api/v1/config/validate \
     -d @config.json
   ```

2. Verify block naming matches exactly:

   ```yaml
   # These are different blocks
   firewall.rules.web    # Block 1
   firewall.rules.web_   # Block 2 (trailing underscore)
   ```

3. Check inheritance order:

   ```bash
   curl -X GET /api/v1/stewards/{id}/config/effective?trace=true
   ```

#### 3. Performance Issues

**Problem**: Slow configuration resolution

**Solutions**:

1. Reduce configuration depth
2. Optimize block structure
3. Use configuration caching
4. Monitor inheritance performance:

   ```bash
   curl -X GET /api/v1/monitoring/config/performance
   ```

### Debug Tools

#### Configuration Tracer

```bash
# Enable detailed inheritance tracing
curl -X GET /api/v1/stewards/{id}/config/effective?trace=true
```

#### Validation Tool

```bash
# Validate configuration syntax and inheritance
cfg config validate --file config.yaml --trace
```

#### Inheritance Visualizer

```bash
# Show configuration inheritance tree
cfg config tree --steward-id {id} --format json
```

## Advanced Topics

### Conditional Inheritance

Future enhancement for condition-based inheritance:

```yaml
modules:
  firewall:
    rules:
      dev_ports:
        condition: "environment == 'development'"
        protocol: tcp
        ports: [3000, 8080, 9000]
        action: allow
```

### Configuration Templates

Template-based inheritance for common patterns:

```yaml
templates:
  web_server_baseline:
    modules:
      firewall:
        rules:
          http: {port: 80, action: allow}
          https: {port: 443, action: allow}
      
      monitoring:
        metrics: ["cpu", "memory", "connections"]

inherit_from: web_server_baseline
modules:
  backup:
    schedule: "0 2 * * *"
```

### Dynamic Configuration

Environment-aware configuration resolution:

```yaml
modules:
  database:
    connection:
      host: "${env:production ? 'prod-db.example.com' : 'dev-db.example.com'}"
      ssl: "${env:production ? true : false}"
```

## Migration Guide

### From Flat Configuration

1. **Identify Configuration Groups**

   ```yaml
   # Before: Flat structure
   ssh_port: 22
   web_port: 80
   backup_schedule: "0 2 * * *"
   
   # After: Hierarchical structure
   modules:
     firewall:
       rules:
         ssh: {port: 22, action: allow}
         web: {port: 80, action: allow}
     backup:
       schedule: "0 2 * * *"
   ```

2. **Establish Hierarchy**
   - Move common settings to MSP level
   - Client-specific settings to client level
   - Device overrides to device level

3. **Test Inheritance**

   ```bash
   # Verify effective configuration
   cfg config preview --steward-id {id}
   ```

### Best Migration Practices

1. **Gradual Migration**: Migrate one module at a time
2. **Backup Original**: Keep original flat configurations
3. **Validate Results**: Compare effective configurations
4. **Monitor Performance**: Check inheritance performance impact

This completes the Configuration Inheritance User Guide. The system provides powerful inheritance capabilities while maintaining transparency and control over configuration sources.
