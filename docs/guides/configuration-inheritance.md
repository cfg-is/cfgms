# Configuration Inheritance User Guide

## Overview

CFGMS implements a hierarchical configuration inheritance system that allows MSPs to define organization-wide policies while enabling customization at lower levels. This guide explains how to effectively use configuration inheritance for multi-tenant management.

## Table of Contents

- [Tenant Model](#tenant-model)
- [Hierarchy Levels](#hierarchy-levels)
- [Inheritance Rules](#inheritance-rules)
- [Configuration Format](#configuration-format)
- [Licensing Boundary: Apache vs Elastic](#licensing-boundary-apache-vs-elastic)
- [Practical Examples](#practical-examples)
- [Best Practices](#best-practices)
- [API Usage](#api-usage)
- [Troubleshooting](#troubleshooting)

## Tenant Model

CFGMS uses a **recursive parent-child tenant model with arbitrary depth**. Tenants are identified by a **path** such as `root/msp-a/client-1/servers`. There are no fixed hierarchy levels — the MSP → Client → Group → Device convention is a common four-level pattern, but the system supports any depth. Path-based identification enables:

- **Prefix matching** — target all tenants under `root/msp-a/` with a single operation
- **Wildcard targeting** — `root/msp-a/*/production` matches all production groups across clients
- **Efficient resolution** — cfg inheritance walks the path from root to leaf

### Current Inheritance Depth

The inheritance resolver currently processes the **first three tenant path levels** plus device-specific configuration:

| Path position | Conventional name | Config namespace |
|---------------|-------------------|-----------------|
| Level 0 (root) | MSP | `msp-policies` |
| Level 1 | Client | `client-policies` |
| Level 2 | Group | `group-policies` |
| Level 3+ intermediate | (skipped) | — |
| Device (leaf) | Device | `stewards` (per steward ID) |

Tenants at path depth > 3 that are not the leaf device-specific level are silently skipped during resolution. The device-specific cfg always has the highest priority.

## Hierarchy Levels

The conventional four-level pattern:

```
MSP (Level 0, root)
├── Client (Level 1)
│   ├── Group (Level 2)
│   │   └── Device (steward) — device-specific cfg applied last
│   └── Group (Level 2)
│       └── Device (steward)
└── Client (Level 1)
    └── Device (steward)  # no group — inherits directly from client
```

### Level Definitions

| Level | Conventional Name | Description | Use Cases |
|-------|-------------------|-------------|-----------|
| 0 | MSP | Service provider root | Security baselines, compliance policies |
| 1 | Client | Customer organization | Client-specific policies, branding |
| 2 | Group | Device groupings | Department policies, environment configs |
| Device | Device | Individual endpoint | Device-specific overrides, local settings |

## Inheritance Rules

### 1. Declarative Resource Merging

Configuration inheritance uses **named resource replacement**: when a child level defines a resource with the same `name` as a parent's resource, the child's resource block **completely replaces** the parent's. Parent resources with unique names are inherited unchanged.

```yaml
# MSP Level: defines 'ssh-rules' resource
resources:
  - name: ssh-rules
    module: firewall
    config:
      protocol: tcp
      port: 22
      action: allow
      source: "10.0.0.0/8"
  - name: web-rules
    module: firewall
    config:
      protocol: tcp
      ports: [80, 443]
      action: allow

# Client Level: redefines 'web-rules' to add ports; 'ssh-rules' is inherited unchanged
resources:
  - name: web-rules
    module: firewall
    config:
      protocol: tcp
      ports: [80, 443, 8080, 8443]   # Development ports added
      action: allow
      source: "10.0.0.0/8"
```

**Result**: `web-rules` comes entirely from the client level. `ssh-rules` is inherited from MSP.

### 2. Child Overrides Parent (Leaf Wins)

Configuration is applied from root to leaf. Each child level overrides what its parent set for any resource with the same name. Higher-specificity levels always win:

1. Device (device-specific cfg) — highest priority
2. Group (Level 2)
3. Client (Level 1)
4. MSP (Level 0, root) — lowest priority

### 3. Source Tracking

Every resolved configuration carries metadata identifying which tenant level provided each setting.

The effective configuration response includes a `sources` map alongside the resolved `config`:

```json
{
  "steward_id": "dev-server-01",
  "tenant_id": "root/msp-a/acme-corp/development",
  "config": {
    "steward": { "id": "dev-server-01", "mode": "standalone" },
    "resources": [
      { "name": "ssh-rules",  "module": "firewall", "config": { ... } },
      { "name": "web-rules",  "module": "firewall", "config": { ... } }
    ]
  },
  "sources": {
    "resource.ssh-rules": {
      "level": 0,
      "tenant_id": "root/msp-a",
      "config_name": "global",
      "version": 3,
      "updated_at": "2026-05-01T10:00:00Z",
      "source": "Level 0 (msp-policies)"
    },
    "resource.web-rules": {
      "level": 1,
      "tenant_id": "root/msp-a/acme-corp",
      "config_name": "root/msp-a/acme-corp",
      "version": 7,
      "updated_at": "2026-05-10T14:30:00Z",
      "source": "Level 1 (client-policies)"
    }
  },
  "generated_at": "2026-05-19T09:00:00Z"
}
```

## Configuration Format

CFGMS configuration files use a **resources array** format. Each resource names a module and provides module-specific config. The `modules` key (optional) maps module names to custom binary paths, not to config.

```yaml
steward:
  id: my-steward
  mode: standalone          # or "controller" when connected to a controller

resources:
  - name: resource-unique-name  # used as the merge key for inheritance
    module: module-name
    config:
      key: value            # module-specific settings

  - name: another-resource
    module: other-module
    config:
      setting: value

# Optional: override where specific modules are loaded from
modules:
  firewall: /opt/cfgms/modules/custom-firewall
```

### Using Environment Variables

Configuration values support `${VAR}` and `${VAR:-default}` syntax:

| Pattern | Behavior |
|---------|----------|
| `${VAR}` | Expands to VAR. **Fails at startup if VAR is unset** |
| `${VAR:-default}` | Uses default if VAR is unset |
| `${VAR:=default}` | Sets VAR to default if unset, then expands |

```yaml
steward:
  id: ${HOSTNAME}

resources:
  - name: app-database
    module: file
    config:
      path: /etc/myapp/database.cfg
      content: |
        host=${DB_HOST:-localhost}
        password=${DB_PASSWORD}   # required — startup fails if not set
```

## Licensing Boundary: Apache vs Elastic

The tenant depth capability is the same in both tiers, but the **number of root tenants** determines which license applies:

### Apache License (OSS)

A **single root tenant tree** — one MSP, unlimited depth beneath it.

```
acme-msp (single root)
 ├── client-a
 │   ├── production
 │   │   ├── device-1 (steward)
 │   │   └── device-2 (steward)
 │   └── development
 │       └── device-3 (steward)
 └── client-b
     └── device-4 (steward)
```

### Elastic License (Commercial)

**Multiple independent root tenants** under a platform root — the cfg.is SaaS deployment model.

```
cfg-is (platform root)
 ├── msp-alpha (root — isolated)
 │   ├── client-1
 │   └── client-2
 ├── msp-beta (root — isolated)
 │   └── client-1
 └── msp-gamma (root)
     └── ...
```

MSPs cannot see each other's trees. Cfg inheritance never crosses root boundaries. Use the single-root model unless you are building a multi-MSP platform.

## Practical Examples

### Example 1: Security Policy Inheritance

#### MSP Level Configuration

```yaml
# MSP-wide security baseline applied to all tenants
resources:
  - name: firewall-ssh
    module: firewall
    config:
      protocol: tcp
      port: 22
      source: "10.0.0.0/8"
      action: allow

  - name: firewall-web
    module: firewall
    config:
      protocol: tcp
      ports: [80, 443]
      action: allow

  - name: script-signing
    module: script
    config:
      signing_policy: required
      timeout: "300s"

  - name: package-policy
    module: package
    config:
      policy: "security_updates_only"
      auto_update: true
```

#### Client Level Customization

```yaml
# ACME Corp overrides web ports; other resources inherited from MSP
resources:
  - name: firewall-web
    module: firewall
    config:
      protocol: tcp
      ports: [80, 443, 8080, 8443]  # Development ports added
      action: allow

  - name: backup-policy
    module: backup
    config:
      schedule: "0 1 * * *"     # 1 AM daily
      destination: "s3://acme-backups/"
```

#### Group Level Specialization

```yaml
# Development group relaxes script signing; package policy also relaxed
resources:
  - name: script-signing
    module: script
    config:
      signing_policy: optional     # Relaxed for development
      timeout: "300s"

  - name: package-policy
    module: package
    config:
      policy: "all_updates"        # Allow all packages in dev
```

#### Device Level Specifics

```yaml
# dev-server-01: adds a debug port firewall rule
resources:
  - name: firewall-debug
    module: firewall
    config:
      protocol: tcp
      port: 9229
      source: "192.168.1.100"      # Developer workstation only
      action: allow
```

### Example 2: Multi-Environment Setup

#### MSP: Base Monitoring

```yaml
resources:
  - name: monitoring-base
    module: monitoring
    config:
      interval: "60s"
      metrics: ["cpu", "memory", "disk"]
```

#### Client: Production Environment

```yaml
resources:
  - name: monitoring-base
    module: monitoring
    config:
      interval: "60s"
      metrics: ["cpu", "memory", "disk", "network", "services"]
      alerts:
        cpu_threshold: 80
        memory_threshold: 85

  - name: backup-policy
    module: backup
    config:
      schedule: "0 2 * * *"
      retention: "90d"
      encryption: true
```

#### Group: Database Servers

```yaml
resources:
  - name: monitoring-base
    module: monitoring
    config:
      interval: "60s"
      metrics: ["cpu", "memory", "disk", "network", "services", "database_performance"]

  - name: backup-policy
    module: backup
    config:
      schedule: "0 0,12 * * *"    # Twice daily
      retention: "180d"
      encryption: true
```

### Example 3: Effective Configuration Result

Given the configurations above, the effective configuration API response for `dev-server-01` would look like:

```json
{
  "steward_id": "dev-server-01",
  "tenant_id": "root/msp-a/acme-corp/development",
  "config": {
    "steward": { "id": "dev-server-01", "mode": "standalone" },
    "resources": [
      {
        "name": "firewall-ssh",
        "module": "firewall",
        "config": { "protocol": "tcp", "port": 22, "source": "10.0.0.0/8", "action": "allow" }
      },
      {
        "name": "firewall-web",
        "module": "firewall",
        "config": { "protocol": "tcp", "ports": [80, 443, 8080, 8443], "action": "allow" }
      },
      {
        "name": "script-signing",
        "module": "script",
        "config": { "signing_policy": "optional", "timeout": "300s" }
      },
      {
        "name": "package-policy",
        "module": "package",
        "config": { "policy": "all_updates" }
      },
      {
        "name": "firewall-debug",
        "module": "firewall",
        "config": { "protocol": "tcp", "port": 9229, "source": "192.168.1.100", "action": "allow" }
      }
    ]
  },
  "sources": {
    "resource.firewall-ssh":  { "level": 0, "source": "Level 0 (msp-policies)", "version": 1 },
    "resource.firewall-web":  { "level": 1, "source": "Level 1 (client-policies)", "version": 7 },
    "resource.script-signing":{ "level": 2, "source": "Level 2 (group-policies)", "version": 2 },
    "resource.package-policy":{ "level": 2, "source": "Level 2 (group-policies)", "version": 1 },
    "resource.firewall-debug":{ "level": 3, "source": "Device Configuration", "version": 1 }
  },
  "generated_at": "2026-05-19T09:00:00Z"
}
```

Note: `firewall-web` came from Client (overriding MSP), `script-signing` and `package-policy` came from Group (overriding both MSP and Client), and `firewall-debug` is device-specific (highest priority).

## Best Practices

### 1. Configuration Organization

#### Use Descriptive Resource Names

The `name` field is the merge key across inheritance levels. A resource in a child cfg with the same name as a parent resource **replaces the entire parent resource block**.

```yaml
# Good: descriptive names that communicate intent and scope
resources:
  - name: security-firewall-ssh
    module: firewall
    config:
      port: 22
      action: allow

  - name: compliance-password-policy
    module: security
    config:
      min_length: 12
      require_mfa: true
```

#### Group Related Settings into Named Resources

```yaml
# Good: related settings in one well-named resource
resources:
  - name: web-server-config
    module: web_server
    config:
      max_connections: 500
      timeout: 30
      ssl_protocols: ["TLSv1.2", "TLSv1.3"]
```

### 2. Inheritance Strategy

#### Start with Restrictive Defaults

```yaml
# MSP Level — secure by default
resources:
  - name: firewall-default
    module: firewall
    config:
      default_action: deny

  - name: script-policy
    module: script
    config:
      signing_policy: required

  - name: package-policy
    module: package
    config:
      auto_update: false
      policy: "security_only"
```

#### Allow Controlled Relaxation

```yaml
# Development Group — relaxed for development
resources:
  - name: script-policy
    module: script
    config:
      signing_policy: optional

  - name: package-policy
    module: package
    config:
      policy: "all_updates"
```

### 3. Version Control

#### Track Configuration Changes

Configuration files should be version-controlled. CFGMS stores every cfg write as a new version with a full audit trail automatically.

```bash
# Store configurations in version control
git add config/client/acme-corp/
git commit -m "feat: add development environment config for ACME Corp"
```

## API Usage

### Retrieve Effective Configuration

Get the fully resolved configuration for a steward, including source tracking:

```bash
curl -X GET /api/v1/stewards/{steward-id}/config/effective \
  -H "X-API-Key: your-api-key" \
  -H "Accept: application/json"
```

The response returns an `EffectiveConfiguration` object with:
- `config` — the merged `StewardConfig` (resources array)
- `sources` — map of `"resource.<name>"` → `InheritanceSource` (level, tenant_id, config_name, version, updated_at, source description)
- `generated_at` — timestamp of resolution

### Retrieve or Update Steward Configuration

```bash
# Get the raw (non-inherited) configuration stored for a steward
curl -X GET /api/v1/stewards/{steward-id}/config \
  -H "X-API-Key: your-api-key"

# Upload/update a steward's configuration (JSON or YAML)
curl -X PUT /api/v1/stewards/{steward-id}/config \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/yaml" \
  --data-binary @steward-config.yaml
```

### Validate Configuration

Validate configuration syntax and structure before uploading:

```bash
curl -X POST /api/v1/stewards/{steward-id}/config/validate \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d @new-config.json
```

Response:
```json
{
  "valid": true,
  "errors": [],
  "metadata": {
    "validation_timestamp": "2026-05-19T09:00:00Z",
    "total_issues": "0"
  }
}
```

## Troubleshooting

### Common Issues

#### 1. Configuration Not Inherited

**Problem**: Device not receiving expected configuration.

**Solution**:

1. Check the steward's effective configuration to see what it resolved to and where each resource came from:

   ```bash
   curl -X GET /api/v1/stewards/{id}/config/effective \
     -H "X-API-Key: your-api-key"
   ```

   Inspect the `sources` map — it shows which level each resource came from.

2. Verify the resource name matches exactly at each level. Inheritance merging is case-sensitive and exact:

   ```yaml
   # These are different resources:
   - name: firewall-rules      # Resource 1
   - name: firewall_rules      # Resource 2 (different name — no merge)
   ```

3. Validate configuration syntax at each level:

   ```bash
   curl -X POST /api/v1/stewards/{id}/config/validate \
     -H "X-API-Key: your-api-key" \
     -d @config.json
   ```

#### 2. Unexpected Configuration Override

**Problem**: Lower-level configuration not taking effect.

**Solution**:

1. Verify block `name` matches exactly — a different name means a separate resource (both inherited), not a replacement.

2. Check that the overriding cfg was actually stored at the correct tenant level by reading the effective config and checking `sources`.

3. Remember that the current resolver only handles 3 intermediate path levels (root=MSP, depth-1=client, depth-2=group). If your path is deeper, intermediate levels are skipped.

#### 3. Cfg Format Errors

**Problem**: Configuration upload rejected with parse errors.

**Solution**: Ensure the cfg uses the `resources` array format, not a flat `modules` namespace:

```yaml
# Correct format
resources:
  - name: my-rule
    module: firewall
    config:
      port: 443
      action: allow

# Incorrect — this is not the cfg format
modules:
  firewall:
    rules:
      my-rule:
        port: 443
```

## Advanced Topics

### Cfg Targeting Interaction

Configuration inheritance through the tenant hierarchy is one of several targeting mechanisms. The controller resolves which cfg a steward receives from:

- **Direct assignment** — cfg explicitly names a steward ID
- **Group membership** — cfg targets a named group; all stewards in that group receive it
- **Tag-based targeting** — stewards carry tags (`ring=canary`, `role=web`); cfgs target tag expressions
- **DNA-attribute matching** — target stewards whose DNA attributes match (e.g., `os=linux`)
- **Tenant hierarchy** — cfgs inherit through the tenant tree as described in this guide

The effective cfg for a steward is the result of **all applicable layers merged together**, with the above priority order determining which setting wins for each named resource.

### Cfg Signing

Every cfg distributed to a steward is signed with the controller's signing certificate. The steward verifies this signature before applying, ensuring cfgs cannot be tampered with in transit.

### Future: Advanced Inheritance Features

The following are **not yet implemented** and are listed for planning purposes only:

**Conditional inheritance** (planned):
```yaml
# NOT YET IMPLEMENTED
resources:
  - name: dev-ports
    module: firewall
    condition: "environment == 'development'"
    config:
      ports: [3000, 8080, 9000]
      action: allow
```

**Configuration templates** (planned): template-based inheritance for common resource patterns.

**Dynamic environment expressions** (planned): conditional expressions like `${env:production ? 'prod-db' : 'dev-db'}`. Current support is limited to direct variable expansion (`${VAR}` and `${VAR:-default}`).

## Migration Guide

### From Flat Configuration

1. **Identify Configuration Groups**

   ```yaml
   # Before: flat structure
   ssh_port: 22
   web_port: 80
   backup_schedule: "0 2 * * *"

   # After: resources array
   resources:
     - name: firewall-ssh
       module: firewall
       config:
         port: 22
         action: allow
     - name: firewall-web
       module: firewall
       config:
         port: 80
         action: allow
     - name: backup-policy
       module: backup
       config:
         schedule: "0 2 * * *"
   ```

2. **Establish Hierarchy**
   - Move common settings to root (MSP) level
   - Client-specific settings to client level
   - Device overrides to device level (store against the steward ID)

3. **Test Inheritance**

   ```bash
   # Verify effective configuration after uploading each level
   curl -X GET /api/v1/stewards/{id}/config/effective \
     -H "X-API-Key: your-api-key"
   ```

### Best Migration Practices

1. **Gradual Migration**: Migrate one module at a time
2. **Backup Original**: Keep original flat configurations until verified
3. **Validate Results**: Compare effective configurations at each step
4. **Check Sources**: Use the `sources` map in the effective cfg response to confirm each resource came from the expected level
