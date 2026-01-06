# Configuration Template Engine Design

## Overview

This document outlines the design for the CFGMS configuration template engine. The template system enables MSPs to create reusable, dynamic configurations that adapt to different clients and environments while leveraging DNA properties for real-time system state.

## Goals

1. **Reusability**: Create once, deploy to many with client-specific customizations
2. **DNA Integration**: Use real-time system properties as template variables
3. **Inheritance**: Build on existing config inheritance for layered templates
4. **Compliance**: Enable best-practice templates for CIS, HIPAA, PCI-DSS, etc.
5. **Safety**: Validate templates before deployment to prevent errors

## Architecture

### Core Components

```
┌─────────────────────┐
│  Template Engine    │
├─────────────────────┤
│ • Parser            │ ← Parses template syntax
│ • Executor          │ ← Safely executes templates
│ • Function Registry │ ← Built-in & custom functions
│ • Validator         │ ← Pre-deployment validation
└─────────────────────┘
         │
         ├── DNA Integration
         ├── Config Inheritance  
         ├── Git Backend
         └── External Data Sources
```

### Data Flow

1. **Template Definition** → Stored in Git (MSP global or client repo)
2. **Value Resolution** → Merge inheritance + DNA + external data
3. **Template Execution** → Render with security sandbox
4. **Validation** → Check output before deployment
5. **Deployment** → Send to Steward as normal configuration

## Template Syntax

### Variable Declaration and Usage

Configuration files can declare variables at the top, which can then be used throughout:

```yaml
# Variables declared at top of config file
variables:
  client_name: "acme-corp"
  environment: "production"
  ssh_port: 2222
  enable_firewall: true

# Then use $variable syntax anywhere in the config
hostname: "$client_name-$environment-server"

# DNA properties also use $syntax
network:
  interface: "$DNA.Network.PrimaryInterface"
  current_ip: "$DNA.Network.IPv4Address"
  
# Can mix declared and DNA variables
ssh:
  port: $ssh_port
  bind_interface: "$DNA.Network.PrimaryInterface"

# Conditionals work with $ syntax
$if $enable_firewall
firewall:
  enabled: true
  default_interface: "$DNA.Network.PrimaryInterface"
$endif
```

### Advanced Syntax

```yaml
variables:
  authorized_users:
    - name: "admin"
      role: "administrator"
    - name: "backup"
      role: "operator"

# Loops with declared variables
users:
$for user in $authorized_users
  - name: "$user.name"
    role: "$user.role"
    home: "/home/$user.name"
$endfor

# DNA-based conditionals
$if "$DNA.System.OS" == "windows"
windows_config:
  defender: enabled
$elif "$DNA.System.OS" == "linux"  
linux_config:
  selinux: enforcing
$endif
```

### Built-in Functions

```yaml
variables:
  client_name: "ACME Corp"
  custom_port: null  # Will use default

# String manipulation
hostname: "$string.lower($client_name | $string.replace(' ', '-'))"

# Default values (if custom_port is null/undefined, use 8080)
port: "$default($custom_port, 8080)"

# Math operations  
memory_limit: "$math.mul($DNA.Memory.TotalMB, 0.8)MB"

# Date/time
backup_time: "$time.now() | $time.format('15:04:05')"

# Environment lookup
api_key: "$env('API_KEY') | $required('API_KEY must be set')"

# DNA queries with filters
primary_disk: "$DNA.Storage.Disks | $filter(.Primary == true) | $first"

# Include other templates
$include "templates/common-security.yaml"

# Template inheritance
$extend "templates/base-firewall.yaml"
```

### Variable Resolution Order

When resolving `$variable`, the template engine checks in this order:

1. **Local variables** (declared in current config file)
2. **Inherited variables** (from parent configs via inheritance)
3. **DNA properties** (real-time system state)

```yaml
# Example showing precedence
variables:
  hostname: "override-name"  # Local variable takes precedence

system:
  # This uses local variable, not DNA.System.Hostname
  name: "$hostname"
  
  # This explicitly uses DNA
  actual_hostname: "$DNA.System.Hostname"
  
  # This falls back to DNA if no local variable
  display_name: "$display_name || $DNA.System.Hostname"
```

### DNA Integration

DNA properties are automatically available using `$DNA.` prefix:

```yaml
# System properties
system:
  hostname: "$DNA.System.Hostname"
  os: "$DNA.System.OS"
  arch: "$DNA.System.Architecture"

# Conditional based on DNA
$if "$DNA.System.OS" == "windows"
windows_specific:
  defender: enabled
$elif "$DNA.System.OS" == "linux"
linux_specific:
  selinux: enforcing
$endif

# Dynamic resource allocation
resources:
  # Allocate 80% of available memory
  memory: "$math.mul($DNA.Memory.AvailableMB, 0.8)MB"
  
  # Use all but one CPU core
  cpu_cores: "$math.max($math.sub($DNA.CPU.Cores, 1), 1)"
```

## Template Inheritance Model

### Hierarchy

```
MSP Global Templates
    ↓
Client Templates  
    ↓
Group Templates
    ↓
Device-Specific Values
```

### Example Flow

1. **MSP Global Template** (`msp-global/templates/secure-server.yaml`):

```yaml
# Base security template all clients inherit
$extend "templates/base.yaml"

security:
  ssh:
    port: "$default($ssh_port, 22)"
    permit_root: false
    password_auth: false
  
  firewall:
    default_action: drop
    rules:
      $include "templates/firewall-rules.yaml"
      
  updates:
    auto_apply: "$default($auto_update, true)"
    schedule: "$default($update_schedule, 'Sun 02:00')"
```

1. **Client Template** (`client-123/templates/server.yaml`):

```yaml
$extend "msp-global/templates/secure-server.yaml"

variables:
  client_office_ip: "203.0.113.0/24"
  requires_pci: true

# Override firewall rules with client-specific rules
firewall:
  rules:
    - allow_from: "$client_office_ip"
      to_port: 443
      
    # Include compliance rules if needed
    $if $requires_pci
    $include "templates/pci-firewall-rules.yaml"
    $endif
```

1. **Device Values** (`client-123/devices/web-server-01/config.yaml`):

```yaml
$extend "client-123/templates/server.yaml"

variables:
  ssh_port: 2222
  auto_update: false  # This server needs manual updates
```

## Compliance Templates

Pre-built templates for common compliance requirements:

### CIS Hardening Template

```yaml
# templates/compliance/cis-hardening.yaml
$if $enable_cis_hardening
# CIS Benchmark - Level $default($cis_level, 1)
security:
  password_policy:
    min_length: "$if $cis_level == 2 then 14 else 8"
    complexity: true
    history: 5
    
  audit:
    enabled: true
    events:
      - authentication
      - authorization  
      - configuration_changes
      
  kernel:
    $if "$DNA.System.OS" == "linux"
    sysctl:
      "net.ipv4.ip_forward": 0
      "net.ipv4.conf.all.send_redirects": 0
      "kernel.randomize_va_space": 2
    $endif
$endif
```

### HIPAA Compliance Template

```yaml
# templates/compliance/hipaa.yaml
$if $requires_hipaa
healthcare:
  encryption:
    at_rest: 
      algorithm: "AES-256"
      key_rotation: "90d"
    in_transit:
      min_tls: "1.2"
      
  access_control:
    mfa_required: true
    session_timeout: "$default($hipaa_session_timeout, 15)m"
    
  audit:
    retention: "$default($hipaa_audit_retention, 2555)d"
    tamper_protection: true
$endif
```

## Security Considerations

### Template Sandbox

- No file system access beyond designated paths
- No network calls during template execution
- No shell command execution
- Limited CPU/memory for template rendering
- Timeout protection against infinite loops

### Validation Requirements

1. **Syntax Validation**: Template must parse correctly
2. **Schema Validation**: Output must match expected schema
3. **Security Validation**: No sensitive data exposure
4. **DNA Validation**: Referenced DNA properties must exist
5. **Dependency Validation**: Required templates must be available

### Safe Functions Only

```go
// Allowed functions
- String manipulation (lower, upper, trim, replace)
- Math operations (add, sub, mul, div, mod)
- Logic operations (eq, ne, lt, gt, and, or)
- Date formatting (now, date, dateModify)
- Type conversion (int, float, string, bool)
- Data selection (first, last, index, where)

// Blocked functions  
- File operations (readFile, writeFile)
- Network operations (httpGet, tcpDial)
- Process execution (exec, shell)
- Unsafe reflection (reflect, unsafe)
```

## Implementation Phases

### Phase 1: Core Template Engine

- Basic template parser using Go text/template
- Variable substitution with dot notation
- Simple conditionals and loops
- Integration with config inheritance

### Phase 2: DNA Integration  

- DNA property access in templates
- Real-time DNA value resolution
- DNA-based conditionals
- Caching for performance

### Phase 3: Advanced Features

- Template inheritance and blocks
- Built-in function library
- External data sources
- Template composition

### Phase 4: Compliance & Security

- Pre-built compliance templates
- Security sandbox implementation
- Comprehensive validation
- Performance optimization

## Testing Strategy

### Template Test Framework

```yaml
# test-cases/firewall-template-test.yaml
template: "templates/secure-firewall.yaml"
test_cases:
  - name: "Basic firewall with defaults"
    values:
      ClientName: "test-client"
    expect:
      firewall.enabled: true
      firewall.rules[0].action: "deny"
      
  - name: "PCI compliance mode"
    values:
      ClientName: "test-client"  
      RequiresPCI: true
    expect:
      firewall.rules: 
        count: 15  # PCI adds 14 rules
        contains:
          - action: "deny"
            source: "0.0.0.0/0"
            destination: "any"
            port: 23  # Telnet must be blocked
```

### Validation Tests

- Malformed template syntax
- Missing required variables
- Invalid DNA references
- Security constraint violations
- Performance benchmarks

## Integration Points

### With Git Backend (Story #74)

- Templates stored in Git repositories
- Version control for template evolution
- Template discovery and loading
- Cross-repository template references

### With Rollback (Story #75)

- Template changes can be rolled back
- Template rendering history tracked
- Safe testing of template modifications

### With Config Service

- Templates rendered during config generation
- Merged with inherited configurations
- Validated before deployment

## Success Metrics

1. **Developer Productivity**: 80% reduction in configuration duplication
2. **Compliance**: 100% of compliance requirements codified in templates  
3. **Performance**: < 100ms template rendering time
4. **Reliability**: 99.9% successful template deployments
5. **Adoption**: 50%+ of configs using templates within 6 months
