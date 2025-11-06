# Active Directory Module

The Active Directory module enables CFGMS stewards to read and manage Microsoft Active Directory objects via LDAP protocol. This module runs on stewards deployed to Windows domain controllers or servers with AD access.

## Purpose and scope

**Purpose**: The Active Directory module provides CFGMS with comprehensive Microsoft Active Directory integration capabilities, enabling configuration management systems to read, query, and manage AD objects through a secure, standardized interface.

**Scope**: This module covers:
- User account management and queries
- Group membership and security group management  
- Organizational Unit (OU) structure navigation
- Computer object tracking and management
- Group Policy Object (GPO) reading and analysis
- Domain trust relationship validation
- Multi-domain and multi-forest operations
- Cross-domain authentication and queries
- Real-time status monitoring and health checks

**Target Environments**: Designed for enterprise Active Directory deployments including multi-domain forests, MSP environments with multiple client domains, and complex trust relationships.

## Overview

This module provides:
- **LDAP Integration**: Direct connection to Active Directory via LDAP/LDAPS
- **Domain Controller Discovery**: Automatic DC discovery via DNS SRV records
- **Object Management**: Read operations for users, groups, OUs, computers, GPOs, and trusts
- **Multi-Domain Support**: Cross-domain queries and forest-wide searches
- **Authentication**: Support for simple bind, Kerberos, and NTLM
- **Windows Integration**: Optimized for Windows domain environments
- **AD-Specific Operations**: Computer objects, Group Policy Objects, domain trusts

## Architecture

The AD module follows CFGMS's security-first design:
- **Steward Deployment**: Runs on Windows servers with AD access
- **Local Access**: Uses LDAP to access local/nearby domain controllers
- **MQTT+QUIC Communication**: Controller accesses AD via secure steward communication
- **Zero Trust**: All communication uses mTLS authentication

## Configuration options

### Basic Configuration

```yaml
# Steward configuration (cfgms.yaml)
modules:
  activedirectory:
    enabled: true
    config:
      domain: "corp.example.com"
      auth_method: "simple"
      operation_type: "read"
      object_types: ["user", "group", "organizational_unit"]
      username: "CORP\\svc-cfgms"
      password: "${AD_SERVICE_PASSWORD}"
```

### Advanced Configuration

```yaml
modules:
  activedirectory:
    enabled: true
    config:
      # Connection settings
      domain: "corp.example.com"
      domain_controller: "dc01.corp.example.com"  # Optional: specific DC
      port: 636                                   # LDAPS port
      use_tls: true
      
      # Authentication
      auth_method: "kerberos"
      username: "svc-cfgms@corp.example.com"
      password: "${AD_SERVICE_PASSWORD}"
      
      # Search settings
      search_base: "DC=corp,DC=example,DC=com"
      page_size: 200
      
      # Performance settings
      max_connections: 10
      request_timeout: "45s"
      
      # Security settings
      operation_type: "read"  # "read" or "read_write"
      object_types: 
        - "user"
        - "group"
        - "organizational_unit"
        - "computer"
```

### Multi-Domain Configuration

```yaml
modules:
  activedirectory:
    enabled: true
    config:
      # Primary domain settings
      domain: "corp.contoso.com"
      auth_method: "kerberos"
      use_tls: true
      port: 636
      
      # Multi-domain and forest settings
      trusted_domains:
        - "dev.contoso.com"
        - "test.contoso.com"
        - "external.partner.com"
      forest_root: "contoso.com"
      global_catalog_dc: "gc1.contoso.com"
      cross_domain_auth: true
      
      # Enhanced object support
      operation_type: "read"
      object_types:
        - "user"
        - "group"
        - "organizational_unit"
        - "computer"
        - "gpo"
        - "group_policy"
        - "domain_trust"
        - "trust"
      
      # Performance optimization
      page_size: 1000
      max_connections: 20
      request_timeout: "60s"
```

## Resource Types

### Connection Status (`status`)

Query the connection status and health:

```bash
# Via controller API
curl -X GET https://controller/api/v1/stewards/{steward-id}/modules/activedirectory/status

# Returns ADConnectionStatus
{
  "connected": true,
  "domain_controller": "dc01.corp.example.com",
  "domain": "corp.example.com",
  "auth_method": "simple",
  "connected_since": "2025-01-15T10:30:00Z",
  "last_health_check": "2025-01-15T14:25:30Z",
  "health_status": "healthy",
  "response_time": "50ms",
  "error_count": 0,
  "request_count": 1247
}
```

### User Queries (`query:user:{identifier}`)

Query specific users by various identifiers:

```bash
# Query by sAMAccountName
GET /modules/activedirectory/query:user:john.doe

# Query by UPN
GET /modules/activedirectory/query:user:john.doe@corp.example.com

# Query by DN
GET /modules/activedirectory/query:user:CN=John Doe,OU=Users,DC=corp,DC=example,DC=com
```

### Group Queries (`query:group:{identifier}`)

Query specific groups:

```bash
# Query by sAMAccountName
GET /modules/activedirectory/query:group:Domain Admins

# Query by DN
GET /modules/activedirectory/query:group:CN=Domain Admins,CN=Users,DC=corp,DC=example,DC=com
```

### Organizational Unit Queries (`query:ou:{identifier}`)

Query specific OUs:

```bash
# Query by name
GET /modules/activedirectory/query:ou:Users

# Query by DN
GET /modules/activedirectory/query:ou:OU=Users,DC=corp,DC=example,DC=com
```

### List Operations

List objects by type:

```bash
# List all users
GET /modules/activedirectory/list:user

# List all groups
GET /modules/activedirectory/list:group

# List all OUs
GET /modules/activedirectory/list:ou

# List computers
GET /modules/activedirectory/list:computer

# List Group Policy Objects
GET /modules/activedirectory/list:gpo

# List domain trusts
GET /modules/activedirectory/list:trust
```

### Multi-Domain Operations

Query objects across trusted domains:

```bash
# Cross-domain user query
GET /modules/activedirectory/query:user:john.doe:dev.contoso.com

# Cross-domain group query  
GET /modules/activedirectory/query:group:admins:external.partner.com

# Forest-wide user search
GET /modules/activedirectory/forest:user:jane.smith

# Forest-wide group search
GET /modules/activedirectory/forest:group:managers

# Validate domain trust
GET /modules/activedirectory/validate_trust:dev.contoso.com
```

### AD-Specific Object Queries

Query Active Directory specific objects:

```bash
# Computer object query
GET /modules/activedirectory/query:computer:WORKSTATION-01

# Group Policy Object query
GET /modules/activedirectory/query:gpo:Default Domain Policy

# Domain trust query
GET /modules/activedirectory/query:trust:external.partner.com
```

## Authentication Methods

### Simple Bind (`simple`)
- Basic username/password authentication
- Supports both UPN and DN formats
- Recommended for service accounts

### Kerberos (`kerberos`)
- Uses Kerberos tickets for authentication
- Requires properly configured service account
- Best security for domain environments

### NTLM (`ntlm`)
- Windows NTLM authentication (planned)
- Fallback for environments without Kerberos

## Deployment

### Prerequisites

**Windows Deployment (Recommended):**
- Windows Server 2019+ or Windows 10+
- Domain-joined machine
- Network access to domain controllers
- Service account with "Log on as a service" right

**Linux Deployment (Limited):**
- Network access to domain controllers
- LDAP-only functionality (no Windows APIs)
- Service account credentials

### Service Account Setup

1. Create dedicated service account:
```powershell
New-ADUser -Name "svc-cfgms" -UserPrincipalName "svc-cfgms@corp.example.com" -AccountPassword (ConvertTo-SecureString "ComplexPassword123!" -AsPlainText -Force) -Enabled $true
```

2. Grant required permissions:
```powershell
# Grant "Log on as a service"
Grant-CServicePermission -Identity "CORP\svc-cfgms" -Privilege SeServiceLogonRight

# Grant read permissions to AD (usually inherited from Domain Users)
```

## Usage examples

### Basic User Management

```go
// Query a specific user
result, err := module.Get(ctx, "query:user:john.doe")
if err != nil {
    log.Printf("Failed to get user: %v", err)
    return
}

userResult := result.(*ADQueryResult)
if userResult.Success && userResult.User != nil {
    fmt.Printf("User: %s (%s)\n", userResult.User.DisplayName, userResult.User.EmailAddress)
}
```

### Multi-Domain Operations

```go
// Cross-domain user lookup
result, err := module.Get(ctx, "query:user:jane.doe:dev.contoso.com")

// Forest-wide user search
result, err := module.Get(ctx, "forest:user:admin.user")

// Validate domain trust
result, err := module.Get(ctx, "validate_trust:external.partner.com")
```

### Enterprise Scenarios

```go
// List all computers in domain
computers, err := module.Get(ctx, "list:computer")

// Get Group Policy Objects
gpos, err := module.Get(ctx, "list:gpo")

// Check domain trusts
trusts, err := module.Get(ctx, "list:trust")
```

## Known limitations

- **Write Operations**: Currently read-only mode; write operations planned for future release
- **Real-time Monitoring**: DirSync change notifications not yet implemented
- **Linux Limitations**: Full functionality requires Windows deployment; Linux provides LDAP-only access
- **Forest Topology**: Complex forest topologies may require additional trust configuration
- **Performance**: Large forests with 100k+ objects may require performance tuning
- **Exchange Objects**: Mailbox and Exchange-specific attributes not currently supported
- **ADFS Integration**: Active Directory Federation Services not directly supported

## Security considerations

### Authentication Security
- **Credential Protection**: Store passwords in secure configuration or environment variables
- **Least Privilege**: Use read-only service accounts when possible
- **Multi-Factor Authentication**: Service accounts should use strong authentication methods
- **Account Rotation**: Implement regular service account password rotation

### Network Security
- **Encrypted Communication**: Use LDAPS (port 636) for encrypted communication
- **Certificate Validation**: Validate domain controller certificates in production
- **Network Segmentation**: Isolate AD traffic using network security controls
- **Connection Limits**: Configure appropriate connection pool sizes to prevent DoS

### Access Control
- **Service Account Permissions**: Grant minimal required AD permissions
- **Audit Logging**: All AD operations are logged for security auditing  
- **Cross-Domain Controls**: Validate trust relationships before cross-domain access
- **Tenant Isolation**: Ensure proper tenant separation in MSP deployments

### Data Protection
- **Sensitive Data Handling**: PII and sensitive AD attributes are handled securely
- **Log Sanitization**: Passwords and sensitive data are redacted from logs
- **Transport Encryption**: All data in transit is encrypted via TLS/mTLS
- **Storage Security**: Configuration data is stored using CFGMS secure storage providers

## Integration with Directory DNA

The AD module integrates with CFGMS DirectoryDNA system:

```yaml
# Enable DNA collection for AD objects
features:
  directory_dna:
    enabled: true
    providers:
      - activedirectory
    collection_schedule: "0 */6 * * *"  # Every 6 hours
```

This enables:
- **Drift Detection**: Monitor changes to AD objects
- **Relationship Mapping**: Track group memberships and OU hierarchy
- **Change History**: Historical tracking of AD modifications
- **Compliance Monitoring**: Detect unauthorized AD changes

## Monitoring and Health Checks

The module provides comprehensive monitoring:

### Health Checks
- **AD Connectivity**: Test LDAP connection to domain controller
- **Authentication**: Verify service account credentials
- **Response Time**: Monitor query performance
- **Error Rates**: Track failed operations

### Metrics
- `ad_requests_total`: Total AD requests processed
- `ad_request_duration_seconds`: Request latency distribution
- `ad_errors_total`: Total errors by type
- `ad_connection_status`: Connection health status

### Logging

All operations are logged with structured fields:
```json
{
  "level": "info",
  "timestamp": "2025-01-15T14:25:30Z",
  "module": "activedirectory",
  "operation": "query_user",
  "object_id": "john.doe",
  "success": true,
  "response_time": "75ms",
  "steward_id": "steward-dc01"
}
```

## Troubleshooting

### Common Issues

**Connection Failed:**
- Verify domain controller accessibility
- Check firewall rules (ports 389/636)
- Validate service account credentials
- Ensure proper DNS resolution

**Authentication Failed:**
- Verify service account is not disabled/locked
- Check password expiration
- Validate domain trust relationships
- Ensure proper time synchronization

**Slow Performance:**
- Increase connection pool size
- Reduce page size for large queries
- Check network latency to domain controller
- Monitor domain controller performance

**Permission Denied:**
- Verify service account has read permissions
- Check for account restrictions or group policies
- Validate OU access permissions

### Debug Mode

Enable detailed logging:
```yaml
logging:
  level: debug
  modules:
    activedirectory: debug
```

This provides verbose LDAP operation logging for troubleshooting.

## Future Enhancements

- **Write Operations**: User/group creation and modification
- **Real-time Monitoring**: DirSync for change notifications
- **Multi-Forest Support**: Cross-forest trust relationships
- **Computer Management**: Full computer object lifecycle
- **Group Policy Integration**: Read GP assignments and settings
- **Exchange Integration**: Mailbox and distribution list management