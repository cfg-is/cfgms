# Active Directory Module (System Context)

## Purpose and scope

The Active Directory module provides secure, credential-free integration with local Active Directory domains using Windows system context APIs. This module is designed to run on Windows stewards that are members of an Active Directory domain, leveraging the system service account for authentication and authorization.

## Overview

The Active Directory module provides secure, credential-free integration with local Active Directory domains using Windows system context APIs. This module is designed to run on Windows stewards that are members of an Active Directory domain, leveraging the system service account for authentication and authorization.

## Key Features

- **System Context Authentication**: Uses Windows system context (typically SYSTEM account) instead of stored credentials
- **PowerShell Integration**: Leverages the Windows Active Directory PowerShell module for robust AD operations
- **Directory DNA Collection**: Comprehensive AD domain statistics and metadata collection for drift detection
- **Multi-Object Support**: Supports users, groups, computers, and organizational units
- **Zero Credential Storage**: No credential storage or management required - relies on Windows authentication

## Architecture

### Execution Environment
- **Executor Type**: `steward` - Runs locally on Windows steward systems
- **Platform Support**: Windows only (requires Windows Active Directory PowerShell module)
- **Authentication**: Windows system context (service account permissions)

### System Requirements
- Windows Server 2012 R2+ or Windows 10/11
- Active Directory PowerShell module installed
- Steward running as service with system-level privileges
- Domain membership (steward must be domain-joined)

## Configuration options

### Minimal Configuration
The module requires minimal configuration due to system context authentication:

```yaml
operation_type: read
object_types:
  - user
  - group
  - computer
  - organizational_unit
enable_dna_collection: true
```

### Configuration Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `operation_type` | string | Yes | "read" | Type of operations (read/write) |
| `object_types` | array | Yes | - | AD object types to manage |
| `search_base` | string | No | Auto-detected | Search base DN (auto-discovers if not specified) |
| `page_size` | integer | No | 100 | Number of objects to retrieve per page |
| `request_timeout` | duration | No | 30s | Timeout for PowerShell operations |
| `enable_dna_collection` | boolean | No | true | Enable directory DNA collection |

## Supported Operations

### Read Operations
- `status` - Get system and domain status
- `query:type:id` - Query specific AD object by ID
- `list:type` - List AD objects by type
- `dna_collection` - Collect comprehensive directory DNA

### Supported Object Types
- `user` - AD user accounts (including computer accounts)
- `group` - AD groups (security and distribution)
- `computer` - AD computer objects
- `organizational_unit` / `ou` - Organizational units
- `gpo` / `group_policy` - Group Policy Objects (read-only)

## Usage examples

### Query Specific User
```bash
cfgcli steward get-config steward-id "query:user:Administrator"
```

### List All Groups
```bash
cfgcli steward get-config steward-id "list:group"
```

### Get System Status
```bash
cfgcli steward get-config steward-id "status"
```

### Collect Directory DNA
```bash
cfgcli steward get-config steward-id "dna_collection"
```

## Security considerations

### Zero-Credential Design
- **No Stored Credentials**: Module does not store or manage any AD credentials
- **System Context**: Leverages Windows service account security context
- **Automatic Authentication**: Uses Kerberos/NTLM through Windows subsystem
- **Minimal Attack Surface**: No credential exposure risk

### Required Permissions
The steward service account requires:
- **Log on as a service** - Standard service account permission
- **Act as part of operating system** - For system context access
- **Domain membership** - Computer must be domain-joined

### Audit and Compliance
- All operations are logged with security event correlation
- Sensitive operations (create/update/delete) are audited
- No credential information is logged or stored

## Directory DNA Integration

The module integrates with the DirectoryDNA framework to provide:

### Collected Metrics
- **Domain Statistics**: Total users, groups, computers, OUs
- **Domain Controller Information**: DC names, roles, health status
- **Group Policy Data**: GPO count, names, versions
- **Forest Information**: Forest mode, schema master, naming contexts
- **Security Metrics**: Enabled/disabled accounts, group types

### DNA Data Structure
```json
{
  "collection_time": "2023-01-01T12:00:00Z",
  "success": true,
  "source": "activedirectory_system",
  "dna": {
    "domain_info": {
      "domain_name": "example.com",
      "forest_name": "example.com",
      "domain_mode": "WinThreshold",
      "forest_mode": "WinThreshold"
    },
    "statistics": {
      "total_users": 150,
      "enabled_users": 145,
      "disabled_users": 5,
      "total_groups": 75,
      "security_groups": 65,
      "distribution_groups": 10
    }
  }
}
```

## Error Handling

### Common Error Scenarios
- **Module Not Available**: Active Directory PowerShell module not installed
- **Domain Access**: System cannot access domain controller
- **Permission Denied**: Insufficient system permissions
- **PowerShell Execution**: PowerShell script execution failures

### Error Response Format
```json
{
  "success": false,
  "error": "PowerShell execution failed: Access denied",
  "response_time": "1.5s"
}
```

## Performance Considerations

### Optimization Features
- **Configurable Page Size**: Control memory usage for large result sets
- **Request Timeouts**: Prevent hung operations
- **Efficient Queries**: Uses PowerShell filters for server-side filtering
- **Minimal Data Transfer**: Returns only requested fields

### Monitoring Metrics
- `ad_local_requests_total` - Total requests processed
- `ad_local_request_duration_seconds` - Request processing time
- `ad_local_errors_total` - Total errors encountered
- `ad_dna_collection_status` - DNA collection health status

## Comparison with Network AD Module

| Feature | System Context Module | Network AD Module |
|---------|----------------------|-------------------|
| **Executor** | Steward (local) | Outpost (network) |
| **Authentication** | System context | LDAP credentials |
| **Credential Storage** | None | Encrypted storage |
| **Performance** | High (local APIs) | Medium (network LDAP) |
| **Security** | Windows integrated | mTLS + credentials |
| **Use Case** | Domain controllers | Remote management |

## Development and Testing

### Unit Tests
The module includes comprehensive unit tests for:
- Configuration validation
- Object conversion methods
- Error handling scenarios
- Statistics tracking
- YAML serialization

### Integration Tests
Integration tests are provided but require a Windows AD environment:
- System access verification
- Real AD object queries
- Directory DNA collection
- Performance benchmarks

Run tests with:
```bash
go test -v ./features/modules/activedirectory
```

## Troubleshooting

### Common Issues

**"PowerShell execution failed"**
- Verify PowerShell execution policy allows script execution
- Check if Active Directory module is installed: `Get-Module -ListAvailable ActiveDirectory`

**"System AD access verification failed"**
- Verify computer is domain-joined: `Test-ComputerSecureChannel`
- Check steward service account permissions
- Verify domain controller connectivity

**"Module not configured"**
- Ensure module configuration is applied before use
- Verify all required fields are provided in configuration

### Debug Logging
Enable debug logging to troubleshoot issues:
```yaml
logging:
  level: debug
  components:
    - activedirectory
```

## Known limitations

### Platform Restrictions
- **Windows Only**: Requires Windows platform with Active Directory PowerShell module
- **Domain Membership Required**: Steward must be domain-joined for system context access
- **Service Account Privileges**: Requires elevated service account permissions

### Functional Limitations
- **Read-Heavy Operations**: Optimized for read operations; write operations may have higher latency
- **PowerShell Dependency**: Requires PowerShell and AD module availability
- **Local Domain Only**: Cannot query remote domains without trust relationships
- **No Schema Extensions**: Does not support custom AD schema extensions in current version

### Performance Considerations
- **PowerShell Overhead**: PowerShell execution adds processing overhead compared to native LDAP
- **Large Result Sets**: Memory usage scales with query result size
- **Concurrent Limits**: Limited by PowerShell's concurrent execution capabilities

## Version History

- **v1.0.0** - Initial system-context implementation with PowerShell integration
- **v1.0.0** - DirectoryDNA integration and comprehensive testing
- **v1.0.0** - Support for users, groups, computers, and organizational units

## Related Modules

- **network_activedirectory** - Network-based AD provider for outpost components
- **directory** - Generic directory operations and provider abstraction
- **entra_user** - Azure AD/Entra ID user management
- **conditional_access** - Azure AD conditional access policies