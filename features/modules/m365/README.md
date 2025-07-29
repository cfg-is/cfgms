# M365 Virtual Steward Modules

This package implements "Virtual Steward" functionality for Microsoft 365 management using the existing CFGMS module pattern. Instead of managing physical endpoints, these modules manage M365 SaaS resources using the same .cfg file format and workflow engine.

## Architecture Overview

The Virtual Steward approach enables administrators to manage M365 resources identically to physical endpoints:

```yaml
# Physical endpoint example
- id: "/opt/myapp"
  type: "directory"
  config:
    path: "/opt/myapp"
    permissions: 755
    owner: "root"

# M365 SaaS resource example  
- id: "tenant-id:john.doe@company.com"
  type: "entra_user"
  config:
    user_principal_name: "john.doe@company.com"
    display_name: "John Doe"
    account_enabled: true
```

## Key Benefits

1. **Consistent Management Experience**: Same .cfg syntax for both physical and SaaS resources
2. **Cascading Configuration**: MSP → Client → Site → Resource hierarchy works identically 
3. **Workflow Integration**: Existing workflow engine processes both physical and SaaS operations
4. **Drift Detection**: DNA tracking applies to SaaS configurations
5. **Multi-Tenant Support**: Single steward can manage 2-20,000 M365 tenants

## Available Modules

### 1. Entra User Module (`entra_user`)

Manages Entra ID (Azure AD) users including:
- User creation and updates
- License assignments
- Group memberships  
- Profile attributes

**Example Configuration:**
```yaml
- id: "tenant-id:user@domain.com"
  type: "entra_user"
  config:
    user_principal_name: "user@domain.com"
    display_name: "John Doe"
    job_title: "Sales Manager"
    licenses:
      - sku_id: "c7df2760-2c81-4ef7-b578-5b5392b571df"  # Office 365 E5
    groups:
      - "Sales Team"
    managed_fields:
      - "display_name"
      - "job_title"
      - "licenses"
```

### 2. Conditional Access Module (`conditional_access`)

Manages Conditional Access policies for Zero Trust security:
- User and application targeting
- Location-based restrictions
- Device compliance requirements
- Session controls

**Example Configuration:**
```yaml
- id: "tenant-id:mfa-policy"
  type: "conditional_access"
  config:
    display_name: "Require MFA for All Users"
    state: "enabled"
    conditions:
      users:
        include_users: ["All"]
      applications:
        include_applications: ["All"]
    grant_controls:
      operator: "OR"
      built_in_controls: ["mfa"]
```

### 3. Intune Policy Module (`intune_policy`)

Manages Intune device configuration policies:
- Security baselines
- Compliance policies
- Application management
- Device restrictions

**Example Configuration:**
```yaml
- id: "tenant-id:security-baseline"
  type: "intune_policy"
  config:
    display_name: "Windows 10 Security Baseline"
    device_configuration_type: "microsoft.graph.windows10GeneralConfiguration"
    settings:
      passwordRequired: true
      passwordMinimumLength: 12
      defenderRequireRealTimeMonitoring: true
    assignments:
      - target:
          target_type: "groupAssignmentTarget"
          include_groups: ["Corporate Devices"]
```

## Authentication

The modules support OAuth2 authentication with secure local credential storage:

### Client Credentials Flow (Recommended for Production)
```yaml
steward:
  authentication:
    type: "oauth2_client_credentials"
    client_id: "${M365_CLIENT_ID}"
    client_secret: "${M365_CLIENT_SECRET}"
    tenant_id: "your-tenant-id"
    scopes:
      - "https://graph.microsoft.com/.default"
```

### Required Microsoft Graph Permissions

The Azure AD application needs these permissions:

**User Management:**
- `User.ReadWrite.All`
- `Group.ReadWrite.All`
- `Directory.ReadWrite.All`

**Conditional Access:**
- `Policy.ReadWrite.ConditionalAccess`
- `Application.Read.All`

**Intune Management:**
- `DeviceManagementConfiguration.ReadWrite.All`
- `DeviceManagementApps.ReadWrite.All`

## Multi-Tenant Configuration

The Virtual Steward supports multi-tenant scenarios with cascading configuration:

### MSP Configuration Example
```yaml
# MSP baseline applies to all client tenants
- id: "*:baseline-mfa-policy"  # * applies to all tenants
  type: "conditional_access"
  config:
    display_name: "MSP Baseline - Require MFA"
    # ... policy configuration
    cascade: true  # Inherits to all client tenants

# Client-specific configuration
- tenant_id: "client-tenant-id"
  resources:
    - id: "client-tenant-id:client-specific-policy"
      type: "conditional_access"
      config:
        # Client-specific overrides
```

### Configuration Inheritance

The system supports intelligent configuration merging:

1. **MSP Level (Level 0)**: Baseline security policies
2. **Client Level (Level 1)**: Client-specific requirements  
3. **Site Level (Level 2)**: Location-based policies
4. **Resource Level (Level 3)**: Individual resource settings

## Workflow Integration

M365 modules integrate with the existing workflow engine:

```yaml
workflow:
  name: "m365-user-provisioning"
  steps:
    - name: "create-user"
      type: "task"
      module: "entra_user"
      config:
        user_principal_name: "{{workflow.user_email}}"
        display_name: "{{workflow.user_name}}"
    
    - name: "assign-to-groups"
      type: "task"
      module: "entra_user"  
      config:
        user_principal_name: "{{workflow.user_email}}"
        groups: ["{{workflow.department}} Team"]
        managed_fields: ["groups"]
```

## Error Handling and Retry Logic

The modules include comprehensive error handling:

- **Rate Limiting**: Adaptive rate limiting for Graph API
- **Retry Logic**: Exponential backoff for transient failures
- **Error Classification**: Distinguishes between retryable and permanent errors
- **Circuit Breaker**: Prevents cascade failures across tenants

## Security Features

### Secure Credential Storage
- AES-256 encryption for stored tokens
- Secure file permissions (0600)
- Automatic token refresh
- Credential backup/restore capabilities

### Zero Trust Architecture  
- OAuth2 with PKCE support
- Token-based authentication (no passwords stored)
- Principle of least privilege
- Audit logging for all operations

## Getting Started

1. **Register Azure AD Application**
   ```bash
   # Create app registration with required permissions
   az ad app create --display-name "CFGMS-Virtual-Steward"
   ```

2. **Configure Authentication**
   ```bash
   # Set environment variables
   export M365_CLIENT_ID="your-client-id"
   export M365_CLIENT_SECRET="your-client-secret"
   ```

3. **Create Configuration File**
   ```yaml
   # Save as hostname.cfg (e.g., m365-tenant.cfg)
   steward:
     id: "m365-virtual-steward"
     tenant_id: "your-tenant-id"
   
   resources:
     - id: "your-tenant-id:test-user@domain.com"
       type: "entra_user"
       config:
         user_principal_name: "test-user@domain.com"
         display_name: "Test User"
         account_enabled: true
   ```

4. **Run Virtual Steward**
   ```bash
   # Execute configuration
   cfgms-steward --config m365-tenant.cfg
   ```

## Example Configurations

See the `examples/m365/` directory for complete configuration examples:

- `client-tenant.cfg`: Single tenant M365 management
- `multi-tenant-msp.cfg`: MSP managing multiple client tenants

## Advanced Features

### DNA Tracking for SaaS
The system tracks configuration drift for M365 resources:
```json
{
  "resource_id": "tenant-id:user@domain.com",
  "resource_type": "entra_user", 
  "current_state": {
    "display_name": "John Doe",
    "job_title": "Sales Manager"
  },
  "desired_state": {
    "display_name": "John Smith", 
    "job_title": "Sales Director"
  },
  "drift_detected": true
}
```

### BEC Response Workflows
Automate Business Email Compromise response:
```yaml
workflow:
  name: "bec-response"
  steps:
    - name: "disable-compromised-user"
      type: "task"
      module: "entra_user"
      config:
        account_enabled: false
    
    - name: "revoke-sessions"
      type: "api"
      provider: "microsoft"
      operation: "revokeSignInSessions"
    
    - name: "block-sender-ip"  
      type: "task"
      module: "conditional_access"
      config:
        # Create blocking policy
```

## Performance and Scale

The Virtual Steward is designed for enterprise scale:

- **Multi-Tenant**: Supports 2-20,000 M365 tenants
- **Rate Limiting**: Respects Graph API limits (10,000 requests/10 min)
- **Parallel Processing**: Concurrent operations across tenants
- **Caching**: Intelligent token and metadata caching
- **Batch Operations**: Groups related API calls for efficiency

## Monitoring and Observability

Built-in monitoring capabilities:
- **Health Metrics**: Token validity, API response times
- **Error Tracking**: Detailed error classification and trends
- **Compliance Reporting**: Cross-tenant compliance status
- **Audit Trails**: Complete operation history

## Contributing

When extending the M365 modules:

1. Follow the existing module pattern (`Get`/`Set` interface)
2. Implement `ConfigState` for efficient field comparison
3. Use the shared auth and Graph client components
4. Add comprehensive error handling
5. Include example configurations
6. Update this README with new capabilities

## License

This software is part of the CFGMS project and subject to the project's licensing terms.