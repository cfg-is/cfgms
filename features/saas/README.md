# M365 Virtual Steward

The M365 Virtual Steward implements SaaS platform management using the existing CFGMS module pattern. Instead of building a separate SaaS agent, we extend the steward to manage M365 resources using the same .cfg file format as physical endpoints.

## Architecture

The Virtual Steward approach uses the existing workflow engine and module system:

```
Virtual Steward (M365)
├── M365 Modules (entra_user, conditional_access, intune_policy)
├── OAuth2 Authentication Framework
├── Microsoft Graph API Client
├── Existing Workflow Engine Integration
└── Standard .cfg Configuration Files
```

## Key Components

### 1. Authentication Framework
- **OAuth2 with PKCE**: Enhanced security for public clients
- **Token Management**: Automatic refresh before expiration
- **Secure Storage**: OS keychain integration where available
- **Multi-Provider Support**: Extensible authentication providers

### 2. M365 Module System
- **entra_user**: Entra ID user management (creation, updates, licenses, groups)
- **conditional_access**: Conditional Access policies for Zero Trust security
- **intune_policy**: Intune device configuration and compliance policies
- **Extensible**: Standard module interface for additional M365 services

### 3. Virtual Steward Integration  
- **Standard .cfg Files**: Same configuration format as physical endpoints
- **Cascading Configuration**: MSP → Client → Site → Resource hierarchy
- **Workflow Engine**: Existing workflow engine processes M365 operations
- **DNA Tracking**: Configuration drift detection for SaaS resources

## Usage

### Standard .cfg Configuration

```yaml
# M365 tenant configuration using standard .cfg format
steward:
  id: "m365-acme-corp"
  tenant_id: "12345678-1234-1234-1234-123456789012"
  authentication:
    type: "oauth2_client_credentials"
    client_id: "${M365_CLIENT_ID}"
    client_secret: "${M365_CLIENT_SECRET}"

resources:
  # Entra ID user management
  - id: "12345678-1234-1234-1234-123456789012:john.doe@company.com"
    type: "entra_user"
    config:
      user_principal_name: "john.doe@company.com"
      display_name: "John Doe"
      account_enabled: true
      licenses:
        - sku_id: "c7df2760-2c81-4ef7-b578-5b5392b571df"  # Office 365 E5
      groups:
        - "Sales Team"

  # Conditional Access policy
  - id: "12345678-1234-1234-1234-123456789012:mfa-policy"
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

### Multi-Tenant MSP Configuration

```yaml
# MSP managing multiple client tenants with cascading policies
resources:
  # Baseline policy applied to all client tenants
  - id: "*:baseline-mfa-policy"  # * applies to all tenants
    type: "conditional_access"
    config:
      display_name: "MSP Baseline - Require MFA"
      # ... policy configuration
      cascade: true

  # Client-specific configuration
  - tenant_id: "client-tenant-id"
    resources:
      - id: "client-tenant-id:client-admin@client.com"
        type: "entra_user"
        config:
          # Client-specific user configuration
```

## Security Features

- **OAuth2 PKCE**: Prevents authorization code interception
- **Encrypted Storage**: Credentials encrypted at rest
- **Automatic Refresh**: Tokens refreshed before expiration
- **Audit Logging**: All API calls logged for compliance
- **Scope Limitation**: Minimal required permissions

## Consent State Storage

Admin-consent state (granted/revoked, accessible tenants, active OAuth2 flow) is
persisted through the `ConsentStore` interface defined in `multitenant_store.go`.

### ConsentStore interface

```go
type ConsentStore interface {
    StoreConsent(provider string, status *ConsentStatus) error
    GetConsent(provider string) (*ConsentStatus, error)   // (nil, nil) = not found
    DeleteConsent(provider string) error                  // idempotent
}
```

`StoreConsent` and `GetConsent` round-trip the complete `ConsentStatus` struct,
including `AccessibleTenants []TenantInfo` and the nested `*OAuth2Flow` pointer.

### InMemoryConsentStore

`InMemoryConsentStore` is the pre-production implementation. It serialises each
`ConsentStatus` to JSON before storing (using a `sync.RWMutex`-protected `[]byte`
map), which exercises the same serialisation path a durable store would use. The
contract test in `multitenant_store_test.go` runs `contractConsentStore` against
this implementation to verify round-trip fidelity for all fields.

```go
// Zero value is ready to use, or construct explicitly:
store := NewInMemoryConsentStore()
manager := NewMultiTenantManager(credStore, store, httpClient)
```

`CredentialStore` (`StoreClientSecret` / `GetClientSecret`) is **no longer used
for consent state**. Those methods remain on the interface for auth flows only.
Any legacy flat-string consent data (e.g. `consent_granted:true;tenants:1`) that
arrives at `GetConsent` returns a hard error — re-grant admin consent to recover.

## Development

The SaaS Steward is designed to be:
- **Lightweight**: Minimal dependencies and resource usage
- **Secure**: Industry-standard OAuth2 implementation
- **Extensible**: Plugin architecture for new providers
- **Observable**: Comprehensive logging and monitoring
- **Testable**: Real components (InMemoryConsentStore, MockCredentialStore) for unit testing