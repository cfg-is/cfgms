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
- **OAuth2 with PKCE**: Authorization code exchange performs a real HTTP POST to the provider token endpoint; PKCE `code_verifier` is included when set
- **Client Credentials Grant**: `DefaultOAuth2Client.ClientCredentialsGrant` issues a real HTTP POST to the configured `TokenURL`, decodes the JSON response body into a `TokenSet`, and returns the server-issued access token; no placeholder strings are returned
- **Token Refresh**: `DefaultOAuth2Client.RefreshToken` issues a real HTTP POST with `grant_type=refresh_token` using the client credentials stored in `DefaultOAuth2Client.config`; the server-issued access token is returned directly
- **JWT Signing**: `UniversalAuthenticator.generateJWT` uses `github.com/golang-jwt/jwt/v5` to sign real JWTs; RSA algorithms (RS256/RS384/RS512) accept a PEM-encoded private key and HMAC algorithms (HS256/HS384/HS512) use the raw key bytes; defaults to RS256 when `Algorithm` is empty
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

### TenantOnboardingWorkflow construction

`NewTenantOnboardingWorkflow` requires a `*MicrosoftMultiTenantConfig` as its second
argument. This config must carry real `ClientID`, `ClientSecret`, and `RedirectURI`
values sourced from secure storage (e.g. OS keychain via `pkg/secrets`). Placeholder
strings such as `"your-client-id"` must never be passed — `startAdminConsentFlow`
will propagate these values directly into Microsoft's OAuth2 authorization endpoint,
and placeholder values will cause consent to fail or silently target the wrong
application registration.

```go
cfg := &MicrosoftMultiTenantConfig{
    ClientID:     credentialStore.GetClientID(),
    ClientSecret: credentialStore.GetClientSecret(),
    RedirectURI:  "https://your-app.example.com/oauth/callback",
}
workflow := NewTenantOnboardingWorkflow(provider, cfg)
```

If `cfg` is `nil`, `startAdminConsentFlow` returns an error immediately rather than
panicking — but callers should always supply a populated config.

## Security Features

- **OAuth2 PKCE**: Prevents authorization code interception
- **Encrypted Storage**: Credentials encrypted at rest
- **Automatic Refresh**: Tokens refreshed before expiration
- **Audit Logging**: All API calls logged for compliance
- **Scope Limitation**: Minimal required permissions

## HTTP Client

All Microsoft Graph API calls use an `*http.Client` built by `NewGraphHTTPClient`:

```go
// Default values: 10 req/s sustained, burst of 20
client := saas.NewGraphHTTPClient(10, 20)

// High limits for tests (avoids flakiness from rate limiting)
testClient := saas.NewGraphHTTPClient(100, 1000)
```

### Rate limiting

`NewGraphHTTPClient` wraps `http.DefaultTransport` with a `rateLimitedTransport`
that enforces a per-process token-bucket rate limit using `golang.org/x/time/rate`.
The limiter is shared across all tenants in the process (per-process, not per-tenant).
Per-tenant limiting is a future optimization.

Default values (10 req/s, burst 20) are conservative enough to avoid Microsoft Graph
throttling under normal MSP workloads while still allowing short bursts for startup
discovery.

### Why not `pkg/cert`?

`pkg/cert` manages CFGMS-internal mTLS certificates used for gRPC-over-QUIC between
controller and steward. Microsoft Graph uses Microsoft's own public CA infrastructure —
there is no mutual TLS or CFGMS certificate authority involved. `http.DefaultTransport`
uses system root CAs, which already trust Microsoft's certificates. Using `pkg/cert`
here would be incorrect: it would attempt to validate Microsoft's certificate against
the CFGMS CA rather than the system trust store.

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
manager := NewMultiTenantManager(credStore, store, httpClient, discoverer)
```

`CredentialStore` (`StoreClientSecret` / `GetClientSecret`) is **no longer used
for consent state**. Those methods remain on the interface for auth flows only.
Any legacy flat-string consent data (e.g. `consent_granted:true;tenants:1`) that
arrives at `GetConsent` returns a hard error — re-grant admin consent to recover.

### TenantDiscoverer wiring

Tenant discovery is performed through the `TenantDiscoverer` interface (defined in
`multitenant_store.go`):

```go
type TenantDiscoverer interface {
    DiscoverTenants(ctx context.Context, token *TokenSet) (*TenantDiscoveryResult, error)
}
```

**Production implementation:** `MicrosoftMultiTenantProvider` satisfies
`TenantDiscoverer` via its `DiscoverTenants` method, which delegates to
`DiscoverTenantsFromMicrosoft`. This makes a real HTTP GET to the Microsoft Graph
`/v1.0/organization` endpoint and maps the response to `[]TenantInfo`.
`NewMicrosoftMultiTenantProvider` wires itself as the discoverer at construction
time:

```go
p := &MicrosoftMultiTenantProvider{...}
p.multiTenantManager = NewMultiTenantManager(credStore, store, httpClient, p)
```

**Test implementation:** Unit tests use `stubTenantDiscoverer` (defined in
`multitenant_test.go`) which returns a configurable fixed list of tenants without
making any HTTP calls. Pass it to `NewMultiTenantManager` as the fourth argument:

```go
stub := newStubTenantDiscoverer(TenantInfo{TenantID: "test-tenant", HasAccess: true})
mtm := NewMultiTenantManager(credStore, store, httpClient, stub)
```

## Tenant-Scoped Operations

All CRUD operations on `MicrosoftMultiTenantProvider` must use the explicit `*InTenant`
variants. The unqualified methods (`Create`, `Read`, `Update`, `Delete`, `RawAPI`) return
`ErrNoTenantSelected` immediately with no side effects.

**Why:** A multi-tenant provider may have access to dozens of customer tenants. Silently
routing an unqualified write to `tenants[0]` — whichever tenant happens to be first in
the list — would make the target unpredictable and could corrupt or expose data in the
wrong tenant. Forcing callers to name a tenant at the call site makes intent explicit and
eliminates an entire class of cross-tenant write bugs.

```go
// Wrong — returns ErrNoTenantSelected, no request is made.
result, err := provider.Create(ctx, "users", userData)

// Correct — targets a specific tenant explicitly.
result, err := provider.CreateInTenant(ctx, "tenant-id-here", "users", userData)
```

The `*InTenant` family covers all mutation and query operations:

| Method | Tenant-scoped variant |
|--------|----------------------|
| `Create` | `CreateInTenant(ctx, tenantID, resourceType, data)` |
| `Read` | `ReadFromTenant(ctx, tenantID, resourceType, resourceID)` |
| `Update` | `UpdateInTenant(ctx, tenantID, resourceType, resourceID, data)` |
| `Delete` | `DeleteFromTenant(ctx, tenantID, resourceType, resourceID)` |
| `RawAPI` | `RawAPIInTenant(ctx, tenantID, method, path, body)` |

`List` is excluded from this restriction — it performs an explicit cross-tenant aggregate
via `ListUsersAcrossAllTenants` and its cross-tenant semantics are intentional and correct.

## JWT Tenant Verification

`MultiTenantManager.GetTenantToken` verifies that the `tid` claim in the returned
access token matches the requested `tenantID` before returning the token to the caller.
This prevents a compromised or misconfigured token store from silently returning a token
that belongs to a different tenant.

### How it works

After the token is retrieved from the credential store (or refreshed), `GetTenantToken`
calls `extractJWTTenantID(tokenSet.AccessToken)`, which:

1. Splits the token on `.` and confirms three segments are present.
2. Base64 URL-decodes the payload segment (middle segment, no padding — `RawURLEncoding`).
3. JSON-unmarshals the payload and reads the `tid` string field.
4. Returns the `tid` value, or an error if any step fails.

If `tid` matches `tenantID` exactly, the token is returned normally.
If `tid` does not match, the token is rejected and `GetTenantToken` returns:

```
token tenant mismatch: got "<actual-tid>", want "<requested-tenant>" — token rejected
```

### Fail-open for opaque tokens

If `extractJWTTenantID` returns an error (e.g. the token is not a JWT, the payload
cannot be decoded, or the `tid` field is absent), `GetTenantToken` logs a WARN and
returns the token as-is. This preserves compatibility with client-credentials flows that
issue opaque (non-JWT) access tokens.

The WARN log includes the provider name, tenant ID, and the extraction error. It never
includes any portion of the token value.

### Dependency on real OAuth2 tokens (#697/#698)

Full integration coverage of the tid check requires real OAuth2 tokens flowing through
`refreshTenantToken`. The unit-level criteria (crafted JWT mismatch, opaque token
fail-open) are testable independently. Mark the integration acceptance criterion as
blocked on #697/#698 if those issues have not yet merged.

## Development

The SaaS Steward is designed to be:
- **Lightweight**: Minimal dependencies and resource usage
- **Secure**: Industry-standard OAuth2 implementation
- **Extensible**: Plugin architecture for new providers
- **Observable**: Comprehensive logging and monitoring
- **Testable**: Real components (InMemoryConsentStore, MockCredentialStore) for unit testing