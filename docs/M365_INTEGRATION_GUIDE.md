# M365 Integration Guide

Complete guide for integrating CFGMS with Microsoft 365, covering development setup, MSP production deployment, and testing.

## Overview

CFGMS integrates with M365 for **MSP (Managed Service Provider)** scenarios where MSP employees manage multiple client tenants using application permissions.

**Architecture**: MSP app (registered in cfgis.onmicrosoft.com) manages multiple client tenants via admin consent.

## Part 1: Development Setup

### 1.1 Create Test App Registration

For development/testing, create an app in your development tenant:

1. **Azure Portal** → **App registrations** → **New registration**
2. Configure:
   ```
   Name: CFGMS-Dev-Testing
   Account types: Single tenant (for development)
   Redirect URI: http://localhost:8080/callback
   ```

3. **Add Application Permissions**:
   ```
   Microsoft Graph:
   - User.ReadWrite.All
   - Directory.ReadWrite.All
   - Group.ReadWrite.All
   - Policy.ReadWrite.ConditionalAccess
   - DeviceManagementManagedDevices.ReadWrite.All
   - Organization.ReadWrite.All
   - Reports.Read.All
   - AuditLog.Read.All
   ```

4. **Grant Admin Consent** (for your dev tenant only)
5. **Create Client Secret**

### 1.2 Development Environment

Create `.env.local` (never commit):
```bash
M365_CLIENT_ID=your-dev-client-id
M365_CLIENT_SECRET=your-dev-client-secret
M365_TENANT_ID=your-dev-tenant-id
M365_INTEGRATION_ENABLED=true
```

### 1.3 Run Tests

```bash
# Load environment
source .env.local

# Test capability functions
go test -v ./features/modules/m365/auth -run TestMSPCapabilities

# Test with real API (if credentials available)
go test -v ./features/modules/m365/auth -run TestRealM365Integration
```

## Part 2: Production MSP Setup

### 2.1 Create Production MSP App

In your **MSP tenant (cfgis.onmicrosoft.com)**:

1. **Azure Portal** → **App registrations** → **New registration**
2. Configure:
   ```
   Name: CFGMS MSP Production
   Account types: Multi-tenant (REQUIRED for MSP)
   Redirect URI: https://auth.cfgms.com/admin/callback
   ```

3. **Add Same Application Permissions** as development
4. **DO NOT grant admin consent** (each client will consent individually)
5. **Create Client Secret** and **Certificate** (prod)

### 2.2 MSP Client Onboarding

**Step 1: MSP Admin Initiates**
```go
// Generate admin consent URL for new client
func OnboardNewClient(clientName, mspEmployee string) (string, error) {
    flow := NewAdminConsentFlow(mspConfig, clientStore)
    
    request, adminURL, err := flow.StartAdminConsentFlow(
        ctx, 
        generateClientID(), 
        clientName, 
        mspEmployee,
    )
    
    return adminURL, err
}
```

**Step 2: Send to Client Admin**
```
Subject: CFGMS MSP Setup - Admin Consent Required

Click to authorize CFGMS MSP access to your M365:
[ADMIN CONSENT URL]

This allows our team to manage your M365 environment 
per your service agreement.
```

**Step 3: Client Admin Clicks** → Signs into their tenant → Grants consent

**Step 4: Handle Callback**
```go
func HandleAdminCallback(w http.ResponseWriter, r *http.Request) {
    result, err := flow.HandleAdminConsentCallback(ctx, r.URL.String())
    
    if result.Success {
        // Client tenant now ready for MSP management
        log.Printf("Client %s activated", result.ClientTenant.TenantID)
        http.Redirect(w, r, "/msp/clients", http.StatusFound)
    }
}
```

### 2.3 MSP Operations

**Get Token for Client Tenant:**
```go
// MSP app uses client credentials to access client tenant
func GetMSPToken(clientTenantID string) (*AccessToken, error) {
    tokenURL := fmt.Sprintf(
        "https://login.microsoftonline.com/%s/oauth2/v2.0/token", 
        clientTenantID,
    )
    
    data := url.Values{
        "grant_type":    {"client_credentials"},
        "client_id":     {mspConfig.ClientID},
        "client_secret": {mspConfig.ClientSecret},
        "scope":         {"https://graph.microsoft.com/.default"},
    }
    
    return exchangeForToken(tokenURL, data)
}
```

**Test Client Readiness:**
```go
func ValidateClient(clientTenantID string) {
    token, _ := GetMSPToken(clientTenantID)
    
    report, _ := TestMSPCapabilities(ctx, mspConfig, clientTenantID, token)
    
    if report.OverallSuccess {
        fmt.Printf("✅ Client %s ready for management\n", clientTenantID)
    } else {
        fmt.Printf("⚠️  Setup required: %.1f%% ready\n", report.SuccessRate*100)
        fmt.Println(report.GetMSPCapabilitySummary())
    }
}
```

## Part 3: Storage Configuration

CFGMS follows a **pluggable storage architecture** that allows choosing the appropriate storage backend based on deployment requirements.

### Storage Options

#### 3.1 File Storage (Default - Simple Deployments)
```yaml
# cfgms.yaml
msp:
  client_store:
    type: file
    file_path: /var/lib/cfgms/msp-client-data
    enable_sharding: false
```

**Use Cases:**
- Development environments
- Small MSP deployments (< 50 clients)
- Single-node deployments
- No external dependencies required

#### 3.2 Git Storage (Recommended - CFGMS Philosophy)
```yaml
# cfgms.yaml
msp:
  client_store:
    type: git
    git_repository: https://github.com/your-msp/client-config.git
    git_branch: production
    enable_sharding: false
```

**Use Cases:**
- Distributed MSP teams
- Configuration version control
- Audit trail requirements
- Works with Mozilla's secret management

#### 3.3 Database Storage (Production - High Volume)
```yaml
# cfgms.yaml
msp:
  client_store:
    type: database
    database_url: postgresql://user:pass@localhost/cfgms_msp
    enable_sharding: true
    shard_count: 8
```

**Database Schema (Auto-created):**
```sql
-- Client tenant tracking
CREATE TABLE client_tenants (
    id SERIAL PRIMARY KEY,
    client_identifier VARCHAR(100) UNIQUE NOT NULL,
    tenant_id VARCHAR(36) UNIQUE NOT NULL,
    tenant_name VARCHAR(255) NOT NULL,
    domain_name VARCHAR(255),
    admin_email VARCHAR(255),
    status VARCHAR(20) DEFAULT 'pending',
    created_by VARCHAR(100),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    consented_at TIMESTAMP,
    metadata JSONB
);

-- Admin consent request tracking
CREATE TABLE admin_consent_requests (
    id SERIAL PRIMARY KEY,
    state VARCHAR(255) UNIQUE NOT NULL,
    client_identifier VARCHAR(100) NOT NULL,
    client_name VARCHAR(255) NOT NULL,
    requested_by VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP NOT NULL,
    metadata JSONB
);
```

**Use Cases:**
- Large MSP deployments (> 100 clients)
- High availability requirements
- Complex querying needs
- Multiple concurrent operators

#### 3.4 Hybrid Storage (Enterprise)
```yaml
# cfgms.yaml
msp:
  client_store:
    type: hybrid
    hybrid:
      git_repository: https://github.com/your-msp/client-config.git
      database_url: postgresql://user:pass@localhost/cfgms_msp
      sync_interval: 5m
    enable_sharding: true
    shard_count: 16
```

**Use Cases:**
- Enterprise MSP deployments
- Best of both worlds (performance + audit trail)
- Disaster recovery requirements
- Complex compliance needs

### Storage Migration

**Upgrade Path:** Simple → Git → Database → Hybrid
```bash
# Start simple for POC
cfgms init --storage-type=file

# Upgrade to git for team collaboration
cfgms migrate-storage --from=file --to=git --repository=https://github.com/msp/config.git

# Scale to database for production
cfgms migrate-storage --from=git --to=database --url=postgresql://...

# Add hybrid for enterprise features
cfgms migrate-storage --from=database --to=hybrid
```

## Part 4: Capability Testing

### MSP Capabilities Tested

1. **User Management** (`User.ReadWrite.All`) - `/users` API
2. **Directory Access** (`Directory.ReadWrite.All`) - `/organization` API  
3. **Group Management** (`Group.ReadWrite.All`) - `/groups` API
4. **Conditional Access** (`Policy.ReadWrite.ConditionalAccess`) - `/identity/conditionalAccess/policies`
5. **Intune Management** (`DeviceManagementManagedDevices.ReadWrite.All`) - `/deviceManagement/managedDevices`
6. **Audit Logs** (`AuditLog.Read.All`) - `/auditLogs/directoryAudits`
7. **Usage Reports** (`Reports.Read.All`) - `/reports/getOffice365ActiveUserDetail`
8. **Organization Settings** (`Organization.ReadWrite.All`) - `/organization`

### Test Usage

```go
// Test all MSP capabilities for client tenant
report, err := TestMSPCapabilities(ctx, mspConfig, clientTenantID, token)

if report.OverallSuccess {
    fmt.Println("✅ MSP READY - All capabilities operational")
} else {
    fmt.Printf("⚠️  SETUP REQUIRED - %d capabilities need attention\n", 
               len(report.Recommendations))
    
    for _, rec := range report.Recommendations {
        fmt.Printf("  • %s\n", rec)
    }
}
```

## Part 5: Configuration

### MSP Production Config
```go
type MSPConfig struct {
    ClientID                string   `yaml:"client_id"`
    ClientSecret            string   `yaml:"client_secret"`  
    MSPTenantID            string   `yaml:"msp_tenant_id"`    // cfgis tenant
    ApplicationPermissions  []string `yaml:"app_permissions"`
    AdminCallbackURI        string   `yaml:"admin_callback"`   // https://auth.cfgms.com/admin/callback
}

// Default MSP permissions
func DefaultMSPPermissions() []string {
    return []string{
        "User.ReadWrite.All",
        "Directory.ReadWrite.All", 
        "Group.ReadWrite.All",
        "Policy.ReadWrite.ConditionalAccess",
        "DeviceManagementManagedDevices.ReadWrite.All",
        "Organization.ReadWrite.All",
        "Reports.Read.All",
        "AuditLog.Read.All",
    }
}
```

## Key Concepts

**MSP vs Traditional SaaS:**
- **MSP**: App uses application permissions to manage client tenants on behalf of MSP employees
- **Traditional**: Users authenticate with delegated permissions to access their own data

**Admin Consent vs User Consent:**  
- **Admin Consent**: Client tenant admin grants MSP app permission to manage entire tenant
- **User Consent**: Individual users grant permission to access their personal data

**Application vs Delegated Permissions:**
- **Application**: App can access all data in tenant (MSP scenario)
- **Delegated**: App can only access data the user can access (traditional scenario)

## Troubleshooting

**"Insufficient permissions" errors:** 
- Verify application permissions are configured (not delegated)
- Ensure client admin has granted consent
- Check that client tenant status is "active"

**"Client tenant not found" errors:**
- Verify admin consent callback was processed successfully
- Check client_tenants table for tenant record

**API access denied:**
- Confirm MSP token is for correct client tenant
- Verify specific application permission is granted (e.g., User.ReadWrite.All for /users API)

This single guide covers everything needed for M365 integration in MSP scenarios, from development setup to production deployment and testing.