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
   - User.ReadWrite.All                              # User management (entra_user)
   - Group.ReadWrite.All                             # Group management (entra_group)  
   - Application.ReadWrite.All                       # Application management (entra_application)
   - AdministrativeUnit.ReadWrite.All               # Administrative unit management (entra_admin_unit)
   - Directory.ReadWrite.All                        # Directory operations (unified directory provider)
   - Policy.ReadWrite.ConditionalAccess            # Conditional access policies
   - DeviceManagementManagedDevices.ReadWrite.All  # Intune device management
   - Organization.ReadWrite.All                     # Organization settings
   - Reports.Read.All                               # Usage reports
   - AuditLog.Read.All                              # Audit logs
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
   Redirect URI: https://portal.example.com/admin/callback
   ```

   **Note**: Replace `portal.example.com` with your actual CFGMS controller domain.

   **Examples**:
   - Self-hosted: `https://cfgms.yourcompany.com/admin/callback`
   - cfg.is hosted beta: `https://portal.cfg.is/admin/callback`

3. **Add Same Application Permissions** as development
4. **DO NOT grant admin consent** (each client will consent individually)
5. **Create Client Secret** and **Certificate** (prod)

### 2.2 MSP Operations

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

## Part 3: Capability Testing

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

## Part 4: Configuration

### MSP Production Config

```go
type MSPConfig struct {
    ClientID                string   `yaml:"client_id"`
    ClientSecret            string   `yaml:"client_secret"`
    MSPTenantID            string   `yaml:"msp_tenant_id"`    // Your MSP tenant ID
    ApplicationPermissions  []string `yaml:"app_permissions"`
    AdminCallbackURI        string   `yaml:"admin_callback"`   // https://portal.example.com/admin/callback
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

### Permission Errors

**"Authorization_RequestDenied" or "Insufficient privileges" errors:**

This means the API call is working but the service principal lacks required permissions. Check these:

1. **Application Permissions Required:**
   - `Application.ReadWrite.All` - For entra_application module (create/manage applications)
   - `AdministrativeUnit.ReadWrite.All` - For entra_admin_unit module (create/manage admin units)  
   - `User.ReadWrite.All` - For entra_user module (create/manage users)
   - `Group.ReadWrite.All` - For entra_group module (create/manage groups)

2. **Verification Steps:**

   ```bash
   # Test specific permissions
   go test -v ./features/modules/m365/entra_application/ -run TestEntraApplication_Integration_BasicOperations
   go test -v ./features/modules/m365/entra_admin_unit/ -run TestEntraAdminUnit_Integration_BasicOperations
   ```

3. **Azure Portal Check:**
   - Go to Azure Portal → App Registrations → Your App → API Permissions
   - Verify all permissions above are listed as "Application" type (not "Delegated")
   - Ensure "Admin consent" status shows green checkmark
   - Click "Grant admin consent" if needed

**"Client tenant not found" errors:**

- Verify the client tenant exists in CFGMS

**API access denied:**

- Confirm MSP token is for correct client tenant
- Verify specific application permission is granted (e.g., User.ReadWrite.All for /users API)

This single guide covers everything needed for M365 integration in MSP scenarios, from development setup to production deployment and testing.
