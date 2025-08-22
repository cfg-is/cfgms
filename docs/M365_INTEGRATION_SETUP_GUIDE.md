# M365 Integration Testing Setup Guide

This guide provides step-by-step instructions for setting up real Microsoft 365 integration testing with Azure AD app registrations for CFGMS development and testing.

## Overview

Real M365 integration testing requires:
1. **Azure AD App Registration** with appropriate permissions
2. **Test Tenant Setup** (development tenant recommended)
3. **Credential Management** for secure testing
4. **Permission Configuration** for different test scenarios

## Prerequisites

- Azure AD tenant (development tenant recommended)
- Global Administrator access
- Development environment with Go 1.23+
- CFGMS development environment set up

## Step 1: Create Azure AD App Registration

### 1.1 Register New Application

1. Go to **Azure Portal** → **Azure Active Directory** → **App registrations**
2. Click **"New registration"**
3. Configure application:
   ```
   Name: CFGMS-Integration-Testing
   Supported account types: Single tenant
   Redirect URI: http://localhost:8080/callback (Web)
   ```
4. Click **"Register"**

### 1.2 Configure Application Permissions

**Required Application Permissions (for app-only testing):**
```
Microsoft Graph:
- User.Read.All
- Directory.Read.All
- Group.Read.All
- Policy.Read.All
- DeviceManagementConfiguration.Read.All
- Reports.Read.All
```

**Required Delegated Permissions (for user context testing):**
```
Microsoft Graph:
- User.Read
- User.ReadWrite.All
- Directory.Read.All
- Group.ReadWrite.All
- Policy.ReadWrite.ConditionalAccess
- DeviceManagementConfiguration.ReadWrite.All
```

### 1.3 Grant Admin Consent

1. In **API permissions** tab
2. Click **"Grant admin consent for [tenant]"**
3. Confirm consent for all permissions

### 1.4 Create Client Secret

1. Go to **Certificates & secrets** tab
2. Click **"New client secret"**
3. Configure:
   ```
   Description: CFGMS Integration Testing
   Expires: 12 months
   ```
4. **Copy the secret value immediately** (it won't be shown again)

### 1.5 Record Configuration

Save these values securely:
```
Application (client) ID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
Directory (tenant) ID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
Client secret: your-client-secret-value
```

## Step 2: Development Environment Setup

### 2.1 Environment Variables

Create a `.env.local` file (never commit this):
```bash
# M365 Integration Testing Credentials
M365_CLIENT_ID=your-client-id
M365_CLIENT_SECRET=your-client-secret
M365_TENANT_ID=your-tenant-id

# Optional: Test user for delegated permissions
M365_TEST_USER_UPN=testuser@yourdomain.onmicrosoft.com
M365_TEST_USER_PASSWORD=SecurePassword123!

# Integration test control
M365_INTEGRATION_ENABLED=true
M365_SKIP_DESTRUCTIVE_TESTS=true
```

### 2.2 Load Environment Variables

Add to your shell profile or use direnv:
```bash
# Load environment variables
source .env.local

# Or use direnv (recommended)
echo "source .env.local" > .envrc
direnv allow
```

### 2.3 Test Credential Setup

Run the credential verification test:
```bash
go test -v ./features/modules/m365/auth -run TestCredentialSetup
```

## Step 3: Integration Test Categories

### 3.1 Authentication Tests
- **OAuth2 token acquisition** (application and delegated)
- **Token refresh and caching**
- **Permission validation**
- **Error handling and fallback scenarios**

### 3.2 Microsoft Graph API Tests
- **User management operations**
- **Group operations**
- **Directory queries**
- **Conditional Access policies** (read-only in test tenant)
- **Intune configuration queries**

### 3.3 End-to-End Workflow Tests
- **SaaS Steward operations**
- **Configuration inheritance**
- **Multi-tenant simulation** (single tenant with role simulation)

## Step 4: Running Integration Tests

### 4.1 Individual Test Categories

```bash
# Authentication integration tests
go test -v ./features/modules/m365/auth -run TestRealM365Integration

# Graph API integration tests  
go test -v ./features/modules/m365/graph -run TestGraphAPIIntegration

# End-to-end workflow tests
go test -v ./features/modules/m365/testing -run TestE2EIntegration
```

### 4.2 Full Integration Test Suite

```bash
# Run all M365 integration tests
make test-m365-integration

# Run with verbose output
make test-m365-integration-verbose
```

### 4.3 CI/CD Integration Tests

```bash
# For CI/CD environments with secured credentials
make test-integration-ci
```

## Step 5: Test Data Management

### 5.1 Test Tenant Setup

**Recommended test tenant configuration:**
- **Development tenant** (not production)
- **Test users** with different role assignments
- **Test groups** for group management testing
- **Test conditional access policies** (disabled/report-only)

### 5.2 Test Data Cleanup

Integration tests should:
- **Create temporary resources** with unique naming
- **Clean up after themselves** in defer statements
- **Use read-only operations** when possible
- **Avoid modifying production-critical settings**

## Step 6: Security Considerations

### 6.1 Credential Security

- **Never commit credentials** to repository
- **Use environment variables** for local development
- **Use Azure Key Vault** or GitHub Secrets for CI/CD
- **Rotate secrets regularly** (90-day maximum)

### 6.2 Permission Scope

- **Request minimum necessary permissions**
- **Use read-only permissions** when possible
- **Avoid high-privilege operations** in automated tests
- **Implement permission checks** before destructive operations

### 6.3 Test Isolation

- **Use dedicated test tenant** (never production)
- **Prefix test resources** with unique identifiers
- **Implement cleanup procedures** for all test resources
- **Monitor API rate limits** to avoid throttling

## Step 7: Troubleshooting

### 7.1 Common Issues

**Authentication Errors:**
```
Error: "AADSTS70011: The provided value for the input parameter 'scope' is not valid"
Solution: Check scope format and ensure permissions are granted
```

**Permission Errors:**
```
Error: "Insufficient privileges to complete the operation"
Solution: Verify admin consent and permission configuration
```

**Rate Limiting:**
```
Error: "TooManyRequests" (429)
Solution: Implement exponential backoff and respect rate limits
```

### 7.2 Debug Tools

**Token Inspection:**
```bash
# Decode JWT token for debugging
echo "your-access-token" | base64 -d
```

**Graph Explorer:**
- Use https://developer.microsoft.com/en-us/graph/graph-explorer
- Test API calls manually with same credentials

## Step 8: Advanced Integration Scenarios

### 8.1 Multi-Tenant Simulation

Even with single tenant, simulate multi-tenant scenarios:
- **Different user roles** representing different "tenants"
- **Group-based isolation** simulating client separation
- **Permission inheritance testing** with nested structures

### 8.2 Performance Testing

- **Concurrent API calls** testing
- **Rate limit handling** validation
- **Cache effectiveness** measurement
- **Token refresh performance** under load

### 8.3 Error Recovery Testing

- **Network failure simulation**
- **Token expiration handling**
- **API error response processing**
- **Fallback mechanism validation**

## Example Integration Test Structure

```go
func TestRealM365UserManagement(t *testing.T) {
    // Check credentials
    if !isIntegrationEnabled() {
        t.Skip("M365 integration tests disabled")
    }
    
    // Setup
    client := setupM365Client(t)
    defer cleanupTestResources(t, client)
    
    // Test scenarios
    t.Run("ListUsers", func(t *testing.T) {
        users, err := client.Users().List(context.Background())
        require.NoError(t, err)
        assert.NotEmpty(t, users)
    })
    
    t.Run("CreateTestUser", func(t *testing.T) {
        if os.Getenv("M365_SKIP_DESTRUCTIVE_TESTS") == "true" {
            t.Skip("Destructive tests disabled")
        }
        
        user := createTestUser(t, client)
        defer deleteTestUser(t, client, user.ID)
        
        assert.NotEmpty(t, user.ID)
        assert.Contains(t, user.UserPrincipalName, "test-")
    })
}
```

## Next Steps

1. **Complete app registration** following Step 1
2. **Set up development environment** with credentials (Step 2)
3. **Run authentication tests** to validate setup (Step 3)
4. **Implement Graph API tests** for your specific use cases
5. **Set up CI/CD integration** with secured credentials

This setup provides a complete foundation for real M365 integration testing while maintaining security and isolation from production environments.