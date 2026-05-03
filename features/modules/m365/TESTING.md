# M365 Delegated Permissions Testing Guide

This guide provides comprehensive instructions for testing CFGMS M365 delegated permissions integration with real Microsoft 365 tenants.

## Prerequisites

### 1. Microsoft 365 Setup

You'll need:
- **Microsoft 365 tenant** (can be a developer tenant from Microsoft 365 Developer Program)
- **Azure AD Application** with both application and delegated permissions
- **User account** with appropriate administrative roles for testing

### 2. Azure AD Application Registration

#### Step 1: Register Application
1. Go to [Azure Portal](https://portal.azure.com) → Azure Active Directory → App registrations
2. Click "New registration"
3. Configure:
   - **Name**: `CFGMS-Testing-App`
   - **Supported account types**: Accounts in this organizational directory only
   - **Redirect URI**: Web → `http://localhost:8080/callback`

#### Step 2: Configure Application Permissions (for fallback testing)
Navigate to **API permissions** and add:
- `User.ReadWrite.All`
- `Directory.ReadWrite.All`
- `Group.ReadWrite.All`
- `Policy.ReadWrite.ConditionalAccess`
- `DeviceManagementConfiguration.ReadWrite.All`
- `AuditLog.Read.All`

#### Step 3: Configure Delegated Permissions (for main testing)
Add these **delegated permissions**:
- `User.Read`
- `User.ReadWrite.All`
- `Directory.Read.All`
- `Directory.ReadWrite.All`
- `Group.Read.All`
- `Group.ReadWrite.All`
- `Policy.ReadWrite.ConditionalAccess`
- `DeviceManagementConfiguration.ReadWrite.All`
- `AuditLog.Read.All`

#### Step 4: Grant Admin Consent
1. Click **"Grant admin consent for [Your Organization]"**
2. Confirm the consent

#### Step 5: Create Client Secret
1. Go to **Certificates & secrets**
2. Click **"New client secret"**
3. Set description: `CFGMS Testing Secret`
4. Set expiration: 6 months
5. **Copy the secret value immediately** (you won't see it again)

### 3. Test User Preparation

For comprehensive testing, prepare users with different permission levels:

#### Global Administrator (Full Access)
- Can test all scenarios
- Has access to all M365 services

#### User Administrator (Limited Access)
- Can test user management scenarios
- Limited access to other services

#### Standard User (Minimal Access)
- Can only read their own profile
- Tests permission boundaries

## Environment Setup

### 1. Set Environment Variables

```bash
# Required: Azure AD Application Details
export M365_CLIENT_ID="your-application-client-id"
export M365_CLIENT_SECRET="your-client-secret-value"
export M365_TENANT_ID="your-tenant-id"

# Optional: Test User (for non-interactive testing)
export M365_TEST_USER_UPN="testuser@yourdomain.onmicrosoft.com"

# Optional: Custom redirect URI (default: http://localhost:8080/callback)
export M365_REDIRECT_URI="http://localhost:8080/callback"
```

## Test Scenarios

M365 integration tests run via `make test-m365-integration`. The following scenarios are validated:

### 1. User Management Scenario
Tests user profile operations and user listing capabilities.

**Operations:**
- Get current user profile (`/me`)
- List users (`/users`)
- Get user's manager (`/me/manager`)

**Expected Results:**
- ✅ Success for users with User.Read permissions
- ❌ Failure for listing users without User.ReadWrite.All
- ⚠️  Manager may not exist (normal)

### 2. Directory Read Scenario
Tests directory information access.

**Operations:**
- Get organization info (`/organization`)
- List directory roles (`/directoryRoles`)
- Get subscribed SKUs (`/subscribedSkus`)

**Expected Results:**
- ✅ Success for users with Directory.Read.All
- ❌ Limited results for standard users

### 3. Group Management Scenario
Tests group access and membership operations.

**Operations:**
- List groups (`/groups`)
- Get user group memberships (`/me/memberOf`)

**Expected Results:**
- ✅ Success varies by user permissions
- Standard users see limited group information

### 4. Conditional Access Scenario
Tests Conditional Access policy access.

**Operations:**
- List CA policies (`/identity/conditionalAccess/policies`)
- List named locations (`/identity/conditionalAccess/namedLocations`)

**Expected Results:**
- ✅ Success only for Conditional Access administrators
- ❌ Forbidden for other users (expected)

### 5. Intune Device Management Scenario
Tests Intune policy and device access.

**Operations:**
- List device configurations (`/deviceManagement/deviceConfigurations`)
- List managed devices (`/deviceManagement/managedDevices`)

**Expected Results:**
- ✅ Success only for Intune administrators
- ❌ Forbidden for other users (expected)

### 6. Audit Logs Scenario
Tests audit log access.

**Operations:**
- Get sign-in logs (`/auditLogs/signIns`)
- Get directory audit logs (`/auditLogs/directoryAudits`)

**Expected Results:**
- ✅ Success only for Security Reader/Administrator roles
- ❌ Forbidden for other users (expected)

## Expected Test Outcomes by User Role

### Global Administrator
- ✅ All scenarios should pass
- ✅ All permission scopes should work
- ✅ Full access to all M365 services

### User Administrator
- ✅ User Management scenario
- ✅ Directory Read scenario (limited)
- ✅ Group Management scenario (limited)
- ❌ Conditional Access scenario (expected)
- ❌ Intune scenario (expected)
- ❌ Audit Logs scenario (expected)

### Standard User
- ✅ User Management scenario (own profile only)
- ⚠️  Directory Read scenario (very limited)
- ⚠️  Group Management scenario (own memberships only)
- ❌ All other scenarios (expected)

### Conditional Access Administrator
- ✅ User Management scenario
- ✅ Directory Read scenario
- ✅ Group Management scenario
- ✅ Conditional Access scenario
- ❌ Intune scenario (expected)
- ❌ Audit Logs scenario (expected)

## Troubleshooting

### Common Issues

#### 1. "Application not found" Error
**Cause:** Incorrect Client ID or Tenant ID
**Solution:** Verify IDs in Azure Portal → App registrations

#### 2. "Invalid client secret" Error
**Cause:** Expired or incorrect client secret
**Solution:** Generate new client secret in Azure Portal

#### 3. "Insufficient privileges" Errors
**Cause:** Missing permissions or admin consent
**Solution:** 
- Ensure all required permissions are added
- Grant admin consent for the permissions
- Wait 5-10 minutes for propagation

#### 4. "Redirect URI mismatch" Error
**Cause:** Redirect URI doesn't match Azure AD configuration
**Solution:** Ensure redirect URI in Azure AD matches test tool setting

#### 5. Browser doesn't open for authentication
**Manual Steps:**
1. Copy the displayed authorization URL
2. Open in your browser
3. Complete authentication
4. Return to terminal for results

### Permission Troubleshooting

#### Missing Scopes
If permission tests fail, verify:
1. Permissions are added in Azure AD
2. Admin consent is granted
3. User has appropriate roles
4. Token includes requested scopes

#### Graph API Errors
Common Graph API error codes:
- **403 Forbidden**: Insufficient permissions
- **401 Unauthorized**: Token expired or invalid
- **429 Too Many Requests**: Rate limiting (test will retry)
- **404 Not Found**: Resource doesn't exist (may be expected)

## Security Considerations

### Test Environment Safety

- **Use test/development tenants** when possible
- **Never test in production** without careful planning
- **Use dedicated test accounts** with limited privileges
- **Monitor audit logs** during testing

### Credential Security

- Test credentials are **encrypted at rest** using AES-256-GCM
- Credential files use **secure permissions** (0600)
- **Never commit credentials** to version control
- **Rotate test credentials** regularly

### Network Security

- Tests use **HTTPS only** for all communications
- OAuth2 flow uses **PKCE** for additional security
- **Local callback server** runs only during authentication

## Contributing

When adding new test scenarios:

1. **Handle permission failures gracefully** (many are expected)
2. **Add clear success/failure criteria**
3. **Document expected outcomes** for different user roles

## Support

For issues with M365 integration testing:

1. Check the troubleshooting section above
2. Review Azure AD application configuration
3. Verify user permissions and roles
4. Check test result files for detailed error information