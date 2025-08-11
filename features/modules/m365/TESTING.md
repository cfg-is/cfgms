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

### 2. Build the Testing Tool

```bash
# From the CFGMS root directory
go build -o bin/m365-test ./cmd/m365-test
```

## Running Tests

### 1. Interactive Testing (Recommended)

This is the primary testing mode that performs complete delegated permissions testing:

```bash
# Run with environment variables
./bin/m365-test

# Or with command line flags
./bin/m365-test \
  -client-id="your-client-id" \
  -client-secret="your-client-secret" \
  -tenant-id="your-tenant-id" \
  -verbose=true
```

**Test Flow:**
1. Tests application permissions (client credentials)
2. Opens browser for interactive user authentication
3. Performs delegated permissions testing
4. Tests token storage/retrieval
5. Runs comprehensive M365 operation scenarios
6. Saves detailed test results

### 2. Non-Interactive Testing

For automated testing environments:

```bash
./bin/m365-test -interactive=false -test-scopes=false
```

This only tests:
- Application permissions
- Token management
- Basic provider functionality

### 3. Scope-Only Testing

To test only permission scopes without full scenarios:

```bash
./bin/m365-test -test-scopes=true
```

## Test Scenarios

The testing tool runs six comprehensive scenarios:

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

## Test Results

### Result Files

Test results are saved in the credential path (default: `./m365-test-creds/`):

```
m365-test-creds/
├── test-results/
│   └── permission-test-user-at-domain-20240101-120000.json
├── scenario-results/
│   └── scenario-results-20240101-120000.json
└── [encrypted credential files]
```

### Permission Test Results Format

```json
{
  "user_context": {
    "user_id": "user-guid",
    "user_principal_name": "user@domain.com",
    "display_name": "Test User",
    "roles": ["Global Administrator"],
    "session_id": "session-123"
  },
  "tested_scopes": {
    "User.Read": true,
    "User.ReadWrite.All": true,
    "Directory.Read.All": false
  },
  "failed_scopes": ["Directory.Read.All"],
  "test_results": {
    "User.Read": "Success",
    "Directory.Read.All": "Failed: Insufficient privileges"
  },
  "test_timestamp": "2024-01-01T12:00:00Z"
}
```

### Scenario Results Format

```json
[
  {
    "scenario_name": "User Management",
    "success": true,
    "operations": [
      {
        "name": "Get Current User Profile",
        "method": "GET",
        "url": "https://graph.microsoft.com/v1.0/me",
        "status_code": 200,
        "success": true,
        "duration": "234ms"
      }
    ],
    "metadata": {
      "current_user_name": "Test User",
      "user_count": 5
    },
    "execution_time": "1.2s"
  }
]
```

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

## Advanced Testing

### Custom Test Scenarios

Create custom scenarios by extending the testing package:

```go
package main

import (
    "context"
    "github.com/cfgis/cfgms/features/modules/m365/auth"
    "github.com/cfgis/cfgms/features/modules/m365/testing"
)

func customScenario(ctx context.Context) {
    // Initialize provider and authenticate user
    // ...
    
    scenarioRunner := testing.NewScenarioRunner(provider, tenantID, userContext, token)
    
    // Run individual scenarios
    userResult := scenarioRunner.RunUserManagementScenario(ctx)
    caResult := scenarioRunner.RunConditionalAccessScenario(ctx)
    
    // Process results
    // ...
}
```

### Automated Testing Integration

For CI/CD integration, use environment variables and non-interactive mode:

```bash
#!/bin/bash
# ci-test-m365.sh

export M365_CLIENT_ID="$CI_M365_CLIENT_ID"
export M365_CLIENT_SECRET="$CI_M365_CLIENT_SECRET"
export M365_TENANT_ID="$CI_M365_TENANT_ID"

# Run non-interactive tests only
./bin/m365-test -interactive=false -test-scopes=false -verbose=true

# Check for failures
if [ $? -ne 0 ]; then
    echo "M365 integration tests failed"
    exit 1
fi
```

## Contributing

When adding new test scenarios:

1. **Follow existing patterns** in the testing package
2. **Handle permission failures gracefully** (many are expected)
3. **Include comprehensive metadata** in results
4. **Add clear success/failure criteria**
5. **Document expected outcomes** for different user roles

## Support

For issues with M365 integration testing:

1. Check the troubleshooting section above
2. Review Azure AD application configuration
3. Verify user permissions and roles
4. Check test result files for detailed error information