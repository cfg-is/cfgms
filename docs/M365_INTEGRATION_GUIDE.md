# M365 Integration Guide

Complete guide for integrating CFGMS with Microsoft 365, covering development setup, MSP production deployment, and testing.

## Overview

CFGMS integrates with M365 for **MSP (Managed Service Provider)** scenarios where MSP employees manage multiple client tenants using application permissions.

**Architecture**: each CFGMS client tenant holds its own M365 connection, stored in the controller's secret store. A connection is either *direct* (the client's own application registration) or *partner* (the MSP's partner application reaching the client through a GDAP relationship). Connections are created with `cfg tenant m365`.

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

## Part 2: Connecting Client Tenants

An M365 connection exists **only on an existing CFGMS client tenant**: a tenant whose parent is an MSP tenant (a direct child of the root tenant). The root tenant, an MSP tenant, a tenant that does not exist and a tenant below a client tenant (for example `root/msp-a/client-1/servers`) are refused before anything is written. No `cfg tenant m365` command creates a tenant, an account or a consent record, so create the client tenant first.

A client secret is never accepted as a flag value and is never echoed, logged or audited. Pass `--client-secret-stdin` and write the secret as one line on standard input. A command that asks for confirmation has no terminal left to ask on when the secret is piped, so it needs `--yes`. `--json` prints the API response data.

Connecting needs `tenant:manage` (`tenant:read` for `get`). A root-scoped operator needs an active crossing into the MSP first (see [Tenant Management](administration/tenant-management.md#tenant-crossings)).

### 2.1 Direct mode: one client, its own app registration

1. In the **client's** Entra tenant, register an application, add the application permissions the modules need (see Part 3), grant admin consent in that tenant, and create a client secret.
2. Connect the client tenant:

   ```bash
   printf '%s\n' "$CLIENT_SECRET" | cfg tenant m365 set client-1 \
     --app-id <application-client-id> \
     --m365-tenant <client-directory-tenant-id> \
     --client-secret-stdin
   ```

   The stored connection holds the application ID, the directory tenant ID and the secret, and nothing else.
3. Check it (the secret is never printed):

   ```bash
   cfg tenant m365 get client-1
   ```

   `get` prints the mode, app ID, M365 tenant, partner tenant and GDAP roles for a partner connection, and `client secret: set`. A tenant without a connection reports that it has none.

A tenant that already has a connection is refused. Re-run `set` with `--replace` to overwrite it; the command prints what it will change and asks `Proceed? [y/N]`. With no terminal and no `--yes` it refuses and exits non-zero:

```bash
printf '%s\n' "$NEW_SECRET" | cfg tenant m365 set client-1 --app-id <id> --m365-tenant <directory-id> --client-secret-stdin --replace --yes
```

Remove a connection and its stored token with `cfg tenant m365 delete client-1` (also confirm-gated; `--yes` skips the prompt).

### 2.2 Partner mode: many customers through GDAP

In the **MSP's** M365 tenant, register one partner application with Partner Center access and the application permissions the modules need, and create a client secret. Each customer must have an active GDAP relationship with the MSP.

1. List the MSP's active GDAP customers and see which are already linked:

   ```bash
   printf '%s\n' "$PARTNER_SECRET" | cfg tenant m365 gdap-customers msp-a \
     --partner-tenant <msp-m365-tenant-id> --app-id <partner-app-id> --client-secret-stdin
   ```

   The table has the columns `CUSTOMER TENANT`, `NAME`, `STATUS`, `EXPIRES` and `LINKED TO`. `LINKED TO` is the client tenant of that MSP whose stored connection names the customer, or `unlinked`. It is computed on demand and never stored. Nothing is written.
2. Link many customers to existing client tenants in one command:

   ```bash
   printf '%s\n' "$PARTNER_SECRET" | cfg tenant m365 gdap-link msp-a \
     --partner-tenant <msp-m365-tenant-id> --app-id <partner-app-id> --client-secret-stdin \
     --link <customer-1-m365-tenant>=client-1 \
     --link <customer-2-m365-tenant>=client-2 \
     --gdap-role "User Administrator" --yes
   ```

   The command prints the planned links and asks `Proceed? [y/N]` (`--yes` skips the prompt). Each linked client tenant gets a partner connection holding the partner tenant ID, the customer tenant ID, the required GDAP roles and the partner app's ID and secret.

The partner credentials are supplied on every `gdap-customers` and `gdap-link` call. They are copied only into the connections of the client tenants being linked and are never stored on the MSP tenant or under any other key.

`gdap-link` validates the whole request before it writes anything. If any check fails, nothing is written:

- every `--link` target must be a client tenant of `msp-a`;
- every customer must be in the partner's active GDAP list;
- no customer and no target may appear twice;
- no customer may already be linked to a different client tenant;
- a target that already has a connection is refused unless `--replace` is set.

A customer M365 tenant is linked to at most one client tenant under an MSP, and a client tenant holds at most one connection. Use `cfg tenant m365 get <client-tenant>` and `cfg tenant m365 delete <client-tenant>` to inspect or unlink.

Each write emits one audit event per affected client tenant (`m365.connection.set`, `m365.connection.delete`, `m365.gdap.link`) carrying the mode, the app ID and the M365 tenant IDs, never the secret.

### 2.3 Using the connection from workflows

A connection made with `cfg tenant m365 set` or `cfg tenant m365 gdap-link` is used by the M365 workflow modules (`m365-entra-user`, `m365-entra-group`, `m365-entra-application`, `m365-entra-admin-unit`, `m365-conditional-access`, `m365-intune-policy`) with no other setup. When a workflow step runs one of them, the controller reads the client tenant's connection from its secret store, mints a short-lived Microsoft Graph access token and hands only that token to the module process. The client secret never leaves the controller. If the tenant has no connection, the step fails with an error that names the tenant and points back to `cfg tenant m365 set` or `cfg tenant m365 gdap-link`. A replaced or deleted connection takes effect on the next step. A step that outlives its token fails; start it again.

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

Connections are stored with the controller's secret store and are managed only through `cfg tenant m365` (Part 2) or the `/api/v1/tenants/{id}/m365-connection`, `/m365-gdap-customers` and `/m365-gdap-links` routes behind it. There is no configuration file to edit.

## Key Concepts

**MSP vs Traditional SaaS:**

- **MSP**: App uses application permissions to manage client tenants on behalf of MSP employees
- **Traditional**: Users authenticate with delegated permissions to access their own data

**Direct vs Partner connections:**

- **Direct**: the client's own application registration, with a client secret stored on the client tenant
- **Partner (GDAP)**: the MSP's partner application reaches the customer through a GDAP relationship; the partner app's credentials are stored on each linked client tenant

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
