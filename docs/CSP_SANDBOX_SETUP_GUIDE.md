# CSP Integration Sandbox Setup Guide

## Overview

This guide provides step-by-step instructions for setting up a Microsoft Partner Center integration sandbox environment for Cloud Solution Provider (CSP) partners. The sandbox environment enables safe testing of Partner Center APIs, GDAP relationships, and customer management operations without affecting production data.

## Purpose and Benefits

### What is a CSP Integration Sandbox?
- **Isolated testing environment** with synthetic customer data
- **75 test customers** maximum with realistic subscription structures¹⁹
- **Complete API access** for Partner Center development¹¹¹⁶
- **GDAP relationship testing** capabilities¹⁰
- **Zero risk** to production customer data or billing

### Key Use Cases
- Testing Partner Center API integrations
- Validating GDAP (Granular Delegated Admin Privileges) implementations
- Developing customer management applications
- Training and learning Partner Center operations
- Proof of concept development for MSP solutions

## Prerequisites Validation Checklist

### ✅ **Prerequisite 1: CSP Partner Program Enrollment**

**Required Status:**
- Active CSP Partner Center account
- Either **Direct Bill Partner** OR **Indirect Provider** status²³
- ❌ **NOT available for CPV (Control Panel Vendor) partners**²⁰

**Validation Steps:**
1. Navigate to https://partner.microsoft.com/
2. Sign in with your work account credentials
3. Go to **Account Settings** (gear icon) → **Partner profile** → **Programs**
4. Verify one of the following program enrollments:
   - ✅ **"Cloud Solution Provider - Direct Bill"**
   - ✅ **"Cloud Solution Provider - Indirect Provider"**
   - ✅ **"Cloud Solution Provider - Indirect Reseller"** (limited sandbox capabilities)

**❌ Common Issues:**
- Account shows "Microsoft AI Cloud Partner Program" only → Need CSP enrollment
- Shows "Control Panel Vendor" → Sandbox not available for CPV partners
- No CSP program visible → Contact Microsoft Partner Support

---

### ✅ **Prerequisite 2: Global Administrator Permissions**

**Required Permissions:**
- Global Administrator role in Azure AD/Entra ID⁴
- Account Administrator role in Partner Center⁵
- Permissions to manage billing and create resources

**Validation Steps:**

**Method A: Partner Center Check**
1. In Partner Center, click your **profile picture** (top right)
2. Select **"My profile"**
3. Under **"Roles and permissions"**, verify:
   - ✅ **"Global admin"** 
   - ✅ **"Account admin"**

**Method B: Azure Portal Check**
1. Go to https://portal.azure.com/
2. Navigate to **"Microsoft Entra ID"** → **"Roles and administrators"**
3. Search for **"Global Administrator"**
4. Click the role and verify your account is assigned

**Method C: PowerShell Verification**
```powershell
# Connect to Azure AD
Connect-AzureAD

# Check your role assignments
Get-AzureADDirectoryRole | Where-Object {$_.DisplayName -eq "Global Administrator"} | Get-AzureADDirectoryRoleMember | Where-Object {$_.UserPrincipalName -eq "your-email@domain.com"}
```

**❌ Common Issues:**
- Shows "User" or "Member" only → Need Global Admin elevation
- Access denied errors → Insufficient permissions
- Role not visible → Contact your organization's Global Admin

---

### ✅ **Prerequisite 3: Tenant Creator Role**

**Required Permissions:**
- Tenant Creator role in Azure AD⁶
- Ability to create new Azure AD tenants
- Permissions to associate tenants with Partner account

**Validation Steps:**

**Method A: Direct Role Check**
1. In **Azure Portal** → **"Microsoft Entra ID"** → **"Roles and administrators"**
2. Search for **"Tenant Creator"**
3. Click the role and verify your account assignment

**Method B: Practical Test**
1. Go to **Azure Portal** → **"+ Create a resource"**
2. Search for **"Azure Active Directory"**
3. Click **"Create"** and verify you can access the creation form
4. **DO NOT COMPLETE** - this is just a permission test

**Method C: Partner Center Tenant Management**
1. In Partner Center → **Account Settings** → **Tenants**
2. Verify you can see **"Add Azure AD tenant"** option

**❌ Common Issues:**
- Cannot access tenant creation → Missing Tenant Creator role
- Error: "Insufficient privileges" → Contact Global Admin to assign role
- Option not visible in Partner Center → Account permissions issue

---

### ✅ **Prerequisite 4: Microsoft Customer Agreement (MCA) Billing Account**

**Required Setup:**
- Active Microsoft Customer Agreement billing account
- **MANDATORY** as of 2024/2025 for sandbox creation⁷
- Properly configured billing profile

**Validation Steps:**

**Method A: Azure Cost Management Check**
1. Go to **Azure Portal** → Search **"Cost Management + Billing"**
2. If **single billing scope**:
   - Select **"Properties"** from left menu
   - Verify **"Type"** field shows: ✅ **"Microsoft Customer Agreement"**
3. If **multiple billing scopes**:
   - Select **"Billing scopes"** from left menu
   - Check **"Billing account type"** column
   - Look for: ✅ **"Microsoft Customer Agreement"**

**Method B: Partner Center Billing Check**
1. In Partner Center → **Account Settings** → **Billing profile**
2. Verify billing account shows **"Microsoft Customer Agreement"** type
3. Check that billing profile is **"Active"** status

**Method C: Azure CLI Verification**
```bash
# List billing accounts and their agreement types¹²
az billing account list --query "[].{name:name, agreementType:agreementType}" --output table
```

**Expected Output:**
```
Name                                    AgreementType
--------------------------------------  -------------------------
xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx   MicrosoftCustomerAgreement
```

**❌ Common Issues:**
- Shows "Microsoft Online Subscription Program" → Need MCA setup
- Shows "Enterprise Agreement" → Need MCA migration
- Shows "Microsoft Partner Agreement" → Need customer MCA
- No billing account visible → Contact Microsoft Billing Support

**🔧 Fix Missing MCA:**
If you don't have MCA, follow these steps:
1. Go to **Azure Portal** → **"Cost Management + Billing"**¹⁴
2. Look for **"Set up billing"** or **"Onboard to MCA"** options
3. Follow the guided setup process
4. Accept the Microsoft Customer Agreement terms
5. Complete billing profile configuration

---

### ✅ **Prerequisite 5: Azure Subscription Association**

**Required Setup:**
- At least one active Azure subscription
- Subscription associated with the MCA billing account
- Valid payment method configured

**Validation Steps:**

**Method A: Subscription List Check**
1. Go to **Azure Portal** → **"Subscriptions"**
2. Verify at least one subscription shows:
   - ✅ **"Active"** status
   - ✅ Valid subscription name and ID
   - ✅ Your organization as owner

**Method B: Billing Association Check**
1. In **Cost Management + Billing** → **"Billing profiles"**
2. Select your billing profile
3. Go to **"Azure subscriptions"** tab
4. Verify your subscription is listed and **"Active"**

**Method C: Subscription Details**
1. Click on your subscription in the Subscriptions list
2. Verify **"Billing account"** shows your MCA account
3. Check **"Payment method"** is configured

**❌ Common Issues:**
- No subscriptions visible → Need to create Azure subscription
- Subscription shows "Disabled" → Payment or billing issue
- Not associated with MCA → Need to transfer subscription
- Payment method missing → Configure valid payment method

---

## Sandbox Creation Process

### Phase 1: Pre-Creation Setup

**Step 1: Access Partner Center Production Account**
1. Sign in to https://partner.microsoft.com/ with **production** credentials
2. Verify you're in the **production environment** (not sandbox)
3. Confirm CSP customer list shows real customers (if any)

**Step 2: Navigate to Integration Sandbox Settings**
1. Click **Settings** (gear icon) in top right corner
2. Select **"Account settings"** from dropdown menu
3. In left navigation, look for **"Integration sandbox"** section
4. Click **"Integration sandbox"**

### Phase 2: Sandbox Account Creation

**Step 3: Create New Sandbox Tenant**
1. On Integration Sandbox page, click **"Create and associate"** button
2. **Sandbox Tenant Creation Form** will appear:
   ```
   Tenant Domain Prefix: [enter-unique-prefix]
   Organization Name: [your-test-org-name]
   Country/Region: [select-your-region]
   Contact Information: [admin-contact-details]
   ```

**Step 4: Complete MCA Association**
1. System will prompt for **Microsoft Customer Agreement** association
2. Select your **MCA billing account** from dropdown
3. Confirm billing profile association
4. Accept additional terms if prompted

**Step 5: Wait for Provisioning**
1. Sandbox creation typically takes **5-15 minutes**
2. You'll see **"Provisioning in progress"** status
3. **DO NOT** close the browser during this process
4. System will display completion notification

### Phase 3: Sandbox Configuration

**Step 6: Record Sandbox Details**
1. **Copy and save** the sandbox domain name: `[prefix].onmicrosoft.com`
2. **Note the tenant ID** for API configuration
3. **Save the admin credentials** provided
4. **Record the sandbox Partner Center URL** (if different)

**Step 7: Sign Out and Sign In to Sandbox**
1. **Sign out** of production Partner Center completely
2. **Sign in** to Partner Center using **sandbox tenant credentials**:
   - Email: `admin@[prefix].onmicrosoft.com`
   - Password: [provided during setup]
3. Verify you're now in the **sandbox environment**

**Step 8: Enable API Access**
1. In sandbox Partner Center → **Settings** → **Account settings**
2. Select **"App management"** from left menu
3. Click **"Add new web app"** (or use existing)
4. **App Registration Details:**
   ```
   App Name: [your-app-name]
   Type: Web App
   ```
5. **Critical:** Copy and securely store:
   - ✅ **Application ID** (Client ID)
   - ✅ **Application Key** (Client Secret)
   - ✅ **Tenant ID**

### Phase 4: Verification and Testing

**Step 9: Verify Sandbox Environment**
1. Check **"Customers"** section shows synthetic test customers
2. Verify maximum of **75 customers** are available
3. Confirm **5 subscriptions per customer** limit
4. Test **"Add customer"** functionality works

**Step 10: Test API Connectivity**
```bash
# Test Partner Center API authentication
curl -X POST https://login.microsoftonline.com/[sandbox-tenant-id]/oauth2/v2.0/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=[your-app-id]" \
  -d "client_secret=[your-app-secret]" \
  -d "scope=https://api.partnercenter.microsoft.com/.default"
```

**Step 11: Validate GDAP Capabilities**¹⁰
1. In sandbox Partner Center → **"Customers"**
2. Select a test customer
3. Go to **"Admin relationships"**
4. Verify **"GDAP"** options are available
5. Test creating a GDAP relationship request

## Troubleshooting Common Issues

### Issue: "Cannot create sandbox - MCA required"
**Cause:** Missing Microsoft Customer Agreement billing account
**Solution:**
1. Complete MCA setup in Azure Portal
2. Ensure billing profile is active
3. Retry sandbox creation

### Issue: "Insufficient permissions to create tenant"
**Cause:** Missing Tenant Creator role
**Solution:**
1. Request Tenant Creator role from Global Admin
2. Verify role assignment in Azure AD
3. Wait 15-30 minutes for role propagation

### Issue: "CSP program not found"
**Cause:** Account not enrolled in CSP program
**Solution:**
1. Complete CSP enrollment process
2. Wait for approval (can take 24-48 hours)
3. Verify program status in Partner Center

### Issue: "Sandbox creation stuck in provisioning"
**Cause:** Backend provisioning delays
**Solution:**
1. Wait up to 30 minutes
2. Check Azure Service Health for issues¹⁸
3. Contact Partner Center Support if still failing

### Issue: "Cannot access sandbox after creation"
**Cause:** Authentication or URL issues
**Solution:**
1. Ensure using sandbox-specific credentials
2. Clear browser cache and cookies
3. Try incognito/private browsing mode
4. Verify sandbox domain is correct

## Security and Best Practices

### Credential Management
- **Never use production credentials** in sandbox
- **Store sandbox credentials securely** (password manager)
- **Rotate API keys regularly** (every 90 days)
- **Use separate development machines** for sandbox testing

### Data Handling
- **All sandbox data is synthetic** - safe for testing
- **No real customer information** exists in sandbox
- **API limits still apply** - respect rate limits
- **Billing limits enforced** - monitor spending

### Access Control
- **Limit sandbox access** to development team only
- **Use principle of least privilege** for API permissions
- **Monitor sandbox usage** for unusual activity
- **Regular access reviews** for team members

## Integration Testing Scenarios

### Basic Partner Center Operations
```powershell
# PowerShell example for testing Partner Center APIs¹³
Install-Module -Name PartnerCenter -Force

# Connect to sandbox
$credential = Get-Credential # Use sandbox credentials
Connect-PartnerCenter -Credential $credential -Environment Sandbox

# Test basic operations
Get-PartnerCustomer | Select-Object -First 5
Get-PartnerCustomerSubscription -CustomerId "test-customer-id"
```

### GDAP Relationship Testing
1. **Create GDAP relationship** with test customer
2. **Test role assignments** and permissions
3. **Validate API access** with delegated permissions
4. **Test relationship termination** and cleanup

### API Development Workflow
1. **Develop against sandbox** APIs first
2. **Test error handling** with invalid data
3. **Validate rate limiting** behavior
4. **Test pagination** with large datasets
5. **Verify webhook** functionality

## Support and Resources

### Microsoft Support Channels
- **Partner Center Support:** https://partner.microsoft.com/support
- **Azure Support:** https://portal.azure.com/#create/Microsoft.Support
- **Partner Community:** https://www.microsoftpartnercommunity.com/¹⁹

### Documentation Resources
- **Partner Center Developer Guide:** https://learn.microsoft.com/partner-center/developer/¹¹
- **GDAP Documentation:** https://learn.microsoft.com/partner-center/customers/gdap-introduction¹⁰
- **API Reference:** https://learn.microsoft.com/partner-center/developer/partner-center-rest-api-reference¹⁷

### Getting Help
If you encounter issues not covered in this guide:
1. **Check Microsoft Learn documentation** for latest updates
2. **Search Partner Community forums** for similar issues
3. **Contact Microsoft Partner Support** with specific error messages
4. **Provide sandbox tenant ID** and detailed steps when reporting issues

---

## Appendix: Verification Checklist Summary

Print this checklist for easy reference during setup:

### Prerequisites Verification
- [ ] CSP Partner Center account with Direct Bill/Indirect Provider status
- [ ] Global Administrator permissions in Azure AD and Partner Center  
- [ ] Tenant Creator role assigned and verified
- [ ] Microsoft Customer Agreement (MCA) billing account active
- [ ] Azure subscription associated with MCA billing account

### Sandbox Creation Steps
- [ ] Accessed production Partner Center with correct permissions
- [ ] Located Integration Sandbox settings successfully
- [ ] Completed sandbox tenant creation form
- [ ] Associated MCA billing account during setup
- [ ] Recorded sandbox domain and credentials securely
- [ ] Signed into sandbox environment successfully
- [ ] Enabled API access and recorded application credentials
- [ ] Verified synthetic customer data presence
- [ ] Tested basic API connectivity
- [ ] Validated GDAP functionality availability

### Post-Setup Validation
- [ ] Can authenticate to sandbox APIs
- [ ] Can perform basic customer operations
- [ ] GDAP relationships can be created and managed
- [ ] No production data visible in sandbox
- [ ] Team access properly configured
- [ ] Development environment configured for sandbox testing

**Setup Complete!** Your CSP integration sandbox is ready for development and testing.

---

## References and Sources

### Footnotes

¹ **Microsoft Partner Center Integration Sandbox Overview**  
Source: Microsoft Learn - "Partner Center Integration Sandbox" - https://learn.microsoft.com/en-us/partner-center/developer/set-up-api-access-in-partner-center#integration-sandbox  
Verification: Official Microsoft documentation confirming sandbox capabilities and 75 customer limit

² **CSP Partner Program Enrollment Requirements**  
Source: Microsoft Partner Center - "Cloud Solution Provider program overview" - https://learn.microsoft.com/en-us/partner-center/csp-overview  
Verification: Official documentation specifying Direct Bill, Indirect Provider, and Indirect Reseller eligibility

³ **CSP Partner Program Types and Capabilities**  
Source: Microsoft Learn - "CSP program guide, agreements, price lists, and offers" - https://learn.microsoft.com/en-us/partner-center/csp-documents-and-learning-resources  
Verification: Official Microsoft documentation defining CSP partner types and their capabilities

⁴ **Global Administrator Role Requirements**  
Source: Microsoft Learn - "Azure AD built-in roles" - https://learn.microsoft.com/en-us/azure/active-directory/roles/permissions-reference#global-administrator  
Verification: Official Azure Active Directory documentation defining Global Administrator permissions

⁵ **Partner Center Account Administrator Role**  
Source: Microsoft Learn - "Assign users roles and permissions" - https://learn.microsoft.com/en-us/partner-center/permissions-overview#account-admin  
Verification: Official Partner Center documentation specifying Account Administrator role requirements

⁶ **Tenant Creator Role Requirements**  
Source: Microsoft Learn - "Azure AD built-in roles" - https://learn.microsoft.com/en-us/azure/active-directory/roles/permissions-reference#tenant-creator  
Verification: Official Azure AD documentation confirming Tenant Creator role is required for creating new Azure AD tenants

⁷ **Microsoft Customer Agreement (MCA) Requirement for Sandbox**  
Source: Microsoft Partner Community - "CSP Integration Sandbox Setup" (2024 update) - https://www.microsoftpartnercommunity.com/  
Verification: Partner Community posts and Microsoft Support documentation confirming MCA became mandatory in 2024

⁸ **Azure Subscription Association Requirements**  
Source: Microsoft Learn - "Associate an existing Azure subscription" - https://learn.microsoft.com/en-us/azure/cost-management-billing/manage/link-partner-id  
Verification: Official Azure billing documentation specifying subscription association requirements

⁹ **Sandbox Customer and Subscription Limits**  
Source: Microsoft Learn - "Partner Center Integration Sandbox" - https://learn.microsoft.com/en-us/partner-center/developer/set-up-api-access-in-partner-center#integration-sandbox  
Verification: Official documentation specifying 75 customer maximum and 5 subscriptions per customer limits

¹⁰ **GDAP (Granular Delegated Admin Privileges) Overview**  
Source: Microsoft Learn - "Granular delegated admin privileges (GDAP) introduction" - https://learn.microsoft.com/en-us/partner-center/customers/gdap-introduction  
Verification: Official Microsoft documentation explaining GDAP capabilities and requirements

¹¹ **Partner Center API Authentication Methods**  
Source: Microsoft Learn - "Partner Center authentication" - https://learn.microsoft.com/en-us/partner-center/developer/partner-center-authentication  
Verification: Official API documentation specifying OAuth 2.0 authentication requirements and endpoints

¹² **Azure CLI Billing Account Commands**  
Source: Microsoft Learn - "az billing account" - https://learn.microsoft.com/en-us/cli/azure/billing/account  
Verification: Official Azure CLI documentation for billing account management commands

¹³ **PowerShell Partner Center Module**  
Source: PowerShell Gallery - "PartnerCenter Module" - https://www.powershellgallery.com/packages/PartnerCenter  
Verification: Official PowerShell Gallery listing for Microsoft Partner Center PowerShell module

¹⁴ **Azure Cost Management + Billing Portal**  
Source: Microsoft Learn - "What is Azure Cost Management + Billing?" - https://learn.microsoft.com/en-us/azure/cost-management-billing/cost-management-billing-overview  
Verification: Official Azure documentation for cost management and billing portal functionality

¹⁵ **Microsoft Customer Agreement Types and Migration**  
Source: Microsoft Learn - "Microsoft Customer Agreement administrative tasks" - https://learn.microsoft.com/en-us/azure/cost-management-billing/manage/mca-overview  
Verification: Official documentation explaining MCA types and migration from other agreement types

¹⁶ **Partner Center App Registration Process**  
Source: Microsoft Learn - "Set up API access in Partner Center" - https://learn.microsoft.com/en-us/partner-center/developer/set-up-api-access-in-partner-center  
Verification: Official step-by-step documentation for Partner Center API app registration

¹⁷ **Partner Center REST API Reference**  
Source: Microsoft Learn - "Partner Center REST API reference" - https://learn.microsoft.com/en-us/partner-center/developer/partner-center-rest-api-reference  
Verification: Complete official API reference documentation with endpoints and examples

¹⁸ **Azure Service Health Portal**  
Source: Microsoft Azure - "Azure Service Health" - https://portal.azure.com/#view/Microsoft_Azure_Health/AzureHealthBrowseBlade  
Verification: Official Azure portal service for monitoring Azure service status and issues

¹⁹ **Microsoft Partner Community Forums**  
Source: Microsoft Partner Community - https://www.microsoftpartnercommunity.com/  
Verification: Official Microsoft partner community platform for support and discussions

²⁰ **Control Panel Vendor (CPV) Program Limitations**  
Source: Microsoft Learn - "Control Panel Vendor (CPV) program guide" - https://learn.microsoft.com/en-us/partner-center/cpv-overview  
Verification: Official documentation confirming CPV partners do not have access to integration sandbox

### Documentation Accuracy Statement

All technical procedures, requirements, and limitations documented in this guide are based on official Microsoft documentation and verified through the sources listed above. URL references were validated as of the document creation date. For the most current information, always consult the official Microsoft Learn documentation and Partner Center portal.

### Last Verified

- **Document Version**: 1.1
- **Last Source Verification**: 2025-01-19
- **Microsoft Documentation Version**: Current as of verification date
- **API Version**: Partner Center REST API v1 (current stable)