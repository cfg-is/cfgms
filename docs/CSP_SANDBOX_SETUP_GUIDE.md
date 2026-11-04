# Partner Center Sandbox Setup

Use an eligible Partner Center integration sandbox to test the partner/customer
relationship path without using a production customer as a test fixture. This is
optional development setup, separate from CFGMS deployment and Graph directory
inventory. Sandbox eligibility and portal labels are Microsoft policy; use the
[current Partner Center guidance](https://learn.microsoft.com/en-us/partner-center/developer/set-up-api-access-in-partner-center)
rather than treating a copied portal walkthrough as a permanent product contract.

## Prepare the environment

1. Confirm your partner account is eligible for an integration sandbox and that
   the administrator can create/configure it. A general partner-program account
   or a portal menu appearing is not proof of eligibility.
2. Create the sandbox through Partner Center and record which directory is the
   partner, which is the test customer, and which app registration is being used.
3. Configure the app permissions and consent for the particular Partner Center
   and Graph operations under test. Restrict testing to designated customer
   objects; the sandbox is not a blanket “zero risk” guarantee.
4. Establish the appropriate active GDAP relationship and roles when testing
   that path. Test expiry/missing-role and wrong-customer refusals too.
5. Store application secrets in the approved secret provider. Do not retain
   credentials in examples, shell history, plaintext configuration or reports.

## Connect and verify through CFGMS

Follow [Microsoft 365 integration](M365_INTEGRATION_GUIDE.md) to map existing CFGMS
client tenants to the correct customer directory using the stdin secret interface.
Use [M365 testing](../features/workflow/modules/m365/TESTING.md) for current test
names, credential gates and evidence requirements.

Verify the stored client mapping and the actual API response for each operation.
Partner Center test data, Graph test data and GDAP permission grants are different
things: successful access to one is not proof that all three are provisioned.
Do not copy a documented customer-count limit, published API quota or old portal
label into CFGMS acceptance criteria without current vendor evidence.

When retiring the test environment, remove test connections/objects through their
supported management interfaces and revoke the associated credentials. Preserve
only redacted scenario/results evidence needed to reproduce a product finding.
