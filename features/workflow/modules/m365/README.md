# Microsoft 365 Implementation

Developer entry for Graph authentication, workflow modules and controller
inventory/convergence. [The integration guide](../../../../docs/M365_INTEGRATION_GUIDE.md)
owns operator setup and resource declarations; [TESTING](TESTING.md) owns test
credentials and bounded live scenarios. Do not duplicate their procedures here.

## Integration boundaries

- `auth/`: OAuth/token storage, direct application access and explicit partner/GDAP
  access. Credentials are partitioned by the authenticated CFGMS client tenant.
- `graph/`: Graph HTTP client, paging, throttling and object/membership operations.
- `directory_provider.go`: directory-provider integration.
- `entra_user/` and sibling module packages: module implementation surfaces.
- [Controller directory service](../../../controller/directory/): scheduled M365
  inventory and declared-resource convergence. It does not require a steward.

The controller's managed user/group declarations and the forked workflow module
are different paths. A package existing or a Graph client method compiling does
not establish that every module is published/executable or every onboarding step
is wired into the UI/workflow experience.

## Build, Publish, and Resolution (entra_user)

In this source tree, only `entra_user` currently builds to a
runnable binary and resolves end to end through the controller workflow
engine (Issue #4325). `conditional_access` and `intune_policy` (along with
`entra_admin_unit`, `entra_application`, `entra_group`) have no `cmd/main.go`
and cannot be built, published, or executed yet through this external workflow-module path. Controller directory convergence
for `m365-entra-user`/`m365-entra-group` is a separate integration described below.

**Build:**

```bash
make build-workflow-modules   # builds bin/cfgms-module-m365-entra-user
```

This is a separate Makefile list/target (`WORKFLOW_MODULES`) from the
steward-installer `STDLIB_MODULES` payload — workflow-kind modules are never
part of the steward installer (ADR-016 is a closed set) and are instead
published to and pulled from the controller module cache (ADR-006), independently of any future additional module entry points.

**Publish and resolve:** the built binary is wrapped in a publisher-signed
`bundle.Bundle` (`publisher: cfgms`, matching `module.yaml`) and published
through the existing controller module cache APIs
(`features/controller/modules/cache`). Once approved,
`WorkflowModuleFactory.CreateModuleInstance("m365-entra-user")` resolves the
cached bundle, fork/execs the binary, and returns a live gRPC-backed
`modules.Module` — see `features/workflow/module_loader.go` and
`features/workflow/entra_user_e2e_test.go` for the exact flow.

**Tenant resolution:** `entra_user`'s `Set`/`Get` take the CFGMS tenant from
the authenticated workflow execution context (`ctxkeys.TenantID` on `ctx`),
never from a step's `tenant_id` configuration or from a resource ID's own
tenant segment — either of those is only checked for agreement with the
execution context's tenant and refused on mismatch. Credentials
(`SecretStoreCredentialStore`) are partitioned by that same real CFGMS
tenant, not by the caller-supplied M365 tenant identifier.


## Direct and partner authentication

The stored `OAuth2Config` for a CFGMS tenant selects the flow. The shared default
configuration is not a customer-specific delegated grant. Partner fields are
`partner_delegated`, `partner_tenant_id`, `customer_tenant_id` and
`gdap_required_roles`, alongside the partner app's `client_id` and secret.

For partner access, [delegated_token.go](auth/delegated_token.go) obtains Partner
Center access, checks the active/unexpired customer relationship and required
roles, then mints the Graph application token against that customer's authority.
It checks the token tenant claim against the expected customer. Empty required
roles means the relationship still must be active and unexpired; it is not a
request to skip relationship validation. A failure must not silently switch to
the partner directory or another client's credentials.

Interactive/delegated user authentication is a separate provider capability.
Do not describe the customer application-token path as an operator login or infer
production consent from the presence of delegated-auth tests. Inspect
[OAuth config](auth/provider.go), [token flow](auth/delegated_token.go) and their
adjacent tests for the precise scope being changed.

## Validation and limits

Use source-adjacent Graph/auth, directory and module-loader tests. The integration
guide distinguishes inventory (observed unmanaged objects) from declared writes;
licensing, mailbox actions and complete onboarding/offboarding require their own
verified implementation. This reference makes no tenant-capacity, API quota or
production-readiness claim from illustrative examples.
