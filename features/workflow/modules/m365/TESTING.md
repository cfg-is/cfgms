# Microsoft 365 Integration Testing

Use a dedicated test directory and bounded identities for live Graph/partner tests.
Local source tests and interactive/live credentials establish different evidence.
The [operator setup guide](../../../../docs/M365_INTEGRATION_GUIDE.md) owns tenant
connections and permissions; it is not repeated here.

## Local tests

```bash
go test -short ./features/workflow/modules/m365/auth ./features/workflow/modules/m365/graph
go test -short ./features/workflow/modules/m365/entra_user
```

Read skip/output results: a passing process with skipped credential-gated tests
is not a live integration result. Fake values do not prove Graph consent or GDAP.

## Credential-gated tests

The auth integration tests read `M365_CLIENT_ID`, `M365_CLIENT_SECRET` and
`M365_TENANT_ID`; scenario tests also use `M365_TEST_USER_UPN`. The user module
integration tests have their own credential/skip checks in
[integration_test.go](entra_user/integration_test.go). Inspect those checks before
running a live scenario; do not set `ALLOW_SKIP_INTEGRATION` to manufacture a pass.

Load credentials through the approved secret mechanism into the process
environment, never a committed or plaintext `.env` file. Keep tokens/passwords
out of logs and output. Clear temporary environment bindings after the test.

```bash
go test -v ./features/workflow/modules/m365/auth -run '^TestDelegatedPermissionsIntegration$'
go test -v ./features/workflow/modules/m365/auth -run '^TestDelegatedPermissionsScenarios$'
```

These names identify existing tests, not a claim that every subtest contacts the
remote service. Read their bodies and record actual API calls, skips, consent
and environment. Interactive callback tests depend on their configured redirect
URI and browser context; an example localhost URI is not a production default.

For user-write tests, use expendable test objects and inspect the test's cleanup
and mutation behavior before supplying a live directory. For GDAP, verify the
partner/customer relationship and the customer token authority with dedicated
partner test credentials. Sandbox Partner Center access alone does not establish
Microsoft Graph write access.

## Evidence to retain

Record revision, scenario, tenant environment classification, permissions/consent,
pass/fail/skip outcomes and observed inventory/convergence effects without retaining
credentials or client-identifying data. Verify failure isolation and wrong-tenant
refusal as well as success. A local test suite does not establish complete M365
onboarding/offboarding, licensing or production readiness.
