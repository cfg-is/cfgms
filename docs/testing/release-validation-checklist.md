# Release Validation

Use this evidence checklist for the release being assessed. The
[roadmap](../product/roadmap.md) owns beta/launch scope; existing tests or an old
checked-off story do not establish acceptance. Define the release's actual
platform/backend/integration matrix before running checks.

## Code and artifact gates

- [ ] Required CI checks ran for real at the intended revision/merge context;
  distinguish stubbed contexts, credential-dependent skips and deferred jobs.
- [ ] Relevant unit, integration, architecture, frontend, lint and security checks
  passed. Use [the validation map](testing-strategy.md) and current Makefile.
- [ ] Intended platform artifacts build and their provenance/checksums are verified.
  See [artifact verification](../deployment/release-artifact-verification.md).
- [ ] Changed docs, schemas, loader consumers, local links and examples agree with
  shipped behavior and clearly distinguish approved future scope.

## Operator journeys

- [ ] Install and enroll the required steward OS targets using the maintained
  installer/trust path; verify identity survives upgrade and reconnect.
- [ ] Upgrade/recover the controller using the supported service procedure; test
  serving-node outage/routing separately from leader change for a cluster.
- [ ] Complete an authenticated controller-to-steward query and handle offline,
  timeout, denied and partial results visibly.
- [ ] Deliver governed configuration, observe drift/enforcement behavior, and
  verify effective-state provenance and failures with the included modules.
- [ ] Execute required workflow blocks/approval paths with correct trigger/user
  scope and audit results; interrupted progress/history is not automatic resume.
- [ ] Validate the query workspace and agentic cockpit requirements for the
  chosen release. UI scaffolding is not the investigation loop.
- [ ] Validate the declared Microsoft 365 operations and, when required by release
  scope, PAX8/HaloPSA workflows end to end. Existing inventory/user modules do not
  prove licensing procurement, reconciliation or complete offboarding.

## Security and recovery

- [ ] Exercise authorization, tenant/client isolation, required assurance/proof,
  wrong-target refusal and relevant credential/trust failure cases.
- [ ] Verify logs, optional alerting, partial failures and recovery instructions;
  no invisible failures or fabricated success from unavailable data.
- [ ] Test a backend-consistent backup/restore and compatible binary rollback for
  the deployed shape. Keep credentials protected and do not reset identities to
  conceal an upgrade defect.

## Evidence and decision

Record each scenario's revision, environment, actual result, skips and unresolved
findings. Native platform/live service tests need appropriate credentials and
infrastructure. A reduced local run or old measured result is useful bounded
evidence, not a passing release matrix. There is no fixed completion time or
universal performance guarantee in this checklist.
