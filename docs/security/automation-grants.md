# Automation Grants: Threat Model and Residual Risks

This guide covers the security properties of automation grants and pre-approved content as the controller implements them today. [ADR-036](../architecture/decisions/036-scoped-automation-grants-and-pre-approved-content.md) is the decision record. The [controller operating model](../architecture/controller-operating-model.md#automation-grants-and-pre-approved-content-adr-036) describes the mechanics and the [REST API guide](../api/rest-api.md#automation-grants-and-approvals) lists every route.

Every script runs as SYSTEM on the endpoint. The question this design answers is which approval a script or workflow needs before it runs with no human tap. A pre-approved version can be run by an automation grant. Nothing else is available to a grant: it reads, and it runs pre-approved content.

**Wiring status.** The controller composition root does not yet install the grant store, the script-step approver for restricted workflow runs or the tenant notify channel resolver. Until it does, grant routes answer `503`, a grant credential is refused with `401`, and a script step or notify step of a grant-started workflow refuses to run. The approval store, library modes, approvals and workflow publication are installed. The risks below describe the implemented behavior and apply once the grant store is wired.

## What a grant can and cannot do

| Property | Behavior |
|---|---|
| Principal | A machine principal with no permissions, never root scoped, never implicit admin. Credential `cfgag_<id>_<secret>`, accepted only as `Authorization: Bearer`. |
| Creation | Presence tap, strong assurance, audited. Expiry is required and at most 90 days. The secret is shown once; only its SHA-256 is stored, in the secrets provider. |
| Revocation | Strong assurance, no tap. Takes effect on the next call, because every call re-reads the grant. Ends the grant's open runs. |
| Reach | Only the closed route table: begin and end a run, five reads, list and start library scripts, start and read pinned workflow versions. Any other route is refused with `403`. |
| Tenant | Each run is locked to one tenant, which must be the grant tenant or a descendant. Devices must be in exactly the run tenant. |
| Content | Only content that passes the evaluator for the exact version: the header declaration or `preapproved_for_automation` must be present in every mode, and the owner tenant's library mode decides the rest. Scripts that require API scopes are never run by a grant. |
| Endpoint | The steward verifies the library script signature against its own trusted keys. |

## Script steps outside a grant

A human takes a passkey tap to save a workflow and a tap to start one; the steps of a running workflow take no per-step tap. A script step runs outside a grant only from a workflow version published with a tap. The publication, not the script evaluator, covers such a step: it runs the library script pinned by `script_id` and `script_version` in the run's own tenant, and the queue refuses it at dispatch if the content changed after the step queued. The publication is verified at each start, so a scheduled, webhook or API-key run of a published version needs no tap, and risk (d) applies to it. Script steps of nested workflows and of a resumed approval tail are refused outside a grant in v1. The steward's signature check applies to these steps as to every library run.

## Threat model

### Grant theft

An attacker who holds the credential acts as the grant until it expires or is revoked.

What the attacker can do: open runs on any tenant in the grant's subtree, read steward lists and DNA of devices in the run tenant, list the scripts the run tenant can resolve, and run versions that are already pre-approved on devices of the run tenant.

What bounds it:

- The credential expires after at most 90 days and revocation is immediate on every node.
- A grant has at most 5 open runs and at most 20 begin attempts per minute, and a run lasts at most one hour.
- The route table is closed, so the credential cannot push configuration, control services, open a terminal or approve anything. An approval, a library mode change, a grant change and a publication need a human session.
- Content runs only as a pinned version that was evaluated, with params limited to declared literals. The target count is bounded by the tenant's target limit.
- The steward refuses an unsigned library script whatever the controller decided.
- Failed credential attempts are throttled per source address.

Response: revoke the grant (`DELETE /api/v1/automation/grants/{id}`), which also ends its open runs, then review the audit trail for the grant id (see [What to monitor](#what-to-monitor-in-audit)).

### Phished admin

An admin account that is taken over for a short time can do what the admin can do with a presence tap. For this design that is: create a grant, approve a script or workflow version, change a library's approval mode and publish a workflow version.

What bounds it:

- Each of those actions needs a presence tap (a passkey assertion), and publication is the assertion itself over the exact version hash. A stolen cookie or session alone does not carry the tap.
- Approval is bound to the approval hash of one exact version. A later change to the content needs a new approval.
- The library mode is a rarely touched setting. Changing it is tapped and audited, and the audit event is written before the change is applied.
- The controller holds no workflow-signing key, so a compromised controller cannot mint a published workflow version.
- The steward's own trusted keys decide whether a library script runs on the endpoint, and they are not changed by an approval.

Response: revoke the grants the account created, withdraw the approvals it made (`DELETE /api/v1/automation/approvals/{kind}s/...`), set the library modes back and review `content_library.mode_change`, `content_approval.approve`, `automation_grant.create` and `workflow.publish` events for the account. Withdrawing the account's `workflow:publish` permission or disabling the account makes every workflow publication it signed stop verifying.

### Comment mode

In `comment` mode the header declaration alone pre-approves a script (or the `preapproved_for_automation` flag a workflow version), and the repository's own access control is the only protection. A person who can write to the repository can make content that automation will run. See residual risk (c).

## Residual risks

These risks remain by design. They are listed so an operator can decide whether the controls around them are enough.

### (a) The event tenant is declared by the grant holder

The controller cannot verify the triggering external event. The grant holder declares the tenant of the event when it begins a run, and the controller only checks that the tenant lies in the grant tenant's subtree. A holder that is wrong, or compromised, can declare any tenant in the subtree for any event reference.

Bounds: the event reference is bound to the first tenant it is declared for, so the same event can never be re-bound to another tenant (`409`); a grant has at most 5 open runs; begin attempts are rate limited to 20 per minute per grant. These bound how many tenants one credential can touch at once. They do not make the declaration true. Scope a grant to the smallest subtree that works, for example one client tenant, rather than to a broad MSP tenant, when the system that holds the credential cannot be trusted to name the tenant correctly.

### (b) With steward `script_signing.policy` not `required`, approve and comment mode trust the controller

For content that is not a library run, a steward whose `script_signing.policy` is not `required` has nothing independent to check, so the approve and comment mode decision rests on the controller alone.

The exception, verified for every content path a grant can reach today, is the library run: a library script start, a library-script step of a grant-started workflow and a library-script step of a tap-published workflow all queue the script with its library identity and signature. The steward refuses any library script without a valid signature from a key in its own trusted keys, under every policy and trust mode (see [script signing](../guides/script-signing-ci.md)). So for those paths controller approval alone never makes unsigned content run on an endpoint, and a script that is approved in `approve` or `comment` mode but unsigned is refused by the steward instead of run. The residual risk is therefore limited to a path that is not a library run; no such path is reachable by a grant today. Set `script_signing.policy: required` on endpoints of clients that need a guarantee that does not depend on that fact.

### (c) Comment mode makes repository write access equal to SYSTEM execution through automation

In `comment` mode a commit that adds the declaration to a script is enough for automation to run it as SYSTEM on every device of the run tenant that trusts its signature. If the repository's signing pipeline signs what is committed, write access to the repository is execution as SYSTEM.

The mode is opt-in, per tenant and per library, and changing it needs a tap and is audited. There is no parent floor: the mode of a library is set by the tenant that owns it, so an administrator of a client tenant can choose `comment` for that client's own library even when the MSP tenant uses `signed`. A grant created at the MSP tenant that resolves that library runs its content under the owner's mode. Review the `content_library.mode_change` events for each tenant, and prefer `signed` or `approve`.

### (d) Workflow publications have no maximum age

A publication is the passkey assertion over one workflow version. The controller verifies it again at every evaluation and applies no maximum age. A publication lapses only when the version changes or moves tenant, or when the signer loses the passkey, the account or `workflow:publish` in the workflow's tenant. A version published years ago still runs while its signer is intact.

### (e) The grant can read every script of the run tenant and the inherited libraries it can resolve

`GET /api/v1/automation/runs/{run_id}/scripts` lists, for every script in the run tenant's library chain, the identifier, name, latest version, owner tenant, evaluator state, reason and approval hash, whether or not the script is pre-approved. No grant route returns script text, but a holder learns what exists and which versions are pre-approved. The grant can also read the stewards and DNA of devices in the run tenant and the results of the runs it started.

### (f) Restricted workflows: lapse and revocation checks and dispatched steps

In a restricted (grant-started) workflow run, the run guard (run open, grant neither revoked nor expired) runs before every step, and each library-script step is evaluated again under its own owner tenant's mode and records when it is reached, so a withdrawn approval or a changed signature is seen at the next script step. A workflow publication is verified when the run is evaluated and started; a signer that lapses afterwards does not stop a run already in progress. A script step that was already dispatched to a steward when the revocation or lapse happened is not recalled: queued commands are cancelled at dequeue and before dispatch, but a script the steward has started runs to its end.

### (g) The inheritance ceiling is the grant tenant

A run resolves scripts and workflows through the run tenant, then each ancestor up to and including the grant tenant, and never above it. A grant at an MSP tenant can therefore run content owned by the MSP tenant and by every tenant between it and the run tenant, under each owner's mode and records. In `signed` mode the signature must verify under the owner tenant's effective trusted keys and, when the run tenant has trusted keys of its own, under the run tenant's effective keys. A version with no signature, or an owner with no trusted keys, falls back to `approve`, and a signature that is present and does not verify is denied.

## What to monitor in audit

Records of automation calls are filed under the run tenant with the grant id, run id and event reference. Alert on these:

| Event | What to look for |
|---|---|
| `automation_grant.create`, `automation_grant.revoke` | A grant you did not expect, a long expiry, a grant at a broad tenant. |
| `content_library.mode_change` | Any change to `comment` or `approve`, especially for a client tenant's library. |
| `content_approval.approve`, `content_approval.revoke` | Approvals outside the normal change window, and the actor. |
| `workflow.publish` | A publication of a workflow that opts in to automation. |
| `automation.run.begin` (denied) | Reasons `tenant_outside_grant_subtree`, `event_bound_to_other_tenant`, `open_run_cap` and `begin_rate_limit` mean a holder is declaring wrong tenants or events, or is looping. |
| `automation.run.begin` (success) | Many distinct tenants or event references from one grant in a short time. |
| `automation.call` (denied) | Reasons `grant_revoked`, `grant_expired`, `run_not_found`, `run_belongs_to_another_grant`, `query_names_another_tenant` and `body_names_another_tenant` after a revocation or from an unexpected source. |
| `automation.script.run` | Scripts, versions and approval hashes you do not expect; denied runs with `content_not_approved`, `approval_pending` and `target_outside_run_tenant`; unusually large device counts. |
| `automation.script.list` | Frequent enumeration of the library. |
| `automation.workflow.run` | Workflows and versions you do not expect; denied runs with `restricted_validation_failed`. |

Failed grant credential attempts are logged, not audited, and throttled per source address; watch the controller log for `Automation grant credential refused`. A pending change notice by email, and the pending list at `GET /api/v1/automation/approvals/scripts/pending`, show scripts that changed after approval.
