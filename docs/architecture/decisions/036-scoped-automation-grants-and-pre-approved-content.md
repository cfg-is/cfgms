# ADR-036: Scoped Automation Grants and Pre-Approved Content

**Status:** Accepted

**Date:** 2026-10-23

**Deciders:** Founder, Architecture

**Related:** ADR-021 §8 (automation terminal at `AssuranceMachine`), ADR-021 Amendment 2 and the operator-payload signing cross-reference (#3695), ADR-025 (tenant access boundary), ADR-022 (entity graph / case workflow), Epic #5300 (web admin parity), Epic [#5421](https://github.com/cfg-is/cfgms/issues/5421).

---

## Context

ADR-021 §8 made automation terminal at `AssuranceMachine` and required a new ADR before any automated flow could do more. That flow now exists: a triage agent that starts on a PSA ticket-creation event with no human present, and gathers information from endpoints by running scripts.

Every script runs as SYSTEM. So the question is not what account a script runs as. It is **which approval a script or workflow needs before it can run without a per-action human tap**.

Three facts shape the decision:

1. MSPs keep their scripts in one git repository. Not every script in it should be runnable by automation.
2. Most MSPs do not sign scripts today. A per-version hash approval alone means every edit in git silently breaks automation until someone re-approves it in CFGMS.
3. A web-only admin builds workflows in the browser and holds no signing key.

## Decision

### 1. Content is tap-required by default; pre-approval is the exception

A script or workflow needs a per-action human tap to run or schedule, unless it is **pre-approved**. A pre-approved script or workflow can be run by an automation grant (§3) with no human present.

A script **requests** pre-approval with a declaration in its header comment block. The declaration is a request. Whether it is enough to grant pre-approval depends on the library's approval mode (§2).

### 2. Each content library has an approval mode

| Mode | A new version becomes pre-approved when |
|---|---|
| `signed` (default) | It carries a valid signature from a key in the tenant's trusted script-signing keys. If the version is unsigned, or the tenant has no trusted keys, the version falls back to `approve`. |
| `approve` | An admin approves that exact version (content hash) with a presence tap. When the content changes, automation runs of it pause, admins are notified with a diff, and re-approval is one tap. |
| `comment` | The header declaration alone is sufficient. The repository's own access control is the only protection. |

Approval is always bound to a content hash. An approval never carries over to a different version.

**Changing a library's approval mode requires a presence tap and is audited.** It is a rarely touched setting that bounds the blast radius of a phished admin.

**The endpoint has the final say.** A steward whose `steward.cfg` sets `script_signing.policy: required` refuses unsigned content in every mode. An MSP can hold sensitive clients to signed content even when a library runs in `comment` mode.

### 3. Automation grants

An **automation grant** is a scoped machine principal, created once by an admin with a presence tap. All human approval happens when the grant is configured, never while it runs.

- **Reach:** a grant is created at a tenant (typically the MSP tenant) and may act in that tenant's subtree.
- **Per-run tenant lock:** each run is bound to exactly one tenant — the tenant of the triggering event (for example, the PSA ticket's client). A run can never act in a second tenant and never crosses a tenant boundary (ADR-025).
- **Actions:** read operations and running pre-approved scripts and workflows. Nothing else. Every other action — config push, service control, terminal, and every permission with a presence requirement — stays human-only.
- **Expiry and revocation:** a grant has an expiry and can be revoked at once. Every run is audited under the grant's identity and the triggering event.

### 4. Workflows published in the browser are signed by the publishing tap

Publishing a workflow version from the web UI requires a presence tap. The WebAuthn assertion is made over the hash of the exact workflow version, using the same ceremony as operator-payload signing (#3695). The assertion **is** the version's signature. The controller stores it with the version and verifies it before any automated run.

The controller holds no workflow-signing key. A compromised controller therefore cannot mint a pre-approved workflow version on its own.

Automated runs execute a pinned, approved version, never "latest". An edit that is not yet published by a tap cannot run without a human.

Workflows synced from git follow the same three approval modes as scripts.

### 5. ADR-021 §8 is amended

§8's "no exception mechanism" is replaced by this ADR. Automation grants are the only machine-elevation path. They never reach a permission that requires presence.

## Non-Goals

- **Limited (non-SYSTEM) run accounts on endpoints.** All scripts run as SYSTEM. This may be revisited later.
- **Remediation by automation.** Fix actions stay human-tapped in this version.
- **Ticket-scoped access.** An investigation scoped to one ticket, with devices added as they are confirmed in scope, is a later refinement of §3. It narrows a grant and does not replace it.

## Consequences

**Positive**
- A triage agent can work end to end from a PSA event with no human in the loop, inside a bounded scope.
- Signed libraries update from git with no CFGMS re-approval.
- An unsigned git edit cannot silently change what automation runs, except in the opt-in `comment` mode.

**Negative / costs**
- `approve` mode pauses automation on every content change until someone taps.
- `comment` mode makes repository write access equal to fleet-wide SYSTEM execution through automation. This is opt-in, the mode change is tapped and audited, and stewards can refuse it.
- A new principal type (automation grant) touches RBAC, assurance, audit and tenant scoping.

## Prerequisite

Saved-script (library) runs must work end to end before any of this is built: the controller must wire the script library and forward the library script's identity and signature to the steward (Issue #5422).
