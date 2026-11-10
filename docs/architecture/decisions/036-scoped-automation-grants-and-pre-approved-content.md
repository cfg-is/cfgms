# ADR-036: Scoped Automation Grants and Pre-Approved Content

**Status:** Accepted; amended 2026-11-10 (Amendment 1)

**Date:** 2026-10-23

**Deciders:** Founder, Architecture

**Related:** ADR-021 §8 (automation terminal at `AssuranceMachine`), ADR-021 Amendment 2 and the operator-payload signing cross-reference (#3695), ADR-025 (tenant access boundary), ADR-022 (entity graph / case workflow), Epic #5300 (web admin parity), Epic [#5421](https://github.com/cfg-is/cfgms/issues/5421), Epic [#5980](https://github.com/cfg-is/cfgms/issues/5980) (Amendment 1).

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

A script **requests** pre-approval with a declaration in its header comment block. The declaration is a request. The declaration is required in every approval mode: content without it is never run by an automation grant, whatever its signature or approval state. Whether it is enough to grant pre-approval depends on the library's approval mode (§2).

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

§8's "no exception mechanism" is replaced by this ADR. Machine principals have exactly two elevation paths: automation grants (§3) and the rollout credential ([Amendment 1](#amendment-1-2026-11-10-rollout-credential-for-continuous-deployment)). Automation grants never reach a permission that requires presence.

This ADR governs machine principals only. AI agents that act as operators are treated as users with their own accounts, not as machine principals; that model needs its own decision (see the roadmap entry for agent user accounts).

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

---

## Amendment 1 (2026-11-10): Rollout credential for continuous deployment

**Implementation status:** not yet built. Delivered by fix [#6053](https://github.com/cfg-is/cfgms/issues/6053) (binary approval) and stories [#6065](https://github.com/cfg-is/cfgms/issues/6065), [#6066](https://github.com/cfg-is/cfgms/issues/6066), [#6067](https://github.com/cfg-is/cfgms/issues/6067), [#6068](https://github.com/cfg-is/cfgms/issues/6068) and [#6069](https://github.com/cfg-is/cfgms/issues/6069) under Epic #5980.

### Context

Continuous deployment publishes a steward binary, approves it and rolls it out with no human acting per build. Ordinary API keys can already publish binaries, dispatch upgrades and start rollouts (#5298 kept them working). They cannot approve a binary: the approve route requires a presence tap and refuses machine principals (#6053), and every upgrade path requires an approved binary. §3 grants do not cover this either, because their actions are limited to reads and pre-approved content.

### Decision

1. **Rollout credential.** A rollout credential is an API key with the explicit kind `rollout`, stored on the key record. Only a dedicated route sets the kind; the generic API-key route cannot. An admin mints it once with a presence tap and must already hold every permission it receives. It is bound to the admin's tenant, has a required expiry within a fixed maximum, is shown once and can be revoked at once. The kind is never inferred from a permission set.
2. **Permissions.** Exactly `installer:publish:steward`, `installer:dispatch:steward`, `installer:read` and `monitoring:write-markers`. It cannot approve a binary through the approve route, change any setting or mint credentials.
3. **Per-cell opt-in.** Each controller cell has an "unattended rollouts" setting. It is off by default, changing it requires a presence tap, and every change is audited. While it is off, the rollout credential is refused on binary publish, upgrade dispatch and rollout start. The setting does not affect other API keys.
4. **Automatic approval.** A binary published by the rollout credential while the setting is on, whose publisher signature verified at publish, is approved automatically. The approval is a durable record bound to the SHA-256 of those bytes, with `approved_by` set to `unattended:<credential-id>`, and it is audited as its own action. Different bytes need a new approval. Turning the setting off later does not revoke approvals already recorded.
5. **Accepted for any deployment.** This is the accepted continuous-deployment path for every cell, including hosted SaaS cells. Each cell opts in through its own setting.

### Threat-model bounds

A stolen rollout credential:

- can roll out only binaries signed by a publisher key the controller already trusts; the credential holds no signing key;
- cannot reach a steward that verifies signatures itself (`module_trust.mode: strict`) with anything that steward does not trust;
- acts only within its tenant;
- stops working when it expires, is revoked, or the cell's setting is turned off;
- leaves an audit record and a deploy marker for every publish, approval, rollout and halt.

The cell setting is the rarely touched control that bounds this. A phished admin who turns it on must tap, and the change is audited.

### Consequences

- Continuous deployment needs one tapped setup step per cell (mint the credential and turn the setting on), then runs with no human per build.
- A second machine principal kind exists beside automation grants, and RBAC, assurance and audit treat it explicitly.
- The publisher signing key, not the credential, is the trust root for what reaches stewards. Protecting that key is the deployment pipeline's responsibility.

