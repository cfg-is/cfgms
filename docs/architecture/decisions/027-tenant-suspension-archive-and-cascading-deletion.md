# ADR-027: Tenant Suspension, Archive, and Cascading Deletion Lifecycle

**Status:** Accepted

**Date:** 2026-07-31

**Deciders:** Founder, Architecture

**Related:** Epic [#2858](https://github.com/cfg-is/cfgms/issues/2858) (web tenant & access
administration — this ADR governs its deletion/suspension model). Story
[#3125](https://github.com/cfg-is/cfgms/issues/3125) (tenant list/update/delete API — its
`DELETE` design is superseded by this ADR's pipeline, and its existing
`ErrTenantHasChildren` check changes meaning, see Decision 2). Story
[#3131](https://github.com/cfg-is/cfgms/issues/3131) (tenant admin tree UI — blocked pending
this ADR; its original mockup's single delete-confirm-with-409 interaction is superseded).
ADR-025 (SaaS-Operator ↔ MSP Tenant Access Boundary — the sibling decision covering *who gets
in from outside a tenant subtree*; this ADR covers *what a tenant's own administrator can do
to their subtree*, a deliberately separate concern). CLAUDE.md Threat Model (rarely-touched,
blast-radius-bounding config knobs — `module_trust.mode` is the precedent this ADR's
dual-control toggle follows).

---

## Context

### Deletion is a real, unrecoverable SQL `DELETE` today, gated only by "no children"

`Manager.DeleteTenant` (`features/tenant/manager.go:220-255`) already refuses to delete the
`default` tenant and already refuses deletion while children exist (`ErrTenantHasChildren`).
But once those two conditions are satisfied, it cascades RBAC cleanup and calls the store, and
`DatabaseTenantStore.DeleteTenant` (`pkg/storage/providers/database/tenant_store.go:241-249`)
issues an unrecoverable `DELETE FROM cfgms_tenants` — despite a stale comment at
`manager.go:253` calling it a "soft delete." There is no hold period and no second approver.
No HTTP route exposes this yet (#3125 is what would add `DELETE /api/v1/tenants/{id}`), which
is exactly why this ADR needs to land before that route is designed rather than after.

`Suspend` (`POST /tenants/{id}/suspend`, already implemented and already reversible) has no
such children check — but it also has no cascade: suspending a parent today does not suspend
its children, and nothing stops a "suspended" MSP's client sub-tenants from continuing to
operate independently, which does not match how suspension needs to work for the reasons
tenants actually get suspended.

### Why this needs to be an explicit lifecycle, not a single delete action

Per the founder: the realistic reasons an MSP tenant gets suspended or deleted are
**non-payment** or **the client has left.** In both cases:

- The operator (whether that's a SaaS-side billing action or an MSP administrator
  offboarding a client) needs to suspend the *entire* affected business relationship in one
  action — an MSP that stops paying has every one of its clients' sub-tenants suspended with
  it, not just its own top-level record. A partial suspension that leaves child tenants
  running defeats the purpose of suspending for non-payment.
- The same logic applies recursively at every level: an MSP offboarding `client-1` needs
  `client-1`'s entire sub-tree (`servers`, `workstations`, whatever exists under it)
  suspended together, not blocked by a "has children" error that forces deleting or
  reassigning them first.
- Because a tenant subtree is "what a business runs on" (ADR-025's framing), the eventual,
  irreversible deletion of that whole suspended subtree needs a deliberate hold period and,
  by default, a second approver — not a single click.

This ADR replaces the current "delete a single childless tenant" model with a **cascading
suspend/archive/restore/delete lifecycle** that operates on a tenant and its entire subtree
as one unit, at any level of the tree.

---

## Decision

### 1. Suspend cascades to the entire subtree; no children check applies

`POST /tenants/{id}/suspend` suspends the target tenant **and every descendant in its
subtree**, atomically, regardless of depth. The existing `ErrTenantHasChildren` check is
**removed from Suspend** — it never applied a real constraint suspension needs; a tenant with
children should always be suspendable, and suspending it must take its children with it.

This applies **at any level**: suspending `root/msp-a` suspends `client-1`, `client-2`, and
everything beneath them; suspending `root/msp-a/client-1` suspends only `servers` and
`workstations` beneath it, leaving `client-2` (a sibling, not a descendant) untouched.

### 2. Cascade-suspended vs. directly-suspended is tracked separately

Each tenant's suspension record carries **why** it is suspended:

- `DirectlySuspended` — this specific tenant was the target of a suspend action.
- `CascadeSuspended(from=<ancestor id>)` — this tenant is suspended purely as a side effect
  of an ancestor's suspend action.

A tenant can be both: independently suspended for its own reason (e.g. a client sub-tenant
already suspended for its own non-payment) and *also* cascade-suspended when its parent is
later suspended. **Restoring an ancestor only lifts the cascade effect it caused** — it never
overrides a descendant's own independent suspension. Concretely: if `client-1` was already
suspended on its own before `msp-a` (its parent) was suspended, restoring `msp-a` un-suspends
`msp-a` and any children that were *only* suspended via that cascade, but `client-1` stays
suspended until it is independently restored. This is founder-confirmed (2026-07-31) as the
correct behavior — cascade actions must never silently discard an unrelated, pre-existing
suspension.

### 3. Deletion operates on a subtree, gated by "fully suspended," not "childless"

The `ErrTenantHasChildren` check is **repurposed, not removed, for Delete**: a delete request
is no longer rejected because children exist — it is rejected unless **the entire target
subtree (the target tenant and every descendant) is already suspended.** A single childless
tenant is simply the size-1 case of the same rule. This replaces #3131's original mockup
interaction (a delete-confirm that 409s with "has children" and stops there) with a
cascading pipeline:

1. **Suspend** (Decision 1) — the only immediately-effective step, cascades to the whole
   subtree, reversible at any time subject to Decision 2's independence rule.
2. **Hold.** A delete request against a tenant whose **entire subtree is suspended** starts a
   single hold-period timer for the whole cascade (`tenant_admin.delete_hold_period`, a
   `Duration` mirroring the `Duration` type already used elsewhere in controller config, e.g.
   `RingSpec.Soak` at `features/controller/config/config.go:48`). The timer is scoped to the
   subtree root the delete was requested against — it is **not** per-node; a child suspended
   moments before its parent does not reach eligibility on a different clock than the rest of
   the cascade.
   - If any part of the subtree is not (yet) suspended when delete is requested — e.g. a
     child was independently restored after the cascade suspend — the delete request is
     rejected with a clear "not fully suspended" error naming the offending descendant(s),
     distinct from a generic failure.
3. **Eligible.** Once the hold elapses and the entire subtree is still suspended, the deletion
   becomes eligible to execute. It does not execute automatically.
4. **Execute, dual-control default-on.** Executing the terminal, unrecoverable delete of the
   whole subtree requires approval from a second distinct principal — not the one who
   initiated the hold — enforced server-side (compare-and-swap on approver identity, not
   client-asserted). Controlled by a new controller config toggle,
   `tenant_admin.delete_requires_dual_control` (bool, default `true`), settable to `false`
   for deployments where a second approver isn't practical (e.g. a single-admin on-prem
   install) — the same shape as `module_trust.mode`: a rarely-touched knob that bounds blast
   radius by default but is not forced on every deployment.
5. **Hard delete, cascaded.** `Manager.DeleteTenant`'s existing SQL delete becomes the
   terminal step, executed for every tenant in the held subtree together, not one node at a
   time. The already-implemented RBAC cleanup cascade and `default`-tenant protection are
   unchanged.

### 4. Cancelling a pending deletion never discards state

Cancelling a delete at the Hold or Eligible step returns the subtree to ordinary Suspended
state (not Active) — an administrator who wants the tenant back must still explicitly
restore it (Decision 2), the same as any other suspension. Cancelling never partially
restores only some of the subtree.

---

## Non-Goals

- **Not covering who is allowed to suspend/delete from outside a tenant's own subtree** —
  that is ADR-025's access-boundary concern entirely. This ADR assumes the caller already has
  ordinary administrative access to the subtree in question.
- **Not fixing the hold-period length or break-glass-style justification requirements for
  delete** — the config toggle and `Duration` field shape are decided here; the default
  values are a PO/founder tunable (see below).
- **Not building a UI in this ADR** — #3131's story body is rescoped separately to reflect
  this pipeline once both this ADR and ADR-025 are accepted.
- **Not changing `default`-tenant protection or the RBAC-cleanup cascade** — both are kept
  exactly as `manager.go` implements them today.

---

## Consequences

### Positive

- Suspension finally does what "suspend an MSP for non-payment" needs: the whole business
  relationship stops together, not just the top-level record.
- Deletion of a real, populated business (an MSP's entire tenant tree, or a departed client's
  sub-tree) is possible without first manually deleting or reassigning every leaf — a
  realistic and previously-blocked operation — while remaining safe: nothing is deleted until
  every affected tenant has been suspended, held, and (by default) approved by a second
  principal.
- The independent-vs-cascade suspension distinction (Decision 2) means restoring a parent can
  never accidentally reactivate a child that has its own, unrelated reason to stay suspended.

### Negative / costs

- **New state required.** Per-tenant suspension provenance (`DirectlySuspended` vs.
  `CascadeSuspended(from)`), a subtree-scoped pending-deletion record (requested-by,
  requested-at, eligible-at, approved-by), and cascade-execution logic (suspend/restore/
  delete walking the whole subtree, not a single row) are all new — this is real storage and
  business-logic work, not a UI-only change.
- **#3125's `DELETE /api/v1/tenants/{id}` design changes** — it cannot be a direct call into
  `Manager.DeleteTenant`. It must initiate or advance the Suspend→Hold→Delete pipeline across
  a subtree, and a distinct approval step/endpoint is needed for dual-control.
- **`POST /tenants/{id}/suspend`'s contract changes** — it must become subtree-cascading and
  return enough information (which descendants were newly cascade-suspended vs. already
  independently suspended) for the UI to render accurately.
- **#3131's tenant admin tree UI** needs cascade-aware suspend/restore affordances, a
  hold-eligibility countdown, a distinct "approve pending deletion" action for the second
  approver, and must render a tenant's suspension provenance (direct vs. cascaded) so an
  admin understands why restoring a parent didn't restore a given child.

### Migration / Sequencing

- **#3125 is not yet merged.** Its delete implementation must be built against this pipeline
  from the start.
- **#3131 stays Blocked** pending both this ADR and ADR-025's acceptance, and a rescoped story
  body reflecting cascade suspend/restore, hold-eligibility, and dual-control approval UX
  (replacing the original mockup's single delete-confirm-with-409 interaction).
- **#2858's epic body needs a note** that this ADR governs its deletion/suspension model.

---

## Remaining tunables (PO-set, founder may override)

1. **Default hold-period length** (`tenant_admin.delete_hold_period`) — no default is fixed by
   this ADR. 30 days is a reasonable starting point to propose at decomposition.
2. **Whether initiating a delete (starting the hold) itself requires dual-control**, or only
   the terminal execute step does — this ADR specifies dual-control on execute (Decision 3,
   step 4); whether the initiating action also needs a second approver is open.
3. **Exact permission names** (e.g. `tenant:suspend`, `tenant:delete`,
   `tenant:approve-delete`) — left to the implementing story, following existing RBAC naming
   conventions in `features/rbac/defaults.go`.
