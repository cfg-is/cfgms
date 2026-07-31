# ADR-025: SaaS-Operator ↔ MSP Tenant Access Boundary

**Status:** Accepted

**Date:** 2026-07-30

**Deciders:** Founder, Architecture

**Related:** Epic [#2858](https://github.com/cfg-is/cfgms/issues/2858) (web tenant & access
administration — this ADR governs its access model). Story
[#3125](https://github.com/cfg-is/cfgms/issues/3125) (tenant list/update/delete API — its
proposed shared subtree-check helper is extended here). Story
[#3131](https://github.com/cfg-is/cfgms/issues/3131) (tenant admin tree UI — blocked pending
this ADR; the reason this ADR exists). ADR-027 (Tenant Suspension, Archive, and Cascading
Deletion Lifecycle — the sibling decision covering *what happens inside* a tenant subtree;
this ADR covers *who gets in from outside it*, a deliberately separate concern). ADR-021
(Identity Assurance Levels — break-glass and step-up compose with `AssuranceStrong`, not with
a parallel mechanism). CLAUDE.md Threat Model (rarely-touched, blast-radius-bounding config
knobs — `module_trust.mode` is the existing precedent this ADR's config toggles follow) and
Multi-Tenancy section (the recursive parent-child path model this ADR narrows).

---

## Context

### The current model grants ancestors default access to every descendant

CFGMS's tenant model is a recursive parent-child tree with path-based identification
(`root/msp-a/client-1/servers`, CLAUDE.md). Server-side scope enforcement — where it
exists — uses the same prefix-match shape in multiple handlers: `id == callerTenant ||
strings.HasPrefix(id, callerTenant+"/")` (e.g. `handlers_stewards.go:142`,
`handlers_push.go:113`, `handlers_fleet.go:70`, `handlers_ip_trust.go:105`, among others).
The config-store layer's `checkCrossTenant` (`pkg/configrouting/providers/controller/
router.go:243-264`) calls `tenantStore.IsTenantAncestor` and permits an ancestor to read a
descendant's config. This is deliberate and correct **within** an organization: an MSP
administrator scoped to `root/msp-a` is expected to see and manage `root/msp-a/client-1`.

It is not correct **at the top of the tree** in a multi-tenant SaaS deployment. `root` is
the SaaS operator's own scope. Under the existing rule, a principal scoped to `root`
automatically has the same descendant access to `root/msp-a` (and everything below it) that
`root/msp-a` has to its own children — there is no gate between "the company that operates
the SaaS platform" and "a customer's entire business." One handler currently has no check at
all: `handleGetTenant` (`features/controller/api/handlers_tenants.go:44-64`) performs no
subtree check whatsoever — any caller holding `tenant:read` can fetch any tenant by ID,
regardless of ancestry. Story #3125 already flags this as an unresolved defect and proposes
introducing a shared subtree-check helper. This ADR decides what that helper — and the
`root` boundary specifically — must enforce.

### Why this matters more than an ordinary access bug

An MSP's CFGMS tenant is not a sandbox — per the founder, "an MSP's tenant is likely to be
what they run their business on." Default visibility from the SaaS operator's root scope
into that tenant is a standing trust assumption CFGMS has never asked customers to make
explicitly. It also cuts against CLAUDE.md's own threat model framing: rarely-touched
settings should "bound the blast radius of admin or controller compromise." Today a
compromised root-scoped credential at the SaaS operator has that blast radius by
construction, with nothing to bound it.

### What does not exist today that this ADR needs

- **No cross-tenant consent or elevation mechanism.** `emergency.break-glass`
  (`features/rbac/templates.go:332-354`, `features/rbac/defaults.go:229-234`) is a real,
  tested, time-boxed (4h) RBAC permission template — but it grants `emergency.access` "on
  system resources only." It is not a tenant-crossing mechanism and this ADR does not
  overload it; a new, analogous permission is needed for crossing the root↔MSP boundary
  specifically.
- **No per-tenant "allow support access" grant.** Nothing today lets an MSP administrator
  explicitly permit the SaaS operator into their tenant, time-boxed and revocable.

### Scope decided in conversation with the founder (2026-07-30)

1. **`root` stays a real tenant node.** It is not removed from the path model or renamed —
   it remains useful for SaaS-operator-level operations (billing, cross-MSP ops). It is
   *walled off* from MSP subtrees by default, not eliminated.
2. **The boundary is exactly one seam: `root` ↔ its immediate MSP children.** It is
   deliberately **not** recursive at every parent/child level. An MSP's own default
   visibility into its clients' sub-tenants is unchanged — today's ancestor-inherits-
   descendant behavior continues to apply below `root` exactly as it does now.
3. **This is its own ADR, decided before #3131/#2858 continue** — not an interim rule bolted
   onto the tenant-admin-tree story. #3131 stays blocked until this ADR is accepted and its
   body is rescoped against it.
4. **A narrow, transparent logging/metrics carve-out exists independent of the access
   boundary** (Decision 4) — the boundary gates *administrative* access into a tenant's
   config and resources; it does not blind the SaaS operator to platform-level security and
   operability signals.

---

## Decision

### 1. A single, named boundary — not a general recursive rule

The existing ancestor-prefix-match rule (`id == callerTenant || HasPrefix(id,
callerTenant+"/")`) is **suspended specifically when `callerTenant` is the root tenant path
and the target is a descendant of it** (i.e. `target != root && strings.HasPrefix(target,
rootPath+"/")`). Every other ancestor/descendant pair — `root/msp-a` looking at
`root/msp-a/client-1`, `root/msp-a/client-1` looking at `root/msp-a/client-1/servers`, and so
on — is **unchanged** and keeps today's behavior. This is one boundary check, not a rewrite
of the general scope-matching helper, and it composes with (rather than replaces) the shared
subtree-check helper #3125 already proposes introducing for `handleGetTenant` and friends.

### 2. Crossing the boundary requires an explicit, auditable grant

Two distinct mechanisms, both logged via `pkg/audit` and both visible to the MSP whose
boundary was crossed (surfaced in their own tenant activity/audit view, not hidden from
them):

- **(a) Client-granted access.** An MSP administrator, from inside their own tenant scope,
  explicitly enables a support-access grant (e.g. "Allow CFGMS support access for
  troubleshooting"), time-boxed with an expiry, and revocable at any time. This is the
  preferred path and requires no root-side justification, because the customer opted in.
- **(b) Break-glass access.** A SaaS-operator principal invokes an emergency, time-boxed
  elevation without a prior grant (security incident, legal request, billing dispute).
  Modeled on the existing `emergency.break-glass` shape (time-boxed permission assignment,
  `features/rbac/engine.go:72` already enforces `ExpiresAt`) but as a **new**,
  tenant-crossing-specific permission — not a reuse of the system-resource-only template.
  Requires a mandatory recorded justification string; whether it additionally requires a
  second approver by default is a PO/founder tunable (see Remaining Tunables).

Neither mechanism grants standing access: both expire, and expiry ends the elevation without
requiring an explicit revoke.

### 3. Enforcement lives in the shared subtree-check helper, not scattered per-handler

The shared `isWithinTenantScope`-shaped helper #3125 already proposes (to fix
`handleGetTenant`'s missing check, among others) is the single place this boundary is
enforced. It must reject — with a step-up-shaped challenge per ADR-021's composition model,
not a bare 403, so a legitimate break-glass invocation has a clear path forward — any
`root`-scoped caller reaching into a descendant path without an active grant or break-glass
session flag. A caller with an active grant/break-glass session is allowed through exactly as
an ordinary ancestor would be, for the lifetime of that elevation.

### 4. A narrow, transparent security/platform log and metrics carve-out

The access boundary gates **administrative access to a tenant's own config, resources, and
business data.** It is not a blindfold on the SaaS operator's ability to run the platform
safely. A defined, narrow allowlist of signal categories remains visible to `root` **at all
times, independent of any grant or break-glass session**:

- Authentication failures, account lockouts, and suspicious-login patterns on MSP admin
  accounts.
- Break-glass and access-grant usage itself — the meta-log of when and why the boundary was
  crossed. (This must be root-visible by construction, or root could not audit its own
  break-glass usage.)
- Abuse and resource-exhaustion signals — rate-limit trips, anomalous API volume, and similar
  platform-health indicators.
- Billing and subscription state changes, including non-payment flags (this is also what
  drives the non-payment suspension trigger in ADR-027).
- **System/platform logs and metrics generally** — operational telemetry, performance
  metrics, and platform-level system logs needed to run and support the SaaS deployment.

**Explicitly not carved out:** ordinary business/config audit trail — e.g. "MSP created
client tenant X," "admin changed config value Y." That is normal business activity and stays
behind the boundary; the carve-out is for platform operability and trust-and-safety signals,
not a backdoor into tenant administration.

**Design constraints:**

- The carve-out is a **narrow, explicit allowlist of audit-event/metric categories**, not
  "everything above some severity." Growing it is a founder decision, not a reviewer's
  judgement call — the same posture ADR-021 takes with its `RequireUserPresence` set.
- **Visibility is bidirectionally transparent.** An MSP can see that (and roughly when) root
  viewed a carved-out signal about them, the same way they can see break-glass or grant
  usage. There is no silent, root-only visibility.
- Carve-out entries must avoid leaking sensitive business/config content — e.g. "auth failure
  for user X at time Y," not "auth failure while accessing config value Z."
- **Pull, not push, for v1.** A carved-out signal is queryable/visible at all times (during
  an investigation, a billing review, or routine platform monitoring). Real-time alerting
  into the existing `AlertCenter`/notification path is a later increment, not part of this
  ADR's decision.

---

## Non-Goals

- **Not designing the client-grant UI in this ADR.** The "allow support access" surface
  inside an MSP's own tenant view is a follow-on story once this ADR is accepted.
- **Not extending the access boundary recursively below `root`.** Explicitly decided
  (Context, axis 2): an MSP's default visibility into its own clients' sub-tenants is
  unchanged.
- **Not building real-time alerting on the logging carve-out.** Pull/queryable only for v1
  (Decision 4).
- **Not covering tenant suspension, archival, or deletion.** That is ADR-027's concern
  entirely; this ADR only governs who may look into or act on a tenant from outside its own
  subtree.

---

## Consequences

### Positive

- Closes the default-access gap the founder identified: a compromised or merely careless
  root-scoped credential at the SaaS operator no longer has standing access into every
  customer's tenant tree.
- Composes with existing machinery rather than inventing parallel systems: break-glass
  mirrors the existing `emergency.break-glass` shape; the boundary check slots into #3125's
  already-planned shared helper; elevation can be gated at `AssuranceStrong` per ADR-021
  rather than defining a new auth concept.
- The platform keeps the operability and trust-and-safety visibility it actually needs
  (abuse detection, billing state, security signals) without that visibility doubling as
  general tenant access — the two concerns don't get conflated into one permission.

### Negative / costs

- **New state required.** Client-grant records and break-glass session flags/audit entries
  need a store, plus a defined, versioned allowlist for the logging/metrics carve-out.
- **#3125's `handleGetTenant` (and sibling handlers') subtree check** must be implemented
  against this boundary from the start, not the plain ancestor-prefix rule.
- **#3131's tenant admin tree UI** must not render descendant tenants' detail at all for a
  `root`-scoped session without an active grant/break-glass flag — a boundary/empty state,
  not just hidden action buttons.
- **Break-glass and client-grant both need an audit-visible surface on the MSP side** — real
  UI work beyond what #2858 currently scopes, and should be called out explicitly when
  #2858's body is updated.

### Migration / Sequencing

- **#3125 is not yet merged.** Its read/update/delete endpoints must be designed against this
  ADR from the start. Its proposed shared subtree-check helper is the correct enforcement
  point for Decision 3 above and should be extended, not duplicated.
- **#3131 stays Blocked** pending this ADR's acceptance and a rescoped story body.
- **#2858's epic body needs a note** that this ADR governs its access model, and that a
  client-grant UI and break-glass audit surface are in its scope even though they weren't
  called out in the epic's original stories.

---

## Remaining tunables (PO-set, founder may override)

1. **Whether break-glass requires a second approver by default** — this ADR requires
   break-glass to be time-boxed and justified/audited, but does not fix whether it
   additionally needs dual approval.
2. **Exact permission names** (e.g. `tenant:cross-boundary-access`, `tenant:break-glass`) —
   left to the implementing story, following existing RBAC naming conventions in
   `features/rbac/defaults.go`.
3. **Whether client-granted access defaults to a fixed expiry** (e.g. 24h, renewable) or
   stays open until the MSP explicitly revokes it.
4. **The exact carve-out allowlist's final shape** — the category list in Decision 4 is
   founder-confirmed at the level described; the precise audit-event-type enum is an
   implementation detail for the story that builds it.
