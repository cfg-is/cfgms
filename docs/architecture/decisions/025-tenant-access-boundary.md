# ADR-025: SaaS-Operator ↔ MSP Tenant Access Boundary

**Status:** Accepted

**Date:** 2026-07-30

**Amended:** 2026-08-01 — [Amendment 1](#amendment-1-2026-08-01--boundary-check-must-use-ancestry-lookup-not-path-prefix-matching):
Decision 1's boundary mechanism (`strings.HasPrefix` on tenant IDs) cannot work — tenant IDs
are not paths — and is replaced with an `IsTenantAncestor`-based check.
**Amended:** 2026-08-09 — [Amendment 2](#amendment-2-2026-08-09--a13-resolved-approach-a-decision-123-implemented):
A1.3 resolved (explicit root-scope marker, never inferred from an empty tenant); Decisions
1-3 implemented (`authorizeTenantAccess`, `TenantCrossingStore`, step-up challenge).

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

---

## Amendment 1 (2026-08-01) — Boundary check must use ancestry lookup, not path-prefix matching

Surfaced during adversarial BA/Tech Lead/Security review of story #3158 (the ADR-027
backend), independently verified from three angles before this amendment was drafted.

### A1.1 — The premise this ADR (and the code it cited) inherited is wrong

Decision 1 suspends the existing `id == callerTenant || strings.HasPrefix(id,
callerTenant+"/")` rule specifically for `root` — but that rule assumes tenant IDs are
slash-delimited paths (`root/msp-a/client-1`), matching CLAUDE.md's own Multi-Tenancy
description. **They are not.** A tenant ID is validated as a single DNS-label-style token
(`k8sNameRegex = ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`, `features/tenant/manager.go:414`, ≤63
chars, `generateTenantID` strips everything but `[a-zA-Z0-9_-]`) — it can never contain a
`/`. Hierarchy is carried entirely by a separate `ParentID` field, resolved via
`IsTenantAncestor`/`GetTenantPath`, never by string concatenation.

The already-merged `isWithinTenantScope` (`features/controller/api/middleware.go:232-239`,
landed via #3147/#3148) makes the consequence concrete:

```go
func isWithinTenantScope(callerTenant, resourceTenant string) bool {
	if callerTenant == "" {
		return true
	}
	return resourceTenant == callerTenant ||
		strings.HasPrefix(resourceTenant, callerTenant+"/")
}
```

The `HasPrefix` branch can **never evaluate true** against real tenant IDs — it is dead
code today, and every existing handler cited in this ADR's Context (`handlers_stewards.go`,
`handlers_push.go`, `handlers_fleet.go`, `handlers_ip_trust.go`) that relies on the same
prefix-match shape has the identical gap. Decision 1 as originally written
(`strings.HasPrefix(target, rootPath+"/")`) would have inherited the same dead mechanism —
a faithful implementation of the original text would silently enforce nothing.

### A1.2 — Corrected Decision 1: ancestry via `IsTenantAncestor`, not string comparison

The boundary check must call `IsTenantAncestor(ctx, callerTenant, resourceTenant)`
(`business.TenantStore` interface method, `pkg/storage/interfaces/business/tenant_store.go:31`;
exposed at the manager layer via `features/tenant/manager.go:277-279`) to determine
descendant relationship, not string matching. This is a materially different shape than the
original text implied: ancestry resolution requires a `context.Context` and a store
round-trip, not a pure string function. **#3125's shared subtree-check helper (Decision 3)
must be built with this dependency from the start** — it cannot stay the zero-dependency
pure function `isWithinTenantScope` is today.

The exact-match branch (`resourceTenant == callerTenant`) and the empty-`callerTenant`
branch (unscoped access) are unaffected by this amendment — only the prefix-match branch is
replaced.

CLAUDE.md's Multi-Tenancy section description ("path-based identification
(`root/msp-a/client-1/servers`)") is inaccurate against the current implementation. This
amendment does not correct CLAUDE.md itself (out of this ADR's scope, and CLAUDE.md changes
need their own story justification per repo convention) — flagging here so the discrepancy
isn't silently rediscovered again.

### A1.3 — Open question this amendment does NOT resolve: identifying a "root-scoped caller" at all

Even with A1.2's fix, Decision 1 and Decision 3 both presuppose the enforcement point can
tell "a principal genuinely scoped to the `root` tenant" apart from "a principal with no
tenant scope at all." Today it cannot: mTLS admin principals — the primary SaaS-operator
access path — are constructed with `TenantID: ""` unconditionally
(`features/controller/api/middleware.go:205-225`, deliberate per that code's own comment,
tied to a prior incident (CFG-70-02) where hardcoding a fallback tenant broke cross-tenant
admin reads). `isWithinTenantScope`'s empty-`callerTenant` branch already treats that as
"unrestricted access," which is correct for today's actual unscoped-superadmin case — but
it means no principal in the system currently presents as "scoped to `root`" in the sense
Decision 1 requires, so the boundary has nothing to trigger on in practice even once A1.2
ships.

This is a real, unresolved design question, not a mechanical bug — options include (a)
introducing a genuinely `root`-scoped principal type distinct from unscoped-superadmin, (b)
treating empty-`callerTenant` as equivalent to `root`-scoped for boundary purposes (changes
today's "unrestricted access" semantics for every existing empty-`callerTenant` caller,
including cross-tenant admin reads the CFG-70-02 fix depends on), or (c) something narrower
scoped to specific admin-session types. **Left open for #3125 (or a follow-on decision) to
resolve before Decision 1 can be considered actually enforced** — added as Remaining Tunable
5 below.

### Consequences of the amendment

- #3125 cannot deliver a working ADR-025 boundary check by simply calling the existing
  `isWithinTenantScope` — it must extend/replace it with an `IsTenantAncestor`-based version
  per A1.2, and cannot mark Decision 1 "implemented" until A1.3 is also resolved.
- #3158 (and any other story whose acceptance criteria assume the boundary check works)
  should treat that criterion as blocked on #3125 resolving both A1.2 and A1.3, not merely
  on #3125 merging.
- No change to this ADR's actual policy (Decisions 2, 4; Non-Goals; Consequences) — only the
  Decision 1 mechanism and the newly-surfaced A1.3 gap.

### New Remaining Tunable (added by this amendment)

5. **How to identify a `root`-scoped caller distinctly from an unscoped superadmin (A1.3)**
   — genuinely open; the implementing story must propose an approach for founder sign-off
   rather than assume one.

---

## Amendment 2 (2026-08-09) — A1.3 resolved (approach (a)); Decision 1/2/3 implemented

Founder sign-off on A1.3, 2026-08-08, recorded on #3125/#3228 (#3228 folded into #3125
and closed as not planned once the deadlock — each story blocked on the other's output —
was recognized). This amendment records the decision and what #3125 built against it.

### A2.1 — A1.3 decision: approach (a), an explicit marker, never inferred from an empty tenant

Approach (b) (Amendment 1's alternative — treating `callerTenant == ""` as `root`-scoped)
is **rejected**. A root-scoped SaaS-operator principal is identified by an **explicit
marker set only at issuance**, distinct from — and never derived from — `TenantID` being
empty or `GlobalScope` being true.

**Precedent this extends, not invents.** Half of approach (a) already shipped under Issue
\#2919: `RootScope bool` on web accounts (`handlers_web_accounts.go:57-68`), stated
outright as "must be set explicitly at creation — an empty TenantID alone never grants
root scope (defense-in-depth)," enforced mutually-exclusive with `tenant_id`
(`handlers_web_accounts.go:317`), and consumed at session-build time
(`middleware.go:418-428` computes `globalScope = acct.RootScope`, not from tenant
emptiness). This amendment finishes that pattern on the two human auth paths that never
got it:

- **mTLS admin certs.** `Principal.RootScoped bool` (`middleware.go:81-99`) is read from a
  new certificate extension, `cert.RootScopeMarkerOID` = `1.3.6.1.4.1.99999.1.2`
  (`pkg/cert/root_scope_marker.go`), sibling to `AdminMarkerOID` (`.1.1`,
  `pkg/cert/admin_marker.go`). `extractAdminPrincipal` sets
  `RootScoped: cert.HasRootScopeMarker(peerCert)` (`middleware.go`, immediately after the
  existing unconditional `TenantID: ""` assignment) — `TenantID` itself is untouched,
  matching A1.3's own framing that both an unscoped superadmin and a root-scoped operator
  present `TenantID == ""` and are disambiguated by the new signal alone. No production
  issuance path sets the marker yet (`cert.SetRootScopeMarker` exists, following
  `SetAdminMarker`'s restricted-caller convention, but has no allow-listed caller in this
  story) — every admin cert issued to date, and every one issued by today's Story
  B/D flows, is unaffected and continues to present as an unscoped superadmin.
- **cfg-CLI Bearer sessions.** `session.Session.RootScoped bool`
  (`pkg/session/contract.go`) is set only by a new `Manager.IssueRootScoped(ctx,
  principalID, connectionName)` method (`pkg/session/manager.go`) — a sibling to `Issue`,
  not a parameter added to it (`Issue`'s 4-arg signature has 47 call sites across the
  repo; changing it was rejected as unnecessary blast radius). `IssueRootScoped` always
  issues with `TenantID: ""`, exactly like `Issue`, and there is deliberately no method to
  flip `RootScoped` on an already-issued session — only fresh issuance by a caller that
  has independently verified the principal is a legitimate root-scoped operator may set
  it. Persisted through both durable session-token stores (`root_scoped` column,
  `pkg/storage/providers/sqlite/schema.go` and `.../database/schemas.go`, both
  back-filled for pre-existing installations) so the marker survives `Validate`/`Renew`
  round-trips, not just the initial `Issue` response. No production call site invokes
  `IssueRootScoped` yet, for the same reason as the cert path above.

### A2.2 — Why not (b): the measured blast radius that ruled it out

On the `develop` tip this amendment was written against, an empty `callerTenant` is
load-bearing at **31 explicit branches across 14 files** in `features/controller/api/` —
4 written as `callerTenant == ""`, 27 as the inverse guard `if callerTenant != ""
{ …scope… }` — plus `isWithinTenantScope` (`middleware.go:255-261`), whose own first line
is `if callerTenant == "" { return true }`, reached from 14 further call sites. Treating
that condition as "scoped to `root`" (approach (b)) would have changed what every one of
those branches means, including the CFG-70-02 admin-read behaviour A1.3 itself cites
(`middleware.go`'s comment on `extractAdminPrincipal`: hardcoding a fallback tenant once
made `handleListStewards` return zero records for an admin on a deployment with
non-default tenants). Approach (a) touches none of those 31 branches or
`isWithinTenantScope`'s empty-caller return — confirmed by the full `features/controller/api`
test suite passing unchanged.

**`GlobalScope` is not the A1.3 marker either**, for two reasons recorded here so the
distinction doesn't get re-collapsed later: (1) post-Issue #3194 (PR #3240), the bearer
path computes `globalScope := sess.TenantID == ""` — deriving cross-tenant visibility
*from tenant emptiness*, the exact ambiguity A1.3 exists to resolve; a principal that is
`GlobalScope=true` under that rule is merely "unscoped," not "scoped to `root`." (2) Only
one path still hardcodes `GlobalScope: true` unconditionally post-#3240:
`extractAdminPrincipal` (`middleware.go`). `RootScoped` and `GlobalScope` are set from
independent signals on every principal type and neither is derived from the other.

### A2.3 — Decision 1 implemented: `authorizeTenantAccess`

`features/controller/api/handlers_tenants.go` replaces the story's original
`isCallerAuthorizedForTenant` (Amendment 1 A1.2's ancestry-only check) with
`authorizeTenantAccess(ctx, principal, resourceTenant) tenantAuthDecision`:

- An unscoped, non-`RootScoped` principal (`TenantID == ""`, today's only shape) keeps
  unrestricted access — byte-identical to pre-Amendment-2 behavior, verified by
  `TestEmptyCallerTenant_NoRootScopeMarker_RetainsUnscopedAccess`.
- A tenant-scoped principal keeps the A1.2 ancestry check (`IsTenantAncestor`), unchanged.
- A `RootScoped` principal is confined to the literal tenant ID `"root"`
  (`rootTenantID` constant) plus any descendant it holds an active crossing for
  (Decision 2, A2.4 below); a strict descendant of `"root"` without one denies with
  `tenantAuthNeedsCrossing`, not a silent `tenantAuthDenied` — see A2.5.
- A tenant genuinely outside `"root"`'s own subtree (a second top-level tenant, in a
  multi-root deployment) is an ordinary out-of-scope `tenantAuthDenied` (404) for a
  `RootScoped` caller — there is no crossing that could remedy access to a subtree that
  was never `root`'s to begin with.

Covered by `TestAuthorizeRootScopedCaller_DeniedRealDescendantWithoutCrossing` (the
REQUIRED TEST), `_AllowedWithActiveGrant`, `_RootItselfAlwaysAllowed`, and
`_UnrelatedTopLevelTenant_Returns404NotChallenge` (`handlers_tenant_crossing_test.go`).

**Enforcement point: `requirePermission`, not the individual handlers.** A `RootScoped`
principal presents `GlobalScope == true` and `TenantID == ""`, so the pre-existing
tenant-isolation block in `requirePermission` (`if !principal.GlobalScope &&
principal.TenantID != ""`) is structurally unreachable for it. Calling
`authorizeTenantAccess` only from the handlers that happen to have a scope guard would
therefore leave the boundary open on every other tenant-targeting route — `tenant:manage`'s
suspend and config-source/test, and the per-tenant refresh-policy and assurance-policy
endpoints — where a root-scoped operator could suspend an MSP tenant or drive a
config-source test against that tenant's git credential with no crossing and no
break-glass record. `requirePermission` therefore applies the Decision 1 check for every
`RootScoped` principal on any request that names a tenant, resolving the target through
`extractBoundaryTenantFromRequest` (the isolation-engine extractor plus the `tenant_path`
variable those two policy routes use). Two permissions are exempt, listed in
`tenantCrossingRemedyPermissions`: `tenant:crossing-break-glass` (the remedy itself —
gating it on holding a crossing would make the boundary unopenable) and
`tenant:crossing-grant` (whose handler refuses root-scoped callers outright, a stricter
answer than a challenge).

`tenantBoundaryRouteTable` (`middleware_tenant_boundary_test.go`) is asserted against a
`mux` route walk, so a newly added tenant-targeting route fails the test suite until it is
listed and thereby covered by the boundary assertions —
`TestRootScopedPrincipal_BlockedOnEveryTenantRoute`,
`_RemedyRoutesNotPreEmpted`, `_AllowedOnEveryTenantRouteWithActiveCrossing`,
`_RootTenantItselfAlwaysAllowed`, and `TestUnscopedAdmin_UnaffectedOnEveryTenantRoute`.
`handleSuspendTenant` additionally keeps its own `authorizeTenantAccess` guard: suspension
is a denial of service against everything inside the target tenant, so it carries the same
handler-level second line of defence as `handleUpdateTenant`.

### A2.4 — Decision 2 implemented: `TenantCrossingStore`

A single storage contract backs both crossing kinds — they are the same shape (a
time-boxed, revocable, auditable authorization record for one principal on one tenant
subtree), differing only in `Kind`, `GrantedBy`, and justification requirements, which
the calling handler enforces:

- `pkg/storage/interfaces/business/tenant_crossing_store.go` — the `TenantCrossingStore`
  interface, `TenantCrossing` record, and `TenantCrossingKindGrant` /
  `TenantCrossingKindBreakGlass` constants. Following the Central Provider System's
  pluggable-by-default rule (CLAUDE.md), it is wired as an **optional** `StorageProvider`
  extension (`TenantCrossingStoreCreator`, `pkg/storage/interfaces/provider.go`) —
  the same pattern `AssuranceStoreCreator` (Issue #2845) already established — rather
  than a mandatory method every provider must implement.
- Implemented for both business-store backends: SQLite
  (`pkg/storage/providers/sqlite/tenant_crossing_store.go`, `tenant_crossings` table) and
  PostgreSQL (`pkg/storage/providers/database/tenant_crossing_store.go`,
  same table name). A shared contract test
  (`business.TenantCrossingStoreContract`, `pkg/storage/interfaces/business/contract.go`)
  exercises both.
- **(a) Client-granted access** — `POST /api/v1/tenants/{id}/access-grants`
  (`tenant:crossing-grant`, `AssuranceStrong`), callable only by a caller already
  authorized for `{id}` under `authorizeTenantAccess` above — an MSP admin can grant
  access into a tenant it already controls, never an arbitrary one. No justification
  required (client opt-in). Time-boxed by caller-supplied `duration_minutes`, capped at
  `maxTenantCrossingGrantDuration` (24h, an implementation default — Remaining Tunable 3
  stays open on whether this should be founder-fixed).
- **(b) Break-glass** — `POST /api/v1/tenants/{id}/break-glass`
  (`tenant:crossing-break-glass`, `AssuranceStrong`), callable only by a `RootScoped`
  principal, mandatory `X-Justification` header (10-1000 chars, mirroring
  `features/rbac.ValidateSensitiveOperation`'s M-AUTH-2 convention without reusing that
  helper's RBAC-CRUD-scoped `SensitiveOperationType` enum). Fixed 30-minute window
  (`tenantCrossingBreakGlassDuration`), deliberately shorter than
  `emergency.break-glass`'s 4h system-resource window because this elevation reaches a
  specific MSP's own configuration and data, not shared platform infrastructure. **Dual
  approval is not implemented** — Remaining Tunable 1 stays open; self-invocation with
  justification and full audit is what shipped.
- A parallel, declarative RBAC permission and template —
  `tenant.crossing-break-glass` (`features/rbac/defaults.go`,
  `features/rbac/templates.go`) — models the capability for role-assignment purposes in
  the richer RBAC engine, explicitly not a reuse of `emergency.break-glass`. This is
  documentation/role-modeling surface; it does not itself gate the REST endpoints above,
  which enforce via the flat `knownPermissions`/`permissionAssurance` registries
  (`features/controller/api/permissions.go`, `assurance.go`) like every other endpoint in
  this package.
- Both kinds audit via `pkg/audit` (`recordTenantCrossingAudit`,
  `handlers_tenant_crossing.go`), tenant-scoped to the affected MSP so the existing
  `GET /api/v1/audit/entries` endpoint — which always scopes to the caller's own context
  tenant — surfaces crossing activity to that MSP without a bespoke activity-view
  endpoint. `GET /api/v1/tenants/{id}/access-grants` (`tenant:crossing-list`) additionally
  lists the raw crossing records (active, expired, and revoked) for a tenant.

### A2.5 — Decision 3 implemented: step-up-shaped challenge, not a bare 403/404

`writeTenantCrossingChallenge` (`handlers_tenants.go`) responds to a `RootScoped` caller
denied solely for lacking an active crossing with `401` + `WWW-Authenticate: CFGMS-StepUp
realm="cfgms", required="tenant-crossing"` + a JSON body naming the break-glass endpoint
— the same envelope shape ADR-021 Decision 6 defines for assurance step-up
(`middleware.go:715-727`), reusing its pattern without touching the `AssuranceLevel` enum
itself ("tenant-crossing" is not a session assurance level). This is deliberately
**not** issued from `handleListTenants`: a bulk list silently omits tenants the caller
lacks a crossing for (matching how any other out-of-scope item is already omitted),
because a list response has no single resource to attach a per-item challenge to.

### Consequences of this amendment

- ADR-025 Decision 1 is now enforced in practice, not merely mechanically correct against
  a caller type that never occurs — the gap Amendment 1 A1.3 identified ("no principal in
  the system currently presents as `root`-scoped... the boundary has nothing to trigger
  on") is closed by the explicit marker, even though no production issuance path sets it
  yet in this story.
- Every existing `callerTenant == ""` caller (all of them, on `develop` as of this
  amendment) is `RootScoped == false` by construction and is therefore completely
  unaffected — the regression this amendment had to avoid.
- Remaining Tunables 1 (dual-approval default) and 3 (grant-expiry default/fixed-vs-open)
  are still open; this story picked concrete, narrower-than-required implementation
  defaults (no dual approval; 24h grant cap, 30m break-glass window) rather than resolving
  them as founder-fixed policy. A future story should either ratify these defaults
  explicitly or revisit them.
- Tunable 2 (exact permission names) is resolved by this implementation:
  `tenant:crossing-grant`, `tenant:crossing-list`, `tenant:crossing-break-glass` (flat
  registry) and `tenant.crossing-break-glass` (RBAC template), following each
  subsystem's own existing naming convention.
- Tunable 4 (carve-out allowlist's precise audit-event-type enum) is **not** addressed by
  this amendment — Decision 4's logging/metrics carve-out has no implementation in this
  story; it remains fully open.

### New Remaining Tunables (added by this amendment)

6. **Whether the 24h client-grant cap and 30-minute break-glass window should be
   founder-fixed policy** (Tunable 3, narrowed) rather than implementation defaults set by
   this story.
7. **Whether tenant-crossing break-glass should require a fresh presence proof**
   (`RequireUserPresence`, ADR-021 Decision 4's shape) in addition to `AssuranceStrong` —
   not added in this story because it is unconfirmed whether every principal type able to
   reach `RootScoped` status (mTLS admin, cfg-CLI bearer) has a path to a WebAuthn
   presence ceremony at all; adding the requirement without confirming that could make the
   endpoint unusable for its intended callers.
8. **Decision 4's logging/metrics carve-out remains entirely unimplemented** (Tunable 4)
   — no code in this story touches it.
