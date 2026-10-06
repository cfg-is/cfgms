# ADR-025: SaaS-Operator ↔ MSP Tenant Access Boundary

**Status:** Accepted

**Date:** 2026-07-30

**Amended:** 2026-08-01 — [Amendment 1](#amendment-1-2026-08-01--boundary-check-must-use-ancestry-lookup-not-path-prefix-matching):
Decision 1's boundary mechanism (`strings.HasPrefix` on tenant IDs) cannot work — tenant IDs
are not paths — and is replaced with an `IsTenantAncestor`-based check.
**Amended:** 2026-08-09 — [Amendment 2](#amendment-2-2026-08-09--a13-resolved-approach-a-decision-123-implemented):
A1.3 resolved (explicit root-scope marker, never inferred from an empty tenant); Decisions
1-3 implemented (`authorizeTenantAccess`, `TenantCrossingStore`, step-up challenge).
**Amended:** 2026-09-28 — [Amendment 5](#amendment-5-2026-09-28--globalscope-is-the-crossing-boundary-marker-for-account-bound-principals):
for a principal resolved from a durable account record, the boundary now binds on
`GlobalScope` (`acct.RootScope`), not the assurance-gated `RootScoped` marker — reversing
A2.2's rejection of `GlobalScope`, whose reasoning no longer matches the code.
**Amended:** 2026-10-06 — [Amendment 6](#amendment-6-2026-10-06--billing-visibility-across-the-boundary):
`root` sees each MSP's name, tech count, endpoint count, anonymized platform metrics, and
per-client sizes under opaque labels — never client names — without a grant; the MSP sees
the same report for its own clients with real names. Supersedes A2.5's "bulk list silently
omits" rule for MSP-level rows.

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
tied to a prior incident where hardcoding a fallback tenant broke cross-tenant
admin reads). `isWithinTenantScope`'s empty-`callerTenant` branch already treats that as
"unrestricted access," which is correct for today's actual unscoped-superadmin case — but
it means no principal in the system currently presents as "scoped to `root`" in the sense
Decision 1 requires, so the boundary has nothing to trigger on in practice even once A1.2
ships.

This is a real, unresolved design question, not a mechanical bug — options include (a)
introducing a genuinely `root`-scoped principal type distinct from unscoped-superadmin, (b)
treating empty-`callerTenant` as equivalent to `root`-scoped for boundary purposes (changes
today's "unrestricted access" semantics for every existing empty-`callerTenant` caller,
including cross-tenant admin reads the prior-incident fix depends on), or (c) something narrower
scoped to specific admin-session types. **Left open for #3125 (or a follow-on decision) to
resolve before Decision 1 can be considered actually enforced** — added as Remaining Tunable
5 below.

### A1.4 — Realm-qualified form for cross-cell surfaces (ADR-032 Decision 3, Issue #3782)

ADR-032 ("SaaS deployment topology and trust hierarchy foundations") introduces the *realm* —
a deployment-wide identifier naming a cell — and requires every tenant identity to carry a
realm qualifier before the first production tenant exists (ADR-032 Decision 3). Issue #3782
adds the grammar for that qualified form: `<realm>/<unqualified-id>`, where both `<realm>` and
`<unqualified-id>` independently satisfy the same k8s-DNS-label rule A1.1 established
(`k8sNameRegex`, `features/tenant/manager.go`) via `validateRealmQualifiedTenantID`.

This is deliberately **not** a relaxation of A1.1's finding. A1.1 established that a plain
tenant ID (the form `isWithinTenantScope` and `IsTenantAncestor` operate on) is a single DNS
label and never contains `/`. The realm-qualified form is a distinct, syntactically
unambiguous shape — exactly one `/`, both halves independently validated — reserved for
**cross-cell surfaces only** (a future tenant→cell directory, cross-cell admin routing,
cross-cell audit aggregation — none of which exist yet; ADR-032 explicitly defers building
them). It is never passed to `isWithinTenantScope` or `IsTenantAncestor`, and intra-cell
ancestry resolution is completely unaffected by its existence.

The realm itself is a single deployment-wide config value (`RealmID` in `controller.cfg`,
Issue #3782), never stored per-tenant. `Manager.QualifiedTenantID` computes a tenant's
qualified identity on demand from whatever `RealmID` is currently configured, returning the
bare unqualified ID unchanged when `RealmID` is empty (the self-hosted default: no realm
concept). Because nothing is persisted per-tenant, there is no migration to run if a
deployment's realm is assigned — or corrected — at any point before a real cross-cell surface
starts persisting the qualified form.

The grammar is enforced at the point of construction, not merely documented: `QualifiedTenantID`
validates both halves and the assembled result, and returns an error rather than a malformed
identity. A realm that is not a single DNS label — `root/msp-a`, `Cell1`, `../..` — can
therefore never produce a qualified ID, closing the path by which `realm_id: "root/msp-a"`
would otherwise yield the ambiguous `root/msp-a/client-1` shape A1.1 eliminated.

To make "assigned before the first production tenant is created" an enforced fact rather than
an optional field nobody sets, `tenant.EnforceRealmGuard` fails closed at controller startup:
a `CFGMS_TELEMETRY_ENVIRONMENT=production` controller with `ha.mode: cluster` (the existing
SaaS-deployment signal, `HAConfig.Mode`) and an empty `RealmID` refuses to boot. Self-hosted
deployments (`ha.mode` unset or not `cluster`) are never gated on *emptiness*, regardless of
`RealmID` — but a `RealmID` that is set and malformed refuses to boot on every deployment
shape and in every environment, because a bad realm is wrong everywhere.

The guard runs where `RealmID` is consumed — `server.New`, on the path every controller start
takes — and again on the one-time `--init` path before any CA material is written. It is
deliberately not placed behind an optional config block (certificate management, `cluster_ca`),
since a deployment that omits that block would otherwise skip the check entirely.

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
  present `TenantID == ""` and are disambiguated by the new signal alone. The production
  issuance path is `IssueAdminBundle`'s `--root-scoped` opt-in (`cmd/controller/main.go`'s
  `bootstrap-admin` subcommand, `features/controller/initialization/admin_bundle.go`) —
  see A2.6 below. Every admin cert issued to date, and every one issued by the first-boot
  / `--regenerate` system-bundle path (`issueAdminBundle`, `initialization.go`), remains
  unaffected and continues to present as an unscoped superadmin: `--root-scoped` is
  opt-in, defaults to off, and is deliberately not reachable from first boot.
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
  round-trips, not just the initial `Issue` response. The production call site is
  `handleSessionCreate` (`features/controller/api/handlers_sessions.go`): it branches to
  `IssueRootScoped` when the authenticating `Principal.RootScoped` is true, otherwise
  calls the ordinary `Issue` — a cfg-CLI session inherits its scope from the
  authenticating credential, never from a request field.

### A2.6 — Root-scoped issuance wired: `bootstrap-admin --root-scoped` (2026-08-09)

Landing Decision 1/2/3 with no issuance path left the boundary provably correct but inert
— nothing could ever present as `RootScoped`. Rather than merge that gap and track it
separately, the founder directed the issuance path to land in the same story/PR (#3125 /
#3215). Scope was deliberately narrow — one opt-in, one call site, no new policy surface:

- **Cert side.** `IssueAdminBundle` (`features/controller/initialization/admin_bundle.go`)
  gained a `rootScoped bool` parameter. When true, its `TemplateModifier` composes
  `cert.SetAdminMarker` **and** `cert.SetRootScopeMarker` on the same cert (still a single
  admin-marked cert — root-scoped is a narrower category of admin, not a separate
  identity). Surfaced as `bootstrap-admin --name <op> --output <path> --root-scoped`
  (`cmd/controller/main.go`), rejected when combined with `--regenerate`/`--revoke`/
  `--list`, or with `--root-scoped` but no `--name`. `SetRootScopeMarker` gained its own
  architecture allow-list test (`pkg/cert/architecture_test.go`,
  `TestSetRootScopeMarker_Architecture`, mirroring `TestSetAdminMarker_Architecture`),
  allow-listing only `admin_bundle.go` — the risk it guards is inverted from the admin
  marker's: this marker *reduces* privilege, so the hazard is accidental stamping
  (an operator unexpectedly locked out below `root`), not escalation.
- **First boot stays unmarked, on purpose.** `issueAdminBundle` (`initialization.go`),
  shared by first-run `--init` and `--regenerate`, never sets the marker. It mints the
  deployment's one system admin bundle; on a single-root or on-prem install, "descendants
  of `root`" is the entire fleet, so marking it would lock that admin out of everything it
  manages with no self-service way to grant a crossing. Unmarked remains the default
  everywhere — the opt-in exists only on the named-operator path.
- **Session side.** No new request field. `handleSessionCreate` reads the already-derived
  `Principal.RootScoped` and picks `IssueRootScoped` vs. `Issue` accordingly (A2.1 above)
  — a caller cannot choose its own scope by setting a field on the session-create request.
- **Audit.** Issuing a root-scoped bundle records a `Critical`-severity `system_access`
  audit event (`auditRootScopedBundleIssuance`, `admin_bundle.go`; action
  `root_scoped_admin_bundle_issued`) via a short-lived storage+audit manager opened for
  that one CLI invocation. A credential that changes which side of the tenant boundary its
  holder sits on is not mintable without a trace. Storage/audit failure is a hard error
  from `IssueAdminBundle` even though the bundle file is already on disk at that point —
  the CLI must not silently produce an unaudited root-scoped credential.
- **Tests.** `features/controller/initialization/admin_bundle_test.go`:
  `TestIssueAdminBundle_RootScoped_StampsBothMarkers`,
  `TestIssueAdminBundle_NotRootScoped_NoRootMarker`,
  `TestIssueAdminBundle_FirstBoot_NeverRootScoped`,
  `TestIssueAdminBundle_RootScoped_RecordsAuditEvent`,
  `TestIssueAdminBundle_NotRootScoped_NoAuditEvent`. Session-side:
  `features/controller/api/handlers_sessions_test.go`,
  `TestHandleSessionCreate_RootScopedPrincipal_IssuesRootScopedSession`. Cert-extraction
  coverage (a cert carrying both markers yields a `RootScoped` principal; an ordinary one
  does not) already existed pre-issuance-wiring in
  `features/controller/api/handlers_tenant_crossing_test.go`
  (`TestExtractAdminPrincipal_RootScopeMarker`) and is unchanged.

### A2.2 — Why not (b): the measured blast radius that ruled it out

On the `develop` tip this amendment was written against, an empty `callerTenant` is
load-bearing at **31 explicit branches across 14 files** in `features/controller/api/` —
4 written as `callerTenant == ""`, 27 as the inverse guard `if callerTenant != ""
{ …scope… }` — plus `isWithinTenantScope` (`middleware.go:255-261`), whose own first line
is `if callerTenant == "" { return true }`, reached from 14 further call sites. Treating
that condition as "scoped to `root`" (approach (b)) would have changed what every one of
those branches means, including the prior-incident admin-read behaviour A1.3 itself cites
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
  on") is closed by the explicit marker, and (per A2.6) a production issuance path now
  sets it: `bootstrap-admin --root-scoped`, opt-in and off by default everywhere else.
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

## Amendment 3 (2026-08-25) — An admin certificate authenticates; it does not authorize

**Status:** Accepted · **Deciders:** Founder, Architecture · **Amends:** Decision 1, Amendment 2

Epic #3178 makes the administrator account the identity anchor and binds mTLS admin certificates to
it. That forced a decision about a state this ADR never described: **an admin-marked certificate
with no bound account.**

Today such a certificate is implicitly root. `extractAdminPrincipal` hardcodes `GlobalScope: true`,
`TenantID: ""` and `Permissions: nil`, and `hasPermission` reads nil `Permissions` as implicit
admin. Possession of the certificate *is* the authorization.

### Decision

**An admin mTLS certificate is an authentication credential and nothing more. It confers no
authority on its own. Authorization comes exclusively from the account it is bound to.**

- **A certificate with no bound account authenticates and can do nothing.** Its principal carries a
  **non-nil, empty** `Permissions` slice, `GlobalScope: false`, and `TenantID: ""`. Every
  permission check fails closed.
- **Implicit root by possession of a certificate is removed**, not merely bounded, audited, or
  time-limited. There is no state in which holding a certificate grants authority that no account
  granted.
- **Bootstrap issues a bound certificate, not an unbound one.** `bootstrap-admin` and the first-boot
  `issueAdminBundle` path must create an administrator account and bind the issued certificate to it
  in the same operation. An unbound certificate is never a useful artifact, so first boot never
  produces one.
- **Recovery is local, not remote.** A deployment that loses its accounts recovers with
  `bootstrap-admin` on the controller host, which reads config and the CA directly and needs no
  network authentication. That requires shell access to the controller — strictly stronger than
  possessing a certificate, and unavailable to a remote attacker holding a stale bundle.

### The `nil`-means-admin sentinel is inverted, and must be replaced

`nil` `Permissions` is the **implicit-admin marker** consumed by `hasPermission`. The zero value of
the field therefore means *unrestricted*. Every principal-construction site is one forgotten
initialisation away from granting root: writing the natural `var permissions []string`, or letting a
lookup error fall through to an unset field, yields implicit admin rather than nothing.

Today exactly one site gets this right by discipline. The web-cookie branch initialises
`permissions := []string{}` before its account lookup, with a comment explaining that "non-nil is the
fail-closed default: an account that cannot be resolved gets an empty grant set, never an unbounded
one" — so a store error leaves the empty slice intact and the request is denied. That is correct, and
it is correct because a developer remembered.

**That is not a property to rely on, and epic #3178 adds two more construction sites that must each
remember it independently.** A database error, a timeout, a refactor that hoists a declaration, or a
new authentication path written by someone who has not read that comment all fail *open*.

**Requirement: implicit admin must be carried by an explicit field, not by the zero value.** A
principal is implicitly admin only when something deliberately says so — `Permissions` then describes
grants and nothing else. With that inversion, a principal built from zero values, or abandoned
half-constructed on an error path, denies everything by construction rather than by vigilance.

The concept of implicit admin is retained deliberately: enumerating every permission ID onto a
root-scope account would add no gate that `permissionAssurance` does not already apply, and would
silently strip an administrator of any permission introduced after their account was created. What
changes is only how it is encoded.

Until that inversion lands, any new construction site must initialise to a non-nil empty slice and
carry a required test asserting an unbound or unresolved principal is **denied a specific
permission** — not merely that it authenticates.

### Why not keep an audited, indefinite bootstrap fallback

Considered and rejected. An earlier draft of this amendment kept implicit root for unbound
certificates indefinitely, with a per-use audit event and anomaly detection, on the grounds that
closing it risked an unrecoverable deployment: a lost account store would leave a freshly issued
certificate also unbound and therefore rejected, so holding the CA would no longer suffice.

**That argument was wrong, because it assumed recovery had to happen over the network.**
`bootstrap-admin` is a local controller subcommand — it needs shell access to the controller host,
not a credential the API will accept. So the recovery path never depended on the fallback being
open, and the fallback bought nothing that local access does not already provide.

What it cost was real: a standing network-reachable path where possession of a certificate the
account layer knows nothing about yields unrestricted access, forever. Detection is not prevention,
and CLAUDE.md's threat model asks that rarely-touched settings **bound the blast radius** of admin
or controller compromise rather than merely record it. A stale certificate issued before accounts
existed, or one whose account was later deleted, now authenticates and does nothing.

### Relationship to `RootScoped`

Unchanged. `Principal.RootScoped` continues to derive from `cert.HasRootScopeMarker` alone, per
A2.1/A2.2 — never from an account, bound or unbound. This amendment governs `TenantID`,
`GlobalScope` and `Permissions`. A certificate's root-scope classification remains a property of the
certificate; what changes is that classification alone no longer grants anything.

### Consequences

- Every existing admin certificate stops working until bound to an account. Pre-GA, this is a clean
  break rather than a migration; the project convention is to prefer the break and a clear error
  message over a compatibility shim.
- Revocation remains authoritative but is no longer the only control. Deleting or disabling the
  bound account is now sufficient to render a certificate inert, without needing to reach the CA.
- The follow-up question recorded on epic #3178 — whether a root-scope account should be *required*
  to carry a marker certificate — is unaffected and still open.

### Effect on decomposition

Epic #3178's principal-resolution story implements the unbound-certificate rule and cites this
amendment. The bootstrap account-and-binding requirement is a separate deliverable. Stories cite
ADRs; they do not edit them.

## Amendment 4 (2026-08-28) — A phishing-resistant assertion by a root-scope account is an A1.3 marker

Founder decision, 2026-08-28, taken during the decomposition of epic #3711. This amendment
extends A2.1's explicit-marker rule to the session authentication paths. It does not weaken it.

### A4.1 — Decision

A session established by a **phishing-resistant assertion** — passkey login, or WebAuthn
step-up — for an account whose `RootScope` flag is explicitly set constitutes an A1.3 explicit
root-scope marker for that session, on both the browser cookie path and the CLI bearer path.

This remains an explicit marker and not an inference. It rests on two facts that are each set
deliberately: the account's `RootScope` flag, set explicitly at account creation and
mutually exclusive with a tenant assignment (Issue #2919), and a completed phishing-resistant
assertion. It is never derived from `TenantID` being empty, from `GlobalScope`, or from
`ImplicitAdmin`. Approach (b) stays rejected exactly as A2.1 rejected it.

### A4.2 — This amendment CONFINES; it does not widen

`RootScoped` is named for what grants it and acts as a confinement. Setting it subjects a caller
to the Decision 1 boundary; its absence exempts them.

Before this amendment the browser path never set the marker, so a root-scope administrator in the
browser presented an empty `TenantID` **and** no marker. `authorizeTenantAccess` returns
unrestricted for that combination, and the catch-all boundary gate inside `requirePermission`
fires only when the marker is present. A root-scope web session was therefore **unconfined** —
exempt from the very gate whose own comment records that it exists because handler-by-handler
enforcement had already failed once.

That was a live gap, not a consequence of this amendment. Closing it is this amendment's primary
effect: a root-scope browser session becomes subject to Decision 1 and requires an active grant
or a break-glass crossing to reach a strict descendant tenant, exactly as the same operator's
certificate credential already does.

### A4.3 — Derive per request; do not store it on the session record

The marker must be re-derived on each request from the bound account's `RootScope` flag and the
session's current assurance. It must not be stored on the session record as the source of truth.

Two reasons, both operational. Assurance can be downgraded mid-session — ADR-021 Decision 5
downgrades on a source-address change — and a session that is no longer phishing-resistant must
no longer carry the marker. And the account flag can be cleared administratively, which must take
effect on the next request rather than at session expiry. This matches the account-authoritative
re-derivation the bearer path already performs (Issue #3576), and inherits its off switch: a
disabled account is rejected outright on the next request.

### A4.4 — The bound: a session-derived marker never mints a certificate-borne one

**A root scope derived from a session must never be sufficient to issue a certificate carrying
`RootScopeMarkerOID`.** Granting that certificate extension remains gated on a
certificate-derived principal — one whose certificate authenticated the request, evidenced by a
non-empty `CertSerial`, which is set only after the revocation check and only on the certificate
paths.

This bound is what keeps the amendment safe, and it is not optional. Without it, a root-scope
session could lodge a signing request, approve it, and collect a certificate with a 45-day floor
and unattended renewal — converting a revocable eight-hour session into a durable credential that
survives remediation.

With it, the strongest durable credential in the system still requires an existing certificate to
create, and the accepted interface-substitution non-goal stays bounded: an adversary who
substitutes the browser interface obtains at most a root-scope **session** — idle-timed,
absolutely capped, revocable, and killed on the next request if the account is disabled — and
never a durable certificate. That is a strictly smaller prize than the one an adversary who has
reached the controller host already holds, since the controller is itself the certificate
authority.

### A4.5 — Consequences

- The Decision 1 boundary applies to root-scope operators on every authentication path, closing
  the browser-path gap described in A4.2.
- Browser-authenticated CLI login becomes available to root-scope operators, and the session it
  mints is root-scoped and therefore confined. Those operators no longer require a permanently
  held certificate bundle for ordinary work.
- The certificate bundle path remains necessary for issuing a new root-scope-marked certificate,
  per A4.4, and for first-boot bootstrap.
- Self-approval, permitted by epic #3711's D9, stays bounded by A4.4: a session-derived root scope
  cannot approve itself into a stronger credential class.

## Amendment 5 (2026-09-28) — GlobalScope is the crossing-boundary marker for account-bound principals

**Status:** Accepted · **Deciders:** Founder, Architecture · **Amends:** A2.2, A4.1-A4.3 ·
**Related:** Issue [#4337](https://github.com/cfg-is/cfgms/issues/4337)

### A5.1 — Decision

For a principal resolved from a durable account record (`Principal.AccountBound`), the
Decision 1 boundary now binds on `GlobalScope`, not `RootScoped`. A root-scope account
(`acct.RootScope == true`) is subject to the boundary, produces the crossing challenge or
grant decision, and emits the crossing audit record on **every** request that names a
tenant outside `root`'s own scope — unconditionally, regardless of the current session's
assurance level.

`subjectToTenantCrossingBoundary(principal)` (`handlers_tenants.go`) is the single function
this decision lives in: `principal.GlobalScope` when `AccountBound`, else
`principal.RootScoped`. `authorizeTenantAccess`, `requirePermission`'s boundary gate,
`tenantScopedTerminalWrapper`, and `handleUpdateStewardConfig` all call it instead of
reading `RootScoped` directly — one decision function, not four independent copies of it.

### A5.2 — Why this reverses A2.2, not just narrows it

A2.2 rejected `GlobalScope` as the A1.3 marker for two reasons, both about code that has
since changed:

1. "Post-Issue #3194 (PR #3240), the bearer path computes `globalScope := sess.TenantID ==
   ""`" — deriving it from tenant emptiness, A1.3's own ambiguity. This is still true, but
   only for a Bearer session with **no bound account** (`middleware.go`, the
   `acct == nil` fallback before the account-lookup override). The moment Issue #3576 (cited
   by A2.3 itself) landed, an account-bound Bearer session stopped using that expression:
   `globalScope = acct.RootScope`, read from the account record on every request, is what a
   bound session has actually carried since. The web-cookie path was never on the
   tenant-emptiness expression at all: `globalScope = acct.RootScope` when a web account
   resolves (`middleware.go`).
2. "`extractAdminPrincipal` hardcodes `GlobalScope: true` unconditionally" — true only for
   its no-bound-account bootstrap-fallback branch. Its bound-account branch, added by A2.3's
   own subject (ADR-025 Amendment 3 / Issue #3715's cert-serial account binding), sets
   `GlobalScope: acct.RootScope` — the identical durable-account-field shape as the two
   session paths.

A2.2 was correct when it was written: at that point every principal construction site really
did derive `GlobalScope` from tenant emptiness or hardcode it. It is no longer correct
because the code it reasoned about is not the code that exists now. This amendment does not
relitigate A2.2's caution about re-collapsing `RootScoped` and `GlobalScope` into one
signal — it narrows *which principals* that caution applies to.

### A5.3 — What this closes

Before this amendment, `RootScoped` was the only signal `subjectToTenantCrossingBoundary`'s
predecessor checks read, and for a session it is re-derived every request from
`rootScopeFromAssertion(acct, sess.Assurance)` (A4.1/A4.3): `acct.RootScope && assurance >=
AssuranceStrong`. An account whose `RootScope` has not changed presents `RootScoped ==
false` the instant its current session's assurance drops below phishing-resistant (an
ADR-021 Decision 5 downgrade, or simply a session that never stepped up). Three call sites
keyed the *entire* boundary check on that single, assurance-gated bit:

- `tenantScopedTerminalWrapper` (`routes_terminal.go`): its root-scope branch was an
  `else if principal.RootScoped` with **no final `else`** — a low-assurance root-scope
  session matched no branch at all and reached the remote-shell handler unconditionally,
  no crossing check, no challenge, no audit.
- `requirePermission`'s Decision 1 gate (`middleware.go`, A2.3's "Enforcement point"): gated
  identically on `principal.RootScoped`. Below it, the ordinary tenant-isolation check
  (`!principal.GlobalScope && principal.TenantID != ""`) is also unreachable for this
  principal shape (`GlobalScope == true`, `TenantID == ""`), so a low-assurance root-scope
  session skipped *both* checks and reached the handler with no isolation applied at all —
  the general-purpose version of the same gap.
- `handleUpdateStewardConfig` (`handlers_stewards.go`) had no Decision 1 check of any kind
  for `callerTenant == ""` — every unscoped caller, including a root-scope account at any
  assurance level, retained the unconditional legacy access A2.3 documents for the
  non-`RootScoped`, certificate-authenticated case, even though this route pushes a steward's
  entire configuration and is the most powerful write class in the API.

All three are the same bug wearing different clothes: a check gated on the wrong bit,
because the right bit (the account's actual, durable scope) was available as `GlobalScope`
and not used. Binding on `GlobalScope` for account-bound principals mechanically closes all
three from a single function change.

### A5.4 — What this does not change

- **Unbound principals keep `RootScoped` as authoritative.** A principal not resolved from
  an account — the mTLS bootstrap fallback with no bound cert-serial account
  (`extractAdminPrincipal`'s "no binding found" branch, `GlobalScope: true` unconditionally)
  and a Bearer session with no resolvable account (`middleware.go`'s `acct == nil` path,
  `globalScope := sess.TenantID == ""`) — is exactly the case A2.2 warned about: `GlobalScope`
  there carries no account-level root-scope signal, and reading it as one would re-collapse
  the ambiguity A1.3 was written to resolve, for the population A2.2 already correctly
  identified. `subjectToTenantCrossingBoundary` falls back to `RootScoped` for these
  principals, unchanged from A2.1/A4.1. The 31-branch legacy-access invariant A2.2 and A2.3
  measured is therefore still intact: it was always about this same unbound, non-`RootScoped`,
  certificate-authenticated population, and this amendment does not touch it.
- **A4.3's re-derivation rule for `RootScoped` itself is untouched.** `RootScoped` still goes
  false on an assurance downgrade for a session — that is by design, and other code (e.g.
  break-glass eligibility, `handleTenantBreakGlass`) still reads it directly for questions
  this amendment does not reassign. Only the Decision 1 boundary-entry question moves to
  `GlobalScope`, and only for account-bound principals.
- **The assurance level is not lost — it moves to the audit record.** Binding on `GlobalScope`
  means the boundary can no longer be read as "assurance was insufficient" by its outcome
  alone: it now engages the same way regardless of assurance. `auditAuthorizationDecision`
  (`middleware.go`) therefore records the principal's current `Assurance` on every
  authorization-decision audit entry, so a crossing made from a lower-assurance session
  remains visible after the fact instead of being inferred from whether the gate fired.

### Consequences

- A root-scope account's session meets the crossing gate strictly more often than before this
  amendment — including at assurance levels where it previously bypassed the gate entirely.
  That is the fix, not a regression: the gap was a caller silently escaping both the boundary
  and its audit trail, not a caller being denied something it should have had.
- `tenantScopedTerminalWrapper`'s fall-through (A5.3) is closed as a side effect of routing
  every `callerTenant == ""` principal through `authorizeTenantAccess` uniformly, rather than
  by adding a bespoke default-deny branch beside the existing ones — the same function that
  already had a defined answer for "unscoped, not boundary-subject, not certificate-
  authenticated" (Amendment 4 A4.2: deny) now supplies it here too.
- `handleUpdateStewardConfig` gains a Decision 1 check for `callerTenant == ""` for the first
  time, matching the guard every other tenant-targeting route already carries.

---

## Amendment 6 (2026-10-06) — Billing visibility across the boundary

**Status:** Accepted · **Deciders:** Founder, Architecture · **Amends:** Decision 4, A2.5 ·
**Related:** Epic [#4579](https://github.com/cfg-is/cfgms/issues/4579) (tenant admin tree
boundary rows), `docs/design/mockups/tenant-admin.html`

### A6.1 — Decision: what `root` sees about a walled-off MSP without a grant

Decision 4 already lets `root` see billing and subscription state across the boundary. This
amendment fixes exactly which facts that covers. For every MSP directly under `root`, with
no client grant and no break-glass session, `root` may see:

- **The MSP's name and tenant ID.**
- **Tech count** — the number of operator accounts in the MSP's subtree.
- **Endpoint count** — the number of registered stewards in the MSP's subtree.
- **Anonymized platform metrics** — aggregate counts over the subtree's steward records:
  online/offline counts, operating-system platform mix, and steward version mix. These fall
  under Decision 4's platform-metrics carve-out. No host names, no device identifiers, no
  config content.
- **Per-client size** — for each client tenant in the MSP's subtree, its endpoint count and
  tech count, keyed by an **opaque client label**, never by the client's name or tenant ID.

Nothing else crosses. Config, scripts, workflows, ordinary audit trail, device-level data and
client names stay behind the boundary until the MSP grants access or `root` invokes
break-glass (Decision 2), exactly as before.

### A6.2 — Client names never cross, so the label cannot be the tenant ID

A tenant ID is derived from the tenant's name (`generateTenantID` in
`features/tenant/manager.go`), so exposing a client's tenant ID to `root` would expose its
name. The opaque client label is therefore:

- **Random, not derived.** It is generated once per tenant from a cryptographic random
  source and stored with the tenant. It must not be a hash of the name or ID: client names
  are guessable, so a hash could be reversed by trying likely names.
- **Stable.** The same client keeps the same label for its whole life, so `root` can trend a
  client's size over time and reconcile invoices without learning who it is.
- **Scoped to `root`'s billing view only.** It is never used as an identifier on any other
  API surface, and possessing a label grants nothing — it cannot be passed to a tenant
  endpoint to reach the client.

### A6.3 — The MSP sees the same report, for its own clients, with real names

The MSP-side billing report shows the same facts `root` sees (A6.1), with two differences:

- **Scope:** it covers only the caller's own subtree. An MSP never sees another MSP's data,
  and a client tenant never sees its siblings.
- **Names:** clients appear under their real names, not opaque labels. The MSP already owns
  those names; anonymizing them for their owner would make the report unusable.

This is what satisfies Decision 4's "no silent, root-only visibility" for billing data: the
MSP can always see exactly what `root` can see about it. Routine reads of the billing
summary by `root` are therefore **not** individually logged to the MSP's audit view — the
visibility is standing and disclosed, not an event. Break-glass and grant usage keep their
existing per-use audit records (Decision 2).

### A6.4 — Supersedes A2.5's silent omission for MSP-level rows

A2.5 says a bulk tenant list silently omits tenants the caller holds no crossing for. For a
`root` caller, the tenant list now returns each walled-off MSP as a **boundary row** carrying
only the A6.1 MSP-level facts (name, ID, tech count, endpoint count) plus its client tenant
count, marked as not accessible. The client count discloses nothing new: A6.1 already gives
`root` one per-client size row per client. Client tenants below a walled-off MSP are still omitted from the tree entirely;
their sizes appear only in the billing view under opaque labels (A6.2).

The reason is operational: break-glass (Decision 2b) needs a target. Hiding every MSP forces
an operator to already know and type an MSP's ID during an incident, while the MSP's
existence is visible to `root` through billing anyway. Showing the row protects nothing less
and makes the emergency path usable.

### Consequences

- The tenant list response for a `root` caller gains boundary rows; existing callers that
  assumed walled-off MSPs were absent must treat a boundary row as present but not
  accessible.
- Each tenant record gains a stored opaque billing label, generated at creation and
  backfilled for existing tenants. This is a storage field addition across every tenant
  store provider.
- Two report surfaces exist with one data source: `root`'s cross-MSP billing view (opaque
  client labels) and each MSP's own-subtree report (real names). They must be built from the
  same aggregation so the two can never disagree.
- Per-client tech counts can be zero; a client with no accounts of its own is normal.

## Amendment 7 (2026-10-06) — Root principals are bound to the root tenant; an empty tenant is never root

**Status:** Accepted · **Deciders:** Founder, Architecture · **Amends:** A1.3, A3, A4, Issue #4316 ·
**Related:** Issue [#4665](https://github.com/cfg-is/cfgms/issues/4665)

### A7.1 — Context

Root principals were represented by an empty tenant ID, and an empty tenant was read as
"unrestricted" across the controller — in about sixty handler decisions, the fleet query,
reports, the config router and the RBAC store. A request that lost its tenant, or a
principal that never had one, was therefore indistinguishable from root. At the same time
the root `TenantScope` was granted only to an admin certificate, so a root-scope account
signed in with a passkey or `cfg connect` was refused by every handler that recognised root
through `TenantScope`.

### A7.2 — Decision

- **Identity.** A root-scope account's principal (any credential) and the bootstrap admin
  certificate's principal carry the deployment's root tenant — the single parentless tenant
  (Issue #4542) — as `TenantID`. Account responses report it as `tenant_id`; sessions are
  issued for it.
- **Authority.** A principal is root only by its explicit `GlobalScope` flag (the account's
  `root_scope`, or the bootstrap admin certificate), surfaced per request as root
  `TenantScope`. Proof strength stays a separate layer: `requirePermission` still applies
  each permission's assurance floor, so AssuranceStrong permissions still require step-up.
- **One decision point.** `ctxkeys.TenantRestriction` is the only place an "all tenants"
  decision is made: root scope, or a context explicitly marked system-internal with
  `ctxkeys.WithSystem`, is unrestricted; a tenant caller is confined to its tenant; anything
  else is refused — including a context that simply carries no caller, such as a stray
  `context.Background()` on a request path. Background jobs, startup tasks and fleet-wide
  reads that apply their own tenant filter (the fleet query, signing-CA rotation) take the
  mark at their entry point, so every unrestricted context is a deliberate, greppable
  decision. An empty tenant ID never grants reach.
- **Fail closed at the edge.** Every credential path in the authentication middleware —
  admin certificate, bearer session, web session, API key and relay — refuses a principal
  with neither a root flag nor a tenant (`NO_TENANT_SCOPE`) before it reaches a handler. An
  unbound session with an empty tenant — the pre-amendment form — is refused with
  `SESSION_SCOPE_INVALID`; reconnecting issues a bound session.
- **The crossing boundary applies to actions on stored records.** A root scope is not
  unconditional. For a principal subject to Decision 1's boundary, every route that acts
  on a record a request names by ID, or on the stewards a fleet selector matches, is judged
  by the same `authorizeTenantAccess` decision as a tenant path variable, through one
  function (`tenantAccessForScope`): creating, changing, deleting, approving, revoking or
  provisioning an account, certificate, cert binding, enrolment token, credential request,
  registration, registration token or refresh, API key, role or RBAC subject, case, session,
  rollout, run, rollback or steward config; moving, hiding or decommissioning a steward;
  pushing configuration; and dispatching a batch job, upgrade, osquery query or signed
  operator payload. A rollback target whose owner cannot be established is refused for such
  a caller, since no crossing can be evaluated for it. The root tenant's own records are reachable; a record owned by a tenant below
  root needs an active grant or break-glass crossing and otherwise answers with the
  crossing challenge (Decision 3). Bulk actions (approve-all, approve-by-CIDR) skip the
  records the caller may not act on, as A2.5 reads bulk lists. Routes that were open to a
  root session only by its unset scope before this amendment are judged the same way, so
  none of them widens.
- **Provisioned certificates are steward leaves.** Certificate provisioning, for every
  caller, stamps the steward Organization, refuses any other, and refuses an identity that
  names a controller cluster node, so the endpoint can never mint a controller peer
  identity. Signing-CA rotation stays with a certificate-authenticated root principal; a
  root web or Bearer session cannot perform it.
- **Read breadth is unchanged.** List endpoints, and by-ID reads of records a list already
  shows (a steward, an account, a command, a job, a push or upgrade record, a certificate),
  keep root's existing fleet-wide breadth: such a read is no stricter than the list it
  drills into. Whether root reads of a client tenant's data should themselves require a
  crossing, as Decision 4 implies for business data, is a separate decision this amendment
  does not take.
- **Enforced by an architecture rule.** In `features/controller/api`, any root-allow
  decision made outside `tenantAccessForScope` — a `TenantScope.IsRoot()` branch, an
  `isWithinTenantScope` call fed the root caller's empty filter, or a hand-written
  comparison of that filter with `""` — must carry
  `//architecture:allow-root-scope -- <reason>` on the same line
  (`TestRootScopeDecisionsGoThroughTenantAccess`). Handlers that are not `*Server`
  (the rollback handler) are given the server's decision function rather than a copy of it.
- **No substituted tenant.** Where an operation needs a tenant the caller did not name, it
  uses the caller's own authenticated tenant — the root tenant for a root caller — never a
  literal fallback such as `default` (Issue #4543): a per-steward config read, write or
  delete uses the steward's own tenant (registry, then durable record), falling back to the
  caller's tenant only for a steward known nowhere; config and deployment listings read the
  caller's tenant or one it names with `?tenant_id` and is authorized for; an API key or a
  non-root account created without a tenant belongs to the caller's tenant. Data a root
  caller previously wrote under `default` is reachable through `?tenant_id=default` where
  `default` exists as a tenant.

### A7.3 — Consequences

- Per-tenant assurance overrides now apply to root callers: `requirePermission` resolves a
  root caller's assurance requirement against the root tenant's override chain, where it
  previously resolved against no tenant and used only the global floor. An override declared
  on the root tenant therefore binds root operators as well — the intended reading of an
  override on that tenant.
- The steward data plane, the registration path and other controller-internal consumers
  that resolve a tenant from their own context (`features/controller/service`) are tracked
  separately under Issue #4543; they serve stewards rather than tenant principals and are
  outside this amendment.

### A7.4 — Unchanged

- The steward operator-roster wire format: root entries keep their existing representation,
  so deployed stewards verify them as before.
- Account storage routing: a root account's record stays in the system storage namespace;
  only the stored routing key is empty, and it is never read as an authorization signal.
- The steward-binary `default` namespace: root publishes there because deployed stewards'
  self-fetch falls back to it.

