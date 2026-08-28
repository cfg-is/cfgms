# ADR-021: Identity Assurance Levels and Step-Up Authentication

**Status:** Accepted

**Date:** 2026-07-16

**Deciders:** Founder, Architecture

**Related:** [014](014-cfg-sessions-and-credential-unlock.md) (`cfg` admin sessions — Bearer-token principals gain an assurance level here; its `IdleTimeout`/`AbsoluteTimeout` remain and cover the walked-away case). [018](018-web-session-semantics.md) (web-session semantics — the cookie session this ADR levels). [006](006-module-packaging-and-distribution.md) (module approval is the highest-blast-radius action gated by this ADR). Auth-tier policy epic #1419 (`authTier` / `tier3Permissions` — **superseded by this ADR**, see Migration). Epic #2713 (web UI management — surfaced the gap this ADR closes). Epic #2051 (SaaS cluster — **closed without covering sessions**; `pkg/session/contract.go:95` still defers the durable store to it, incorrectly — see Sequencing). Epic #2735 / story #2736 (durable session store — **this ADR's epic is blocked on it**). Epic #2737 (implements this ADR). Stories #2728, #2732 (module approval REST + UI — **held pending this ADR**). `features/rbac/jit` (unwired JIT access — complementary, not superseded; see Context).

---

## Context

### The current model collapses three authentication strengths into one bit

`Principal.IsAdmin` (`features/controller/api/middleware.go:54-59`) is a single
boolean, and three very different authentication paths all set it to `true`
(`middleware.go:50-53`):

| Path | Credential | Real strength |
|---|---|---|
| mTLS admin cert | Possession of a private key, often file- or HSM-backed | Strong; not phishable |
| `cfg`-CLI Bearer session (ADR-014) | Opaque token from a credential login | Medium; bearer token |
| Web session cookie (ADR-018) | Opaque token in an `HttpOnly` cookie | Medium; phishable at the login step |

Only API-key principals are always `IsAdmin == false`.

The sole authorization gate above ordinary permissions is
`requireTier(TierMTLSOnly)`, whose entire check is:

```go
if principal == nil || !principal.IsAdmin {  // auth_tiers.go:51-58
```

Because a web-session Principal is constructed with `IsAdmin: true`
**unconditionally** (`middleware.go:370-375`), **a browser session passes every
Tier-3 gate**. `server.go:570-573` states this outright: "no tier-3 wrapper needed
because session-token principals also have IsAdmin==true."

### Three consequences, all bad

1. **The name and comment lie.** `auth_tiers.go:17` documents `TierMTLSOnly` as
   "mTLS admin cert required; API-key callers rejected even with matching
   permissions." The second clause is true. **The first is false.** The gate's
   real and only effect is *excluding API-key callers* — which is a meaningful
   boundary, but not the one the name advertises. This is not a cosmetic defect: a
   comment that misstates an auth gate's semantics in a security-critical file is
   worse than no comment, because it is believed. During the decomposition of epic
   #2713 it caused two independent reviewers to reach the wrong conclusion about
   what a story could do, and two stories were briefly scoped to a crippled design
   on the strength of it.

2. **A phished session has the full privileged surface.** CLAUDE.md's threat model
   states that "admin accounts may be phished or taken over for short periods,"
   and that rarely-touched settings should "bound the blast radius of admin or
   controller compromise." Today nothing does. A stolen `cfgms_session` cookie
   confers module-bundle approval — arbitrary code on every managed endpoint —
   indistinguishable from an admin holding a hardware-backed cert. The one gate
   that appears to bound this does not.

3. **It is load-bearing on an unwritten assumption.** `requireTier` is safe today
   *only* because every web account is an admin account
   (`handlers_web_accounts.go` calls them "Web-admin account provisioning
   endpoints"). The day a non-admin web account type is added, **every Tier-3
   endpoint silently opens to it** — no code change, no failing test, no review
   signal.

### Nothing exists to build on

Verified against `develop` (2026-07-16):

- **No continuous authentication or authorization work exists.** No continuous
  access evaluation, no device posture, no device binding, no re-auth or step-up
  machinery. (The `risk_score` fields in `pkg/dna/drift` and `pkg/directory/dna`
  are **configuration**-drift scoring — unrelated to identity.)
- **No WebAuthn / FIDO / passkey anywhere**, including `go.mod`. Net-new.
- **Sessions carry no device or network context.** `pkg/session.Session`
  (`contract.go:31-39`) holds only ID, ConnectionName, PrincipalID, TenantID,
  IssuedAt, LastActivity, AbsoluteExpiresAt. `RemoteAddr` and `User-Agent` are
  logged (`handlers_web_session.go:138,152,223,287`) but never stored — so there is
  nothing today against which "has this device or location changed?" could be
  evaluated.
- The one device-ish binding that does exist is `Principal.CertFingerprint`
  (`middleware.go:62`), and only for mTLS principals.
- ADR-014 already provides `IdleTimeout: 15m`, `AbsoluteTimeout: 8h`
  (`pkg/session/contract.go:53`) — the "admin walked away" case is covered.

**One adjacent system does exist, and is unwired.** `features/rbac/jit` is a
complete, tested Just-In-Time access implementation — time-bounded grants
(`JITAccessGrant`), approval workflows, an approver registry, notifications, audit
integration, an optional durable `business.SessionStore` backing, and a
`WorkflowProvider` hook documented as supporting "risk-based" policy. It has **zero
production callers**: only its own tests import the package.

JIT is **complementary to this ADR, not overlapping**, and the distinction matters:

| | Question answered |
|---|---|
| **JIT access** (`features/rbac/jit`) | "You do not normally hold this permission — may you borrow it, for a while, with approval?" |
| **Assurance** (this ADR) | "You hold this permission — are you really you, on the same device, and did you mean to do this?" |

They compose (a JIT grant could itself carry an assurance requirement), but neither
subsumes the other, and this ADR does **not** depend on JIT. Whether to wire, keep,
or delete `features/rbac/jit` is a separate decision. **This ADR's implementation
must neither half-wire it nor reinvent it** — if temporary elevation is wanted, that
is a deliberate follow-on, not an accident of this work.

### What is actually needed

The distinction that matters is not *transport* (mTLS vs cookie) — it is **how
strongly the human at the other end was authenticated, whether that device is still
demonstrably the same one, and whether a human deliberately authorized this
particular action**. Some actions (listing stewards) are fine behind any
authenticated session. Others (approving a module bundle that will execute
fleet-wide) should require phishing-resistant proof and a deliberate human gesture.

Note that these are three separate properties, and the design below keeps them
separate rather than collapsing them into a clock:

| Property | Answered by | Not answered by |
|---|---|---|
| How strongly was this principal authenticated? | Authenticator type (level) | Elapsed time |
| Is this still the same principal on the same device? | Cryptographic device proof | IP/User-Agent signals (spoofable by a cookie thief on the same network); elapsed time |
| Did a human deliberately authorize *this action*? | A user-presence gesture | Continuity; elapsed time |

---

## Decision

### 1. `Principal` carries an assurance level, not an admin bit

Replace `Principal.IsAdmin` with an **assurance level** plus the timestamp of the
authentication that established it:

```go
type AssuranceLevel int

const (
    AssuranceMachine  AssuranceLevel = 0 // Non-interactive credential (API key)
    AssuranceBasic    AssuranceLevel = 1 // Human, password-authenticated (phishable)
    AssuranceStrong   AssuranceLevel = 2 // Human, phishing-resistant + device-bound
)

type Principal struct {
    // ...
    Assurance    AssuranceLevel
    LastProvenAt time.Time // when the device key last proved this Assurance (silently or by gesture)
}
```

| Level | Established by |
|---|---|
| `AssuranceMachine` | API key |
| `AssuranceBasic` | Username/password → web session cookie (ADR-018) or `cfg` Bearer session (ADR-014) |
| `AssuranceStrong` | WebAuthn platform passkey; FIDO2 roaming hardware token; **or** mTLS client certificate |

**TOTP does not reach `AssuranceStrong`.** It is not phishing-resistant — a
real-time phishing proxy relays the code. TOTP may be added later as a factor that
strengthens `AssuranceBasic` against credential stuffing, but it must never satisfy
a `AssuranceStrong` requirement.

**mTLS client certificates are `AssuranceStrong`.** The certificate remains the
`cfg`/automation path to privileged actions. Browser mTLS is *permitted* but not
the intended browser path — client-certificate selection UX in browsers is poor;
WebAuthn is the browser-native answer.

### 2. Sensitive actions declare a minimum level; a few also demand human presence

`tier3Permissions` (`auth_tiers.go:20-42`) is already a registry of permissions
that "require something stronger." It is **generalized**, not replaced by a
parallel system:

```go
// Was: tier3Permissions map[string]struct{}
// Now: the minimum assurance — and, for a narrow catastrophic set, a demand for
// a fresh human-presence gesture — required to exercise each permission.
var permissionAssurance = map[string]Requirement{
    "module:approve":       {Min: AssuranceStrong, RequireUserPresence: true},
    "module:reject":        {Min: AssuranceStrong, RequireUserPresence: true},
    "publisher-trust:add":  {Min: AssuranceStrong, RequireUserPresence: true},
    "web-account:create":   {Min: AssuranceStrong},
    "web-account:delete":   {Min: AssuranceStrong},
    "steward:decommission": {Min: AssuranceStrong},
    // ... every current tier3Permissions entry maps here
}
// Anything absent from this map requires only its ordinary permission grant.
```

**There is deliberately no blanket `MaxAge` timer.** An earlier draft required
`AssuranceStrong` re-established within 15 minutes, on the `sudo` analogy. That is
rejected for three reasons:

1. **It duplicates an existing control.** ADR-014 already ships `IdleTimeout: 15m`
   and `AbsoluteTimeout: 8h` (`pkg/session/contract.go:53`). The "admin walked
   away" case is already covered; a freshness timer adds nothing there.
2. **It taxes exactly the wrong behavior.** A fixed timer only ever interrupts
   *continuous legitimate work* — re-authenticating every 15 minutes during an
   incident is how a control teaches people to resent and route around it.
3. **It does not stop the attack it appears to stop.** Malware or a hijacked
   browser on the admin's own machine is inside every timer window the admin is
   inside. A clock does not distinguish the human from the malware sharing the
   session.

**Assurance is maintained by continuity, not by a clock** (Decision 3), and the
small set of catastrophic actions is gated on **human presence**, not on age
(Decision 4). These are different properties and the distinction is load-bearing:
continuity answers *"is this the same principal on the same device?"*; presence
answers *"did a human deliberately authorize this specific action?"* No amount of
continuity establishes the second.

**Reads stay out.** The existing registry contains **zero** list/read entries
across all eight resources it covers — reads are categorically outside the
elevated surface by design, and `GET /rbac/roles` / `GET /api-keys` are
permission-gated only. That property is preserved: `permissionAssurance` gates
mutations, never reads.

### 3. Assurance is maintained by silent device proof, not by a timer

`AssuranceStrong` persists for the life of the session **as long as device
continuity holds**. Continuity is established by **cryptographic proof, not by
signals**: a silent WebAuthn assertion (`userVerification: "discouraged"`) against
the credential that established the session. The private key never leaves the
authenticator's TPM/Secure Enclave, so a successful assertion proves *this
request comes from the device that authenticated* — and it does so with **no user
gesture, no modal, nothing the operator sees**.

The controller re-proves silently when continuity is in doubt: on a network-context
change (Decision 5), after a long gap in activity, or on a configurable interval.
`LastProvenAt` records the last successful proof. A failed or impossible assertion
downgrades the session to `AssuranceBasic`.

**Why proof and not signals.** Source IP and `User-Agent` are the intuitive
"is it the same device?" check and they are **not sufficient**. A session cookie is
a bearer token: an attacker who steals it and replays from the same network with a
copied `User-Agent` is *indistinguishable by signals*. Signals are corroboration;
only the key is proof. (This is also why the model needs net-new session state —
see Consequences: `pkg/session.Session` records no device or network context today,
and `RemoteAddr` is only ever logged.)

**Why no blanket timer** — see Decision 2. Silent re-proof gives the property a
timer was reaching for (this is still the same authenticated device) without the
property a timer actually delivers (interrupting whoever is working right now).

### 4. Catastrophic actions require a fresh human-presence gesture

A narrow set of permissions carries `RequireUserPresence: true`. These demand a
WebAuthn assertion with `userVerification: "required"` — an actual touch of the
key — taken **for that specific action**, regardless of session continuity.

This is not a stricter version of continuity; it answers a **different question**.
Continuity establishes *this is the same principal on the same device*. Presence
establishes *a human is here and deliberately authorized this*. The gap between
them is exactly the attack that continuity cannot see: **malware or a hijacked
browser on the admin's own machine** has the same device, same location, same
session, and perfect continuity. A timer would not have caught it either — the
malware operates inside the admin's own window. Only a gesture the malware cannot
produce distinguishes them.

The set is deliberately tiny — actions whose blast radius justifies interrupting a
human every single time:

- `module:approve` / `module:reject` — an approved bundle is code that executes on
  every managed endpoint. This is the largest blast radius in the system (ADR-006).
- `publisher-trust:add` — grants an entire publisher standing authority.
- `registration:approve-by-cidr` — one call admits every pending steward whose source
  IP falls in a range, and RFC1918 ranges collide across tenants, so the match set is
  a trust-boundary decision rather than a convenience filter. The read-only preview
  (`GET /registration/approve-by-cidr/preview`) is *not* presence-gated, so the
  gesture is spent once, on a match set the operator has already inspected.

Everything else in `permissionAssurance` is gated on level alone. **Growing this
set is a founder decision, not a reviewer's judgement call** — every addition
spends operator patience, and a control that fires too often gets designed around.

The resulting operator experience: *work all day, never re-authenticate; touch your
key when you approve a module bundle.*

### 5. Network context is a signal that downgrades, never a hard lock

A change in the session's source IP **downgrades the session's effective assurance
to `AssuranceBasic` and clears `LastProvenAt`**, so the next sensitive action
triggers a silent re-proof (Decision 3) — or a step-up (Decision 6) if silent proof
fails. The session is not killed.

Hard-locking a session to its initial IP is explicitly rejected: it breaks on
mobile roaming, corporate NAT egress rotation, CGNAT, and VPN reconnect —
generating lockouts during legitimate work — while an attacker behind the same
egress is unaffected. The device-bound key is what actually defeats cookie replay
from another machine; IP is corroboration, not proof.

This shape is deliberately extensible: `Assurance` is **computed and
re-evaluatable**, so additional zero-trust signals (device posture, EDR health,
impossible travel) can feed the same downgrade path later without redesign. A
broader continuous-evaluation pipeline is **not** in v1 (see Non-Goals) — but
Decision 3's silent re-proof is itself the first increment of one, and the
mechanism the rest would hang off.

### 6. Insufficient assurance returns a step-up challenge, not a refusal

When silent proof cannot satisfy the requirement — no credential on this device,
assertion failed, or the action demands presence (Decision 4) — the caller does
**not** get an opaque 403. The endpoint returns a challenge the client can satisfy
and retry:

```
HTTP 401 Unauthorized
WWW-Authenticate: CFGMS-StepUp realm="cfgms", required="strong", presence="required"
{ "error": "step_up_required", "required_assurance": "strong", "user_presence": true }
```

- **Web UI:** presents a WebAuthn re-authentication modal; on success the session's
  `Assurance`/`LastProvenAt` are raised server-side and the action is retried.
- **`cfg` CLI:** prompts for the security key, or fails with an actionable message
  naming the required level when non-interactive.
- **API-key callers:** cannot step up — `AssuranceMachine` is terminal. They
  receive a plain 403. **Automation cannot self-elevate to approve a module
  bundle**; this preserves the one real boundary the current Tier-3 gate provides.

Step-up is chosen over hard refusal deliberately. Hard refusal pushes admins to
start every session at the highest level and keep it open all day — which
maximizes the lifetime of the most valuable credential and defeats the purpose.

---

## Non-Goals

- **No OIDC / SSO / federation.** Consistent with ADR-018. WebAuthn here is local
  to the controller — a credential registered against a CFGMS account, not an
  external IdP.
- **No continuous access evaluation in v1.** Assurance is computed at
  authentication, on silent re-proof, on step-up, and on the IP-change downgrade.
  A broader signal pipeline (device posture, EDR health, impossible travel) is a
  later increment the model is shaped to accept — Decision 3's silent re-proof is
  the first increment of it and the mechanism the rest hangs off.
- **No TOTP as a high-trust factor** (see Decision 1).
- **No hard IP locking** (see Decision 5).
- **No blanket re-authentication timer** (see Decision 2).
- **No new credential storage backend.** WebAuthn credentials are public keys —
  they extend the existing web-account record; they do not need secret storage.

---

## Consequences

### Positive

- A phished cookie no longer confers fleet-wide code execution. The dominant
  browser risk (ADR-018 names XSS token exfiltration as exactly this) is bounded:
  a stolen session is `AssuranceBasic` and cannot approve a module bundle without
  a device-bound key the attacker does not hold.
- The gate stops lying. `permissionAssurance` enforces what its name says.
- The unwritten "every web account is an admin account" assumption stops being
  load-bearing. A future non-admin web account type is a level, not a silent
  privilege grant.
- Automation is bounded by construction: `AssuranceMachine` is terminal and cannot
  step up.
- **Malware on the admin's own machine is bounded too** — the case no timer and no
  continuity check reaches. `RequireUserPresence` demands a gesture the malware
  cannot produce, for exactly the actions where that matters.
- **The control fires rarely.** Silent re-proof means an operator working
  continuously is never interrupted; the only prompt is a key touch when approving
  a module bundle. A control that fires rarely is a control that survives contact
  with operators instead of being designed around.

### Negative / costs

- **Breaking change, taken deliberately.** `Principal.IsAdmin`, `authTier`,
  `requireTier`, and `tier3Permissions` all change or disappear. Per the pre-GA
  policy this is a hard replacement — no shim, no dual-gate transition, no
  deprecation window.
- **Sessions gain device-continuity state that does not exist today.**
  `pkg/session.Session` (`contract.go:31-39`) records only ID, ConnectionName,
  PrincipalID, TenantID, IssuedAt, LastActivity, AbsoluteExpiresAt — **no device
  identity and no network context.** `RemoteAddr` and `User-Agent` are only ever
  logged (`handlers_web_session.go:138,152,223,287`), never stored. Decisions 3 and
  5 require binding a session to the credential that established it and recording
  network context to detect change. This is net-new state on a struct that is
  currently in-memory only (the store drops on controller restart; a durable/shared
  store is deferred to #2051) — a shared store makes this state a cross-node
  concern.
- Every current Tier-3 route's tests change shape (403 → 401 + challenge).
- The web UI gains a re-authentication modal and a retry path — real work in every
  story that touches a mutating admin surface.
- `cfg` gains a step-up prompt and a non-interactive failure mode that must be
  scriptable (an operator running `cfg` in CI needs a comprehensible error, not a
  hang).
- WebAuthn registration/recovery becomes a first-class flow: an admin who loses
  their only authenticator must have a recovery path that is not itself a
  downgrade attack. **This is the hardest problem in this ADR and must be designed,
  not discovered.**

### Migration

`authTier` (0–3) and `tier3Permissions` are **superseded**. Every existing
`requireTier(TierMTLSOnly)` route becomes an entry in `permissionAssurance`
requiring `AssuranceStrong`. The `TierMTLSOnly` constant, its misleading comment,
and the `requireTier` middleware are deleted rather than deprecated.

The startup scan referenced in `auth_tiers.go:20-22` ("S4's startup scan reports
keys holding any of them") is preserved in intent: it becomes a scan reporting API
keys granted permissions that `permissionAssurance` marks as requiring a level
above `AssuranceMachine` — such grants are unsatisfiable and should be surfaced as
configuration errors at boot.

---

## 7. Bootstrap and recovery ride the existing mTLS cert root of trust

> **Amended 2026-07-24 — see [Amendment 1](#amendment-1-2026-07-24-browser-passkey-self-enrollment-for-accounts-without-a-phishing-resistant-authenticator).** The absolute in this section — *"the browser never sees credential enrollment"* — was too strong and made CFGMS not fully web-manageable: a web-only, password-only admin could never obtain a first passkey and so could never reach `AssuranceStrong` from a browser. Amendment 1 permits **first-passkey self-enrollment from the browser for an account that holds no phishing-resistant authenticator** (an *upgrade*, with nothing to downgrade), while keeping this section's anti-downgrade rule intact for every account that already has one, and keeping the **cert path** as the recovery route for a *lost* sole authenticator.

An admin obtains their first strong authenticator — and replaces a lost one — by
**registering a passkey via `cfg`, authenticated with their mTLS admin cert.**

This is the one design constraint the whole model rests on, because **every obvious
recovery path is a downgrade attack**: if a phishable credential (password + email)
can mint a phishing-resistant one, then phishing the password still yields
everything and the model is decorative. The cert path avoids that by construction:

- The cert is already `AssuranceStrong` — re-enrolling from it is not a downgrade.
- The cert is already the root of trust: it is how `cfg` authenticates and it
  already satisfies every current Tier-3 gate. **This adds no exposure** — whoever
  holds the cert file is already omnipotent today. The ADR names the existing root
  of trust rather than inventing a second one.
- **The browser never sees a client certificate.** The cert stays in the CLI where
  it already lives, so this does not reintroduce the browser client-cert selection
  UX that Decision 1 rejects.

Bootstrap and recovery are therefore the same flow: `cfg`, cert, register passkey.
A fresh controller's first admin has a cert by definition — that is how the
controller is administered.

**Consequence to accept deliberately:** the admin cert file becomes the credential
that can mint browser authenticators. It should be protected accordingly (HSM/OS
keystore where available). This is a restatement of today's reality, not a new risk.

## 8. Automation is terminal at `AssuranceMachine` — no exception mechanism

No automated or non-interactive flow legitimately needs a permission in
`permissionAssurance`. API-key principals therefore **cannot step up, and no
elevation escape hatch is provided**. A CI pipeline cannot approve a module bundle,
add a trusted publisher, provision an account, or decommission a steward.

This is stated as a decision rather than left implicit so that a future
implementer who hits the wall treats it as the design working, not a gap to route
around. If an automated flow ever genuinely needs one of these, that requires a new
ADR — a scoped, audited machine-elevation grant — not a weakened gate.

---

## Sequencing: blocked on a durable session store

Decisions 3 and 5 add **device-continuity and network-context state to
`pkg/session.Session`**, which records neither today (`contract.go:31-39`). That
state must not be built on the current `MemStore`.

**This ADR's epic is blocked on a durable/shared session store for `pkg/session`
covering both managers** (`sessionManager` for `cfg`, `webSessionManager` for the
browser — `server.go:126,128`). Rationale: continuity state on a per-node in-memory
store means a node failover looks like a device change and **downgrades every
session at once**; and building the state twice — once on `MemStore`, once on the
durable store — is waste we can see coming.

**That work was orphaned and is now scheduled.** `pkg/session/contract.go:95` defers
it to "the SaaS cluster story (#2051)", but **#2051 is CLOSED and its scope never
included sessions** — its success criteria cover DNA/fleet, config, and audit
durable state only. The deferral pointer is stale and points at an epic that never
owned the work.

It now has an owner: **epic #2735** (durable controller session store), story
**#2736** — which also corrects the stale comment. **This ADR's epic (#2737) is a
hard dependent of #2736** and must not begin implementation until it merges.

Note this is distinct from `pkg/storage/interfaces/business.SessionStore` (durable,
with `database` and `sqlite` providers), which is a different type for a different
purpose — used by `features/rbac/jit` (unwired) and `cmd/cfg/cmd/session_token.go`.
Whether the `pkg/session` durable store reuses it or defines its own is an
implementation question for that story.

---

## Remaining tunables (PO-set, founder may override)

These do not block decomposition and are config, not design:

1. **The `RequireUserPresence` set** — `module:approve`, `module:reject`,
   `publisher-trust:add`. Every addition spends operator patience, and a control
   that fires too often gets designed around; the set should stay small enough that
   a key touch always feels proportionate to what it authorizes. **Growing it is a
   founder decision, not a reviewer's judgement call.**
2. **Silent re-proof cadence** — re-prove on network-context change, after an
   activity gap, and otherwise on a ~5-minute interval. Unlike a step-up timer this
   is invisible to the operator, so it can be aggressive at no UX cost. When silent
   proof is impossible (no credential available on this device), fall back to
   `AssuranceBasic` and step up on the next sensitive action.

---

## Per-tenant tightening of `permissionAssurance` (Issue #2845)

The `permissionAssurance` map in `features/controller/api` is a global registry —
the same floor applies to every tenant. Operators may need stricter floors for
specific tenants (e.g. a managed tenant with elevated security requirements).

**Storage substrate (Issue #2845):** `business.AssurancePolicyStore`, defined in
`pkg/storage/interfaces/business`, stores a set of `AssurancePolicyOverride`
entries per tenant. Each entry carries a `PermissionID`, an optional `MinOverride`
(`*int`, mirroring `session.AssuranceLevel` values: 0=Machine, 1=Basic, 2=Strong),
and a `RequireUserPresence` flag. The store is wired for the `database`
(PostgreSQL) and `sqlite` providers only — the `git`/SOPS config-storage path is
untouched, matching the precedent set by `RefreshPolicyStore`.

`SetPolicy` replaces the tenant's **entire** override set in one call (full-replace
/ PUT semantics). `GetPolicy` returns `{TenantID: id, Overrides: nil}` without
error when no record exists — absence and "no override" are equivalent.

**Resolution (Issue #2839):** `requirePermission` calls
`s.resolveAssuranceRequirement(ctx, tenantID, permissionID)`, which composes
the global `permissionAssurance` floor with any per-tenant overrides declared
along the root→leaf path to the requesting tenant:

- `Min` takes the **maximum** across [global floor, each ancestor, the tenant itself].
- `RequireUserPresence` is true if true anywhere in that chain (OR, never cleared by a
  descendant).
- When `assurancePolicyStore` or `tenantStore` is nil, or `tenantID` is empty, the
  resolver returns the global floor unchanged — preserving today's exact behaviour for
  bare `Server` instances (e.g. unit tests that do not wire a store).
- Store errors cause a Warn log and fall back to the global floor — a storage hiccup
  must never turn a permitted action into a fleet-wide outage.

**Admin endpoint (Issue #2839):**

- `GET /api/v1/tenants/{tenant_path}/assurance-policy` — reads the stored override set
  for a tenant. Gated by `requirePermission("assurance-policy", "get")`. `assurance-policy:get`
  is intentionally absent from `permissionAssurance` so reads stay unrestricted at the
  assurance layer (matching `refresh:get-policy`'s absence from that map).
- `PUT /api/v1/tenants/{tenant_path}/assurance-policy` — replaces the full override set
  (full-replace / PUT semantics). Gated by `requirePermission("assurance-policy", "set")`.
  `assurance-policy:set` IS in `permissionAssurance` at `Min: AssuranceStrong` — a
  strongly-authenticated admin is required to raise a tenant's own posture.

**Tighten-only enforcement (Issue #2839):** `handleSetAssurancePolicy` validates each
requested `MinOverride` against the ancestor-resolved requirement (global floor + ancestor
path, excluding the tenant being written) **before** calling `SetPolicy`. A `MinOverride`
below the ancestor-resolved `Min` is rejected with 400. `RequireUserPresence` needs no
such check — because resolution ORs it across the whole chain including ancestors, a
leaf tenant structurally cannot lower it by omitting or setting it false.

**Note on `scanAPIKeysForPrivilegedAccess`:** The startup scan reads `permissionAssurance`
directly (global-only). Overrides only ever tighten, so the global-floor scan remains a
correct (if conservative) lower bound on which API keys are unreachable. Tenant overrides
do not affect this scan — they cannot make a key reachable that is already blocked.

---

## Amendment 1 (2026-07-24): Browser passkey self-enrollment for accounts without a phishing-resistant authenticator

**Status:** Accepted · **Deciders:** Founder, Architecture · **Amends:** §7

### Why §7 was too strong

§7 rested on one absolute — *"the browser never sees credential enrollment; the
first passkey is enrolled via `cfg` with the mTLS admin cert."* That constraint
made CFGMS **not fully web-manageable**, which every RMM must be. Its concrete
failure: a **web-only account created with a password and no MFA** (the normal way
an MSP onboards a new operator) can *never* obtain a first passkey, because
enrollment requires a cert it does not have. It therefore can never reach
`AssuranceStrong` and can never perform any privileged action from the browser —
including the very act (`+ New account`) that would let it grow the team. The
account is permanently stuck at `AssuranceBasic`. This is the root cause of the
web-session Strong-assurance gap.

The founder's decision: **§7's prohibition was a mistake.** CFGMS must let a
no-MFA account self-enroll a passkey from the browser, under minimal-standing-
privilege, strong-auth-at-time-of-use, and zero-trust.

### The resolution: passkey-only human accounts, forced enrollment via a single-use magic link

§7's anti-downgrade argument is **correct and retained**: a phishable credential must
never mint or recover a phishing-resistant one *for an account that already has strong
auth*. The gap §7 over-corrected was **bootstrap** — it made the browser incapable of
producing a *first* passkey at all, so a web-only account was stuck at `AssuranceBasic`
forever.

The fix (founder-decided 2026-07-24) removes the phishable factor entirely rather than
managing it: **human accounts are passkey-only — they have no password at all.**

- **Passkey-only, mandatory, and multiple.** A human account holds **one or more
  passkeys** and no password. Multiple passkeys are **supported and encouraged for
  anti-lockout** — a second passkey on another device (phone + laptop + hardware key) is
  the primary self-recovery path, not an admin ticket. There is no password to phish, so
  the entire "phished password → Strong" surface these amendments worried about **does
  not exist** for human accounts.
- **Forced first-passkey enrollment via a single-use magic link.** Provisioning mints a
  **single-use, TTL-bounded enrollment magic link**, delivered either **shown once in the
  admin UI** for out-of-band handoff **or emailed** to the new user. Redeeming it forces
  first-passkey registration and consumes the link. A no-passkey account can do **exactly
  one thing** — redeem its link and register a first passkey; every other request is
  refused. A link stolen before the legitimate redemption is useless once redeemed, and
  expires on TTL regardless. The residual exposure is the narrow admin→human handoff
  window of a single-use, short-TTL link — the same irreducible onboarding-secret window
  every system has — not a durable phishable password.
- **QA and bootstrap use the mTLS admin cert**, in the browser as well as in `cfg`. The
  privileged bootstrap path depends on no shared secret at all; a fresh deployment is
  administered from a cert (§7).

A *first* passkey is still an **upgrade** (there is nothing to downgrade from); the
upgrade happens under a forced, single-use magic-link ceremony rather than an open-ended
"password ⇒ passkey" endpoint.

### Decision

1. **Passkey-only, mandatory, multiple.** Human accounts have no password. Each holds one
   or more passkeys; login is a WebAuthn passkey assertion. Registering **additional
   backup passkeys is expected** (anti-lockout). An account with zero passkeys is confined
   to a single permitted action — first-passkey enrollment — and every other request is
   refused. Enrollment is self-scoped to the account the redeemed link identifies, never
   an arbitrary target, and its "zero existing authenticators" precondition is enforced
   **server-side at the finish step** (compare-and-swap on credential-count == 0), never
   inferred from the client.

2. **First-passkey enrollment rides a single-use magic link.** Account provisioning mints
   a single-use, TTL-bounded enrollment link, delivered **shown-once in the admin UI or
   by email**. Redeeming forces first-passkey registration and invalidates the link; a
   reused or expired link is rejected.

3. **Adding or removing a passkey is gated at `AssuranceStrong`.** Once an account holds
   ≥1 passkey, registering an **additional (backup) passkey** — the routine anti-lockout
   action — or removing one requires step-up with an existing passkey (Amendment 2). No
   magic link is involved after the first passkey. A stolen session with no passkey can
   never add one to an enrolled account.

4. **Recovery is self-service while any passkey survives.** With multiple passkeys,
   losing one device is self-service: assert a surviving passkey, register a replacement.
   Only when **all** passkeys are lost does recovery need the **cert path (§7)** or an
   **admin-mediated reset** — an operator at `AssuranceStrong` re-provisions the account
   to the zero-authenticator state and issues a **fresh** single-use magic link,
   invalidating any residual credentials. There is no password path, ever.

5. **Enrollment grants no standing privilege.** A passkey is a *credential*, not an
   entitlement. Privileged actions still require step-up to `AssuranceStrong` at time of
   use (Decision 6 / Amendment 2). Enrolling makes future elevation *possible*; it does
   not elevate the current session.

### Consequences

- A new operator redeems a single-use magic link, registers a first passkey, registers a
  backup passkey, and manages the fleet from the browser — CFGMS is fully web-manageable
  with **no password anywhere** in the human-account model.
- The phishable-factor attack surface for human accounts is **removed, not bounded**:
  there is no password to phish, so a phished-credential → Strong path does not exist. The
  only onboarding residual is the single-use, short-TTL magic-link handoff window.
- Losing a device is self-service (a surviving backup passkey), not an admin ticket —
  which is why multiple passkeys are mandatory to encourage, not merely allowed.
- QA / bootstrap administers a fresh controller entirely from the mTLS cert (§7), browser
  included.
- Implementations MUST enforce rules 1–4 server-side: the zero-authenticator confinement,
  the finish-step CAS precondition, single-use + TTL on the magic link, and the
  Strong-gate on adding/removing passkeys are all controller-side, never client-inferred.

**Consequence to design separately (not in this amendment):** passkey-only human accounts
means the **password web-login path retires** — login becomes a passkey assertion, and a
login-time assertion (`userVerification: "required"`) is itself phishing-resistant and may
establish `AssuranceStrong` directly (subject to Decision 3 continuity), collapsing much of
the Basic→Strong step-up need for humans to the *lost-continuity re-proof* case. That login
redesign is a related but separate change; it is flagged here and tracked as its own story,
not specified in this amendment.

### Scope

This amendment is implemented alongside the web-session step-up handler (Epic #2931):
first-passkey magic-link enrollment (this amendment) + backup-passkey management
(Strong-gated) + the elevation ceremony (Amendment 2). Together they make human accounts
passkey-only and fully web-manageable.

**Implementation reference — enrollment link mint (Issue #2974):** The admin-UI side of
Decision 2 ("shown-once in the admin UI") is implemented in Story #2974. It gates the
`+ New account` button behind `AssuranceStrong` step-up via the `apiFetch` interceptor,
mints a 160-bit (20-byte) single-use enrollment token on account creation, stores only
the SHA-256 hex digest in the account record (never the raw token), shows the raw token
exactly once in the admin UI for out-of-band clipboard handoff, and provides a revoke
endpoint for outstanding unredeemed links. The token TTL defaults to 72 hours and is
configurable via `registration.enrollment_link_ttl` (`RegistrationConfig.GetEnrollmentLinkTTL`,
Issue #2966) rather than a hardcoded constant. Email delivery (also mentioned in Decision 2)
is explicitly deferred to a future notification-provider epic (CLAUDE.md central-provider
rule). The raw token is never logged or audited; audit records carry the
`delivery_method` field (`"ui-shown"`) and whether a link was minted.

Two invariants enforce Decisions 3 and 4 on that mint path:

- **A link is minted only against the zero-authenticator state.** `POST
  /api/v1/web/accounts` refuses to issue a token for an account that already holds a
  registered credential — Decision 3's "no magic link is involved after the first
  passkey" — and returns the account record with no `enrollment_magic_link`. The
  admin-mediated reset of Decision 4 is the request field `reset_credentials`: it
  discards every registered passkey ("invalidating any residual credentials") and only
  then issues a fresh link.
- **Provisioning is tenant-scoped.** Create, list and revoke all confine the caller to
  its own tenant subtree, so a tenant-scoped web admin cannot obtain an enrollment
  bearer token for another tenant's account or grant itself a root-scoped one.

**Implementation reference — enrollment link redemption (Issue #2966):** The browser
side of Decision 2 ("redemption via magic link") and Decisions 5–6 (confinement and
CAS) is implemented in Story #2966.

- **Redemption endpoints** — `POST /api/v1/web/passkey/enroll/begin` and `.../finish`
  are registered on the base router (no `authenticationMiddleware`; the token is the
  credential) with the `authDefense` middleware for DoS protection. They take the raw
  token in the `X-Enrollment-Token` header; account resolution is fully token-driven
  (`getWebAccountByEnrollmentToken`). No caller-supplied username or path variable is
  consulted — eliminating cross-account credential injection.
- **Single-use gate** — `passkeyEnrollSessions.LoadAndDelete(tokenHash)` makes the
  in-flight ceremony atomically consume the session; a second concurrent finish call
  sees no session and gets `NO_ACTIVE_ENROLLMENT`.
- **CAS precondition at finish** — after WebAuthn verification succeeds, the handler
  reloads the account from the durable store (`loadWebAccountFromStore`) and rejects
  the request with `ALREADY_ENROLLED` if any credential is already present, enforcing
  the zero-authenticator precondition under concurrent access.
- **Token consumed on success** — `EnrollmentLinkRevoked = true` is persisted
  immediately; subsequent begin calls with the same token get `TOKEN_INVALID`.
- **Confinement middleware** — `enrollmentConfinementMiddleware` is added to the `/api/v1`
  subrouter (runs after authentication, before `requirePermission`). It blocks every
  request from a cookie-authenticated session whose `AuthenticatorCount` is ≤ 0 with
  `403 ENROLLMENT_REQUIRED`. mTLS admin and API-key principals are never blocked
  (their `cookieAuth` context key is false).
- **`webauthn:register` (add-to-existing) stays at `AssuranceStrong`.** The enrollment
  redemption routes have no entry in `permissionAssurance`; they are fully public.

Revocation is fail-closed: the durable record is written before the in-memory cache is
updated, so a store failure leaves a still-revocable outstanding link rather than a
cache that claims revoked while the persisted link stays live.

---

## Amendment 2 (2026-07-24): Web-session Basic→Strong elevation via WebAuthn assertion

**Status:** Accepted · **Deciders:** Founder, Architecture · **Extends:** Decisions 3 and 6 · **Implements the addendum Epic #2931 required before decomposition**

The assurance model (Decisions 1–6) defined the *levels* and the step-up *challenge*,
but the specific ceremony that raises an **existing** password-authenticated web session
from `AssuranceBasic` to `AssuranceStrong` was left as "future" (named verbatim at
`handlers_webauthn.go:233-237`, unbuilt). Without it, no browser session can reach Strong
and every `Min: AssuranceStrong` action 401s with `WWW-Authenticate: CFGMS-StepUp`. This
amendment specifies that ceremony and its threat model.

### The ceremony

1. A `Min: AssuranceBasic` session encounters a `Min: AssuranceStrong` action and receives the
   step-up challenge (Decision 6). The client calls a **step-up assertion endpoint**, itself
   callable at `AssuranceBasic`.
2. The controller issues a **single-use, server-generated challenge bound to the current
   session**. The browser produces a **WebAuthn assertion** (`userVerification: "required"`)
   signed by a credential **already registered to the account** (via `cfg`/cert per §7, or via
   browser self-enroll per Amendment 1).
3. The controller verifies: challenge match, RP ID + **origin binding**, signature against the
   registered public key, and a **monotonically advancing signature counter** (clone/replay
   detection).
4. On success the controller **elevates the existing session in place** — sets
   `Principal.Assurance = AssuranceStrong` on the *same* session. **No new session is minted**,
   preserving session continuity and the CSRF binding. The original request is retried by the
   client's step-up interceptor.

### Threat model and bounds

- **Elevation is not permanent.** The Strong state is subject to the same continuity and
  downgrade rules as Decision 3: silent device proof maintains it; a network-context change
  (Decision 5), a long activity gap, or the configurable interval triggers re-proof, and a
  failed/impossible proof downgrades to `AssuranceBasic` (requiring a fresh assertion). Step-up
  buys an **elevation window**, not a standing Strong session.
- **Replay / clone.** The challenge is single-use and session-bound; the counter must advance.
  A stolen cookie replayed from the same network still cannot elevate — it holds no private key
  (the reasoning in Decision 3 applies identically).
- **Phishing resistance.** WebAuthn origin binding makes the assertion unphishable: it is valid
  only for the controller's RP ID. A phished password yields at most `AssuranceBasic`.
- **Orthogonal to presence tokens (Decision 4 / #2784).** Elevation raises the *session's
  assurance level*; it does **not** substitute for the per-action human-presence gesture that
  the `RequireUserPresence` catastrophic actions demand. An elevated Strong session still mints
  a presence token for each of those permissions. Elevation and presence are distinct layers.
- **Composes with Amendment 1.** A freshly self-enrolled passkey is immediately usable as the
  assertion credential here — that is how a no-MFA account completes password → self-enroll →
  assert → Strong in a single browser sitting, with no cert.

### Scope note

This supersedes Epic #2931's original "Out of scope: browser never sees credential enrollment"
line — browser first-passkey enrollment is now in scope via Amendment 1. Epic #2931 therefore
decomposes into the elevation assertion handler (this amendment), the browser self-enrollment
backend + UI (Amendment 1), the step-up modal + `apiFetch` interceptor, and the held write-action
wiring (W1–W5) that becomes reachable once elevation works.

---

## Amendment 3 (2026-08-13): Self-service passkey management UI, IDOR fix, and server-side anti-lockout guard

**Status:** Accepted · **Deciders:** Founder, Architecture · **Amends:** §7 (annotation) and Amendment 1 Decision 3/4 (implementation)

### Context

Amendment 1 established that human accounts are passkey-only, that adding/removing a passkey is gated at `AssuranceStrong`, and that losing all passkeys requires the cert path (§7) or an admin-mediated reset. Three gaps remained unimplemented:

1. **IDOR vulnerability in credential management endpoints.** `GET /webauthn/credentials` and `POST /webauthn/revoke/{credential_id}` resolved the target account from the URL path parameter `{username}` rather than from the authenticated session — any cookie-auth user could enumerate or revoke another user's passkeys by changing the path.
2. **No server-side anti-lockout guard.** The server permitted cookie-auth principals to remove their last passkey, which would produce an unrecoverable browser account (no cert fallback for human web accounts — see annotation to §7 below). The spec comment in the earlier implementation claimed "the guard lives in the CLI", which was incorrect for the browser-session context.
3. **No self-service passkeys UI.** There was no browser page where a logged-in user could list, add, and remove their own passkeys.

### Decisions

1. **IDOR fix — session-scoped account resolution.** All passkey management endpoints (`list`, `register/begin`, `register/finish`, `revoke`) resolve the target account from the authenticated session (principal UUID from `principalContextKey`), not from the URL path parameter. For cookie-auth sessions: the target account is `getWebAccountByID(ctx, principal.ID)` — a UUID lookup that is not attacker-controlled. The path parameter `{username}` is validated only to confirm it matches the session account; a mismatch returns `403 FORBIDDEN`. mTLS/API-key admin paths are unchanged — they retain the admin-scoped path-parameter lookup, which is correct (admins may manage other accounts).

2. **Server-side anti-lockout guard for cookie-auth principals (Amendment 1 Decision 4 implementation).** `POST /webauthn/revoke/{credential_id}` now enforces: if the caller is cookie-authenticated (`cookieAuthContextKey=true`) and removing the credential would leave the account with zero passkeys, the request is rejected with `409 Conflict` / `LAST_CREDENTIAL`. mTLS/API-key callers are exempt — they retain the cert-based recovery path described in §7. The error message instructs the user to add a backup passkey first, or request an admin reset.

3. **Atomic CAS for the last-credential check.** The last-credential check and the credential removal are a single compare-and-swap: `credentialMu.Lock()` → fresh durable-store reload (`loadWebAccountFromStore`) → check remaining count → persist → unlock. This prevents two concurrent revokes from each observing the pre-removal count, both passing the guard, and both persisting zero credentials.

4. **Self-service passkeys page.** A "My Passkeys" view accessible at `/passkeys` (linked from the user menu) lets a cookie-auth principal list their registered passkeys, add a backup passkey (WebAuthn `navigator.credentials.create()` gated by step-up), and remove a passkey (step-up gated, blocked by the anti-lockout guard if it would be the last).

5. **Audit events.** `web_account.passkey_added` and `web_account.passkey_revoked` audit events are emitted on successful add and remove respectively, matching the pattern of the existing `web_account.passkey_enrolled` event.

### Annotation to §7 — human web accounts have no mTLS cert fallback

§7 states "the cert path" as the recovery route for a lost sole authenticator. This is accurate for mTLS-authenticated principals (CLI operators, service accounts). It is **not applicable to human web accounts** (Amendment 1): human web accounts are passkey-only and have no associated mTLS client certificate. A human who loses all passkeys cannot recover via cert — they require an admin-mediated account reset (Decision 4 of Amendment 1: "an operator at `AssuranceStrong` re-provisions the account to the zero-authenticator state and issues a fresh single-use magic link"). The server-side anti-lockout guard (Decision 2 above) enforces this: it prevents the browser-self-service path from reaching zero credentials, leaving the emergency reset path as the only way out of a total lockout.

**Implementation reference (Issue #2992):** IDOR fix via `resolveWebAccountForCredentials` helper; anti-lockout guard + CAS under `credentialMu` in `handleWebAuthnRevokeCredential`; self-service passkeys page at `web/src/passkeys/PasskeysView.tsx`; audit helpers `emitPasskeyAddedAudit` / `emitPasskeyRevokedAudit` in `features/controller/api/handlers_webauthn.go`.

## Amendment 4 (2026-08-28): Relying party is configuration, has no default, and wiring it exposed a CLI-relay regression

**Status:** Accepted · **Deciders:** Founder, Architecture · **Amends:** none (closes a wiring gap; documents a consequence)

### Context

`NewWebAuthnFromConfig` and `SetWebAuthn` (`features/controller/api/handlers_webauthn.go`) — the
constructor and installer for the WebAuthn relying party every handler in this ADR depends on —
had no caller in the controller binary. Every shipped controller answered
`/api/v1/web/passkey/login/begin`, `/api/v1/web/passkey/login/finish`, and
`/api/v1/webauthn/presence/begin|finish` with `503 WEBAUTHN_NOT_CONFIGURED`, unconditionally. All
of §3 (silent device proof) and §4 (human-presence gesture) of this ADR, and Amendments 1–3 built
on top of them, were unreachable from a browser. Issue #3713 closes this: `cmd/controller/main.go`
now builds the relying party from a new `webauthn:` controller-configuration block
(`features/controller/config.WebAuthnConfig`: `rp_id`, `rp_display_name`, `rp_origins`) and installs
it via `SetWebAuthn` before the API server starts.

**There is no default.** An absent or empty `rp_id` leaves every passkey endpoint at 503, exactly
as before this issue — the same behavior a pre-#3713 controller always had. A plausible-looking
fallback identifier (e.g. `localhost`) would let a phishing-resistant authenticator complete a
ceremony against an identifier the operator never chose, which is worse than refusing the request.
`ValidateWebAuthn` (`features/controller/config/config.go`) and `NewWebAuthnFromConfig` both refuse,
loudly, at startup: `rp_id` set with no `rp_origins`, or any `rp_origins` entry that is not `https://`.
There is no local-development bypass for either check.

### The regression this wiring causes, and the fix it does not accept

Two existing `cfg` CLI commands run a WebAuthn ceremony from a page served at
`http://127.0.0.1:<random-port>`: the presence relay in `cmd/cfg/cmd/stepup.go` (used by the
non-interactive step-up flow) and the registration relay in `cmd/cfg/cmd/webauthn.go` (`cfg webauthn
register`). A browser enforces that the relying-party identifier is the calling origin's effective
domain (or a registrable suffix of it) before it will run `navigator.credentials.create()` /
`.get()` at all — an IP-literal origin like `http://127.0.0.1` can only satisfy an RPID of exactly
`127.0.0.1`, never a real domain. Before this issue, this was invisible: both relays hit the
begin endpoint first, which always answered 503 before the browser ever ran the ceremony. **Once a
production `rp_id` is configured, that masking disappears** — the begin call now succeeds, the
browser opens the ceremony at the loopback origin, and the browser itself refuses it with a
same-origin/RPID mismatch. Both commands break for real, for every deployment that configures
`webauthn:` to make browser login work.

**Adding `http://127.0.0.1` (or `http://localhost`) to `rp_origins` was considered and rejected.**
`rp_origins` is the relying party's permitted-origin list for every WebAuthn ceremony the controller
ever runs — login, step-up, and passkey registration — not a per-command allowlist. Admitting a
loopback origin would make a plaintext, unauthenticated-by-TLS origin a permanently valid target for
any of them, for every deployment that ever needs the CLI relay to work — the exact class of
weakening Epic #3711's adversarial review already rejected once for the browser-enrolment surface.
No loopback or non-HTTPS origin was added as part of #3713, and `ValidateWebAuthn` /
`NewWebAuthnFromConfig` reject one unconditionally if it ever is.

**Disposition: accepted as a known regression, not fixed by #3713.** The correct fix is for the
loopback relay to run the ceremony under an origin that actually matches the controller's `rp_id` —
e.g. the CLI opens a controller-served relay page (`https://<rp_id>/cli-relay/...`) that
`fetch()`s the result back to the local CLI process, rather than serving the ceremony page from the
CLI itself. That is CLI-relay redirect work, not a config-wiring fix, and is out of scope for #3713
(which is explicitly barred from touching any part of Epic #3711's browser-authenticated-CLI-enrolment
work). It is tracked as a follow-up story under Epic #3711.

### Consequences

- Positive: browser passkey login and passkey step-up (§3, §4, Amendments 1–3) become reachable for
  the first time in a production deployment that sets `webauthn:` in `controller.cfg`.
- Positive: an unconfigured or misconfigured relying party still fails safe — 503 when unset, a
  loud startup error when `rp_id` is set without HTTPS origins.
- Negative (accepted): `cfg stepup`'s presence relay and `cfg webauthn register` stop completing
  their browser ceremony as soon as an operator sets a production `rp_id`. Both commands print the
  relay URL and wait for the browser POST as before; the browser itself refuses the ceremony with a
  same-origin/RPID mismatch, so the operator sees a stuck "waiting for browser ceremony" prompt that
  eventually times out. `cfg webauthn list` / `cfg webauthn revoke` (no ceremony, pure REST calls)
  and the mTLS admin-bundle bootstrap path are unaffected. The admin can still recover via the mTLS
  cert path (§7) or `cfg registration approve` while the follow-up relay-redirect fix lands.

**Implementation reference (Issue #3713):** `features/controller/config.WebAuthnConfig` +
`Config.ValidateWebAuthn`; tightened `NewWebAuthnFromConfig` validation in
`features/controller/api/handlers_webauthn.go`; startup wiring in `cmd/controller/main.go`
(`buildWebAuthnRelyingParty`, called between `server.New` and `runControllerServer`).

---

## Amendment 5 (2026-08-28): Bootstrap credential confinement (Epic #3711)

**Status:** Accepted · **Deciders:** Founder, Architecture · **Extends:** §7 and Decision 4

### Context

Epic #3711 replaces the file-transfer bundle as the ordinary way to obtain a
`cfg` credential with `cfg login` — a browser passkey assertion that mints a
session token and never hands the operator a private key the controller ever
held. `controller bootstrap-admin` remains, because a fresh controller has no
account yet for anyone to log in against: the chicken-and-egg has to break
somewhere. This amendment records what confines the credential that step
produces, so its continued existence is a documented, bounded decision rather
than an unexamined exception.

### The bootstrap credential is controller-custody by construction

`IssueAdminBundle` (`features/controller/initialization/admin_bundle.go`)
generates the certificate's keypair itself and writes both halves into the
bundle file — the controller holds the private key at the moment of issuance.
Every other credential this epic introduces is CSR-based: the requesting party
generates its own keypair and the controller only ever sees the public half
(Epic #3711 D2). The bootstrap bundle is the one credential in the system for
which that is not true, and it is confined precisely because of it.

### What the confinement covers

The bundle's certificate carries `AdminMarkerOID` (`pkg/cert/admin_marker.go`)
and — for a `--root-scoped` bundle — also `RootScopeMarkerOID`. It never
carries `PayloadSigningMarkerOID` (`pkg/cert/payload_signing_marker.go`):
`IssueAdminBundle`'s `TemplateModifier` composes only the admin marker and,
conditionally, the root-scope marker, on every path (Epic #3711 D4). Once signer
verification positively requires the payload-signing marker, a steward will
refuse to execute a payload whose signer lacks it, and the bootstrap credential
— however it is obtained, copied, or misused — will not be able to reach code
execution on a managed endpoint. That is the confinement Epic #3711 D4 names:
*"a credential whose private key the controller has held cannot reach an
endpoint."* It is a stated intent, not a shipped control:

> **[GAP: the positive payload-signing-marker requirement is not yet enforced —
> see Epic #3711, Story #3696. Both signer-verification sites accept any
> admin-marked certificate and never consult the payload-signing marker:
> `verifyOperatorCert` (`features/steward/commands/execute_script.go`) for
> steward-side script execution, and the operator-signature check in
> `features/controller/api/handlers_runs.go` for controller-side ad-hoc runs.
> Both test `cert.HasAdminMarker`; `cert.HasPayloadSigningMarker`
> (`pkg/cert/payload_signing_marker.go`) has no non-test caller repo-wide, and
> `SetPayloadSigningMarker` has no issuance path yet. `IssueAdminBundle` does
> stamp `AdminMarkerOID`, `steward:execute-scripts` carries no
> `RequireUserPresence`, and the bootstrap principal is `ImplicitAdmin` — so
> until #3696 lands, a bootstrap bundle **can** authorise endpoint code
> execution. The bundle's absence of the payload-signing marker (locked by
> `TestIssueAdminBundle_NeverCarriesPayloadSigningMarker`) is a precondition for
> this confinement, not the confinement itself.]**

The same certificate also cannot approve a credential enrolment or renew
itself. Both are catastrophic, credential-granting actions and, like
`module:approve`, require a fresh per-action WebAuthn presence assertion
(Decision 4) — obtainable only for a principal that resolves to a provisioned
account holding registered credentials (`handlePresenceBegin`,
`features/controller/api/handlers_webauthn.go`). `IssueAdminBundle` never
creates an account binding for the certificate it issues, so every request
authenticated with a bootstrap bundle resolves through
`extractAdminPrincipal`'s "no binding found" bootstrap fallback
(`features/controller/api/middleware.go`): an implicit-admin principal keyed
by the certificate's `CommonName`, not by any account. `ImplicitAdmin`
satisfies every *permission* check by construction, but the presence ceremony
resolves the principal to an account by that same `CommonName` and finds
none, so no presence token can ever be minted for it. What blocks the
bootstrap credential here is the presence requirement itself, not an absent
permission string — the principal holds every permission and is refused
anyway.

### What the confinement does not cover

The bootstrap credential still administers the controller: every permission
that does not carry `RequireUserPresence` is available to it, unconditionally,
for as long as the certificate is valid or until it is revoked. At
controller-management actions it is exactly as powerful as any other unscoped
mTLS admin certificate. The confinement is specifically about endpoint
execution and about the narrow set of actions this ADR gates on human
presence — not about the controller's own administration surface.

### Interface substitution remains an accepted non-goal

The controller serves the same browser interface used for both `cfg login`
and enrolment approval, so a compromised controller can present one thing to
an operator and have them authorise another — Epic #3711 D10, inherited
unchanged from Epic #3571 D2. This amendment does not close that gap.
Cryptographic forgery is in scope for the assurance model as a whole; a
controller that lies about what it is showing a human is not. The
compensating controls are the ones Epic #3711 names: the server-side
blast-radius bound described above — which, once Story #3696 lands, will mean
an admin-marked certificate, however obtained, cannot sign a payload a steward
will run, and which today does not hold at all (see the [GAP] above) — and the
audit trail (every bootstrap-fallback authentication is logged —
`emitBootstrapFallbackAudit`, `features/controller/api/middleware.go`). Epic
#3711's decomposition notes that the audit trail's strength against a
host-compromised controller is weaker than that phrase implies, because the
ADR-004 audit chain's signing key lives in the same controller's secret store
(tracked separately, #3727) — that weakness is real and is not resolved by
this amendment.
