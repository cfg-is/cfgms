# ADR-021: Identity Assurance Levels and Step-Up Authentication

**Status:** Accepted

**Date:** 2026-07-16

**Deciders:** Founder, Architecture

**Related:** [014](014-cfg-sessions-and-credential-unlock.md) (`cfg` admin sessions — Bearer-token principals gain an assurance level here; its `IdleTimeout`/`AbsoluteTimeout` remain and cover the walked-away case). [018](018-web-session-semantics.md) (web-session semantics — the cookie session this ADR levels). [006](006-module-packaging-and-distribution.md) (module approval is the highest-blast-radius action gated by this ADR). Auth-tier policy epic #1419 (`authTier` / `tier3Permissions` — **superseded by this ADR**, see Migration). Epic #2713 (web UI management — surfaced the gap this ADR closes). Epic #2051 (SaaS cluster — **closed without covering sessions**; `pkg/session/contract.go:95` still defers the durable store to it, incorrectly — see Sequencing). `features/rbac/jit` (unwired JIT access — complementary, not superseded; see Context).

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

**That work currently has no owner.** `pkg/session/contract.go:95` defers it to
"the SaaS cluster story (#2051)", but **#2051 is CLOSED and its scope never
included sessions** — its success criteria cover DNA/fleet, config, and audit
durable state only. The deferral pointer is stale and points at an epic that never
owned the work. A story must be filed for it; that story also corrects the stale
comment.

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
