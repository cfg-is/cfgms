# ADR-021: Identity Assurance Levels and Step-Up Authentication

**Status:** Proposed

**Date:** 2026-07-16

**Deciders:** Founder, Architecture

**Related:** [014](014-cfg-sessions-and-credential-unlock.md) (`cfg` admin sessions — Bearer-token principals gain an assurance level here). [018](018-web-session-semantics.md) (web-session semantics — the cookie session this ADR levels). [006](006-module-packaging-and-distribution.md) (module approval is the highest-blast-radius action gated by this ADR). Auth-tier policy epic #1419 (`authTier` / `tier3Permissions` — **superseded by this ADR**, see Migration). Epic #2713 (web UI management — surfaced the gap this ADR closes).

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

## Open questions for decomposition

1. **Authenticator recovery.** What is the recovery path when an admin loses their
   only passkey/token? Requiring a second registered authenticator is the clean
   answer; the alternative (an mTLS-cert escape hatch) reintroduces a cert path we
   just said browsers should not use. This needs a decision before the WebAuthn
   story is written.
2. **Bootstrap.** The first admin on a fresh controller has no passkey. Does
   initial provisioning happen over the mTLS cert path only?
3. **The `RequireUserPresence` set.** Proposed: `module:approve`, `module:reject`,
   `publisher-trust:add` — actions whose blast radius is fleet-wide code execution.
   Confirm, add, or remove. Every addition spends operator patience, and a control
   that fires too often gets designed around; this set should stay small enough
   that a key touch always feels proportionate to what it is authorizing.
4. **Silent re-proof cadence.** Decision 3 re-proves on network change, after a
   long activity gap, and on an interval. The interval needs a value — but note
   that unlike a step-up timer it is invisible to the operator, so it can be
   aggressive without a UX cost. The real constraint is that a browser can only
   assert silently when the credential is available; confirm the behavior when
   silent proof is impossible (fall back to `AssuranceBasic` and step up on next
   sensitive action, presumably).
5. **`cfg` non-interactive automation.** An operator's CI pipeline holds an API
   key and is `AssuranceMachine` by construction. Confirm that no automated flow
   legitimately needs a permission in `permissionAssurance` — if one does, the
   boundary needs a deliberate exception mechanism rather than an accidental one.
6. **Session store.** Decisions 3 and 5 add device/network state to
   `pkg/session.Session`, which is in-memory only today (a controller restart drops
   all sessions). Confirm whether this lands before or after the durable/shared
   store (#2051) — in a multi-node deployment, continuity state that lives on one
   node means a node failover looks like a device change and downgrades every
   session.
