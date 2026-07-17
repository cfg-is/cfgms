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

### What is actually needed

The distinction that matters is not *transport* (mTLS vs cookie) — it is **how
strongly the human at the other end was authenticated, and how recently**. Some
actions (listing stewards) are fine behind any authenticated session. Others
(approving a module bundle that will execute fleet-wide) should require proof that
is phishing-resistant and fresh.

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
    Assurance     AssuranceLevel
    AuthenticatedAt time.Time // when the credential establishing Assurance was presented
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

### 2. Sensitive actions declare a minimum level and a freshness window

`tier3Permissions` (`auth_tiers.go:20-42`) is already a registry of permissions
that "require something stronger." It is **generalized**, not replaced by a
parallel system:

```go
// Was: tier3Permissions map[string]struct{}
// Now: the minimum assurance + maximum age required to exercise each permission.
var permissionAssurance = map[string]Requirement{
    "module:approve":         {Min: AssuranceStrong, MaxAge: 15 * time.Minute},
    "module:reject":          {Min: AssuranceStrong, MaxAge: 15 * time.Minute},
    "web-account:create":     {Min: AssuranceStrong, MaxAge: 15 * time.Minute},
    "web-account:delete":     {Min: AssuranceStrong, MaxAge: 15 * time.Minute},
    "steward:decommission":   {Min: AssuranceStrong, MaxAge: 15 * time.Minute},
    // ... every current tier3Permissions entry maps here
}
// Anything absent from this map requires only its ordinary permission grant.
```

**Freshness is part of the requirement, not decoration.** `AssuranceStrong`
established eight hours ago is not evidence that the same human is present now.
This is the `sudo`-timeout model: a strong authentication opens a window, and the
window closes.

**Reads stay out.** The existing registry contains **zero** list/read entries
across all eight resources it covers — reads are categorically outside the
elevated surface by design, and `GET /rbac/roles` / `GET /api-keys` are
permission-gated only. That property is preserved: `permissionAssurance` gates
mutations, never reads.

### 3. Insufficient assurance returns a step-up challenge, not a refusal

A caller whose level or freshness is insufficient does **not** get an opaque 403.
The endpoint returns a challenge the client can satisfy and retry:

```
HTTP 401 Unauthorized
WWW-Authenticate: CFGMS-StepUp realm="cfgms", required="strong", max_age=900
{ "error": "step_up_required", "required_assurance": "strong", "max_age_seconds": 900 }
```

- **Web UI:** presents a WebAuthn re-authentication modal; on success the session's
  `Assurance`/`AuthenticatedAt` are raised server-side and the action is retried.
- **`cfg` CLI:** prompts for the security key, or fails with an actionable message
  naming the required level when non-interactive.
- **API-key callers:** cannot step up — `AssuranceMachine` is terminal. They
  receive a plain 403. **Automation cannot self-elevate to approve a module
  bundle**; this preserves the one real boundary the current Tier-3 gate provides.

Step-up is chosen over hard refusal deliberately. Hard refusal pushes admins to
start every session at the highest level and keep it open all day — which
maximizes the lifetime of the most valuable credential and defeats the purpose.

### 4. Network context is a signal that downgrades, never a hard lock

A change in the session's source IP **downgrades the session's effective assurance
to `AssuranceBasic` and clears its freshness**, forcing a step-up on the next
sensitive action. The session is not killed.

Hard-locking a session to its initial IP is explicitly rejected: it breaks on
mobile roaming, corporate NAT egress rotation, CGNAT, and VPN reconnect —
generating lockouts during legitimate work — while an attacker behind the same
egress is unaffected. The device-bound key is what actually defeats cookie replay
from another machine; IP is corroboration, not proof.

This shape is deliberately extensible: `Assurance` is **computed and
re-evaluatable**, so additional zero-trust signals (device posture, EDR health,
impossible travel) can feed the same downgrade path later without redesign.
Continuous evaluation is **not** in v1 (see Non-Goals).

---

## Non-Goals

- **No OIDC / SSO / federation.** Consistent with ADR-018. WebAuthn here is local
  to the controller — a credential registered against a CFGMS account, not an
  external IdP.
- **No continuous access evaluation in v1.** Assurance is computed at
  authentication, on step-up, and on the IP-change downgrade. A real-time signal
  pipeline is a later increment the model is shaped to accept.
- **No TOTP as a high-trust factor** (see Decision 1).
- **No hard IP locking** (see Decision 4).
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

### Negative / costs

- **Breaking change, taken deliberately.** `Principal.IsAdmin`, `authTier`,
  `requireTier`, and `tier3Permissions` all change or disappear. Per the pre-GA
  policy this is a hard replacement — no shim, no dual-gate transition, no
  deprecation window.
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
3. **Freshness window.** 15 minutes is proposed by analogy to `sudo`. Confirm, or
   set per-permission (module approval could reasonably be tighter than account
   deletion).
4. **`cfg` non-interactive automation.** An operator's CI pipeline holds an API
   key and is `AssuranceMachine` by construction. Confirm that no automated flow
   legitimately needs a permission in `permissionAssurance` — if one does, the
   boundary needs a deliberate exception mechanism rather than an accidental one.
