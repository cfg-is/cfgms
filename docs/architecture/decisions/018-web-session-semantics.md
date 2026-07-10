# ADR-018: Web-Session Semantics (Browser Credential Login)

**Status:** Accepted

**Date:** 2026-07-04

**Deciders:** Founder, Architecture

**Related:** Epic #2344 (Web UI Foundation — this ADR is the prerequisite that pins web-session semantics before auth stories are decomposed). [014](014-cfg-sessions-and-credential-unlock.md) (`cfg` admin sessions — the server-side session model this ADR reuses for the browser). `pkg/session` (the existing idle/absolute session manager). Auth-tier policy epic #1419 (session principals must stay consistent with its tiers). Issue #2490 (credential backend — see Addendum 1).

---

## Context

Epic #2344 adds a browser web app, served by the controller alongside the REST
API from a **single TLS endpoint (same origin)**. An administrator authenticates
with a **credential login that issues a web session**, mirroring how `cfg`
authenticates (credential → controller-issued session token). The web UI is a
plain REST client with **no privileged backend path** — the same public API
surface `cfg` uses.

`cfg` (ADR-014) is a stateless CLI that carries its session as
`Authorization: Bearer <token>` and receives a rolling replacement in the
`X-Session-Token` header. A browser is a different execution environment with a
different threat model:

- **XSS token exfiltration** is the dominant browser risk. Any token readable by
  JavaScript (a bearer token in `localStorage`, or even in memory) can be
  stolen by a single script-injection defect in an admin console that pushes
  config, modules, and scripts to endpoints — a large blast radius.
- **CSRF** becomes a risk the moment the browser sends credentials
  automatically (i.e. cookies), and must be addressed if cookies are used.

The controller already has a server-side session model (`pkg/session`,
ADR-014): opaque token, `SHA-256(token)` stored (raw token never persisted or
logged), idle timeout + absolute cap + immediate revocation. The web session
**reuses that model** and changes only how the token is transported to and from
the browser, plus the CSRF defense that transport requires.

---

## Decision

### 1. Session transport — HttpOnly, Secure, SameSite=Strict cookie

On a valid credential login the controller mints the same opaque session token
as ADR-014 (32 bytes `crypto/rand`, base64url, `SHA-256` stored) and returns it
in a cookie:

```
Set-Cookie: cfgms_session=<token>; HttpOnly; Secure; SameSite=Strict; Path=/
```

- **HttpOnly** — the token is unreadable from JavaScript, so an XSS defect cannot
  exfiltrate the session. This is the decisive reason to prefer a cookie over any
  bearer-token-in-JS scheme for a privileged console.
- **Secure** — sent only over HTTPS (external transport is HTTPS-only anyway).
- **SameSite=Strict** — the cookie is never attached to cross-site requests,
  which is the primary CSRF defense (see §3). Clean to adopt because the SPA and
  API are same-origin.
- **Path=/** — one origin serves both SPA and API.

Rolling renewal (ADR-014's `X-Session-Token`) is expressed for the browser as a
refreshed `Set-Cookie` on authenticated responses; the SPA never sees or handles
the token value.

### 2. Lifetime — idle 60m, absolute 12h, server-side revocable

The web session uses the `pkg/session` idle + absolute model, with web-console
tunables **intentionally longer than the `cfg` CLI defaults** (ADR-014: idle
15m / absolute 8h) for operator comfort during long console work:

| Bound | `cfg` CLI (ADR-014) | Web console (this ADR) |
|-------|---------------------|------------------------|
| Idle timeout | 15 min | **60 min** |
| Absolute cap | 8 h | **12 h** |

- **Sliding on activity:** each authenticated request refreshes `LastActivity`
  and re-TTLs the cookie, up to the absolute cap.
- **Server-side, revocable:** logout invalidates the server-side session
  immediately; expiry (idle or absolute) is enforced server-side, not by trusting
  the cookie's own max-age.
- **Session store is in-memory for v1** (consistent with ADR-014): a controller
  restart ends web sessions and forces re-login.

**Tradeoff, accepted knowingly:** the longer idle/absolute bounds widen the
window in which a hijacked or unattended admin session remains usable, relative
to `cfg`. Mitigations: HttpOnly (no JS theft), SameSite=Strict, immediate
server-side revocation on logout, and the option to tighten the tunables later
without a schema change (they are `pkg/session` config values).

### 3. CSRF — SameSite=Strict plus a double-submit token on unsafe methods

`SameSite=Strict` is the primary CSRF defense (cross-site requests carry no
session cookie). As **defense-in-depth** — for the case where SameSite is ever
weakened, bypassed, or a same-site subdomain is compromised — every **unsafe
method (POST/PUT/PATCH/DELETE)** additionally requires a valid CSRF token:

- On login the controller issues a CSRF token in a **non-HttpOnly** companion
  cookie (readable by the SPA), e.g. `cfgms_csrf`.
- The SPA echoes it in an **`X-CSRF-Token`** request header on every unsafe call
  (double-submit). The controller verifies the header matches the cookie and is
  bound to the session; mismatch → `403`.
- **Safe methods (GET/HEAD)** require no CSRF token — the fleet-overview read
  path in this epic is GET-only, so CSRF applies to login, logout, and future
  write endpoints.
- The **login** endpoint itself is not session-CSRF-gated (no session yet); it is
  protected by the credential check and a `SameSite` pre-session token.

### 4. Logout and expiry semantics

- **Logout** is a POST (CSRF-protected) that revokes the server-side session and
  clears both cookies (`Set-Cookie: …; Max-Age=0`).
- On any request against an expired/revoked session, the API returns **401**; the
  SPA drops to the login screen showing the **"session expired"** state (already
  designed in the login mockup).

---

## Consequences

- **Auth stories can now be decomposed** against fixed semantics: login endpoint
  (credential → `Set-Cookie`), session middleware (validate/roll/expire), logout
  (revoke + clear), CSRF issuance + verification middleware, and the SPA's
  401 → login-screen handling.
- The web session **reuses `pkg/session`** rather than introducing a second
  session system — one revocation model, one place to tune lifetimes.
- **CI security gates** (Epic #2344): CSP is defined and served; the cookie flags
  and CSRF middleware are testable server-side; no token ever reaches JS-readable
  storage.
- **No JWT / no refresh token** for v1 — opaque server-side sessions keep
  revocation immediate and avoid client-side token custody entirely.

## Alternatives considered

- **Bearer token in `localStorage`** — simplest and survives refresh, but any XSS
  reads it. Rejected: unacceptable for a privileged console.
- **Bearer token in memory** — not JS-persistent, but still XSS-readable while
  live and lost on every reload (forcing a refresh-token flow that reintroduces
  client-side token custody). Rejected in favor of HttpOnly cookies.
- **SameSite=Strict with no CSRF token** — likely sufficient for a same-origin
  app, but leaves no second layer. Rejected in favor of defense-in-depth given
  the console's blast radius.
- **JWT sessions** — self-contained tokens complicate immediate revocation and
  add client-side custody. Rejected for v1; server-side opaque sessions match
  ADR-014.

---

## Addendum 1 (2026-07-08): Credential backend — local web-admin accounts

**Status:** Accepted (founder decision). **Implements:** Issue #2490.

The original decision pinned transport, lifetime, and CSRF and left the
credential backend — what "a valid credential login" verifies against — open.
This addendum closes it:

- **Local web-admin account store on the controller.** A web-admin account is a
  username + password credential holding the same principal fields the session
  path builds (principal ID, tenant scope, permission strings). Web accounts
  are **RBAC-equivalent to API-key principals** (ADR-014 §7 parity), NOT
  implicit global admins: verification grants exactly the stored permission
  set, validated against the same permission allow-list API keys use.
- **argon2id password hashing, PHC-encoded.** Only argon2id PHC hash strings
  are ever stored — in memory and at rest — never the cleartext password.
  Cost parameters (19 MiB memory, 2 iterations, 1 lane) are encoded in each
  stored hash, so defaults can be raised later without breaking existing
  hashes: verification derives with the parameters parsed from the hash.
- **Durable persistence through the central `pkg/secrets` seam** — the same
  seam API-key records use (`SecretStore.StoreSecret` via
  `pkg/secrets/interfaces`, distinct `secret_type: web_account`), with the
  in-memory map as cache only. Accounts survive controller restart.
- **Tier-3 provisioning only.** `POST /api/v1/web/accounts` (create, and reset
  via upsert) and `DELETE /api/v1/web/accounts/{username}` require an admin
  mTLS certificate (`requireTier(TierMTLSOnly)`); API-key and session-token
  callers are rejected. Create/reset/delete emit sanitized audit events; the
  password value never appears in any log or error response.
- **No enumeration, uniform failure.** Unknown-user and wrong-password produce
  the identical error; unknown-user verification runs against a dummy argon2id
  hash so both paths perform the same key-derivation work.
- **Lockout state:** 5 consecutive verification failures lock the account for
  15 minutes; success resets the counter. The state lives in the account store
  (in-memory, resets on controller restart, consistent with §2's in-memory
  session store); enforcement happens at the login endpoint (#2493).
- **Out of scope, reaffirmed:** TOTP/second factor is out of scope for this
  epic (candidate follow-on); the login mockup's WebAuthn/passkey `mfa` state
  is a designed seam, built later. Reset is admin-driven via the same Tier-3
  endpoint — no self-service reset.
