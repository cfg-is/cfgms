// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * API client for the controller REST API (Story #2495, ADR-018).
 *
 * Session model (cookie transport):
 *  - The session cookie is HttpOnly — this module NEVER reads or names it
 *    (enforced by a source-scan test); the browser attaches it automatically
 *    via `credentials: 'same-origin'`.
 *  - `cfgms_csrf` is JS-readable by design; its value is echoed as the
 *    `X-CSRF-Token` header on every unsafe-method request (double-submit).
 *  - `cfgms_csrf_pre` is the single-use pre-session token that gates the
 *    login POST itself; obtained from GET /api/v1/web/csrf.
 *  - Any 401 on a normal API call means the session is gone (idle/absolute
 *    expiry or revocation) — a central listener drops the app to the login
 *    screen in its "session expired" state (ADR-018 §4). Login and logout
 *    requests are exempt: a 401 there is not an expired session.
 *  - A 401 with WWW-Authenticate: CFGMS-StepUp is NOT a session expiry —
 *    it is a step-up challenge (ADR-021 Decision 6). The onStepUpRequired
 *    listener handles it; the session-expired listener is NOT fired.
 */

const UNSAFE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])

const csrfCookieSession = 'cfgms_csrf'
const csrfCookiePre = 'cfgms_csrf_pre'
const csrfHeader = 'X-CSRF-Token'

/** Read a (non-HttpOnly) cookie value; null when absent. */
function readCookie(name: string): string | null {
  for (const pair of document.cookie.split(';')) {
    const eq = pair.indexOf('=')
    if (eq === -1) continue
    if (pair.slice(0, eq).trim() === name) {
      return decodeURIComponent(pair.slice(eq + 1).trim())
    }
  }
  return null
}

type SessionExpiredListener = () => void
let sessionExpiredListener: SessionExpiredListener | null = null

/**
 * Register the central session-expired handler (or clear it with null).
 * The AuthProvider owns this; it fires on any plain 401 from apiFetch
 * (i.e. a 401 without WWW-Authenticate: CFGMS-StepUp).
 */
export function onSessionExpired(listener: SessionExpiredListener | null): void {
  sessionExpiredListener = listener
}

type SessionConfirmedListener = () => void
let sessionConfirmedListener: SessionConfirmedListener | null = null

/**
 * Register the central session-confirmed handler (or clear it with null).
 * The AuthProvider owns this; it fires on any non-401 response from apiFetch,
 * signalling that the session cookie is valid (Story #2933).
 */
export function onSessionConfirmed(listener: SessionConfirmedListener | null): void {
  sessionConfirmedListener = listener
}

/**
 * Context carried to the step-up listener on a CFGMS-StepUp 401.
 * Includes the original request so the modal can retry it after a successful
 * assertion ceremony (ADR-021 Decision 6).
 */
export interface StepUpRequest {
  /** Original fetch path. */
  path: string
  /** Original fetch init (method, headers, body). */
  init: RequestInit
  /** True when WWW-Authenticate: CFGMS-StepUp includes presence="required". */
  presenceRequired: boolean
}

/**
 * The listener receives the original request and returns a Promise that resolves
 * with the retry Response on success, or null on cancel / assertion failure.
 * Returning null causes apiFetch to return the original 401 response without
 * firing the session-expired listener (the operator stays signed in).
 */
type StepUpRequiredListener = (req: StepUpRequest) => Promise<Response | null>
let stepUpRequiredListener: StepUpRequiredListener | null = null

/**
 * Register the central step-up handler (or clear it with null).
 * The AuthProvider owns this (Story #2786).
 */
export function onStepUpRequired(listener: StepUpRequiredListener | null): void {
  stepUpRequiredListener = listener
  if (listener === null) {
    // Clear any dangling in-progress slot when the provider unmounts.
    stepUpCeremonyDone = null
  }
}

// Concurrent step-up deduplication (Story #2967, ADR-021 Decision 6).
// If two requests from the same tab simultaneously receive a CFGMS-StepUp 401,
// only the first starts the ceremony. Subsequent callers wait for it to finish,
// then retry with a fresh CSRF header. Resolves once the ceremony completes
// (regardless of success/failure) so waiters can attempt one more retry.
let stepUpCeremonyDone: Promise<void> | null = null

/**
 * Fetch wrapper for all cookie-authenticated API calls.
 * Same-origin credentials, automatic CSRF header on unsafe methods,
 * central 401 → session-expired handling, and CFGMS-StepUp 401 → step-up
 * listener dispatch (Story #2786, ADR-021 Decision 6).
 */
export async function apiFetch(
  path: string,
  init: RequestInit = {},
): Promise<Response> {
  const method = (init.method ?? 'GET').toUpperCase()
  const headers = new Headers(init.headers)
  if (UNSAFE_METHODS.has(method)) {
    const cookieValue = readCookie(csrfCookieSession)
    if (cookieValue !== null) {
      headers.set(csrfHeader, cookieValue)
    }
  }
  const response = await fetch(path, {
    ...init,
    headers,
    credentials: 'same-origin',
  })
  if (response.status === 401) {
    const wwwAuth = response.headers.get('WWW-Authenticate') ?? ''
    if (wwwAuth.startsWith('CFGMS-StepUp')) {
      // Step-up challenge: NEVER fire session-expired regardless of listener state.
      // A CFGMS-StepUp 401 means the operator's session is intact but needs a
      // higher assurance proof — the operator is NOT signed out (ADR-021 Decision 6).

      // Concurrent dedup: a ceremony is already running from another simultaneous
      // request in this tab. Wait for it to finish, then retry this request once
      // with a fresh CSRF header. Cap: if the retry is STILL a 401, return it
      // directly — never start a second ceremony for the same original request.
      if (stepUpCeremonyDone !== null) {
        await stepUpCeremonyDone
        const dedupeHeaders = new Headers(headers)
        if (UNSAFE_METHODS.has(method)) {
          const freshCsrf = readCookie(csrfCookieSession)
          if (freshCsrf !== null) dedupeHeaders.set(csrfHeader, freshCsrf)
        }
        return fetch(path, { ...init, headers: dedupeHeaders, credentials: 'same-origin' })
      }

      if (stepUpRequiredListener !== null) {
        // Claim the in-progress slot before awaiting so concurrent 401s see it.
        let ceremonyDone!: () => void
        stepUpCeremonyDone = new Promise<void>((r) => { ceremonyDone = r })
        try {
          const retryResponse = await stepUpRequiredListener({
            path,
            init,
            presenceRequired: wwwAuth.includes('presence="required"'),
          })
          // Cap: return whatever the listener resolved (including a failed 401) —
          // never re-enter the step-up handler for this apiFetch call.
          return retryResponse ?? response
        } finally {
          // Signal waiters before clearing the slot so they see the resolved promise.
          stepUpCeremonyDone = null
          ceremonyDone()
        }
      }
      // No listener registered: return the 401 without firing session-expired.
      return response
    }
    // Plain 401 (no step-up header): session is gone.
    sessionExpiredListener?.()
    return response
  }
  // Non-401 response: the session cookie is valid (or there is no session guard on
  // this endpoint). Signal to AuthProvider that the probe resolved successfully.
  sessionConfirmedListener?.()
  return response
}

export interface LoginResult {
  ok: boolean
  status: number
  username: string  // authenticated principal from the server (Issue #2993)
  tenantId: string  // Issue #2919: empty string means root scope
  rootScope: boolean // Issue #2919: true when tenantId is "" by explicit grant
}

/**
 * WebAuthn assertion JSON sent to POST /api/v1/web/passkey/login/finish.
 * go-webauthn/webauthn serialises challenge + credential IDs as raw base64url
 * strings; the browser's PublicKeyCredential API uses ArrayBuffer — conversion
 * is done in AuthContext before calling this.
 */
export interface AssertionJSON {
  id: string
  rawId: string
  response: {
    authenticatorData: string
    clientDataJSON: string
    signature: string
    userHandle: string | null
  }
  type: 'public-key'
  clientExtensionResults: Record<string, unknown>
}

/** Passkey challenge options returned by POST /api/v1/web/passkey/login/begin. */
export interface PasskeyLoginOptions {
  publicKey: {
    challenge: string
    timeout?: number
    rpId?: string
    allowCredentials?: Array<{
      type: 'public-key'
      id: string
      transports?: string[]
    }>
    userVerification?: UserVerificationRequirement
  }
}

export interface PasskeyBeginResult {
  ok: boolean
  status: number
  options?: PasskeyLoginOptions
}

/**
 * Passkey login begin pre-flight + POST (Issue #2993 / ADR-021 Amendment 1).
 * Obtains the pre-session CSRF token from GET /api/v1/web/csrf (delivered as
 * the `cfgms_csrf_pre` cookie), then echoes it as `X-CSRF-Token` on the begin
 * POST. The optional username scopes to a specific account; omitting it starts
 * a discoverable (usernameless) ceremony. A 401 here is a CSRF failure, not
 * "session expired".
 */
export async function passkeyLoginBeginRequest(username?: string): Promise<PasskeyBeginResult> {
  const preflight = await fetch('/api/v1/web/csrf', {
    credentials: 'same-origin',
  })
  if (!preflight.ok) {
    return { ok: false, status: preflight.status }
  }
  const headers = new Headers({ 'Content-Type': 'application/json' })
  const preCookieValue = readCookie(csrfCookiePre)
  if (preCookieValue !== null) {
    headers.set(csrfHeader, preCookieValue)
  }
  const response = await fetch('/api/v1/web/passkey/login/begin', {
    method: 'POST',
    headers,
    credentials: 'same-origin',
    body: username ? JSON.stringify({ username }) : '{}',
  })
  if (!response.ok) {
    return { ok: false, status: response.status }
  }
  const options = (await response.json()) as PasskeyLoginOptions
  return { ok: true, status: response.status, options }
}

/**
 * Passkey login finish POST (Issue #2993). Sends the WebAuthn assertion to the
 * server; the `cfgms_passkey_ceremony` cookie (SameSite=Strict) provides CSRF
 * protection so no explicit CSRF header is required on this call.
 * Returns the authenticated principal's username and tenant scope on success.
 */
export async function passkeyLoginFinishRequest(assertion: AssertionJSON): Promise<LoginResult> {
  const response = await fetch('/api/v1/web/passkey/login/finish', {
    method: 'POST',
    headers: new Headers({ 'Content-Type': 'application/json' }),
    credentials: 'same-origin',
    body: JSON.stringify(assertion),
  })
  if (!response.ok) {
    return { ok: false, status: response.status, username: '', tenantId: '', rootScope: false }
  }
  let username = ''
  let tenantId = ''
  let rootScope = false
  try {
    const body = (await response.json()) as Record<string, unknown>
    const data = body.data as Record<string, unknown> | undefined
    if (data !== undefined && data !== null) {
      if (typeof data.username === 'string') username = data.username
      if (typeof data.tenant_id === 'string') tenantId = data.tenant_id
      if (typeof data.root_scope === 'boolean') rootScope = data.root_scope
    }
  } catch {
    // Body parse is best-effort; tenant scoping falls back to root (safest for UI).
  }
  return { ok: true, status: response.status, username, tenantId, rootScope }
}

// ── Passkey enrollment (Issue #2966 / #2968) ─────────────────────────────────

/**
 * HTTP request header that carries the single-use enrollment magic-link token
 * for first-passkey enrollment. Must match the server constant (Issue #2966).
 */
const enrollmentTokenHeader = 'X-Enrollment-Token'

/**
 * WebAuthn creation options returned by POST /api/v1/web/passkey/enroll/begin.
 * go-webauthn/webauthn serialises challenge, user.id, and excludeCredentials
 * IDs as raw base64url strings; the browser expects ArrayBuffer.
 */
export interface PasskeyEnrollOptions {
  publicKey: {
    challenge: string
    rp: { id?: string; name: string }
    user: { id: string; name: string; displayName: string }
    pubKeyCredParams: Array<{ type: 'public-key'; alg: number }>
    timeout?: number
    excludeCredentials?: Array<{
      type: 'public-key'
      id: string
      transports?: string[]
    }>
    authenticatorSelection?: {
      authenticatorAttachment?: string
      requireResidentKey?: boolean
      residentKey?: string
      userVerification?: UserVerificationRequirement
    }
    attestation?: string
  }
}

export interface EnrollBeginResult {
  ok: boolean
  status: number
  options?: PasskeyEnrollOptions
}

/**
 * Serialized WebAuthn attestation response for POST /api/v1/web/passkey/enroll/finish.
 * go-webauthn/webauthn expects base64url-encoded attestationObject and clientDataJSON.
 */
export interface AttestationJSON {
  id: string
  rawId: string
  response: {
    attestationObject: string
    clientDataJSON: string
  }
  type: 'public-key'
  clientExtensionResults: Record<string, unknown>
}

export interface EnrollFinishResult {
  ok: boolean
  status: number
}

/**
 * Passkey enrollment begin POST (Issue #2968 / ADR-021 Amendment 1).
 * Validates the single-use magic-link token server-side and returns the
 * WebAuthn registration ceremony options. Uses raw fetch (not apiFetch)
 * because this endpoint is on the public router and the token IS the auth
 * credential — no session or CSRF cookie is required.
 *
 * Returns ok:false when the token is invalid (401), expired, or the server
 * is not configured for WebAuthn (503).
 */
export async function passkeyEnrollBeginRequest(token: string): Promise<EnrollBeginResult> {
  const response = await fetch('/api/v1/web/passkey/enroll/begin', {
    method: 'POST',
    headers: new Headers({ [enrollmentTokenHeader]: token }),
    credentials: 'same-origin',
  })
  if (!response.ok) {
    return { ok: false, status: response.status }
  }
  const options = (await response.json()) as PasskeyEnrollOptions
  return { ok: true, status: response.status, options }
}

/**
 * Passkey enrollment finish POST (Issue #2968 / ADR-021 Amendment 1).
 * Sends the WebAuthn attestation to the server to complete registration.
 * Routes through apiFetch so the `onSessionConfirmed` listener fires on a
 * successful 201 response, establishing the session in AuthContext without a
 * dedicated probe call (same pattern as the fleet view's data call probe).
 *
 * Returns ok:true (201) on success; ok:false otherwise.
 * Callers must check ok before navigating — a non-401 error response still
 * triggers onSessionConfirmed (apiFetch fires it on any non-401), so the
 * caller is responsible for only navigating on genuine success.
 */
export async function passkeyEnrollFinishRequest(
  token: string,
  attestation: AttestationJSON,
): Promise<EnrollFinishResult> {
  const response = await apiFetch('/api/v1/web/passkey/enroll/finish', {
    method: 'POST',
    headers: new Headers({
      'Content-Type': 'application/json',
      [enrollmentTokenHeader]: token,
    }),
    body: JSON.stringify(attestation),
  })
  return { ok: response.ok, status: response.status }
}

/**
 * Server-side logout (CSRF-checked). A 401 means the session was already
 * gone — the caller returns to the signin state either way, so it is not
 * routed through the session-expired listener.
 */
export async function logoutRequest(): Promise<void> {
  const headers = new Headers()
  const cookieValue = readCookie(csrfCookieSession)
  if (cookieValue !== null) {
    headers.set(csrfHeader, cookieValue)
  }
  await fetch('/api/v1/web/logout', {
    method: 'POST',
    headers,
    credentials: 'same-origin',
  })
}
