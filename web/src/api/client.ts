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
 * The AuthProvider owns this; it fires on any 401 from apiFetch.
 */
export function onSessionExpired(listener: SessionExpiredListener | null): void {
  sessionExpiredListener = listener
}

/**
 * Fetch wrapper for all cookie-authenticated API calls.
 * Same-origin credentials, automatic CSRF header on unsafe methods,
 * central 401 → session-expired handling.
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
    sessionExpiredListener?.()
  }
  return response
}

export interface LoginResult {
  ok: boolean
  status: number
}

/**
 * Login pre-flight + POST (security A7.1 / #2493 contract): obtain the
 * pre-session CSRF token from GET /api/v1/web/csrf (delivered as the
 * `cfgms_csrf_pre` cookie), then echo it as `X-CSRF-Token` on the login
 * POST. Credentials travel only in the JSON body. A 401 here is invalid
 * credentials, never "session expired".
 */
export async function loginRequest(
  username: string,
  password: string,
): Promise<LoginResult> {
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
  const response = await fetch('/api/v1/web/login', {
    method: 'POST',
    headers,
    credentials: 'same-origin',
    body: JSON.stringify({ username, password }),
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
