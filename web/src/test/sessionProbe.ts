// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * AuthProvider reads the signed-in principal from GET /api/v1/web/session when
 * it mounts. Tests that mount AuthProvider around a view and script the view's
 * own requests with a fetch mock wrap that mock with withSessionProbe(), so the
 * provider's session read is answered here and never consumes (or reorders) a
 * response queued for the view. Every other request reaches the wrapped mock.
 */

export const SESSION_PATH = '/api/v1/web/session'

export interface SessionProbePrincipal {
  username: string
  tenant_id: string
  root_scope: boolean
}

/** A root-scoped operator: the scope tests had before the principal was read from the server. */
export const ROOT_PRINCIPAL: SessionProbePrincipal = {
  username: 'test-operator',
  tenant_id: '',
  root_scope: true,
}

function requestPath(input: Parameters<typeof fetch>[0]): string {
  if (typeof input === 'string') return input
  if (input instanceof URL) return input.pathname
  return input.url
}

/** Builds the PasskeyLoginFinishResponse envelope GET /api/v1/web/session answers with. */
export function sessionResponse(principal: SessionProbePrincipal = ROOT_PRINCIPAL): Response {
  return new Response(
    JSON.stringify({
      data: {
        ok: true,
        ...principal,
        expires_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
      },
      timestamp: new Date().toISOString(),
    }),
    { status: 200, headers: { 'Content-Type': 'application/json' } },
  )
}

/** The 401 GET /api/v1/web/session answers when there is no session. */
export function noSessionResponse(): Response {
  return new Response(
    JSON.stringify({ error: { code: 'MISSING_API_KEY', message: 'API key required' } }),
    { status: 401, headers: { 'Content-Type': 'application/json' } },
  )
}

/**
 * Wraps `inner` so GET /api/v1/web/session is answered with `principal` (or with
 * a 401 when `principal` is null: no session until the test signs in) and all
 * other requests are delegated.
 */
export function withSessionProbe(
  inner: typeof fetch,
  principal: SessionProbePrincipal | null = ROOT_PRINCIPAL,
): typeof fetch {
  return ((input: Parameters<typeof fetch>[0], init?: RequestInit) => {
    if (requestPath(input) === SESSION_PATH) {
      return Promise.resolve(principal === null ? noSessionResponse() : sessionResponse(principal))
    }
    return inner(input, init)
  }) as typeof fetch
}
