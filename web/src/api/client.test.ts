// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  apiFetch,
  passkeyLoginBeginRequest,
  passkeyLoginFinishRequest,
  logoutRequest,
  onSessionConfirmed,
  onSessionExpired,
  onStepUpRequired,
  type AssertionJSON,
} from './client.ts'

function clearCookies() {
  for (const pair of document.cookie.split(';')) {
    const name = pair.split('=')[0]?.trim()
    if (name) {
      document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/`
    }
  }
}

function jsonResponse(status: number, body: unknown = {}): Response {
  return new Response(status === 204 ? null : JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

describe('apiFetch', () => {
  const fetchMock = vi.fn<typeof fetch>()

  beforeEach(() => {
    clearCookies()
    fetchMock.mockReset()
    vi.stubGlobal('fetch', fetchMock)
    onSessionConfirmed(null)
    onSessionExpired(null)
    onStepUpRequired(null)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('sends credentials same-origin on every request', async () => {
    fetchMock.mockResolvedValue(jsonResponse(200))
    await apiFetch('/api/v1/stewards')
    const init = fetchMock.mock.calls.at(0)?.[1]
    expect(init?.credentials).toBe('same-origin')
  })

  it('injects X-CSRF-Token from the cfgms_csrf cookie on POST', async () => {
    document.cookie = 'cfgms_csrf=tok-abc123; path=/'
    fetchMock.mockResolvedValue(jsonResponse(200))
    await apiFetch('/api/v1/things', { method: 'POST' })
    const headers = new Headers(fetchMock.mock.calls.at(0)?.[1]?.headers)
    expect(headers.get('X-CSRF-Token')).toBe('tok-abc123')
  })

  it.each(['PUT', 'PATCH', 'DELETE'])(
    'injects X-CSRF-Token on %s',
    async (method) => {
      document.cookie = 'cfgms_csrf=tok-unsafe; path=/'
      fetchMock.mockResolvedValue(jsonResponse(200))
      await apiFetch('/api/v1/things', { method })
      const headers = new Headers(fetchMock.mock.calls.at(0)?.[1]?.headers)
      expect(headers.get('X-CSRF-Token')).toBe('tok-unsafe')
    },
  )

  it('does not send X-CSRF-Token on GET', async () => {
    document.cookie = 'cfgms_csrf=tok-abc123; path=/'
    fetchMock.mockResolvedValue(jsonResponse(200))
    await apiFetch('/api/v1/stewards')
    const headers = new Headers(fetchMock.mock.calls.at(0)?.[1]?.headers)
    expect(headers.get('X-CSRF-Token')).toBeNull()
  })

  it('notifies the session-expired listener on 401', async () => {
    const expired = vi.fn()
    onSessionExpired(expired)
    fetchMock.mockResolvedValue(jsonResponse(401))
    await apiFetch('/api/v1/stewards')
    expect(expired).toHaveBeenCalledTimes(1)
  })

  it('does not notify the session-expired listener on 200 or 403', async () => {
    const expired = vi.fn()
    onSessionExpired(expired)
    fetchMock.mockResolvedValueOnce(jsonResponse(200))
    await apiFetch('/api/v1/stewards')
    fetchMock.mockResolvedValueOnce(jsonResponse(403))
    await apiFetch('/api/v1/things', { method: 'POST' })
    expect(expired).not.toHaveBeenCalled()
  })

  // ── Session-confirmed listener (Story #2933) ──────────────────────────────

  it('notifies the session-confirmed listener on 200', async () => {
    const confirmed = vi.fn()
    onSessionConfirmed(confirmed)
    fetchMock.mockResolvedValue(jsonResponse(200))
    await apiFetch('/api/v1/stewards')
    expect(confirmed).toHaveBeenCalledTimes(1)
  })

  it('notifies the session-confirmed listener on non-401 responses (403, 500)', async () => {
    const confirmed = vi.fn()
    onSessionConfirmed(confirmed)
    fetchMock.mockResolvedValueOnce(jsonResponse(403))
    await apiFetch('/api/v1/stewards')
    fetchMock.mockResolvedValueOnce(jsonResponse(500))
    await apiFetch('/api/v1/stewards')
    expect(confirmed).toHaveBeenCalledTimes(2)
  })

  it('does NOT notify the session-confirmed listener on a plain 401', async () => {
    const confirmed = vi.fn()
    onSessionConfirmed(confirmed)
    fetchMock.mockResolvedValue(jsonResponse(401))
    await apiFetch('/api/v1/stewards')
    expect(confirmed).not.toHaveBeenCalled()
  })

  it('does NOT notify the session-confirmed listener on a CFGMS-StepUp 401', async () => {
    const confirmed = vi.fn()
    onSessionConfirmed(confirmed)
    onStepUpRequired(async () => null)
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({}), {
        status: 401,
        headers: {
          'WWW-Authenticate': 'CFGMS-StepUp realm="cfgms", required="strong"',
        },
      }),
    )
    await apiFetch('/api/v1/stewards')
    expect(confirmed).not.toHaveBeenCalled()
  })

  // ── Step-up detection (Story #2786) ──────────────────────────────────────

  it('CFGMS-StepUp 401 fires onStepUpRequired, not onSessionExpired', async () => {
    const expired = vi.fn()
    const stepUp = vi.fn(async () => null)
    onSessionExpired(expired)
    onStepUpRequired(stepUp)
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ error: 'step_up_required' }), {
        status: 401,
        headers: {
          'Content-Type': 'application/json',
          'WWW-Authenticate': 'CFGMS-StepUp realm="cfgms", required="strong"',
        },
      }),
    )
    await apiFetch('/api/v1/stewards')
    expect(stepUp).toHaveBeenCalledTimes(1)
    expect(expired).not.toHaveBeenCalled()
  })

  it('CFGMS-StepUp with presence="required" sets presenceRequired=true in the payload', async () => {
    const stepUp = vi.fn(async () => null)
    onStepUpRequired(stepUp)
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({}), {
        status: 401,
        headers: {
          'WWW-Authenticate':
            'CFGMS-StepUp realm="cfgms", required="strong", presence="required"',
        },
      }),
    )
    await apiFetch('/api/v1/modules/approvals/cfgms:test:1.0.0:AAAA/approve', {
      method: 'POST',
    })
    expect(stepUp).toHaveBeenCalledWith(
      expect.objectContaining({ presenceRequired: true }),
    )
  })

  it('CFGMS-StepUp without presence="required" sets presenceRequired=false', async () => {
    const stepUp = vi.fn(async () => null)
    onStepUpRequired(stepUp)
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({}), {
        status: 401,
        headers: {
          'WWW-Authenticate': 'CFGMS-StepUp realm="cfgms", required="strong"',
        },
      }),
    )
    await apiFetch('/api/v1/stewards')
    expect(stepUp).toHaveBeenCalledWith(
      expect.objectContaining({ presenceRequired: false }),
    )
  })

  it('step-up listener receives the original path and init', async () => {
    const stepUp = vi.fn(async () => null)
    onStepUpRequired(stepUp)
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({}), {
        status: 401,
        headers: {
          'WWW-Authenticate': 'CFGMS-StepUp realm="cfgms", required="strong"',
        },
      }),
    )
    await apiFetch('/api/v1/stewards', { method: 'GET' })
    const [req] = stepUp.mock.calls[0]! as unknown as [{ path: string; init: RequestInit }]
    expect(req.path).toBe('/api/v1/stewards')
    expect(req.init).toEqual({ method: 'GET' })
  })

  it('when step-up listener returns a Response, apiFetch returns it', async () => {
    const successResponse = jsonResponse(200, { ok: true })
    onStepUpRequired(async () => successResponse)
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({}), {
        status: 401,
        headers: {
          'WWW-Authenticate': 'CFGMS-StepUp realm="cfgms", required="strong"',
        },
      }),
    )
    const result = await apiFetch('/api/v1/stewards')
    expect(result.status).toBe(200)
  })

  it('when step-up listener returns null, apiFetch returns the original 401 without session-expired', async () => {
    const expired = vi.fn()
    onSessionExpired(expired)
    onStepUpRequired(async () => null)
    const original401 = new Response(JSON.stringify({}), {
      status: 401,
      headers: {
        'WWW-Authenticate': 'CFGMS-StepUp realm="cfgms", required="strong"',
      },
    })
    fetchMock.mockResolvedValue(original401)
    const result = await apiFetch('/api/v1/stewards')
    expect(result.status).toBe(401)
    expect(expired).not.toHaveBeenCalled()
  })

  it('CFGMS-StepUp 401 with no step-up listener does NOT fire session-expired', async () => {
    const expired = vi.fn()
    onSessionExpired(expired)
    // No step-up listener registered (onStepUpRequired(null) from beforeEach).
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({}), {
        status: 401,
        headers: {
          'WWW-Authenticate': 'CFGMS-StepUp realm="cfgms", required="strong"',
        },
      }),
    )
    const result = await apiFetch('/api/v1/stewards')
    expect(result.status).toBe(401)
    expect(expired).not.toHaveBeenCalled()
  })

  // ── Concurrent step-up dedup (Story #2967) ────────────────────────────────

  it('concurrent CFGMS-StepUp 401s deduplicate: only one ceremony runs', async () => {
    const stepUp = vi.fn(async () => jsonResponse(200, { ok: true }))
    onStepUpRequired(stepUp)

    const makeStepUp401 = () =>
      new Response(JSON.stringify({}), {
        status: 401,
        headers: { 'WWW-Authenticate': 'CFGMS-StepUp realm="cfgms", required="strong"' },
      })

    // First two fetches (initial requests) return 401; the dedup retry returns 200.
    fetchMock
      .mockResolvedValueOnce(makeStepUp401())
      .mockResolvedValueOnce(makeStepUp401())
      .mockResolvedValue(jsonResponse(200, {}))

    const [r1, r2] = await Promise.all([
      apiFetch('/api/v1/stewards'),
      apiFetch('/api/v1/fleet'),
    ])

    // The step-up listener must be called exactly once (not twice).
    expect(stepUp).toHaveBeenCalledTimes(1)
    // r1 gets the listener's response; r2 gets the dedup-retry response.
    expect(r1.status).toBe(200)
    expect(r2.status).toBe(200)
  })

  it('deduplicated concurrent request re-attaches CSRF on its retry', async () => {
    document.cookie = 'cfgms_csrf=dedup-csrf-tok; path=/'

    // Use a deferred promise so we can resolve the ceremony after both requests start.
    let resolveCeremony!: (r: Response | null) => void
    const ceremonyPromise = new Promise<Response | null>((r) => { resolveCeremony = r })
    onStepUpRequired(() => ceremonyPromise)

    const makeStepUp401 = () =>
      new Response(JSON.stringify({}), {
        status: 401,
        headers: { 'WWW-Authenticate': 'CFGMS-StepUp realm="cfgms", required="strong"' },
      })

    // Initial fetches return 401; the dedup retry for the second caller returns 200.
    fetchMock
      .mockResolvedValueOnce(makeStepUp401())
      .mockResolvedValueOnce(makeStepUp401())
      .mockResolvedValue(jsonResponse(200, {}))

    // Start both concurrent requests.
    const p1 = apiFetch('/api/v1/stewards', { method: 'POST' })
    const p2 = apiFetch('/api/v1/fleet', { method: 'DELETE' })

    // Yield so both initial fetches complete and r2 is waiting for the ceremony.
    await Promise.resolve()
    await Promise.resolve()

    // Resolve the ceremony (r1 receives this response).
    resolveCeremony(jsonResponse(200, { ok: true }))

    const [r1, r2] = await Promise.all([p1, p2])
    expect(r1.status).toBe(200)
    expect(r2.status).toBe(200)

    // The dedup retry (for DELETE /api/v1/fleet) must carry CSRF.
    const dedupeRetry = fetchMock.mock.calls.find(
      ([url]) => String(url).includes('/api/v1/fleet') &&
        new Headers(fetchMock.mock.calls.find(([u]) => String(u).includes('/api/v1/fleet'))?.[1]?.headers)
          .get('X-CSRF-Token') !== null,
    )
    // More direct: the last fleet fetch call should carry CSRF.
    const fleetCalls = fetchMock.mock.calls.filter(([url]) => String(url).includes('/api/v1/fleet'))
    expect(fleetCalls.length).toBeGreaterThanOrEqual(1)
    const lastFleetHeaders = new Headers(fleetCalls.at(-1)?.[1]?.headers)
    expect(lastFleetHeaders.get('X-CSRF-Token')).toBe('dedup-csrf-tok')
    void dedupeRetry
  })
})

// ── passkeyLoginBeginRequest / passkeyLoginFinishRequest (Issue #2993) ─────────

describe('passkeyLoginBeginRequest', () => {
  const fetchMock = vi.fn<typeof fetch>()

  const MOCK_BEGIN_OPTIONS = {
    publicKey: {
      challenge: 'Y2hhbGxlbmdlLWJ5dGVz',
      timeout: 60000,
      rpId: 'localhost',
      allowCredentials: [],
      userVerification: 'required',
    },
  }

  beforeEach(() => {
    clearCookies()
    fetchMock.mockReset()
    vi.stubGlobal('fetch', fetchMock)
    onSessionExpired(null)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('fetches the pre-session CSRF token and echoes it on the begin POST', async () => {
    fetchMock.mockImplementation((input) => {
      const url = String(input)
      if (url.endsWith('/api/v1/web/csrf')) {
        document.cookie = 'cfgms_csrf_pre=pre-tok-begin; path=/'
        return Promise.resolve(jsonResponse(204))
      }
      return Promise.resolve(jsonResponse(200, MOCK_BEGIN_OPTIONS))
    })

    const result = await passkeyLoginBeginRequest('admin@msp-a')

    expect(result.ok).toBe(true)
    expect(String(fetchMock.mock.calls.at(0)?.[0])).toContain('/api/v1/web/csrf')
    const beginCall = fetchMock.mock.calls.at(1)
    if (!beginCall) throw new Error('begin POST was never made')
    expect(String(beginCall[0])).toContain('/api/v1/web/passkey/login/begin')
    expect(beginCall[1]?.method).toBe('POST')
    const headers = new Headers(beginCall[1]?.headers)
    expect(headers.get('X-CSRF-Token')).toBe('pre-tok-begin')
    const body = JSON.parse(String(beginCall[1]?.body))
    expect(body).toEqual({ username: 'admin@msp-a' })
  })

  it('sends an empty body when no username is provided (discoverable flow)', async () => {
    fetchMock.mockImplementation((input) => {
      if (String(input).endsWith('/api/v1/web/csrf')) {
        document.cookie = 'cfgms_csrf_pre=pre-tok-anon; path=/'
        return Promise.resolve(jsonResponse(204))
      }
      return Promise.resolve(jsonResponse(200, MOCK_BEGIN_OPTIONS))
    })

    const result = await passkeyLoginBeginRequest()

    expect(result.ok).toBe(true)
    const beginCall = fetchMock.mock.calls.at(1)
    const body = JSON.parse(String(beginCall?.[1]?.body))
    expect(body).toEqual({})
  })

  it('returns ok:false when the csrf preflight fails', async () => {
    fetchMock.mockResolvedValue(jsonResponse(503))

    const result = await passkeyLoginBeginRequest()

    expect(result.ok).toBe(false)
    expect(result.status).toBe(503)
    expect(result.options).toBeUndefined()
  })

  it('returns ok:false when the begin POST fails', async () => {
    fetchMock.mockImplementation((input) => {
      if (String(input).endsWith('/api/v1/web/csrf')) {
        return Promise.resolve(jsonResponse(204))
      }
      return Promise.resolve(jsonResponse(403))
    })

    const result = await passkeyLoginBeginRequest('admin@msp-a')

    expect(result.ok).toBe(false)
    expect(result.options).toBeUndefined()
  })

  it('returns challenge options on success', async () => {
    fetchMock.mockImplementation((input) => {
      if (String(input).endsWith('/api/v1/web/csrf')) {
        return Promise.resolve(jsonResponse(204))
      }
      return Promise.resolve(jsonResponse(200, MOCK_BEGIN_OPTIONS))
    })

    const result = await passkeyLoginBeginRequest()

    expect(result.ok).toBe(true)
    expect(result.options?.publicKey.challenge).toBe('Y2hhbGxlbmdlLWJ5dGVz')
  })
})

describe('passkeyLoginFinishRequest', () => {
  const fetchMock = vi.fn<typeof fetch>()

  const MOCK_ASSERTION: AssertionJSON = {
    id: 'Y3JlZGVudGlhbC1pZA',
    rawId: 'Y3JlZGVudGlhbC1pZA',
    response: {
      authenticatorData: 'YXV0aERhdGE',
      clientDataJSON: 'Y2xpZW50RGF0YQ',
      signature: 'c2lnbmF0dXJl',
      userHandle: null,
    },
    type: 'public-key',
    clientExtensionResults: {},
  }

  beforeEach(() => {
    clearCookies()
    fetchMock.mockReset()
    vi.stubGlobal('fetch', fetchMock)
    onSessionExpired(null)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('posts the assertion JSON to the finish endpoint', async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(200, { data: { ok: true, username: 'admin@msp-a', tenant_id: '', root_scope: false } }),
    )

    await passkeyLoginFinishRequest(MOCK_ASSERTION)

    expect(fetchMock).toHaveBeenCalledOnce()
    const call = fetchMock.mock.calls[0]!
    expect(String(call[0])).toContain('/api/v1/web/passkey/login/finish')
    expect(call[1]?.method).toBe('POST')
    const body = JSON.parse(String(call[1]?.body))
    expect(body.type).toBe('public-key')
    expect(body.id).toBe(MOCK_ASSERTION.id)
  })

  it('parses username, tenant_id, and root_scope from the finish response', async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(200, {
        data: { ok: true, username: 'admin@msp-a', tenant_id: 'msp-a', root_scope: false },
      }),
    )

    const result = await passkeyLoginFinishRequest(MOCK_ASSERTION)

    expect(result.ok).toBe(true)
    expect(result.username).toBe('admin@msp-a')
    expect(result.tenantId).toBe('msp-a')
    expect(result.rootScope).toBe(false)
  })

  it('parses a root-scoped account (empty tenant_id, root_scope true)', async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(200, {
        data: { ok: true, username: 'root-admin', tenant_id: '', root_scope: true },
      }),
    )

    const result = await passkeyLoginFinishRequest(MOCK_ASSERTION)

    expect(result.ok).toBe(true)
    expect(result.username).toBe('root-admin')
    expect(result.tenantId).toBe('')
    expect(result.rootScope).toBe(true)
  })

  it('returns ok:false on 400 (assertion verification failed)', async () => {
    fetchMock.mockResolvedValue(jsonResponse(400))

    const result = await passkeyLoginFinishRequest(MOCK_ASSERTION)

    expect(result.ok).toBe(false)
    expect(result.username).toBe('')
  })

  it('defaults username/tenantId to "" when the body has no data', async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, {}))

    const result = await passkeyLoginFinishRequest(MOCK_ASSERTION)

    expect(result.ok).toBe(true)
    expect(result.username).toBe('')
    expect(result.tenantId).toBe('')
    expect(result.rootScope).toBe(false)
  })

  it('falls back gracefully when the finish body is not valid JSON', async () => {
    fetchMock.mockResolvedValue(
      new Response('not-json{', {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    const result = await passkeyLoginFinishRequest(MOCK_ASSERTION)

    expect(result.ok).toBe(true)
    expect(result.username).toBe('')
    expect(result.tenantId).toBe('')
  })
})

describe('logoutRequest', () => {
  const fetchMock = vi.fn<typeof fetch>()

  beforeEach(() => {
    clearCookies()
    fetchMock.mockReset()
    vi.stubGlobal('fetch', fetchMock)
    onSessionExpired(null)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('POSTs to the logout endpoint with the session CSRF header', async () => {
    document.cookie = 'cfgms_csrf=sess-tok; path=/'
    fetchMock.mockResolvedValue(jsonResponse(204))
    await logoutRequest()
    const call = fetchMock.mock.calls.at(0)
    if (!call) throw new Error('logout POST was never made')
    expect(String(call[0])).toContain('/api/v1/web/logout')
    expect(call[1]?.method).toBe('POST')
    const headers = new Headers(call[1]?.headers)
    expect(headers.get('X-CSRF-Token')).toBe('sess-tok')
  })

  it('does not fire session-expired when logout races an already-dead session', async () => {
    const expired = vi.fn()
    onSessionExpired(expired)
    fetchMock.mockResolvedValue(jsonResponse(401))
    await logoutRequest()
    expect(expired).not.toHaveBeenCalled()
  })
})
