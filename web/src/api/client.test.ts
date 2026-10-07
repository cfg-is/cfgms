// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  apiFetch,
  passkeyLoginBeginRequest,
  passkeyLoginFinishRequest,
  passkeyEnrollBeginRequest,
  passkeyEnrollFinishRequest,
  getCliLoginRequest,
  approveCliLoginRequest,
  logoutRequest,
  onSessionConfirmed,
  onSessionExpired,
  onStepUpRequired,
  listCredentialRequests,
  approveCredentialRequest,
  denyCredentialRequest,
  parseCredentialRequestEntry,
  type AssertionJSON,
  type AttestationJSON,
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

// ── passkeyEnrollBeginRequest / passkeyEnrollFinishRequest (Issue #2968) ────────

const MOCK_ENROLL_OPTIONS = {
  publicKey: {
    challenge: 'Y2hhbGxlbmdlLWJ5dGVz',
    rp: { id: 'localhost', name: 'CFGMS' },
    user: { id: 'dXNlci1pZA', name: 'admin@msp-a', displayName: 'Admin User' },
    pubKeyCredParams: [{ type: 'public-key' as const, alg: -7 }],
    timeout: 60000,
    excludeCredentials: [],
  },
}

const MOCK_ATTESTATION: AttestationJSON = {
  id: 'Y3JlZA',
  rawId: 'Y3JlZA',
  response: {
    attestationObject: 'YXR0ZXN0YXRpb25PYmplY3Q',
    clientDataJSON: 'Y2xpZW50RGF0YUpTT04',
  },
  type: 'public-key',
  clientExtensionResults: {},
}

describe('passkeyEnrollBeginRequest', () => {
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

  it('POSTs to the enroll/begin endpoint with X-Enrollment-Token header', async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, MOCK_ENROLL_OPTIONS))

    await passkeyEnrollBeginRequest('raw-token-abc')

    expect(fetchMock).toHaveBeenCalledOnce()
    const call = fetchMock.mock.calls[0]!
    expect(String(call[0])).toContain('/api/v1/web/passkey/enroll/begin')
    expect(call[1]?.method).toBe('POST')
    const headers = new Headers(call[1]?.headers)
    expect(headers.get('X-Enrollment-Token')).toBe('raw-token-abc')
  })

  it('does NOT include a CSRF header (token is the auth credential)', async () => {
    document.cookie = 'cfgms_csrf=should-not-be-sent; path=/'
    fetchMock.mockResolvedValue(jsonResponse(200, MOCK_ENROLL_OPTIONS))

    await passkeyEnrollBeginRequest('tok')

    const headers = new Headers(fetchMock.mock.calls[0]?.[1]?.headers)
    expect(headers.get('X-CSRF-Token')).toBeNull()
  })

  it('sends credentials same-origin', async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, MOCK_ENROLL_OPTIONS))

    await passkeyEnrollBeginRequest('tok')

    expect(fetchMock.mock.calls[0]?.[1]?.credentials).toBe('same-origin')
  })

  it('returns ok:true and options on success', async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, MOCK_ENROLL_OPTIONS))

    const result = await passkeyEnrollBeginRequest('tok')

    expect(result.ok).toBe(true)
    expect(result.status).toBe(200)
    expect(result.options?.publicKey.challenge).toBe('Y2hhbGxlbmdlLWJ5dGVz')
  })

  it('returns ok:false on 401 (invalid/expired token)', async () => {
    fetchMock.mockResolvedValue(jsonResponse(401))

    const result = await passkeyEnrollBeginRequest('bad-token')

    expect(result.ok).toBe(false)
    expect(result.status).toBe(401)
    expect(result.options).toBeUndefined()
  })

  it('returns ok:false on 400 (missing token)', async () => {
    fetchMock.mockResolvedValue(jsonResponse(400))

    const result = await passkeyEnrollBeginRequest('')

    expect(result.ok).toBe(false)
    expect(result.status).toBe(400)
  })

  it('returns ok:false on 503 (WebAuthn not configured)', async () => {
    fetchMock.mockResolvedValue(jsonResponse(503))

    const result = await passkeyEnrollBeginRequest('tok')

    expect(result.ok).toBe(false)
    expect(result.status).toBe(503)
  })

  it('does NOT trigger the session-expired listener', async () => {
    const expired = vi.fn()
    onSessionExpired(expired)
    fetchMock.mockResolvedValue(jsonResponse(401))

    await passkeyEnrollBeginRequest('bad-token')

    expect(expired).not.toHaveBeenCalled()
  })
})

describe('passkeyEnrollFinishRequest', () => {
  const fetchMock = vi.fn<typeof fetch>()

  beforeEach(() => {
    clearCookies()
    fetchMock.mockReset()
    vi.stubGlobal('fetch', fetchMock)
    onSessionExpired(null)
    onSessionConfirmed(null)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('POSTs to the enroll/finish endpoint with X-Enrollment-Token and the attestation JSON', async () => {
    fetchMock.mockResolvedValue(jsonResponse(201))

    await passkeyEnrollFinishRequest('raw-token-abc', MOCK_ATTESTATION)

    const call = fetchMock.mock.calls[0]!
    expect(String(call[0])).toContain('/api/v1/web/passkey/enroll/finish')
    expect(call[1]?.method).toBe('POST')
    const headers = new Headers(call[1]?.headers)
    expect(headers.get('X-Enrollment-Token')).toBe('raw-token-abc')
    const body = JSON.parse(String(call[1]?.body)) as AttestationJSON
    expect(body.type).toBe('public-key')
    expect(body.id).toBe(MOCK_ATTESTATION.id)
    expect(body.response.attestationObject).toBe(MOCK_ATTESTATION.response.attestationObject)
  })

  it('sends Content-Type: application/json', async () => {
    fetchMock.mockResolvedValue(jsonResponse(201))

    await passkeyEnrollFinishRequest('tok', MOCK_ATTESTATION)

    const headers = new Headers(fetchMock.mock.calls[0]?.[1]?.headers)
    expect(headers.get('Content-Type')).toBe('application/json')
  })

  it('returns ok:true on 201 (first passkey enrolled)', async () => {
    fetchMock.mockResolvedValue(jsonResponse(201))

    const result = await passkeyEnrollFinishRequest('tok', MOCK_ATTESTATION)

    expect(result.ok).toBe(true)
    expect(result.status).toBe(201)
  })

  it('returns ok:false on 409 (already enrolled)', async () => {
    fetchMock.mockResolvedValue(jsonResponse(409))

    const result = await passkeyEnrollFinishRequest('tok', MOCK_ATTESTATION)

    expect(result.ok).toBe(false)
    expect(result.status).toBe(409)
  })

  it('returns ok:false on 410 (token revoked)', async () => {
    fetchMock.mockResolvedValue(jsonResponse(410))

    const result = await passkeyEnrollFinishRequest('tok', MOCK_ATTESTATION)

    expect(result.ok).toBe(false)
    expect(result.status).toBe(410)
  })

  it('fires the session-confirmed listener on 201 (via apiFetch)', async () => {
    const confirmed = vi.fn()
    onSessionConfirmed(confirmed)
    fetchMock.mockResolvedValue(jsonResponse(201))

    await passkeyEnrollFinishRequest('tok', MOCK_ATTESTATION)

    expect(confirmed).toHaveBeenCalledTimes(1)
  })

  it('does NOT include a session CSRF header when the session cookie is absent', async () => {
    fetchMock.mockResolvedValue(jsonResponse(201))

    await passkeyEnrollFinishRequest('tok', MOCK_ATTESTATION)

    const headers = new Headers(fetchMock.mock.calls[0]?.[1]?.headers)
    expect(headers.get('X-CSRF-Token')).toBeNull()
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

// ── CLI login (Issue #3722) ─────────────────────────────────────────────────────

describe('getCliLoginRequest', () => {
  const fetchMock = vi.fn<typeof fetch>()

  beforeEach(() => {
    clearCookies()
    fetchMock.mockReset()
    vi.stubGlobal('fetch', fetchMock)
    onSessionConfirmed(null)
    onSessionExpired(null)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('GETs the login request by id and parses status/user_code/expires_at', async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(200, {
        data: {
          request_id: 'cli-login-abc',
          status: 'pending',
          user_code: 'ABCD-1234',
          expires_at: '2026-08-29T00:00:00Z',
        },
      }),
    )

    const result = await getCliLoginRequest('cli-login-abc')

    expect(result.ok).toBe(true)
    expect(result.request).toEqual({
      requestId: 'cli-login-abc',
      status: 'pending',
      userCode: 'ABCD-1234',
      expiresAt: '2026-08-29T00:00:00Z',
    })
    const call = fetchMock.mock.calls.at(0)
    if (!call) throw new Error('GET was never made')
    expect(String(call[0])).toBe('/api/v1/cli-login/cli-login-abc')
    expect(call[1]?.method ?? 'GET').toBe('GET')
  })

  it('URL-encodes the id', async () => {
    fetchMock.mockResolvedValue(jsonResponse(404))
    await getCliLoginRequest('has space/slash')
    const call = fetchMock.mock.calls.at(0)
    expect(String(call?.[0])).toBe('/api/v1/cli-login/has%20space%2Fslash')
  })

  it('returns ok:false with the status code on 404 (unknown or expired-and-swept)', async () => {
    fetchMock.mockResolvedValue(jsonResponse(404))
    const result = await getCliLoginRequest('cli-login-gone')
    expect(result.ok).toBe(false)
    expect(result.status).toBe(404)
    expect(result.request).toBeUndefined()
  })

  it('returns ok:false on a plain 401 (no session)', async () => {
    fetchMock.mockResolvedValue(jsonResponse(401))
    const result = await getCliLoginRequest('cli-login-x')
    expect(result.ok).toBe(false)
    expect(result.status).toBe(401)
  })

  it('fires the session-expired listener on a plain 401, via apiFetch', async () => {
    const expired = vi.fn()
    onSessionExpired(expired)
    fetchMock.mockResolvedValue(jsonResponse(401))
    await getCliLoginRequest('cli-login-x')
    expect(expired).toHaveBeenCalled()
  })

  it('never returns a token or verifier field even if the server sent one', async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(200, {
        data: {
          request_id: 'cli-login-abc',
          status: 'pending',
          user_code: 'ABCD-1234',
          expires_at: '2026-08-29T00:00:00Z',
          // A misbehaving/hostile server sending these must not leak them onward —
          // CliLoginRequestState has no field to carry either.
          token: 'super-secret-session-token',
          verifier_hash: 'deadbeef',
        },
      }),
    )
    const result = await getCliLoginRequest('cli-login-abc')
    expect(result.request).toEqual({
      requestId: 'cli-login-abc',
      status: 'pending',
      userCode: 'ABCD-1234',
      expiresAt: '2026-08-29T00:00:00Z',
    })
    expect(JSON.stringify(result.request)).not.toContain('super-secret-session-token')
  })
})

describe('approveCliLoginRequest', () => {
  const fetchMock = vi.fn<typeof fetch>()

  beforeEach(() => {
    clearCookies()
    fetchMock.mockReset()
    vi.stubGlobal('fetch', fetchMock)
    onSessionConfirmed(null)
    onSessionExpired(null)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('POSTs user_code and deny:false for a confirm, with the session CSRF header', async () => {
    document.cookie = 'cfgms_csrf=sess-tok; path=/'
    fetchMock.mockResolvedValue(jsonResponse(200, { data: { request_id: 'cli-login-abc', status: 'approved' } }))

    const result = await approveCliLoginRequest('cli-login-abc', 'ABCD-1234', false)

    expect(result.ok).toBe(true)
    expect(result.requestStatus).toBe('approved')
    const call = fetchMock.mock.calls.at(0)
    if (!call) throw new Error('approve POST was never made')
    expect(String(call[0])).toBe('/api/v1/cli-login/cli-login-abc/approve')
    expect(call[1]?.method).toBe('POST')
    const headers = new Headers(call[1]?.headers)
    expect(headers.get('X-CSRF-Token')).toBe('sess-tok')
    const body = JSON.parse(String(call[1]?.body)) as Record<string, unknown>
    expect(body).toEqual({ user_code: 'ABCD-1234', deny: false })
  })

  it('POSTs deny:true for a deny', async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, { data: { request_id: 'cli-login-abc', status: 'denied' } }))
    await approveCliLoginRequest('cli-login-abc', 'ABCD-1234', true)
    const call = fetchMock.mock.calls.at(0)
    const body = JSON.parse(String(call?.[1]?.body)) as Record<string, unknown>
    expect(body).toEqual({ user_code: 'ABCD-1234', deny: true })
  })

  it('surfaces the error code from a non-2xx response', async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(409, { error: { code: 'REQUEST_NOT_PENDING', message: 'not pending' } }),
    )
    const result = await approveCliLoginRequest('cli-login-abc', 'ABCD-1234', false)
    expect(result.ok).toBe(false)
    expect(result.status).toBe(409)
    expect(result.errorCode).toBe('REQUEST_NOT_PENDING')
  })

  it('never sends any field beyond user_code and deny — no host/scheme/port/callback, no certificate or scope field', async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, { data: { request_id: 'cli-login-abc', status: 'approved' } }))
    await approveCliLoginRequest('cli-login-abc', 'ABCD-1234', false)
    const call = fetchMock.mock.calls.at(0)
    const body = JSON.parse(String(call?.[1]?.body)) as Record<string, unknown>
    expect(Object.keys(body).sort()).toEqual(['deny', 'user_code'])
  })

  it('never returns a token field even if the server sent one', async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(200, {
        data: { request_id: 'cli-login-abc', status: 'approved', token: 'super-secret-session-token' },
      }),
    )
    const result = await approveCliLoginRequest('cli-login-abc', 'ABCD-1234', false)
    expect(JSON.stringify(result)).not.toContain('super-secret-session-token')
  })
})

// ── Credential requests (Issue #3723) ────────────────────────────────────────────

function makeCredentialRequestPayload(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    id: 'creq-abc123',
    tenant_id: 'msp-a',
    status: 'pending',
    public_key_fingerprint: 'a'.repeat(64),
    public_key_fingerprint_short: 'AAAA-AAAA-AAAA-AAAA',
    source_ip: '10.0.0.1',
    hostname: 'host-1',
    label: 'label-1',
    platform: 'linux',
    purpose: 'steward',
    created_at: '2026-08-29T00:00:00Z',
    expires_at: '2026-08-29T01:00:00Z',
    ...overrides,
  }
}

describe('parseCredentialRequestEntry', () => {
  it('returns null for non-objects', () => {
    expect(parseCredentialRequestEntry(null)).toBeNull()
    expect(parseCredentialRequestEntry('x')).toBeNull()
  })

  it('returns null when id is missing or empty', () => {
    expect(parseCredentialRequestEntry({})).toBeNull()
    expect(parseCredentialRequestEntry({ id: '' })).toBeNull()
  })

  it('parses a valid entry', () => {
    const entry = parseCredentialRequestEntry(makeCredentialRequestPayload())
    expect(entry).toEqual({
      id: 'creq-abc123',
      tenantId: 'msp-a',
      status: 'pending',
      publicKeyFingerprint: 'a'.repeat(64),
      publicKeyFingerprintShort: 'AAAA-AAAA-AAAA-AAAA',
      sourceIp: '10.0.0.1',
      hostname: 'host-1',
      label: 'label-1',
      platform: 'linux',
      purpose: 'steward',
      createdAt: '2026-08-29T00:00:00Z',
      expiresAt: '2026-08-29T01:00:00Z',
    })
  })

  it('coerces non-string fields to empty string', () => {
    const entry = parseCredentialRequestEntry({ id: 'creq-1', hostname: 42, purpose: null })
    expect(entry?.hostname).toBe('')
    expect(entry?.purpose).toBe('')
  })
})

describe('listCredentialRequests', () => {
  const fetchMock = vi.fn<typeof fetch>()

  beforeEach(() => {
    clearCookies()
    fetchMock.mockReset()
    vi.stubGlobal('fetch', fetchMock)
    onSessionConfirmed(null)
    onSessionExpired(null)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('GETs the list endpoint and parses the {data:[...]} envelope', async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, { data: [makeCredentialRequestPayload()] }))
    const result = await listCredentialRequests()
    expect(result.ok).toBe(true)
    expect(result.requests).toHaveLength(1)
    expect(result.requests[0]?.id).toBe('creq-abc123')
    const call = fetchMock.mock.calls.at(0)
    expect(String(call?.[0])).toBe('/api/v1/credential-requests')
    expect(call?.[1]?.method ?? 'GET').toBe('GET')
  })

  it('drops entries without an id', async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(200, { data: [{}, makeCredentialRequestPayload()] }),
    )
    const result = await listCredentialRequests()
    expect(result.requests).toHaveLength(1)
  })

  it('returns ok:false and an empty list on a non-2xx response', async () => {
    fetchMock.mockResolvedValue(jsonResponse(500, { error: { code: 'STORE_ERROR', message: 'x' } }))
    const result = await listCredentialRequests()
    expect(result.ok).toBe(false)
    expect(result.status).toBe(500)
    expect(result.requests).toEqual([])
  })

  it('fires the session-expired listener on a plain 401, via apiFetch', async () => {
    const expired = vi.fn()
    onSessionExpired(expired)
    fetchMock.mockResolvedValue(jsonResponse(401))
    await listCredentialRequests()
    expect(expired).toHaveBeenCalled()
  })
})

describe('approveCredentialRequest', () => {
  const fetchMock = vi.fn<typeof fetch>()

  beforeEach(() => {
    clearCookies()
    fetchMock.mockReset()
    vi.stubGlobal('fetch', fetchMock)
    onSessionConfirmed(null)
    onSessionExpired(null)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('POSTs the fingerprint the caller supplied, the new account username, and the requested markers', async () => {
    document.cookie = 'cfgms_csrf=sess-tok; path=/'
    fetchMock.mockResolvedValue(
      jsonResponse(200, {
        data: { id: 'creq-abc123', status: 'approved', account_id: 'acct-1', granted_markers: ['admin'] },
      }),
    )

    const result = await approveCredentialRequest({
      id: 'creq-abc123',
      fingerprint: 'AAAA-AAAA-AAAA-AAAA',
      newAccountUsername: 'host-1',
      grantAdminMarker: true,
      grantPayloadSigningMarker: false,
    })

    expect(result.ok).toBe(true)
    expect(result.accountId).toBe('acct-1')
    expect(result.grantedMarkers).toEqual(['admin'])
    const call = fetchMock.mock.calls.at(0)
    if (!call) throw new Error('approve POST was never made')
    expect(String(call[0])).toBe('/api/v1/credential-requests/creq-abc123/approve')
    expect(call[1]?.method).toBe('POST')
    const headers = new Headers(call[1]?.headers)
    expect(headers.get('X-CSRF-Token')).toBe('sess-tok')
    const body = JSON.parse(String(call[1]?.body)) as Record<string, unknown>
    expect(body).toEqual({
      fingerprint: 'AAAA-AAAA-AAAA-AAAA',
      new_account_username: 'host-1',
      grant_admin_marker: true,
      grant_payload_signing_marker: false,
    })
  })

  it('URL-encodes the id', async () => {
    fetchMock.mockResolvedValue(jsonResponse(404))
    await approveCredentialRequest({
      id: 'has space/slash',
      fingerprint: 'x',
      newAccountUsername: 'host-1',
      grantAdminMarker: false,
      grantPayloadSigningMarker: false,
    })
    const call = fetchMock.mock.calls.at(0)
    expect(String(call?.[0])).toBe('/api/v1/credential-requests/has%20space%2Fslash/approve')
  })

  it('surfaces a 409 conflict distinctly, with the error code', async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(409, { error: { code: 'FINGERPRINT_MISMATCH', message: 'nope' } }),
    )
    const result = await approveCredentialRequest({
      id: 'creq-abc123',
      fingerprint: 'stale',
      newAccountUsername: 'host-1',
      grantAdminMarker: false,
      grantPayloadSigningMarker: false,
    })
    expect(result.ok).toBe(false)
    expect(result.status).toBe(409)
    expect(result.conflict).toBe(true)
    expect(result.errorCode).toBe('FINGERPRINT_MISMATCH')
  })

  it('a 403 (marker not grantable) is surfaced as a non-conflict failure', async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(403, { error: { code: 'MARKER_NOT_GRANTABLE', message: 'nope' } }),
    )
    const result = await approveCredentialRequest({
      id: 'creq-abc123',
      fingerprint: 'x',
      newAccountUsername: 'host-1',
      grantAdminMarker: true,
      grantPayloadSigningMarker: false,
    })
    expect(result.ok).toBe(false)
    expect(result.conflict).toBe(false)
    expect(result.errorCode).toBe('MARKER_NOT_GRANTABLE')
  })

  it('never sends a root-scope marker field, for every reachable combination of the admin/payload-signing markers', async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, { data: { id: 'creq-abc123', status: 'approved' } }))
    const combinations = [
      [false, false],
      [true, false],
      [false, true],
      [true, true],
    ] as const
    for (const [admin, signing] of combinations) {
      fetchMock.mockClear()
      await approveCredentialRequest({
        id: 'creq-abc123',
        fingerprint: 'x',
        newAccountUsername: 'host-1',
        grantAdminMarker: admin,
        grantPayloadSigningMarker: signing,
      })
      const call = fetchMock.mock.calls.at(0)
      const rawBody = String(call?.[1]?.body)
      expect(rawBody).not.toContain('root_scope')
      expect(rawBody).not.toContain('rootScope')
      const body = JSON.parse(rawBody) as Record<string, unknown>
      expect(Object.keys(body).sort()).toEqual([
        'fingerprint',
        'grant_admin_marker',
        'grant_payload_signing_marker',
        'new_account_username',
      ])
    }
  })
})

describe('denyCredentialRequest', () => {
  const fetchMock = vi.fn<typeof fetch>()

  beforeEach(() => {
    clearCookies()
    fetchMock.mockReset()
    vi.stubGlobal('fetch', fetchMock)
    onSessionConfirmed(null)
    onSessionExpired(null)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('POSTs to the deny endpoint', async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, { data: { id: 'creq-abc123', status: 'denied' } }))
    const result = await denyCredentialRequest('creq-abc123')
    expect(result.ok).toBe(true)
    const call = fetchMock.mock.calls.at(0)
    expect(String(call?.[0])).toBe('/api/v1/credential-requests/creq-abc123/deny')
    expect(call?.[1]?.method).toBe('POST')
  })

  it('surfaces a failure status without throwing', async () => {
    fetchMock.mockResolvedValue(jsonResponse(409, { error: { code: 'REQUEST_NOT_PENDING', message: 'x' } }))
    const result = await denyCredentialRequest('creq-abc123')
    expect(result.ok).toBe(false)
    expect(result.status).toBe(409)
  })
})
