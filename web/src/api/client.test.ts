// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  apiFetch,
  loginRequest,
  logoutRequest,
  onSessionConfirmed,
  onSessionExpired,
  onStepUpRequired,
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
})

describe('loginRequest', () => {
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

  it('fetches the pre-session token and echoes it on the login POST', async () => {
    fetchMock.mockImplementation((input) => {
      const url = String(input)
      if (url.endsWith('/api/v1/web/csrf')) {
        // The real controller sets the cookie via Set-Cookie; jsdom fetch
        // stubs cannot, so simulate the cookie the response would set.
        document.cookie = 'cfgms_csrf_pre=pre-tok-1; path=/'
        return Promise.resolve(jsonResponse(204))
      }
      return Promise.resolve(jsonResponse(200))
    })

    const result = await loginRequest('admin@msp-a', 'hunter2hunter2')

    expect(result.ok).toBe(true)
    expect(String(fetchMock.mock.calls.at(0)?.[0])).toContain('/api/v1/web/csrf')
    const loginCall = fetchMock.mock.calls.at(1)
    if (!loginCall) throw new Error('login POST was never made')
    expect(String(loginCall[0])).toContain('/api/v1/web/login')
    expect(loginCall[1]?.method).toBe('POST')
    const headers = new Headers(loginCall[1]?.headers)
    expect(headers.get('X-CSRF-Token')).toBe('pre-tok-1')
    const body = JSON.parse(String(loginCall[1]?.body))
    expect(body).toEqual({ username: 'admin@msp-a', password: 'hunter2hunter2' })
  })

  it('reports invalid credentials on 401 without firing session-expired', async () => {
    const expired = vi.fn()
    onSessionExpired(expired)
    fetchMock.mockImplementation((input) => {
      if (String(input).endsWith('/api/v1/web/csrf')) {
        document.cookie = 'cfgms_csrf_pre=pre-tok-2; path=/'
        return Promise.resolve(jsonResponse(204))
      }
      return Promise.resolve(jsonResponse(401))
    })

    const result = await loginRequest('admin@msp-a', 'wrong')

    expect(result.ok).toBe(false)
    expect(expired).not.toHaveBeenCalled()
  })

  it('never exposes the credentials or token in the request URL', async () => {
    fetchMock.mockImplementation((input) => {
      if (String(input).endsWith('/api/v1/web/csrf')) {
        document.cookie = 'cfgms_csrf_pre=pre-tok-3; path=/'
        return Promise.resolve(jsonResponse(204))
      }
      return Promise.resolve(jsonResponse(200))
    })
    await loginRequest('admin@msp-a', 'hunter2hunter2')
    for (const call of fetchMock.mock.calls) {
      expect(String(call[0])).not.toContain('hunter2hunter2')
      expect(String(call[0])).not.toContain('pre-tok-3')
    }
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
