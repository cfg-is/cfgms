// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Tests for the CLI login confirmation screen (Issue #3722).
 *
 * Coverage:
 *  - Only request_id is read from the URL; host/scheme/port/callback params are ignored
 *  - Passkey login is required before the code/confirm control appears
 *  - The code is displayed and approval only ever happens on an explicit click
 *  - Denied/expired/already-approved states render distinct messages
 *  - No session token is ever rendered, stored, or present in any request payload
 *  - No root-scope certificate grant is ever sent, requested, or rendered
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router'
import { AuthProvider } from '../auth/AuthContext.tsx'
import CliLogin from './CliLogin.tsx'

function jsonResponse(status: number, body: unknown = {}): Response {
  return new Response(status === 204 ? null : JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

const MOCK_PASSKEY_BEGIN_OPTIONS = {
  publicKey: {
    challenge: 'Y2hhbGxlbmdlLWJ5dGVz',
    timeout: 60000,
    rpId: 'localhost',
    allowCredentials: [],
    userVerification: 'required' as const,
  },
}

function makePublicKeyCredential(): PublicKeyCredential {
  const toArrayBuffer = (s: string) => new TextEncoder().encode(s).buffer as ArrayBuffer
  return {
    id: 'cred-id',
    type: 'public-key',
    rawId: toArrayBuffer('cred-id'),
    response: {
      clientDataJSON: toArrayBuffer('{"type":"webauthn.get"}'),
      authenticatorData: toArrayBuffer('authenticator-data'),
      signature: toArrayBuffer('signature'),
      userHandle: null,
    } as AuthenticatorAssertionResponse,
    getClientExtensionResults: () => ({} as AuthenticationExtensionsClientOutputs),
    authenticatorAttachment: null,
    toJSON: () => ({}),
  } as unknown as PublicKeyCredential
}

const CODE = 'ABCD-1234'
const PENDING_REQUEST = {
  request_id: 'cli-login-abc',
  status: 'pending',
  user_code: CODE,
  expires_at: '2026-08-29T00:10:00Z',
}

const fetchMock = vi.fn<typeof fetch>()

/**
 * Wires the passkey login endpoints (session absent until login completes) plus the
 * cli-login GET/approve endpoints. getResponse/approveResponse are mutable so a test
 * can change what they return mid-flow (e.g. after a state transition).
 */
function mockEndpoints(opts: {
  getResponse?: () => Response
  approveResponse?: () => Response
  rootScope?: boolean
}) {
  const getResponse = opts.getResponse ?? (() => jsonResponse(200, { data: PENDING_REQUEST }))
  const approveResponse =
    opts.approveResponse ?? (() => jsonResponse(200, { data: { request_id: 'cli-login-abc', status: 'approved' } }))

  fetchMock.mockImplementation((input, init) => {
    const url = String(input)
    const method = (init?.method ?? 'GET').toUpperCase()
    if (url.endsWith('/api/v1/web/csrf')) {
      document.cookie = 'cfgms_csrf_pre=pre-tok; path=/'
      return Promise.resolve(jsonResponse(204))
    }
    if (url.endsWith('/api/v1/web/passkey/login/begin')) {
      return Promise.resolve(jsonResponse(200, MOCK_PASSKEY_BEGIN_OPTIONS))
    }
    if (url.endsWith('/api/v1/web/passkey/login/finish')) {
      return Promise.resolve(
        jsonResponse(200, {
          data: { ok: true, username: 'admin@msp-a', tenant_id: '', root_scope: opts.rootScope ?? false },
        }),
      )
    }
    if (method === 'POST' && url.includes('/approve')) {
      return Promise.resolve(approveResponse())
    }
    if (method === 'GET' && url.includes('/api/v1/cli-login/')) {
      return Promise.resolve(getResponse())
    }
    return Promise.resolve(jsonResponse(401))
  })
}

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
  window.localStorage.clear()
  window.sessionStorage.clear()
})

afterEach(() => {
  vi.unstubAllGlobals()
})

function renderCliLogin(search = 'request_id=cli-login-abc') {
  return render(
    <MemoryRouter initialEntries={[`/login/confirm?${search}`]}>
      <AuthProvider>
        <Routes>
          <Route path="/login/confirm" element={<CliLogin />} />
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  )
}

/** Drives the passkey login ceremony to completion from the Login fallback screen. */
async function completePasskeyLogin() {
  vi.stubGlobal('navigator', { credentials: { get: vi.fn().mockResolvedValue(makePublicKeyCredential()) } })
  await waitFor(() => expect(screen.getByRole('button', { name: /sign in with a passkey/i })).toBeInTheDocument())
  fireEvent.click(screen.getByRole('button', { name: /sign in with a passkey/i }))
}

// ── URL parameter handling ───────────────────────────────────────────────────────

describe('URL parameter handling', () => {
  it('reads only request_id and ignores host/scheme/port/callback params', async () => {
    mockEndpoints({})
    renderCliLogin(
      'request_id=cli-login-abc&host=evil.example&scheme=http&port=1337&callback=http%3A%2F%2Fevil.example%2Fsteal',
    )

    await waitFor(() => expect(screen.getByTestId('cli-login-code')).toBeInTheDocument())

    const getCall = fetchMock.mock.calls.find(
      (c) => (c[1]?.method ?? 'GET') === 'GET' && String(c[0]).includes('/api/v1/cli-login/'),
    )
    expect(getCall).toBeDefined()
    expect(String(getCall?.[0])).toBe('/api/v1/cli-login/cli-login-abc')
  })

  it('never places any callback/host/scheme/port parameter into a link target', async () => {
    mockEndpoints({})
    const { container } = renderCliLogin(
      'request_id=cli-login-abc&callback=http%3A%2F%2Fevil.example%2Fsteal&host=evil.example',
    )
    await waitFor(() => expect(screen.getByTestId('cli-login-code')).toBeInTheDocument())

    const anchors = container.querySelectorAll('a[href]')
    anchors.forEach((a) => {
      expect(a.getAttribute('href')).not.toContain('evil.example')
    })
  })

  it('shows an error state when request_id is missing from the URL, once authenticated', async () => {
    mockEndpoints({})
    renderCliLogin('host=evil.example')
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(/invalid login link/i))
    // No cli-login GET was ever attempted without an id.
    const getCall = fetchMock.mock.calls.find((c) => String(c[0]).includes('/api/v1/cli-login/'))
    expect(getCall).toBeUndefined()
  })
})

// ── Authentication gate ──────────────────────────────────────────────────────────

describe('authentication gate', () => {
  it('shows the passkey login ceremony first when no session is present', async () => {
    // Every call 401s until login completes — simulates a genuinely session-less visitor.
    fetchMock.mockResolvedValue(jsonResponse(401))
    renderCliLogin()
    await waitFor(() =>
      expect(screen.getByRole('button', { name: /sign in with a passkey/i })).toBeInTheDocument(),
    )
    expect(screen.queryByTestId('cli-login-code')).not.toBeInTheDocument()
  })

  it('shows the code and confirm control after a completed passkey login', async () => {
    let loggedIn = false
    fetchMock.mockImplementation((input, init) => {
      const url = String(input)
      const method = (init?.method ?? 'GET').toUpperCase()
      if (url.endsWith('/api/v1/web/csrf')) {
        document.cookie = 'cfgms_csrf_pre=pre-tok; path=/'
        return Promise.resolve(jsonResponse(204))
      }
      if (url.endsWith('/api/v1/web/passkey/login/begin')) {
        return Promise.resolve(jsonResponse(200, MOCK_PASSKEY_BEGIN_OPTIONS))
      }
      if (url.endsWith('/api/v1/web/passkey/login/finish')) {
        loggedIn = true
        return Promise.resolve(
          jsonResponse(200, { data: { ok: true, username: 'admin@msp-a', tenant_id: '', root_scope: false } }),
        )
      }
      if (!loggedIn) return Promise.resolve(jsonResponse(401))
      if (method === 'GET' && url.includes('/api/v1/cli-login/')) {
        return Promise.resolve(jsonResponse(200, { data: PENDING_REQUEST }))
      }
      return Promise.resolve(jsonResponse(200))
    })

    renderCliLogin()
    await completePasskeyLogin()

    await waitFor(() => expect(screen.getByTestId('cli-login-code')).toHaveTextContent(CODE))
    expect(screen.getByRole('button', { name: /confirm/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /deny/i })).toBeInTheDocument()
  })

  it('completes normally for a root-scope account — no refusal state', async () => {
    mockEndpoints({ rootScope: true })
    fetchMock.mockResolvedValueOnce(jsonResponse(401)) // initial probe fails, forces the ceremony
    renderCliLogin()
    await completePasskeyLogin()

    await waitFor(() => expect(screen.getByTestId('cli-login-code')).toBeInTheDocument())
    expect(screen.queryByText(/too privileged/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/certificate bundle/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/refused/i)).not.toBeInTheDocument()
  })
})

// ── Code display and explicit confirmation ───────────────────────────────────────

describe('code display and explicit confirmation', () => {
  it('does not call approve on mount — only the read call fires', async () => {
    mockEndpoints({})
    renderCliLogin()
    await waitFor(() => expect(screen.getByTestId('cli-login-code')).toBeInTheDocument())

    const approveCall = fetchMock.mock.calls.find((c) => String(c[0]).includes('/approve'))
    expect(approveCall).toBeUndefined()
  })

  it('approves only after an explicit click on Confirm, sending the displayed code back', async () => {
    mockEndpoints({})
    renderCliLogin()
    await waitFor(() => expect(screen.getByTestId('cli-login-code')).toHaveTextContent(CODE))

    fireEvent.click(screen.getByRole('button', { name: /confirm/i }))

    await waitFor(() => {
      const approveCall = fetchMock.mock.calls.find((c) => String(c[0]).includes('/approve'))
      expect(approveCall).toBeDefined()
      const body = JSON.parse(String(approveCall?.[1]?.body)) as Record<string, unknown>
      expect(body).toEqual({ user_code: CODE, deny: false })
    })
    await waitFor(() => expect(screen.getByText(/login approved/i)).toBeInTheDocument())
  })

  it('denies only after an explicit click on Deny, sending deny:true', async () => {
    mockEndpoints({
      approveResponse: () => jsonResponse(200, { data: { request_id: 'cli-login-abc', status: 'denied' } }),
    })
    renderCliLogin()
    await waitFor(() => expect(screen.getByTestId('cli-login-code')).toHaveTextContent(CODE))

    fireEvent.click(screen.getByRole('button', { name: /^deny$/i }))

    await waitFor(() => {
      const approveCall = fetchMock.mock.calls.find((c) => String(c[0]).includes('/approve'))
      const body = JSON.parse(String(approveCall?.[1]?.body)) as Record<string, unknown>
      expect(body).toEqual({ user_code: CODE, deny: true })
    })
    await waitFor(() => expect(screen.getByText(/login denied/i)).toBeInTheDocument())
  })

  it('disables the actions while a submission is in flight (no double-submit)', async () => {
    let resolveApprove!: (r: Response) => void
    mockEndpoints({
      approveResponse: () => {
        throw new Error('replaced below')
      },
    })
    fetchMock.mockImplementation((input, init) => {
      const url = String(input)
      const method = (init?.method ?? 'GET').toUpperCase()
      if (method === 'POST' && url.includes('/approve')) {
        return new Promise((resolve) => {
          resolveApprove = resolve
        })
      }
      if (method === 'GET' && url.includes('/api/v1/cli-login/')) {
        return Promise.resolve(jsonResponse(200, { data: PENDING_REQUEST }))
      }
      return Promise.resolve(jsonResponse(401))
    })

    renderCliLogin()
    await waitFor(() => expect(screen.getByTestId('cli-login-code')).toBeInTheDocument())

    fireEvent.click(screen.getByRole('button', { name: /confirm/i }))
    await waitFor(() => expect(screen.getByRole('button', { name: /confirm/i })).toBeDisabled())
    expect(screen.getByRole('button', { name: /^deny$/i })).toBeDisabled()

    resolveApprove(jsonResponse(200, { data: { request_id: 'cli-login-abc', status: 'approved' } }))
    await waitFor(() => expect(screen.getByText(/login approved/i)).toBeInTheDocument())

    // Exactly one approve POST — no duplicate fired while disabled.
    const approveCalls = fetchMock.mock.calls.filter((c) => String(c[0]).includes('/approve'))
    expect(approveCalls).toHaveLength(1)
  })
})

// ── Terminal states ───────────────────────────────────────────────────────────────

describe('terminal states are distinct', () => {
  it('renders a denied message when the request was already denied', async () => {
    mockEndpoints({
      getResponse: () => jsonResponse(200, { data: { ...PENDING_REQUEST, status: 'denied' } }),
    })
    renderCliLogin()
    await waitFor(() => expect(screen.getByText(/login denied/i)).toBeInTheDocument())
    expect(screen.queryByTestId('cli-login-code')).not.toBeInTheDocument()
  })

  it('renders an expired message when the request has expired', async () => {
    mockEndpoints({
      getResponse: () => jsonResponse(200, { data: { ...PENDING_REQUEST, status: 'expired' } }),
    })
    renderCliLogin()
    await waitFor(() => expect(screen.getByText(/login request expired/i)).toBeInTheDocument())
  })

  it('renders an expired message when the request is no longer found (swept)', async () => {
    mockEndpoints({ getResponse: () => jsonResponse(404) })
    renderCliLogin()
    await waitFor(() => expect(screen.getByText(/login request expired/i)).toBeInTheDocument())
  })

  it('renders an approved message when the request was already approved elsewhere', async () => {
    mockEndpoints({
      getResponse: () => jsonResponse(200, { data: { ...PENDING_REQUEST, status: 'approved' } }),
    })
    renderCliLogin()
    await waitFor(() => expect(screen.getByText(/login approved/i)).toBeInTheDocument())
  })

  it('renders an approved message when the request was already collected', async () => {
    mockEndpoints({
      getResponse: () => jsonResponse(200, { data: { ...PENDING_REQUEST, status: 'collected' } }),
    })
    renderCliLogin()
    await waitFor(() => expect(screen.getByText(/login approved/i)).toBeInTheDocument())
  })

  it('denied, expired and approved states each render different text', async () => {
    const texts = new Set<string>()
    for (const status of ['denied', 'expired', 'approved']) {
      fetchMock.mockReset()
      mockEndpoints({ getResponse: () => jsonResponse(200, { data: { ...PENDING_REQUEST, status } }) })
      const { unmount, container } = renderCliLogin()
      await waitFor(() => expect(container.querySelector('.cli-login-state')).toBeInTheDocument())
      texts.add(container.querySelector('.cli-login-state')?.textContent ?? '')
      unmount()
    }
    expect(texts.size).toBe(3)
  })
})

// ── Token handling ────────────────────────────────────────────────────────────────

describe('session token never appears', () => {
  const HOSTILE_TOKEN = 'super-secret-session-token-should-never-appear'

  it('never renders a token even if the read response includes one', async () => {
    mockEndpoints({
      getResponse: () => jsonResponse(200, { data: { ...PENDING_REQUEST, token: HOSTILE_TOKEN } }),
    })
    renderCliLogin()
    await waitFor(() => expect(screen.getByTestId('cli-login-code')).toBeInTheDocument())
    expect(document.body.textContent).not.toContain(HOSTILE_TOKEN)
  })

  it('never renders, and never stores, a token even if the approve response includes one', async () => {
    const setItem = vi.spyOn(Storage.prototype, 'setItem')
    mockEndpoints({
      approveResponse: () =>
        jsonResponse(200, { data: { request_id: 'cli-login-abc', status: 'approved', token: HOSTILE_TOKEN } }),
    })
    renderCliLogin()
    await waitFor(() => expect(screen.getByTestId('cli-login-code')).toBeInTheDocument())

    fireEvent.click(screen.getByRole('button', { name: /confirm/i }))
    await waitFor(() => expect(screen.getByText(/login approved/i)).toBeInTheDocument())

    expect(document.body.textContent).not.toContain(HOSTILE_TOKEN)
    for (const call of setItem.mock.calls) {
      expect(String(call[1])).not.toContain(HOSTILE_TOKEN)
    }
    setItem.mockRestore()
  })

  it('the approve request payload never contains a token field', async () => {
    mockEndpoints({})
    renderCliLogin()
    await waitFor(() => expect(screen.getByTestId('cli-login-code')).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: /confirm/i }))

    await waitFor(() => {
      const approveCall = fetchMock.mock.calls.find((c) => String(c[0]).includes('/approve'))
      expect(approveCall).toBeDefined()
      const body = JSON.parse(String(approveCall?.[1]?.body)) as Record<string, unknown>
      expect(Object.keys(body)).not.toContain('token')
    })
  })
})

// ── Root-scope certificate assertion ──────────────────────────────────────────────

describe('never sends, requests, or renders a root-scope certificate grant', () => {
  const CERT_LIKE_KEYS = ['certificate', 'cert', 'csr', 'root_scope', 'rootScope', 'bundle']

  it('the approve payload never carries a certificate/root-scope field', async () => {
    mockEndpoints({})
    renderCliLogin()
    await waitFor(() => expect(screen.getByTestId('cli-login-code')).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: /confirm/i }))

    await waitFor(() => {
      const approveCall = fetchMock.mock.calls.find((c) => String(c[0]).includes('/approve'))
      expect(approveCall).toBeDefined()
      const body = JSON.parse(String(approveCall?.[1]?.body)) as Record<string, unknown>
      for (const key of CERT_LIKE_KEYS) {
        expect(Object.keys(body)).not.toContain(key)
      }
    })
  })

  it('the deny payload never carries a certificate/root-scope field', async () => {
    mockEndpoints({
      approveResponse: () => jsonResponse(200, { data: { request_id: 'cli-login-abc', status: 'denied' } }),
    })
    renderCliLogin()
    await waitFor(() => expect(screen.getByTestId('cli-login-code')).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: /^deny$/i }))

    await waitFor(() => {
      const approveCall = fetchMock.mock.calls.find((c) => String(c[0]).includes('/approve'))
      expect(approveCall).toBeDefined()
      const body = JSON.parse(String(approveCall?.[1]?.body)) as Record<string, unknown>
      for (const key of CERT_LIKE_KEYS) {
        expect(Object.keys(body)).not.toContain(key)
      }
    })
  })

  it('renders no control for issuing or requesting a certificate anywhere on the page', async () => {
    mockEndpoints({})
    renderCliLogin()
    await waitFor(() => expect(screen.getByTestId('cli-login-code')).toBeInTheDocument())
    expect(screen.queryByText(/certificate/i)).not.toBeInTheDocument()
  })
})
