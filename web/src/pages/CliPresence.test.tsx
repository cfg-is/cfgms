// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Tests for the CLI presence-relay confirmation screen (Issue #4287).
 *
 * Coverage:
 *  - Only request_id is read from the URL
 *  - Passkey login is required before the action/code/confirm control appears
 *  - The bound action (permission, method+path, body digest) and code are displayed
 *  - Nothing but the bound values is rendered: a caller-supplied "description" in the
 *    read response never reaches the consent text
 *  - The ceremony trigger is unreachable before an explicit code confirmation
 *  - The ceremony refuses to run for an unknown or expired request (no confirm/verify
 *    controls are ever offered for those states)
 *  - A successful ceremony shows the terminal success state
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router'
import { AuthProvider } from '../auth/AuthContext.tsx'
import CliPresence from './CliPresence.tsx'

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
const PERMISSION = 'module:approve'
const METHOD = 'POST'
const PATH = '/api/v1/modules/approvals/test-address/approve'
const EMPTY_BODY_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
const PENDING_REQUEST = {
  request_id: 'cli-presence-abc',
  status: 'pending',
  user_code: CODE,
  expires_at: '2026-08-29T00:10:00Z',
  permission: PERMISSION,
  method: METHOD,
  path: PATH,
  body_sha256: EMPTY_BODY_SHA256,
}

const fetchMock = vi.fn<typeof fetch>()

function mockEndpoints(opts: {
  getResponse?: () => Response
  finishResponse?: () => Response
}) {
  const getResponse = opts.getResponse ?? (() => jsonResponse(200, { data: PENDING_REQUEST }))
  const finishResponse = opts.finishResponse ?? (() => jsonResponse(200, { presence_token: 'server-side-only' }))

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
        jsonResponse(200, { data: { ok: true, username: 'admin@msp-a', tenant_id: '', root_scope: false } }),
      )
    }
    if (method === 'POST' && url.endsWith('/api/v1/webauthn/presence/begin')) {
      return Promise.resolve(jsonResponse(200, MOCK_PASSKEY_BEGIN_OPTIONS))
    }
    if (method === 'POST' && url.includes('/api/v1/webauthn/presence/finish')) {
      return Promise.resolve(finishResponse())
    }
    if (method === 'GET' && url.includes('/api/v1/cli-presence/')) {
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

function renderCliPresence(search = 'request_id=cli-presence-abc') {
  return render(
    <MemoryRouter initialEntries={[`/cli/presence?${search}`]}>
      <AuthProvider>
        <Routes>
          <Route path="/cli/presence" element={<CliPresence />} />
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  )
}

async function completePasskeyLogin() {
  vi.stubGlobal('navigator', { credentials: { get: vi.fn().mockResolvedValue(makePublicKeyCredential()) } })
  await waitFor(() => expect(screen.getByRole('button', { name: /sign in with a passkey/i })).toBeInTheDocument())
  fireEvent.click(screen.getByRole('button', { name: /sign in with a passkey/i }))
}

// ── URL parameter handling ───────────────────────────────────────────────────────

describe('URL parameter handling', () => {
  it('reads only request_id from the URL', async () => {
    mockEndpoints({})
    renderCliPresence('request_id=cli-presence-abc&host=evil.example&callback=http%3A%2F%2Fevil.example%2Fsteal')

    await waitFor(() => expect(screen.getByTestId('cli-presence-code')).toBeInTheDocument())

    const getCall = fetchMock.mock.calls.find(
      (c) => (c[1]?.method ?? 'GET') === 'GET' && String(c[0]).includes('/api/v1/cli-presence/'),
    )
    expect(getCall).toBeDefined()
    expect(String(getCall?.[0])).toBe('/api/v1/cli-presence/cli-presence-abc')
  })

  it('shows an error state when request_id is missing, once authenticated', async () => {
    mockEndpoints({})
    renderCliPresence('host=evil.example')
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(/invalid presence link/i))
  })
})

// ── Authentication gate ──────────────────────────────────────────────────────────

describe('authentication gate', () => {
  it('shows the passkey login ceremony first when no session is present', async () => {
    fetchMock.mockResolvedValue(jsonResponse(401))
    renderCliPresence()
    await waitFor(() =>
      expect(screen.getByRole('button', { name: /sign in with a passkey/i })).toBeInTheDocument(),
    )
    expect(screen.queryByTestId('cli-presence-code')).not.toBeInTheDocument()
  })

  it('shows the bound action and code after a completed passkey login', async () => {
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
      if (method === 'GET' && url.includes('/api/v1/cli-presence/')) {
        return Promise.resolve(jsonResponse(200, { data: PENDING_REQUEST }))
      }
      return Promise.resolve(jsonResponse(200))
    })

    renderCliPresence()
    await completePasskeyLogin()

    await waitFor(() => expect(screen.getByTestId('cli-presence-code')).toHaveTextContent(CODE))
    expect(screen.getByTestId('cli-presence-permission')).toHaveTextContent(PERMISSION)
    expect(screen.getByTestId('cli-presence-request')).toHaveTextContent(`${METHOD} ${PATH}`)
    expect(screen.getByTestId('cli-presence-body-digest')).toHaveTextContent(/empty request body/i)
  })
})

// ── The consent text is the enforced binding, never caller-authored text ──────────

describe('consent text is the enforced action binding', () => {
  it('renders permission, method, path and body digest — the four bound values', async () => {
    mockEndpoints({
      getResponse: () =>
        jsonResponse(200, {
          data: { ...PENDING_REQUEST, body_sha256: 'a'.repeat(64) },
        }),
    })
    renderCliPresence()

    await waitFor(() => expect(screen.getByTestId('cli-presence-action')).toBeInTheDocument())
    expect(screen.getByTestId('cli-presence-permission')).toHaveTextContent(PERMISSION)
    expect(screen.getByTestId('cli-presence-request')).toHaveTextContent(`${METHOD} ${PATH}`)
    expect(screen.getByTestId('cli-presence-body-digest')).toHaveTextContent('sha256:aaaaaaaaaaaaaaaa')
  })

  /*
   * Regression guard for the authorization-display integrity hole: malware holding the
   * CLI credential binds an evil action while describing a benign one. The lodge API no
   * longer accepts display text, and this page renders none — so even a read response
   * that carries a stray "description" key cannot reach the consent display.
   */
  it('ignores a description field in the read response', async () => {
    const benignLie = 'module:approve — POST /api/v1/modules/approvals/corp-baseline/approve'
    mockEndpoints({
      getResponse: () =>
        jsonResponse(200, {
          data: {
            ...PENDING_REQUEST,
            path: '/api/v1/modules/approvals/evil-bundle/approve',
            description: benignLie,
          },
        }),
    })
    renderCliPresence()

    await waitFor(() => expect(screen.getByTestId('cli-presence-action')).toBeInTheDocument())
    expect(screen.queryByText(/corp-baseline/)).not.toBeInTheDocument()
    expect(screen.getByTestId('cli-presence-request')).toHaveTextContent(
      'POST /api/v1/modules/approvals/evil-bundle/approve',
    )
  })
})

// ── Explicit code confirmation gates the ceremony ─────────────────────────────────

describe('explicit code confirmation gates the ceremony', () => {
  it('shows only a code-confirmation control at first — no verify/ceremony control yet', async () => {
    mockEndpoints({})
    renderCliPresence()
    await waitFor(() => expect(screen.getByTestId('cli-presence-code')).toBeInTheDocument())

    expect(screen.getByTestId('cli-presence-confirm-code-btn')).toBeInTheDocument()
    expect(screen.queryByTestId('cli-presence-verify-btn')).not.toBeInTheDocument()
  })

  it('never calls presence/begin before the code is confirmed', async () => {
    mockEndpoints({})
    renderCliPresence()
    await waitFor(() => expect(screen.getByTestId('cli-presence-code')).toBeInTheDocument())

    const beginCall = fetchMock.mock.calls.find((c) => String(c[0]).includes('/webauthn/presence/begin'))
    expect(beginCall).toBeUndefined()
  })

  it('reveals the verify control only after the code is confirmed, and only then starts the ceremony', async () => {
    mockEndpoints({})
    renderCliPresence()
    await waitFor(() => expect(screen.getByTestId('cli-presence-code')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('cli-presence-confirm-code-btn'))
    await waitFor(() => expect(screen.getByTestId('cli-presence-verify-btn')).toBeInTheDocument())

    // Still no network call until the verify button itself is clicked.
    expect(fetchMock.mock.calls.find((c) => String(c[0]).includes('/webauthn/presence/begin'))).toBeUndefined()

    vi.stubGlobal('navigator', { credentials: { get: vi.fn().mockResolvedValue(makePublicKeyCredential()) } })
    fireEvent.click(screen.getByTestId('cli-presence-verify-btn'))

    await waitFor(() => {
      const beginCall = fetchMock.mock.calls.find((c) => String(c[0]).includes('/webauthn/presence/begin'))
      expect(beginCall).toBeDefined()
    })
  })

  it('attaches cli_presence_request_id to the finish call', async () => {
    mockEndpoints({})
    renderCliPresence()
    await waitFor(() => expect(screen.getByTestId('cli-presence-code')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('cli-presence-confirm-code-btn'))
    await waitFor(() => expect(screen.getByTestId('cli-presence-verify-btn')).toBeInTheDocument())

    vi.stubGlobal('navigator', { credentials: { get: vi.fn().mockResolvedValue(makePublicKeyCredential()) } })
    fireEvent.click(screen.getByTestId('cli-presence-verify-btn'))

    await waitFor(() => {
      const finishCall = fetchMock.mock.calls.find((c) => String(c[0]).includes('/webauthn/presence/finish'))
      expect(finishCall).toBeDefined()
      expect(String(finishCall?.[0])).toContain('cli_presence_request_id=cli-presence-abc')
    })
  })

  it('shows the success state after a completed ceremony', async () => {
    mockEndpoints({})
    renderCliPresence()
    await waitFor(() => expect(screen.getByTestId('cli-presence-code')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('cli-presence-confirm-code-btn'))
    await waitFor(() => expect(screen.getByTestId('cli-presence-verify-btn')).toBeInTheDocument())

    vi.stubGlobal('navigator', { credentials: { get: vi.fn().mockResolvedValue(makePublicKeyCredential()) } })
    fireEvent.click(screen.getByTestId('cli-presence-verify-btn'))

    await waitFor(() => expect(screen.getByText(/verified/i)).toBeInTheDocument())
    expect(screen.getByText(/return to your terminal/i)).toBeInTheDocument()
  })
})

// ── Unknown / expired requests never offer a ceremony control ────────────────────

describe('refuses to run the ceremony for an unknown or expired request', () => {
  it('renders an expired message and no confirm/verify control when the request has expired', async () => {
    mockEndpoints({
      getResponse: () => jsonResponse(200, { data: { ...PENDING_REQUEST, status: 'expired' } }),
    })
    renderCliPresence()
    await waitFor(() => expect(screen.getByText(/presence request expired/i)).toBeInTheDocument())
    expect(screen.queryByTestId('cli-presence-confirm-code-btn')).not.toBeInTheDocument()
    expect(screen.queryByTestId('cli-presence-verify-btn')).not.toBeInTheDocument()
  })

  it('renders an expired message and no confirm/verify control when the request is unknown (404)', async () => {
    mockEndpoints({ getResponse: () => jsonResponse(404) })
    renderCliPresence()
    await waitFor(() => expect(screen.getByText(/presence request expired/i)).toBeInTheDocument())
    expect(screen.queryByTestId('cli-presence-confirm-code-btn')).not.toBeInTheDocument()
    expect(screen.queryByTestId('cli-presence-verify-btn')).not.toBeInTheDocument()

    const beginCall = fetchMock.mock.calls.find((c) => String(c[0]).includes('/webauthn/presence/begin'))
    expect(beginCall).toBeUndefined()
  })
})
