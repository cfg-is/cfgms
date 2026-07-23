// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, render, screen, waitFor } from '@testing-library/react'
import { useEffect } from 'react'
import { AuthProvider, RequireAuth, useAuth } from './AuthContext.tsx'
import { apiFetch } from '../api/client.ts'

function jsonResponse(
  status: number,
  body: unknown = {},
  headers: Record<string, string> = {},
): Response {
  return new Response(status === 204 ? null : JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  })
}

/** Probe component exposing auth state + actions to the tests. */
function Probe() {
  const auth = useAuth()
  return (
    <div>
      <output data-testid="status">{auth.status}</output>
      <output data-testid="principal">{auth.principal?.username ?? ''}</output>
      <button onClick={() => void auth.login('admin@msp-a', 'pw-pw-pw-pw')}>
        do-login
      </button>
      <button onClick={() => void auth.logout()}>do-logout</button>
    </div>
  )
}

/**
 * Simulates a protected route: renders PROTECTED-CONTENT and fires a single
 * apiFetch on mount so the session probe can resolve (Story #2933).
 */
function DataCallChild() {
  useEffect(() => {
    void apiFetch('/api/v1/stewards')
  }, [])
  return <div>PROTECTED-CONTENT</div>
}

const fetchMock = vi.fn<typeof fetch>()

function mockLoginEndpoints(loginStatus: number) {
  fetchMock.mockImplementation((input, init) => {
    const url = String(input)
    if (url.endsWith('/api/v1/web/csrf')) {
      document.cookie = 'cfgms_csrf_pre=pre-tok; path=/'
      return Promise.resolve(jsonResponse(204))
    }
    if (url.endsWith('/api/v1/web/login')) {
      return Promise.resolve(jsonResponse(loginStatus))
    }
    if (url.endsWith('/api/v1/web/logout')) {
      return Promise.resolve(jsonResponse(204))
    }
    void init
    return Promise.resolve(jsonResponse(200))
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

describe('AuthProvider state transitions', () => {
  it('starts signed out', () => {
    render(
      <AuthProvider>
        <Probe />
      </AuthProvider>,
    )
    expect(screen.getByTestId('status')).toHaveTextContent('signedOut')
  })

  it('login success → signedIn with the principal username', async () => {
    mockLoginEndpoints(200)
    render(
      <AuthProvider>
        <Probe />
      </AuthProvider>,
    )
    act(() => screen.getByText('do-login').click())
    await waitFor(() =>
      expect(screen.getByTestId('status')).toHaveTextContent('signedIn'),
    )
    expect(screen.getByTestId('principal')).toHaveTextContent('admin@msp-a')
  })

  it('login failure → invalid, not signed in, not expired', async () => {
    mockLoginEndpoints(401)
    render(
      <AuthProvider>
        <Probe />
      </AuthProvider>,
    )
    act(() => screen.getByText('do-login').click())
    await waitFor(() =>
      expect(screen.getByTestId('status')).toHaveTextContent('invalid'),
    )
    expect(screen.getByTestId('principal')).toHaveTextContent('')
  })

  it('a plain 401 (no step-up header) after sign-in → expired', async () => {
    mockLoginEndpoints(200)
    render(
      <AuthProvider>
        <Probe />
      </AuthProvider>,
    )
    act(() => screen.getByText('do-login').click())
    await waitFor(() =>
      expect(screen.getByTestId('status')).toHaveTextContent('signedIn'),
    )

    // Any later cookie-authenticated call that 401s drops the session.
    fetchMock.mockResolvedValue(jsonResponse(401))
    const { apiFetch } = await import('../api/client.ts')
    await act(async () => {
      await apiFetch('/api/v1/stewards')
    })
    await waitFor(() =>
      expect(screen.getByTestId('status')).toHaveTextContent('expired'),
    )
    expect(screen.getByTestId('principal')).toHaveTextContent('')
  })

  it('logout calls the endpoint and returns to signedOut', async () => {
    mockLoginEndpoints(200)
    render(
      <AuthProvider>
        <Probe />
      </AuthProvider>,
    )
    act(() => screen.getByText('do-login').click())
    await waitFor(() =>
      expect(screen.getByTestId('status')).toHaveTextContent('signedIn'),
    )
    act(() => screen.getByText('do-logout').click())
    await waitFor(() =>
      expect(screen.getByTestId('status')).toHaveTextContent('signedOut'),
    )
    const logoutCall = fetchMock.mock.calls.find((c) =>
      String(c[0]).endsWith('/api/v1/web/logout'),
    )
    expect(logoutCall).toBeDefined()
    expect(logoutCall?.[1]?.method).toBe('POST')
  })

  it('never writes auth state to localStorage or sessionStorage', async () => {
    mockLoginEndpoints(200)
    render(
      <AuthProvider>
        <Probe />
      </AuthProvider>,
    )
    act(() => screen.getByText('do-login').click())
    await waitFor(() =>
      expect(screen.getByTestId('status')).toHaveTextContent('signedIn'),
    )
    expect(window.localStorage.length).toBe(0)
    expect(window.sessionStorage.length).toBe(0)
  })
})

describe('AuthProvider — step-up (Story #2786)', () => {
  const MOCK_BEGIN_OPTIONS = {
    publicKey: {
      challenge: 'Y2hhbGxlbmdlLWJ5dGVz',
      timeout: 60000,
      rpId: 'localhost',
      allowCredentials: [],
      userVerification: 'required' as const,
    },
  }

  it('CFGMS-StepUp 401 shows the step-up modal, NOT the sign-in screen', async () => {
    mockLoginEndpoints(200)
    // presence/begin returns valid options so the modal reaches 'waiting' state.
    fetchMock.mockImplementation((input) => {
      const url = String(input)
      if (url.endsWith('/api/v1/web/csrf')) {
        document.cookie = 'cfgms_csrf_pre=pre-tok; path=/'
        return Promise.resolve(jsonResponse(204))
      }
      if (url.endsWith('/api/v1/web/login')) return Promise.resolve(jsonResponse(200))
      if (url.includes('presence/begin')) {
        return Promise.resolve(jsonResponse(200, MOCK_BEGIN_OPTIONS))
      }
      // The API call that triggers step-up.
      return Promise.resolve(
        jsonResponse(401, { error: 'step_up_required' }, {
          'WWW-Authenticate': 'CFGMS-StepUp realm="cfgms", required="strong", presence="required"',
        }),
      )
    })

    render(
      <AuthProvider>
        <Probe />
      </AuthProvider>,
    )

    act(() => screen.getByText('do-login').click())
    await waitFor(() =>
      expect(screen.getByTestId('status')).toHaveTextContent('signedIn'),
    )

    const { apiFetch } = await import('../api/client.ts')
    // Fire the step-up 401 without awaiting — the listener promise holds it
    // open until the modal is dismissed. Do NOT use void act(async () => ...)
    // here: calling act() without await defers React state updates until after
    // the test frame, so waitFor never sees setStepUpState flush.
    void apiFetch('/api/v1/modules/approvals/cfgms:test:1.0.0:AAAA/approve', {
      method: 'POST',
    })

    // Modal overlay must appear; waitFor flushes state updates on each retry.
    await waitFor(() =>
      expect(screen.getByTestId('step-up-overlay')).toBeInTheDocument(),
    )
    // Auth status must remain signedIn (not expired, not signedOut).
    expect(screen.getByTestId('status')).toHaveTextContent('signedIn')
    // No "Sign in" button — the login screen must NOT be shown.
    expect(screen.queryByRole('button', { name: /sign in/i })).not.toBeInTheDocument()

    // Dismiss the modal to resolve the listener promise and prevent a dangling
    // Promise from contaminating later tests in this file.
    await waitFor(() => screen.getByTestId('step-up-verify-btn'))
    act(() => screen.getByTestId('step-up-cancel-btn').click())
    await waitFor(() =>
      expect(screen.queryByTestId('step-up-overlay')).not.toBeInTheDocument(),
    )
  })

  it('plain 401 (no CFGMS-StepUp header) still triggers session-expired — regression', async () => {
    mockLoginEndpoints(200)
    render(
      <AuthProvider>
        <Probe />
      </AuthProvider>,
    )
    act(() => screen.getByText('do-login').click())
    await waitFor(() =>
      expect(screen.getByTestId('status')).toHaveTextContent('signedIn'),
    )

    fetchMock.mockResolvedValue(jsonResponse(401))
    const { apiFetch } = await import('../api/client.ts')
    await act(async () => {
      await apiFetch('/api/v1/stewards')
    })

    await waitFor(() =>
      expect(screen.getByTestId('status')).toHaveTextContent('expired'),
    )
    // No step-up modal should appear.
    expect(screen.queryByTestId('step-up-overlay')).not.toBeInTheDocument()
  })

  it('cancelling the step-up modal leaves auth status signedIn', async () => {
    mockLoginEndpoints(200)
    fetchMock.mockImplementation((input) => {
      const url = String(input)
      if (url.endsWith('/api/v1/web/csrf')) {
        document.cookie = 'cfgms_csrf_pre=pre-tok; path=/'
        return Promise.resolve(jsonResponse(204))
      }
      if (url.endsWith('/api/v1/web/login')) return Promise.resolve(jsonResponse(200))
      if (url.includes('presence/begin')) {
        return Promise.resolve(jsonResponse(200, MOCK_BEGIN_OPTIONS))
      }
      return Promise.resolve(
        jsonResponse(401, { error: 'step_up_required' }, {
          'WWW-Authenticate': 'CFGMS-StepUp realm="cfgms", required="strong", presence="required"',
        }),
      )
    })

    render(
      <AuthProvider>
        <Probe />
      </AuthProvider>,
    )

    act(() => screen.getByText('do-login').click())
    await waitFor(() =>
      expect(screen.getByTestId('status')).toHaveTextContent('signedIn'),
    )

    const { apiFetch } = await import('../api/client.ts')
    void apiFetch('/api/v1/modules/approvals/cfgms:test:1.0.0:AAAA/approve', {
      method: 'POST',
    })

    // Wait for modal with Cancel button enabled (waiting state).
    await waitFor(() => screen.getByTestId('step-up-verify-btn'))

    // Click Cancel.
    act(() => screen.getByTestId('step-up-cancel-btn').click())

    // Modal must close.
    await waitFor(() =>
      expect(screen.queryByTestId('step-up-overlay')).not.toBeInTheDocument(),
    )
    // Auth must stay signedIn.
    expect(screen.getByTestId('status')).toHaveTextContent('signedIn')
    expect(screen.getByTestId('principal')).toHaveTextContent('admin@msp-a')
  })
})

describe('RequireAuth route guard', () => {
  it('renders children on initial mount (probe phase — not the login screen)', () => {
    // On fresh load (probing=true, signedOut), RequireAuth renders children so
    // the route's data call can act as the session probe (Story #2933).
    render(
      <AuthProvider>
        <RequireAuth>
          <div>PROTECTED-CONTENT</div>
        </RequireAuth>
      </AuthProvider>,
    )
    expect(screen.getByText('PROTECTED-CONTENT')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /sign in/i })).not.toBeInTheDocument()
  })

  it('shows login screen after the initial data call 401s (probe resolved unauthenticated)', async () => {
    fetchMock.mockResolvedValue(jsonResponse(401))
    render(
      <AuthProvider>
        <RequireAuth>
          <DataCallChild />
        </RequireAuth>
      </AuthProvider>,
    )
    // Children render during probe phase.
    expect(screen.getByText('PROTECTED-CONTENT')).toBeInTheDocument()
    // After the 401 resolves the probe, the login screen appears.
    await waitFor(() =>
      expect(screen.getByRole('button', { name: /sign in/i })).toBeInTheDocument(),
    )
    expect(screen.queryByText('PROTECTED-CONTENT')).not.toBeInTheDocument()
  })

  it('renders protected content once signed in via explicit login', async () => {
    mockLoginEndpoints(200)
    render(
      <AuthProvider>
        <Probe />
        <RequireAuth>
          <div>PROTECTED-CONTENT</div>
        </RequireAuth>
      </AuthProvider>,
    )
    act(() => screen.getByText('do-login').click())
    await waitFor(() =>
      expect(screen.getByText('PROTECTED-CONTENT')).toBeInTheDocument(),
    )
  })

  it('shows login screen immediately for invalid status (failed login attempt)', async () => {
    mockLoginEndpoints(401)
    render(
      <AuthProvider>
        <Probe />
        <RequireAuth>
          <div>PROTECTED-CONTENT</div>
        </RequireAuth>
      </AuthProvider>,
    )
    act(() => screen.getByText('do-login').click())
    await waitFor(() =>
      expect(screen.getByTestId('status')).toHaveTextContent('invalid'),
    )
    expect(screen.getByRole('button', { name: /sign in/i })).toBeInTheDocument()
    expect(screen.queryByText('PROTECTED-CONTENT')).not.toBeInTheDocument()
  })

  it('shows login screen immediately for expired status (mid-session 401)', async () => {
    mockLoginEndpoints(200)
    render(
      <AuthProvider>
        <Probe />
        <RequireAuth>
          <div>PROTECTED-CONTENT</div>
        </RequireAuth>
      </AuthProvider>,
    )
    act(() => screen.getByText('do-login').click())
    await waitFor(() =>
      expect(screen.getByTestId('status')).toHaveTextContent('signedIn'),
    )

    fetchMock.mockResolvedValue(jsonResponse(401))
    const { apiFetch: af } = await import('../api/client.ts')
    await act(async () => {
      await af('/api/v1/stewards')
    })
    await waitFor(() =>
      expect(screen.getByRole('button', { name: /sign in/i })).toBeInTheDocument(),
    )
    expect(screen.getByTestId('status')).toHaveTextContent('expired')
    expect(screen.queryByText('PROTECTED-CONTENT')).not.toBeInTheDocument()
  })
})

describe('AuthProvider — session probe (Story #2933)', () => {
  it('initial mount with successful data call → signedIn (valid session cookie)', async () => {
    fetchMock.mockResolvedValue(jsonResponse(200))
    render(
      <AuthProvider>
        <Probe />
        <RequireAuth>
          <DataCallChild />
        </RequireAuth>
      </AuthProvider>,
    )
    await waitFor(() =>
      expect(screen.getByTestId('status')).toHaveTextContent('signedIn'),
    )
  })

  it('initial mount with 401 data call → signedOut, not expired (no session cookie)', async () => {
    fetchMock.mockResolvedValue(jsonResponse(401))
    render(
      <AuthProvider>
        <Probe />
        <RequireAuth>
          <DataCallChild />
        </RequireAuth>
      </AuthProvider>,
    )
    await waitFor(() =>
      expect(screen.getByRole('button', { name: /sign in/i })).toBeInTheDocument(),
    )
    // Must be signedOut (first-load semantics), not expired (mid-session semantics).
    expect(screen.getByTestId('status')).toHaveTextContent('signedOut')
    expect(screen.getByTestId('status').textContent).toBe('signedOut')
  })

  it('explicit failed login → invalid immediately (regression: not via probe path)', async () => {
    mockLoginEndpoints(401)
    render(
      <AuthProvider>
        <Probe />
        <RequireAuth>
          <div>PROTECTED-CONTENT</div>
        </RequireAuth>
      </AuthProvider>,
    )
    act(() => screen.getByText('do-login').click())
    await waitFor(() =>
      expect(screen.getByTestId('status')).toHaveTextContent('invalid'),
    )
    expect(screen.queryByTestId('status')?.textContent).toBe('invalid')
  })
})
