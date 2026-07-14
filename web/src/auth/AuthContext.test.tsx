// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, render, screen, waitFor } from '@testing-library/react'
import { AuthProvider, RequireAuth, useAuth } from './AuthContext.tsx'

function jsonResponse(status: number, body: unknown = {}): Response {
  return new Response(status === 204 ? null : JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
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

  it('a 401 on any API call after sign-in → expired', async () => {
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

describe('RequireAuth route guard', () => {
  it('renders the login screen instead of protected content when signed out', () => {
    render(
      <AuthProvider>
        <RequireAuth>
          <div>PROTECTED-CONTENT</div>
        </RequireAuth>
      </AuthProvider>,
    )
    expect(screen.queryByText('PROTECTED-CONTENT')).not.toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /sign in/i }),
    ).toBeInTheDocument()
  })

  it('renders protected content once signed in', async () => {
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
})
