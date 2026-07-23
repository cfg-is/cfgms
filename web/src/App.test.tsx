// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import App from './App.tsx'

function jsonResponse(status: number, body: unknown = {}): Response {
  return new Response(status === 204 ? null : JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  vi.unstubAllGlobals()
})

/**
 * App requires a router provider; production uses BrowserRouter in main.tsx.
 * Tests use MemoryRouter so they don't depend on browser history.
 */
function renderApp() {
  return render(
    <MemoryRouter initialEntries={['/']}>
      <App />
    </MemoryRouter>,
  )
}

describe('App', () => {
  it('guards the authenticated screen: unauthenticated visit renders the login screen', async () => {
    // All data calls return 401 — no session cookie.
    // RequireAuth renders children during the probe phase, the first data call
    // 401s, and the guard falls back to the login screen (Story #2933).
    fetchMock.mockResolvedValue(jsonResponse(401))
    renderApp()
    await waitFor(() =>
      expect(screen.getByRole('button', { name: /sign in/i })).toBeInTheDocument(),
    )
    expect(screen.queryByRole('navigation')).not.toBeInTheDocument()
  })

  it('full flow: login lands on the app shell; sign-out returns to signin', async () => {
    // Initial probe calls return 401 so the login form appears; once the user
    // logs in all subsequent calls return 200 (Story #2933 probe pattern).
    let loggedIn = false
    fetchMock.mockImplementation((input) => {
      const url = String(input)
      if (url.endsWith('/api/v1/web/csrf')) {
        document.cookie = 'cfgms_csrf_pre=pre-tok; path=/'
        return Promise.resolve(jsonResponse(204))
      }
      if (url.endsWith('/api/v1/web/login')) {
        loggedIn = true
        return Promise.resolve(jsonResponse(200))
      }
      if (url.endsWith('/api/v1/web/logout')) {
        return Promise.resolve(jsonResponse(204))
      }
      return Promise.resolve(jsonResponse(loggedIn ? 200 : 401))
    })

    renderApp()
    // Probe resolves with 401 → signedOut → login form appears.
    await waitFor(() =>
      expect(screen.getByLabelText(/username/i)).toBeInTheDocument(),
    )
    fireEvent.change(screen.getByLabelText(/username/i), {
      target: { value: 'admin@msp-a' },
    })
    fireEvent.change(screen.getByLabelText(/password/i), {
      target: { value: 'pw-pw-pw-pw' },
    })
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }))

    await waitFor(() => expect(screen.getByRole('navigation')).toBeInTheDocument())

    fireEvent.click(screen.getByRole('button', { name: /account menu/i }))
    expect(screen.getByText('admin@msp-a')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('menuitem', { name: /sign out/i }))

    await waitFor(() =>
      expect(
        screen.getByRole('button', { name: /sign in/i }),
      ).toBeInTheDocument(),
    )
    // Back at the fresh signin state — no expired banner, no invalid error.
    expect(screen.queryByText(/session expired/i)).not.toBeInTheDocument()
    expect(
      screen.queryByText('Invalid username or password.'),
    ).not.toBeInTheDocument()
  })

  it('a 401 on the fleet data call drops to the expired login screen', async () => {
    fetchMock.mockImplementation((input) => {
      const url = String(input)
      if (url.endsWith('/api/v1/web/csrf')) {
        document.cookie = 'cfgms_csrf_pre=pre-tok; path=/'
        return Promise.resolve(jsonResponse(204))
      }
      if (url.endsWith('/api/v1/web/login')) {
        return Promise.resolve(jsonResponse(200))
      }
      // All data calls return 401: probe resolves to signedOut, login form
      // appears; after explicit login the fleet call 401s again (mid-session
      // drop) and the guard shows the expired state (Story #2933, ADR-018 §4).
      return Promise.resolve(jsonResponse(401))
    })

    renderApp()
    // Probe resolves with 401 → signedOut → login form appears.
    await waitFor(() =>
      expect(screen.getByLabelText(/username/i)).toBeInTheDocument(),
    )
    fireEvent.change(screen.getByLabelText(/username/i), {
      target: { value: 'admin@msp-a' },
    })
    fireEvent.change(screen.getByLabelText(/password/i), {
      target: { value: 'pw-pw-pw-pw' },
    })
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }))

    // The fleet data call fires on mount of the authenticated screen, 401s
    // mid-session, and the guard drops back to the login screen as expired.
    await waitFor(() =>
      expect(
        screen.getByText(/session expired\. sign in again to continue\./i),
      ).toBeInTheDocument(),
    )
    const dataCall = fetchMock.mock.calls.find((c) =>
      String(c[0]).includes('/api/v1/stewards'),
    )
    expect(dataCall).toBeDefined()
  })
})
