// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
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

describe('App', () => {
  it('guards the authenticated screen: unauthenticated visit renders the login screen', () => {
    render(<App />)
    expect(screen.getByRole('button', { name: /sign in/i })).toBeInTheDocument()
    expect(screen.queryByText(/signed in as/i)).not.toBeInTheDocument()
  })

  it('full flow: login lands on the authenticated placeholder; sign-out returns to signin', async () => {
    fetchMock.mockImplementation((input) => {
      const url = String(input)
      if (url.endsWith('/api/v1/web/csrf')) {
        document.cookie = 'cfgms_csrf_pre=pre-tok; path=/'
        return Promise.resolve(jsonResponse(204))
      }
      return Promise.resolve(jsonResponse(url.endsWith('/logout') ? 204 : 200))
    })

    render(<App />)
    fireEvent.change(screen.getByLabelText(/username/i), {
      target: { value: 'admin@msp-a' },
    })
    fireEvent.change(screen.getByLabelText(/password/i), {
      target: { value: 'pw-pw-pw-pw' },
    })
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }))

    await waitFor(() =>
      expect(screen.getByText(/signed in as/i)).toBeInTheDocument(),
    )
    expect(screen.getByText('admin@msp-a')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /sign out/i }))
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

  it('probes the session after login; a 401 drops to the expired login screen', async () => {
    fetchMock.mockImplementation((input) => {
      const url = String(input)
      if (url.endsWith('/api/v1/web/csrf')) {
        document.cookie = 'cfgms_csrf_pre=pre-tok; path=/'
        return Promise.resolve(jsonResponse(204))
      }
      if (url.endsWith('/api/v1/web/login')) {
        return Promise.resolve(jsonResponse(200))
      }
      // The authenticated probe — a dead session answers 401.
      return Promise.resolve(jsonResponse(401))
    })

    render(<App />)
    fireEvent.change(screen.getByLabelText(/username/i), {
      target: { value: 'admin@msp-a' },
    })
    fireEvent.change(screen.getByLabelText(/password/i), {
      target: { value: 'pw-pw-pw-pw' },
    })
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }))

    // The probe fires on mount of the authenticated screen, 401s, and the
    // guard drops back to the login screen in its expired state.
    await waitFor(() =>
      expect(
        screen.getByText(/session expired\. sign in again to continue\./i),
      ).toBeInTheDocument(),
    )
    const probeCall = fetchMock.mock.calls.find((c) =>
      String(c[0]).includes('/api/v1/stewards'),
    )
    expect(probeCall).toBeDefined()
  })
})
