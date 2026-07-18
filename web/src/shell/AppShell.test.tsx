// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { AuthProvider } from '../auth/AuthContext.tsx'
import FleetOverview from '../fleet/FleetOverview.tsx'
import AppShell from './AppShell.tsx'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
  // The fleet view (#2497) fetches its steward page on mount; the health tiles
  // (Issue #2729) also fetch on mount. Use mockImplementation to create a fresh
  // Response per call — a shared Response from mockResolvedValue would have its
  // body consumed by the health fetch, breaking the stewards fetch.
  fetchMock.mockImplementation(() =>
    Promise.resolve(
      new Response(
        JSON.stringify({
          data: { stewards: [], total: 0, limit: 50, offset: 0 },
          timestamp: new Date().toISOString(),
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    ),
  )
  document.body.className = ''
})

afterEach(() => {
  vi.unstubAllGlobals()
})

/**
 * Renders AppShell as a layout route with FleetOverview at the index route.
 * AppShell provides search state via Outlet context, which FleetOverview
 * reads via useOutletContext.
 */
function renderShell() {
  return render(
    <MemoryRouter initialEntries={['/']}>
      <AuthProvider>
        <Routes>
          <Route path="/" element={<AppShell />}>
            <Route index element={<FleetOverview />} />
          </Route>
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  )
}

describe('AppShell', () => {
  it('renders sidebar navigation with Fleet and Audit as links', () => {
    renderShell()
    expect(screen.getByRole('navigation')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /fleet/i })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /audit/i })).toBeInTheDocument()
  })

  it('marks Modules and Config as soon while Fleet and Audit are real links', () => {
    renderShell()
    // 2 soon-tagged items remain (Modules, Config); Audit is now a real link
    expect(screen.getAllByText(/soon/i).length).toBeGreaterThan(0)
    // Audit is a NavLink, not a soon anchor
    expect(screen.getByRole('link', { name: /audit/i })).toBeInTheDocument()
  })

  it('mounts the fleet overview (#2497) in the content area', async () => {
    renderShell()
    expect(
      screen.getByRole('heading', { name: 'Fleet', level: 1 }),
    ).toBeInTheDocument()
    expect(
      await screen.findByText(/no stewards enrolled yet/i),
    ).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /columns/i })).toBeInTheDocument()
  })

  it('renders the tenant switcher, search, alert center, and user menu', () => {
    renderShell()
    expect(screen.getByRole('button', { name: /root/i })).toBeInTheDocument()
    expect(screen.getByRole('searchbox')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /notifications/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /account menu/i })).toBeInTheDocument()
  })

  it('opens the mobile drawer via the hamburger button and shows a scrim', () => {
    renderShell()
    const hamburger = screen.getByRole('button', { name: /open navigation/i })
    fireEvent.click(hamburger)
    expect(document.body.classList.contains('drawer')).toBe(true)
  })

  it('closes the drawer on Escape', () => {
    renderShell()
    fireEvent.click(screen.getByRole('button', { name: /open navigation/i }))
    expect(document.body.classList.contains('drawer')).toBe(true)
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(document.body.classList.contains('drawer')).toBe(false)
  })

  it('closes the drawer when the scrim is clicked', () => {
    renderShell()
    fireEvent.click(screen.getByRole('button', { name: /open navigation/i }))
    fireEvent.click(screen.getByTestId('shell-scrim'))
    expect(document.body.classList.contains('drawer')).toBe(false)
  })
})
