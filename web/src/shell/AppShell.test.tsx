// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { AuthProvider } from '../auth/AuthContext.tsx'
import AppShell from './AppShell.tsx'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
  document.body.className = ''
})

afterEach(() => {
  vi.unstubAllGlobals()
})

function renderShell() {
  return render(
    <AuthProvider>
      <AppShell />
    </AuthProvider>,
  )
}

describe('AppShell', () => {
  it('renders sidebar navigation with Fleet active and other items marked soon', () => {
    renderShell()
    expect(screen.getByRole('navigation')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /fleet/i })).toBeInTheDocument()
    expect(screen.getAllByText(/soon/i).length).toBeGreaterThan(0)
  })

  it('renders the content area empty-state placeholder (no fleet table in this story)', () => {
    renderShell()
    expect(screen.getByText(/fleet overview lands in story #2497/i)).toBeInTheDocument()
    expect(screen.queryByRole('table')).not.toBeInTheDocument()
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
