// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * RegistrationConsolePage suite (Stories #2934, #2935): tab strip composition,
 * default tab, roving tabindex, ArrowLeft/ArrowRight keyboard navigation with
 * wraparound, focus side-effects, and the real-vs-soon panel switch.
 *
 * Fetch is stubbed at the global level so PendingQueueTab and TokensTab render
 * against real apiFetch, not stand-ins. Default mock never settles, keeping
 * tabs in their loading state during structural assertions.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, createEvent, fireEvent, render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { AuthProvider } from '../auth/AuthContext.tsx'
import RegistrationConsolePage, { TABS } from './RegistrationConsolePage.tsx'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
  // Default: fetches never settle — tab-strip assertions are not racing async updates.
  fetchMock.mockReturnValue(new Promise(() => {}))
})

afterEach(() => {
  vi.unstubAllGlobals()
  cleanup()
})

function renderPage() {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <RegistrationConsolePage />
      </AuthProvider>
    </MemoryRouter>,
  )
}

function tab(name: RegExp) {
  return screen.getByRole('tab', { name })
}

// ── Tab strip composition ─────────────────────────────────────────────────────

describe('RegistrationConsolePage — tab strip', () => {
  it('renders a tablist with Pending, Tokens, and IP Trust', () => {
    renderPage()

    expect(screen.getByRole('tablist', { name: /registration sections/i })).toBeInTheDocument()
    expect(tab(/^Pending/i)).toBeInTheDocument()
    expect(tab(/^Tokens/i)).toBeInTheDocument()
    expect(tab(/^IP Trust/i)).toBeInTheDocument()
    expect(screen.getAllByRole('tab')).toHaveLength(TABS.length)
  })

  it('opens on Pending by default', () => {
    renderPage()

    expect(tab(/^Pending/i)).toHaveAttribute('aria-selected', 'true')
    expect(tab(/^Tokens/i)).toHaveAttribute('aria-selected', 'false')
    expect(tab(/^IP Trust/i)).toHaveAttribute('aria-selected', 'false')
  })

  it('gives the active tab a roving tabindex of 0 and the rest -1', () => {
    renderPage()

    expect(tab(/^Pending/i)).toHaveAttribute('tabindex', '0')
    expect(tab(/^Tokens/i)).toHaveAttribute('tabindex', '-1')
    expect(tab(/^IP Trust/i)).toHaveAttribute('tabindex', '-1')

    fireEvent.click(tab(/^Tokens/i))

    expect(tab(/^Pending/i)).toHaveAttribute('tabindex', '-1')
    expect(tab(/^Tokens/i)).toHaveAttribute('tabindex', '0')
  })

  it('badges only the not-yet-available tabs with "soon"', () => {
    renderPage()

    for (const spec of TABS.filter((t) => t.soon)) {
      const tabEl = screen.getByRole('tab', { name: (n) => n.startsWith(spec.label) })
      expect(within(tabEl).getByText(/^soon$/i)).toBeInTheDocument()
    }
    expect(within(tab(/^Pending/i)).queryByText(/^soon$/i)).toBeNull()
    expect(within(tab(/^Tokens/i)).queryByText(/^soon$/i)).toBeNull()
  })

  it('associates the panel with the active tab via aria-labelledby', () => {
    renderPage()

    const panel = screen.getByRole('tabpanel')
    expect(panel).toHaveAttribute('aria-labelledby', 'reg-tab-pending')
    expect(tab(/^Pending/i)).toHaveAttribute('id', 'reg-tab-pending')

    fireEvent.click(tab(/^IP Trust/i))

    const nextPanel = screen.getByRole('tabpanel')
    expect(nextPanel).toHaveAttribute('aria-labelledby', 'reg-tab-ip-trust')
    expect(nextPanel).toHaveAttribute('id', 'reg-panel-ip-trust')
  })
})

// ── Panel switching ───────────────────────────────────────────────────────────

describe('RegistrationConsolePage — panel rendering', () => {
  it('mounts the real PendingQueueTab on the Pending tab, not a soon placeholder', () => {
    renderPage()

    expect(screen.getByTestId('pending-loading')).toBeInTheDocument()
    expect(screen.queryByText(/Pending is not yet available/i)).toBeNull()
  })

  it('mounts the real TokensTab on the Tokens tab, not a soon placeholder', () => {
    renderPage()

    fireEvent.click(tab(/^Tokens/i))

    expect(tab(/^Tokens/i)).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByTestId('tokens-loading')).toBeInTheDocument()
    expect(screen.queryByText(/Tokens is not yet available/i)).toBeNull()
    expect(screen.queryByTestId('pending-loading')).toBeNull()
  })

  it('renders the soon placeholder for IP Trust', () => {
    renderPage()

    fireEvent.click(tab(/^IP Trust/i))

    expect(screen.getByText(/IP Trust is not yet available/i)).toBeInTheDocument()
  })

  it('restores the Pending panel after visiting the Tokens tab', () => {
    renderPage()

    fireEvent.click(tab(/^Tokens/i))
    fireEvent.click(tab(/^Pending/i))

    expect(tab(/^Pending/i)).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByTestId('pending-loading')).toBeInTheDocument()
    expect(screen.queryByTestId('tokens-loading')).toBeNull()
  })

  it('exposes no approve control on the console shell', () => {
    renderPage()

    expect(screen.queryByRole('button', { name: /approve/i })).toBeNull()
  })
})

// ── Keyboard navigation ───────────────────────────────────────────────────────

describe('RegistrationConsolePage — keyboard navigation', () => {
  it('ArrowRight advances through the tabs in order', () => {
    renderPage()
    const tablist = screen.getByRole('tablist')

    fireEvent.keyDown(tablist, { key: 'ArrowRight' })
    expect(tab(/^Tokens/i)).toHaveAttribute('aria-selected', 'true')

    fireEvent.keyDown(tablist, { key: 'ArrowRight' })
    expect(tab(/^IP Trust/i)).toHaveAttribute('aria-selected', 'true')
  })

  it('ArrowRight wraps from the last tab back to Pending', () => {
    renderPage()
    const tablist = screen.getByRole('tablist')

    fireEvent.click(tab(/^IP Trust/i))
    fireEvent.keyDown(tablist, { key: 'ArrowRight' })

    expect(tab(/^Pending/i)).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByTestId('pending-loading')).toBeInTheDocument()
  })

  it('ArrowLeft wraps from Pending to IP Trust', () => {
    renderPage()
    const tablist = screen.getByRole('tablist')

    fireEvent.keyDown(tablist, { key: 'ArrowLeft' })

    expect(tab(/^IP Trust/i)).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByText(/IP Trust is not yet available/i)).toBeInTheDocument()
  })

  it('ArrowLeft steps backwards one tab at a time', () => {
    renderPage()
    const tablist = screen.getByRole('tablist')

    fireEvent.click(tab(/^IP Trust/i))
    fireEvent.keyDown(tablist, { key: 'ArrowLeft' })

    expect(tab(/^Tokens/i)).toHaveAttribute('aria-selected', 'true')
  })

  it('moves DOM focus to the newly activated tab', () => {
    renderPage()
    const tablist = screen.getByRole('tablist')

    fireEvent.keyDown(tablist, { key: 'ArrowRight' })
    expect(document.activeElement).toBe(tab(/^Tokens/i))

    fireEvent.keyDown(tablist, { key: 'ArrowLeft' })
    expect(document.activeElement).toBe(tab(/^Pending/i))
  })

  it('focuses the clicked tab', () => {
    renderPage()

    fireEvent.click(tab(/^IP Trust/i))

    expect(document.activeElement).toBe(tab(/^IP Trust/i))
  })

  it('prevents default scrolling behaviour on the arrow keys it handles', () => {
    renderPage()
    const tablist = screen.getByRole('tablist')

    const right = createEvent.keyDown(tablist, { key: 'ArrowRight' })
    fireEvent(tablist, right)
    expect(right.defaultPrevented).toBe(true)

    const left = createEvent.keyDown(tablist, { key: 'ArrowLeft' })
    fireEvent(tablist, left)
    expect(left.defaultPrevented).toBe(true)
  })

  it('ignores keys it does not handle', () => {
    renderPage()
    const tablist = screen.getByRole('tablist')

    const down = createEvent.keyDown(tablist, { key: 'ArrowDown' })
    fireEvent(tablist, down)

    expect(down.defaultPrevented).toBe(false)
    expect(tab(/^Pending/i)).toHaveAttribute('aria-selected', 'true')

    fireEvent.keyDown(tablist, { key: 'Enter' })
    expect(tab(/^Pending/i)).toHaveAttribute('aria-selected', 'true')
  })
})

// ── Tab specification ─────────────────────────────────────────────────────────

describe('TABS', () => {
  it('declares Pending and Tokens with real panels; IP Trust as soon', () => {
    expect(TABS.map((t) => t.key)).toEqual(['pending', 'tokens', 'ip-trust'])
    expect(TABS[0]?.soon).toBe(false)
    expect(TABS[0]?.Panel).toBeDefined()
    expect(TABS[1]?.soon).toBe(false)
    expect(TABS[1]?.Panel).toBeDefined()
    expect(TABS[2]?.soon).toBe(true)
    expect(TABS[2]?.Panel).toBeUndefined()
  })
})
