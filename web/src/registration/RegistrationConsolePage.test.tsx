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
import { cleanup, createEvent, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
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
  it('renders a tablist with Pending, Tokens, IP Trust, and Credential Requests', () => {
    renderPage()

    expect(screen.getByRole('tablist', { name: /registration sections/i })).toBeInTheDocument()
    expect(tab(/^Pending/i)).toBeInTheDocument()
    expect(tab(/^Tokens/i)).toBeInTheDocument()
    expect(tab(/^IP Trust/i)).toBeInTheDocument()
    expect(tab(/^Credential Requests/i)).toBeInTheDocument()
    expect(screen.getAllByRole('tab')).toHaveLength(TABS.length)
  })

  it('opens on Pending by default', () => {
    renderPage()

    expect(tab(/^Pending/i)).toHaveAttribute('aria-selected', 'true')
    expect(tab(/^Tokens/i)).toHaveAttribute('aria-selected', 'false')
    expect(tab(/^IP Trust/i)).toHaveAttribute('aria-selected', 'false')
    expect(tab(/^Credential Requests/i)).toHaveAttribute('aria-selected', 'false')
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

  it('mounts the real IPTrustTab on the IP Trust tab, not a soon placeholder', async () => {
    renderPage()

    fireEvent.click(tab(/^IP Trust/i))

    expect(tab(/^IP Trust/i)).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByTestId('iptrust-loading')).toBeInTheDocument()
    expect(screen.queryByText(/IP Trust is not yet available/i)).toBeNull()
  })

  it('mounts the real CredentialRequestsTab on the Credential Requests tab, not a soon placeholder', async () => {
    renderPage()

    fireEvent.click(tab(/^Credential Requests/i))

    expect(tab(/^Credential Requests/i)).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByTestId('credential-requests-loading')).toBeInTheDocument()
    expect(screen.queryByText(/Credential Requests is not yet available/i)).toBeNull()
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

    fireEvent.keyDown(tablist, { key: 'ArrowRight' })
    expect(tab(/^Credential Requests/i)).toHaveAttribute('aria-selected', 'true')
  })

  it('ArrowRight wraps from the last tab back to Pending', () => {
    renderPage()
    const tablist = screen.getByRole('tablist')

    fireEvent.click(tab(/^Credential Requests/i))
    fireEvent.keyDown(tablist, { key: 'ArrowRight' })

    expect(tab(/^Pending/i)).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByTestId('pending-loading')).toBeInTheDocument()
  })

  it('ArrowLeft wraps from Pending to the last tab (Credential Requests)', async () => {
    renderPage()
    const tablist = screen.getByRole('tablist')

    fireEvent.keyDown(tablist, { key: 'ArrowLeft' })

    expect(tab(/^Credential Requests/i)).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByTestId('credential-requests-loading')).toBeInTheDocument()
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

// ── Pending-count badge (Issue #3786) ───────────────────────────────────────────

// Two independent consumers hit this endpoint (PendingQueueTab's own fetch and
// the parent's badge fetch), each reading the response body once — a shared
// Response instance would throw "body stream already read" on the second
// consumer, so a fresh Response is built per call.
function mockPendingEndpoint(body: object, status = 200) {
  fetchMock.mockImplementation((input) => {
    const url = typeof input === 'string' ? input : (input as Request).url
    if (url.includes('/api/v1/registration/pending')) {
      return Promise.resolve(
        new Response(JSON.stringify(body), {
          status,
          headers: { 'Content-Type': 'application/json' },
        }),
      )
    }
    // Every other endpoint (tokens, resolve, ...) never settles — irrelevant
    // to badge assertions and keeps those panels in a stable loading state.
    return new Promise(() => {})
  })
}

describe('RegistrationConsolePage — pending count badge', () => {
  it('shows a non-zero pending count on the Pending tab without opening it', async () => {
    mockPendingEndpoint([
      { pending_id: 'p1', steward_id: 's1', source_ip: '10.0.0.1', registered_at: '2026-07-25T10:00:00Z' },
      { pending_id: 'p2', steward_id: 's2', source_ip: '10.0.0.2', registered_at: '2026-07-25T10:05:00Z' },
    ])

    renderPage()
    fireEvent.click(tab(/^Tokens/i))

    const badge = await within(tab(/^Pending/i)).findByTestId('pending-count-badge')
    expect(badge).toHaveTextContent('2')
    // Visible while a different tab is active — no navigation into Pending needed.
    expect(tab(/^Tokens/i)).toHaveAttribute('aria-selected', 'true')
  })

  it('shows no badge when there are zero pending registrations', async () => {
    mockPendingEndpoint([])

    renderPage()

    // Default active tab is Pending, so its own panel settles against the
    // same mocked endpoint — waiting for its empty state proves the parent's
    // independent fetch has also had a chance to settle.
    await screen.findByTestId('pending-empty')
    expect(screen.queryByTestId('pending-count-badge')).toBeNull()
  })

  it('shows no badge when the caller lacks registration:list-pending (403)', async () => {
    mockPendingEndpoint({ error: 'forbidden' }, 403)

    renderPage()

    await waitFor(() => {
      expect(screen.getByRole('alert')).toBeInTheDocument()
    })
    expect(screen.queryByTestId('pending-count-badge')).toBeNull()
  })
})

// ── Tab specification ─────────────────────────────────────────────────────────

describe('TABS', () => {
  it('declares Pending, Tokens, IP Trust, and Credential Requests with real panels', () => {
    expect(TABS.map((t) => t.key)).toEqual(['pending', 'tokens', 'ip-trust', 'credential-requests'])
    for (const spec of TABS) {
      expect(spec.soon).toBe(false)
      expect(spec.Panel).toBeDefined()
    }
  })
})
