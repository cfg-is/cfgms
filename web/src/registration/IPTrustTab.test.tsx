// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * IPTrustTab test suite (Story #2936): data states (loading, empty, error,
 * populated), badge rendering, revoked entry display, retry flow, and
 * security checks (text-node-only rendering, no add/revoke controls).
 *
 * The component fetches GET /api/v1/registration/ip-trust which uses the
 * {data: [...]} envelope shape.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { AuthProvider } from '../auth/AuthContext.tsx'
import IPTrustTab, { parseIPTrustList } from './IPTrustTab.tsx'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})

afterEach(() => {
  vi.unstubAllGlobals()
  cleanup()
})

function makeEntry(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    cidr: '10.2.4.0/24',
    pre_seeded: false,
    trusted_since: '2026-01-04T00:00:00Z',
    last_activity: '2026-07-30T00:00:00Z',
    revoked: false,
    ...overrides,
  }
}

function makeListResponse(entries: object[], status = 200) {
  return new Response(
    JSON.stringify({ data: entries }),
    { status, headers: { 'Content-Type': 'application/json' } },
  )
}

function renderTab() {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <IPTrustTab />
      </AuthProvider>
    </MemoryRouter>,
  )
}

describe('IPTrustTab — data states', () => {
  it('shows loading rows while fetching', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderTab()
    expect(screen.getByTestId('iptrust-loading')).toBeInTheDocument()
  })

  it('[REQUIRED] empty trust list renders a clear empty state, not a blank panel', async () => {
    fetchMock.mockResolvedValue(makeListResponse([]))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('iptrust-empty')).toBeInTheDocument())
    expect(screen.getByRole('heading', { name: /no trusted cidr ranges/i })).toBeInTheDocument()
    expect(screen.getByText(/no ip ranges have been added/i)).toBeInTheDocument()
  })

  it('renders a table when entries are present', async () => {
    fetchMock.mockResolvedValue(makeListResponse([makeEntry(), makeEntry({ cidr: '192.0.2.0/24' })]))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('iptrust-table')).toBeInTheDocument())
    expect(screen.getAllByTestId('iptrust-row')).toHaveLength(2)
  })

  it('renders the CIDR value as a text node', async () => {
    fetchMock.mockResolvedValue(makeListResponse([makeEntry({ cidr: '10.0.0.0/8' })]))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('iptrust-table')).toBeInTheDocument())
    expect(screen.getByText('10.0.0.0/8')).toBeInTheDocument()
  })

  it('renders trusted_since and last_activity fields as text nodes', async () => {
    fetchMock.mockResolvedValue(
      makeListResponse([
        makeEntry({
          trusted_since: '2026-01-04T00:00:00Z',
          last_activity: '2026-07-30T12:00:00Z',
        }),
      ]),
    )
    renderTab()
    await waitFor(() => expect(screen.getByTestId('iptrust-table')).toBeInTheDocument())
    expect(screen.getByText('2026-01-04T00:00:00Z')).toBeInTheDocument()
    expect(screen.getByText('2026-07-30T12:00:00Z')).toBeInTheDocument()
  })
})

describe('IPTrustTab — source badge', () => {
  it('shows Pre-seeded badge when pre_seeded is true', async () => {
    fetchMock.mockResolvedValue(makeListResponse([makeEntry({ pre_seeded: true })]))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('iptrust-table')).toBeInTheDocument())
    expect(screen.getByTestId('badge-preseeded')).toBeInTheDocument()
    expect(screen.queryByTestId('badge-manual')).not.toBeInTheDocument()
  })

  it('shows Manual badge when pre_seeded is false', async () => {
    fetchMock.mockResolvedValue(makeListResponse([makeEntry({ pre_seeded: false })]))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('iptrust-table')).toBeInTheDocument())
    expect(screen.getByTestId('badge-manual')).toBeInTheDocument()
    expect(screen.queryByTestId('badge-preseeded')).not.toBeInTheDocument()
  })
})

describe('IPTrustTab — revoked entries', () => {
  it('shows Revoked badge when entry has revoked: true', async () => {
    fetchMock.mockResolvedValue(makeListResponse([makeEntry({ revoked: true })]))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('iptrust-table')).toBeInTheDocument())
    expect(screen.getByTestId('badge-revoked')).toBeInTheDocument()
  })

  it('shows no Revoked badge when entry has revoked: false', async () => {
    fetchMock.mockResolvedValue(makeListResponse([makeEntry({ revoked: false })]))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('iptrust-table')).toBeInTheDocument())
    expect(screen.queryByTestId('badge-revoked')).not.toBeInTheDocument()
  })
})

describe('IPTrustTab — error and retry', () => {
  it('shows an error notice on a non-OK response', async () => {
    fetchMock.mockResolvedValue(makeListResponse([], 500))
    renderTab()
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument())
    expect(screen.getByRole('alert')).toHaveTextContent('500')
  })

  it('shows connectivity copy for a network-level failure', async () => {
    fetchMock.mockRejectedValue(new Error('network down'))
    renderTab()
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument())
    expect(screen.getByText(/check your connection/i)).toBeInTheDocument()
  })

  it('shows server-error copy for a 5xx response', async () => {
    fetchMock.mockResolvedValue(makeListResponse([], 503))
    renderTab()
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument())
    expect(screen.queryByText(/check your connection/i)).toBeNull()
    expect(screen.getByText(/server.*error|returned an error/i)).toBeInTheDocument()
  })

  it('retries the fetch when Retry is clicked', async () => {
    fetchMock
      .mockResolvedValueOnce(makeListResponse([], 500))
      .mockResolvedValueOnce(makeListResponse([]))
    renderTab()
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: /retry/i }))
    await waitFor(() => expect(screen.getByTestId('iptrust-empty')).toBeInTheDocument())
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })
})

describe('IPTrustTab — security (A9.1)', () => {
  it('renders CIDR as a text node, not markup', async () => {
    const maliciousCidr = '<script>alert(1)</script>'
    fetchMock.mockResolvedValue(makeListResponse([makeEntry({ cidr: maliciousCidr })]))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('iptrust-table')).toBeInTheDocument())
    expect(screen.queryByRole('button', { name: /script/i })).not.toBeInTheDocument()
    expect(screen.getByText(maliciousCidr)).toBeInTheDocument()
  })
})

describe('IPTrustTab — no add/revoke affordance', () => {
  it('renders no add button in any state', async () => {
    fetchMock.mockResolvedValue(makeListResponse([makeEntry()]))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('iptrust-table')).toBeInTheDocument())
    expect(screen.queryByRole('button', { name: /add/i })).not.toBeInTheDocument()
  })

  it('renders no revoke button even for active entries', async () => {
    fetchMock.mockResolvedValue(makeListResponse([makeEntry({ revoked: false })]))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('iptrust-table')).toBeInTheDocument())
    expect(screen.queryByRole('button', { name: /revoke/i })).not.toBeInTheDocument()
  })

  it('renders no add or revoke button in the empty state', async () => {
    fetchMock.mockResolvedValue(makeListResponse([]))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('iptrust-empty')).toBeInTheDocument())
    expect(screen.queryByRole('button', { name: /add/i })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /revoke/i })).not.toBeInTheDocument()
  })
})

describe('parseIPTrustList', () => {
  it('throws on non-array input', () => {
    expect(() => parseIPTrustList(null)).toThrow()
    expect(() => parseIPTrustList({ cidr: '10.0.0.0/8' })).toThrow()
    expect(() => parseIPTrustList('string')).toThrow()
  })

  it('returns an empty array for an empty input array', () => {
    expect(parseIPTrustList([])).toEqual([])
  })

  it('skips entries without a cidr field', () => {
    expect(parseIPTrustList([{ pre_seeded: true }])).toHaveLength(0)
  })

  it('skips non-object items silently', () => {
    expect(parseIPTrustList([null, 42, 'bad'])).toHaveLength(0)
  })

  it('coerces missing boolean fields to false', () => {
    const result = parseIPTrustList([{ cidr: '10.0.0.0/8' }])
    expect(result[0]?.preSeeded).toBe(false)
    expect(result[0]?.revoked).toBe(false)
  })

  it('maps wire fields to camelCase interface fields', () => {
    const result = parseIPTrustList([
      {
        cidr: '192.168.1.0/24',
        pre_seeded: true,
        trusted_since: '2026-01-01T00:00:00Z',
        last_activity: '2026-07-01T00:00:00Z',
        revoked: false,
      },
    ])
    expect(result).toHaveLength(1)
    expect(result[0]).toEqual({
      cidr: '192.168.1.0/24',
      preSeeded: true,
      trustedSince: '2026-01-01T00:00:00Z',
      lastActivity: '2026-07-01T00:00:00Z',
      revoked: false,
    })
  })
})
