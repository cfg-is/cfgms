// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * IPTrustTab test suite (Story #2936, #2971): data states (loading, empty, error,
 * populated), badge rendering, revoked entry display, retry flow, add/revoke
 * affordance and step-up wiring, and security checks (text-node-only rendering).
 *
 * The component fetches GET /api/v1/registration/ip-trust which uses the
 * {data: [...]} envelope shape.
 *
 * Add calls POST /api/v1/registration/ip-trust and revoke calls
 * DELETE /api/v1/registration/ip-trust/{tenant_id}/{cidr}.  Both require
 * AssuranceStrong; the step-up challenge is handled transparently by apiFetch
 * → AuthProvider → StepUpModal (#2967). Tests verify:
 *  - The form and revoke button render.
 *  - A direct 204 (already-elevated session) succeeds and refreshes the list.
 *  - A 401 + CFGMS-StepUp causes the StepUpModal to appear (step-up gate).
 *  - A non-OK response surfaces an inline error.
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
    tenant_id: 'test-tenant',
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

function make204() {
  return new Response(null, { status: 204 })
}

function makeStepUpChallenge() {
  return new Response(JSON.stringify({}), {
    status: 401,
    headers: {
      'WWW-Authenticate': 'CFGMS-StepUp realm="cfgms", required="strong"',
      'Content-Type': 'application/json',
    },
  })
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

// ── Add affordance ────────────────────────────────────────────────────────────

describe('IPTrustTab — add form', () => {
  it('renders the add form with a CIDR input and Add button', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderTab()
    expect(screen.getByTestId('iptrust-add-form')).toBeInTheDocument()
    expect(screen.getByTestId('iptrust-cidr-input')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^add$/i })).toBeInTheDocument()
  })

  it('shows the add form even in the empty-list state', async () => {
    fetchMock.mockResolvedValue(makeListResponse([]))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('iptrust-empty')).toBeInTheDocument())
    expect(screen.getByTestId('iptrust-add-form')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^add$/i })).toBeInTheDocument()
  })

  it('shows an inline error when Add is submitted with an empty CIDR', async () => {
    fetchMock.mockResolvedValue(makeListResponse([]))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('iptrust-empty')).toBeInTheDocument())

    fireEvent.click(screen.getByRole('button', { name: /^add$/i }))

    expect(screen.getByTestId('iptrust-add-error')).toBeInTheDocument()
    expect(screen.getByTestId('iptrust-add-error')).toHaveTextContent(/cidr is required/i)
    // No fetch call for the mutation.
    expect(fetchMock).toHaveBeenCalledTimes(1) // only the initial list fetch
  })

  it('[REQUIRED] Add calls POST and refreshes list on 204', async () => {
    // First call: initial list (empty). Second: POST add. Third: refreshed list.
    fetchMock
      .mockResolvedValueOnce(makeListResponse([]))
      .mockResolvedValueOnce(make204())
      .mockResolvedValueOnce(makeListResponse([makeEntry({ cidr: '10.0.0.0/8' })]))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('iptrust-empty')).toBeInTheDocument())

    fireEvent.change(screen.getByTestId('iptrust-cidr-input'), { target: { value: '10.0.0.0/8' } })
    fireEvent.click(screen.getByRole('button', { name: /^add$/i }))

    await waitFor(() => expect(screen.getByTestId('iptrust-table')).toBeInTheDocument())

    const postCall = fetchMock.mock.calls.find((c) => {
      const init = c[1] as RequestInit | undefined
      return init?.method === 'POST'
    })
    expect(postCall).toBeDefined()
    expect(postCall?.[0]).toBe('/api/v1/registration/ip-trust')
    const body = JSON.parse((postCall?.[1] as RequestInit)?.body as string) as Record<string, unknown>
    expect(body.cidr).toBe('10.0.0.0/8')
    expect(screen.getByText('10.0.0.0/8')).toBeInTheDocument()
  })

  it('includes pre_seeded: true in the POST body when checkbox is checked', async () => {
    fetchMock
      .mockResolvedValueOnce(makeListResponse([]))
      .mockResolvedValueOnce(make204())
      .mockResolvedValueOnce(makeListResponse([]))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('iptrust-empty')).toBeInTheDocument())

    fireEvent.change(screen.getByTestId('iptrust-cidr-input'), { target: { value: '10.0.0.0/8' } })
    fireEvent.click(screen.getByTestId('iptrust-preseeded-checkbox'))
    fireEvent.click(screen.getByRole('button', { name: /^add$/i }))

    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(3))
    const postCall = fetchMock.mock.calls.find((c) => {
      const init = c[1] as RequestInit | undefined
      return init?.method === 'POST'
    })
    const body = JSON.parse((postCall?.[1] as RequestInit)?.body as string) as Record<string, unknown>
    expect(body.pre_seeded).toBe(true)
  })

  it('shows an inline error on a non-OK add response', async () => {
    fetchMock
      .mockResolvedValueOnce(makeListResponse([]))
      .mockResolvedValueOnce(new Response(null, { status: 500 }))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('iptrust-empty')).toBeInTheDocument())

    fireEvent.change(screen.getByTestId('iptrust-cidr-input'), { target: { value: '10.0.0.0/8' } })
    fireEvent.click(screen.getByRole('button', { name: /^add$/i }))

    await waitFor(() => expect(screen.getByTestId('iptrust-add-error')).toBeInTheDocument())
    expect(screen.getByTestId('iptrust-add-error')).toHaveTextContent(/add failed.*500/i)
  })

  it('[REQUIRED] Add triggers step-up modal on 401 + CFGMS-StepUp', async () => {
    // List succeeds; add returns a step-up challenge.
    fetchMock
      .mockResolvedValueOnce(makeListResponse([]))
      .mockResolvedValueOnce(makeStepUpChallenge())
    renderTab()
    await waitFor(() => expect(screen.getByTestId('iptrust-empty')).toBeInTheDocument())

    fireEvent.change(screen.getByTestId('iptrust-cidr-input'), { target: { value: '10.0.0.0/8' } })
    fireEvent.click(screen.getByRole('button', { name: /^add$/i }))

    // AuthProvider should show the step-up modal.
    await waitFor(() => expect(screen.getByTestId('step-up-overlay')).toBeInTheDocument())
  })
})

// ── Revoke affordance ─────────────────────────────────────────────────────────

describe('IPTrustTab — revoke', () => {
  it('[REQUIRED] renders a Revoke button for each active (non-revoked) entry', async () => {
    fetchMock.mockResolvedValue(
      makeListResponse([makeEntry({ cidr: '10.0.0.0/8', revoked: false })]),
    )
    renderTab()
    await waitFor(() => expect(screen.getByTestId('iptrust-table')).toBeInTheDocument())
    expect(screen.getByTestId('revoke-btn-10.0.0.0/8')).toBeInTheDocument()
  })

  it('renders no Revoke button for already-revoked entries', async () => {
    fetchMock.mockResolvedValue(
      makeListResponse([makeEntry({ cidr: '10.0.0.0/8', revoked: true })]),
    )
    renderTab()
    await waitFor(() => expect(screen.getByTestId('iptrust-table')).toBeInTheDocument())
    expect(screen.queryByTestId('revoke-btn-10.0.0.0/8')).not.toBeInTheDocument()
  })

  it('[REQUIRED] Revoke calls DELETE and refreshes list on 204', async () => {
    // Initial list: one active entry. DELETE: 204. Refreshed list: entry revoked.
    fetchMock
      .mockResolvedValueOnce(
        makeListResponse([makeEntry({ cidr: '10.0.0.0/8', tenant_id: 'test-tenant' })]),
      )
      .mockResolvedValueOnce(make204())
      .mockResolvedValueOnce(
        makeListResponse([makeEntry({ cidr: '10.0.0.0/8', tenant_id: 'test-tenant', revoked: true })]),
      )
    renderTab()
    await waitFor(() => expect(screen.getByTestId('revoke-btn-10.0.0.0/8')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('revoke-btn-10.0.0.0/8'))

    await waitFor(() => expect(screen.getByTestId('badge-revoked')).toBeInTheDocument())

    const deleteCall = fetchMock.mock.calls.find((c) => {
      const init = c[1] as RequestInit | undefined
      return init?.method === 'DELETE'
    })
    expect(deleteCall).toBeDefined()
    // CIDR '10.0.0.0/8' must be encoded so the slash survives as a URL segment.
    expect(deleteCall?.[0]).toBe(
      '/api/v1/registration/ip-trust/test-tenant/10.0.0.0%2F8',
    )
  })

  it('shows a per-row error on a non-OK revoke response', async () => {
    fetchMock
      .mockResolvedValueOnce(
        makeListResponse([makeEntry({ cidr: '10.0.0.0/8' })]),
      )
      .mockResolvedValueOnce(new Response(null, { status: 403 }))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('revoke-btn-10.0.0.0/8')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('revoke-btn-10.0.0.0/8'))

    await waitFor(() =>
      expect(screen.getByTestId('revoke-error-10.0.0.0/8')).toBeInTheDocument(),
    )
    expect(screen.getByTestId('revoke-error-10.0.0.0/8')).toHaveTextContent(
      /revoke failed.*403/i,
    )
  })

  it('[REQUIRED] Revoke triggers step-up modal on 401 + CFGMS-StepUp', async () => {
    fetchMock
      .mockResolvedValueOnce(
        makeListResponse([makeEntry({ cidr: '10.0.0.0/8' })]),
      )
      .mockResolvedValueOnce(makeStepUpChallenge())
    renderTab()
    await waitFor(() => expect(screen.getByTestId('revoke-btn-10.0.0.0/8')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('revoke-btn-10.0.0.0/8'))

    await waitFor(() => expect(screen.getByTestId('step-up-overlay')).toBeInTheDocument())
  })
})

// ── parseIPTrustList unit tests ───────────────────────────────────────────────

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

  it('coerces missing tenant_id to empty string', () => {
    const result = parseIPTrustList([{ cidr: '10.0.0.0/8' }])
    expect(result[0]?.tenantId).toBe('')
  })

  it('maps wire fields to camelCase interface fields', () => {
    const result = parseIPTrustList([
      {
        cidr: '192.168.1.0/24',
        tenant_id: 'acme',
        pre_seeded: true,
        trusted_since: '2026-01-01T00:00:00Z',
        last_activity: '2026-07-01T00:00:00Z',
        revoked: false,
      },
    ])
    expect(result).toHaveLength(1)
    expect(result[0]).toEqual({
      cidr: '192.168.1.0/24',
      tenantId: 'acme',
      preSeeded: true,
      trustedSince: '2026-01-01T00:00:00Z',
      lastActivity: '2026-07-01T00:00:00Z',
      revoked: false,
    })
  })
})
