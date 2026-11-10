// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Tests for BlastRadiusCard (Story #3610).
 *
 * Fixture pin shapes are drawn from handlers_cases.go pinResponse/pinRefResponse
 * (Issue #3605). API response shape mirrors the Go Neighborhood struct serialised
 * by writeEntityJSON (pkg/entitygraph/types/edge.go); EID fields are the
 * canonical string form (EID.MarshalJSON).
 *
 * fetch is stubbed globally per test; stubs are restored in afterEach via the
 * test setup file's cleanup hook.
 */
import { describe, expect, it, vi, afterEach } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import BlastRadiusCard from './BlastRadiusCard.tsx'
import type { Pin } from '../evidenceTypes.ts'

// ── Fixture data ──────────────────────────────────────────────────────────────

// Populated neighborhood — root with two dependents.
const MOCK_NEIGHBORHOOD_POPULATED = {
  Root: 'eid:root/msp-a/client-1/sql-primary',
  Nodes: [
    { EID: 'eid:root/msp-a/client-1/sql-primary', Kind: 'host' },
    { EID: 'eid:root/msp-a/client-1/api-02', Kind: 'host' },
    { EID: 'eid:root/msp-a/client-1/reports-01', Kind: 'host' },
  ],
  Edges: [
    {
      Type: 'serves',
      From: 'eid:root/msp-a/client-1/api-02',
      To: 'eid:root/msp-a/client-1/sql-primary',
    },
    {
      Type: 'runs-on',
      From: 'eid:root/msp-a/client-1/reports-01',
      To: 'eid:root/msp-a/client-1/sql-primary',
    },
  ],
}

// Single-node neighborhood — root only, no edges.
const MOCK_NEIGHBORHOOD_SINGLE = {
  Root: 'eid:root/msp-a/client-1/sql-primary',
  Nodes: [{ EID: 'eid:root/msp-a/client-1/sql-primary', Kind: 'host' }],
  Edges: [],
}

// Pins drawn from handlers_cases.go pinResponse/pinRefResponse shapes (Issue #3605).
const pinEID: Pin = {
  id: 'pin-eid-001',
  case_id: 'case-001',
  ref: { kind: 'eid', eid: 'eid:root/msp-a/client-1/sql-primary' },
  annotation: 'Primary entity under investigation',
  author: 'operator',
  pinned_at: '2026-07-03T08:52:00Z',
}

// Pin type that carries no EID — should not trigger the card.
const pinEdgeIdentity: Pin = {
  id: 'pin-edge-001',
  case_id: 'case-001',
  ref: { kind: 'edge-identity', edge_identity: 'edge:sql-primary->api-02' },
  annotation: 'Dependent at ×4 latency',
  author: 'cfgms',
  pinned_at: '2026-07-03T08:50:00Z',
}

// ── Fetch helper ──────────────────────────────────────────────────────────────

function makeFetch(body: unknown) {
  return vi.fn(() =>
    Promise.resolve({
      ok: true,
      status: 200,
      headers: new Headers(),
      json: () => Promise.resolve(body),
    }),
  )
}

afterEach(() => {
  vi.unstubAllGlobals()
})

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('BlastRadiusCard', () => {
  it('renders nothing when no eid-bearing pin is present', () => {
    render(<BlastRadiusCard pins={[pinEdgeIdentity]} />)
    expect(document.querySelector('.blast-radius-card')).toBeNull()
  })

  // ── REQUIRED TEST (AC4) ───────────────────────────────────────────────────
  it('[REQUIRED] single-node state renders "No dependents found" when neighborhood API returns zero edges', async () => {
    vi.stubGlobal('fetch', makeFetch(MOCK_NEIGHBORHOOD_SINGLE))
    render(<BlastRadiusCard pins={[pinEID]} />)

    await waitFor(() => {
      expect(screen.getByText('No dependents found')).toBeInTheDocument()
    })

    // Card is visible (not null, not an error) — shows root node + no-deps message.
    expect(document.querySelector('.blast-radius-card')).toBeInTheDocument()
    // The SVG dependency graph is present.
    expect(document.querySelector('.blast-radius-card__svg')).toBeInTheDocument()
    // No error state rendered.
    expect(document.querySelector('.blast-radius-card__error')).toBeNull()
  })

  it('shows a loading state while fetching', () => {
    // fetch never resolves — component stays in loading phase.
    vi.stubGlobal('fetch', vi.fn(() => new Promise(() => {})))
    render(<BlastRadiusCard pins={[pinEID]} />)
    expect(screen.getByLabelText('Loading neighborhood')).toBeInTheDocument()
  })

  it('shows an error state when the neighborhood endpoint fails', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve({
          ok: false,
          status: 500,
          headers: new Headers(),
          json: () => Promise.reject(new Error('server error')),
        }),
      ),
    )
    render(<BlastRadiusCard pins={[pinEID]} />)
    await waitFor(() => {
      expect(document.querySelector('.blast-radius-card__error')).toBeInTheDocument()
    })
  })

  it('renders the dependency graph with populated nodes and edges', async () => {
    vi.stubGlobal('fetch', makeFetch(MOCK_NEIGHBORHOOD_POPULATED))
    render(<BlastRadiusCard pins={[pinEID]} />)

    await waitFor(() => {
      expect(screen.getByRole('img', { name: /dependency graph/i })).toBeInTheDocument()
    })

    // Dependents count appears in the header.
    expect(screen.getByText(/2 dependents/i)).toBeInTheDocument()
    // No "no dependents found" message when edges exist.
    expect(screen.queryByText('No dependents found')).toBeNull()
  })

  it('renders nodes in neutral (non-health-colored) state only', async () => {
    vi.stubGlobal('fetch', makeFetch(MOCK_NEIGHBORHOOD_POPULATED))
    render(<BlastRadiusCard pins={[pinEID]} />)

    await waitFor(() => {
      expect(document.querySelector('.blast-radius-card__node')).toBeInTheDocument()
    })

    // Neutral node classes are present.
    expect(document.querySelector('.blast-radius-card__node-root')).toBeInTheDocument()
    expect(document.querySelector('.blast-radius-card__node')).toBeInTheDocument()
    // No health-state classes.
    expect(document.querySelector('.blast-radius-card__node--ok')).toBeNull()
    expect(document.querySelector('.blast-radius-card__node--crit')).toBeNull()
    expect(document.querySelector('.blast-radius-card__node--warn')).toBeNull()
  })

  it('uses subject-time-range pin subject as the EID when no eid pin is present', async () => {
    const pinSubjectTimeRange: Pin = {
      id: 'pin-stime-001',
      case_id: 'case-001',
      ref: {
        kind: 'subject-time-range',
        subject: 'eid:root/msp-a/client-1/sql-primary',
        time_range_start: '2026-07-03T08:41:00Z',
        time_range_end: '2026-07-03T09:30:00Z',
      },
      annotation: 'Incident window',
      author: 'cfgms',
      pinned_at: '2026-07-03T09:00:00Z',
    }
    const fetchStub = makeFetch(MOCK_NEIGHBORHOOD_POPULATED)
    vi.stubGlobal('fetch', fetchStub)
    render(<BlastRadiusCard pins={[pinSubjectTimeRange]} />)

    await waitFor(() => {
      expect(screen.getByRole('img', { name: /dependency graph/i })).toBeInTheDocument()
    })

    // Confirm the subject EID was used in the neighborhood request path.
    const requested = (fetchStub.mock.calls as unknown[][]).map((c) => String(c[0]))
    expect(requested[0]).toContain(
      `/api/v1/entities/${encodeURIComponent('eid:root/msp-a/client-1/sql-primary')}/neighborhood`,
    )
  })

  it('percent-encodes the EID when building the neighborhood request path', async () => {
    const pinWithTraversal: Pin = {
      id: 'pin-eid-002',
      case_id: 'case-001',
      ref: { kind: 'eid', eid: 'eid:root/../../api/v1/tenants?x=#' },
      annotation: 'hostile local id',
      author: 'operator',
      pinned_at: '2026-07-03T08:52:00Z',
    }
    const fetchStub = makeFetch(MOCK_NEIGHBORHOOD_SINGLE)
    vi.stubGlobal('fetch', fetchStub)
    render(<BlastRadiusCard pins={[pinWithTraversal]} />)

    await waitFor(() => {
      expect(fetchStub).toHaveBeenCalled()
    })

    const requested = (fetchStub.mock.calls as unknown[][]).map((c) => String(c[0]))
    expect(requested[0]).toContain(
      `/api/v1/entities/${encodeURIComponent('eid:root/../../api/v1/tenants?x=#')}/neighborhood`,
    )
    // No raw traversal metacharacters escape the encoded segment.
    expect(requested[0]).not.toContain('/../')
  })

  it('handles null Nodes and Edges gracefully without throwing', async () => {
    vi.stubGlobal(
      'fetch',
      makeFetch({ Root: 'eid:root/msp-a/client-1/sql-primary', Nodes: null, Edges: null }),
    )
    render(<BlastRadiusCard pins={[pinEID]} />)

    await waitFor(() => {
      expect(document.querySelector('.blast-radius-card')).toBeInTheDocument()
    })
    // Normalised to empty arrays → single-node state.
    expect(screen.getByText('No dependents found')).toBeInTheDocument()
  })

  it('renders a singular "dependent" label when exactly one dependent exists', async () => {
    const singleDepNeighborhood = {
      Root: 'eid:root/msp-a/client-1/sql-primary',
      Nodes: [
        { EID: 'eid:root/msp-a/client-1/sql-primary', Kind: 'host' },
        { EID: 'eid:root/msp-a/client-1/api-02', Kind: 'host' },
      ],
      Edges: [
        {
          Type: 'serves',
          From: 'eid:root/msp-a/client-1/api-02',
          To: 'eid:root/msp-a/client-1/sql-primary',
        },
      ],
    }
    vi.stubGlobal('fetch', makeFetch(singleDepNeighborhood))
    render(<BlastRadiusCard pins={[pinEID]} />)

    await waitFor(() => {
      expect(screen.getByText('1 dependent')).toBeInTheDocument()
    })
  })

  // ── Assert relationship (Story #5464) ─────────────────────────────────────
  const ROOT = 'eid:root/msp-a/client-1/sql-primary'
  const NEW_DEP = 'eid:root/msp-a/client-1/cache-03'

  const MOCK_NEIGHBORHOOD_AFTER = {
    ...MOCK_NEIGHBORHOOD_POPULATED,
    Nodes: [...MOCK_NEIGHBORHOOD_POPULATED.Nodes, { EID: NEW_DEP, Kind: 'host' }],
    Edges: [...MOCK_NEIGHBORHOOD_POPULATED.Edges, { Type: 'depends-on', From: NEW_DEP, To: ROOT }],
  }

  // Routes the card's neighborhood GET, the drawer's entity search and the
  // assertion POST. The first neighborhood answer is the "before" graph; any
  // later one is the "after" graph.
  function makeAssertFetch(edges: () => Response) {
    let neighborhoodCalls = 0
    const stub = vi.fn((input: RequestInfo | URL) => {
      const url = String(input)
      if (url.includes('/neighborhood')) {
        neighborhoodCalls += 1
        const body = neighborhoodCalls === 1 ? MOCK_NEIGHBORHOOD_POPULATED : MOCK_NEIGHBORHOOD_AFTER
        return Promise.resolve(new Response(JSON.stringify(body), { status: 200 }))
      }
      if (url.startsWith('/api/v1/entities/edges')) return Promise.resolve(edges())
      if (url.startsWith('/api/v1/entities?')) {
        return Promise.resolve(
          new Response(
            JSON.stringify({ Entities: [{ Entity: { EID: NEW_DEP, Kind: 'host' } }], NextToken: '' }),
            { status: 200 },
          ),
        )
      }
      return Promise.reject(new Error(`unexpected request ${url}`))
    })
    vi.stubGlobal('fetch', stub)
    return stub
  }

  const urlsOf = (stub: ReturnType<typeof makeAssertFetch>) =>
    (stub.mock.calls as unknown as string[][]).map((c) => String(c[0]))
  const neighborhoodCount = (stub: ReturnType<typeof makeAssertFetch>) =>
    urlsOf(stub).filter((u) => u.includes('/neighborhood')).length

  async function openAndFill() {
    await screen.findByRole('img', { name: /dependency graph/i })
    fireEvent.click(screen.getByRole('button', { name: /Assert relationship/ }))
    const dialog = screen.getByRole('dialog', { name: 'Assert relationship' })
    fireEvent.change(within(dialog).getByLabelText(/^Relationship/), { target: { value: 'depends-on' } })
    fireEvent.change(within(dialog).getByLabelText('Search entities'), { target: { value: 'cache' } })
    fireEvent.click(await within(dialog).findByRole('option', { name: /cache-03/ }))
    return dialog
  }

  it('opens the assert drawer from the card header with the pinned entity as From', async () => {
    makeAssertFetch(() => new Response(null, { status: 201 }))
    render(<BlastRadiusCard pins={[pinEID]} />)
    await screen.findByRole('img', { name: /dependency graph/i })

    expect(screen.queryByRole('dialog')).toBeNull()
    const header = document.querySelector('.blast-radius-card__header') as HTMLElement
    fireEvent.click(within(header).getByRole('button', { name: /Assert relationship/ }))

    const dialog = screen.getByRole('dialog', { name: 'Assert relationship' })
    expect(within(dialog).getByText(ROOT)).toBeInTheDocument()
    // The pinned entity's kind comes from the neighborhood node.
    expect(within(dialog).getByText(ROOT).parentElement).toHaveTextContent('host')

    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }))
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  it('does not offer the action when the card renders nothing', () => {
    render(<BlastRadiusCard pins={[pinEdgeIdentity]} />)
    expect(screen.queryByRole('button', { name: /Assert relationship/ })).toBeNull()
  })

  // ── REQUIRED TEST ─────────────────────────────────────────────────────────
  it('BlastRadiusCard re-fetches the neighborhood after a successful assert', async () => {
    // 201 with no body: the hook must not parse a response body.
    const stub = makeAssertFetch(() => new Response(null, { status: 201 }))
    render(<BlastRadiusCard pins={[pinEID]} />)
    const dialog = await openAndFill()
    expect(screen.getByText('2 dependents')).toBeInTheDocument()
    expect(neighborhoodCount(stub)).toBe(1)

    fireEvent.click(within(dialog).getByRole('button', { name: 'Assert relationship' }))

    // The same /neighborhood path is fetched again — no second fetch path.
    await waitFor(() => expect(neighborhoodCount(stub)).toBe(2))
    const neighborhoodUrls = urlsOf(stub).filter((u) => u.includes('/neighborhood'))
    expect(neighborhoodUrls[1]).toBe(neighborhoodUrls[0])
    // The graph shows the new dependent while the drawer is still open.
    expect(await screen.findByText('3 dependents')).toBeInTheDocument()
    expect(screen.getByText('Relationship recorded')).toBeInTheDocument()

    const post = (stub.mock.calls as unknown as Array<[string, RequestInit]>).find(
      ([u]) => u === '/api/v1/entities/edges',
    )!
    expect(JSON.parse(post[1].body as string)).toEqual({
      edge_type: 'depends-on',
      from_eid: ROOT,
      to_eid: NEW_DEP,
      attributes: {},
    })

    fireEvent.click(within(dialog).getByRole('button', { name: 'Done' }))
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  it('does not re-fetch the neighborhood when the assertion is refused', async () => {
    const stub = makeAssertFetch(() => new Response('not found\n', { status: 404 }))
    render(<BlastRadiusCard pins={[pinEID]} />)
    const dialog = await openAndFill()
    fireEvent.click(within(dialog).getByRole('button', { name: 'Assert relationship' }))

    expect(await within(dialog).findByRole('alert')).toHaveTextContent('404')
    expect(neighborhoodCount(stub)).toBe(1)
    expect(screen.getByText('2 dependents')).toBeInTheDocument()
  })
})
