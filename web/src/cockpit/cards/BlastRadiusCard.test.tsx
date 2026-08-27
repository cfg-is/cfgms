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
import { render, screen, waitFor } from '@testing-library/react'
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
    const requested = fetchStub.mock.calls.map((c) => String(c[0]))
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

    const requested = fetchStub.mock.calls.map((c) => String(c[0]))
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
})
