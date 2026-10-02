// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Tests for ChangeTimelineCard (Story #3611).
 *
 * Fixture pin shapes are drawn from handlers_cases.go pinResponse/pinRefResponse
 * (Issue #3605) — the authoritative contract for GET /api/v1/cases/{id}'s embedded
 * pin array. The /entities/timeline response shape mirrors TimelineEvent
 * (pkg/entitygraph/interfaces/provider.go), serialised by writeEntityJSON with no
 * json tags → PascalCase fields; Subject is an EID with a custom MarshalJSON that
 * encodes it as its canonical string form.
 *
 * fetch is stubbed globally per test; stubs are restored in afterEach.
 */
import { describe, expect, it, vi, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import ChangeTimelineCard from './ChangeTimelineCard.tsx'
import type { Pin } from '../evidenceTypes.ts'

// ── Fixture pins ──────────────────────────────────────────────────────────────

const pinEID: Pin = {
  id: 'pin-eid-001',
  case_id: 'case-001',
  ref: { kind: 'eid', eid: 'eid:root/msp-a/client-1/sql-primary' },
  annotation: 'Primary entity under investigation',
  author: 'operator',
  pinned_at: '2026-07-03T08:52:00Z',
}

const pinDriftRecord: Pin = {
  id: 'pin-drift-001',
  case_id: 'case-001',
  ref: { kind: 'drift-record', drift_record: 'drift:r2291:sql-primary:memory' },
  annotation: 'Memory section of r2291 failed to apply',
  author: 'cfgms',
  pinned_at: '2026-07-03T08:44:00Z',
}

// ── Fixture /entities/timeline response ──────────────────────────────────────
// Field names PascalCase: Go struct serialised without json tags.

const MOCK_GRAPH_EVENTS = [
  {
    Subject: 'eid:root/msp-a/client-1/sql-primary',
    OccurredAt: '2026-07-03T08:41:00Z',
    Kind: 'state-change',
    Detail: { revision: 'r2291', ring: 'broad' },
  },
  {
    Subject: 'eid:root/msp-a/client-1/sql-primary',
    OccurredAt: '2026-07-03T08:44:30Z',
    Kind: 'drift-detected',
    Detail: { section: 'memory' },
  },
]

function makeFetch(response: unknown | null, ok = true, status = 200) {
  return vi.fn<typeof fetch>().mockResolvedValue({
    ok,
    status,
    headers: new Headers(),
    json: () => (response === null ? Promise.reject(new Error('no body')) : Promise.resolve(response)),
  } as Response)
}

afterEach(() => {
  vi.unstubAllGlobals()
})

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('ChangeTimelineCard', () => {
  it('shows a loading state while fetching entity-graph events', () => {
    vi.stubGlobal('fetch', vi.fn(() => new Promise(() => {})))
    render(<ChangeTimelineCard pins={[pinEID]} caseCreatedAt="2026-07-03T08:30:00Z" />)
    expect(screen.getByLabelText('Loading timeline')).toBeInTheDocument()
  })

  it('shows an error state when the timeline endpoint fails', async () => {
    vi.stubGlobal('fetch', makeFetch(null, false, 500))
    render(<ChangeTimelineCard pins={[pinEID]} caseCreatedAt="2026-07-03T08:30:00Z" />)
    await waitFor(() => {
      expect(document.querySelector('.change-timeline-card__error')).toBeInTheDocument()
    })
  })

  it('renders a distinct empty state (not an error) when there are no events at all', () => {
    // No pins (no eids to query, no pin-added events) and no case-created
    // timestamp — nothing for the card to show.
    render(<ChangeTimelineCard pins={[]} />)
    expect(document.querySelector('.change-timeline-card--empty')).toBeInTheDocument()
    expect(screen.getByText(/no timeline events yet/i)).toBeInTheDocument()
    expect(document.querySelector('.change-timeline-card__error')).toBeNull()
  })

  it('does not fetch the timeline endpoint when no eid/subject-time-range pin is present', () => {
    const fetchStub = makeFetch([])
    vi.stubGlobal('fetch', fetchStub)
    render(<ChangeTimelineCard pins={[pinDriftRecord]} caseCreatedAt="2026-07-03T08:30:00Z" />)
    // Case events (case-created, pin-added) render synchronously without a fetch.
    expect(screen.getByText('Case created')).toBeInTheDocument()
    expect(fetchStub).not.toHaveBeenCalled()
  })

  // ── REQUIRED TEST ────────────────────────────────────────────────────────
  it('[REQUIRED] merges entity-graph events and case events into one chronologically ordered list', async () => {
    vi.stubGlobal('fetch', makeFetch(MOCK_GRAPH_EVENTS))
    render(
      <ChangeTimelineCard
        pins={[pinEID]}
        caseCreatedAt="2026-07-03T08:30:00Z"
      />,
    )

    await waitFor(() => {
      expect(document.querySelectorAll('.change-timeline-card__event')).toHaveLength(4)
    })

    const rows = Array.from(document.querySelectorAll('.change-timeline-card__event'))
    const titles = rows.map((r) => r.querySelector('b')?.textContent ?? '')

    // Expected chronological order (ascending):
    //   08:30 case-created  < 08:41 state-change  < 08:44:30 drift-detected  < 08:52 pin-added
    // A wrong implementation would either produce two separate lists (all
    // graph events, then all case events — grouped, not interleaved) or sort
    // incorrectly. This asserts the actual interleaved, ascending order.
    expect(titles).toEqual([
      'Case created',
      'State change on sql-primary',
      'Drift detected on sql-primary',
      'Pin added',
    ])
  })

  it('drift-detected events render with the critical variant', async () => {
    vi.stubGlobal('fetch', makeFetch(MOCK_GRAPH_EVENTS))
    render(<ChangeTimelineCard pins={[pinEID]} caseCreatedAt="2026-07-03T08:30:00Z" />)

    await waitFor(() => {
      expect(screen.getByText('Drift detected on sql-primary')).toBeInTheDocument()
    })

    const critRows = document.querySelectorAll('.change-timeline-card__event--crit')
    expect(critRows).toHaveLength(1)
    expect(critRows[0]).toHaveTextContent('Drift detected on sql-primary')
  })

  it('the most recent event (chronologically last) renders with the now variant', async () => {
    vi.stubGlobal('fetch', makeFetch(MOCK_GRAPH_EVENTS))
    render(<ChangeTimelineCard pins={[pinEID]} caseCreatedAt="2026-07-03T08:30:00Z" />)

    await waitFor(() => {
      expect(document.querySelectorAll('.change-timeline-card__event')).toHaveLength(4)
    })

    // pinEID (pinned_at 08:52) is the latest timestamp among case-created (08:30),
    // state-change (08:41), drift-detected (08:44:30) and pin-added (08:52).
    const nowRows = document.querySelectorAll('.change-timeline-card__event--now')
    expect(nowRows).toHaveLength(1)
    expect(nowRows[0]).toHaveTextContent('Pin added')
  })

  it('renders a case-created event using the caseCreatedAt prop', async () => {
    vi.stubGlobal('fetch', makeFetch([]))
    render(<ChangeTimelineCard pins={[]} caseCreatedAt="2026-07-03T08:30:00Z" />)
    await waitFor(() => {
      expect(screen.getByText('Case created')).toBeInTheDocument()
    })
  })

  it('renders one pin-added event per pin, using the pin annotation as detail', async () => {
    vi.stubGlobal('fetch', makeFetch([]))
    render(<ChangeTimelineCard pins={[pinEID, pinDriftRecord]} />)
    await waitFor(() => {
      expect(screen.getAllByText('Pin added')).toHaveLength(2)
    })
    expect(screen.getByText('Primary entity under investigation')).toBeInTheDocument()
    expect(screen.getByText('Memory section of r2291 failed to apply')).toBeInTheDocument()
  })

  it('does not render a case-created event when caseCreatedAt is not provided', async () => {
    vi.stubGlobal('fetch', makeFetch([]))
    render(<ChangeTimelineCard pins={[pinEID]} />)
    await waitFor(() => {
      expect(screen.getByText('Pin added')).toBeInTheDocument()
    })
    expect(screen.queryByText('Case created')).not.toBeInTheDocument()
  })

  it('queries the timeline endpoint with every distinct pinned-subject eid', async () => {
    const pinSubjectTimeRange: Pin = {
      id: 'pin-stime-001',
      case_id: 'case-001',
      ref: {
        kind: 'subject-time-range',
        subject: 'eid:root/msp-a/client-1/api-02',
        time_range_start: '2026-07-03T08:41:00Z',
        time_range_end: '2026-07-03T09:30:00Z',
      },
      annotation: 'Dependent host',
      author: 'cfgms',
      pinned_at: '2026-07-03T08:50:00Z',
    }
    const fetchStub = makeFetch([])
    vi.stubGlobal('fetch', fetchStub)
    render(<ChangeTimelineCard pins={[pinEID, pinSubjectTimeRange]} caseCreatedAt="2026-07-03T08:30:00Z" />)

    await waitFor(() => expect(fetchStub).toHaveBeenCalled())
    const requested = String(fetchStub.mock.calls[0]![0])
    const url = new URL(requested, 'http://localhost')
    expect(url.pathname).toBe('/api/v1/entities/timeline')
    expect(url.searchParams.getAll('eid')).toEqual([
      'eid:root/msp-a/client-1/sql-primary',
      'eid:root/msp-a/client-1/api-02',
    ])
  })

  it('drops malformed timeline event entries instead of throwing', async () => {
    vi.stubGlobal(
      'fetch',
      makeFetch([null, 'not-an-object', { Subject: 'eid:root/x', OccurredAt: '2026-07-03T08:41:00Z', Kind: 'state-change' }]),
    )
    render(<ChangeTimelineCard pins={[pinEID]} caseCreatedAt="2026-07-03T08:30:00Z" />)
    await waitFor(() => {
      expect(screen.getByText(/state change on x/i)).toBeInTheDocument()
    })
    // Only the one well-formed entry survives, plus the two case events.
    expect(document.querySelectorAll('.change-timeline-card__event')).toHaveLength(3)
  })

  it('renders without throwing when the timeline response is null (nil slice)', async () => {
    // Stub: response body is the JSON literal `null` — a Go nil slice.
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve({
          ok: true,
          status: 200,
          headers: new Headers(),
          json: () => Promise.resolve(null),
        }),
      ),
    )
    render(<ChangeTimelineCard pins={[pinEID]} caseCreatedAt="2026-07-03T08:30:00Z" />)
    await waitFor(() => {
      expect(screen.getByText('Pin added')).toBeInTheDocument()
    })
    expect(document.querySelector('.change-timeline-card__error')).toBeNull()
  })
})
