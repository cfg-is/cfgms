// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Tests for DriftDiffCard (Story #3609).
 *
 * Fixture pin shapes are drawn from handlers_cases.go pinResponse/pinRefResponse
 * (Issue #3605) — the authoritative contract for GET /api/v1/cases/{id}'s embedded
 * pin array. API response shapes mirror the Go structs serialised by writeEntityJSON:
 *   DriftState      → features/controller/api/handlers_entities.go / pkg/entitygraph/interfaces/provider.go
 *   DesiredStateView→ pkg/entitygraph/types/entity.go
 * Both structs lack json tags, so field names are PascalCase in the JSON response.
 *
 * fetch is stubbed globally per test; stubs are restored in afterEach via the
 * test setup file's cleanup hook.
 */
import { describe, expect, it, vi, afterEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import DriftDiffCard from './DriftDiffCard.tsx'
import type { Pin } from '../evidenceTypes.ts'

// ── Fixture data ──────────────────────────────────────────────────────────────

// Drift response: two fields — one mismatched (bad), one matching (good).
// Field names are PascalCase: Go struct serialised without json tags.
const MOCK_DRIFT_DRIFTED = {
  EID: 'eid:root/msp-a/client-1/sql-primary',
  DetectedAt: '2026-07-03T08:44:00Z',
  Fields: [
    { Attribute: 'max_server_memory', Desired: 12288, Actual: 2048, Matching: false },
    { Attribute: 'max_worker_threads', Desired: 640, Actual: 640, Matching: true },
  ],
  ConfigRevision: 'r2291',
  LifecycleStatus: 'detected',
}

// Drift response: all fields match (no drift).
const MOCK_DRIFT_MATCHED = {
  EID: 'eid:root/msp-a/client-1/sql-primary',
  DetectedAt: '2026-07-03T08:44:00Z',
  Fields: [
    { Attribute: 'max_server_memory', Desired: 12288, Actual: 12288, Matching: true },
    { Attribute: 'max_worker_threads', Desired: 640, Actual: 640, Matching: true },
  ],
  ConfigRevision: 'r2291',
  LifecycleStatus: 'resolved',
}

// DesiredStateView: PascalCase field names, State is a plain map.
const MOCK_DESIRED_STATE = {
  EID: 'eid:root/msp-a/client-1/sql-primary',
  State: { max_server_memory: 12288, max_worker_threads: 640 },
  ConfigRevision: 'r2291',
  ObservedAt: '2026-07-03T08:44:00Z',
}

// Pins drawn from handlers_cases.go pinResponse/pinRefResponse shapes (Issue #3605).
const pinDriftRecord: Pin = {
  id: 'pin-drift-001',
  case_id: 'case-001',
  ref: { kind: 'drift-record', drift_record: 'drift:r2291:sql-primary:memory' },
  annotation: 'Memory section of r2291 failed to apply',
  author: 'cfgms',
  pinned_at: '2026-07-03T08:44:00Z',
}

const pinEID: Pin = {
  id: 'pin-eid-001',
  case_id: 'case-001',
  ref: { kind: 'eid', eid: 'eid:root/msp-a/client-1/sql-primary' },
  annotation: 'Primary entity under investigation',
  author: 'operator',
  pinned_at: '2026-07-03T08:52:00Z',
}

const pinEdgeIdentity: Pin = {
  id: 'pin-edge-001',
  case_id: 'case-001',
  ref: { kind: 'edge-identity', edge_identity: 'edge:sql-primary->api-02' },
  annotation: 'Dependent at ×4 latency',
  author: 'cfgms',
  pinned_at: '2026-07-03T08:50:00Z',
}

// ── Fetch helpers ─────────────────────────────────────────────────────────────

function makeFetch(responses: Record<string, unknown | null>) {
  return vi.fn((url: string) => {
    const path = typeof url === 'string' ? url : ''
    // Use Object.entries to avoid the object-injection lint sink.
    const match = Object.entries(responses).find(([key]) => path.includes(key))
    const body = match !== undefined ? match[1] : null
    if (body === null) {
      return Promise.resolve({
        ok: false,
        status: 404,
        headers: new Headers(),
        json: () => Promise.reject(new Error('404')),
      })
    }
    return Promise.resolve({
      ok: true,
      status: 200,
      headers: new Headers(),
      json: () => Promise.resolve(body),
    })
  })
}

afterEach(() => {
  vi.unstubAllGlobals()
})

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('DriftDiffCard', () => {
  it('renders nothing when no drift-record or eid pin is present', () => {
    render(<DriftDiffCard pins={[pinEdgeIdentity]} />)
    expect(document.querySelector('.drift-diff-card')).toBeNull()
  })

  it('renders nothing when only an eid pin is present and drift endpoint returns 404', async () => {
    vi.stubGlobal(
      'fetch',
      makeFetch({ '/drift': null, '/desired-state': MOCK_DESIRED_STATE }),
    )
    render(<DriftDiffCard pins={[pinEID]} />)
    await waitFor(() => {
      expect(document.querySelector('.drift-diff-card')).toBeNull()
    })
  })

  // ── REQUIRED TEST (AC4) ───────────────────────────────────────────────────
  it('[REQUIRED] mismatched field renders with bad state token; matching field with good state token', async () => {
    vi.stubGlobal(
      'fetch',
      makeFetch({
        '/drift': MOCK_DRIFT_DRIFTED,
        '/desired-state': MOCK_DESIRED_STATE,
      }),
    )
    render(<DriftDiffCard pins={[pinDriftRecord, pinEID]} />)

    // Wait for async data to arrive and field rows to render.
    await waitFor(() => {
      expect(screen.getAllByText('max_server_memory').length).toBeGreaterThan(0)
    })

    // Locate both actual-side field rows (the column that carries bad/good state).
    // Each field renders twice (desired col + actual col); the actual column rows
    // carry the bad/good class, so query by class .bad / .good directly.
    const badRows = document.querySelectorAll('.drift-kv.bad')
    const goodRows = document.querySelectorAll('.drift-kv.good')

    // Exactly one mismatched field (max_server_memory) and one matching field
    // (max_worker_threads) from MOCK_DRIFT_DRIFTED.
    expect(badRows).toHaveLength(1)
    expect(goodRows).toHaveLength(1)

    // The bad row carries the mismatched attribute name.
    expect(badRows[0]).toHaveTextContent('max_server_memory')
    // The good row carries the matching attribute name.
    expect(goodRows[0]).toHaveTextContent('max_worker_threads')
  })

  it('matched (non-drifted) state renders without the drift note banner', async () => {
    vi.stubGlobal(
      'fetch',
      makeFetch({
        '/drift': MOCK_DRIFT_MATCHED,
        '/desired-state': MOCK_DESIRED_STATE,
      }),
    )
    render(<DriftDiffCard pins={[pinDriftRecord, pinEID]} />)

    await waitFor(() => {
      expect(screen.getAllByText('max_server_memory').length).toBeGreaterThan(0)
    })

    // No drift note banner when all fields match.
    expect(document.querySelector('.drift-diff-card__note')).toBeNull()
    // No bad-state rows.
    expect(document.querySelectorAll('.drift-kv.bad')).toHaveLength(0)
    // All rows are good.
    expect(document.querySelectorAll('.drift-kv.good')).toHaveLength(2)
  })

  it('raw-view toggle reveals the underlying field-level raw values', async () => {
    vi.stubGlobal(
      'fetch',
      makeFetch({
        '/drift': MOCK_DRIFT_DRIFTED,
        '/desired-state': MOCK_DESIRED_STATE,
      }),
    )
    render(<DriftDiffCard pins={[pinDriftRecord, pinEID]} />)

    await waitFor(() => {
      expect(screen.getAllByText('max_server_memory').length).toBeGreaterThan(0)
    })

    // Raw view is hidden before toggle.
    const rawSection = document.querySelector('.drift-diff-card__raw')
    expect(rawSection).not.toHaveClass('drift-diff-card__raw--show')

    // Click the toggle.
    fireEvent.click(screen.getByRole('button', { name: /raw/i }))

    // Raw view is now visible.
    expect(rawSection).toHaveClass('drift-diff-card__raw--show')

    // Raw text contains field values.
    const pre = rawSection?.querySelector('pre')
    expect(pre?.textContent).toContain('max_server_memory')
    expect(pre?.textContent).toContain('12288')
    expect(pre?.textContent).toContain('2048')

    // Click again to close.
    fireEvent.click(screen.getByRole('button', { name: /hide/i }))
    expect(rawSection).not.toHaveClass('drift-diff-card__raw--show')
  })

  it('shows a loading state while fetching', () => {
    // fetch never resolves — component stays in loading phase.
    vi.stubGlobal('fetch', vi.fn(() => new Promise(() => {})))
    render(<DriftDiffCard pins={[pinDriftRecord, pinEID]} />)
    expect(screen.getByLabelText('Loading drift data')).toBeInTheDocument()
  })

  it('shows an error state when the drift endpoint fails', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn((url: string) => {
        if (url.includes('/drift')) {
          return Promise.resolve({
            ok: false,
            status: 500,
            headers: new Headers(),
            json: () => Promise.reject(new Error('server error')),
          })
        }
        return Promise.resolve({
          ok: false,
          status: 404,
          headers: new Headers(),
          json: () => Promise.reject(new Error('404')),
        })
      }),
    )
    render(<DriftDiffCard pins={[pinDriftRecord, pinEID]} />)
    await waitFor(() => {
      expect(document.querySelector('.drift-diff-card__error')).toBeInTheDocument()
    })
  })

  it('renders the card with drift-record pin and shows entity name in header', async () => {
    vi.stubGlobal(
      'fetch',
      makeFetch({
        '/drift': MOCK_DRIFT_DRIFTED,
        '/desired-state': MOCK_DESIRED_STATE,
      }),
    )
    render(<DriftDiffCard pins={[pinDriftRecord, pinEID]} />)

    await waitFor(() => {
      expect(screen.getByRole('region', { name: /desired vs actual/i })).toBeInTheDocument()
    })

    // Entity name (last EID segment) appears in the header.
    expect(screen.getByText('sql-primary')).toBeInTheDocument()
    // Config revision appears in the desired column label.
    expect(screen.getByText(/intent r2291/i)).toBeInTheDocument()
  })

  it('renders the card with only an eid pin when drift endpoint returns data', async () => {
    vi.stubGlobal(
      'fetch',
      makeFetch({
        '/drift': MOCK_DRIFT_DRIFTED,
        '/desired-state': MOCK_DESIRED_STATE,
      }),
    )
    render(<DriftDiffCard pins={[pinEID]} />)

    await waitFor(() => {
      expect(screen.getByRole('region', { name: /desired vs actual/i })).toBeInTheDocument()
    })
    expect(document.querySelectorAll('.drift-kv.bad')).toHaveLength(1)
  })

  it('uses subject-time-range pin subject as the EID when no eid pin is present', async () => {
    // Exercises the subject-time-range branch of extractEID (line 67-68).
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
    vi.stubGlobal(
      'fetch',
      makeFetch({
        '/drift': MOCK_DRIFT_DRIFTED,
        '/desired-state': MOCK_DESIRED_STATE,
      }),
    )
    render(<DriftDiffCard pins={[pinDriftRecord, pinSubjectTimeRange]} />)

    await waitFor(() => {
      expect(screen.getByRole('region', { name: /desired vs actual/i })).toBeInTheDocument()
    })
    // The subject EID was used: entity name from the EID's last segment.
    expect(screen.getByText('sql-primary')).toBeInTheDocument()
    // Drift fields resolved correctly via the subject EID.
    expect(document.querySelectorAll('.drift-kv.bad')).toHaveLength(1)
  })

  it('renders an empty card without throwing when Fields is null', async () => {
    // A Go nil slice serialises as `"Fields": null` — parseDriftFields returns
    // (nil, nil) for stored fields JSON of "", "[]" or "null". The card must not
    // throw: the SPA has no ErrorBoundary, so a TypeError blanks the cockpit.
    vi.stubGlobal(
      'fetch',
      makeFetch({
        '/drift': { ...MOCK_DRIFT_MATCHED, Fields: null },
        '/desired-state': MOCK_DESIRED_STATE,
      }),
    )
    render(<DriftDiffCard pins={[pinDriftRecord, pinEID]} />)

    await waitFor(() => {
      expect(screen.getByRole('region', { name: /desired vs actual/i })).toBeInTheDocument()
    })

    // Card renders with no field rows and no drift banner.
    expect(document.querySelectorAll('.drift-kv')).toHaveLength(0)
    expect(document.querySelector('.drift-diff-card__note')).toBeNull()
    // Raw view still builds from the fields-less record.
    fireEvent.click(screen.getByRole('button', { name: /raw/i }))
    expect(document.querySelector('.drift-diff-card__raw-pre')?.textContent).toContain('r2291')
  })

  it('drops malformed Fields entries instead of throwing', async () => {
    vi.stubGlobal(
      'fetch',
      makeFetch({
        '/drift': {
          ...MOCK_DRIFT_DRIFTED,
          Fields: [null, 'not-an-object', { Attribute: 'max_server_memory', Matching: false }],
        },
        '/desired-state': MOCK_DESIRED_STATE,
      }),
    )
    render(<DriftDiffCard pins={[pinDriftRecord, pinEID]} />)

    await waitFor(() => {
      expect(screen.getAllByText('max_server_memory').length).toBeGreaterThan(0)
    })
    // Only the one well-formed entry survives, on the mismatched side.
    expect(document.querySelectorAll('.drift-kv.bad')).toHaveLength(1)
    expect(document.querySelectorAll('.drift-kv.good')).toHaveLength(0)
  })

  it('percent-encodes the EID when building request paths', async () => {
    // A steward-supplied localID may contain '/', '..', '?' or '#': ParseEID
    // validates only the authority segment. Unencoded, such a value would send
    // this credentialed same-origin GET to an attacker-chosen API path.
    const pinTraversalEID: Pin = {
      id: 'pin-eid-002',
      case_id: 'case-001',
      ref: { kind: 'eid', eid: 'eid:root/../../api/v1/tenants?x=#' },
      annotation: 'hostile local id',
      author: 'operator',
      pinned_at: '2026-07-03T08:52:00Z',
    }
    const fetchStub = makeFetch({
      '/drift': MOCK_DRIFT_DRIFTED,
      '/desired-state': MOCK_DESIRED_STATE,
    })
    vi.stubGlobal('fetch', fetchStub)
    render(<DriftDiffCard pins={[pinTraversalEID]} />)

    await waitFor(() => {
      expect(fetchStub).toHaveBeenCalled()
    })

    const requested = fetchStub.mock.calls.map((c) => String(c[0]))
    expect(requested).toContain(
      `/api/v1/entities/${encodeURIComponent('eid:root/../../api/v1/tenants?x=#')}/drift`,
    )
    expect(requested).toContain(
      `/api/v1/entities/${encodeURIComponent('eid:root/../../api/v1/tenants?x=#')}/desired-state`,
    )
    // No raw traversal, query or fragment metacharacter escapes the segment.
    for (const url of requested) {
      expect(url.split('/api/v1/entities/')[1]).not.toMatch(/[?#]/)
      expect(url).not.toContain('/../')
    }
  })

  it('reports the encoded path in the error message when the drift endpoint fails', async () => {
    const pinTraversalEID: Pin = {
      id: 'pin-eid-003',
      case_id: 'case-001',
      ref: { kind: 'eid', eid: 'eid:root/../evil?x=#frag' },
      annotation: 'hostile local id',
      author: 'operator',
      pinned_at: '2026-07-03T08:52:00Z',
    }
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
    render(<DriftDiffCard pins={[pinDriftRecord, pinTraversalEID]} />)

    await waitFor(() => {
      expect(document.querySelector('.drift-diff-card__error')).toBeInTheDocument()
    })
    const message = document.querySelector('.drift-diff-card__error')?.textContent ?? ''
    expect(message).toContain(encodeURIComponent('eid:root/../evil?x=#frag'))
    expect(message).not.toContain('/../')
  })

  it('shows drift annotation text in the note banner when drift-record pin has an annotation', async () => {
    // Exercises the driftAnnotation render path (drift-diff-card__note-text span).
    vi.stubGlobal(
      'fetch',
      makeFetch({
        '/drift': MOCK_DRIFT_DRIFTED,
        '/desired-state': MOCK_DESIRED_STATE,
      }),
    )
    render(<DriftDiffCard pins={[pinDriftRecord, pinEID]} />)

    await waitFor(() => {
      expect(document.querySelector('.drift-diff-card__note')).toBeInTheDocument()
    })

    // pinDriftRecord.annotation appears in the drift note banner.
    expect(document.querySelector('.drift-diff-card__note-text')).toHaveTextContent(
      'Memory section of r2291 failed to apply',
    )
  })
})
