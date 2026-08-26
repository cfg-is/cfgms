// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Evidence Canvas tests (Story #3607).
 *
 * Fixture pin shapes are drawn from Story 4 (Issue #3605), specifically the
 * pinResponse/pinRefResponse JSON structures documented in
 * features/controller/api/handlers_cases.go — the authoritative contract for
 * GET /api/v1/cases/{id}'s embedded pin array. Using the same literal shapes
 * here means a future change to Story 4's JSON contract will surface as a
 * cross-reference prompt in this file.
 *
 * No live backend is used — all pins are in-memory fixtures.
 */
import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import EvidenceCanvas from './EvidenceCanvas.tsx'
import type { Pin } from './evidenceTypes.ts'

// ── Fixture pins ─────────────────────────────────────────────────────────────
// Shapes drawn from handlers_cases.go pinResponse / pinRefResponse (Issue #3605).

const fixturePinEID: Pin = {
  id: 'pin-eid-001',
  case_id: 'case-001',
  ref: { kind: 'eid', eid: 'eid:root/msp-a/client-1/sql-primary' },
  annotation: 'Primary subject of investigation',
  author: 'operator',
  pinned_at: '2026-07-03T08:52:00Z',
}

const fixturePinDriftRecord: Pin = {
  id: 'pin-drift-001',
  case_id: 'case-001',
  ref: { kind: 'drift-record', drift_record: 'drift:r2291:sql-primary:memory' },
  annotation: 'max_server_memory reverted to 2048 MB',
  author: 'cfgms',
  pinned_at: '2026-07-03T08:44:00Z',
}

const fixturePinEdgeIdentity: Pin = {
  id: 'pin-edge-001',
  case_id: 'case-001',
  ref: { kind: 'edge-identity', edge_identity: 'edge:sql-primary->api-02' },
  annotation: 'Dependent at ×4 latency',
  author: 'cfgms',
  pinned_at: '2026-07-03T08:50:00Z',
}

const fixturePinObservationVersion: Pin = {
  id: 'pin-obs-001',
  case_id: 'case-001',
  ref: { kind: 'observation-version', observation_version: 'obs:sql-primary:r2291:memory' },
  annotation: 'Observation at push r2291',
  author: 'cfgms',
  pinned_at: '2026-07-03T08:41:00Z',
}

const fixturePinSubjectTimeRange: Pin = {
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

// All five PinRef kinds present — exercises every branch of the PinRef discriminant.
const ALL_FIXTURE_PINS: Pin[] = [
  fixturePinEID,
  fixturePinDriftRecord,
  fixturePinEdgeIdentity,
  fixturePinObservationVersion,
  fixturePinSubjectTimeRange,
]

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('EvidenceCanvas', () => {
  it('renders canvas-level empty state for zero pins (sparse case is valid, not an error)', () => {
    // Fixture provenance: pins=[] matches the "empty array for a sparse case,
    // not an error or omitted field" guarantee in GET /api/v1/cases/{id} (Issue #3605).
    render(<EvidenceCanvas pins={[]} />)
    expect(screen.getByText(/No pins yet/i)).toBeInTheDocument()
  })

  it('auto-discovers FixtureCard from cards/ via glob and renders it with the full pin list', () => {
    // Proves the import.meta.glob self-registration seam: FixtureCard.tsx was dropped
    // into cards/ without any edit to EvidenceCanvas.tsx, and it appears here.
    render(<EvidenceCanvas pins={ALL_FIXTURE_PINS} />)
    const card = screen.getByTestId('evidence-fixture-card')
    expect(card).toBeInTheDocument()
    expect(card).toHaveAttribute('data-pin-count', String(ALL_FIXTURE_PINS.length))
  })

  it('does not render the empty state when at least one pin is present', () => {
    render(<EvidenceCanvas pins={[fixturePinEID]} />)
    expect(screen.queryByText(/No pins yet/i)).not.toBeInTheDocument()
  })

  it('passes the full pin array to each discovered card unchanged', () => {
    render(<EvidenceCanvas pins={ALL_FIXTURE_PINS} />)
    const card = screen.getByTestId('evidence-fixture-card')
    // data-pin-count reflects what the card received — canvas must not filter.
    expect(card).toHaveAttribute('data-pin-count', String(ALL_FIXTURE_PINS.length))
  })
})
