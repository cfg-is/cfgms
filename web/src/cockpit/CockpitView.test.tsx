// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * CockpitView tests (Story #3608).
 *
 * Verifies:
 *  - Loading state renders while fetch is in-flight.
 *  - Error state (case fetch 404) renders distinctly from loading and ready.
 *  - Ready state renders the case bar, ticket quick reference, and tabbed rail.
 *  - EvidenceCanvas is mounted with the case's pins (no local placeholder).
 *  - Chat tab renders as a static placeholder pane (no backend call for it).
 *
 * All fetches are mocked — no live server required.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router'
import CockpitView from './CockpitView.tsx'
import type { Case } from './caseTypes.ts'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
  Object.defineProperty(document, 'cookie', {
    get: () => 'cfgms_csrf=test-csrf-token',
    configurable: true,
  })
})

afterEach(() => {
  vi.unstubAllGlobals()
  cleanup()
})

function makeCase(overrides: Partial<Case> = {}): Case {
  return {
    id: 'case-001',
    tenant_id: 'root/msp-a/client-1',
    status: 'open',
    ticket: {
      title: { value: 'SQL app slow since 9am', source: 'email', filled: true },
      client: { value: 'client-1', source: 'caller-id', filled: true },
      contact: { value: '', source: '', filled: false },
      priority: { value: 'High', source: 'email', filled: true },
      category: { value: '', source: '', filled: false },
    },
    pins: [
      {
        id: 'pin-001',
        case_id: 'case-001',
        ref: { kind: 'eid', eid: 'eid:root/msp-a/client-1/sql-primary' },
        annotation: 'Primary subject',
        author: 'operator',
        pinned_at: '2026-07-03T08:52:00Z',
      },
    ],
    content: [
      {
        id: 'content-001',
        case_id: 'case-001',
        kind: 'finding',
        body: 'Config push r2291 caused drift on sql-primary',
        author: 'cfgms',
        created_at: '2026-07-03T08:52:00Z',
      },
    ],
    created_at: '2026-07-03T08:52:00Z',
    updated_at: '2026-07-03T08:52:00Z',
    ...overrides,
  }
}

function jsonResponse(status: number, data: unknown = null): Response {
  if (status === 404) {
    return new Response('not found', { status: 404 })
  }
  return new Response(
    JSON.stringify({ data, timestamp: '2026-07-03T09:00:00Z' }),
    { status, headers: { 'Content-Type': 'application/json' } },
  )
}

function renderCockpit(caseId = 'case-001') {
  return render(
    <MemoryRouter initialEntries={[`/cases/${caseId}`]}>
      <Routes>
        <Route path="/cases/:id" element={<CockpitView />} />
      </Routes>
    </MemoryRouter>,
  )
}

describe('CockpitView', () => {
  it('renders loading state while fetch is in-flight', () => {
    // Never resolves — keeps the component in the loading state.
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderCockpit()
    expect(screen.getByRole('status')).toBeInTheDocument()
  })

  it('renders error state for a 404 response, distinct from loading and ready', async () => {
    fetchMock.mockResolvedValue(jsonResponse(404))
    renderCockpit()
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument())
    expect(screen.queryByRole('status')).toBeNull()
    // Case bar should not be rendered — it has .cbar class.
    expect(document.querySelector('.cbar')).toBeNull()
  })

  it('renders the case bar, ticket quick reference, and rail in the ready state', async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, makeCase()))
    renderCockpit()
    // Case bar: tenant_id rendered as path.
    await waitFor(() =>
      expect(screen.getByText(/root.*msp-a.*client-1/i)).toBeInTheDocument(),
    )
    // Ticket quick reference: filled field value.
    expect(screen.getByText('SQL app slow since 9am')).toBeInTheDocument()
    // Tabbed rail: Investigation and Chat tabs.
    expect(screen.getByRole('tab', { name: /investigation/i })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /chat/i })).toBeInTheDocument()
  })

  it('mounts EvidenceCanvas with the case pins — canvas is in non-empty (pin-forwarded) state', async () => {
    // EvidenceCanvas renders class "evidence-canvas" in BOTH branches, so the
    // presence of that class alone proves nothing. Two assertions below do
    // discriminate: the empty branch adds .evidence-canvas--empty (absent here),
    // and the cards mounted by the canvas receive the pin array itself — the
    // fixture card echoes its length as data-pin-count. A CockpitView that
    // passed [] instead of caseData.pins would fail both.
    const twoPinCase = makeCase({
      pins: [
        ...makeCase().pins,
        {
          id: 'pin-002',
          case_id: 'case-001',
          ref: { kind: 'drift-record', drift_record: 'drift-2291' },
          annotation: 'Drift record',
          author: 'cfgms',
          pinned_at: '2026-07-03T08:53:00Z',
        },
      ],
    })
    fetchMock.mockResolvedValue(jsonResponse(200, twoPinCase))
    renderCockpit()
    await waitFor(() => expect(screen.queryByRole('status')).toBeNull())

    const canvas = document.querySelector('.evidence-canvas')
    expect(canvas).not.toBeNull()
    // Not the empty-pins branch.
    expect(document.querySelector('.evidence-canvas--empty')).toBeNull()
    // The canvas's cards received the case's own pins, in full.
    const card = screen.getByTestId('evidence-fixture-card')
    expect(canvas!.contains(card)).toBe(true)
    expect(card).toHaveAttribute('data-pin-count', String(twoPinCase.pins.length))
  })

  it('renders the empty EvidenceCanvas state when the case has no pins', async () => {
    // Counterpart to the test above: proves the assertions there actually
    // discriminate, by showing the empty branch is reachable through CockpitView.
    fetchMock.mockResolvedValue(jsonResponse(200, makeCase({ pins: [] })))
    renderCockpit()
    await waitFor(() => expect(screen.queryByRole('status')).toBeNull())
    expect(document.querySelector('.evidence-canvas--empty')).not.toBeNull()
  })

  it('Chat tab renders as a static placeholder with no backend call for it', async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, makeCase()))
    renderCockpit()
    await waitFor(() =>
      expect(screen.getByRole('tab', { name: /chat/i })).toBeInTheDocument(),
    )
    // Only one fetch call was made (GET /api/v1/cases/case-001) — no chat backend.
    expect(fetchMock).toHaveBeenCalledTimes(1)
    // The Chat tab is present.
    expect(screen.getByRole('tab', { name: /chat/i })).toBeInTheDocument()
  })

  it('percent-encodes the :id route parameter into the GET path', async () => {
    // useParams() URL-decodes the route segment, so the raw value can contain
    // "/" and "..". Both the GET here and the PUT in TicketQuickReference must
    // encode it before interpolation.
    fetchMock.mockResolvedValue(jsonResponse(404))
    renderCockpit(encodeURIComponent('case-001/../../admin'))
    await waitFor(() => expect(fetchMock).toHaveBeenCalled())
    const [url] = fetchMock.mock.calls[0]!
    expect(String(url)).toBe(
      `/api/v1/cases/${encodeURIComponent('case-001/../../admin')}`,
    )
  })

  it('renders error state for a 500 response, distinct from loading', async () => {
    fetchMock.mockResolvedValue(jsonResponse(500))
    renderCockpit()
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument())
    expect(screen.queryByRole('status')).toBeNull()
  })
})
