// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * CockpitView tests (Story #3608 + Story #3613).
 *
 * Story #3608 verifies:
 *  - Loading state renders while fetch is in-flight.
 *  - Error state (case fetch 404) renders distinctly from loading and ready.
 *  - Ready state renders the case bar, ticket quick reference, and tabbed rail.
 *  - EvidenceCanvas is mounted with the case's pins (no local placeholder).
 *  - Chat tab renders as a static placeholder pane (no backend call for it).
 *
 * Story #3613 adds:
 *  - [REQUIRED TEST] Render CockpitView, drive a mocked WebSocket to emit a
 *    WatchEvent, and assert a mounted card's rendered output changes in response.
 *    This test proves useCaseWatch IS mounted in CockpitView, not just tested
 *    in isolation — an unmounted hook with passing unit tests is the same
 *    masking failure the Tech Lead caught in Story 1/4's storage wiring.
 *
 * All fetches and WebSocket connections are mocked — no live server required.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router'
import CockpitView from './CockpitView.tsx'
import type { Case } from './caseTypes.ts'

// FakeWebSocket — replaces global WebSocket for watch-endpoint tests.
class FakeWebSocket {
  static instances: FakeWebSocket[] = []

  readyState: number = WebSocket.CONNECTING
  onopen: ((e: Event) => void) | null = null
  onmessage: ((e: MessageEvent) => void) | null = null
  onclose: ((e: CloseEvent) => void) | null = null
  onerror: ((e: Event) => void) | null = null

  url: string

  constructor(url: string) {
    // Explicit field + assignment: TS parameter properties are not erasable
    // syntax, which this project's tsconfig disallows.
    this.url = url
    FakeWebSocket.instances.push(this)
  }

  close() {
    this.readyState = WebSocket.CLOSED
    this.onclose?.(new CloseEvent('close'))
  }

  simulateOpen() {
    this.readyState = WebSocket.OPEN
    this.onopen?.(new Event('open'))
  }

  simulateMessage(data: string) {
    this.onmessage?.(new MessageEvent('message', { data }))
  }

  send() {}
}

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  FakeWebSocket.instances = []
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('WebSocket', FakeWebSocket)
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
    // The case's default pin is an `eid` pin, which the drift-diff evidence
    // card (Story #3609) also fetches against — so the total fetch count
    // across the ready cockpit is no longer just the case GET. That's the
    // evidence card's traffic, not the Chat tab's, so this test scopes to
    // the Chat tab itself: switching to it must add zero further fetches.
    fetchMock.mockResolvedValue(jsonResponse(200, makeCase()))
    renderCockpit()
    await waitFor(() =>
      expect(screen.getByRole('tab', { name: /chat/i })).toBeInTheDocument(),
    )
    // Let any evidence-card fetches from the ready state settle before
    // taking the baseline count.
    await waitFor(() => expect(screen.queryByRole('status')).toBeNull())
    const callsBeforeChatTab = fetchMock.mock.calls.length

    fireEvent.click(screen.getByRole('tab', { name: /chat/i }))
    expect(screen.getByText('Chat is not yet available.')).toBeInTheDocument()
    expect(fetchMock).toHaveBeenCalledTimes(callsBeforeChatTab)
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

// ── useCaseWatch mounting (Story #3613) ────────────────────────────────────

// [REQUIRED TEST] Mount test: render CockpitView itself (not useCaseWatch in
// isolation), drive a mocked WebSocket to emit a WatchEvent, and assert a
// mounted card's rendered output changes in response.
//
// This test would FAIL if useCaseWatch were not called inside CockpitView —
// a hook that exists but is never mounted never creates a WebSocket, so
// FakeWebSocket.instances stays empty and the act() calls below would throw.
// That is exactly the masking-failure this test exists to catch.
describe('CockpitView + useCaseWatch mount integration', () => {
  it('[REQUIRED] WatchEvent emitted from mocked WebSocket reaches FixtureCard', async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, makeCase()))
    renderCockpit()

    // Wait for the case to load so CockpitView is in the ready state.
    await waitFor(() => expect(screen.queryByRole('status')).toBeNull())

    // useCaseWatch is mounted in CockpitView — exactly one WebSocket was created.
    expect(FakeWebSocket.instances).toHaveLength(1)
    const socket = FakeWebSocket.instances[0]!

    // The FixtureCard starts with no watch event.
    const card = screen.getByTestId('evidence-fixture-card')
    expect(card).toHaveAttribute('data-last-event-kind', '')

    // Simulate the WebSocket lifecycle: open → message.
    act(() => { socket.simulateOpen() })
    act(() => {
      socket.simulateMessage(
        JSON.stringify({
          type: 'event',
          subject: 'cfgms:agent1/host/sql-primary',
          event_kind: 'drift-updated',
          version: 5,
          at: '2026-08-01T10:00:00Z',
        }),
      )
    })

    // FixtureCard's rendered output must reflect the event — proves the
    // WatchEventContext chain (CockpitView provides → FixtureCard consumes).
    await waitFor(() =>
      expect(screen.getByTestId('evidence-fixture-card')).toHaveAttribute(
        'data-last-event-kind',
        'drift-updated',
      ),
    )
  })

  it('[REQUIRED] WebSocket URL includes the case ID from the route param', async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, makeCase({ id: 'case-xyz' })))
    renderCockpit('case-xyz')
    await waitFor(() => expect(FakeWebSocket.instances.length).toBeGreaterThan(0))
    expect(FakeWebSocket.instances[0]!.url).toContain('case-xyz')
  })
})
