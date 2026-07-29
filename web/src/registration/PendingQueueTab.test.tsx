// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * PendingQueueTab test suite (Story #2934): list rendering, data states, and
 * deny-remove / deny-error flows.
 *
 * Required AC: deny removes the row on success; surfaces a row-level error
 * state on a failed deny request without crashing.
 *
 * Security A9.1: steward-supplied values (pending_id, steward_id, source_ip,
 * registered_at) must render as text content, not markup. Tests assert on
 * textContent only — never on innerHTML.
 *
 * The GET /api/v1/registration/pending response is a bare JSON array (no
 * {data:...} envelope) — confirmed against handlers_registration.go line 133.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { AuthProvider } from '../auth/AuthContext.tsx'
import PendingQueueTab, { parsePendingEntry, parsePendingRegistrations } from './PendingQueueTab.tsx'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})

afterEach(() => {
  vi.unstubAllGlobals()
  cleanup()
})

// ── Factories ─────────────────────────────────────────────────────────────────

function makeEntry(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    pending_id: 'pend-abc123',
    steward_id: 'stwd-xyz789',
    source_ip: '10.0.0.1',
    registered_at: '2026-07-25T10:00:00Z',
    ...overrides,
  }
}

function makePendingResponse(entries: object[], status = 200) {
  return new Response(JSON.stringify(entries), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function renderTab() {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <PendingQueueTab />
      </AuthProvider>
    </MemoryRouter>,
  )
}

// ── Parse helpers ─────────────────────────────────────────────────────────────

describe('parsePendingEntry', () => {
  it('returns null for non-objects', () => {
    expect(parsePendingEntry(null)).toBeNull()
    expect(parsePendingEntry('string')).toBeNull()
    expect(parsePendingEntry(42)).toBeNull()
  })

  it('returns null when pending_id is missing or empty', () => {
    expect(parsePendingEntry({})).toBeNull()
    expect(parsePendingEntry({ pending_id: '' })).toBeNull()
  })

  it('parses a valid entry', () => {
    const entry = parsePendingEntry(makeEntry())
    expect(entry).toEqual({
      pending_id: 'pend-abc123',
      steward_id: 'stwd-xyz789',
      source_ip: '10.0.0.1',
      registered_at: '2026-07-25T10:00:00Z',
    })
  })

  it('coerces non-string fields to empty string', () => {
    const entry = parsePendingEntry({
      pending_id: 'pend-1',
      steward_id: 99,
      source_ip: null,
      registered_at: undefined,
    })
    expect(entry).toEqual({
      pending_id: 'pend-1',
      steward_id: '',
      source_ip: '',
      registered_at: '',
    })
  })
})

describe('parsePendingRegistrations', () => {
  it('throws on non-array input', () => {
    expect(() => parsePendingRegistrations(null)).toThrow('unexpected response shape')
    expect(() => parsePendingRegistrations({ pending: [] })).toThrow('unexpected response shape')
  })

  it('parses a list of entries', () => {
    const list = parsePendingRegistrations([makeEntry()])
    expect(list).toHaveLength(1)
    expect(list[0]?.pending_id).toBe('pend-abc123')
  })

  it('drops entries without a pending_id', () => {
    const list = parsePendingRegistrations([{}, makeEntry()])
    expect(list).toHaveLength(1)
  })
})

// ── List rendering ────────────────────────────────────────────────────────────

describe('PendingQueueTab — list rendering', () => {
  it('shows loading rows while the fetch is in-flight', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderTab()
    expect(screen.getByTestId('pending-loading')).toBeInTheDocument()
  })

  it('shows the empty state when no registrations are pending', async () => {
    fetchMock.mockResolvedValue(makePendingResponse([]))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('pending-empty')).toBeInTheDocument())
  })

  it('renders a table row per pending entry', async () => {
    fetchMock.mockResolvedValue(
      makePendingResponse([
        makeEntry(),
        makeEntry({ pending_id: 'pend-def456', steward_id: 'stwd-uvw321', source_ip: '10.0.0.2' }),
      ]),
    )
    renderTab()
    await waitFor(() => expect(screen.getByTestId('pending-table')).toBeInTheDocument())
    expect(screen.getAllByTestId('pending-row')).toHaveLength(2)
  })

  it('renders pending_id, steward_id, source_ip, and registered_at as text nodes', async () => {
    fetchMock.mockResolvedValue(makePendingResponse([makeEntry()]))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('pending-table')).toBeInTheDocument())
    expect(screen.getByText('pend-abc123')).toBeInTheDocument()
    expect(screen.getByText('stwd-xyz789')).toBeInTheDocument()
    expect(screen.getByText('10.0.0.1')).toBeInTheDocument()
    expect(screen.getByText('2026-07-25T10:00:00Z')).toBeInTheDocument()
  })

  it('shows a Deny button for each row', async () => {
    fetchMock.mockResolvedValue(makePendingResponse([makeEntry()]))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('pending-table')).toBeInTheDocument())
    expect(screen.getByTestId('deny-btn-pend-abc123')).toBeInTheDocument()
  })

  it('renders no approve control of any kind', async () => {
    fetchMock.mockResolvedValue(makePendingResponse([makeEntry()]))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('pending-table')).toBeInTheDocument())
    expect(screen.queryByRole('button', { name: /approve/i })).toBeNull()
  })

  it('shows an error notice on a non-200 list response', async () => {
    fetchMock.mockResolvedValue(makePendingResponse([], 500))
    renderTab()
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument())
    expect(screen.getByRole('alert')).toHaveTextContent('500')
  })

  it('shows an error notice on a network-level failure', async () => {
    fetchMock.mockRejectedValue(new Error('network down'))
    renderTab()
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument())
    expect(screen.getByText(/check your connection/i)).toBeInTheDocument()
  })

  it('retries the fetch when the Retry button is clicked', async () => {
    fetchMock
      .mockResolvedValueOnce(makePendingResponse([], 500))
      .mockResolvedValueOnce(makePendingResponse([]))
    renderTab()
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: /retry/i }))
    await waitFor(() => expect(screen.getByTestId('pending-empty')).toBeInTheDocument())
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })
})

// ── Deny flow ─────────────────────────────────────────────────────────────────

describe('PendingQueueTab — deny', () => {
  it('deny removes the row from the list on success', async () => {
    fetchMock
      .mockResolvedValueOnce(makePendingResponse([makeEntry()]))
      .mockResolvedValueOnce(new Response(null, { status: 200 }))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('pending-table')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('deny-btn-pend-abc123'))

    await waitFor(() => expect(screen.getByTestId('pending-empty')).toBeInTheDocument())
    expect(screen.queryByTestId('pending-row')).toBeNull()
    const denyCall = fetchMock.mock.calls[1]!
    expect(String(denyCall[0])).toContain('/deny')
    expect((denyCall[1] as RequestInit | undefined)?.method).toBe('POST')
  })

  it('surfaces a row-level error on a failed deny without crashing', async () => {
    fetchMock
      .mockResolvedValueOnce(makePendingResponse([makeEntry()]))
      .mockResolvedValueOnce(new Response(null, { status: 403 }))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('pending-table')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('deny-btn-pend-abc123'))

    await waitFor(() =>
      expect(screen.getByTestId('deny-error-pend-abc123')).toBeInTheDocument(),
    )
    expect(screen.getByTestId('deny-error-pend-abc123')).toHaveTextContent('403')
    // Row is still present — the component did not crash
    expect(screen.getByTestId('pending-table')).toBeInTheDocument()
    expect(screen.getAllByTestId('pending-row')).toHaveLength(1)
  })

  it('surfaces a row-level error on a network failure during deny without crashing', async () => {
    fetchMock
      .mockResolvedValueOnce(makePendingResponse([makeEntry()]))
      .mockRejectedValueOnce(new Error('connection refused'))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('pending-table')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('deny-btn-pend-abc123'))

    await waitFor(() =>
      expect(screen.getByTestId('deny-error-pend-abc123')).toBeInTheDocument(),
    )
    expect(screen.getByTestId('deny-error-pend-abc123')).toHaveTextContent('connection refused')
    expect(screen.getAllByTestId('pending-row')).toHaveLength(1)
  })

  it('clears a previous deny error when deny is retried', async () => {
    fetchMock
      .mockResolvedValueOnce(makePendingResponse([makeEntry()]))
      .mockResolvedValueOnce(new Response(null, { status: 403 }))
      .mockResolvedValueOnce(new Response(null, { status: 200 }))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('pending-table')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('deny-btn-pend-abc123'))
    await waitFor(() =>
      expect(screen.getByTestId('deny-error-pend-abc123')).toBeInTheDocument(),
    )

    fireEvent.click(screen.getByTestId('deny-btn-pend-abc123'))
    await waitFor(() => expect(screen.getByTestId('pending-empty')).toBeInTheDocument())
    expect(screen.queryByTestId('deny-error-pend-abc123')).toBeNull()
  })

  it('keeps other rows intact when one deny succeeds', async () => {
    fetchMock
      .mockResolvedValueOnce(
        makePendingResponse([
          makeEntry(),
          makeEntry({ pending_id: 'pend-def456', steward_id: 'stwd-uvw321' }),
        ]),
      )
      .mockResolvedValueOnce(new Response(null, { status: 200 }))
    renderTab()
    await waitFor(() => expect(screen.getAllByTestId('pending-row')).toHaveLength(2))

    fireEvent.click(screen.getByTestId('deny-btn-pend-abc123'))

    await waitFor(() => expect(screen.getAllByTestId('pending-row')).toHaveLength(1))
    expect(screen.getByText('pend-def456')).toBeInTheDocument()
    expect(screen.queryByText('pend-abc123')).toBeNull()
  })
})
