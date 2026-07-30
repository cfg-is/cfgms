// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * RefreshQueuePage test suite (Story #2941): list rendering, data states, and
 * reject-remove / reject-error flows.
 *
 * Required AC: reject removes the row on success; surfaces a row-level error
 * state on a failed request without crashing.
 *
 * Security A9.1: device-supplied and operator-influenced values (pending_id,
 * device_id, tenant_id, source_ip, created_at) must render as text content,
 * not markup. Tests assert on textContent only — never on innerHTML.
 *
 * The GET /api/v1/stewards/refresh/pending response is a bare JSON array (no
 * {data:...} envelope) — confirmed against handlers_registration_refresh.go:624.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { AuthProvider } from '../auth/AuthContext.tsx'
import RefreshQueuePage, {
  parsePendingRefreshEntry,
  parsePendingRefreshList,
} from './RefreshQueuePage.tsx'

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
    pending_id: 'ref-abc123',
    device_id: 'dev-xyz789',
    tenant_id: 'root/msp-a/prod',
    source_ip: '10.2.4.19',
    provenance_matched_fields: 7,
    provenance_total_fields: 7,
    status: 'pending',
    created_at: '2026-07-25T10:00:00Z',
    expires_at: '2026-07-25T11:00:00Z',
    ...overrides,
  }
}

function makeRefreshResponse(entries: object[], status = 200) {
  return new Response(JSON.stringify(entries), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function renderPage() {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <RefreshQueuePage />
      </AuthProvider>
    </MemoryRouter>,
  )
}

// ── Parse helpers ─────────────────────────────────────────────────────────────

describe('parsePendingRefreshEntry', () => {
  it('returns null for non-objects', () => {
    expect(parsePendingRefreshEntry(null)).toBeNull()
    expect(parsePendingRefreshEntry('string')).toBeNull()
    expect(parsePendingRefreshEntry(42)).toBeNull()
  })

  it('returns null when pending_id is missing or empty', () => {
    expect(parsePendingRefreshEntry({})).toBeNull()
    expect(parsePendingRefreshEntry({ pending_id: '' })).toBeNull()
  })

  it('parses a valid entry', () => {
    const entry = parsePendingRefreshEntry(makeEntry())
    expect(entry).toEqual({
      pending_id: 'ref-abc123',
      device_id: 'dev-xyz789',
      tenant_id: 'root/msp-a/prod',
      source_ip: '10.2.4.19',
      provenance_matched_fields: 7,
      provenance_total_fields: 7,
      status: 'pending',
      created_at: '2026-07-25T10:00:00Z',
    })
  })

  it('coerces non-string fields to empty string and numeric fields to 0', () => {
    const entry = parsePendingRefreshEntry({
      pending_id: 'ref-1',
      device_id: 99,
      tenant_id: null,
      source_ip: undefined,
      provenance_matched_fields: 'not-a-number',
      provenance_total_fields: null,
      status: false,
      created_at: undefined,
    })
    expect(entry).toEqual({
      pending_id: 'ref-1',
      device_id: '',
      tenant_id: '',
      source_ip: '',
      provenance_matched_fields: 0,
      provenance_total_fields: 0,
      status: '',
      created_at: '',
    })
  })
})

describe('parsePendingRefreshList', () => {
  it('throws on non-array input', () => {
    expect(() => parsePendingRefreshList(null)).toThrow('unexpected response shape')
    expect(() => parsePendingRefreshList({ pending: [] })).toThrow('unexpected response shape')
  })

  it('parses a list of entries', () => {
    const list = parsePendingRefreshList([makeEntry()])
    expect(list).toHaveLength(1)
    expect(list[0]?.pending_id).toBe('ref-abc123')
  })

  it('drops entries without a pending_id', () => {
    const list = parsePendingRefreshList([{}, makeEntry()])
    expect(list).toHaveLength(1)
  })
})

// ── List rendering ────────────────────────────────────────────────────────────

describe('RefreshQueuePage — list rendering', () => {
  it('shows loading rows while the fetch is in-flight', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderPage()
    expect(screen.getByTestId('refresh-loading')).toBeInTheDocument()
  })

  it('shows the empty state when no refresh requests are pending', async () => {
    fetchMock.mockResolvedValue(makeRefreshResponse([]))
    renderPage()
    await waitFor(() => expect(screen.getByTestId('refresh-empty')).toBeInTheDocument())
  })

  it('renders a table row per pending entry', async () => {
    fetchMock.mockResolvedValue(
      makeRefreshResponse([
        makeEntry(),
        makeEntry({ pending_id: 'ref-def456', device_id: 'dev-uvw321', source_ip: '10.2.4.20' }),
      ]),
    )
    renderPage()
    await waitFor(() => expect(screen.getByTestId('refresh-table')).toBeInTheDocument())
    expect(screen.getAllByTestId('refresh-row')).toHaveLength(2)
  })

  it('renders pending_id, device_id, tenant_id, source_ip, and created_at as text nodes', async () => {
    fetchMock.mockResolvedValue(makeRefreshResponse([makeEntry()]))
    renderPage()
    await waitFor(() => expect(screen.getByTestId('refresh-table')).toBeInTheDocument())
    expect(screen.getByText('ref-abc123')).toBeInTheDocument()
    expect(screen.getByText('dev-xyz789')).toBeInTheDocument()
    expect(screen.getByText('root/msp-a/prod')).toBeInTheDocument()
    expect(screen.getByText('10.2.4.19')).toBeInTheDocument()
    expect(screen.getByText('2026-07-25T10:00:00Z')).toBeInTheDocument()
  })

  it('shows a full-match provenance badge (7 / 7) with ok styling', async () => {
    fetchMock.mockResolvedValue(
      makeRefreshResponse([makeEntry({ provenance_matched_fields: 7, provenance_total_fields: 7 })]),
    )
    renderPage()
    await waitFor(() => expect(screen.getByTestId('refresh-table')).toBeInTheDocument())
    const badge = screen.getByTestId('provenance-badge-ref-abc123')
    expect(badge).toHaveTextContent('7 / 7')
    expect(badge).toHaveClass('b-ok')
  })

  it('shows a partial-match provenance badge (4 / 7) with warn styling', async () => {
    fetchMock.mockResolvedValue(
      makeRefreshResponse([makeEntry({ provenance_matched_fields: 4, provenance_total_fields: 7 })]),
    )
    renderPage()
    await waitFor(() => expect(screen.getByTestId('refresh-table')).toBeInTheDocument())
    const badge = screen.getByTestId('provenance-badge-ref-abc123')
    expect(badge).toHaveTextContent('4 / 7')
    expect(badge).toHaveClass('b-warn')
  })

  it('shows a Reject button for each row', async () => {
    fetchMock.mockResolvedValue(makeRefreshResponse([makeEntry()]))
    renderPage()
    await waitFor(() => expect(screen.getByTestId('refresh-table')).toBeInTheDocument())
    expect(screen.getByTestId('reject-btn-ref-abc123')).toBeInTheDocument()
  })

  it('shows an Approve button for each row', async () => {
    fetchMock.mockResolvedValue(makeRefreshResponse([makeEntry()]))
    renderPage()
    await waitFor(() => expect(screen.getByTestId('refresh-table')).toBeInTheDocument())
    expect(screen.getByTestId('approve-btn-ref-abc123')).toBeInTheDocument()
  })

  it('shows an error notice on a non-200 list response', async () => {
    fetchMock.mockResolvedValue(makeRefreshResponse([], 500))
    renderPage()
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument())
    expect(screen.getByRole('alert')).toHaveTextContent('500')
  })

  it('shows an error notice on a network-level failure', async () => {
    fetchMock.mockRejectedValue(new Error('network down'))
    renderPage()
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument())
    expect(screen.getByText(/check your connection/i)).toBeInTheDocument()
  })

  it('retries the fetch when the Retry button is clicked', async () => {
    fetchMock
      .mockResolvedValueOnce(makeRefreshResponse([], 500))
      .mockResolvedValueOnce(makeRefreshResponse([]))
    renderPage()
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: /retry/i }))
    await waitFor(() => expect(screen.getByTestId('refresh-empty')).toBeInTheDocument())
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })
})

// ── Reject flow ───────────────────────────────────────────────────────────────

describe('RefreshQueuePage — reject', () => {
  it('reject removes the row from the list on success', async () => {
    fetchMock
      .mockResolvedValueOnce(makeRefreshResponse([makeEntry()]))
      .mockResolvedValueOnce(new Response(null, { status: 200 }))
    renderPage()
    await waitFor(() => expect(screen.getByTestId('refresh-table')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('reject-btn-ref-abc123'))

    await waitFor(() => expect(screen.getByTestId('refresh-empty')).toBeInTheDocument())
    expect(screen.queryByTestId('refresh-row')).toBeNull()
    const rejectCall = fetchMock.mock.calls[1]!
    expect(String(rejectCall[0])).toContain('/reject')
    expect((rejectCall[1] as RequestInit | undefined)?.method).toBe('POST')
  })

  it('surfaces a row-level error on a failed reject without crashing', async () => {
    fetchMock
      .mockResolvedValueOnce(makeRefreshResponse([makeEntry()]))
      .mockResolvedValueOnce(new Response(null, { status: 403 }))
    renderPage()
    await waitFor(() => expect(screen.getByTestId('refresh-table')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('reject-btn-ref-abc123'))

    await waitFor(() =>
      expect(screen.getByTestId('reject-error-ref-abc123')).toBeInTheDocument(),
    )
    expect(screen.getByTestId('reject-error-ref-abc123')).toHaveTextContent('403')
    // Row is still present — the component did not crash
    expect(screen.getByTestId('refresh-table')).toBeInTheDocument()
    expect(screen.getAllByTestId('refresh-row')).toHaveLength(1)
  })

  it('surfaces a row-level error on a network failure during reject without crashing', async () => {
    fetchMock
      .mockResolvedValueOnce(makeRefreshResponse([makeEntry()]))
      .mockRejectedValueOnce(new Error('connection refused'))
    renderPage()
    await waitFor(() => expect(screen.getByTestId('refresh-table')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('reject-btn-ref-abc123'))

    await waitFor(() =>
      expect(screen.getByTestId('reject-error-ref-abc123')).toBeInTheDocument(),
    )
    expect(screen.getByTestId('reject-error-ref-abc123')).toHaveTextContent('connection refused')
    expect(screen.getAllByTestId('refresh-row')).toHaveLength(1)
  })

  it('clears a previous reject error when reject is retried', async () => {
    fetchMock
      .mockResolvedValueOnce(makeRefreshResponse([makeEntry()]))
      .mockResolvedValueOnce(new Response(null, { status: 403 }))
      .mockResolvedValueOnce(new Response(null, { status: 200 }))
    renderPage()
    await waitFor(() => expect(screen.getByTestId('refresh-table')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('reject-btn-ref-abc123'))
    await waitFor(() =>
      expect(screen.getByTestId('reject-error-ref-abc123')).toBeInTheDocument(),
    )

    fireEvent.click(screen.getByTestId('reject-btn-ref-abc123'))
    await waitFor(() => expect(screen.getByTestId('refresh-empty')).toBeInTheDocument())
    expect(screen.queryByTestId('reject-error-ref-abc123')).toBeNull()
  })

  it('keeps other rows intact when one reject succeeds', async () => {
    fetchMock
      .mockResolvedValueOnce(
        makeRefreshResponse([
          makeEntry(),
          makeEntry({ pending_id: 'ref-def456', device_id: 'dev-uvw321' }),
        ]),
      )
      .mockResolvedValueOnce(new Response(null, { status: 200 }))
    renderPage()
    await waitFor(() => expect(screen.getAllByTestId('refresh-row')).toHaveLength(2))

    fireEvent.click(screen.getByTestId('reject-btn-ref-abc123'))

    await waitFor(() => expect(screen.getAllByTestId('refresh-row')).toHaveLength(1))
    expect(screen.getByText('ref-def456')).toBeInTheDocument()
    expect(screen.queryByText('ref-abc123')).toBeNull()
  })
})

// ── Approve flow (Story #2973) ────────────────────────────────────────────────
// Approve calls POST /api/v1/stewards/refresh/{pending_id}/approve.
// Strong step-up (S1 elevation) is handled transparently by apiFetch +
// StepUpModal in AuthContext — no explicit assertion here; the step-up
// ceremony fires only when the server returns 401 CFGMS-StepUp.

describe('RefreshQueuePage — approve', () => {
  it('approve removes the row from the list on success', async () => {
    fetchMock
      .mockResolvedValueOnce(makeRefreshResponse([makeEntry()]))
      .mockResolvedValueOnce(new Response(null, { status: 200 }))
    renderPage()
    await waitFor(() => expect(screen.getByTestId('refresh-table')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('approve-btn-ref-abc123'))

    await waitFor(() => expect(screen.getByTestId('refresh-empty')).toBeInTheDocument())
    expect(screen.queryByTestId('refresh-row')).toBeNull()
    const approveCall = fetchMock.mock.calls[1]!
    expect(String(approveCall[0])).toContain('/approve')
    expect((approveCall[1] as RequestInit | undefined)?.method).toBe('POST')
  })

  it('surfaces a row-level error on a failed approve without crashing', async () => {
    fetchMock
      .mockResolvedValueOnce(makeRefreshResponse([makeEntry()]))
      .mockResolvedValueOnce(new Response(null, { status: 403 }))
    renderPage()
    await waitFor(() => expect(screen.getByTestId('refresh-table')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('approve-btn-ref-abc123'))

    await waitFor(() =>
      expect(screen.getByTestId('approve-error-ref-abc123')).toBeInTheDocument(),
    )
    expect(screen.getByTestId('approve-error-ref-abc123')).toHaveTextContent('403')
    expect(screen.getByTestId('refresh-table')).toBeInTheDocument()
    expect(screen.getAllByTestId('refresh-row')).toHaveLength(1)
  })

  it('surfaces a row-level error on a network failure during approve without crashing', async () => {
    fetchMock
      .mockResolvedValueOnce(makeRefreshResponse([makeEntry()]))
      .mockRejectedValueOnce(new Error('connection refused'))
    renderPage()
    await waitFor(() => expect(screen.getByTestId('refresh-table')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('approve-btn-ref-abc123'))

    await waitFor(() =>
      expect(screen.getByTestId('approve-error-ref-abc123')).toBeInTheDocument(),
    )
    expect(screen.getByTestId('approve-error-ref-abc123')).toHaveTextContent('connection refused')
    expect(screen.getAllByTestId('refresh-row')).toHaveLength(1)
  })

  it('clears a previous approve error when approve is retried', async () => {
    fetchMock
      .mockResolvedValueOnce(makeRefreshResponse([makeEntry()]))
      .mockResolvedValueOnce(new Response(null, { status: 403 }))
      .mockResolvedValueOnce(new Response(null, { status: 200 }))
    renderPage()
    await waitFor(() => expect(screen.getByTestId('refresh-table')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('approve-btn-ref-abc123'))
    await waitFor(() =>
      expect(screen.getByTestId('approve-error-ref-abc123')).toBeInTheDocument(),
    )

    fireEvent.click(screen.getByTestId('approve-btn-ref-abc123'))
    await waitFor(() => expect(screen.getByTestId('refresh-empty')).toBeInTheDocument())
    expect(screen.queryByTestId('approve-error-ref-abc123')).toBeNull()
  })

  it('keeps other rows intact when one approve succeeds', async () => {
    fetchMock
      .mockResolvedValueOnce(
        makeRefreshResponse([
          makeEntry(),
          makeEntry({ pending_id: 'ref-def456', device_id: 'dev-uvw321' }),
        ]),
      )
      .mockResolvedValueOnce(new Response(null, { status: 200 }))
    renderPage()
    await waitFor(() => expect(screen.getAllByTestId('refresh-row')).toHaveLength(2))

    fireEvent.click(screen.getByTestId('approve-btn-ref-abc123'))

    await waitFor(() => expect(screen.getAllByTestId('refresh-row')).toHaveLength(1))
    expect(screen.getByText('ref-def456')).toBeInTheDocument()
    expect(screen.queryByText('ref-abc123')).toBeNull()
  })
})
