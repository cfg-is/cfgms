// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * CaseListView tests (Story #3614).
 *
 * Verifies:
 *  - Loading state renders while fetch is in-flight.
 *  - Empty state renders (not loading, not error) when GET /api/v1/cases returns [].
 *  - Table renders with correct columns (Title, Client, Priority, Status, Last updated).
 *  - Row click navigates to /cases/:id via a Link.
 *  - Cases from a different tenant (excluded by server-side filter) never render.
 *  - Missing (unfilled) Client or Priority renders a muted marker, not a blank cell.
 *  - Error state renders on a non-OK response.
 *  - Error state renders when the fetch itself rejects (network/DNS/CORS abort),
 *    with connectivity copy distinct from the HTTP-error branch, and recovers on retry.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router'
import CaseListView from './CaseListView.tsx'
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
    pins: [],
    content: [],
    created_at: '2026-07-03T08:52:00Z',
    updated_at: '2026-07-03T09:00:00Z',
    ...overrides,
  }
}

function jsonResponse(status: number, data: unknown = null): Response {
  return new Response(
    JSON.stringify({ data, timestamp: '2026-07-03T09:00:00Z' }),
    { status, headers: { 'Content-Type': 'application/json' } },
  )
}

function renderCaseListView() {
  return render(
    <MemoryRouter initialEntries={['/cases']}>
      <Routes>
        <Route path="/cases" element={<CaseListView />} />
        <Route path="/cases/:id" element={<div data-testid="case-detail-page" />} />
      </Routes>
    </MemoryRouter>,
  )
}

// ── Loading state ─────────────────────────────────────────────────────────────

describe('CaseListView — loading state', () => {
  it('renders the loading skeleton while the fetch is in-flight', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderCaseListView()
    expect(screen.getByTestId('case-loading')).toBeInTheDocument()
    expect(screen.queryByTestId('cases-empty')).toBeNull()
    expect(screen.queryByTestId('cases-table')).toBeNull()
  })
})

// ── Empty state ───────────────────────────────────────────────────────────────

describe('CaseListView — empty state', () => {
  it('renders the empty state (not loading, not error) when GET /api/v1/cases returns zero cases', async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, []))
    renderCaseListView()
    await waitFor(() => expect(screen.getByTestId('cases-empty')).toBeInTheDocument())
    expect(screen.queryByTestId('case-loading')).toBeNull()
    expect(screen.queryByRole('alert')).toBeNull()
    expect(screen.queryByTestId('cases-table')).toBeNull()
  })

  it('empty state includes a heading and explanatory text — not a blank screen', async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, []))
    renderCaseListView()
    await waitFor(() => expect(screen.getByTestId('cases-empty')).toBeInTheDocument())
    expect(screen.getByRole('heading', { level: 3 })).toBeInTheDocument()
    // Body text must be present so the screen reads as "no cases" not "broken".
    const emptyEl = screen.getByTestId('cases-empty')
    expect(emptyEl.querySelector('p')).not.toBeNull()
  })
})

// ── Server-side filter trust ──────────────────────────────────────────────────

describe('CaseListView — server-side filter trust', () => {
  it('never renders a row for a case excluded from the tenant-filtered API response', async () => {
    // Raw fixture has two cases — one from root/msp-a/client-1, one from
    // root/msp-b/client-2. The server returns only the first (tenant-filtered).
    // This asserts the view trusts the server and does not attempt to add back
    // the excluded case client-side.
    const includedCase = makeCase({
      id: 'case-001',
      tenant_id: 'root/msp-a/client-1',
      ticket: {
        title: { value: 'Included case', source: 'email', filled: true },
        client: { value: 'client-1', source: 'caller-id', filled: true },
        contact: { value: '', source: '', filled: false },
        priority: { value: 'High', source: 'email', filled: true },
        category: { value: '', source: '', filled: false },
      },
    })
    // This case belongs to a different tenant and must NOT appear.
    const excludedCaseId = 'case-999'
    const excludedCaseTitle = 'Excluded different-tenant case'

    // The API returns only the included case (server already filtered out the other).
    fetchMock.mockResolvedValue(jsonResponse(200, [includedCase]))

    renderCaseListView()
    await waitFor(() => expect(screen.getByTestId('cases-table')).toBeInTheDocument())

    // The included case is rendered.
    expect(screen.getByText('Included case')).toBeInTheDocument()

    // The excluded case's id and title must not appear anywhere in the DOM.
    expect(screen.queryByText(excludedCaseTitle)).toBeNull()
    expect(document.querySelector(`[href*="${excludedCaseId}"]`)).toBeNull()
    // Exactly one data row.
    expect(screen.getAllByTestId('case-row')).toHaveLength(1)
  })
})

// ── Column layout ─────────────────────────────────────────────────────────────

describe('CaseListView — column layout', () => {
  it('renders exactly these columns in order: Title, Client, Priority, Status, Last updated', async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, [makeCase()]))
    renderCaseListView()
    await waitFor(() => expect(screen.getByTestId('cases-table')).toBeInTheDocument())

    const headers = screen
      .getByTestId('cases-table')
      .querySelectorAll('thead th')
    const labels = Array.from(headers)
      .map((h) => h.textContent?.trim())
      .filter(Boolean)
    // Spacer th is empty — filter removes it. Remaining must be exactly these 5.
    expect(labels).toEqual(['Title', 'Client', 'Priority', 'Status', 'Last updated'])
  })
})

// ── Row navigation ────────────────────────────────────────────────────────────

describe('CaseListView — row navigation', () => {
  it('each case row links to /cases/:id for that case', async () => {
    const c = makeCase({ id: 'case-abc-123' })
    fetchMock.mockResolvedValue(jsonResponse(200, [c]))
    renderCaseListView()
    await waitFor(() => expect(screen.getByTestId('case-row')).toBeInTheDocument())

    const link = screen.getByRole('link', { name: /SQL app slow since 9am/i })
    expect(link).toHaveAttribute('href', `/cases/${encodeURIComponent('case-abc-123')}`)
  })

  it('percent-encodes the case id in the row link', async () => {
    const weirdId = 'case/with/slashes'
    const c = makeCase({ id: weirdId })
    fetchMock.mockResolvedValue(jsonResponse(200, [c]))
    renderCaseListView()
    await waitFor(() => expect(screen.getByTestId('case-row')).toBeInTheDocument())

    const link = screen.getByRole('link', { name: /SQL app slow since 9am/i })
    expect(link).toHaveAttribute('href', `/cases/${encodeURIComponent(weirdId)}`)
  })
})

// ── Missing field markers ─────────────────────────────────────────────────────

describe('CaseListView — missing field markers', () => {
  it('renders a muted marker (not a blank cell) for an unfilled Client field', async () => {
    const c = makeCase({
      ticket: {
        title: { value: 'Test case', source: 'email', filled: true },
        client: { value: '', source: '', filled: false },
        contact: { value: '', source: '', filled: false },
        priority: { value: 'High', source: 'email', filled: true },
        category: { value: '', source: '', filled: false },
      },
    })
    fetchMock.mockResolvedValue(jsonResponse(200, [c]))
    renderCaseListView()
    await waitFor(() => expect(screen.getByTestId('case-row')).toBeInTheDocument())

    const row = screen.getByTestId('case-row')
    const cells = row.querySelectorAll('td')
    // Client is the second data cell (index 1).
    const clientCell = cells[1]
    // Must contain a non-empty muted marker, not be blank.
    expect(clientCell?.textContent?.trim()).not.toBe('')
    expect(clientCell?.querySelector('.mut')).not.toBeNull()
  })

  it('renders a muted marker (not a blank cell) for an unfilled Priority field', async () => {
    const c = makeCase({
      ticket: {
        title: { value: 'Test case', source: 'email', filled: true },
        client: { value: 'acme', source: 'caller-id', filled: true },
        contact: { value: '', source: '', filled: false },
        priority: { value: '', source: '', filled: false },
        category: { value: '', source: '', filled: false },
      },
    })
    fetchMock.mockResolvedValue(jsonResponse(200, [c]))
    renderCaseListView()
    await waitFor(() => expect(screen.getByTestId('case-row')).toBeInTheDocument())

    const row = screen.getByTestId('case-row')
    const cells = row.querySelectorAll('td')
    // Priority is the third data cell (index 2).
    const priorityCell = cells[2]
    expect(priorityCell?.textContent?.trim()).not.toBe('')
    expect(priorityCell?.querySelector('.mut')).not.toBeNull()
  })
})

// ── Error state ───────────────────────────────────────────────────────────────

describe('CaseListView — error state', () => {
  it('renders an error state on a non-OK response', async () => {
    fetchMock.mockResolvedValue(jsonResponse(500))
    renderCaseListView()
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument())
    expect(screen.queryByTestId('case-loading')).toBeNull()
    expect(screen.queryByTestId('cases-empty')).toBeNull()
    // HTTP-error branch carries the status code and reads as a server fault.
    expect(screen.getByText('Load failed — 500')).toBeInTheDocument()
    expect(screen.getByText(/returned an error/i)).toBeInTheDocument()
    expect(screen.queryByText(/check your connection/i)).toBeNull()
  })

  it('renders an error state when the fetch itself rejects (network failure)', async () => {
    fetchMock.mockRejectedValue(new TypeError('Failed to fetch'))
    renderCaseListView()
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument())
    // The loading skeleton is replaced; no empty state and no table are shown.
    expect(screen.queryByTestId('case-loading')).toBeNull()
    expect(screen.queryByTestId('cases-empty')).toBeNull()
    expect(screen.queryByTestId('cases-table')).toBeNull()
    // The count chip is suppressed in the error state — no misleading "0 cases".
    expect(screen.queryByTestId('cases-count')).toBeNull()
  })

  it('network failure shows connectivity copy, distinct from the HTTP-error branch', async () => {
    fetchMock.mockRejectedValue(new TypeError('Failed to fetch'))
    renderCaseListView()
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument())
    expect(screen.getByText('Failed to load cases')).toBeInTheDocument()
    expect(screen.getByText(/check your connection/i)).toBeInTheDocument()
    // Must NOT be classified as a server-side error — there was no response.
    expect(screen.queryByText(/returned an error/i)).toBeNull()
  })

  it('errors when the OK response body is not valid JSON', async () => {
    // res.ok is true but res.json() rejects — this also lands in the catch branch.
    fetchMock.mockResolvedValue(
      new Response('not json', {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    renderCaseListView()
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument())
    expect(screen.getByText('Failed to load cases')).toBeInTheDocument()
    expect(screen.queryByTestId('cases-table')).toBeNull()
  })

  it('recovers on retry after a network failure', async () => {
    fetchMock.mockRejectedValueOnce(new TypeError('Failed to fetch'))
    fetchMock.mockResolvedValue(jsonResponse(200, [makeCase()]))
    renderCaseListView()
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument())

    fireEvent.click(screen.getByRole('button', { name: /retry/i }))

    await waitFor(() => expect(screen.getByTestId('cases-table')).toBeInTheDocument())
    expect(screen.queryByRole('alert')).toBeNull()
    expect(screen.getByText('SQL app slow since 9am')).toBeInTheDocument()
  })
})
