// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Audit view suite (Story #2727, #2989): filter-param round-tripping for every
 * query parameter handleListAuditEntries reads, the untrusted-value rendering
 * rule (security A9.1), UI-state coverage (loading, error, empty, table),
 * row expansion (details/changes), CSV export, and has_more pager behaviour.
 */
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { AuthProvider } from '../auth/AuthContext.tsx'
import AuditView, { escapeCsvCell, buildAuditCSV } from './AuditView.tsx'
import type { AuditEntry } from './useAuditEntries.ts'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})

afterEach(() => {
  vi.unstubAllGlobals()
  cleanup()
})

function makeEntry(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    id: 'e1',
    timestamp: '2026-01-15T10:30:00Z',
    event_type: 'authentication',
    action: 'login',
    user_id: 'user-1',
    user_type: 'human',
    resource_type: 'session',
    resource_id: 'sess-1',
    resource_name: '',
    result: 'success',
    severity: 'low',
    source: 'controller',
    ip_address: '10.0.0.1',
    method: 'POST',
    path: '/api/v1/web/login',
    error_code: '',
    error_message: '',
    ...overrides,
  }
}

function makeResponse(entries: object[], status = 200, hasMore = false) {
  return new Response(
    JSON.stringify({
      data: { entries, has_more: hasMore },
      timestamp: new Date().toISOString(),
    }),
    { status, headers: { 'Content-Type': 'application/json' } },
  )
}

/** Extract the URL from the most recent fetch call. */
function lastFetchURL(): string {
  const calls = fetchMock.mock.calls
  return calls[calls.length - 1]![0] as string
}

function renderAuditView() {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <AuditView />
      </AuthProvider>
    </MemoryRouter>,
  )
}

describe('AuditView — filter controls', () => {
  it('renders a filter control for every query param handleListAuditEntries reads', () => {
    fetchMock.mockResolvedValue(makeResponse([]))
    renderAuditView()
    expect(screen.getByRole('textbox', { name: /user id/i })).toBeInTheDocument()
    expect(screen.getByRole('textbox', { name: /action/i })).toBeInTheDocument()
    expect(screen.getByRole('textbox', { name: /module/i })).toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: /severity/i })).toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: /event type/i })).toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: /result/i })).toBeInTheDocument()
    // since and until are datetime-local inputs (not role=textbox in all browsers)
    expect(screen.getByLabelText(/since/i)).toBeInTheDocument()
    expect(screen.getByLabelText(/until/i)).toBeInTheDocument()
  })

  it('severity select includes all server-recognised values', () => {
    fetchMock.mockResolvedValue(makeResponse([]))
    renderAuditView()
    const select = screen.getByRole('combobox', { name: /severity/i })
    const options = Array.from((select as HTMLSelectElement).options).map((o) => o.value)
    expect(options).toContain('low')
    expect(options).toContain('medium')
    expect(options).toContain('high')
    expect(options).toContain('critical')
  })

  it('event_type select includes all server-recognised values', () => {
    fetchMock.mockResolvedValue(makeResponse([]))
    renderAuditView()
    const select = screen.getByRole('combobox', { name: /event type/i })
    const options = Array.from((select as HTMLSelectElement).options).map((o) => o.value)
    expect(options).toContain('authentication')
    expect(options).toContain('authorization')
    expect(options).toContain('configuration')
    expect(options).toContain('user_management')
    expect(options).toContain('system_access')
    expect(options).toContain('data_access')
    expect(options).toContain('data_modification')
    expect(options).toContain('security_event')
    expect(options).toContain('system_event')
    expect(options).toContain('compliance')
  })

  it('result select includes all server-recognised values', () => {
    fetchMock.mockResolvedValue(makeResponse([]))
    renderAuditView()
    const select = screen.getByRole('combobox', { name: /result/i })
    const options = Array.from((select as HTMLSelectElement).options).map((o) => o.value)
    expect(options).toContain('success')
    expect(options).toContain('failure')
    expect(options).toContain('error')
    expect(options).toContain('denied')
  })
})

describe('AuditView — filter-param round-tripping', () => {
  it('sends severity to the API when the filter is applied', async () => {
    fetchMock.mockResolvedValue(makeResponse([]))
    renderAuditView()
    await waitFor(() => expect(fetchMock).toHaveBeenCalled())

    fireEvent.change(screen.getByRole('combobox', { name: /severity/i }), {
      target: { value: 'high' },
    })
    fireEvent.click(screen.getByRole('button', { name: /apply/i }))

    await waitFor(() => expect(lastFetchURL()).toContain('severity=high'))
  })

  it('sends event_type to the API when the filter is applied', async () => {
    fetchMock.mockResolvedValue(makeResponse([]))
    renderAuditView()
    await waitFor(() => expect(fetchMock).toHaveBeenCalled())

    fireEvent.change(screen.getByRole('combobox', { name: /event type/i }), {
      target: { value: 'configuration' },
    })
    fireEvent.click(screen.getByRole('button', { name: /apply/i }))

    await waitFor(() => expect(lastFetchURL()).toContain('event_type=configuration'))
  })

  it('sends result to the API when the filter is applied', async () => {
    fetchMock.mockResolvedValue(makeResponse([]))
    renderAuditView()
    await waitFor(() => expect(fetchMock).toHaveBeenCalled())

    fireEvent.change(screen.getByRole('combobox', { name: /result/i }), {
      target: { value: 'failure' },
    })
    fireEvent.click(screen.getByRole('button', { name: /apply/i }))

    await waitFor(() => expect(lastFetchURL()).toContain('result=failure'))
  })

  it('sends user_id to the API when the filter is applied', async () => {
    fetchMock.mockResolvedValue(makeResponse([]))
    renderAuditView()
    await waitFor(() => expect(fetchMock).toHaveBeenCalled())

    fireEvent.change(screen.getByRole('textbox', { name: /user id/i }), {
      target: { value: 'alice' },
    })
    fireEvent.click(screen.getByRole('button', { name: /apply/i }))

    await waitFor(() => expect(lastFetchURL()).toContain('user_id=alice'))
  })

  it('sends action to the API when the filter is applied', async () => {
    fetchMock.mockResolvedValue(makeResponse([]))
    renderAuditView()
    await waitFor(() => expect(fetchMock).toHaveBeenCalled())

    fireEvent.change(screen.getByRole('textbox', { name: /action/i }), {
      target: { value: 'delete' },
    })
    fireEvent.click(screen.getByRole('button', { name: /apply/i }))

    await waitFor(() => expect(lastFetchURL()).toContain('action=delete'))
  })

  it('sends module to the API when the filter is applied', async () => {
    fetchMock.mockResolvedValue(makeResponse([]))
    renderAuditView()
    await waitFor(() => expect(fetchMock).toHaveBeenCalled())

    fireEvent.change(screen.getByRole('textbox', { name: /module/i }), {
      target: { value: 'patch' },
    })
    fireEvent.click(screen.getByRole('button', { name: /apply/i }))

    await waitFor(() => expect(lastFetchURL()).toContain('module=patch'))
  })

  it('sends since and until as RFC3339 when set', async () => {
    fetchMock.mockResolvedValue(makeResponse([]))
    renderAuditView()
    await waitFor(() => expect(fetchMock).toHaveBeenCalled())

    fireEvent.change(screen.getByLabelText(/since/i), {
      target: { value: '2026-01-01T00:00' },
    })
    fireEvent.change(screen.getByLabelText(/until/i), {
      target: { value: '2026-01-31T23:59' },
    })
    fireEvent.click(screen.getByRole('button', { name: /apply/i }))

    await waitFor(() => {
      const url = lastFetchURL()
      expect(url).toContain('since=')
      expect(url).toContain('until=')
      // both must contain Z (RFC3339 UTC marker)
      const params = new URLSearchParams(url.split('?')[1])
      expect(params.get('since')).toMatch(/Z$/)
      expect(params.get('until')).toMatch(/Z$/)
    })
  })

  it('omits empty filter params from the request', async () => {
    fetchMock.mockResolvedValue(makeResponse([]))
    renderAuditView()
    await waitFor(() => expect(fetchMock).toHaveBeenCalled())
    const url = lastFetchURL()
    expect(url).not.toContain('severity=')
    expect(url).not.toContain('event_type=')
    expect(url).not.toContain('result=')
    expect(url).not.toContain('user_id=')
    expect(url).not.toContain('action=')
    expect(url).not.toContain('module=')
    expect(url).not.toContain('since=')
    expect(url).not.toContain('until=')
  })

  it('clears all filters and resets to defaults on Clear', async () => {
    fetchMock.mockResolvedValue(makeResponse([]))
    renderAuditView()
    await waitFor(() => expect(fetchMock).toHaveBeenCalled())

    // Apply a filter first
    fireEvent.change(screen.getByRole('combobox', { name: /severity/i }), {
      target: { value: 'critical' },
    })
    fireEvent.click(screen.getByRole('button', { name: /apply/i }))
    await waitFor(() => expect(lastFetchURL()).toContain('severity=critical'))

    // Clear
    fireEvent.click(screen.getByRole('button', { name: /clear/i }))
    await waitFor(() => {
      const url = lastFetchURL()
      expect(url).not.toContain('severity=')
    })
  })

  it('resets to page 0 (offset=0) when a filter is applied', async () => {
    fetchMock.mockImplementation(() =>
      Promise.resolve(
        makeResponse(Array.from({ length: 50 }, (_, i) => makeEntry({ id: `e${i}` })), 200, true),
      ),
    )
    renderAuditView()
    await waitFor(() => expect(fetchMock).toHaveBeenCalled())

    // Advance to page 2
    fireEvent.click(screen.getByRole('button', { name: /next page/i }))
    await waitFor(() => expect(lastFetchURL()).toContain('offset=50'))

    // Apply a filter — should reset offset
    fireEvent.change(screen.getByRole('combobox', { name: /severity/i }), {
      target: { value: 'medium' },
    })
    fireEvent.click(screen.getByRole('button', { name: /apply/i }))
    await waitFor(() => {
      const url = lastFetchURL()
      expect(url).toContain('severity=medium')
      expect(url).toContain('offset=0')
    })
  })
})

describe('AuditView — untrusted-value rendering rule (security A9.1)', () => {
  it('renders entry field values as plain text, not as HTML markup', async () => {
    const xssAction = '<img src=x onerror="window.__auditXss=1">'
    fetchMock.mockResolvedValue(makeResponse([makeEntry({ action: xssAction })]))
    renderAuditView()

    // The payload must appear literally on screen
    await screen.findByText(xssAction)

    // The onerror handler must NOT have fired
    expect((window as unknown as Record<string, unknown>).__auditXss).toBeUndefined()
  })

  it('does not inject markup from event_type, user_id, or resource fields', async () => {
    const tag = '<b>BOLD</b>'
    fetchMock.mockResolvedValue(
      makeResponse([
        makeEntry({
          event_type: tag,
          user_id: tag,
          resource_type: tag,
          resource_id: tag,
        }),
      ]),
    )
    renderAuditView()
    await waitFor(() => expect(screen.queryByTestId('audit-loading')).toBeNull())

    // All four tag strings appear as literal text — not as rendered <b> elements
    const bolds = document.querySelectorAll('b')
    // No injected bold elements from the XSS payloads
    const injected = Array.from(bolds).filter((el) =>
      el.textContent === 'BOLD',
    )
    expect(injected).toHaveLength(0)
  })
})

describe('AuditView — data states', () => {
  it('shows a loading state before the first response', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderAuditView()
    expect(screen.getByTestId('audit-loading')).toBeInTheDocument()
  })

  it('shows an error notice when the request fails', async () => {
    fetchMock.mockResolvedValue(makeResponse([], 500))
    renderAuditView()
    await waitFor(() =>
      expect(screen.getByRole('alert')).toBeInTheDocument(),
    )
    expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument()
  })

  it('retries the request when Retry is clicked', async () => {
    fetchMock.mockImplementation(() => Promise.resolve(makeResponse([], 500)))
    renderAuditView()
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument())

    fetchMock.mockImplementation(() => Promise.resolve(makeResponse([makeEntry()])))
    fireEvent.click(screen.getByRole('button', { name: /retry/i }))

    await waitFor(() =>
      expect(screen.getByTestId('audit-table')).toBeInTheDocument(),
    )
  })

  it('shows the empty state when the response has no entries', async () => {
    fetchMock.mockResolvedValue(makeResponse([]))
    renderAuditView()
    await waitFor(() =>
      expect(screen.getByTestId('audit-empty')).toBeInTheDocument(),
    )
  })

  it('renders entries in the table', async () => {
    fetchMock.mockResolvedValue(
      makeResponse([
        makeEntry({ id: 'e1', action: 'login', severity: 'low' }),
        makeEntry({ id: 'e2', action: 'delete', severity: 'high', result: 'failure' }),
      ]),
    )
    renderAuditView()
    await waitFor(() =>
      expect(screen.getByTestId('audit-table')).toBeInTheDocument(),
    )
    expect(screen.getByText('login')).toBeInTheDocument()
    expect(screen.getByText('delete')).toBeInTheDocument()
  })

  it('shows the page heading and description', () => {
    fetchMock.mockResolvedValue(makeResponse([]))
    renderAuditView()
    expect(
      screen.getByRole('heading', { name: /audit log/i, level: 1 }),
    ).toBeInTheDocument()
  })
})

describe('AuditView — pagination', () => {
  it('hides the pager when there is only one page of results', async () => {
    fetchMock.mockResolvedValue(makeResponse([makeEntry()]))
    renderAuditView()
    await waitFor(() =>
      expect(screen.getByTestId('audit-table')).toBeInTheDocument(),
    )
    expect(screen.queryByTestId('audit-pager')).toBeNull()
  })

  it('shows Next when the server signals has_more=true', async () => {
    fetchMock.mockImplementation(() =>
      Promise.resolve(
        makeResponse(Array.from({ length: 50 }, (_, i) => makeEntry({ id: `e${i}` })), 200, true),
      ),
    )
    renderAuditView()
    await waitFor(() =>
      expect(screen.getByTestId('audit-pager')).toBeInTheDocument(),
    )
    expect(screen.getByRole('button', { name: /next page/i })).not.toBeDisabled()
    expect(screen.getByRole('button', { name: /previous page/i })).toBeDisabled()
  })

  it('hides Next when the server signals has_more=false even on a full page', async () => {
    // Exactly PAGE_SIZE entries but has_more=false — old heuristic would show Next incorrectly.
    fetchMock.mockImplementation(() =>
      Promise.resolve(
        makeResponse(Array.from({ length: 50 }, (_, i) => makeEntry({ id: `e${i}` })), 200, false),
      ),
    )
    renderAuditView()
    await waitFor(() =>
      expect(screen.getByTestId('audit-table')).toBeInTheDocument(),
    )
    // Pager may or may not render (no prev either), but Next must be absent or disabled
    const nextBtn = screen.queryByRole('button', { name: /next page/i })
    if (nextBtn) {
      expect(nextBtn).toBeDisabled()
    }
  })

  it('advances to the next page and sends offset in the request', async () => {
    fetchMock.mockImplementation(() =>
      Promise.resolve(
        makeResponse(Array.from({ length: 50 }, (_, i) => makeEntry({ id: `e${i}` })), 200, true),
      ),
    )
    renderAuditView()
    await waitFor(() => expect(screen.getByTestId('audit-pager')).toBeInTheDocument())

    fireEvent.click(screen.getByRole('button', { name: /next page/i }))
    await waitFor(() => expect(lastFetchURL()).toContain('offset=50'))
  })

  it('goes back to the previous page when Previous is clicked', async () => {
    fetchMock.mockImplementation(() =>
      Promise.resolve(
        makeResponse(Array.from({ length: 50 }, (_, i) => makeEntry({ id: `e${i}` })), 200, true),
      ),
    )
    renderAuditView()
    await waitFor(() => expect(screen.getByTestId('audit-pager')).toBeInTheDocument())

    fireEvent.click(screen.getByRole('button', { name: /next page/i }))
    await waitFor(() => expect(lastFetchURL()).toContain('offset=50'))

    fireEvent.click(screen.getByRole('button', { name: /previous page/i }))
    await waitFor(() => expect(lastFetchURL()).toContain('offset=0'))
  })
})

describe('AuditView — row expansion', () => {
  it('does not render a detail row before the row is clicked', async () => {
    fetchMock.mockResolvedValue(
      makeResponse([makeEntry({ id: 'e1', details: { key: 'val' } })]),
    )
    renderAuditView()
    await waitFor(() => expect(screen.getByTestId('audit-table')).toBeInTheDocument())
    expect(screen.queryByTestId('audit-detail-e1')).toBeNull()
  })

  it('renders details payload when a row with details is clicked', async () => {
    fetchMock.mockResolvedValue(
      makeResponse([makeEntry({ id: 'e1', details: { host: 'srv-01', count: 3 } })]),
    )
    renderAuditView()
    await waitFor(() => expect(screen.getByTestId('audit-row-e1')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('audit-row-e1'))

    await waitFor(() =>
      expect(screen.getByTestId('audit-detail-e1')).toBeInTheDocument(),
    )
    // Details content rendered as text
    expect(screen.getByTestId('audit-detail-e1').textContent).toContain('srv-01')
    expect(screen.getByTestId('audit-detail-e1').textContent).toContain('count')
  })

  it('renders changes payload when a row with changes is clicked', async () => {
    const changes = { before: { name: 'old-name' }, after: { name: 'new-name' } }
    fetchMock.mockResolvedValue(
      makeResponse([makeEntry({ id: 'e2', changes })]),
    )
    renderAuditView()
    await waitFor(() => expect(screen.getByTestId('audit-row-e2')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('audit-row-e2'))

    await waitFor(() =>
      expect(screen.getByTestId('audit-detail-e2')).toBeInTheDocument(),
    )
    expect(screen.getByTestId('audit-detail-e2').textContent).toContain('old-name')
    expect(screen.getByTestId('audit-detail-e2').textContent).toContain('new-name')
  })

  it('collapses the detail row when the expanded row is clicked again', async () => {
    fetchMock.mockResolvedValue(
      makeResponse([makeEntry({ id: 'e1', details: { k: 'v' } })]),
    )
    renderAuditView()
    await waitFor(() => expect(screen.getByTestId('audit-row-e1')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('audit-row-e1'))
    await waitFor(() => expect(screen.getByTestId('audit-detail-e1')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('audit-row-e1'))
    await waitFor(() => expect(screen.queryByTestId('audit-detail-e1')).toBeNull())
  })

  it('renders details payload as text nodes, not as HTML (security A9.1)', async () => {
    fetchMock.mockResolvedValue(
      makeResponse([
        makeEntry({ id: 'e1', details: { xss: '<img src=x onerror="window.__detailXss=1">' } }),
      ]),
    )
    renderAuditView()
    await waitFor(() => expect(screen.getByTestId('audit-row-e1')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('audit-row-e1'))
    await waitFor(() => expect(screen.getByTestId('audit-detail-e1')).toBeInTheDocument())

    expect((window as unknown as Record<string, unknown>).__detailXss).toBeUndefined()
  })

  it('does not expand a row that has no details or changes', async () => {
    fetchMock.mockResolvedValue(makeResponse([makeEntry({ id: 'e1' })]))
    renderAuditView()
    await waitFor(() => expect(screen.getByTestId('audit-row-e1')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('audit-row-e1'))
    expect(screen.queryByTestId('audit-detail-e1')).toBeNull()
  })
})

describe('AuditView — CSV export utilities (unit)', () => {
  it('prefixes cells starting with = to prevent formula injection', () => {
    expect(escapeCsvCell('=SUM(A1:A10)')).toBe("'=SUM(A1:A10)")
  })

  it('prefixes cells starting with + to prevent formula injection', () => {
    expect(escapeCsvCell('+1234')).toBe("'+1234")
  })

  it('prefixes cells starting with - to prevent formula injection', () => {
    expect(escapeCsvCell('-1234')).toBe("'-1234")
  })

  it('prefixes cells starting with @ to prevent formula injection', () => {
    expect(escapeCsvCell('@user')).toBe("'@user")
  })

  it('does not prefix safe values', () => {
    expect(escapeCsvCell('hello')).toBe('hello')
    expect(escapeCsvCell('')).toBe('')
    expect(escapeCsvCell('normal text')).toBe('normal text')
  })

  it('wraps fields containing commas in double quotes', () => {
    expect(escapeCsvCell('hello,world')).toBe('"hello,world"')
  })

  it('wraps fields containing newlines in double quotes', () => {
    expect(escapeCsvCell('line1\nline2')).toBe('"line1\nline2"')
  })

  it('escapes embedded double-quotes by doubling them', () => {
    expect(escapeCsvCell('"quoted"')).toBe('"""quoted"""')
  })

  it('applies injection prefix then quoting when both apply', () => {
    // =hello,world → prefix → '=hello,world → contains comma → "'=hello,world"
    expect(escapeCsvCell('=hello,world')).toBe("\"'=hello,world\"")
  })

  it('buildAuditCSV produces a header row as the first line', () => {
    const csv = buildAuditCSV([])
    const firstLine = csv.split('\n')[0]!
    expect(firstLine).toContain('timestamp')
    expect(firstLine).toContain('action')
    expect(firstLine).toContain('user_id')
    expect(firstLine).toContain('severity')
  })

  it('buildAuditCSV includes entry data in subsequent rows', () => {
    const entry: AuditEntry = {
      id: 'e1',
      timestamp: '2026-01-15T10:30:00Z',
      event_type: 'authentication',
      action: 'login',
      user_id: 'user-1',
      user_type: 'human',
      resource_type: 'session',
      resource_id: 'sess-1',
      resource_name: '',
      result: 'success',
      severity: 'low',
      source: 'controller',
      ip_address: '10.0.0.1',
      method: 'POST',
      path: '/api/v1/web/login',
      error_code: '',
      error_message: '',
    }
    const csv = buildAuditCSV([entry])
    const lines = csv.split('\n')
    expect(lines).toHaveLength(2)
    expect(lines[1]).toContain('login')
    expect(lines[1]).toContain('user-1')
    expect(lines[1]).toContain('2026-01-15T10:30:00Z')
  })

  it('buildAuditCSV escapes injection characters in cell values', () => {
    const entry: AuditEntry = {
      id: 'e1',
      timestamp: '2026-01-15T10:30:00Z',
      event_type: '',
      action: '=cmd /c calc',
      user_id: '+injected',
      user_type: '',
      resource_type: '',
      resource_id: '',
      resource_name: '',
      result: '',
      severity: '',
      source: '',
      ip_address: '',
      method: '',
      path: '',
      error_code: '',
      error_message: '',
    }
    const csv = buildAuditCSV([entry])
    expect(csv).toContain("'=cmd /c calc")
    expect(csv).toContain("'+injected")
  })
})

describe('AuditView — CSV export button', () => {
  it('shows Export CSV button when entries are loaded', async () => {
    fetchMock.mockResolvedValue(makeResponse([makeEntry()]))
    renderAuditView()
    await waitFor(() =>
      expect(screen.getByTestId('audit-export-btn')).toBeInTheDocument(),
    )
  })

  it('hides Export CSV button when the entries list is empty', async () => {
    fetchMock.mockResolvedValue(makeResponse([]))
    renderAuditView()
    await waitFor(() => expect(screen.getByTestId('audit-empty')).toBeInTheDocument())
    expect(screen.queryByTestId('audit-export-btn')).toBeNull()
  })

  it('hides Export CSV button while loading', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderAuditView()
    expect(screen.queryByTestId('audit-export-btn')).toBeNull()
  })
})
