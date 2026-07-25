// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * LogsPanel suite (Story #2940): fetch and render of steward log records,
 * loading/error/empty states, untrusted wire data validation, chronological
 * ordering, and URL encoding of the steward ID.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router'
import LogsPanel, { parseLogsResponse } from './LogsPanel.tsx'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function renderPanel(stewardId = 'stw-001') {
  return render(
    <MemoryRouter initialEntries={[`/stewards/${encodeURIComponent(stewardId)}`]}>
      <Routes>
        <Route path="/stewards/:id" element={<LogsPanel />} />
      </Routes>
    </MemoryRouter>,
  )
}

function makeEvent(overrides: Partial<{
  timestamp: string
  level: string
  message: string
  component: string
}> = {}) {
  return {
    timestamp: overrides.timestamp ?? '2026-07-23T10:00:00Z',
    level: overrides.level ?? 'INFO',
    message: overrides.message ?? 'Test log message',
    component: overrides.component ?? 'test-component',
  }
}

function mockLogs(events: unknown[] = []) {
  fetchMock.mockResolvedValue(
    new Response(
      JSON.stringify({
        data: { events },
        timestamp: new Date().toISOString(),
      }),
      { status: 200, headers: { 'Content-Type': 'application/json' } },
    ),
  )
}

// ---------------------------------------------------------------------------
// parseLogsResponse (untrusted wire data)
// ---------------------------------------------------------------------------

describe('parseLogsResponse (untrusted wire data)', () => {
  it('rejects non-object payloads', () => {
    expect(() => parseLogsResponse(null)).toThrow()
    expect(() => parseLogsResponse('str')).toThrow()
    expect(() => parseLogsResponse(42)).toThrow()
  })

  it('rejects payloads without an events array', () => {
    expect(() => parseLogsResponse({})).toThrow()
    expect(() => parseLogsResponse({ events: 'not-array' })).toThrow()
  })

  it('returns an empty array for an empty events list', () => {
    expect(parseLogsResponse({ events: [] })).toEqual([])
  })

  it('skips entries with no detection field', () => {
    const result = parseLogsResponse({
      events: [
        { correlation_id: 'x' }, // no detection
        { detection: makeEvent(), correlation_id: 'y' },
      ],
    })
    expect(result).toHaveLength(1)
    expect(result[0]?.correlationId).toBe('y')
  })

  it('skips detection entries that are not objects', () => {
    const result = parseLogsResponse({
      events: [
        { detection: 'not-an-object' },
        { detection: makeEvent(), correlation_id: 'valid' },
      ],
    })
    expect(result).toHaveLength(1)
  })

  it('coerces missing event fields to empty strings', () => {
    const result = parseLogsResponse({ events: [{ detection: {} }] })
    expect(result).toHaveLength(1)
    expect(result[0]?.detection.timestamp).toBe('')
    expect(result[0]?.detection.level).toBe('')
    expect(result[0]?.detection.message).toBe('')
    expect(result[0]?.detection.component).toBe('')
  })

  it('parses a full correlated record with detection and outcome', () => {
    const detection = makeEvent({ timestamp: '2026-07-23T10:00:00Z', message: 'detected' })
    const outcome = makeEvent({ timestamp: '2026-07-23T10:00:01Z', message: 'resolved' })
    const result = parseLogsResponse({
      events: [{ correlation_id: 'corr-1', detection, outcome, pending_outcome: false }],
    })
    expect(result).toHaveLength(1)
    expect(result[0]?.correlationId).toBe('corr-1')
    expect(result[0]?.detection.message).toBe('detected')
    expect(result[0]?.outcome?.message).toBe('resolved')
    expect(result[0]?.pendingOutcome).toBe(false)
  })

  it('sets pendingOutcome=true when the field is true', () => {
    const result = parseLogsResponse({
      events: [{ detection: makeEvent(), pending_outcome: true }],
    })
    expect(result[0]?.pendingOutcome).toBe(true)
  })

  it('outcome is null when absent or not an object', () => {
    const result = parseLogsResponse({
      events: [
        { detection: makeEvent() },
        { detection: makeEvent(), outcome: 'bad' },
      ],
    })
    expect(result[0]?.outcome).toBeNull()
    expect(result[1]?.outcome).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// Fetch and rendering
// ---------------------------------------------------------------------------

describe('LogsPanel fetch and rendering', () => {
  it('fetches the correct endpoint for the route :id', async () => {
    mockLogs([{ detection: makeEvent({ message: 'boot complete' }), correlation_id: '' }])
    renderPanel('stw-42')

    expect(await screen.findByText('boot complete')).toBeTruthy()
    const url = String(fetchMock.mock.calls[0]?.[0])
    expect(url).toBe('/api/v1/stewards/stw-42/logs')
  })

  it('encodes special characters in the steward ID', async () => {
    mockLogs([{ detection: makeEvent(), correlation_id: '' }])
    renderPanel('stw/special id')

    await screen.findByText('Test log message')
    const url = String(fetchMock.mock.calls[0]?.[0])
    expect(url).toBe('/api/v1/stewards/stw%2Fspecial%20id/logs')
  })

  it('renders log entries with level and message', async () => {
    mockLogs([
      { detection: makeEvent({ level: 'ERROR', message: 'disk full' }), correlation_id: '' },
      { detection: makeEvent({ level: 'INFO', message: 'task started' }), correlation_id: '' },
    ])
    renderPanel()

    expect(await screen.findByText('disk full')).toBeTruthy()
    expect(screen.getByText('ERROR')).toBeTruthy()
    expect(screen.getByText('task started')).toBeTruthy()
    expect(screen.getByText('INFO')).toBeTruthy()
  })

  it('renders events in chronological order (as returned by the API)', async () => {
    mockLogs([
      { detection: makeEvent({ timestamp: '2026-07-23T09:00:00Z', message: 'first event' }), correlation_id: 'a' },
      { detection: makeEvent({ timestamp: '2026-07-23T10:00:00Z', message: 'second event' }), correlation_id: 'b' },
    ])
    renderPanel()

    const messages = await screen.findAllByText(/first event|second event/)
    expect(messages[0]?.textContent).toBe('first event')
    expect(messages[1]?.textContent).toBe('second event')
  })

  it('renders the outcome event when a correlated pair is present', async () => {
    mockLogs([
      {
        correlation_id: 'corr-x',
        detection: makeEvent({ message: 'module drift detected' }),
        outcome: makeEvent({ message: 'module applied' }),
      },
    ])
    renderPanel()

    expect(await screen.findByText('module drift detected')).toBeTruthy()
    expect(screen.getByText('module applied')).toBeTruthy()
  })

  it('renders a pending-outcome indicator when pending_outcome is true', async () => {
    mockLogs([
      {
        detection: makeEvent({ message: 'pending change' }),
        pending_outcome: true,
      },
    ])
    renderPanel()

    await screen.findByText('pending change')
    expect(screen.getByTestId('log-pending')).toBeTruthy()
  })
})

// ---------------------------------------------------------------------------
// Loading state
// ---------------------------------------------------------------------------

describe('loading state', () => {
  it('shows a loading indicator before the response arrives', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderPanel()
    expect(screen.getByTestId('logs-loading')).toBeTruthy()
  })

  it('loading state is distinct from error state', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderPanel()
    expect(screen.queryByRole('alert')).toBeNull()
    expect(screen.queryByTestId('logs-empty')).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// Empty state
// ---------------------------------------------------------------------------

describe('empty state', () => {
  it('renders a distinct empty state when the events array is empty', async () => {
    mockLogs([])
    renderPanel()

    expect(await screen.findByTestId('logs-empty')).toBeTruthy()
    expect(screen.queryByTestId('logs-list')).toBeNull()
    expect(screen.queryByRole('alert')).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// Error state
// ---------------------------------------------------------------------------

describe('error states', () => {
  it('renders an error alert on a non-ok HTTP response', async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ error: 'internal error' }), { status: 500 }),
    )
    renderPanel()

    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toContain('500')
    expect(screen.queryByTestId('logs-loading')).toBeNull()
    expect(screen.queryByTestId('logs-empty')).toBeNull()
  })

  it('renders an error alert on network failure with a retry button', async () => {
    fetchMock.mockRejectedValueOnce(new Error('network down'))
    mockLogs([{ detection: makeEvent({ message: 'recovered' }), correlation_id: '' }])
    renderPanel()

    await screen.findByRole('alert')
    fireEvent.click(screen.getByRole('button', { name: /retry/i }))
    expect(await screen.findByText('recovered')).toBeTruthy()
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  it('renders an error alert on malformed response body (wire validation)', async () => {
    fetchMock.mockResolvedValue(
      new Response(
        JSON.stringify({ data: { not_events: [] } }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    )
    renderPanel()

    const alert = await screen.findByRole('alert')
    expect(alert).toBeTruthy()
    expect(screen.queryByTestId('logs-list')).toBeNull()
  })

  it('error state is distinct from empty state', async () => {
    fetchMock.mockResolvedValue(
      new Response('{}', { status: 503 }),
    )
    renderPanel()

    await screen.findByRole('alert')
    expect(screen.queryByTestId('logs-empty')).toBeNull()
  })
})
