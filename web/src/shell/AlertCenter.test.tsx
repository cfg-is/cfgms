// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, render, screen, fireEvent, waitFor } from '@testing-library/react'
import AlertCenter from './AlertCenter.tsx'

const fetchMock = vi.fn<typeof fetch>()

function alertsResponse(alerts: unknown[] = [], totalAlerts?: number): Response {
  return new Response(
    JSON.stringify({
      alerts,
      total_alerts: totalAlerts ?? alerts.length,
      time_range: { start: '', end: '' },
      generated_at: '',
    }),
    { status: 200, headers: { 'Content-Type': 'application/json' } },
  )
}

function makeAlert(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 'alert-abc123',
    timestamp: '2026-08-18T10:00:00Z',
    device_id: 'device-1',
    severity: 'critical',
    description: 'Config drift detected',
    acknowledged: false,
    silenced: false,
    ...overrides,
  }
}

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
  // Default: empty alerts list for GET, 204 for POST actions.
  fetchMock.mockImplementation((input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : String(input)
    if (url.includes('/dashboard/alerts')) {
      return Promise.resolve(alertsResponse([]))
    }
    return Promise.resolve(new Response(null, { status: 204 }))
  })
})

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('AlertCenter', () => {
  it('renders a bell button with no badge when there are no alerts', () => {
    render(<AlertCenter />)
    const button = screen.getByRole('button', { name: /notifications/i })
    expect(button).toBeInTheDocument()
    expect(screen.queryByTestId('alert-badge')).not.toBeInTheDocument()
  })

  it('opens a popover showing the designed empty state when there are no alerts', async () => {
    render(<AlertCenter />)
    fireEvent.click(screen.getByRole('button', { name: /notifications/i }))
    await waitFor(() => expect(screen.getByText(/no notifications/i)).toBeInTheDocument())
  })

  it('closes on Escape', async () => {
    render(<AlertCenter />)
    fireEvent.click(screen.getByRole('button', { name: /notifications/i }))
    await waitFor(() => expect(screen.getByRole('menu')).toBeInTheDocument())
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(screen.queryByRole('menu')).not.toBeInTheDocument()
  })

  it('shows badge count matching total_alerts after opening', async () => {
    fetchMock.mockImplementation((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : String(input)
      if (url.includes('/dashboard/alerts')) {
        return Promise.resolve(alertsResponse([makeAlert(), makeAlert({ id: 'alert-def456', description: 'Another alert' })]))
      }
      return Promise.resolve(new Response(null, { status: 204 }))
    })

    render(<AlertCenter />)
    expect(screen.queryByTestId('alert-badge')).not.toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /notifications/i }))
    await waitFor(() => expect(screen.getByTestId('alert-badge')).toBeInTheDocument())
    expect(screen.getByTestId('alert-badge')).toHaveTextContent('2')
  })

  it('renders populated alert rows with description and device_id', async () => {
    fetchMock.mockImplementation((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : String(input)
      if (url.includes('/dashboard/alerts')) {
        return Promise.resolve(
          alertsResponse([
            makeAlert({ id: 'id-1', description: 'Critical drift', device_id: 'srv-01', severity: 'critical' }),
            makeAlert({ id: 'id-2', description: 'Warning drift', device_id: 'srv-02', severity: 'warning' }),
          ]),
        )
      }
      return Promise.resolve(new Response(null, { status: 204 }))
    })

    render(<AlertCenter />)
    fireEvent.click(screen.getByRole('button', { name: /notifications/i }))

    await waitFor(() => expect(screen.getAllByTestId('alert-row')).toHaveLength(2))
    expect(screen.getByText('Critical drift')).toBeInTheDocument()
    expect(screen.getByText('srv-01')).toBeInTheDocument()
    expect(screen.getByText('Warning drift')).toBeInTheDocument()
    expect(screen.getByText('srv-02')).toBeInTheDocument()
    expect(screen.queryByText(/no notifications/i)).not.toBeInTheDocument()
  })

  it('renders warning-severity alerts (not critical-only)', async () => {
    fetchMock.mockImplementation((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : String(input)
      if (url.includes('/dashboard/alerts')) {
        return Promise.resolve(
          alertsResponse([makeAlert({ id: 'warn-1', severity: 'warning', description: 'Disk usage high' })]),
        )
      }
      return Promise.resolve(new Response(null, { status: 204 }))
    })

    render(<AlertCenter />)
    fireEvent.click(screen.getByRole('button', { name: /notifications/i }))

    await waitFor(() => expect(screen.getByText('Disk usage high')).toBeInTheDocument())
  })

  it('acknowledge button calls POST /api/v1/alerts/{id}/acknowledge and refreshes', async () => {
    const alertId = 'alert-abc123'
    let fetchCount = 0
    fetchMock.mockImplementation((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : String(input)
      if (url.includes('/dashboard/alerts')) {
        fetchCount += 1
        // Second fetch (after ack) returns alert with acknowledged=true
        const acked = fetchCount > 1
        return Promise.resolve(
          alertsResponse([makeAlert({ acknowledged: acked })]),
        )
      }
      if (url.includes(`/alerts/${alertId}/acknowledge`)) {
        return Promise.resolve(new Response(null, { status: 204 }))
      }
      return Promise.resolve(new Response(null, { status: 204 }))
    })

    render(<AlertCenter />)
    fireEvent.click(screen.getByRole('button', { name: /notifications/i }))

    // Wait for alert row to appear
    await waitFor(() => expect(screen.getByTestId('alert-row')).toBeInTheDocument())

    const ackBtn = screen.getByRole('button', { name: /acknowledge/i })
    await act(async () => {
      fireEvent.click(ackBtn)
    })

    // Verify POST to acknowledge endpoint
    await waitFor(() => {
      const calls = fetchMock.mock.calls.map((c) => ({
        url: typeof c[0] === 'string' ? c[0] : String(c[0]),
        method: (c[1] as RequestInit | undefined)?.method ?? 'GET',
      }))
      expect(calls.some((c) => c.url.includes(`/alerts/${alertId}/acknowledge`) && c.method === 'POST')).toBe(true)
    })

    // Verify re-fetch (refresh after action)
    await waitFor(() => {
      const getCalls = fetchMock.mock.calls.filter((c) => {
        const url = typeof c[0] === 'string' ? c[0] : String(c[0])
        return url.includes('/dashboard/alerts')
      })
      expect(getCalls.length).toBeGreaterThanOrEqual(2)
    })
  })

  it('silence button calls POST /api/v1/alerts/{id}/silence with until and refreshes', async () => {
    const alertId = 'alert-abc123'
    let fetchCount = 0
    fetchMock.mockImplementation((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : String(input)
      if (url.includes('/dashboard/alerts')) {
        fetchCount += 1
        // After silence, alert is gone (silenced alerts are excluded)
        const silenced = fetchCount > 1
        return Promise.resolve(alertsResponse(silenced ? [] : [makeAlert()]))
      }
      if (url.includes(`/alerts/${alertId}/silence`)) {
        return Promise.resolve(new Response(null, { status: 204 }))
      }
      return Promise.resolve(new Response(null, { status: 204 }))
    })

    render(<AlertCenter />)
    fireEvent.click(screen.getByRole('button', { name: /notifications/i }))

    await waitFor(() => expect(screen.getByTestId('alert-row')).toBeInTheDocument())

    const silenceBtn = screen.getByRole('button', { name: /silence/i })
    await act(async () => {
      fireEvent.click(silenceBtn)
    })

    // Verify POST to silence endpoint with until in body
    await waitFor(() => {
      const silenceCalls = fetchMock.mock.calls.filter((c) => {
        const url = typeof c[0] === 'string' ? c[0] : String(c[0])
        return url.includes(`/alerts/${alertId}/silence`)
      })
      expect(silenceCalls).toHaveLength(1)
      const init = silenceCalls[0]?.[1] as RequestInit
      expect(init.method).toBe('POST')
      const body = JSON.parse(init.body as string) as Record<string, unknown>
      expect(typeof body.until).toBe('string')
      // until must be in the future (a silence duration)
      expect(new Date(body.until as string).getTime()).toBeGreaterThan(Date.now())
    })

    // After silence, the list refreshes and the alert is gone
    await waitFor(() => expect(screen.getByText(/no notifications/i)).toBeInTheDocument())
  })

  it('surfaces a 403 from the acknowledge POST and does not refresh the list', async () => {
    const alertId = 'alert-abc123'
    fetchMock.mockImplementation((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : String(input)
      if (url.includes('/dashboard/alerts')) {
        return Promise.resolve(alertsResponse([makeAlert()]))
      }
      if (url.includes(`/alerts/${alertId}/acknowledge`)) {
        return Promise.resolve(
          new Response(
            JSON.stringify({ error: { code: 'FORBIDDEN', message: 'insufficient permission' } }),
            { status: 403, headers: { 'Content-Type': 'application/json' } },
          ),
        )
      }
      return Promise.resolve(new Response(null, { status: 204 }))
    })

    render(<AlertCenter />)
    fireEvent.click(screen.getByRole('button', { name: /notifications/i }))
    await waitFor(() => expect(screen.getByTestId('alert-row')).toBeInTheDocument())

    const getCallsBefore = fetchMock.mock.calls.filter((c) =>
      (typeof c[0] === 'string' ? c[0] : String(c[0])).includes('/dashboard/alerts'),
    ).length

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /acknowledge/i }))
    })

    // The refusal is surfaced, not swallowed.
    await waitFor(() =>
      expect(screen.getByTestId('alert-action-error')).toHaveTextContent('insufficient permission'),
    )

    // A failed action must NOT re-fetch: re-rendering the same unacknowledged
    // state would read as success.
    const getCallsAfter = fetchMock.mock.calls.filter((c) =>
      (typeof c[0] === 'string' ? c[0] : String(c[0])).includes('/dashboard/alerts'),
    ).length
    expect(getCallsAfter).toBe(getCallsBefore)

    // The alert is still listed and still actionable.
    expect(screen.getByTestId('alert-row')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /acknowledge/i })).toBeInTheDocument()
  })

  it('surfaces a 500 from the silence POST and does not refresh the list', async () => {
    const alertId = 'alert-abc123'
    fetchMock.mockImplementation((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : String(input)
      if (url.includes('/dashboard/alerts')) {
        return Promise.resolve(alertsResponse([makeAlert()]))
      }
      if (url.includes(`/alerts/${alertId}/silence`)) {
        return Promise.resolve(new Response(null, { status: 500 }))
      }
      return Promise.resolve(new Response(null, { status: 204 }))
    })

    render(<AlertCenter />)
    fireEvent.click(screen.getByRole('button', { name: /notifications/i }))
    await waitFor(() => expect(screen.getByTestId('alert-row')).toBeInTheDocument())

    const getCallsBefore = fetchMock.mock.calls.filter((c) =>
      (typeof c[0] === 'string' ? c[0] : String(c[0])).includes('/dashboard/alerts'),
    ).length

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /silence/i }))
    })

    // No error envelope in the body: fall back to the status code.
    await waitFor(() =>
      expect(screen.getByTestId('alert-action-error')).toHaveTextContent('500'),
    )

    const getCallsAfter = fetchMock.mock.calls.filter((c) =>
      (typeof c[0] === 'string' ? c[0] : String(c[0])).includes('/dashboard/alerts'),
    ).length
    expect(getCallsAfter).toBe(getCallsBefore)
    expect(screen.getByTestId('alert-row')).toBeInTheDocument()
  })

  it('surfaces a network failure from the silence POST without an unhandled rejection', async () => {
    const alertId = 'alert-abc123'
    const unhandled = vi.fn()
    window.addEventListener('unhandledrejection', unhandled)
    fetchMock.mockImplementation((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : String(input)
      if (url.includes('/dashboard/alerts')) {
        return Promise.resolve(alertsResponse([makeAlert()]))
      }
      if (url.includes(`/alerts/${alertId}/silence`)) {
        return Promise.reject(new Error('Failed to fetch'))
      }
      return Promise.resolve(new Response(null, { status: 204 }))
    })

    try {
      render(<AlertCenter />)
      fireEvent.click(screen.getByRole('button', { name: /notifications/i }))
      await waitFor(() => expect(screen.getByTestId('alert-row')).toBeInTheDocument())

      await act(async () => {
        fireEvent.click(screen.getByRole('button', { name: /silence/i }))
      })

      await waitFor(() =>
        expect(screen.getByTestId('alert-action-error')).toHaveTextContent('Failed to fetch'),
      )
      expect(unhandled).not.toHaveBeenCalled()
    } finally {
      window.removeEventListener('unhandledrejection', unhandled)
    }
  })

  it('clears a stale action error when the popover is reopened', async () => {
    const alertId = 'alert-abc123'
    fetchMock.mockImplementation((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : String(input)
      if (url.includes('/dashboard/alerts')) {
        return Promise.resolve(alertsResponse([makeAlert()]))
      }
      if (url.includes(`/alerts/${alertId}/acknowledge`)) {
        return Promise.resolve(new Response(null, { status: 403 }))
      }
      return Promise.resolve(new Response(null, { status: 204 }))
    })

    render(<AlertCenter />)
    fireEvent.click(screen.getByRole('button', { name: /notifications/i }))
    await waitFor(() => expect(screen.getByTestId('alert-row')).toBeInTheDocument())

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /acknowledge/i }))
    })
    await waitFor(() => expect(screen.getByTestId('alert-action-error')).toBeInTheDocument())

    fireEvent.click(screen.getByRole('button', { name: /notifications/i })) // close
    fireEvent.click(screen.getByRole('button', { name: /notifications/i })) // reopen
    await waitFor(() => expect(screen.getByTestId('alert-row')).toBeInTheDocument())
    expect(screen.queryByTestId('alert-action-error')).not.toBeInTheDocument()
  })

  it('renders the load-failure state when GET /dashboard/alerts returns non-2xx', async () => {
    fetchMock.mockImplementation((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : String(input)
      if (url.includes('/dashboard/alerts')) {
        return Promise.resolve(new Response(null, { status: 500 }))
      }
      return Promise.resolve(new Response(null, { status: 204 }))
    })

    render(<AlertCenter />)
    fireEvent.click(screen.getByRole('button', { name: /notifications/i }))

    await waitFor(() => expect(screen.getByText(/failed to load alerts/i)).toBeInTheDocument())
    // The failure state replaces the empty state — they must not both render.
    expect(screen.queryByText(/no notifications/i)).not.toBeInTheDocument()
    expect(screen.queryByTestId('alert-row')).not.toBeInTheDocument()
    expect(screen.queryByTestId('alert-badge')).not.toBeInTheDocument()
  })

  it('renders the load-failure state when GET /dashboard/alerts rejects', async () => {
    fetchMock.mockImplementation((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : String(input)
      if (url.includes('/dashboard/alerts')) {
        return Promise.reject(new Error('Failed to fetch'))
      }
      return Promise.resolve(new Response(null, { status: 204 }))
    })

    render(<AlertCenter />)
    fireEvent.click(screen.getByRole('button', { name: /notifications/i }))

    await waitFor(() => expect(screen.getByText(/failed to load alerts/i)).toBeInTheDocument())
    expect(screen.queryByText(/no notifications/i)).not.toBeInTheDocument()
  })

  it('renders the load-failure state when GET /dashboard/alerts returns a non-object body', async () => {
    fetchMock.mockImplementation((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : String(input)
      if (url.includes('/dashboard/alerts')) {
        return Promise.resolve(
          new Response('"not-an-object"', {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          }),
        )
      }
      return Promise.resolve(new Response(null, { status: 204 }))
    })

    render(<AlertCenter />)
    fireEvent.click(screen.getByRole('button', { name: /notifications/i }))

    await waitFor(() => expect(screen.getByText(/failed to load alerts/i)).toBeInTheDocument())
  })

  it('shows Acknowledge button only when alert is not yet acknowledged', async () => {
    fetchMock.mockImplementation((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : String(input)
      if (url.includes('/dashboard/alerts')) {
        return Promise.resolve(
          alertsResponse([makeAlert({ acknowledged: true })]),
        )
      }
      return Promise.resolve(new Response(null, { status: 204 }))
    })

    render(<AlertCenter />)
    fireEvent.click(screen.getByRole('button', { name: /notifications/i }))
    await waitFor(() => expect(screen.getByTestId('alert-row')).toBeInTheDocument())

    // Already acknowledged: no Acknowledge button, but Silence is still present
    expect(screen.queryByRole('button', { name: /acknowledge/i })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: /silence/i })).toBeInTheDocument()
  })
})
