// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import AlertsView from './AlertsView.tsx'

const fetchMock = vi.fn<typeof fetch>()

function feed(alerts: unknown[]): Response {
  return new Response(JSON.stringify({ alerts, total_alerts: alerts.length }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

function makeAlert(o: Record<string, unknown> = {}) {
  return {
    id: 'a1',
    timestamp: '2026-08-18T10:00:00Z',
    device_id: 'dev-1',
    severity: 'critical',
    description: 'Config drift',
    acknowledged: false,
    silenced: false,
    ...o,
  }
}

const crit = makeAlert({ id: 'c1', severity: 'critical', description: 'Crit finding' })
const warn = makeAlert({ id: 'w1', severity: 'warning', description: 'Warn finding' })
const silenced = makeAlert({
  id: 's1',
  severity: 'warning',
  description: 'Silenced finding',
  silenced: true,
  silenced_by: 'bob',
})

function urlOf(input: RequestInfo | URL): string {
  return typeof input === 'string' ? input : String(input)
}

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})
afterEach(() => vi.unstubAllGlobals())

describe('AlertsView', () => {
  it('shows loading, then rows', async () => {
    fetchMock.mockResolvedValue(feed([crit]))
    render(<AlertsView />)
    expect(screen.getByTestId('alerts-loading')).toBeInTheDocument()
    expect(await screen.findByText('Crit finding')).toBeInTheDocument()
  })

  it('shows the empty state', async () => {
    fetchMock.mockResolvedValue(feed([]))
    render(<AlertsView />)
    expect(await screen.findByTestId('alerts-empty')).toBeInTheDocument()
  })

  it('shows an error with retry', async () => {
    fetchMock.mockResolvedValueOnce(new Response('x', { status: 500 }))
    render(<AlertsView />)
    expect(await screen.findByTestId('alerts-error')).toBeInTheDocument()
    fetchMock.mockResolvedValue(feed([crit]))
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByText('Crit finding')).toBeInTheDocument()
  })

  it('severity filter hides non-matching severities', async () => {
    fetchMock.mockResolvedValue(feed([crit, warn]))
    render(<AlertsView />)
    await screen.findByText('Crit finding')
    expect(screen.getByText('Warn finding')).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('Severity filter'), { target: { value: 'critical' } })
    expect(screen.queryByText('Warn finding')).not.toBeInTheDocument()
    expect(screen.getByText('Crit finding')).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('Severity filter'), { target: { value: 'warning' } })
    expect(screen.queryByText('Crit finding')).not.toBeInTheDocument()
    expect(screen.getByText('Warn finding')).toBeInTheDocument()
  })

  it('Show silenced requests include_silenced=true and shows silenced rows', async () => {
    fetchMock.mockImplementation((input) =>
      Promise.resolve(
        urlOf(input).includes('include_silenced=true') ? feed([crit, silenced]) : feed([crit]),
      ),
    )
    render(<AlertsView />)
    await screen.findByText('Crit finding')
    expect(screen.queryByText('Silenced finding')).not.toBeInTheDocument()
    fireEvent.click(screen.getByLabelText('Show silenced'))
    expect(await screen.findByText('Silenced finding')).toBeInTheDocument()
    expect(fetchMock.mock.calls.some(([i]) => urlOf(i).includes('include_silenced=true'))).toBe(true)
    expect(screen.getByRole('button', { name: /Unsilence: Silenced finding/ })).toBeInTheDocument()
  })

  it('Unsilence posts to /unsilence and the row returns to the active list', async () => {
    let unsilenced = false
    fetchMock.mockImplementation((input, init) => {
      const url = urlOf(input)
      if (url.endsWith('/api/v1/alerts/s1/unsilence')) {
        expect(init?.method).toBe('POST')
        unsilenced = true
        return Promise.resolve(new Response(null, { status: 200 }))
      }
      return Promise.resolve(
        feed([unsilenced ? { ...silenced, silenced: false } : silenced]),
      )
    })
    render(<AlertsView />)
    fireEvent.click(screen.getByLabelText('Show silenced'))
    fireEvent.click(await screen.findByRole('button', { name: /Unsilence: Silenced finding/ }))
    await waitFor(() =>
      expect(screen.getByRole('button', { name: /^Silence: Silenced finding/ })).toBeInTheDocument(),
    )
    expect(screen.queryByRole('button', { name: /Unsilence:/ })).not.toBeInTheDocument()
  })

  it('shows an error when unsilence is refused', async () => {
    fetchMock.mockImplementation((input) =>
      Promise.resolve(
        urlOf(input).endsWith('/unsilence')
          ? new Response(JSON.stringify({ error: { message: 'forbidden' } }), { status: 403 })
          : feed([silenced]),
      ),
    )
    render(<AlertsView />)
    fireEvent.click(screen.getByLabelText('Show silenced'))
    fireEvent.click(await screen.findByRole('button', { name: /Unsilence:/ }))
    expect(await screen.findByTestId('alerts-action-error')).toHaveTextContent('forbidden')
  })

  it('shows acknowledged by on acknowledged rows', async () => {
    fetchMock.mockResolvedValue(
      feed([makeAlert({ acknowledged: true, acknowledged_by: 'alice' })]),
    )
    render(<AlertsView />)
    expect(await screen.findByText('acknowledged by alice')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Acknowledge:/ })).not.toBeInTheDocument()
  })

  it('severity element has an accessible text label for warn and crit', async () => {
    fetchMock.mockResolvedValue(feed([crit, warn]))
    render(<AlertsView />)
    await screen.findByText('Crit finding')
    const sevs = screen.getAllByTestId('alert-severity')
    expect(sevs[0]).toHaveTextContent('Critical')
    expect(sevs[1]).toHaveTextContent('Warning')
  })
})
