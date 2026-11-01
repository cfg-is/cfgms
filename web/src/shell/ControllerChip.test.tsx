// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, render, screen, fireEvent, waitFor } from '@testing-library/react'
import ControllerChip from './ControllerChip.tsx'

const fetchMock = vi.fn<typeof fetch>()

function health(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})

afterEach(() => {
  vi.useRealTimers()
  vi.unstubAllGlobals()
})

describe('ControllerChip', () => {
  it('renders healthy and version for a healthy response', async () => {
    fetchMock.mockResolvedValue(
      health(200, { data: { status: 'healthy', version: '0.42.1' } }),
    )
    render(<ControllerChip />)
    await waitFor(() => expect(screen.getByText(/healthy/)).toBeTruthy())
    expect(screen.getByText(/v0\.42\.1/)).toBeTruthy()
    expect(fetchMock.mock.calls[0]?.[0]).toBe('/api/v1/health')
  })

  it('renders degraded when the controller reports degraded (503)', async () => {
    fetchMock.mockResolvedValue(
      health(503, { data: { status: 'degraded', version: '0.42.1' } }),
    )
    render(<ControllerChip />)
    await waitFor(() => expect(screen.getByText(/degraded/)).toBeTruthy())
  })

  it('renders unreachable when the fetch fails', async () => {
    fetchMock.mockRejectedValue(new TypeError('network'))
    render(<ControllerChip />)
    await waitFor(() => expect(screen.getByText(/unreachable/)).toBeTruthy())
  })

  it('renders unreachable for an unparseable response', async () => {
    fetchMock.mockResolvedValue(new Response('<html>', { status: 502 }))
    render(<ControllerChip />)
    await waitFor(() => expect(screen.getByText(/unreachable/)).toBeTruthy())
  })

  it('shows a loading state before the first response', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    render(<ControllerChip />)
    expect(screen.getByText(/checking/)).toBeTruthy()
  })

  it('popover lists endpoint origin and version', async () => {
    fetchMock.mockResolvedValue(
      health(200, { data: { status: 'healthy', version: '0.42.1' } }),
    )
    render(<ControllerChip />)
    await waitFor(() => expect(screen.getByText(/healthy/)).toBeTruthy())
    fireEvent.click(screen.getByRole('button', { name: /controller/i }))
    expect(screen.getByText('Endpoint')).toBeTruthy()
    expect(screen.getByText(window.location.origin)).toBeTruthy()
    expect(screen.getByText('Version')).toBeTruthy()
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(screen.queryByText('Endpoint')).toBeNull()
  })

  it('polls every 30s and pauses while the tab is hidden', async () => {
    vi.useFakeTimers()
    fetchMock.mockResolvedValue(
      health(200, { data: { status: 'healthy', version: '1' } }),
    )
    render(<ControllerChip />)
    await act(async () => {})
    expect(fetchMock).toHaveBeenCalledTimes(1)
    await act(async () => {
      await vi.advanceTimersByTimeAsync(30_000)
    })
    expect(fetchMock).toHaveBeenCalledTimes(2)

    Object.defineProperty(document, 'hidden', { configurable: true, value: true })
    await act(async () => {
      document.dispatchEvent(new Event('visibilitychange'))
      await vi.advanceTimersByTimeAsync(60_000)
    })
    expect(fetchMock).toHaveBeenCalledTimes(2)

    Object.defineProperty(document, 'hidden', { configurable: true, value: false })
    await act(async () => {
      document.dispatchEvent(new Event('visibilitychange'))
    })
    expect(fetchMock).toHaveBeenCalledTimes(3)
  })
})
