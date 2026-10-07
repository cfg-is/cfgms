// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import CrossingBanner from './CrossingBanner.tsx'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})
afterEach(() => {
  vi.useRealTimers()
  vi.unstubAllGlobals()
  cleanup()
})

function entry(expiresInMs: number) {
  return {
    tenantId: 'msp-a',
    crossingId: 'c-1',
    expiresAt: new Date(Date.now() + expiresInMs).toISOString(),
    reason: 'outage response',
  }
}

describe('CrossingBanner', () => {
  it('shows target, reason and a live countdown', () => {
    vi.useFakeTimers()
    render(<CrossingBanner entry={entry(90_000)} onEnded={vi.fn()} onExpired={vi.fn()} />)
    expect(screen.getByTestId('crossing-banner-target')).toHaveTextContent('msp-a')
    expect(screen.getByTestId('crossing-banner-reason')).toHaveTextContent('outage response')
    expect(screen.getByTestId('crossing-banner-countdown')).toHaveTextContent('1:30')
    act(() => {
      vi.advanceTimersByTime(30_000)
    })
    expect(screen.getByTestId('crossing-banner-countdown')).toHaveTextContent('1:00')
  })

  it('refetches (onExpired) once when the countdown reaches zero', () => {
    vi.useFakeTimers()
    const onExpired = vi.fn()
    render(<CrossingBanner entry={entry(3000)} onEnded={vi.fn()} onExpired={onExpired} />)
    expect(onExpired).not.toHaveBeenCalled()
    act(() => {
      vi.advanceTimersByTime(3500)
    })
    expect(onExpired).toHaveBeenCalledTimes(1)
    expect(screen.getByTestId('crossing-banner-countdown')).toHaveTextContent('0:00')
    act(() => {
      vi.advanceTimersByTime(5000)
    })
    expect(onExpired).toHaveBeenCalledTimes(1)
  })

  it('End session calls DELETE on the crossing path and reports ended', async () => {
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ data: {} }), { status: 200 }))
    const onEnded = vi.fn()
    render(<CrossingBanner entry={entry(60_000)} onEnded={onEnded} onExpired={vi.fn()} />)
    fireEvent.click(screen.getByTestId('crossing-end-btn'))
    await waitFor(() => expect(onEnded).toHaveBeenCalledTimes(1))
    const [url, init] = fetchMock.mock.calls[0]!
    expect(url).toBe('/api/v1/tenants/msp-a/access-grants/c-1')
    expect(init?.method).toBe('DELETE')
  })

  it('keeps the banner and shows the error when End session fails', async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ error: { code: 'NOT_CROSSING_OWNER', message: 'only the invoker can end it' } }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    const onEnded = vi.fn()
    render(<CrossingBanner entry={entry(60_000)} onEnded={onEnded} onExpired={vi.fn()} />)
    fireEvent.click(screen.getByTestId('crossing-end-btn'))
    expect(await screen.findByTestId('crossing-banner-error')).toHaveTextContent('only the invoker')
    expect(onEnded).not.toHaveBeenCalled()
    expect(screen.getByTestId('crossing-end-btn')).not.toBeDisabled()
  })
})
