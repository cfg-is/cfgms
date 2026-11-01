// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, renderHook } from '@testing-library/react'
import { activeCrossingsPollMs, notifyActiveCrossingsChanged, useActiveCrossings } from './useActiveCrossings.ts'

const fetchMock = vi.fn<typeof fetch>()

function feed(items: unknown[]): Response {
  return new Response(JSON.stringify({ data: items }), { status: 200 })
}
const item = (over: Record<string, unknown> = {}) => ({
  id: 'c-1',
  tenant_id: 'msp-a',
  kind: 'break_glass',
  principal_name: 'root-op',
  reason_category: 'account_recovery',
  expires_at: '2030-01-01T00:00:00Z',
  tenant_name: 'MSP A',
  ...over,
})

beforeEach(() => {
  vi.useFakeTimers()
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})
afterEach(() => {
  vi.useRealTimers()
  vi.unstubAllGlobals()
})

describe('useActiveCrossings', () => {
  it('fetches on mount, parses the feed and polls on the interval', async () => {
    fetchMock.mockImplementation(() => Promise.resolve(feed([item()])))
    const { result } = renderHook(() => useActiveCrossings())
    await act(async () => {})
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(String(fetchMock.mock.calls[0]![0])).toContain('/api/v1/tenant-crossings/active')
    expect(result.current.crossings).toHaveLength(1)
    expect(result.current.crossings[0]).toMatchObject({ id: 'c-1', tenantName: 'MSP A', principalName: 'root-op' })

    await act(async () => {
      await vi.advanceTimersByTimeAsync(activeCrossingsPollMs)
    })
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  it('drops a crossing that leaves the feed', async () => {
    fetchMock.mockImplementationOnce(() => Promise.resolve(feed([item()])))
    fetchMock.mockImplementation(() => Promise.resolve(feed([])))
    const { result } = renderHook(() => useActiveCrossings())
    await act(async () => {})
    expect(result.current.crossings).toHaveLength(1)
    await act(async () => {
      await vi.advanceTimersByTimeAsync(activeCrossingsPollMs)
    })
    expect(result.current.crossings).toHaveLength(0)
  })

  it('stops polling on unmount', async () => {
    fetchMock.mockImplementation(() => Promise.resolve(feed([])))
    const { unmount } = renderHook(() => useActiveCrossings())
    await act(async () => {})
    unmount()
    await act(async () => {
      await vi.advanceTimersByTimeAsync(activeCrossingsPollMs * 3)
    })
    notifyActiveCrossingsChanged()
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('refetches immediately when notified', async () => {
    fetchMock.mockImplementation(() => Promise.resolve(feed([])))
    renderHook(() => useActiveCrossings())
    await act(async () => {})
    await act(async () => {
      notifyActiveCrossingsChanged()
    })
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  it('reports an error when the first fetch fails and keeps data on a later failure', async () => {
    fetchMock.mockImplementationOnce(() => Promise.resolve(new Response('{}', { status: 500 })))
    fetchMock.mockImplementationOnce(() => Promise.resolve(feed([item()])))
    fetchMock.mockImplementation(() => Promise.resolve(new Response('{}', { status: 500 })))
    const { result } = renderHook(() => useActiveCrossings())
    await act(async () => {})
    expect(result.current.error).not.toBeNull()
    await act(async () => {
      await vi.advanceTimersByTimeAsync(activeCrossingsPollMs)
    })
    expect(result.current.crossings).toHaveLength(1)
    await act(async () => {
      await vi.advanceTimersByTimeAsync(activeCrossingsPollMs)
    })
    expect(result.current.crossings).toHaveLength(1)
    expect(result.current.error).toBeNull()
  })

  it('drops malformed entries', async () => {
    fetchMock.mockImplementation(() => Promise.resolve(feed([item(), { kind: 'grant' }, 'x'])))
    const { result } = renderHook(() => useActiveCrossings())
    await act(async () => {})
    expect(result.current.crossings).toHaveLength(1)
  })
})
