// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { renderHook, waitFor, act } from '@testing-library/react'
import { useAlerts } from './useAlerts.ts'

const fetchMock = vi.fn<typeof fetch>()

function feed(alerts: unknown[]): Response {
  return new Response(JSON.stringify({ alerts, total_alerts: alerts.length }), { status: 200 })
}

function urlOf(input: RequestInfo | URL): string {
  return typeof input === 'string' ? input : String(input)
}

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})
afterEach(() => vi.unstubAllGlobals())

describe('useAlerts', () => {
  it('does not fetch while closed', () => {
    renderHook(() => useAlerts(false))
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('omits include_silenced by default and sets it when requested', async () => {
    fetchMock.mockImplementation(() => Promise.resolve(feed([])))
    const { rerender } = renderHook(({ s }) => useAlerts(true, { includeSilenced: s }), {
      initialProps: { s: false },
    })
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1))
    expect(urlOf(fetchMock.mock.calls[0]![0])).not.toContain('include_silenced')
    rerender({ s: true })
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2))
    expect(urlOf(fetchMock.mock.calls[1]![0])).toContain('include_silenced=true')
  })

  it('parses acknowledged_by and silenced_by', async () => {
    fetchMock.mockImplementation(() =>
      Promise.resolve(
        feed([{ id: 'a', acknowledged: true, acknowledged_by: 'alice', silenced_by: 'bob' }]),
      ),
    )
    const { result } = renderHook(() => useAlerts(true))
    await waitFor(() => expect(result.current.alerts).toHaveLength(1))
    expect(result.current.alerts[0]!.acknowledged_by).toBe('alice')
    expect(result.current.alerts[0]!.silenced_by).toBe('bob')
  })

  it('unsilence POSTs and refreshes on success, reports failure otherwise', async () => {
    fetchMock.mockImplementation((input) =>
      Promise.resolve(urlOf(input).includes('/unsilence') ? new Response(null, { status: 200 }) : feed([])),
    )
    const { result } = renderHook(() => useAlerts(true))
    await waitFor(() => expect(result.current.loading).toBe(false))
    let res: Awaited<ReturnType<typeof result.current.unsilence>> | undefined
    await act(async () => {
      res = await result.current.unsilence('a/b')
    })
    expect(res).toEqual({ ok: true })
    expect(fetchMock.mock.calls.some(([i]) => urlOf(i).endsWith('/api/v1/alerts/a%2Fb/unsilence'))).toBe(true)

    fetchMock.mockImplementation(() => Promise.resolve(new Response('{}', { status: 403 })))
    await act(async () => {
      res = await result.current.unsilence('x')
    })
    expect(res?.ok).toBe(false)
  })
})
