// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * useReportsDashboard suite (Story #4585): the reporting window is sent as
 * `days` on both the overview and trends requests, and changing it re-fetches.
 * Fetch stubbing follows ReportsDashboardView.test.tsx: vi.stubGlobal with
 * fresh Response objects per call.
 */
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { useReportsDashboard } from './useReportsDashboard.ts'
import type { ReportWindow } from './useReportsDashboard.ts'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  vi.unstubAllGlobals()
})

function urlOf(input: Parameters<typeof fetch>[0]): string {
  if (typeof input === 'string') return input
  if (input instanceof URL) return input.toString()
  return input.url
}

function stubOk(): void {
  fetchMock.mockImplementation((input) => {
    const url = urlOf(input)
    const body = url.includes('/overview')
      ? { summary: {}, metadata: {}, time_range: {} }
      : { charts: [] }
    return Promise.resolve(
      new Response(JSON.stringify(body), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
  })
}

function requestedUrls(): string[] {
  return fetchMock.mock.calls.map(([input]) => urlOf(input))
}

describe('useReportsDashboard window', () => {
  it('sends the selected window on the overview and trends requests', async () => {
    stubOk()
    const { result } = renderHook(() => useReportsDashboard(14))
    await waitFor(() => expect(result.current.loading).toBe(false))

    const urls = requestedUrls()
    expect(urls.some((u) => u.includes('/api/v1/reports/dashboard/overview') && u.includes('days=14'))).toBe(true)
    expect(urls.some((u) => u.includes('/api/v1/reports/dashboard/trends') && u.includes('days=14'))).toBe(true)
  })

  it('defaults to a 7 day window', async () => {
    stubOk()
    const { result } = renderHook(() => useReportsDashboard())
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(requestedUrls().every((u) => u.includes('days=7'))).toBe(true)
  })

  it('re-fetches both endpoints when the window changes', async () => {
    stubOk()
    const { result, rerender } = renderHook(
      ({ days }: { days: ReportWindow }) => useReportsDashboard(days),
      { initialProps: { days: 7 as ReportWindow } },
    )
    await waitFor(() => expect(result.current.loading).toBe(false))

    rerender({ days: 30 })
    await waitFor(() => {
      const urls = requestedUrls()
      expect(urls.filter((u) => u.includes('days=30'))).toHaveLength(2)
    })
    await waitFor(() => expect(result.current.loading).toBe(false))
  })

  it('surfaces an error when a request fails', async () => {
    fetchMock.mockImplementation(() =>
      Promise.resolve(new Response('boom', { status: 500 })),
    )
    const { result } = renderHook(() => useReportsDashboard(7))
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.error).toMatch(/500/)
  })
})
