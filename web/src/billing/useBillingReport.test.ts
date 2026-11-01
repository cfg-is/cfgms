// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { parseRootReport, parseTenantReport, useBillingReport } from './useBillingReport.ts'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  vi.unstubAllGlobals()
})

function json(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

describe('parseRootReport', () => {
  it('keeps only label and sizes on a client, dropping name and id', () => {
    const [msp] = parseRootReport({
      msps: [
        {
          id: 'm',
          name: 'M',
          clients: [{ label: 'AB12', endpoint_count: 3, tech_count: 1, name: 'Secret', id: 'x' }],
        },
      ],
    })
    expect(msp!.clients).toEqual([{ label: 'AB12', endpointCount: 3, techCount: 1 }])
  })

  it('defaults malformed and missing fields to zero values', () => {
    expect(parseRootReport(null)).toEqual([])
    const [msp] = parseRootReport({ msps: [{ tech_count: -2, endpoint_count: 'x' }] })
    expect(msp).toMatchObject({ techCount: 0, endpointCount: 0, clients: [] })
    expect(msp!.metrics.byPlatform.map((p) => p.count)).toEqual([0, 0, 0, 0])
    expect(msp!.metrics.byVersion).toEqual([])
  })
})

describe('parseTenantReport', () => {
  it('parses named clients and metrics', () => {
    const r = parseTenantReport({
      id: 't',
      name: 'T',
      client_count: 1,
      metrics: { endpoints_online: 2, endpoints_by_version: { '1.0': 2 } },
      clients: [{ id: 'c', name: 'C', endpoint_count: 2, tech_count: 0 }],
    })
    expect(r.clients).toEqual([{ id: 'c', name: 'C', endpointCount: 2, techCount: 0 }])
    expect(r.metrics.online).toBe(2)
    expect(r.metrics.byVersion).toEqual([{ name: '1.0', count: 2 }])
  })
})

describe('useBillingReport', () => {
  it('loads the root endpoint when root, and surfaces the data', async () => {
    fetchMock.mockResolvedValue(json(200, { data: { msps: [] } }))
    const { result } = renderHook(() => useBillingReport(true, ''))
    expect(result.current.loading).toBe(true)
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.data).toEqual({ kind: 'root', msps: [] })
    expect(fetchMock.mock.calls.map((c) => c[0])).toEqual(['/api/v1/billing/report'])
  })

  it('loads the tenant endpoint otherwise, encoding the id', async () => {
    fetchMock.mockResolvedValue(json(200, { data: { id: 'a/b', clients: [] } }))
    const { result } = renderHook(() => useBillingReport(false, 'a/b'))
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.data?.kind).toBe('tenant')
    expect(fetchMock.mock.calls.map((c) => c[0])).toEqual(['/api/v1/tenants/a%2Fb/billing-report'])
  })

  it('reports the server message on failure, and a status line when none is sent', async () => {
    fetchMock.mockResolvedValueOnce(json(403, { error: { message: 'nope' } }))
    const first = renderHook(() => useBillingReport(true, ''))
    await waitFor(() => expect(first.result.current.error).toBe('nope'))

    fetchMock.mockResolvedValueOnce(json(502, {}))
    const second = renderHook(() => useBillingReport(true, ''))
    await waitFor(() =>
      expect(second.result.current.error).toBe('GET /api/v1/billing/report — 502'),
    )
  })

  it('reports a network failure', async () => {
    fetchMock.mockRejectedValue(new Error('offline'))
    const { result } = renderHook(() => useBillingReport(true, ''))
    await waitFor(() => expect(result.current.error).toBe('offline'))
  })
})
