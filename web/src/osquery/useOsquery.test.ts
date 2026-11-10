// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * useOsquery test suite (Issue #5460, Epic #5300). Real apiFetch; only global
 * fetch is stubbed at the network edge.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, renderHook, waitFor } from '@testing-library/react'
import {
  OsqueryRequestError,
  parseOsqueryCatalog,
  parseOsqueryResults,
  resultKind,
  runOsqueryQuery,
  tallyResults,
  useOsqueryCatalog,
  useOsqueryRun,
} from './useOsquery.ts'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  vi.unstubAllGlobals()
  cleanup()
})

function jsonResponse(status: number, body: unknown = {}, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  })
}

const request = { catalogId: 'process_list', params: { name_prefix: 'cfgms' }, selector: 'tag:edge' }

describe('parseOsqueryCatalog', () => {
  it('reads ids and parameter schemas and drops malformed entries', () => {
    const catalog = parseOsqueryCatalog([
      { id: 'host_info', params: [] },
      {
        id: 'process_list',
        params: [
          { name: 'name_prefix', type: 'enum', allowed_values: ['cfgms', 'osquery'] },
          { name: 'path', type: 'charset' },
          { name: 'odd', type: 'sql' },
          { type: 'enum' },
        ],
      },
      { params: [] },
      'junk',
    ])
    expect(catalog.map((e) => e.id)).toEqual(['host_info', 'process_list'])
    expect(catalog[1]?.params).toEqual([
      { name: 'name_prefix', type: 'enum', allowedValues: ['cfgms', 'osquery'] },
      { name: 'path', type: 'charset', allowedValues: [] },
    ])
  })

  it('treats null as an empty catalog and rejects a non-array payload', () => {
    expect(parseOsqueryCatalog(null)).toEqual([])
    expect(() => parseOsqueryCatalog({ id: 'x' })).toThrow(/unexpected response shape/)
  })
})

describe('parseOsqueryResults', () => {
  it('useOsquery maps per-steward errors without dropping other results', () => {
    const results = parseOsqueryResults({
      results: [
        { steward_id: 'steward-a', rows: [{ name: 'a', pid: '1' }] },
        { steward_id: 'steward-b', error: 'steward did not respond' },
        { steward_id: 'steward-c' },
        { steward_id: 'steward-d', rows: [] },
        { steward_id: 'steward-e', rows: [{ name: 'e' }] },
      ],
    })
    expect(results.map((r) => r.stewardId)).toEqual([
      'steward-a',
      'steward-b',
      'steward-c',
      'steward-d',
      'steward-e',
    ])
    expect(results.map(resultKind)).toEqual(['rows', 'err', 'none', 'none', 'rows'])
    expect(results[1]?.error).toBe('steward did not respond')
    expect(results[0]?.rows).toEqual([{ name: 'a', pid: '1' }])
    expect(tallyResults(results)).toEqual({ total: 5, rows: 2, none: 2, err: 1 })
  })

  it('coerces non-string cell values to text and drops results without a steward id', () => {
    const results = parseOsqueryResults({
      results: [{ steward_id: 's1', rows: [{ pid: 12, name: null, ok: true }] }, { rows: [] }, 5],
    })
    expect(results).toHaveLength(1)
    expect(results[0]?.rows[0]).toEqual({ pid: '12', name: '', ok: 'true' })
  })

  it('an error wins over rows and an absent results array is an empty list', () => {
    const results = parseOsqueryResults({ results: [{ steward_id: 's', rows: [{ a: '1' }], error: 'boom' }] })
    expect(resultKind(results[0]!)).toBe('err')
    expect(parseOsqueryResults({ results: [] })).toEqual([])
    expect(parseOsqueryResults({})).toEqual([])
    expect(() => parseOsqueryResults({ results: 'x' })).toThrow(/unexpected response shape/)
  })
})

describe('runOsqueryQuery', () => {
  it('posts catalog_id, params and selector and returns the parsed results', async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(200, { data: { results: [{ steward_id: 's1', rows: [{ name: 'x' }] }] } }),
    )
    const results = await runOsqueryQuery(request)
    expect(results).toHaveLength(1)
    const [url, init] = fetchMock.mock.calls[0]!
    expect(String(url)).toBe('/api/v1/osquery/query')
    expect(init?.method).toBe('POST')
    expect(JSON.parse(String(init?.body))).toEqual({
      catalog_id: 'process_list',
      params: { name_prefix: 'cfgms' },
      selector: 'tag:edge',
    })
  })

  it.each([
    [400, 'rejected'],
    [403, 'forbidden'],
    [503, 'unavailable'],
    [500, 'error'],
    [401, 'cancelled'],
  ] as const)('maps HTTP %i to the %s failure', async (status, kind) => {
    fetchMock.mockResolvedValue(jsonResponse(status, { error: { message: 'nope' } }))
    const failure = await runOsqueryQuery(request).catch((e: unknown) => e)
    expect(failure).toBeInstanceOf(OsqueryRequestError)
    expect((failure as OsqueryRequestError).kind).toBe(kind)
  })

  it('maps a network failure to the generic error', async () => {
    fetchMock.mockRejectedValue(new TypeError('network down'))
    const failure = await runOsqueryQuery(request).catch((e: unknown) => e)
    expect((failure as OsqueryRequestError).kind).toBe('error')
  })
})

describe('useOsqueryCatalog', () => {
  it('loads the catalog and exposes a retry after a failure', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(500))
    const { result } = renderHook(() => useOsqueryCatalog())
    expect(result.current.loading).toBe(true)
    await waitFor(() => expect(result.current.error).toMatch(/500/))
    expect(result.current.catalog).toEqual([])

    fetchMock.mockResolvedValueOnce(jsonResponse(200, { data: [{ id: 'host_info', params: [] }] }))
    act(() => result.current.retry())
    await waitFor(() => expect(result.current.catalog.map((e) => e.id)).toEqual(['host_info']))
    expect(result.current.error).toBeNull()
    expect(String(fetchMock.mock.calls[1]![0])).toBe('/api/v1/osquery/catalog')
  })
})

describe('useOsqueryRun', () => {
  it('moves from idle through running to done with the results', async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, { data: { results: [{ steward_id: 's1' }] } }))
    const { result } = renderHook(() => useOsqueryRun())
    expect(result.current.state.phase).toBe('idle')
    await act(async () => {
      await result.current.run(request)
    })
    expect(result.current.state.phase).toBe('done')
    if (result.current.state.phase === 'done') expect(result.current.state.results).toHaveLength(1)
  })

  it('reports the request failure phase', async () => {
    fetchMock.mockResolvedValue(jsonResponse(403, { error: 'cross tenant' }))
    const { result } = renderHook(() => useOsqueryRun())
    await act(async () => {
      await result.current.run(request)
    })
    expect(result.current.state.phase).toBe('forbidden')
  })
})
