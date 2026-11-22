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
  parseOsqueryResponse,
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
    expect(tallyResults(results)).toEqual({ total: 5, rows: 2, none: 2, unreached: 0, err: 1 })
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

describe('parseOsqueryResults outcomes', () => {
  it('maps the three wire outcomes through', () => {
    const results = parseOsqueryResults({
      results: [
        { steward_id: 's-1', rows: [{ hostname: 'h' }], outcome: 'answered' },
        { steward_id: 's-2', outcome: 'answered' },
        {
          steward_id: 's-3',
          error: 'osquery: steward not connected to osquery stream',
          outcome: 'not_connected',
          last_seen: '2026-11-22T13:40:00Z',
        },
        { steward_id: 's-4', error: 'osquery execution failed', outcome: 'failed' },
      ],
    })
    expect(results.map((r) => r.outcome)).toEqual(['answered', 'answered', 'not_connected', 'failed'])
    expect(results.map(resultKind)).toEqual(['rows', 'none', 'unreached', 'err'])
    expect(results[2]?.lastSeen).toBe('2026-11-22T13:40:00Z')
    expect(results[2]?.error).toBe('osquery: steward not connected to osquery stream')
    expect(results[3]?.error).toBe('osquery execution failed')
  })

  it('an error wins over a wire answered outcome; not_connected and failed stay as sent', () => {
    const results = parseOsqueryResults({
      results: [
        { steward_id: 'ans-err', rows: [{ a: '1' }], error: 'boom', outcome: 'answered' },
        { steward_id: 'ans-err-empty', error: 'boom', outcome: 'answered', last_seen: '2026-11-22T13:40:00Z' },
        { steward_id: 'ans-ok', rows: [{ a: '1' }], outcome: 'answered' },
        { steward_id: 'nc-no-err', outcome: 'not_connected' },
        { steward_id: 'failed-no-err', outcome: 'failed' },
      ],
    })
    expect(results.map((r) => r.outcome)).toEqual(['failed', 'failed', 'answered', 'not_connected', 'failed'])
    expect(results.map(resultKind)).toEqual(['err', 'err', 'rows', 'unreached', 'err'])
    expect(results[0]?.error).toBe('boom')
    expect(results[1]?.lastSeen).toBeNull()
  })

  it('a derived summary counts an answered-with-error result as failed', () => {
    const parsed = parseOsqueryResponse({
      results: [
        { steward_id: 'a', rows: [{ x: '1' }], outcome: 'answered' },
        { steward_id: 'b', error: 'boom', outcome: 'answered' },
      ],
    })
    expect(parsed.summary).toMatchObject({ matched: 2, answered: 1, notConnected: 0, failed: 1 })
  })

  it('derives a missing or unknown outcome from the error', () => {
    const results = parseOsqueryResults({
      results: [
        { steward_id: 'a', rows: [{ x: '1' }] },
        { steward_id: 'b', error: 'boom' },
        { steward_id: 'c', outcome: 'exploded', error: 'boom' },
        { steward_id: 'd', outcome: 'exploded' },
        { steward_id: 'e', outcome: 42 },
      ],
    })
    expect(results.map((r) => r.outcome)).toEqual(['answered', 'failed', 'failed', 'answered', 'answered'])
    expect(results.every((r) => r.lastSeen === null)).toBe(true)
  })

  it('keeps last_seen only on not_connected and only when it is a real check-in time', () => {
    const results = parseOsqueryResults({
      results: [
        { steward_id: 'never', outcome: 'not_connected', error: 'x' },
        { steward_id: 'zero', outcome: 'not_connected', error: 'x', last_seen: '0001-01-01T00:00:00Z' },
        { steward_id: 'junk', outcome: 'not_connected', error: 'x', last_seen: 'yesterday-ish' },
        { steward_id: 'num', outcome: 'not_connected', error: 'x', last_seen: 1732284000000 },
        { steward_id: 'ok', outcome: 'answered', last_seen: '2026-11-22T13:40:00Z' },
        { steward_id: 'bad', outcome: 'failed', error: 'x', last_seen: '2026-11-22T13:40:00Z' },
        { steward_id: 'legacy', error: 'x', last_seen: '2026-11-22T13:40:00Z' },
      ],
    })
    expect(results.map((r) => r.lastSeen)).toEqual([null, null, null, null, null, null, null])
    expect(results.slice(0, 4).map(resultKind)).toEqual(['unreached', 'unreached', 'unreached', 'unreached'])
  })
})

describe('parseOsqueryResponse summary', () => {
  const results = [
    { steward_id: 'a', rows: [{ x: '1' }], outcome: 'answered' },
    { steward_id: 'b', outcome: 'answered' },
    { steward_id: 'c', outcome: 'not_connected', error: 'x' },
    { steward_id: 'd', outcome: 'failed', error: 'y' },
  ]

  it('uses the wire summary when its counts are valid', () => {
    const parsed = parseOsqueryResponse({
      summary: { matched: 9, answered: 5, not_connected: 3, failed: 1, queried_at: '2026-11-22T14:03:05.123Z' },
      results,
    })
    expect(parsed.results).toHaveLength(4)
    expect(parsed.summary).toEqual({
      matched: 9,
      answered: 5,
      notConnected: 3,
      failed: 1,
      queriedAt: Date.parse('2026-11-22T14:03:05.123Z'),
    })
  })

  it('derives the counts from the results when the summary is absent', () => {
    expect(parseOsqueryResponse({ results }).summary).toEqual({
      matched: 4,
      answered: 2,
      notConnected: 1,
      failed: 1,
      queriedAt: null,
    })
  })

  it.each([
    ['a negative count', { matched: 4, answered: -1, not_connected: 1, failed: 1 }],
    ['a non-integer count', { matched: 4, answered: 2.5, not_connected: 1, failed: 1 }],
    ['a string count', { matched: '4', answered: 2, not_connected: 1, failed: 1 }],
    ['a missing count', { matched: 4, answered: 2, failed: 1 }],
    ['a non-object summary', 'summary'],
    ['an array summary', [4, 2, 1, 1]],
  ])('derives the counts when the summary has %s', (_, summary) => {
    const parsed = parseOsqueryResponse({ summary, results })
    expect(parsed.summary).toMatchObject({ matched: 4, answered: 2, notConnected: 1, failed: 1 })
  })

  it('parses queried_at independently of the counts and nulls an invalid one', () => {
    const at = '2026-11-22T14:03:05.123Z'
    expect(parseOsqueryResponse({ summary: { matched: 'x', queried_at: at }, results }).summary.queriedAt).toBe(
      Date.parse(at),
    )
    expect(
      parseOsqueryResponse({ summary: { matched: 4, answered: 2, not_connected: 1, failed: 1, queried_at: 'soon' }, results })
        .summary.queriedAt,
    ).toBeNull()
    expect(
      parseOsqueryResponse({ summary: { matched: 4, answered: 2, not_connected: 1, failed: 1, queried_at: 5 }, results })
        .summary.queriedAt,
    ).toBeNull()
  })

  it('an empty payload is no results and a zero summary; a bad shape throws', () => {
    expect(parseOsqueryResponse(null)).toEqual({
      results: [],
      summary: { matched: 0, answered: 0, notConnected: 0, failed: 0, queriedAt: null },
    })
    expect(() => parseOsqueryResponse({ results: 'x' })).toThrow(/unexpected response shape/)
  })

  it('tallies the not-reached kind apart from errors', () => {
    expect(tallyResults(parseOsqueryResponse({ results }).results)).toEqual({
      total: 4,
      rows: 1,
      none: 1,
      unreached: 1,
      err: 1,
    })
  })
})

describe('runOsqueryQuery', () => {
  it('posts catalog_id, params and selector and returns the parsed results', async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(200, { data: { results: [{ steward_id: 's1', rows: [{ name: 'x' }] }] } }),
    )
    const { results, summary } = await runOsqueryQuery(request)
    expect(results).toHaveLength(1)
    expect(summary).toEqual({ matched: 1, answered: 1, notConnected: 0, failed: 0, queriedAt: null })
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
    if (result.current.state.phase === 'done') {
      expect(result.current.state.results).toHaveLength(1)
      expect(result.current.state.summary.matched).toBe(1)
    }
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
