// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  buildListQuery,
  DirectoryError,
  listDirectory,
  listGroupMembers,
  listUserGroups,
  probeDirectoryAccess,
} from './directoryApi.ts'

const fetchMock = vi.fn<typeof fetch>()

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify({ data, timestamp: 't' }), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})
afterEach(() => vi.unstubAllGlobals())

describe('buildListQuery', () => {
  it('emits only set filters and trims q', () => {
    expect(buildListQuery({})).toBe('')
    const query = buildListQuery({
      q: '  ann ',
      source: 'm365',
      managed: 'false',
      limit: 50,
      pageToken: 'tok+/=',
    })
    const params = new URLSearchParams(query.slice(1))
    expect(params.get('q')).toBe('ann')
    expect(params.get('source')).toBe('m365')
    expect(params.get('managed')).toBe('false')
    expect(params.get('limit')).toBe('50')
    expect(params.get('page_token')).toBe('tok+/=')
  })
})

describe('directory requests', () => {
  it('lists users with the expected query parameters', async () => {
    fetchMock.mockResolvedValue(
      json({
        items: [{ id: 'u1', source: 'ad', display_name: 'Ann', managed: true, stale: true, enabled: false }],
        next_page_token: 'n1',
      }),
    )
    const result = await listDirectory('users', { q: 'ann', source: 'ad', managed: 'true', limit: 25, pageToken: 'p' })
    const url = new URL(String(fetchMock.mock.calls[0]![0]), 'https://x')
    expect(url.pathname).toBe('/api/v1/directory/users')
    expect(Object.fromEntries(url.searchParams)).toEqual({
      q: 'ann',
      source: 'ad',
      managed: 'true',
      limit: '25',
      page_token: 'p',
    })
    expect(result).toMatchObject({
      status: 'ok',
      value: { nextPageToken: 'n1', items: [{ id: 'u1', displayName: 'Ann', managed: true, stale: true, enabled: false }] },
    })
  })

  it('addresses groups, members and user groups by escaped path', async () => {
    fetchMock.mockImplementation(() => Promise.resolve(json({ members: [], groups: [] })))
    await listGroupMembers('ad', 'g/1', { limit: 100, pageToken: 'm' })
    await listUserGroups('m365', 'u 1', { limit: 100 })
    expect(String(fetchMock.mock.calls[0]![0])).toBe(
      '/api/v1/directory/groups/ad/g%2F1/members?limit=100&page_token=m',
    )
    expect(String(fetchMock.mock.calls[1]![0])).toBe('/api/v1/directory/users/m365/u%201/groups?limit=100')
  })

  it('reports a 404 as the neutral notFound outcome, not an error', async () => {
    fetchMock.mockResolvedValue(json({}, 404))
    expect(await listDirectory('groups', {})).toEqual({ status: 'notFound' })
    expect(await listGroupMembers('ad', 'x', {})).toEqual({ status: 'notFound' })
  })

  it('throws a DirectoryError for other failures and bad shapes', async () => {
    fetchMock.mockResolvedValueOnce(json({}, 503))
    await expect(listDirectory('users', {})).rejects.toBeInstanceOf(DirectoryError)
    fetchMock.mockResolvedValueOnce(json({ items: 'nope' }))
    await expect(listDirectory('users', {})).rejects.toThrow('unexpected response shape')
  })

  it('drops rows without an id', async () => {
    fetchMock.mockResolvedValue(json({ items: [{ display_name: 'x' }, { id: 'ok' }] }))
    const result = await listDirectory('users', {})
    expect(result.status === 'ok' && result.value.items.map((i) => i.id)).toEqual(['ok'])
  })
})

describe('probeDirectoryAccess', () => {
  it('is true only on a 2xx', async () => {
    fetchMock.mockResolvedValueOnce(json({ items: [] }))
    expect(await probeDirectoryAccess()).toBe(true)
    fetchMock.mockResolvedValueOnce(json({}, 403))
    expect(await probeDirectoryAccess()).toBe(false)
    fetchMock.mockRejectedValueOnce(new Error('net'))
    expect(await probeDirectoryAccess()).toBe(false)
  })
})
