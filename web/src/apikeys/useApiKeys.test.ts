// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  createApiKey,
  deleteApiKey,
  parseApiKeyCreateResult,
  parseApiKeyInfo,
  parseApiKeyList,
  splitPermissions,
} from './useApiKeys.ts'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  vi.unstubAllGlobals()
})

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

describe('parsers', () => {
  it('rejects entries without an id and coerces bad fields', () => {
    expect(parseApiKeyInfo(null)).toBeNull()
    expect(parseApiKeyInfo({ name: 'x' })).toBeNull()
    expect(parseApiKeyInfo({ id: 'k', name: 5, permissions: ['a', 3], expires_at: 7 })).toEqual({
      id: 'k',
      name: '',
      permissions: ['a'],
      created_at: '',
      expires_at: null,
      tenant_id: '',
    })
  })

  it('parseApiKeyList accepts null, skips bad items, throws on non-arrays', () => {
    expect(parseApiKeyList(null)).toEqual([])
    expect(parseApiKeyList([{ id: 'a' }, 'junk'])).toHaveLength(1)
    expect(() => parseApiKeyList({})).toThrow()
  })

  it('parseApiKeyCreateResult requires the key', () => {
    expect(parseApiKeyCreateResult({ id: 'a' })).toBeNull()
    expect(parseApiKeyCreateResult({ id: 'a', key: 's' })?.key).toBe('s')
  })

  it('splitPermissions splits on commas and newlines and trims', () => {
    expect(splitPermissions(' a:b,\n c:d ,, \ne:f')).toEqual(['a:b', 'c:d', 'e:f'])
    expect(splitPermissions('')).toEqual([])
  })
})

describe('createApiKey / deleteApiKey', () => {
  it('createApiKey surfaces string and object server errors verbatim', async () => {
    fetchMock.mockResolvedValueOnce(json(400, { error: 'bad perms' }))
    await expect(createApiKey({ name: 'n', permissions: [] })).rejects.toThrow('bad perms')
    fetchMock.mockResolvedValueOnce(json(400, { error: { message: 'nope' } }))
    await expect(createApiKey({ name: 'n', permissions: [] })).rejects.toThrow('nope')
    fetchMock.mockResolvedValueOnce(new Response('', { status: 500 }))
    await expect(createApiKey({ name: 'n', permissions: [] })).rejects.toThrow('Create failed — 500')
  })

  it('createApiKey rejects a response without a secret', async () => {
    fetchMock.mockResolvedValueOnce(json(201, { data: { id: 'a' } }))
    await expect(createApiKey({ name: 'n', permissions: [] })).rejects.toThrow(/unexpected response/i)
  })

  it('deleteApiKey encodes the id and reports failure', async () => {
    fetchMock.mockResolvedValueOnce(new Response(null, { status: 204 }))
    await deleteApiKey('a/b')
    expect(String(fetchMock.mock.calls[0]?.[0])).toBe('/api/v1/api-keys/a%2Fb')
    fetchMock.mockResolvedValueOnce(new Response('', { status: 404 }))
    await expect(deleteApiKey('x')).rejects.toThrow('Delete failed — 404')
  })
})
