// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

import { renderHook, waitFor, act } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import {
  useAuditEntries,
  parseAuditEntries,
  DEFAULT_FILTERS,
} from './useAuditEntries.ts'
import type { AuditFilters } from './useAuditEntries.ts'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})

afterEach(() => {
  vi.unstubAllGlobals()
})

function makeEntry(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    id: 'e1',
    timestamp: '2026-01-01T00:00:00Z',
    event_type: 'authentication',
    action: 'login',
    user_id: 'user-1',
    user_type: 'human',
    resource_type: 'session',
    resource_id: 'sess-1',
    resource_name: '',
    result: 'success',
    severity: 'low',
    source: 'controller',
    ip_address: '1.2.3.4',
    method: 'POST',
    path: '/api/v1/web/login',
    error_code: '',
    error_message: '',
    ...overrides,
  }
}

function makeResponse(entries: object[], status = 200) {
  return new Response(
    JSON.stringify({ data: entries, timestamp: new Date().toISOString() }),
    { status, headers: { 'Content-Type': 'application/json' } },
  )
}

describe('parseAuditEntries', () => {
  it('parses a valid array of entries', () => {
    const entries = parseAuditEntries([makeEntry()])
    expect(entries).toHaveLength(1)
    expect(entries[0].id).toBe('e1')
    expect(entries[0].action).toBe('login')
    expect(entries[0].severity).toBe('low')
  })

  it('skips entries with an empty id', () => {
    const entries = parseAuditEntries([makeEntry({ id: '' })])
    expect(entries).toHaveLength(0)
  })

  it('skips entries with a missing id', () => {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { id: _id, ...withoutId } = makeEntry()
    const entries = parseAuditEntries([withoutId])
    expect(entries).toHaveLength(0)
  })

  it('skips non-object items', () => {
    const entries = parseAuditEntries([null, 'string', 42, makeEntry()])
    expect(entries).toHaveLength(1)
  })

  it('throws on non-array input', () => {
    expect(() => parseAuditEntries(null)).toThrow('unexpected response shape')
    expect(() => parseAuditEntries({})).toThrow('unexpected response shape')
    expect(() => parseAuditEntries('string')).toThrow('unexpected response shape')
  })

  it('coerces non-string fields to empty string', () => {
    const entries = parseAuditEntries([
      makeEntry({ action: 42, event_type: null, severity: true }),
    ])
    expect(entries).toHaveLength(1)
    expect(entries[0].action).toBe('')
    expect(entries[0].event_type).toBe('')
    expect(entries[0].severity).toBe('')
  })

  it('parses all declared string fields', () => {
    const entry = makeEntry({
      user_type: 'system',
      resource_type: 'config',
      resource_name: 'main.yaml',
      error_code: 'UNAUTHORIZED',
      error_message: 'not allowed',
      ip_address: '10.0.0.1',
      method: 'PUT',
      path: '/api/v1/cfg',
    })
    const [parsed] = parseAuditEntries([entry])
    expect(parsed.user_type).toBe('system')
    expect(parsed.resource_type).toBe('config')
    expect(parsed.resource_name).toBe('main.yaml')
    expect(parsed.error_code).toBe('UNAUTHORIZED')
    expect(parsed.ip_address).toBe('10.0.0.1')
  })
})

describe('useAuditEntries', () => {
  it('starts in loading state before the response arrives', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    const { result } = renderHook(() => useAuditEntries(DEFAULT_FILTERS))
    expect(result.current.loading).toBe(true)
    expect(result.current.entries).toEqual([])
    expect(result.current.error).toBeNull()
  })

  it('always includes limit and offset in the request URL', async () => {
    fetchMock.mockResolvedValue(makeResponse([]))
    const filters: AuditFilters = { ...DEFAULT_FILTERS, limit: 25, offset: 50 }
    renderHook(() => useAuditEntries(filters))
    await waitFor(() => expect(fetchMock).toHaveBeenCalled())
    const url = fetchMock.mock.calls[0][0] as string
    expect(url).toContain('limit=25')
    expect(url).toContain('offset=50')
  })

  it('includes only non-empty optional filter params', async () => {
    fetchMock.mockResolvedValue(makeResponse([]))
    const filters: AuditFilters = {
      ...DEFAULT_FILTERS,
      severity: 'high',
      result: 'failure',
      user_id: 'user-abc',
      event_type: 'authentication',
      action: '',
      since: '',
      until: '',
      module: '',
    }
    renderHook(() => useAuditEntries(filters))
    await waitFor(() => expect(fetchMock).toHaveBeenCalled())
    const url = fetchMock.mock.calls[0][0] as string
    expect(url).toContain('severity=high')
    expect(url).toContain('result=failure')
    expect(url).toContain('user_id=user-abc')
    expect(url).toContain('event_type=authentication')
    expect(url).not.toContain('action=')
    expect(url).not.toContain('since=')
    expect(url).not.toContain('until=')
    expect(url).not.toContain('module=')
  })

  it('includes since, until, and module when set', async () => {
    fetchMock.mockResolvedValue(makeResponse([]))
    const filters: AuditFilters = {
      ...DEFAULT_FILTERS,
      since: '2026-01-01T00:00:00Z',
      until: '2026-01-31T23:59:59Z',
      module: 'patch',
    }
    renderHook(() => useAuditEntries(filters))
    await waitFor(() => expect(fetchMock).toHaveBeenCalled())
    const url = fetchMock.mock.calls[0][0] as string
    expect(url).toContain('since=2026-01-01T00%3A00%3A00Z')
    expect(url).toContain('until=2026-01-31T23%3A59%3A59Z')
    expect(url).toContain('module=patch')
  })

  it('returns parsed entries on success and clears loading', async () => {
    fetchMock.mockResolvedValue(
      makeResponse([makeEntry(), makeEntry({ id: 'e2', action: 'logout' })]),
    )
    const { result } = renderHook(() => useAuditEntries(DEFAULT_FILTERS))
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.entries).toHaveLength(2)
    expect(result.current.entries[1].action).toBe('logout')
    expect(result.current.error).toBeNull()
  })

  it('surfaces a user-presentable error on non-ok response', async () => {
    fetchMock.mockResolvedValue(makeResponse([], 503))
    const { result } = renderHook(() => useAuditEntries(DEFAULT_FILTERS))
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.error).toContain('503')
    expect(result.current.entries).toEqual([])
  })

  it('surfaces a user-presentable error on network failure', async () => {
    fetchMock.mockRejectedValue(new Error('network down'))
    const { result } = renderHook(() => useAuditEntries(DEFAULT_FILTERS))
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.error).toBe('network down')
  })

  it('returns a fallback error string when the thrown error has no message', async () => {
    fetchMock.mockRejectedValue({})
    const { result } = renderHook(() => useAuditEntries(DEFAULT_FILTERS))
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.error).toContain('request failed')
  })

  it('refetches when retry is called', async () => {
    fetchMock.mockResolvedValue(makeResponse([]))
    const { result } = renderHook(() => useAuditEntries(DEFAULT_FILTERS))
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(fetchMock).toHaveBeenCalledTimes(1)

    act(() => {
      result.current.retry()
    })
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2))
  })

  it('goes back to loading when filters change', async () => {
    fetchMock.mockResolvedValue(makeResponse([]))
    let filters = DEFAULT_FILTERS
    const { result, rerender } = renderHook(() => useAuditEntries(filters))
    await waitFor(() => expect(result.current.loading).toBe(false))

    filters = { ...DEFAULT_FILTERS, severity: 'high' }
    rerender()
    expect(result.current.loading).toBe(true)
  })
})
