// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest'
import { renderHook, waitFor, act } from '@testing-library/react'
import {
  parseConfigList,
  parseStewardConfigInfo,
  parsePushStatus,
  parseRollbackPoints,
  parseRollbackOperations,
  useConfigList,
  useStewardConfig,
  usePushStatus,
  useStewardHostnameMap,
} from './useConfigs.ts'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})

afterEach(() => {
  vi.unstubAllGlobals()
})

function makeEnvelope(data: unknown, status = 200) {
  return new Response(
    JSON.stringify({ data, timestamp: new Date().toISOString() }),
    { status, headers: { 'Content-Type': 'application/json' } },
  )
}

function makeDirectResponse(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

// ── parseConfigList ───────────────────────────────────────────────────────────

describe('parseConfigList', () => {
  it('parses a valid array of summaries', () => {
    const data = [
      {
        tenant_id: 'root',
        steward_id: 'sw-1',
        version: 3,
        updated_at: '2026-01-01T00:00:00Z',
        updated_by: 'admin',
        source: 'git',
        checksum: 'abc',
        tags: ['prod'],
      },
    ]
    const result = parseConfigList(data)
    expect(result).toHaveLength(1)
    expect(result[0]!.steward_id).toBe('sw-1')
    expect(result[0]!.version).toBe(3)
    expect(result[0]!.tags).toEqual(['prod'])
  })

  it('returns an empty array for an empty input array', () => {
    expect(parseConfigList([])).toEqual([])
  })

  it('throws on non-array input', () => {
    expect(() => parseConfigList(null)).toThrow('unexpected response shape')
    expect(() => parseConfigList({ data: [] })).toThrow('unexpected response shape')
  })

  it('coerces non-string fields to defaults', () => {
    const result = parseConfigList([{ tenant_id: 42, steward_id: 'sw-1' }])
    expect(result[0]!.tenant_id).toBe('')
    expect(result[0]!.steward_id).toBe('sw-1')
    expect(result[0]!.version).toBe(0)
    expect(result[0]!.tags).toEqual([])
  })

  it('skips non-object entries', () => {
    const result = parseConfigList([null, undefined, 'string', { steward_id: 'sw-1' }])
    expect(result).toHaveLength(1)
  })
})

// ── parseStewardConfigInfo ────────────────────────────────────────────────────

describe('parseStewardConfigInfo', () => {
  it('parses a valid config info object', () => {
    const data = {
      steward_id: 'sw-1',
      version: '3',
      config: { resources: [] },
      updated_at: '2026-01-01T00:00:00Z',
    }
    const result = parseStewardConfigInfo(data)
    expect(result.steward_id).toBe('sw-1')
    expect(result.version).toBe('3')
    expect(result.config).toEqual({ resources: [] })
  })

  it('throws on null input', () => {
    expect(() => parseStewardConfigInfo(null)).toThrow()
  })

  it('coerces non-object config to empty object', () => {
    const result = parseStewardConfigInfo({ steward_id: 'sw-1', config: 'invalid' })
    expect(result.config).toEqual({})
  })
})

// ── parsePushStatus ───────────────────────────────────────────────────────────

describe('parsePushStatus', () => {
  it('parses a valid push status', () => {
    const data = {
      push_id: 'push-123',
      config_id: 'sw-1',
      tenant_id: 'root',
      version: '2',
      status: 'completed',
      initiated_by: 'admin',
      created_at: '2026-01-01T00:00:00Z',
      updated_at: '2026-01-01T00:01:00Z',
    }
    const result = parsePushStatus(data)
    expect(result.push_id).toBe('push-123')
    expect(result.status).toBe('completed')
  })

  it('throws on null input', () => {
    expect(() => parsePushStatus(null)).toThrow()
  })
})

// ── parseRollbackPoints ───────────────────────────────────────────────────────

describe('parseRollbackPoints', () => {
  it('parses valid rollback points', () => {
    const data = [
      {
        commit_sha: 'abc123',
        timestamp: '2026-01-01T00:00:00Z',
        author: 'admin',
        message: 'Initial config',
        configurations: ['sw-1'],
        risk_level: 'low',
        can_rollback: true,
      },
    ]
    const result = parseRollbackPoints(data)
    expect(result).toHaveLength(1)
    expect(result[0]!.commit_sha).toBe('abc123')
    expect(result[0]!.can_rollback).toBe(true)
  })

  it('throws on non-array', () => {
    expect(() => parseRollbackPoints(null)).toThrow('unexpected response shape')
  })
})

// ── parseRollbackOperations ───────────────────────────────────────────────────

describe('parseRollbackOperations', () => {
  it('parses valid operations', () => {
    const data = [
      {
        id: 'rb-1',
        target_type: 'steward',
        target_id: 'sw-1',
        rollback_type: 'full',
        rollback_to: 'abc123',
        status: 'completed',
        created_at: '2026-01-01T00:00:00Z',
        completed_at: '2026-01-01T00:01:00Z',
        reason: 'test',
      },
    ]
    const result = parseRollbackOperations(data)
    expect(result).toHaveLength(1)
    expect(result[0]!.id).toBe('rb-1')
  })

  it('skips items without id', () => {
    const data = [{ target_type: 'steward' }]
    expect(parseRollbackOperations(data)).toHaveLength(0)
  })

  it('throws on non-array', () => {
    expect(() => parseRollbackOperations(null)).toThrow()
  })
})

// ── useConfigList ─────────────────────────────────────────────────────────────

describe('useConfigList', () => {
  it('starts in loading state before the response arrives', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    const { result } = renderHook(() => useConfigList())
    expect(result.current.loading).toBe(true)
    expect(result.current.configs).toEqual([])
    expect(result.current.error).toBeNull()
  })

  it('returns parsed configs on success', async () => {
    fetchMock.mockResolvedValue(
      makeEnvelope([{ steward_id: 'sw-1', version: 1, tenant_id: 'root' }]),
    )
    const { result } = renderHook(() => useConfigList())
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.configs).toHaveLength(1)
    expect(result.current.configs[0]!.steward_id).toBe('sw-1')
    expect(result.current.error).toBeNull()
  })

  it('surfaces an error on non-ok response', async () => {
    fetchMock.mockResolvedValue(makeEnvelope([], 500))
    const { result } = renderHook(() => useConfigList())
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.error).toContain('500')
    expect(result.current.configs).toEqual([])
  })

  it('refetches when retry is called', async () => {
    fetchMock.mockResolvedValueOnce(makeEnvelope([], 500))
    const { result } = renderHook(() => useConfigList())
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.error).not.toBeNull()

    fetchMock.mockResolvedValueOnce(
      makeEnvelope([{ steward_id: 'sw-2', version: 1, tenant_id: 'root' }]),
    )
    act(() => result.current.retry())
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.configs).toHaveLength(1)
    expect(result.current.error).toBeNull()
  })
})

// ── useStewardConfig ──────────────────────────────────────────────────────────

describe('useStewardConfig', () => {
  it('returns null config and not-loading when stewardId is null', () => {
    const { result } = renderHook(() => useStewardConfig(null))
    expect(result.current.config).toBeNull()
    expect(result.current.loading).toBe(false)
  })

  it('starts loading when stewardId is provided', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    const { result } = renderHook(() => useStewardConfig('sw-1'))
    expect(result.current.loading).toBe(true)
  })

  it('returns parsed config on success', async () => {
    fetchMock.mockResolvedValue(
      makeEnvelope({
        steward_id: 'sw-1',
        version: '2',
        config: { resources: [] },
        updated_at: '2026-01-01T00:00:00Z',
      }),
    )
    const { result } = renderHook(() => useStewardConfig('sw-1'))
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.config?.steward_id).toBe('sw-1')
    expect(result.current.error).toBeNull()
  })

  it('surfaces an error on non-ok response', async () => {
    fetchMock.mockResolvedValue(makeEnvelope({}, 404))
    const { result } = renderHook(() => useStewardConfig('sw-1'))
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.error).toContain('404')
  })
})

// ── usePushStatus ─────────────────────────────────────────────────────────────

describe('usePushStatus', () => {
  it('returns null status and no loading when pushId is null', () => {
    const { result } = renderHook(() => usePushStatus(null))
    expect(result.current.status).toBeNull()
    expect(result.current.loading).toBe(false)
  })

  it('fetches push status when pushId is provided', async () => {
    fetchMock.mockResolvedValue(
      makeDirectResponse({
        push_id: 'push-123',
        config_id: 'sw-1',
        tenant_id: 'root',
        version: '1',
        status: 'completed',
        initiated_by: '',
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:01Z',
      }),
    )
    const { result } = renderHook(() => usePushStatus('push-123'))
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.status?.push_id).toBe('push-123')
    expect(result.current.status?.status).toBe('completed')
    expect(result.current.error).toBeNull()
  })

  it('surfaces an error on non-ok response', async () => {
    fetchMock.mockResolvedValue(makeDirectResponse({}, 404))
    const { result } = renderHook(() => usePushStatus('push-bad'))
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.error).toContain('404')
  })
})

// ── useStewardHostnameMap ─────────────────────────────────────────────────────

function makeStewardsPageResponse(stewards: object[], status = 200) {
  return new Response(
    JSON.stringify({
      data: { stewards, total: stewards.length, limit: 500, offset: 0 },
      timestamp: new Date().toISOString(),
    }),
    { status, headers: { 'Content-Type': 'application/json' } },
  )
}

describe('useStewardHostnameMap', () => {
  it('returns an empty map before the stewards response arrives', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    const { result } = renderHook(() => useStewardHostnameMap())
    expect(result.current.size).toBe(0)
  })

  it('maps steward id → hostname when dna.hostname is present', async () => {
    fetchMock.mockResolvedValue(
      makeStewardsPageResponse([
        { id: 'sw-1', dna: { hostname: 'CFG-AB-01' } },
        { id: 'sw-2', dna: { hostname: 'CFG-AB-02' } },
      ]),
    )
    const { result } = renderHook(() => useStewardHostnameMap())
    await waitFor(() => expect(result.current.size).toBe(2))
    expect(result.current.get('sw-1')).toBe('CFG-AB-01')
    expect(result.current.get('sw-2')).toBe('CFG-AB-02')
  })

  it('falls back to steward id when dna.hostname is absent', async () => {
    fetchMock.mockResolvedValue(
      makeStewardsPageResponse([{ id: 'sw-3', dna: null }]),
    )
    const { result } = renderHook(() => useStewardHostnameMap())
    await waitFor(() => expect(result.current.size).toBe(1))
    expect(result.current.get('sw-3')).toBe('sw-3')
  })

  it('returns empty map and does not throw when stewards fetch fails', async () => {
    fetchMock.mockRejectedValue(new Error('network down'))
    const { result } = renderHook(() => useStewardHostnameMap())
    // Allow microtasks to settle; map must stay empty without throwing.
    await act(async () => {})
    expect(result.current.size).toBe(0)
  })

  it('returns empty map when stewards response is non-ok', async () => {
    fetchMock.mockResolvedValue(makeStewardsPageResponse([], 503))
    const { result } = renderHook(() => useStewardHostnameMap())
    await act(async () => {})
    expect(result.current.size).toBe(0)
  })
})
