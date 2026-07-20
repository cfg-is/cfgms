// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

import { renderHook, waitFor, act } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import {
  useModuleQueue,
  parseModuleApprovalEntry,
  parseModuleApprovalList,
} from './useModuleQueue.ts'
import type { ActionResult } from './useModuleQueue.ts'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})

afterEach(() => {
  vi.unstubAllGlobals()
})

function makeBundle(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    address: 'vendor-a:file:1.0.0:abc123',
    publisher: 'vendor-a',
    name: 'file',
    version: '1.0.0',
    content_hash: 'abc123==',
    ...overrides,
  }
}

function makeListResponse(bundles: object[], status = 200) {
  return new Response(
    JSON.stringify({ data: { pending: bundles } }),
    { status, headers: { 'Content-Type': 'application/json' } },
  )
}

function makeActionResponse(status = 200) {
  return new Response(
    JSON.stringify({ data: { status: 'approved' } }),
    { status, headers: { 'Content-Type': 'application/json' } },
  )
}

describe('parseModuleApprovalEntry', () => {
  it('parses a valid bundle entry', () => {
    const entry = parseModuleApprovalEntry(makeBundle())
    expect(entry).not.toBeNull()
    expect(entry!.address).toBe('vendor-a:file:1.0.0:abc123')
    expect(entry!.publisher).toBe('vendor-a')
    expect(entry!.name).toBe('file')
    expect(entry!.version).toBe('1.0.0')
    expect(entry!.content_hash).toBe('abc123==')
  })

  it('returns null when address is empty', () => {
    expect(parseModuleApprovalEntry(makeBundle({ address: '' }))).toBeNull()
  })

  it('returns null when address is missing', () => {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { address: _a, ...withoutAddress } = makeBundle()
    expect(parseModuleApprovalEntry(withoutAddress)).toBeNull()
  })

  it('returns null for non-object input', () => {
    expect(parseModuleApprovalEntry(null)).toBeNull()
    expect(parseModuleApprovalEntry('string')).toBeNull()
    expect(parseModuleApprovalEntry(42)).toBeNull()
  })

  it('coerces non-string fields to empty string', () => {
    const entry = parseModuleApprovalEntry(
      makeBundle({ publisher: 42, name: null, version: true }),
    )
    expect(entry).not.toBeNull()
    expect(entry!.publisher).toBe('')
    expect(entry!.name).toBe('')
    expect(entry!.version).toBe('')
  })
})

describe('parseModuleApprovalList', () => {
  it('parses a valid list', () => {
    const list = parseModuleApprovalList({ pending: [makeBundle()] })
    expect(list).toHaveLength(1)
    expect(list[0]!.address).toBe('vendor-a:file:1.0.0:abc123')
  })

  it('returns empty list when pending is empty', () => {
    expect(parseModuleApprovalList({ pending: [] })).toEqual([])
  })

  it('skips entries with empty address', () => {
    const list = parseModuleApprovalList({ pending: [makeBundle({ address: '' })] })
    expect(list).toHaveLength(0)
  })

  it('throws on null input', () => {
    expect(() => parseModuleApprovalList(null)).toThrow('unexpected response shape')
  })

  it('throws when pending is missing', () => {
    expect(() => parseModuleApprovalList({})).toThrow('unexpected response shape')
  })

  it('throws when input is not an object', () => {
    expect(() => parseModuleApprovalList('string')).toThrow('unexpected response shape')
    expect(() => parseModuleApprovalList(42)).toThrow('unexpected response shape')
  })
})

describe('useModuleQueue', () => {
  it('starts in loading state before the response arrives', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    const { result } = renderHook(() => useModuleQueue())
    expect(result.current.loading).toBe(true)
    expect(result.current.bundles).toEqual([])
    expect(result.current.error).toBeNull()
  })

  it('returns parsed bundles on success and clears loading', async () => {
    fetchMock.mockResolvedValue(makeListResponse([makeBundle()]))
    const { result } = renderHook(() => useModuleQueue())
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.bundles).toHaveLength(1)
    expect(result.current.bundles[0]!.publisher).toBe('vendor-a')
    expect(result.current.error).toBeNull()
  })

  it('surfaces a user-presentable error on non-ok response', async () => {
    fetchMock.mockResolvedValue(makeListResponse([], 503))
    const { result } = renderHook(() => useModuleQueue())
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.error).toContain('503')
    expect(result.current.bundles).toEqual([])
  })

  it('surfaces a user-presentable error on network failure', async () => {
    fetchMock.mockRejectedValue(new Error('network down'))
    const { result } = renderHook(() => useModuleQueue())
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.error).toBe('network down')
  })

  it('returns a fallback error string when the thrown error has no message', async () => {
    fetchMock.mockRejectedValue({})
    const { result } = renderHook(() => useModuleQueue())
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.error).toContain('request failed')
  })

  it('refetches when retry is called', async () => {
    fetchMock.mockResolvedValue(makeListResponse([]))
    const { result } = renderHook(() => useModuleQueue())
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(fetchMock).toHaveBeenCalledTimes(1)

    act(() => {
      result.current.retry()
    })
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2))
  })

  it('approve POSTs to the correct endpoint and triggers a list refetch', async () => {
    fetchMock
      .mockResolvedValueOnce(makeListResponse([makeBundle()]))
      .mockResolvedValueOnce(makeActionResponse())
      .mockResolvedValueOnce(makeListResponse([]))

    const { result } = renderHook(() => useModuleQueue())
    await waitFor(() => expect(result.current.loading).toBe(false))

    let actionResult!: ActionResult
    await act(async () => {
      actionResult = await result.current.approve('vendor-a:file:1.0.0:abc123')
    })

    expect(actionResult.ok).toBe(true)
    const approveCall = fetchMock.mock.calls[1]!
    expect(String(approveCall[0])).toContain('/approve')
    expect(String(approveCall[0])).toContain('vendor-a')
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(3))
  })

  it('reject POSTs to the correct endpoint and triggers a list refetch', async () => {
    fetchMock
      .mockResolvedValueOnce(makeListResponse([makeBundle()]))
      .mockResolvedValueOnce(makeActionResponse())
      .mockResolvedValueOnce(makeListResponse([]))

    const { result } = renderHook(() => useModuleQueue())
    await waitFor(() => expect(result.current.loading).toBe(false))

    let actionResult!: ActionResult
    await act(async () => {
      actionResult = await result.current.reject('vendor-a:file:1.0.0:abc123')
    })

    expect(actionResult.ok).toBe(true)
    const rejectCall = fetchMock.mock.calls[1]!
    expect(String(rejectCall[0])).toContain('/reject')
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(3))
  })

  it('approve returns an error result on non-ok response', async () => {
    fetchMock
      .mockResolvedValueOnce(makeListResponse([makeBundle()]))
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({ error: { message: 'Bundle not found' } }),
          { status: 404, headers: { 'Content-Type': 'application/json' } },
        ),
      )

    const { result } = renderHook(() => useModuleQueue())
    await waitFor(() => expect(result.current.loading).toBe(false))

    let actionResult!: ActionResult
    await act(async () => {
      actionResult = await result.current.approve('vendor-a:file:1.0.0:abc123')
    })

    expect(actionResult.ok).toBe(false)
    expect((actionResult as { ok: false; error: string }).error).toContain('Bundle not found')
  })

  it('reject returns an error result on network failure', async () => {
    fetchMock
      .mockResolvedValueOnce(makeListResponse([makeBundle()]))
      .mockRejectedValueOnce(new Error('network down'))

    const { result } = renderHook(() => useModuleQueue())
    await waitFor(() => expect(result.current.loading).toBe(false))

    let actionResult!: ActionResult
    await act(async () => {
      actionResult = await result.current.reject('vendor-a:file:1.0.0:abc123')
    })

    expect(actionResult.ok).toBe(false)
    expect((actionResult as { ok: false; error: string }).error).toBe('network down')
  })
})
