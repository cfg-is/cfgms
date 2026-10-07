// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, renderHook, waitFor } from '@testing-library/react'
import {
  bannerStorageKey,
  createAccessGrant,
  endCrossing,
  parseCrossing,
  requestBreakGlass,
  useCrossingBanner,
  useTenantCrossings,
} from './useTenantCrossings.ts'
import { onStepUpRequired } from '../api/client.ts'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
  window.sessionStorage.clear()
})

afterEach(() => {
  onStepUpRequired(null)
  vi.unstubAllGlobals()
  cleanup()
})

function json(status: number, body: unknown, headers: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  })
}

const future = () => new Date(Date.now() + 20 * 60_000).toISOString()
const past = () => new Date(Date.now() - 60_000).toISOString()

function crossing(over: Record<string, unknown> = {}) {
  return {
    ID: 'c-1',
    TenantID: 'msp-a',
    PrincipalID: 'root-op',
    Kind: 'break_glass',
    GrantedBy: 'root-op',
    Justification: 'outage response',
    CreatedAt: past(),
    ExpiresAt: future(),
    RevokedAt: null,
    ...over,
  }
}

describe('parseCrossing', () => {
  it('reads the controller PascalCase shape', () => {
    const c = parseCrossing(crossing())
    expect(c).toMatchObject({ id: 'c-1', tenantId: 'msp-a', kind: 'break_glass', revokedAt: null })
  })

  it('reads snake_case keys', () => {
    const c = parseCrossing({ id: 'c-2', tenant_id: 't', expires_at: '2030-01-01T00:00:00Z' })
    expect(c).toMatchObject({ id: 'c-2', tenantId: 't', expiresAt: '2030-01-01T00:00:00Z' })
  })

  it('rejects a value without an id', () => {
    expect(parseCrossing({ TenantID: 'x' })).toBeNull()
    expect(parseCrossing(null)).toBeNull()
  })
})

describe('crossing requests', () => {
  it('break-glass sends the justification only as the X-Justification header', async () => {
    fetchMock.mockResolvedValueOnce(json(201, { data: crossing() }))
    const c = await requestBreakGlass('msp-a', 'outage response')
    expect(c.id).toBe('c-1')
    const [url, init] = fetchMock.mock.calls[0]!
    expect(url).toBe('/api/v1/tenants/msp-a/break-glass')
    expect(init?.method).toBe('POST')
    expect(new Headers(init?.headers).get('X-Justification')).toBe('outage response')
    expect(init?.body).toBeUndefined()
  })

  it('break-glass retries through the step-up listener keeping the header', async () => {
    fetchMock.mockResolvedValueOnce(
      json(401, { error: 'x' }, { 'WWW-Authenticate': 'CFGMS-StepUp realm="cfgms"' }),
    )
    const listener = vi.fn(async (req: { path: string; init: RequestInit }) =>
      fetch(req.path, req.init),
    )
    onStepUpRequired(listener)
    fetchMock.mockResolvedValueOnce(json(201, { data: crossing() }))
    await requestBreakGlass('msp-a', 'outage response')
    expect(listener).toHaveBeenCalledTimes(1)
    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(new Headers(fetchMock.mock.calls[1]![1]?.headers).get('X-Justification')).toBe('outage response')
  })

  it('surfaces a 403 as an error', async () => {
    fetchMock.mockResolvedValueOnce(
      json(403, { error: { code: 'NOT_ROOT_SCOPED', message: 'break-glass is only available to root-scoped callers' } }),
    )
    await expect(requestBreakGlass('msp-a', 'outage response')).rejects.toMatchObject({
      status: 403,
      code: 'NOT_ROOT_SCOPED',
    })
  })

  it('surfaces the crossing challenge body as a coded error', async () => {
    fetchMock.mockResolvedValueOnce(json(401, { error: 'tenant_crossing_required' }))
    await expect(createAccessGrant('msp-a', { principalId: 'p', durationMinutes: 5 })).rejects.toMatchObject({
      code: 'tenant_crossing_required',
    })
  })

  it('grant posts principal_id, duration_minutes and justification', async () => {
    fetchMock.mockResolvedValueOnce(json(201, { data: crossing({ Kind: 'grant' }) }))
    await createAccessGrant('msp-a', { principalId: 'root-op', durationMinutes: 90, justification: 'quarterly review' })
    const [url, init] = fetchMock.mock.calls[0]!
    expect(url).toBe('/api/v1/tenants/msp-a/access-grants')
    expect(JSON.parse(String(init?.body))).toEqual({
      principal_id: 'root-op',
      duration_minutes: 90,
      justification: 'quarterly review',
    })
  })

  it('end calls DELETE on the crossing path', async () => {
    fetchMock.mockResolvedValueOnce(json(200, { data: crossing() }))
    await endCrossing('msp a', 'c/1')
    const [url, init] = fetchMock.mock.calls[0]!
    expect(url).toBe('/api/v1/tenants/msp%20a/access-grants/c%2F1')
    expect(init?.method).toBe('DELETE')
  })
})

describe('useTenantCrossings', () => {
  it('loads the list, and reports errors', async () => {
    fetchMock.mockResolvedValueOnce(json(200, { data: [crossing()] }))
    const ok = renderHook(() => useTenantCrossings('msp-a'))
    expect(ok.result.current.loading).toBe(true)
    await waitFor(() => expect(ok.result.current.crossings).toHaveLength(1))

    fetchMock.mockResolvedValueOnce(json(500, { error: { message: 'boom' } }))
    const bad = renderHook(() => useTenantCrossings('msp-b'))
    await waitFor(() => expect(bad.result.current.error).toBe('boom'))
  })

  it('does not fetch for a null tenant', () => {
    const { result } = renderHook(() => useTenantCrossings(null))
    expect(result.current.loading).toBe(false)
    expect(fetchMock).not.toHaveBeenCalled()
  })
})

describe('useCrossingBanner persistence', () => {
  function persist(over: Record<string, unknown> = {}) {
    window.sessionStorage.setItem(
      bannerStorageKey,
      JSON.stringify({ tenantId: 'msp-a', crossingId: 'c-1', expiresAt: future(), reason: 'outage response', ...over }),
    )
  }

  it('reappears after reload when GET confirms the crossing', async () => {
    persist()
    fetchMock.mockResolvedValueOnce(json(200, { data: [crossing()] }))
    const { result } = renderHook(() => useCrossingBanner())
    expect(result.current.entry?.crossingId).toBe('c-1')
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/api/v1/tenants/msp-a/access-grants', expect.anything()))
    expect(result.current.entry).not.toBeNull()
    expect(window.sessionStorage.getItem(bannerStorageKey)).not.toBeNull()
  })

  it('is dropped when the crossing is expired', async () => {
    persist()
    fetchMock.mockResolvedValueOnce(json(200, { data: [crossing({ ExpiresAt: past() })] }))
    const { result } = renderHook(() => useCrossingBanner())
    await waitFor(() => expect(result.current.entry).toBeNull())
    expect(window.sessionStorage.getItem(bannerStorageKey)).toBeNull()
  })

  it('is dropped when revoked', async () => {
    persist()
    fetchMock.mockResolvedValueOnce(json(200, { data: [crossing({ RevokedAt: past() })] }))
    const { result } = renderHook(() => useCrossingBanner())
    await waitFor(() => expect(result.current.entry).toBeNull())
  })

  it('is dropped when not found in the list', async () => {
    persist()
    fetchMock.mockResolvedValueOnce(json(200, { data: [crossing({ ID: 'other' })] }))
    const { result } = renderHook(() => useCrossingBanner())
    await waitFor(() => expect(result.current.entry).toBeNull())
  })

  it('is dropped on a 404 tenant', async () => {
    persist()
    fetchMock.mockResolvedValueOnce(json(404, { error: { code: 'TENANT_NOT_FOUND', message: 'tenant not found' } }))
    const { result } = renderHook(() => useCrossingBanner())
    await waitFor(() => expect(result.current.entry).toBeNull())
  })

  it('keeps the entry on a transient failure', async () => {
    persist()
    fetchMock.mockResolvedValueOnce(json(500, { error: { message: 'boom' } }))
    const { result } = renderHook(() => useCrossingBanner())
    await waitFor(() => expect(fetchMock).toHaveBeenCalled())
    await act(async () => {})
    expect(result.current.entry).not.toBeNull()
  })

  it('ignores corrupt storage and survives an unavailable store', () => {
    window.sessionStorage.setItem(bannerStorageKey, '{not json')
    const { result } = renderHook(() => useCrossingBanner())
    expect(result.current.entry).toBeNull()
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('adopt persists and clear removes', () => {
    const { result } = renderHook(() => useCrossingBanner())
    const c = parseCrossing(crossing())!
    act(() => result.current.adopt(c))
    expect(JSON.parse(window.sessionStorage.getItem(bannerStorageKey)!)).toMatchObject({
      tenantId: 'msp-a',
      crossingId: 'c-1',
      reason: 'outage response',
    })
    act(() => result.current.clear())
    expect(window.sessionStorage.getItem(bannerStorageKey)).toBeNull()
  })
})
