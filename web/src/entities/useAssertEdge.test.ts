// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Tests for useAssertEdge (Story #5464, Epic #5300).
 *
 * POST /api/v1/entities/edges answers 201 with no body on success; the refusals
 * mirror handleAssertEdge in features/controller/api/handlers_entities.go:
 * 404 "not found" (endpoint missing or outside the caller's tenants), 401
 * CFGMS-StepUp tenant-crossing, 400 validation text, 500/503 failures.
 * fetch is stubbed globally per test.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import { act, renderHook } from '@testing-library/react'
import { useAssertEdge, containsPipe, type AssertEdgeInput } from './useAssertEdge.ts'

const input: AssertEdgeInput = {
  edgeType: 'depends-on',
  fromEid: 'eid:host:7f3a21c4',
  toEid: 'eid:cluster:hv-clu-01/vm/sql-02',
  attributes: { ticket: 'INC-1042' },
}

function respond(status: number, body = '', headers: Record<string, string> = {}) {
  // A 201 carries no body: a Response with a null body throws on json().
  return vi.fn(() => Promise.resolve(new Response(status === 201 ? null : body, { status, headers })))
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('containsPipe', () => {
  it('detects the subject delimiter', () => {
    expect(containsPipe('a|b')).toBe(true)
    expect(containsPipe('related:a-b')).toBe(false)
  })
})

describe('useAssertEdge', () => {
  it('POSTs the edge and succeeds on a 201 with no body', async () => {
    const fetchStub = respond(201)
    vi.stubGlobal('fetch', fetchStub)
    const { result } = renderHook(() => useAssertEdge())
    expect(result.current.state).toEqual({ kind: 'idle' })

    let outcome
    await act(async () => {
      outcome = await result.current.assertEdge(input)
    })

    expect(outcome).toEqual({ kind: 'success' })
    expect(result.current.state).toEqual({ kind: 'success' })
    expect(fetchStub).toHaveBeenCalledTimes(1)
    const [path, init] = fetchStub.mock.calls[0] as unknown as [string, RequestInit]
    expect(path).toBe('/api/v1/entities/edges')
    expect(init.method).toBe('POST')
    expect(JSON.parse(init.body as string)).toEqual({
      edge_type: 'depends-on',
      from_eid: 'eid:host:7f3a21c4',
      to_eid: 'eid:cluster:hv-clu-01/vm/sql-02',
      attributes: { ticket: 'INC-1042' },
    })
  })

  it('rejects the pipe delimiter in any component without calling the server', async () => {
    const fetchStub = respond(201)
    vi.stubGlobal('fetch', fetchStub)
    const { result } = renderHook(() => useAssertEdge())

    for (const bad of [
      { ...input, edgeType: 'related:a|b' },
      { ...input, fromEid: 'eid:host:a|b' },
      { ...input, toEid: 'eid:host:a|b' },
    ]) {
      await act(async () => {
        await result.current.assertEdge(bad)
      })
      expect(result.current.state.kind).toBe('invalid')
    }
    expect(fetchStub).not.toHaveBeenCalled()
  })

  it('surfaces cross-tenant refusals', async () => {
    // A cross-tenant endpoint is a 404 that names nothing.
    vi.stubGlobal('fetch', respond(404, 'not found\n'))
    const notFound = renderHook(() => useAssertEdge())
    await act(async () => {
      await notFound.result.current.assertEdge(input)
    })
    expect(notFound.result.current.state).toEqual({ kind: 'not-found' })

    // A tenant-crossing challenge is a 401 naming the tenant to request.
    vi.stubGlobal(
      'fetch',
      respond(
        401,
        JSON.stringify({
          error: 'tenant_crossing_required',
          break_glass_endpoint: '/api/v1/tenants/msp-b/break-glass',
        }),
        {
          'Content-Type': 'application/json',
          'WWW-Authenticate': 'CFGMS-StepUp required="tenant-crossing"',
        },
      ),
    )
    const crossing = renderHook(() => useAssertEdge())
    await act(async () => {
      await crossing.result.current.assertEdge(input)
    })
    expect(crossing.result.current.state).toEqual({ kind: 'crossing', tenantId: 'msp-b' })
  })

  it('surfaces a cross-tenant 404 as not-found without naming an endpoint', async () => {
    vi.stubGlobal('fetch', respond(404, 'not found\n'))
    const { result } = renderHook(() => useAssertEdge())
    await act(async () => {
      await result.current.assertEdge(input)
    })
    expect(result.current.state).toEqual({ kind: 'not-found' })
  })

  it('surfaces a tenant-crossing 401 as crossing, with the tenant from the challenge', async () => {
    vi.stubGlobal(
      'fetch',
      respond(
        401,
        JSON.stringify({
          error: 'tenant_crossing_required',
          break_glass_endpoint: '/api/v1/tenants/msp-b/break-glass',
        }),
        {
          'Content-Type': 'application/json',
          'WWW-Authenticate': 'CFGMS-StepUp required="tenant-crossing"',
        },
      ),
    )
    const { result } = renderHook(() => useAssertEdge())
    await act(async () => {
      await result.current.assertEdge(input)
    })
    expect(result.current.state).toEqual({ kind: 'crossing', tenantId: 'msp-b' })
  })

  it('surfaces a 400 with the controller validation text', async () => {
    vi.stubGlobal('fetch', respond(400, 'attribute key is too long\n'))
    const { result } = renderHook(() => useAssertEdge())
    await act(async () => {
      await result.current.assertEdge(input)
    })
    expect(result.current.state).toEqual({
      kind: 'invalid',
      message: 'attribute key is too long',
    })
  })

  it('surfaces a server failure as an error carrying the status', async () => {
    vi.stubGlobal('fetch', respond(500, 'assertion failed\n'))
    const { result } = renderHook(() => useAssertEdge())
    await act(async () => {
      await result.current.assertEdge(input)
    })
    expect(result.current.state).toEqual({
      kind: 'error',
      status: 500,
      message: 'assertion failed',
    })
  })

  it('surfaces a network failure as an error', async () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.reject(new Error('offline'))))
    const { result } = renderHook(() => useAssertEdge())
    await act(async () => {
      await result.current.assertEdge(input)
    })
    expect(result.current.state).toEqual({ kind: 'error', status: 0, message: 'offline' })
  })

  it('reset returns to idle', async () => {
    vi.stubGlobal('fetch', respond(404, 'not found'))
    const { result } = renderHook(() => useAssertEdge())
    await act(async () => {
      await result.current.assertEdge(input)
    })
    act(() => result.current.reset())
    expect(result.current.state).toEqual({ kind: 'idle' })
  })
})
