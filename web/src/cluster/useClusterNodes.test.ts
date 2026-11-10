// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  ClusterActionError,
  decommissionClusterNode,
  drainClusterNode,
  nodeHealth,
  nodeRole,
  parseClusterNode,
  parseClusterNodeList,
} from './useClusterNodes.ts'

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
    expect(parseClusterNode(null)).toBeNull()
    expect(parseClusterNode({ address: 'x' })).toBeNull()
    expect(parseClusterNode({ id: 'n1', address: 7, state: 'bogus', role: {}, version: null, last_seen: 3 })).toEqual({
      id: 'n1',
      address: '',
      health: 'unknown',
      role: 'unknown',
      version: '',
      last_seen: '',
    })
  })

  it('maps the numeric NodeState and NodeRole the controller serialises', () => {
    expect(nodeHealth(1)).toBe('healthy')
    expect(nodeHealth(2)).toBe('degraded')
    expect(nodeHealth(3)).toBe('failed')
    expect(nodeHealth(4)).toBe('offline')
    expect(nodeHealth(0)).toBe('unknown')
    expect(nodeHealth(99)).toBe('unknown')
    expect(nodeHealth('Healthy')).toBe('healthy')
    expect(nodeRole(0)).toBe('follower')
    expect(nodeRole(1)).toBe('candidate')
    expect(nodeRole(2)).toBe('leader')
    expect(nodeRole('leader')).toBe('leader')
    expect(nodeRole(undefined)).toBe('unknown')
  })

  it('accepts the {nodes} payload, a bare array, and null as empty; rejects other shapes', () => {
    expect(parseClusterNodeList({ nodes: [{ id: 'a' }, { nope: 1 }], count: 2 }).map((n) => n.id)).toEqual(['a'])
    expect(parseClusterNodeList([{ id: 'b' }]).map((n) => n.id)).toEqual(['b'])
    expect(parseClusterNodeList(null)).toEqual([])
    expect(parseClusterNodeList({ nodes: null })).toEqual([])
    expect(() => parseClusterNodeList('x')).toThrow(/unexpected response shape/)
    expect(() => parseClusterNodeList({ nodes: 'x' })).toThrow(/unexpected response shape/)
  })
})

describe('drainClusterNode / decommissionClusterNode', () => {
  it('POST the node id, path-encoded, with no body and no presence header', async () => {
    fetchMock.mockResolvedValue(json(202, { node_id: 'n/1', state: 'draining' }))
    await drainClusterNode('n/1')
    fetchMock.mockResolvedValue(json(200, { node_id: 'n/1', state: 'decommissioned' }))
    await decommissionClusterNode('n/1')
    const [drain, decom] = fetchMock.mock.calls
    expect(String(drain?.[0])).toBe('/api/v1/cluster/nodes/n%2F1/drain')
    expect(drain?.[1]?.method).toBe('POST')
    expect(String(decom?.[0])).toBe('/api/v1/cluster/nodes/n%2F1/decommission')
    expect(decom?.[1]?.method).toBe('POST')
    for (const [, init] of fetchMock.mock.calls) {
      expect(new Headers(init?.headers).has('X-Presence-Token')).toBe(false)
    }
  })

  it('surfaces the server refusal reason and status', async () => {
    fetchMock.mockResolvedValue(json(409, { error: 'node is not active' }))
    const err = await drainClusterNode('n1').catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ClusterActionError)
    expect((err as ClusterActionError).status).toBe(409)
    expect((err as ClusterActionError).message).toBe('node is not active')

    fetchMock.mockResolvedValue(json(403, { error: { message: 'unscoped principal required' } }))
    await expect(decommissionClusterNode('n1')).rejects.toThrow('unscoped principal required')
  })

  it('falls back to a generic message when the body is not JSON', async () => {
    fetchMock.mockResolvedValue(new Response('boom', { status: 500 }))
    await expect(drainClusterNode('n1')).rejects.toThrow('Drain failed — 500')
    fetchMock.mockResolvedValue(new Response('boom', { status: 500 }))
    await expect(decommissionClusterNode('n1')).rejects.toThrow('Decommission failed — 500')
  })
})
