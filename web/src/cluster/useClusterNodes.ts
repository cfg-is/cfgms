// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Controller cluster node hooks (Issue #5462, Epic #5300).
 *
 * Endpoints covered:
 *   GET  /api/v1/ha/nodes                          → useClusterNodes (ha:read-nodes)
 *   GET  /api/v1/ha/status                         → useClusterNodes (local node id, best effort)
 *   POST /api/v1/cluster/nodes/{id}/drain          → drainClusterNode (Strong step-up)
 *   POST /api/v1/cluster/nodes/{id}/decommission   → decommissionClusterNode (Strong step-up)
 *
 * Step-up and the presence tap are handled transparently by the apiFetch
 * interceptor (StepUpModal); this module never reads or sends a presence token.
 *
 * The controller serialises ha.NodeState and ha.NodeRole as integers; both the
 * numeric and the string forms are accepted.
 *
 * Security A9.1: every wire value is coerced through a parse* validator and must
 * be rendered as JSX text only.
 */
import { useCallback, useEffect, useState } from 'react'
import { apiFetch, unwrapEnvelope } from '../api/client.ts'

const nodesPath = '/api/v1/ha/nodes'
const statusPath = '/api/v1/ha/status'
const nodeActionPath = (id: string, action: 'drain' | 'decommission') =>
  `/api/v1/cluster/nodes/${encodeURIComponent(id)}/${action}`

export type NodeHealth = 'healthy' | 'degraded' | 'failed' | 'offline' | 'unknown'
export type NodeRole = 'leader' | 'candidate' | 'follower' | 'unknown'

export interface ClusterNode {
  id: string
  address: string
  health: NodeHealth
  role: NodeRole
  version: string
  last_seen: string
}

function str(value: unknown): string {
  return typeof value === 'string' ? value : ''
}

// Order matches the ha.NodeState iota in pkg/ha/interfaces.go.
const healthByIndex = new Map<number, NodeHealth>([
  [1, 'healthy'],
  [2, 'degraded'],
  [3, 'failed'],
  [4, 'offline'],
])
const healthNames = new Set<string>(healthByIndex.values())
// Order matches the ha.NodeRole iota in pkg/ha/interfaces.go.
const roleByIndex = new Map<number, NodeRole>([
  [0, 'follower'],
  [1, 'candidate'],
  [2, 'leader'],
])
const roleNames = new Set<string>(roleByIndex.values())

export function nodeHealth(value: unknown): NodeHealth {
  if (typeof value === 'number') return healthByIndex.get(value) ?? 'unknown'
  if (typeof value === 'string') {
    const lower = value.toLowerCase()
    return healthNames.has(lower) ? (lower as NodeHealth) : 'unknown'
  }
  return 'unknown'
}

export function nodeRole(value: unknown): NodeRole {
  if (typeof value === 'number') return roleByIndex.get(value) ?? 'unknown'
  if (typeof value === 'string') {
    const lower = value.toLowerCase()
    return roleNames.has(lower) ? (lower as NodeRole) : 'unknown'
  }
  return 'unknown'
}

export function parseClusterNode(value: unknown): ClusterNode | null {
  if (typeof value !== 'object' || value === null) return null
  const r = value as Record<string, unknown>
  const id = str(r.id)
  if (!id) return null
  return {
    id,
    address: str(r.address),
    health: nodeHealth(r.state),
    role: nodeRole(r.role),
    version: str(r.version),
    last_seen: str(r.last_seen),
  }
}

/** Accepts `{ nodes, count }` or a bare array; null/absent nodes is an empty list. */
export function parseClusterNodeList(data: unknown): ClusterNode[] {
  if (data === null || data === undefined) return []
  let items: unknown = data
  if (!Array.isArray(data)) {
    if (typeof data !== 'object') throw new Error('unexpected response shape')
    items = (data as Record<string, unknown>).nodes
    if (items === null || items === undefined) return []
  }
  if (!Array.isArray(items)) throw new Error('unexpected response shape')
  const list: ClusterNode[] = []
  for (const item of items) {
    const parsed = parseClusterNode(item)
    if (parsed !== null) list.push(parsed)
  }
  return list
}

/** A non-2xx answer to a lifecycle action; message is the server's own reason. */
export class ClusterActionError extends Error {
  readonly status: number

  constructor(message: string, status: number) {
    super(message)
    this.name = 'ClusterActionError'
    this.status = status
  }
}

async function failure(response: Response, fallback: string): Promise<ClusterActionError> {
  const body = (await response.json().catch(() => ({}))) as Record<string, unknown> | null
  const err = body?.error
  let message = ''
  if (typeof err === 'string') message = err
  else if (typeof err === 'object' && err !== null) message = str((err as Record<string, unknown>).message)
  return new ClusterActionError(message || `${fallback} — ${response.status}`, response.status)
}

export async function drainClusterNode(id: string): Promise<void> {
  const response = await apiFetch(nodeActionPath(id, 'drain'), { method: 'POST' })
  if (!response.ok) throw await failure(response, 'Drain failed')
}

export async function decommissionClusterNode(id: string): Promise<void> {
  const response = await apiFetch(nodeActionPath(id, 'decommission'), { method: 'POST' })
  if (!response.ok) throw await failure(response, 'Decommission failed')
}

export interface UseClusterNodesResult {
  nodes: ClusterNode[]
  /** The node serving this request, or '' when /ha/status could not say. */
  localNodeId: string
  loading: boolean
  error: string | null
  retry: () => void
}

interface Outcome {
  key: string
  data?: ClusterNode[]
  localNodeId?: string
  error?: string
}

async function fetchLocalNodeId(): Promise<string> {
  try {
    const response = await apiFetch(statusPath)
    if (!response.ok) return ''
    const body = unwrapEnvelope<unknown>(await response.json())
    return typeof body === 'object' && body !== null ? str((body as Record<string, unknown>).node_id) : ''
  } catch {
    return ''
  }
}

export function useClusterNodes(): UseClusterNodesResult {
  const [attempt, setAttempt] = useState(0)
  const [outcome, setOutcome] = useState<Outcome | null>(null)
  const retry = useCallback(() => setAttempt((n) => n + 1), [])
  const key = `cluster-nodes:${attempt}`

  useEffect(() => {
    let cancelled = false
    const nodes = apiFetch(nodesPath).then(async (response) => {
      if (!response.ok) throw new Error(`GET ${nodesPath} — ${response.status}`)
      return parseClusterNodeList(unwrapEnvelope<unknown>(await response.json()))
    })
    Promise.all([nodes, fetchLocalNodeId()])
      .then(([data, localNodeId]) => {
        if (cancelled) return
        setOutcome({ key, data, localNodeId })
      })
      .catch((cause: unknown) => {
        if (cancelled) return
        setOutcome({
          key,
          error: cause instanceof Error && cause.message ? cause.message : `GET ${nodesPath} — request failed`,
        })
      })
    return () => {
      cancelled = true
    }
  }, [key])

  const current = outcome?.key === key ? outcome : null
  return {
    nodes: current?.data ?? [],
    localNodeId: current?.localNodeId ?? '',
    loading: current === null,
    error: current?.error ?? null,
    retry,
  }
}
