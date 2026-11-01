// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Billing report fetch hook (Issue #4650, ADR-025 Amendment 6 A6.1, A6.3).
 *
 * Endpoints covered:
 *   GET /api/v1/billing/report                    → root view (every MSP, clients as opaque labels)
 *   GET /api/v1/tenants/{id}/billing-report       → MSP view (own subtree, real client names)
 *
 * Responses use the standard { data: ... } envelope. Parsing is allow-list
 * based: a root client is reduced to { label, endpointCount, techCount }, so a
 * stray name or id field on the wire can never reach the screen. Tenant-supplied
 * strings are rendered as text nodes only.
 */
import { useCallback, useEffect, useState } from 'react'
import { apiFetch } from '../api/client.ts'

export interface BillingMetrics {
  online: number
  offline: number
  pending: number
  byPlatform: { name: string; count: number }[]
  byVersion: { name: string; count: number }[]
}

export interface OwnCounts {
  techCount: number
  endpointCount: number
}

/** A client as root sees it: an opaque label and sizes, nothing else. */
export interface RootClient {
  label: string
  endpointCount: number
  techCount: number
}

/** A client as its own MSP sees it. */
export interface NamedClient {
  id: string
  name: string
  endpointCount: number
  techCount: number
}

interface BillingSubtree {
  techCount: number
  endpointCount: number
  clientCount: number
  metrics: BillingMetrics
  mspOwn: OwnCounts
}

export interface RootMsp extends BillingSubtree {
  id: string
  name: string
  clients: RootClient[]
}

export interface TenantBillingReport extends BillingSubtree {
  id: string
  name: string
  clients: NamedClient[]
}

export type BillingReport =
  | { kind: 'root'; msps: RootMsp[] }
  | { kind: 'tenant'; report: TenantBillingReport }

function str(v: unknown): string {
  return typeof v === 'string' ? v : ''
}

function count(v: unknown): number {
  return typeof v === 'number' && v >= 0 ? Math.floor(v) : 0
}

function rec(v: unknown): Record<string, unknown> {
  return typeof v === 'object' && v !== null ? (v as Record<string, unknown>) : {}
}

function parseMetrics(v: unknown): BillingMetrics {
  const m = rec(v)
  const p = rec(m.endpoints_by_platform)
  return {
    online: count(m.endpoints_online),
    offline: count(m.endpoints_offline),
    pending: count(m.endpoints_pending),
    byPlatform: [
      { name: 'Windows', count: count(p.windows) },
      { name: 'Linux', count: count(p.linux) },
      { name: 'macOS', count: count(p.darwin) },
      { name: 'Other', count: count(p.other) },
    ],
    byVersion: Object.entries(rec(m.endpoints_by_version))
      .map(([name, n]) => ({ name, count: count(n) }))
      .sort((x, y) => x.name.localeCompare(y.name)),
  }
}

function parseSubtree(r: Record<string, unknown>): BillingSubtree {
  const own = rec(r.msp_own)
  return {
    techCount: count(r.tech_count),
    endpointCount: count(r.endpoint_count),
    clientCount: count(r.client_count),
    metrics: parseMetrics(r.metrics),
    mspOwn: { techCount: count(own.tech_count), endpointCount: count(own.endpoint_count) },
  }
}

function list(v: unknown): unknown[] {
  return Array.isArray(v) ? v : []
}

export function parseRootReport(body: unknown): RootMsp[] {
  return list(rec(body).msps).map((raw) => {
    const r = rec(raw)
    return {
      id: str(r.id),
      name: str(r.name),
      ...parseSubtree(r),
      // Allow-list only: label and sizes. No name or id is ever read.
      clients: list(r.clients).map((c) => {
        const cr = rec(c)
        return {
          label: str(cr.label),
          endpointCount: count(cr.endpoint_count),
          techCount: count(cr.tech_count),
        }
      }),
    }
  })
}

export function parseTenantReport(body: unknown): TenantBillingReport {
  const r = rec(body)
  return {
    id: str(r.id),
    name: str(r.name),
    ...parseSubtree(r),
    clients: list(r.clients).map((c) => {
      const cr = rec(c)
      return {
        id: str(cr.id),
        name: str(cr.name),
        endpointCount: count(cr.endpoint_count),
        techCount: count(cr.tech_count),
      }
    }),
  }
}

export interface UseBillingReportResult {
  data: BillingReport | null
  loading: boolean
  /** User-presentable failure line; carries the server message when one was sent. */
  error: string | null
  retry: () => void
}

interface FetchState {
  key: string
  data?: BillingReport
  error?: string
}

async function failure(res: Response, path: string): Promise<string> {
  const body = rec(await res.json().catch(() => ({})))
  const message = rec(body.error).message
  return typeof message === 'string' && message ? message : `GET ${path} — ${res.status}`
}

/**
 * Loads the root report when `root` is true, otherwise the report for
 * `tenantId`'s own subtree. The two paths are the only requests it makes.
 */
export function useBillingReport(root: boolean, tenantId: string): UseBillingReportResult {
  const [attempt, setAttempt] = useState(0)
  const [state, setState] = useState<FetchState | null>(null)
  const retry = useCallback(() => setAttempt((n) => n + 1), [])

  const path = root
    ? '/api/v1/billing/report'
    : `/api/v1/tenants/${encodeURIComponent(tenantId)}/billing-report`
  const key = `${path}#${attempt}`

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        const res = await apiFetch(path)
        if (!res.ok) throw new Error(await failure(res, path))
        const body = rec(await res.json())
        const payload = 'data' in body ? body.data : body
        const data: BillingReport = root
          ? { kind: 'root', msps: parseRootReport(payload) }
          : { kind: 'tenant', report: parseTenantReport(payload) }
        if (!cancelled) setState({ key, data })
      } catch (cause) {
        if (cancelled) return
        const error = cause instanceof Error && cause.message ? cause.message : `GET ${path} failed`
        setState({ key, error })
      }
    })()
    return () => {
      cancelled = true
    }
  }, [path, key, root])

  const current = state !== null && state.key === key ? state : null
  return {
    data: current?.data ?? null,
    loading: current === null,
    error: current?.error ?? null,
    retry,
  }
}
