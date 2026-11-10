// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Osquery ad-hoc query hooks (Issue #5460, Epic #5300).
 *
 * Endpoints covered:
 *   GET  /api/v1/osquery/catalog → useOsqueryCatalog (catalog ids + parameter schemas, never SQL)
 *   POST /api/v1/osquery/query   → runOsqueryQuery / useOsqueryRun (osquery:execute: Strong + presence tap)
 *
 * The presence tap is handled transparently by the apiFetch interceptor
 * (StepUpModal); this module never reads or sends a presence token. A cancelled
 * tap makes apiFetch hand back the original 401, which maps to 'cancelled'.
 *
 * The response carries no hostname: a result is identified by steward_id alone.
 *
 * Security A9.1: every wire value is coerced through a parse* validator and must
 * be rendered as JSX text only; cell values are always strings.
 */
import { useCallback, useEffect, useState } from 'react'
import { apiFetch, unwrapEnvelope } from '../api/client.ts'

const catalogPath = '/api/v1/osquery/catalog'
const queryPath = '/api/v1/osquery/query'

export type OsqueryParamType = 'enum' | 'charset'

export interface OsqueryParam {
  name: string
  type: OsqueryParamType
  /** Only meaningful for enum parameters. */
  allowedValues: string[]
}

export interface OsqueryCatalogEntry {
  id: string
  params: OsqueryParam[]
}

export type OsqueryRow = Record<string, string>

export interface OsqueryStewardResult {
  stewardId: string
  rows: OsqueryRow[]
  error: string | null
}

export type OsqueryResultKind = 'rows' | 'none' | 'err'

export interface OsqueryTally {
  total: number
  rows: number
  none: number
  err: number
}

export interface OsqueryRequest {
  catalogId: string
  params: Record<string, string>
  selector: string
}

function str(value: unknown): string {
  return typeof value === 'string' ? value : ''
}

/** Cell values are strings on the wire; anything else is shown as its text form, null as empty. */
function cell(value: unknown): string {
  if (value === null || value === undefined) return ''
  if (typeof value === 'string') return value
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  return ''
}

function parseParam(value: unknown): OsqueryParam | null {
  if (typeof value !== 'object' || value === null) return null
  const r = value as Record<string, unknown>
  const name = str(r.name)
  if (!name || (r.type !== 'enum' && r.type !== 'charset')) return null
  const allowed = Array.isArray(r.allowed_values) ? r.allowed_values.filter((v) => typeof v === 'string') : []
  return { name, type: r.type, allowedValues: r.type === 'enum' ? allowed : [] }
}

/** Accepts the catalog payload (an array of `{id, params}`); null is an empty catalog. */
export function parseOsqueryCatalog(data: unknown): OsqueryCatalogEntry[] {
  if (data === null || data === undefined) return []
  if (!Array.isArray(data)) throw new Error('unexpected response shape')
  const entries: OsqueryCatalogEntry[] = []
  for (const item of data) {
    if (typeof item !== 'object' || item === null) continue
    const r = item as Record<string, unknown>
    const id = str(r.id)
    if (!id) continue
    const params: OsqueryParam[] = []
    if (Array.isArray(r.params)) {
      for (const p of r.params) {
        const parsed = parseParam(p)
        if (parsed !== null) params.push(parsed)
      }
    }
    entries.push({ id, params })
  }
  return entries
}

function parseRow(value: unknown): OsqueryRow | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return null
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, v]) => [key, cell(v)]))
}

/**
 * Accepts the query payload `{ results }`. Each steward's result is kept on its
 * own: an error on one never drops, hides or changes another's rows.
 */
export function parseOsqueryResults(data: unknown): OsqueryStewardResult[] {
  if (data === null || data === undefined) return []
  if (typeof data !== 'object' || Array.isArray(data)) throw new Error('unexpected response shape')
  const results = (data as Record<string, unknown>).results
  if (results === null || results === undefined) return []
  if (!Array.isArray(results)) throw new Error('unexpected response shape')
  const out: OsqueryStewardResult[] = []
  for (const item of results) {
    if (typeof item !== 'object' || item === null) continue
    const r = item as Record<string, unknown>
    const stewardId = str(r.steward_id)
    if (!stewardId) continue
    const rows: OsqueryRow[] = []
    if (Array.isArray(r.rows)) {
      for (const row of r.rows) {
        const parsed = parseRow(row)
        if (parsed !== null) rows.push(parsed)
      }
    }
    out.push({ stewardId, rows, error: str(r.error) || null })
  }
  return out
}

/** An error wins over rows; a result with neither is a ran-but-empty result. */
export function resultKind(result: OsqueryStewardResult): OsqueryResultKind {
  if (result.error !== null) return 'err'
  return result.rows.length > 0 ? 'rows' : 'none'
}

export function tallyResults(results: OsqueryStewardResult[]): OsqueryTally {
  const tally: OsqueryTally = { total: results.length, rows: 0, none: 0, err: 0 }
  for (const r of results) tally[resultKind(r)] += 1
  return tally
}

export interface UseOsqueryCatalogResult {
  catalog: OsqueryCatalogEntry[]
  loading: boolean
  error: string | null
  retry: () => void
}

interface CatalogOutcome {
  key: string
  data?: OsqueryCatalogEntry[]
  error?: string
}

export function useOsqueryCatalog(): UseOsqueryCatalogResult {
  const [attempt, setAttempt] = useState(0)
  const [outcome, setOutcome] = useState<CatalogOutcome | null>(null)
  const retry = useCallback(() => setAttempt((n) => n + 1), [])
  const key = `osquery-catalog:${attempt}`

  useEffect(() => {
    let cancelled = false
    apiFetch(catalogPath)
      .then(async (response) => {
        if (!response.ok) throw new Error(`GET ${catalogPath} — ${response.status}`)
        const parsed = parseOsqueryCatalog(unwrapEnvelope<unknown>(await response.json()))
        if (cancelled) return
        setOutcome({ key, data: parsed })
      })
      .catch((cause: unknown) => {
        if (cancelled) return
        setOutcome({
          key,
          error:
            cause instanceof Error && cause.message ? cause.message : `GET ${catalogPath} — request failed`,
        })
      })
    return () => {
      cancelled = true
    }
  }, [key])

  const current = outcome?.key === key ? outcome : null
  return {
    catalog: current?.data ?? [],
    loading: current === null,
    error: current?.error ?? null,
    retry,
  }
}

/**
 * Why a query did not return results: the controller rejected the selector (400),
 * the tenant is outside the caller's subtree (403), fleet query is not configured
 * (503), the passkey tap was cancelled (401 handed back by apiFetch), or any
 * other failure.
 */
export type OsqueryFailureKind = 'rejected' | 'forbidden' | 'unavailable' | 'cancelled' | 'error'

export class OsqueryRequestError extends Error {
  readonly kind: OsqueryFailureKind
  constructor(kind: OsqueryFailureKind, message: string) {
    super(message)
    this.name = 'OsqueryRequestError'
    this.kind = kind
  }
}

function failureKind(status: number): OsqueryFailureKind {
  switch (status) {
    case 400:
      return 'rejected'
    case 401:
      return 'cancelled'
    case 403:
      return 'forbidden'
    case 503:
      return 'unavailable'
    default:
      return 'error'
  }
}

export async function runOsqueryQuery(input: OsqueryRequest): Promise<OsqueryStewardResult[]> {
  let response: Response
  try {
    response = await apiFetch(queryPath, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        catalog_id: input.catalogId,
        params: input.params,
        selector: input.selector,
      }),
    })
  } catch {
    throw new OsqueryRequestError('error', `POST ${queryPath} — request failed`)
  }
  if (!response.ok) {
    throw new OsqueryRequestError(failureKind(response.status), `POST ${queryPath} — ${response.status}`)
  }
  try {
    return parseOsqueryResults(unwrapEnvelope<unknown>(await response.json()))
  } catch {
    throw new OsqueryRequestError('error', `POST ${queryPath} — unexpected response shape`)
  }
}

export type OsqueryRunState =
  | { phase: 'idle' }
  | { phase: 'running' }
  | { phase: 'done'; results: OsqueryStewardResult[]; request: OsqueryRequest; ranAt: number }
  | { phase: OsqueryFailureKind }

export interface UseOsqueryRunResult {
  state: OsqueryRunState
  run: (input: OsqueryRequest) => Promise<void>
}

export function useOsqueryRun(): UseOsqueryRunResult {
  const [state, setState] = useState<OsqueryRunState>({ phase: 'idle' })
  const run = useCallback(async (input: OsqueryRequest) => {
    setState({ phase: 'running' })
    try {
      const results = await runOsqueryQuery(input)
      setState({ phase: 'done', results, request: input, ranAt: Date.now() })
    } catch (cause: unknown) {
      setState({ phase: cause instanceof OsqueryRequestError ? cause.kind : 'error' })
    }
  }, [])
  return { state, run }
}
