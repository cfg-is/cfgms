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
 * Each result carries an outcome: 'answered' (the steward ran the query; rows may
 * be empty), 'not_connected' (the steward was not connected to the controller node
 * that ran the query, so nothing was sent to it) or 'failed' (any other dispatch
 * error; the error text says which). An error always wins over 'answered': an
 * answered result that carries an error is 'failed'. An older controller sends no
 * outcome; it is then derived from the error (parseOutcome). A not_connected
 * result may carry last_seen, kept only when
 * parseLastSeen (fleet/health.ts) accepts it; it is null when the steward has
 * never checked in, and always null for the other outcomes.
 *
 * The response also carries a summary (matched / answered / not_connected /
 * failed, and the server's queried_at). Valid summary counts are used as sent;
 * when the summary is absent or malformed they are derived from the results
 * (parseSummary). The with-rows / no-rows breakdown is always derived client-side.
 *
 * Security A9.1: every wire value is coerced through a parse* validator and must
 * be rendered as JSX text only; cell values are always strings.
 */
import { useCallback, useEffect, useState } from 'react'
import { apiFetch, unwrapEnvelope } from '../api/client.ts'
import { parseLastSeen } from '../fleet/health.ts'

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

export type OsqueryOutcome = 'answered' | 'not_connected' | 'failed'

export interface OsqueryStewardResult {
  stewardId: string
  rows: OsqueryRow[]
  error: string | null
  outcome: OsqueryOutcome
  /** Wire last_seen of a not_connected steward; null when never seen, and for every other outcome. */
  lastSeen: string | null
}

export type OsqueryResultKind = 'rows' | 'none' | 'unreached' | 'err'

export interface OsqueryTally {
  total: number
  rows: number
  none: number
  unreached: number
  err: number
}

export interface OsquerySummary {
  matched: number
  answered: number
  notConnected: number
  failed: number
  /** Server's queried_at in epoch ms; null when absent or not a valid date. */
  queriedAt: number | null
}

export interface OsqueryResponse {
  results: OsqueryStewardResult[]
  summary: OsquerySummary
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
 * 'not_connected' and 'failed' are kept as sent. An error wins over rows: a wire
 * 'answered' that carries an error is 'failed'. A missing or unknown outcome (an
 * older controller, or an unknown value) is derived the same way: an error means
 * 'failed' and no error means 'answered'.
 */
function parseOutcome(value: unknown, error: string | null): OsqueryOutcome {
  if (value === 'not_connected' || value === 'failed') return value
  return error !== null ? 'failed' : 'answered'
}

/** last_seen is kept only for not_connected, and only when it is a real check-in time. */
function parseResultLastSeen(value: unknown, outcome: OsqueryOutcome): string | null {
  if (outcome !== 'not_connected') return null
  const raw = str(value)
  return parseLastSeen(raw) === null ? null : raw
}

function parseResult(item: unknown): OsqueryStewardResult | null {
  if (typeof item !== 'object' || item === null) return null
  const r = item as Record<string, unknown>
  const stewardId = str(r.steward_id)
  if (!stewardId) return null
  const rows: OsqueryRow[] = []
  if (Array.isArray(r.rows)) {
    for (const row of r.rows) {
      const parsed = parseRow(row)
      if (parsed !== null) rows.push(parsed)
    }
  }
  const error = str(r.error) || null
  const outcome = parseOutcome(r.outcome, error)
  return { stewardId, rows, error, outcome, lastSeen: parseResultLastSeen(r.last_seen, outcome) }
}

/** A summary count: a non-negative integer, else null. */
function parseCount(value: unknown): number | null {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0 ? value : null
}

function parseQueriedAt(value: unknown): number | null {
  const raw = str(value)
  if (!raw) return null
  const ms = Date.parse(raw)
  return Number.isNaN(ms) ? null : ms
}

/**
 * The wire summary's counts when all four are non-negative integers; otherwise
 * the counts are derived from the parsed results. queried_at is read on its own.
 */
function parseSummary(value: unknown, results: OsqueryStewardResult[]): OsquerySummary {
  const s =
    typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : {}
  const queriedAt = parseQueriedAt(s.queried_at)
  const matched = parseCount(s.matched)
  const answered = parseCount(s.answered)
  const notConnected = parseCount(s.not_connected)
  const failed = parseCount(s.failed)
  if (matched !== null && answered !== null && notConnected !== null && failed !== null) {
    return { matched, answered, notConnected, failed, queriedAt }
  }
  const derived: OsquerySummary = { matched: results.length, answered: 0, notConnected: 0, failed: 0, queriedAt }
  for (const r of results) {
    if (r.outcome === 'answered') derived.answered += 1
    else if (r.outcome === 'not_connected') derived.notConnected += 1
    else derived.failed += 1
  }
  return derived
}

/**
 * Accepts the query payload `{ summary, results }`. Each steward's result is kept
 * on its own: an error on one never drops, hides or changes another's rows.
 */
export function parseOsqueryResponse(data: unknown): OsqueryResponse {
  if (data === null || data === undefined) return { results: [], summary: parseSummary(undefined, []) }
  if (typeof data !== 'object' || Array.isArray(data)) throw new Error('unexpected response shape')
  const payload = data as Record<string, unknown>
  const raw = payload.results
  if (raw !== null && raw !== undefined && !Array.isArray(raw)) throw new Error('unexpected response shape')
  const results: OsqueryStewardResult[] = []
  for (const item of Array.isArray(raw) ? raw : []) {
    const parsed = parseResult(item)
    if (parsed !== null) results.push(parsed)
  }
  return { results, summary: parseSummary(payload.summary, results) }
}

/** The per-steward results of the query payload (see parseOsqueryResponse). */
export function parseOsqueryResults(data: unknown): OsqueryStewardResult[] {
  return parseOsqueryResponse(data).results
}

/** Not reached and failed are their own kinds; an answer is 'rows' or 'none' by row count. */
export function resultKind(result: OsqueryStewardResult): OsqueryResultKind {
  if (result.outcome === 'not_connected') return 'unreached'
  if (result.outcome === 'failed') return 'err'
  return result.rows.length > 0 ? 'rows' : 'none'
}

export function tallyResults(results: OsqueryStewardResult[]): OsqueryTally {
  const tally: OsqueryTally = { total: results.length, rows: 0, none: 0, unreached: 0, err: 0 }
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

export async function runOsqueryQuery(input: OsqueryRequest): Promise<OsqueryResponse> {
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
    return parseOsqueryResponse(unwrapEnvelope<unknown>(await response.json()))
  } catch {
    throw new OsqueryRequestError('error', `POST ${queryPath} — unexpected response shape`)
  }
}

export type OsqueryRunState =
  | { phase: 'idle' }
  | { phase: 'running' }
  | {
      phase: 'done'
      results: OsqueryStewardResult[]
      summary: OsquerySummary
      request: OsqueryRequest
      /** Client clock when the response arrived: React keys, and the fallback for summary.queriedAt. */
      ranAt: number
    }
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
      const { results, summary } = await runOsqueryQuery(input)
      setState({ phase: 'done', results, summary, request: input, ranAt: Date.now() })
    } catch (cause: unknown) {
      setState({ phase: cause instanceof OsqueryRequestError ? cause.kind : 'error' })
    }
  }, [])
  return { state, run }
}
