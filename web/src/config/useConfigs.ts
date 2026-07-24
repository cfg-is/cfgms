// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Config fetch and mutation hooks (Story #2730).
 *
 * Endpoints covered:
 *   GET  /api/v1/configs                            → useConfigList
 *   GET  /api/v1/stewards/{id}/config               → useStewardConfig
 *   POST /api/v1/config/push                        → (imperative, see pushConfig)
 *   GET  /api/v1/config/push/{id}                   → usePushStatus (polls)
 *   GET  /api/v1/rollback/points?...                → useRollbackPoints
 *   GET  /api/v1/rollback/history?...               → useRollbackHistory
 *
 * Security A9.1: field values originating from steward/user data are
 * untrusted. Every string field is coerced via str(). Callers must render
 * them as text nodes only, never via dangerouslySetInnerHTML.
 *
 * Response envelope:
 *   writeSuccessResponse → { data: ..., timestamp: ... }
 *   respondJSON          → direct JSON (push status, rollback endpoints)
 */
import { useCallback, useEffect, useState } from 'react'
import { apiFetch } from '../api/client.ts'
import { stewardDisplayName } from '../fleet/columns.ts'
import { parseStewardPage } from '../fleet/useStewards.ts'

// ── Primitive coercers ────────────────────────────────────────────────────────

function str(value: unknown): string {
  return typeof value === 'string' ? value : ''
}

function num(value: unknown): number {
  return typeof value === 'number' ? value : 0
}

function bool(value: unknown): boolean {
  return typeof value === 'boolean' ? value : false
}

// ── Types ─────────────────────────────────────────────────────────────────────

export interface ConfigSummary {
  tenant_id: string
  steward_id: string
  version: number
  updated_at: string
  updated_by: string
  source: string
  checksum: string
  tags: string[]
}

export interface StewardConfigInfo {
  steward_id: string
  version: string
  config: Record<string, unknown>
  updated_at: string
}

export interface ValidationError {
  field: string
  message: string
  level: string
  code: string
  suggestion: string
}

export interface ConfigValidationResult {
  valid: boolean
  errors: ValidationError[]
  metadata: Record<string, string>
}

export interface PushStatus {
  push_id: string
  config_id: string
  tenant_id: string
  version: string
  status: string
  initiated_by: string
  created_at: string
  updated_at: string
}

export interface RollbackPoint {
  commit_sha: string
  timestamp: string
  author: string
  message: string
  configurations: string[]
  risk_level: string
  can_rollback: boolean
}

export interface RollbackOperation {
  id: string
  target_type: string
  target_id: string
  rollback_type: string
  rollback_to: string
  status: string
  created_at: string
  completed_at: string
  reason: string
}

// ── Parse helpers ─────────────────────────────────────────────────────────────

function parseConfigSummary(value: unknown): ConfigSummary | null {
  if (typeof value !== 'object' || value === null) return null
  const r = value as Record<string, unknown>
  return {
    tenant_id: str(r.tenant_id),
    steward_id: str(r.steward_id),
    version: num(r.version),
    updated_at: str(r.updated_at),
    updated_by: str(r.updated_by),
    source: str(r.source),
    checksum: str(r.checksum),
    tags: Array.isArray(r.tags)
      ? r.tags.filter((t): t is string => typeof t === 'string')
      : [],
  }
}

export function parseConfigList(data: unknown): ConfigSummary[] {
  if (!Array.isArray(data)) throw new Error('unexpected response shape')
  const list: ConfigSummary[] = []
  for (const item of data) {
    const c = parseConfigSummary(item)
    if (c !== null) list.push(c)
  }
  return list
}

export function parseStewardConfigInfo(data: unknown): StewardConfigInfo {
  if (typeof data !== 'object' || data === null)
    throw new Error('unexpected response shape')
  const r = data as Record<string, unknown>
  return {
    steward_id: str(r.steward_id),
    version: str(r.version),
    config:
      typeof r.config === 'object' && r.config !== null
        ? (r.config as Record<string, unknown>)
        : {},
    updated_at: str(r.updated_at),
  }
}

export function parsePushStatus(data: unknown): PushStatus {
  if (typeof data !== 'object' || data === null)
    throw new Error('unexpected response shape')
  const r = data as Record<string, unknown>
  return {
    push_id: str(r.push_id),
    config_id: str(r.config_id),
    tenant_id: str(r.tenant_id),
    version: str(r.version),
    status: str(r.status),
    initiated_by: str(r.initiated_by),
    created_at: str(r.created_at),
    updated_at: str(r.updated_at),
  }
}

function parseRollbackPoint(value: unknown): RollbackPoint | null {
  if (typeof value !== 'object' || value === null) return null
  const r = value as Record<string, unknown>
  return {
    commit_sha: str(r.commit_sha),
    timestamp: str(r.timestamp),
    author: str(r.author),
    message: str(r.message),
    configurations: Array.isArray(r.configurations)
      ? r.configurations.filter((c): c is string => typeof c === 'string')
      : [],
    risk_level: str(r.risk_level),
    can_rollback: bool(r.can_rollback),
  }
}

export function parseRollbackPoints(data: unknown): RollbackPoint[] {
  if (!Array.isArray(data)) throw new Error('unexpected response shape')
  const list: RollbackPoint[] = []
  for (const item of data) {
    const p = parseRollbackPoint(item)
    if (p !== null) list.push(p)
  }
  return list
}

function parseRollbackOperation(value: unknown): RollbackOperation | null {
  if (typeof value !== 'object' || value === null) return null
  const r = value as Record<string, unknown>
  const id = str(r.id)
  if (!id) return null
  return {
    id,
    target_type: str(r.target_type),
    target_id: str(r.target_id),
    rollback_type: str(r.rollback_type),
    rollback_to: str(r.rollback_to),
    status: str(r.status),
    created_at: str(r.created_at),
    completed_at: str(r.completed_at),
    reason: str(r.reason),
  }
}

export function parseRollbackOperations(data: unknown): RollbackOperation[] {
  if (!Array.isArray(data)) throw new Error('unexpected response shape')
  const list: RollbackOperation[] = []
  for (const item of data) {
    const op = parseRollbackOperation(item)
    if (op !== null) list.push(op)
  }
  return list
}

// ── Generic fetch outcome ─────────────────────────────────────────────────────

interface FetchOutcome<T> {
  key: string
  data?: T
  error?: string
  notFound?: boolean
  fetchedAtMs: number
}

// ── useConfigList ─────────────────────────────────────────────────────────────

export interface UseConfigListResult {
  configs: ConfigSummary[]
  loading: boolean
  error: string | null
  fetchedAtMs: number
  retry: () => void
}

export function useConfigList(): UseConfigListResult {
  const [attempt, setAttempt] = useState(0)
  const [outcome, setOutcome] = useState<FetchOutcome<ConfigSummary[]> | null>(null)
  const retry = useCallback(() => setAttempt((n) => n + 1), [])
  const key = `configs:${attempt}`

  useEffect(() => {
    let cancelled = false
    apiFetch('/api/v1/configs')
      .then(async (response) => {
        if (!response.ok) throw new Error(`GET /api/v1/configs — ${response.status}`)
        const body: unknown = await response.json()
        const parsed = parseConfigList((body as Record<string, unknown> | null)?.data)
        if (cancelled) return
        setOutcome({ key, data: parsed, fetchedAtMs: Date.now() })
      })
      .catch((cause: unknown) => {
        if (cancelled) return
        setOutcome({
          key,
          error:
            cause instanceof Error && cause.message
              ? cause.message
              : 'GET /api/v1/configs — request failed',
          fetchedAtMs: Date.now(),
        })
      })
    return () => {
      cancelled = true
    }
  }, [key, attempt])

  const current = outcome?.key === key ? outcome : null
  return {
    configs: current?.data ?? [],
    loading: current === null,
    error: current?.error ?? null,
    fetchedAtMs: current?.fetchedAtMs ?? 0,
    retry,
  }
}

// ── useStewardConfig ──────────────────────────────────────────────────────────

export interface UseStewardConfigResult {
  config: StewardConfigInfo | null
  loading: boolean
  error: string | null
  notFound: boolean
  retry: () => void
}

export function useStewardConfig(stewardId: string | null): UseStewardConfigResult {
  const [attempt, setAttempt] = useState(0)
  const [outcome, setOutcome] = useState<FetchOutcome<StewardConfigInfo> | null>(null)
  const retry = useCallback(() => setAttempt((n) => n + 1), [])
  const key = `steward-config:${stewardId ?? ''}:${attempt}`

  useEffect(() => {
    if (!stewardId) return
    let cancelled = false
    apiFetch(`/api/v1/stewards/${encodeURIComponent(stewardId)}/config`)
      .then(async (response) => {
        if (response.status === 404) {
          if (!cancelled) setOutcome({ key, notFound: true, fetchedAtMs: Date.now() })
          return
        }
        if (!response.ok)
          throw new Error(
            `GET /api/v1/stewards/${stewardId}/config — ${response.status}`,
          )
        const body: unknown = await response.json()
        const parsed = parseStewardConfigInfo(
          (body as Record<string, unknown> | null)?.data,
        )
        if (cancelled) return
        setOutcome({ key, data: parsed, fetchedAtMs: Date.now() })
      })
      .catch((cause: unknown) => {
        if (cancelled) return
        setOutcome({
          key,
          error:
            cause instanceof Error && cause.message
              ? cause.message
              : `GET /api/v1/stewards/${stewardId}/config — request failed`,
          fetchedAtMs: Date.now(),
        })
      })
    return () => {
      cancelled = true
    }
  }, [key, stewardId, attempt])

  const current = outcome?.key === key ? outcome : null
  return {
    config: current?.data ?? null,
    loading: stewardId !== null && current === null,
    error: current?.error ?? null,
    notFound: current?.notFound ?? false,
    retry,
  }
}

// ── usePushStatus (polls until terminal) ─────────────────────────────────────

const PUSH_POLL_INTERVAL = 3000
const PUSH_TERMINAL = new Set(['completed', 'failed', 'cancelled'])

export interface UsePushStatusResult {
  status: PushStatus | null
  loading: boolean
  error: string | null
}

export function usePushStatus(pushId: string | null): UsePushStatusResult {
  const [outcome, setOutcome] = useState<FetchOutcome<PushStatus> | null>(null)
  const [pollTick, setPollTick] = useState(0)
  const key = `push-status:${pushId ?? ''}:${pollTick}`

  const current = outcome?.key === key ? outcome : null
  const isTerminal =
    current?.data !== undefined && PUSH_TERMINAL.has(current.data.status)

  // Polling ticker — fires every PUSH_POLL_INTERVAL while push is non-terminal
  useEffect(() => {
    if (!pushId || isTerminal) return
    const timer = setInterval(
      () => setPollTick((n) => n + 1),
      PUSH_POLL_INTERVAL,
    )
    return () => clearInterval(timer)
  }, [pushId, isTerminal])

  // Fetch on pushId change or poll tick
  useEffect(() => {
    if (!pushId) return
    let cancelled = false
    apiFetch(`/api/v1/config/push/${encodeURIComponent(pushId)}`)
      .then(async (response) => {
        if (!response.ok)
          throw new Error(
            `GET /api/v1/config/push/${pushId} — ${response.status}`,
          )
        const body: unknown = await response.json()
        if (cancelled) return
        setOutcome({ key, data: parsePushStatus(body), fetchedAtMs: Date.now() })
      })
      .catch((cause: unknown) => {
        if (cancelled) return
        setOutcome({
          key,
          error:
            cause instanceof Error && cause.message
              ? cause.message
              : 'request failed',
          fetchedAtMs: Date.now(),
        })
      })
    return () => {
      cancelled = true
    }
  }, [key, pushId, pollTick])

  return {
    status: pushId ? (current?.data ?? null) : null,
    loading: pushId !== null && current === null,
    error: pushId ? (current?.error ?? null) : null,
  }
}

// ── useRollbackPoints ─────────────────────────────────────────────────────────

export interface UseRollbackPointsResult {
  points: RollbackPoint[]
  loading: boolean
  error: string | null
  retry: () => void
}

export function useRollbackPoints(stewardId: string | null): UseRollbackPointsResult {
  const [attempt, setAttempt] = useState(0)
  const [outcome, setOutcome] = useState<FetchOutcome<RollbackPoint[]> | null>(null)
  const retry = useCallback(() => setAttempt((n) => n + 1), [])
  const key = `rollback-points:${stewardId ?? ''}:${attempt}`

  useEffect(() => {
    if (!stewardId) return
    let cancelled = false
    const params = new URLSearchParams()
    params.set('target_type', 'steward')
    params.set('target_id', stewardId)
    apiFetch(`/api/v1/rollback/points?${params.toString()}`)
      .then(async (response) => {
        if (!response.ok)
          throw new Error(`GET /api/v1/rollback/points — ${response.status}`)
        const body: unknown = await response.json()
        const parsed = parseRollbackPoints(
          (body as Record<string, unknown> | null)?.rollback_points,
        )
        if (cancelled) return
        setOutcome({ key, data: parsed, fetchedAtMs: Date.now() })
      })
      .catch((cause: unknown) => {
        if (cancelled) return
        setOutcome({
          key,
          error:
            cause instanceof Error && cause.message
              ? cause.message
              : 'GET /api/v1/rollback/points — request failed',
          fetchedAtMs: Date.now(),
        })
      })
    return () => {
      cancelled = true
    }
  }, [key, stewardId, attempt])

  const current = outcome?.key === key ? outcome : null
  return {
    points: current?.data ?? [],
    loading: stewardId !== null && current === null,
    error: current?.error ?? null,
    retry,
  }
}

// ── useRollbackHistory ────────────────────────────────────────────────────────

export interface UseRollbackHistoryResult {
  operations: RollbackOperation[]
  loading: boolean
  error: string | null
  retry: () => void
}

export function useRollbackHistory(stewardId: string | null): UseRollbackHistoryResult {
  const [attempt, setAttempt] = useState(0)
  const [outcome, setOutcome] = useState<FetchOutcome<RollbackOperation[]> | null>(null)
  const retry = useCallback(() => setAttempt((n) => n + 1), [])
  const key = `rollback-history:${stewardId ?? ''}:${attempt}`

  useEffect(() => {
    if (!stewardId) return
    let cancelled = false
    const params = new URLSearchParams()
    params.set('target_type', 'steward')
    params.set('target_id', stewardId)
    apiFetch(`/api/v1/rollback/history?${params.toString()}`)
      .then(async (response) => {
        if (!response.ok)
          throw new Error(`GET /api/v1/rollback/history — ${response.status}`)
        const body: unknown = await response.json()
        const parsed = parseRollbackOperations(
          (body as Record<string, unknown> | null)?.rollback_operations,
        )
        if (cancelled) return
        setOutcome({ key, data: parsed, fetchedAtMs: Date.now() })
      })
      .catch((cause: unknown) => {
        if (cancelled) return
        setOutcome({
          key,
          error:
            cause instanceof Error && cause.message
              ? cause.message
              : 'GET /api/v1/rollback/history — request failed',
          fetchedAtMs: Date.now(),
        })
      })
    return () => {
      cancelled = true
    }
  }, [key, stewardId, attempt])

  const current = outcome?.key === key ? outcome : null
  return {
    operations: current?.data ?? [],
    loading: stewardId !== null && current === null,
    error: current?.error ?? null,
    retry,
  }
}

// ── useStewardHostnameMap ─────────────────────────────────────────────────────

/*
 * Fetches the steward list and returns a Map<stewardId, displayName> for
 * hostname resolution in the config view. Uses the same hostname fallback
 * logic as fleet/columns.ts's `name` column (dna.hostname || id). Errors
 * are silently swallowed — the config view falls back to raw IDs when the
 * stewards fetch fails or is slow.
 */
export function useStewardHostnameMap(): Map<string, string> {
  const [map, setMap] = useState<Map<string, string>>(new Map())

  useEffect(() => {
    let cancelled = false
    apiFetch('/api/v1/stewards?limit=500&offset=0')
      .then(async (response) => {
        if (!response.ok) return
        const body: unknown = await response.json()
        const page = parseStewardPage((body as Record<string, unknown> | null)?.data)
        const m = new Map<string, string>()
        for (const s of page.stewards) {
          m.set(s.id, stewardDisplayName(s))
        }
        if (!cancelled) setMap(m)
      })
      .catch(() => { /* hostname fetch failed; caller falls back to raw steward IDs */ })
    return () => {
      cancelled = true
    }
  }, [])

  return map
}
