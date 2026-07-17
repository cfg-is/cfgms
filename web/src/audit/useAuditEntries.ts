// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Audit-entries fetch hook (Story #2727): query GET /api/v1/audit/entries with
 * the full filter set handleListAuditEntries accepts.
 *
 * The endpoint returns a bare array (no pagination envelope); hasMore is
 * inferred by the caller from response length vs. requested limit. A 401 is
 * handled centrally by apiFetch; everything else surfaces as the view's error.
 *
 * Audit-entry field values may originate from user/steward-supplied data and
 * are untrusted — every field is coerced to a plain string. Callers must
 * render them as text nodes only, never via dangerouslySetInnerHTML (security
 * A9.1 — audit logs are a high-value XSS target because they faithfully record
 * attacker-controlled input).
 */
import { useCallback, useEffect, useState } from 'react'
import { apiFetch } from '../api/client.ts'

export interface AuditFilters {
  since: string       // RFC3339 or '' for no lower bound
  until: string       // RFC3339 or '' for no upper bound
  severity: string    // 'low' | 'medium' | 'high' | 'critical' | ''
  action: string
  event_type: string  // AuditEventType constant or ''
  user_id: string
  result: string      // 'success' | 'failure' | 'error' | 'denied' | ''
  module: string      // resource_type prefix filter (post-query, server-side)
  limit: number       // 1–500; server default is 50
  offset: number
}

export const DEFAULT_FILTERS: AuditFilters = {
  since: '',
  until: '',
  severity: '',
  action: '',
  event_type: '',
  user_id: '',
  result: '',
  module: '',
  limit: 50,
  offset: 0,
}

export interface AuditEntry {
  id: string
  timestamp: string
  event_type: string
  action: string
  user_id: string
  user_type: string
  resource_type: string
  resource_id: string
  resource_name: string
  result: string
  severity: string
  source: string
  ip_address: string
  method: string
  path: string
  error_code: string
  error_message: string
}

export interface UseAuditEntriesResult {
  entries: AuditEntry[]
  loading: boolean
  error: string | null
  fetchedAtMs: number
  retry: () => void
}

function str(value: unknown): string {
  return typeof value === 'string' ? value : ''
}

function parseAuditEntry(value: unknown): AuditEntry | null {
  if (typeof value !== 'object' || value === null) return null
  const r = value as Record<string, unknown>
  if (typeof r.id !== 'string' || r.id === '') return null
  return {
    id: r.id,
    timestamp: str(r.timestamp),
    event_type: str(r.event_type),
    action: str(r.action),
    user_id: str(r.user_id),
    user_type: str(r.user_type),
    resource_type: str(r.resource_type),
    resource_id: str(r.resource_id),
    resource_name: str(r.resource_name),
    result: str(r.result),
    severity: str(r.severity),
    source: str(r.source),
    ip_address: str(r.ip_address),
    method: str(r.method),
    path: str(r.path),
    error_code: str(r.error_code),
    error_message: str(r.error_message),
  }
}

/** Validate + parse the bare array returned by GET /api/v1/audit/entries. */
export function parseAuditEntries(data: unknown): AuditEntry[] {
  if (!Array.isArray(data)) throw new Error('unexpected response shape')
  const entries: AuditEntry[] = []
  for (const item of data) {
    const entry = parseAuditEntry(item)
    if (entry !== null) entries.push(entry)
  }
  return entries
}

interface FetchOutcome {
  key: string
  entries?: AuditEntry[]
  error?: string
  fetchedAtMs: number
}

export function useAuditEntries(filters: AuditFilters): UseAuditEntriesResult {
  const [attempt, setAttempt] = useState(0)
  const [outcome, setOutcome] = useState<FetchOutcome | null>(null)

  const retry = useCallback(() => setAttempt((n) => n + 1), [])

  const {
    since,
    until,
    severity,
    action,
    event_type,
    user_id,
    result,
    limit,
    offset,
  } = filters
  const moduleFilter = filters.module

  const key = `${since}:${until}:${severity}:${action}:${event_type}:${user_id}:${result}:${moduleFilter}:${limit}:${offset}:${attempt}`

  useEffect(() => {
    let cancelled = false
    const params = new URLSearchParams()
    params.set('limit', String(limit))
    params.set('offset', String(offset))
    if (since) params.set('since', since)
    if (until) params.set('until', until)
    if (severity) params.set('severity', severity)
    if (action) params.set('action', action)
    if (event_type) params.set('event_type', event_type)
    if (user_id) params.set('user_id', user_id)
    if (result) params.set('result', result)
    if (moduleFilter) params.set('module', moduleFilter)

    apiFetch(`/api/v1/audit/entries?${params.toString()}`)
      .then(async (response) => {
        if (!response.ok) {
          throw new Error(`GET /api/v1/audit/entries — ${response.status}`)
        }
        const body: unknown = await response.json()
        const parsed = parseAuditEntries(
          (body as Record<string, unknown> | null)?.data,
        )
        if (cancelled) return
        setOutcome({ key, entries: parsed, fetchedAtMs: Date.now() })
      })
      .catch((cause: unknown) => {
        if (cancelled) return
        setOutcome({
          key,
          error:
            cause instanceof Error && cause.message
              ? cause.message
              : 'GET /api/v1/audit/entries — request failed',
          fetchedAtMs: Date.now(),
        })
      })
    return () => {
      cancelled = true
    }
  }, [key, since, until, severity, action, event_type, user_id, result, moduleFilter, limit, offset])

  const current = outcome?.key === key ? outcome : null
  return {
    entries: current?.entries ?? [],
    loading: current === null,
    error: current?.error ?? null,
    fetchedAtMs: current?.fetchedAtMs ?? 0,
    retry,
  }
}
