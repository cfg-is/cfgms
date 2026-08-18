// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Alert data hook (Issue #3275): fetch-on-open from
 * GET /api/v1/reports/dashboard/alerts, with acknowledge and silence actions.
 *
 * Fetch strategy: fetch-on-open (not polling). The popover is typically open
 * for seconds; polling while closed would be wasteful, and there is no existing
 * polling convention in web/src/ to mirror. refresh() re-fetches after a
 * mutation so the list reflects acknowledged/silenced state without a full page
 * reload. The badge count (totalAlerts) persists across popover close/open cycles
 * so the bell stays informative after a first visit.
 *
 * Loading state is derived (not set synchronously in the effect body) following
 * the same pattern as useReportsDashboard: `loading = open && current === null`,
 * where `current` is the resolved state for the latest fetch key.
 *
 * Mutations return an ActionResult rather than throwing, matching the
 * postAction convention in modules/useModuleQueue.ts. A failed acknowledge or
 * silence (403 insufficient permission, a cancelled step-up ceremony, 5xx, or a
 * network-level throw) must reach the caller: refresh() only runs on success, so
 * the UI never re-renders unchanged state as if the action had taken effect.
 */
import { useCallback, useEffect, useState } from 'react'
import { apiFetch } from '../api/client.ts'

export interface Alert {
  id: string
  timestamp: string
  device_id: string
  severity: string
  description: string
  acknowledged: boolean
  silenced: boolean
}

/** Outcome of an alert mutation; mirrors modules/useModuleQueue.ts ActionResult. */
export type ActionResult = { ok: true } | { ok: false; error: string }

export interface UseAlertsResult {
  alerts: Alert[]
  totalAlerts: number
  loading: boolean
  error: string | null
  acknowledge: (id: string) => Promise<ActionResult>
  silence: (id: string, until: Date) => Promise<ActionResult>
  refresh: () => void
}

interface AlertsState {
  key: number
  alerts?: Alert[]
  totalAlerts?: number
  error?: string
}

function parseAlert(value: unknown): Alert | null {
  if (typeof value !== 'object' || value === null) return null
  const r = value as Record<string, unknown>
  if (typeof r.id !== 'string' || r.id === '') return null
  return {
    id: r.id,
    timestamp: typeof r.timestamp === 'string' ? r.timestamp : '',
    device_id: typeof r.device_id === 'string' ? r.device_id : '',
    severity: typeof r.severity === 'string' ? r.severity : '',
    description: typeof r.description === 'string' ? r.description : '',
    acknowledged: r.acknowledged === true,
    silenced: r.silenced === true,
  }
}

/**
 * POST an alert mutation, converting both a non-2xx response and a network-level
 * throw into an ActionResult so no failure is swallowed and no caller is handed a
 * rejected promise. The operator-facing message prefers the server's error
 * envelope ({ error: { message } }) and falls back to the status code.
 */
async function postAlertAction(path: string, init: RequestInit): Promise<ActionResult> {
  try {
    const response = await apiFetch(path, init)
    if (!response.ok) {
      const errBody = (await response.json().catch(() => ({}))) as Record<string, unknown>
      const errMsg =
        ((errBody?.error as Record<string, unknown>)?.message as string) ||
        `Request failed — ${response.status}`
      return { ok: false, error: errMsg }
    }
    return { ok: true }
  } catch (cause: unknown) {
    return {
      ok: false,
      error: cause instanceof Error && cause.message ? cause.message : 'Request failed',
    }
  }
}

export function useAlerts(open: boolean): UseAlertsResult {
  const [gen, setGen] = useState(0)
  const [state, setState] = useState<AlertsState | null>(null)

  const refresh = useCallback(() => setGen((n) => n + 1), [])

  useEffect(() => {
    if (!open) return
    let cancelled = false
    const key = gen
    apiFetch('/api/v1/reports/dashboard/alerts')
      .then(async (r) => {
        if (!r.ok) {
          throw new Error(`GET /api/v1/reports/dashboard/alerts — ${r.status}`)
        }
        const body = await r.json() as unknown
        if (typeof body !== 'object' || body === null) {
          throw new Error('unexpected alerts response shape')
        }
        const b = body as Record<string, unknown>
        const parsed: Alert[] = []
        if (Array.isArray(b.alerts)) {
          for (const a of b.alerts) {
            const alert = parseAlert(a)
            if (alert !== null) parsed.push(alert)
          }
        }
        const total = typeof b.total_alerts === 'number' ? b.total_alerts : parsed.length
        if (!cancelled) {
          setState({ key, alerts: parsed, totalAlerts: total })
        }
      })
      .catch((cause: unknown) => {
        if (!cancelled) {
          setState({
            key,
            error:
              cause instanceof Error && cause.message
                ? cause.message
                : 'Failed to load alerts',
          })
        }
      })
    return () => {
      cancelled = true
    }
  }, [open, gen])

  const current = state?.key === gen ? state : null
  const loading = open && current === null

  const acknowledge = useCallback(
    async (id: string): Promise<ActionResult> => {
      const result = await postAlertAction(
        `/api/v1/alerts/${encodeURIComponent(id)}/acknowledge`,
        { method: 'POST' },
      )
      if (result.ok) refresh()
      return result
    },
    [refresh],
  )

  const silence = useCallback(
    async (id: string, until: Date): Promise<ActionResult> => {
      const result = await postAlertAction(
        `/api/v1/alerts/${encodeURIComponent(id)}/silence`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ until: until.toISOString() }),
        },
      )
      if (result.ok) refresh()
      return result
    },
    [refresh],
  )

  return {
    alerts: current?.alerts ?? [],
    totalAlerts: current?.totalAlerts ?? 0,
    loading,
    error: current?.error ?? null,
    acknowledge,
    silence,
    refresh,
  }
}
