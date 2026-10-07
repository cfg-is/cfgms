// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Monitoring data hook (Story #3274): fetches system health, monitoring
 * configuration, and anomalies from three independent endpoints in parallel.
 *
 * Response shapes match the Go handlers in
 * features/controller/api/handlers_monitoring.go:
 *   SystemHealth     → GET /api/v1/monitoring/health
 *   MonitoringConfig → GET /api/v1/monitoring/config
 *   AnomaliesData    → GET /api/v1/monitoring/anomalies
 *
 * Component health (GET /api/v1/monitoring/components/{component}/health)
 * always returns 503 ("Platform monitor not initialized") — the view renders
 * that section as a designed Error state without fetching on load.
 *
 * All three endpoints are fetched in parallel. Each section exposes an
 * independent error field so the view can render partial results: a config
 * error doesn't blank the health panel and vice versa.
 */
import { useCallback, useEffect, useState } from 'react'
import { apiFetch } from '../api/client.ts'

export interface SystemHealth {
  status: string
  timestamp: string
  version: string
  uptime: string
  components: Record<string, string>
  dependencies: Record<string, string>
}

export type MonitoringConfigSection = Record<string, boolean | string | number>

export type MonitoringConfig = Record<string, MonitoringConfigSection>

export interface AnomaliesData {
  anomalies: unknown[]
  total: number
  summary: {
    total_anomalies: number
    active_anomalies: number
    severity_counts: Record<string, number>
    type_counts: Record<string, number>
  }
}

export interface UseMonitoringResult {
  health: SystemHealth | null
  config: MonitoringConfig | null
  anomalies: AnomaliesData | null
  loading: boolean
  healthError: string | null
  configError: string | null
  anomaliesError: string | null
  retry: () => void
}

type EndpointResult<T> = { data: T; error: null } | { data: null; error: string }

function parseHealth(body: unknown): SystemHealth {
  if (typeof body !== 'object' || body === null) {
    throw new Error('unexpected health response shape')
  }
  const r = body as Record<string, unknown>
  return {
    status: typeof r.status === 'string' ? r.status : 'unknown',
    timestamp: typeof r.timestamp === 'string' ? r.timestamp : '',
    version: typeof r.version === 'string' ? r.version : '',
    uptime: typeof r.uptime === 'string' ? r.uptime : 'unknown',
    components:
      typeof r.components === 'object' && r.components !== null
        ? Object.fromEntries(
            Object.entries(r.components as Record<string, unknown>).filter(
              (e): e is [string, string] => typeof e[1] === 'string',
            ),
          )
        : {},
    dependencies:
      typeof r.dependencies === 'object' && r.dependencies !== null
        ? Object.fromEntries(
            Object.entries(r.dependencies as Record<string, unknown>).filter(
              (e): e is [string, string] => typeof e[1] === 'string',
            ),
          )
        : {},
  }
}

function parseConfig(body: unknown): MonitoringConfig {
  if (typeof body !== 'object' || body === null) {
    throw new Error('unexpected config response shape')
  }
  return Object.fromEntries(
    Object.entries(body as Record<string, unknown>)
      .filter(([, vals]) => typeof vals === 'object' && vals !== null)
      .map(([section, vals]) => [
        section,
        Object.fromEntries(
          Object.entries(vals as Record<string, unknown>).filter(
            ([, v]) => typeof v === 'boolean' || typeof v === 'string' || typeof v === 'number',
          ),
        ) as MonitoringConfigSection,
      ]),
  )
}

function parseAnomalies(body: unknown): AnomaliesData {
  if (typeof body !== 'object' || body === null) {
    throw new Error('unexpected anomalies response shape')
  }
  const r = body as Record<string, unknown>
  const summary =
    typeof r.summary === 'object' && r.summary !== null
      ? (r.summary as Record<string, unknown>)
      : {}
  return {
    anomalies: Array.isArray(r.anomalies) ? r.anomalies : [],
    total: typeof r.total === 'number' ? r.total : 0,
    summary: {
      total_anomalies:
        typeof summary.total_anomalies === 'number' ? summary.total_anomalies : 0,
      active_anomalies:
        typeof summary.active_anomalies === 'number' ? summary.active_anomalies : 0,
      severity_counts:
        typeof summary.severity_counts === 'object' && summary.severity_counts !== null
          ? Object.fromEntries(
              Object.entries(
                summary.severity_counts as Record<string, unknown>,
              ).filter((e): e is [string, number] => typeof e[1] === 'number'),
            )
          : {},
      type_counts:
        typeof summary.type_counts === 'object' && summary.type_counts !== null
          ? Object.fromEntries(
              Object.entries(summary.type_counts as Record<string, unknown>).filter(
                (e): e is [string, number] => typeof e[1] === 'number',
              ),
            )
          : {},
    },
  }
}

function toMessage(cause: unknown, endpoint: string): string {
  return cause instanceof Error && cause.message
    ? cause.message
    : `${endpoint} — request failed`
}

async function fetchEndpoint<T>(
  url: string,
  parse: (body: unknown) => T,
): Promise<EndpointResult<T>> {
  try {
    const r = await apiFetch(url)
    if (!r.ok) {
      return { data: null, error: `GET ${url} — ${r.status}` }
    }
    const body = (await r.json()) as Record<string, unknown> | null
    const data = parse(body?.data ?? body)
    return { data, error: null }
  } catch (cause) {
    return { data: null, error: toMessage(cause, url) }
  }
}

interface FetchState {
  key: string
  health: SystemHealth | null
  config: MonitoringConfig | null
  anomalies: AnomaliesData | null
  healthError: string | null
  configError: string | null
  anomaliesError: string | null
}

export function useMonitoring(): UseMonitoringResult {
  const [attempt, setAttempt] = useState(0)
  const [state, setState] = useState<FetchState | null>(null)

  const retry = useCallback(() => setAttempt((n) => n + 1), [])

  const key = String(attempt)

  useEffect(() => {
    let cancelled = false

    Promise.all([
      fetchEndpoint('/api/v1/monitoring/health', parseHealth),
      fetchEndpoint('/api/v1/monitoring/config', parseConfig),
      fetchEndpoint('/api/v1/monitoring/anomalies', parseAnomalies),
    ]).then(([healthResult, configResult, anomaliesResult]) => {
      if (cancelled) return
      setState({
        key,
        health: healthResult.data,
        config: configResult.data,
        anomalies: anomaliesResult.data,
        healthError: healthResult.error,
        configError: configResult.error,
        anomaliesError: anomaliesResult.error,
      })
    })

    return () => {
      cancelled = true
    }
  }, [key])

  const current = state?.key === key ? state : null

  return {
    health: current?.health ?? null,
    config: current?.config ?? null,
    anomalies: current?.anomalies ?? null,
    loading: current === null,
    healthError: current?.healthError ?? null,
    configError: current?.configError ?? null,
    anomaliesError: current?.anomaliesError ?? null,
    retry,
  }
}
