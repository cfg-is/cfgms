// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Reports dashboard data hook (Story #3270): parallel fetch of
 * GET /api/v1/reports/dashboard/overview and
 * GET /api/v1/reports/dashboard/trends via the existing apiFetch wrapper.
 *
 * Response shape:
 *   overview — { summary, metadata, time_range, generated_at, kpis? }
 *   trends   — { charts, time_range, generated_at, trend_analysis? }
 *
 * Both kpis and trend_analysis are optional; their absence is a partial/empty
 * state, not an error. The hook surfaces a single error state when either
 * request fails so the view always presents a coherent four-state model.
 */
import { useCallback, useEffect, useState } from 'react'
import { apiFetch } from '../api/client.ts'
import type { ChartData, DataPoint } from './palette.ts'

export interface OverviewSummary {
  devices_analyzed: number
  drift_events_total: number
  compliance_score: number
  critical_issues: number
  trend_direction: string
  key_insights?: string[]
  recommended_actions?: string[]
}

export interface OverviewMetadata {
  template: string
  device_count: number
  data_points: number
  generation_ms: number
  cache_hit: boolean
}

export interface OverviewData {
  summary: OverviewSummary
  metadata: OverviewMetadata
  time_range: { start: string; end: string }
  generated_at: string
  kpis?: unknown
}

export interface TrendsData {
  charts: ChartData[]
  time_range: { start: string; end: string }
  generated_at: string
  trend_analysis?: unknown
}

export interface ReportsDashboardData {
  overview: OverviewData
  trends: TrendsData
}

export interface UseReportsDashboardResult {
  data: ReportsDashboardData | null
  loading: boolean
  /** User-presentable failure line, e.g. "GET /api/v1/reports/dashboard/overview — 503". */
  error: string | null
  retry: () => void
}

function parseOverview(body: unknown): OverviewData {
  if (typeof body !== 'object' || body === null) {
    throw new Error('unexpected overview response shape')
  }
  const r = body as Record<string, unknown>
  if (typeof r.summary !== 'object' || r.summary === null) {
    throw new Error('unexpected overview response shape')
  }
  const s = r.summary as Record<string, unknown>
  const summary: OverviewSummary = {
    devices_analyzed: typeof s.devices_analyzed === 'number' ? s.devices_analyzed : 0,
    drift_events_total: typeof s.drift_events_total === 'number' ? s.drift_events_total : 0,
    compliance_score: typeof s.compliance_score === 'number' ? s.compliance_score : 0,
    critical_issues: typeof s.critical_issues === 'number' ? s.critical_issues : 0,
    trend_direction: typeof s.trend_direction === 'string' ? s.trend_direction : 'unknown',
    key_insights: Array.isArray(s.key_insights)
      ? s.key_insights.filter((x): x is string => typeof x === 'string')
      : undefined,
    recommended_actions: Array.isArray(s.recommended_actions)
      ? s.recommended_actions.filter((x): x is string => typeof x === 'string')
      : undefined,
  }
  const m = typeof r.metadata === 'object' && r.metadata !== null
    ? (r.metadata as Record<string, unknown>)
    : {}
  const metadata: OverviewMetadata = {
    template: typeof m.template === 'string' ? m.template : '',
    device_count: typeof m.device_count === 'number' ? m.device_count : 0,
    data_points: typeof m.data_points === 'number' ? m.data_points : 0,
    generation_ms: typeof m.generation_ms === 'number' ? m.generation_ms : 0,
    cache_hit: typeof m.cache_hit === 'boolean' ? m.cache_hit : false,
  }
  const tr = typeof r.time_range === 'object' && r.time_range !== null
    ? (r.time_range as Record<string, unknown>)
    : {}
  return {
    summary,
    metadata,
    time_range: {
      start: typeof tr.start === 'string' ? tr.start : '',
      end: typeof tr.end === 'string' ? tr.end : '',
    },
    generated_at: typeof r.generated_at === 'string' ? r.generated_at : '',
    kpis: r.kpis,
  }
}

function parseDataPoint(v: unknown): DataPoint | null {
  if (typeof v !== 'object' || v === null) return null
  const p = v as Record<string, unknown>
  if ((typeof p.x !== 'string' && typeof p.x !== 'number') || typeof p.y !== 'number') return null
  return { x: p.x as string | number, y: p.y }
}

function parseChart(v: unknown): ChartData | null {
  if (typeof v !== 'object' || v === null) return null
  const c = v as Record<string, unknown>
  if (typeof c.id !== 'string' || typeof c.title !== 'string') return null
  if (typeof c.x_axis !== 'object' || c.x_axis === null) return null
  if (typeof c.y_axis !== 'object' || c.y_axis === null) return null
  const xa = c.x_axis as Record<string, unknown>
  const ya = c.y_axis as Record<string, unknown>
  if (typeof xa.title !== 'string' || typeof xa.type !== 'string') return null
  if (typeof ya.title !== 'string' || typeof ya.type !== 'string') return null
  if (!Array.isArray(c.series)) return null
  const series = c.series.map((s: unknown) => {
    if (typeof s !== 'object' || s === null) return null
    const sr = s as Record<string, unknown>
    if (typeof sr.name !== 'string') return null
    const data = Array.isArray(sr.data) ? sr.data.flatMap((p: unknown) => {
      const pt = parseDataPoint(p)
      return pt !== null ? [pt] : []
    }) : []
    return { name: sr.name, data }
  })
  if (series.some(s => s === null)) return null
  return {
    id: c.id,
    type: (typeof c.type === 'string' ? c.type : 'line') as ChartData['type'],
    title: c.title,
    series: series as ChartData['series'],
    x_axis: { title: xa.title, type: xa.type },
    y_axis: { title: ya.title, type: ya.type },
    config: typeof c.config === 'object' && c.config !== null
      ? c.config as ChartData['config']
      : undefined,
  }
}

function parseTrends(body: unknown): TrendsData {
  if (typeof body !== 'object' || body === null) {
    throw new Error('unexpected trends response shape')
  }
  const r = body as Record<string, unknown>
  const charts: ChartData[] = []
  if (Array.isArray(r.charts)) {
    for (const c of r.charts) {
      const chart = parseChart(c)
      if (chart !== null) charts.push(chart)
    }
  }
  const tr = typeof r.time_range === 'object' && r.time_range !== null
    ? (r.time_range as Record<string, unknown>)
    : {}
  return {
    charts,
    time_range: {
      start: typeof tr.start === 'string' ? tr.start : '',
      end: typeof tr.end === 'string' ? tr.end : '',
    },
    generated_at: typeof r.generated_at === 'string' ? r.generated_at : '',
    trend_analysis: r.trend_analysis,
  }
}

interface FetchState {
  key: number
  data?: ReportsDashboardData
  error?: string
}

export function useReportsDashboard(): UseReportsDashboardResult {
  const [attempt, setAttempt] = useState(0)
  const [state, setState] = useState<FetchState | null>(null)

  const retry = useCallback(() => setAttempt((n) => n + 1), [])

  useEffect(() => {
    let cancelled = false
    Promise.all([
      apiFetch('/api/v1/reports/dashboard/overview').then(async (r) => {
        if (!r.ok) {
          throw new Error(`GET /api/v1/reports/dashboard/overview — ${r.status}`)
        }
        return parseOverview(await r.json() as unknown)
      }),
      apiFetch('/api/v1/reports/dashboard/trends').then(async (r) => {
        if (!r.ok) {
          throw new Error(`GET /api/v1/reports/dashboard/trends — ${r.status}`)
        }
        return parseTrends(await r.json() as unknown)
      }),
    ])
      .then(([overview, trends]) => {
        if (cancelled) return
        setState({ key: attempt, data: { overview, trends } })
      })
      .catch((cause: unknown) => {
        if (cancelled) return
        setState({
          key: attempt,
          error:
            cause instanceof Error && cause.message
              ? cause.message
              : 'Reports dashboard request failed',
        })
      })
    return () => {
      cancelled = true
    }
  }, [attempt])

  const current = state?.key === attempt ? state : null
  return {
    data: current?.data ?? null,
    loading: current === null,
    error: current?.error ?? null,
    retry,
  }
}
