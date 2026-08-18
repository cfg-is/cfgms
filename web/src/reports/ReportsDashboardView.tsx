// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Reports dashboard view (Story #3270) — KPI stat tiles from
 * GET /api/v1/reports/dashboard/overview and a trend chart from
 * GET /api/v1/reports/dashboard/trends.
 *
 * Four data states: Loading (skeleton), Error (notice + retry), Empty
 * (zero devices), Ready (tiles + chart + insights).
 *
 * Palette rules (design system §4): series colours are mapped by index into
 * --cat-* tokens via TrendChart/buildSeriesSlots — never from the wire. The
 * trend direction pill uses --state-ok / --state-crit / --state-neutral, never
 * a raw hex value.
 */

import { useReportsDashboard } from './useReportsDashboard.ts'
import TrendChart from './TrendChart.tsx'
import Sparkline from './Sparkline.tsx'
import './ReportsDashboardView.css'

function CritIcon() {
  return (
    <svg
      width="16"
      height="16"
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.1"
      strokeLinecap="round"
      aria-hidden="true"
    >
      <circle cx="8" cy="8" r="6.2" />
      <path d="M8 4.8v4" />
      <path d="M8 11.2v.05" />
    </svg>
  )
}

function InsightIcon() {
  return (
    <svg
      width="11"
      height="11"
      viewBox="0 0 16 16"
      fill="none"
      stroke="var(--accent)"
      strokeWidth="2"
      strokeLinecap="round"
      aria-hidden="true"
      className="rdb-ico"
    >
      <circle cx="8" cy="8" r="6.2" />
      <path d="M5.4 8h5.2" />
    </svg>
  )
}

function ActionIcon() {
  return (
    <svg
      width="11"
      height="11"
      viewBox="0 0 16 16"
      fill="none"
      stroke="var(--state-ok)"
      strokeWidth="2.1"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      className="rdb-ico"
    >
      <path d="M3 8.5l3.2 3.2L13 5" />
    </svg>
  )
}

function TrendPill({ direction }: { direction: string }) {
  let cls: string
  let label: string
  if (direction === 'improving') {
    cls = 'ok'
    label = 'Improving'
  } else if (direction === 'declining') {
    cls = 'crit'
    label = 'Declining'
  } else if (direction === 'stable') {
    cls = 'neutral'
    label = 'Stable'
  } else {
    cls = 'neutral'
    label = 'Unknown'
  }
  return (
    <span className={`rdb-pill ${cls}`} data-testid="trend-direction-pill">
      {label}
    </span>
  )
}

const PAGE_TITLE = 'Reports'
const PAGE_SUBTITLE = 'Fleet posture for the selected window.'

function PageHeader() {
  return (
    <div className="rdb-header">
      <div>
        <h1>{PAGE_TITLE}</h1>
        <p>{PAGE_SUBTITLE}</p>
      </div>
    </div>
  )
}

export default function ReportsDashboardView() {
  const { data, loading, error, retry } = useReportsDashboard()

  if (loading) {
    return (
      <div className="rdb-content" data-testid="reports-loading">
        <PageHeader />
        <div className="rdb-kpis">
          {[0, 1, 2, 3].map((i) => (
            <div className="rdb-tile" key={i} aria-hidden="true">
              <span className="rdb-skel" style={{ height: '11px', width: '60%' }} />
              <span
                className="rdb-skel"
                style={{ height: '26px', width: '45%', marginTop: '6px' }}
              />
              <span
                className="rdb-skel"
                style={{ height: '11px', width: '35%', marginTop: '6px' }}
              />
            </div>
          ))}
        </div>
        <div className="rdb-panel" aria-hidden="true">
          <span className="rdb-skel" style={{ height: '13px', width: '180px', display: 'block' }} />
          <span
            className="rdb-skel"
            style={{ height: '200px', marginTop: '12px', display: 'block' }}
          />
        </div>
      </div>
    )
  }

  if (error !== null) {
    return (
      <div className="rdb-content">
        <PageHeader />
        <div className="rdb-notice err" role="alert">
          <CritIcon />
          <div className="rdb-notice-body">
            <b>Could not generate the dashboard overview.</b>
            <p className="rdb-notice-sub">{error}</p>
            <button type="button" className="rdb-btn" onClick={retry}>
              Retry
            </button>
          </div>
        </div>
      </div>
    )
  }

  const summary = data?.overview.summary
  if (!summary || summary.devices_analyzed === 0) {
    return (
      <div className="rdb-content">
        <PageHeader />
        <div className="rdb-notice" data-testid="reports-empty">
          <p>No data in this window.</p>
          <p className="rdb-notice-np">
            No stewards reported convergence in the current window. Widen the
            window or check enrollment.
          </p>
        </div>
      </div>
    )
  }

  const metadata = data!.overview.metadata
  const charts = data!.trends.charts
  const firstChart = charts.at(0)
  const sparkValues = firstChart?.series.at(0)?.data.map((p) => p.y)
  const keyInsights = summary.key_insights ?? []
  const recommendedActions = summary.recommended_actions ?? []
  const showInsightPanels = keyInsights.length > 0 || recommendedActions.length > 0

  return (
    <div className="rdb-content" data-testid="reports-ready">
      <PageHeader />

      {/* Hero: compliance score + trend direction */}
      <div className="rdb-panel">
        <div className="rdb-hero-wrap">
          <div>
            <span className="rdb-hero-label">Devices without observed drift</span>
            <div className="rdb-hero" data-testid="compliance-score">
              {summary.compliance_score}%
            </div>
          </div>
          <div className="rdb-hero-side">
            <TrendPill direction={summary.trend_direction} />
            <span className="rdb-tile-sub">vs previous window</span>
          </div>
          <p className="rdb-hero-note">
            {summary.devices_analyzed.toLocaleString()} devices analysed over{' '}
            {metadata.data_points.toLocaleString()} data points.
          </p>
        </div>
      </div>

      {/* KPI tiles */}
      <div className="rdb-kpis" data-testid="kpi-tiles">
        <div className="rdb-tile" data-testid="kpi-devices-analyzed">
          <span className="rdb-tile-label">Devices analysed</span>
          <div className="rdb-tile-row">
            <span className="rdb-tile-value">
              {summary.devices_analyzed.toLocaleString()}
            </span>
          </div>
          <span className="rdb-tile-sub">in tenant scope</span>
        </div>

        <div className="rdb-tile" data-testid="kpi-drift-events">
          <span className="rdb-tile-label">Drift events</span>
          <div className="rdb-tile-row">
            <span className="rdb-tile-value">{summary.drift_events_total}</span>
            {sparkValues !== undefined && sparkValues.length >= 2 && (
              <Sparkline values={sparkValues} />
            )}
          </div>
        </div>

        <div className="rdb-tile" data-testid="kpi-critical-issues">
          <span className="rdb-tile-label">Critical issues</span>
          <div className="rdb-tile-row">
            <span className="rdb-tile-value">{summary.critical_issues}</span>
          </div>
        </div>

        <div className="rdb-tile" data-testid="kpi-generation-ms">
          <span className="rdb-tile-label">Report generated in</span>
          <div className="rdb-tile-row">
            <span className="rdb-tile-value">{metadata.generation_ms} ms</span>
          </div>
          <span className="rdb-tile-sub">
            {metadata.cache_hit ? 'cache hit' : 'computed fresh'}
          </span>
        </div>
      </div>

      {/* Trend chart */}
      {firstChart !== undefined && (
        <div className="rdb-panel">
          <TrendChart chart={firstChart} />
        </div>
      )}

      {/* Key insights + Recommended actions */}
      {showInsightPanels && (
        <div className="rdb-two">
          {keyInsights.length > 0 && (
            <div className="rdb-panel">
              <h2>Key insights</h2>
              <p className="rdb-panel-sub">From the report summary</p>
              <ul className="rdb-ilist">
                {keyInsights.map((text, i) => (
                  <li key={i}>
                    <InsightIcon />
                    <span>{text}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
          {recommendedActions.length > 0 && (
            <div className="rdb-panel">
              <h2>Recommended actions</h2>
              <p className="rdb-panel-sub">Ordered by expected impact</p>
              <ul className="rdb-ilist">
                {recommendedActions.map((text, i) => (
                  <li key={i}>
                    <ActionIcon />
                    <span>{text}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
