// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Monitoring view (Story #3274): system health, monitoring configuration, and
 * anomaly detection — sourced from GET /api/v1/monitoring/health, /config,
 * and /anomalies.
 *
 * Four sections:
 *   1. System health — overall status pill + per-component status pills +
 *      dependency map (from SystemHealth's components/dependencies maps).
 *   2. Anomalies — always-empty list with a designed Empty state (the
 *      server returns [] today; the section is drawn to match the mockup).
 *   3. Component detail — always-503 designed Error state matching the
 *      "Platform monitor not initialized" posture described in the story.
 *   4. Monitoring config — read-only key-value groups from /config.
 *
 * Status pill colour mapping (cstate from visibility-surfaces.html):
 *   "healthy"      → ok
 *   "degraded"     → warn
 *   "unhealthy"    → crit
 *   everything else → neutral  (covers "no_connections", "available", etc.)
 */
import { useMonitoring } from './useMonitoring.ts'
import './MonitoringView.css'

// ── Icons ──────────────────────────────────────────────────────────────────

function OkIcon() {
  return (
    <svg
      width="11"
      height="11"
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.1"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M3 8.5l3.2 3.2L13 5" />
    </svg>
  )
}

function WarnIcon() {
  return (
    <svg
      width="11"
      height="11"
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M8 2.6L14.6 13.4H1.4z" />
      <path d="M8 6.6v3.1" />
      <path d="M8 11.8v.05" />
    </svg>
  )
}

function CritIcon() {
  return (
    <svg
      width="11"
      height="11"
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

function NeutIcon() {
  return (
    <svg
      width="11"
      height="11"
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      aria-hidden="true"
    >
      <circle cx="8" cy="8" r="6.2" />
      <path d="M5.4 8h5.2" />
    </svg>
  )
}

// ── Status pill ────────────────────────────────────────────────────────────

type PillVariant = 'ok' | 'warn' | 'crit' | 'neutral'

function statusToVariant(status: string): PillVariant {
  switch (status) {
    case 'healthy':
      return 'ok'
    case 'degraded':
      return 'warn'
    case 'unhealthy':
      return 'crit'
    default:
      return 'neutral'
  }
}

function PillIcon({ variant }: { variant: PillVariant }) {
  switch (variant) {
    case 'ok':
      return <OkIcon />
    case 'warn':
      return <WarnIcon />
    case 'crit':
      return <CritIcon />
    default:
      return <NeutIcon />
  }
}

function StatusPill({
  status,
  label,
  testId,
}: {
  status: string
  label?: string
  testId?: string
}) {
  const variant = statusToVariant(status)
  const displayText = (label ?? status).replace(/_/g, ' ')
  return (
    <span className={`mv-pill ${variant}`} data-testid={testId}>
      <PillIcon variant={variant} />
      {displayText}
    </span>
  )
}

// ── Page header ────────────────────────────────────────────────────────────

function PageHeader() {
  return (
    <div className="mv-header">
      <div>
        <h1>Monitoring</h1>
        <p>Controller health, configuration and anomalies.</p>
      </div>
    </div>
  )
}

// ── Error notice (shared) ──────────────────────────────────────────────────

function SectionError({
  message,
  onRetry,
  testId,
}: {
  message: string
  onRetry?: () => void
  testId?: string
}) {
  return (
    <div className="mv-notice err" role="alert" data-testid={testId}>
      <CritIcon />
      <div className="mv-notice-body">
        <b>Could not load this section.</b>
        <p className="mv-notice-sub">{message}</p>
        {onRetry && (
          <button type="button" className="mv-btn" onClick={onRetry}>
            Retry
          </button>
        )}
      </div>
    </div>
  )
}

// ── Health section ─────────────────────────────────────────────────────────

function HealthSection({
  health,
  healthError,
  onRetry,
}: {
  health: { status: string; timestamp: string; version: string; uptime: string; components: Record<string, string>; dependencies: Record<string, string> } | null
  healthError: string | null
  onRetry: () => void
}) {
  if (healthError !== null) {
    return (
      <div className="mv-panel">
        <h2>System health</h2>
        <SectionError message={healthError} onRetry={onRetry} testId="health-error" />
      </div>
    )
  }

  if (health === null) return null

  const overallVariant = statusToVariant(health.status)
  const ts = health.timestamp
    ? health.timestamp.replace('T', ' ').replace('Z', ' UTC')
    : ''

  return (
    <div className="mv-panel" data-testid="monitoring-health">
      <div className="mv-panel-head" data-testid="health-panel-header">
        <div>
          <h2>System health</h2>
          <p className="mv-panel-sub">
            Controller <span className="mv-mono">{health.version}</span>
            {' · '}uptime <span className="mv-mono">{health.uptime}</span>
          </p>
        </div>
        <StatusPill
          status={health.status}
          label={overallVariant === 'ok' ? 'Healthy' : health.status}
          testId="health-status-pill"
        />
      </div>

      <div className="mv-cgrid mv-mt10">
        {Object.entries(health.components).map(([name, status]) => (
          <div className="mv-ccard" key={name} data-testid={`component-${name}`}>
            <span className="mv-cname mv-mono">{name.replace(/_/g, ' ')}</span>
            <StatusPill status={status} />
          </div>
        ))}
      </div>

      {Object.keys(health.dependencies).length > 0 && (
        <div className="mv-mt12" data-testid="deps-section">
          <span className="mv-lbl">Dependencies</span>
          <div className="mv-cgrid mv-mt6">
            {Object.entries(health.dependencies).map(([name, value]) => (
              <div className="mv-ccard" key={name} data-testid={`dep-${name}`}>
                <span className="mv-cname mv-mono">{name}</span>
                <span className="mv-dep-val mv-mono">{value}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {ts && (
        <p className="mv-timestamp">
          Checked <span className="mv-mono">{ts}</span>
        </p>
      )}
    </div>
  )
}

// ── Anomalies section ──────────────────────────────────────────────────────

function AnomaliesSection({
  anomalies,
  anomaliesError,
}: {
  anomalies: { anomalies: unknown[]; total: number } | null
  anomaliesError: string | null
}) {
  if (anomaliesError !== null) {
    return (
      <div className="mv-panel">
        <h2>Anomalies</h2>
        <p className="mv-panel-sub">Platform anomaly detection</p>
        <SectionError message={anomaliesError} testId="anomalies-error" />
      </div>
    )
  }

  return (
    <div className="mv-panel">
      <h2>Anomalies</h2>
      <p className="mv-panel-sub">Platform anomaly detection</p>

      {anomalies === null || anomalies.anomalies.length === 0 ? (
        <div className="mv-notice" data-testid="anomalies-empty">
          <p>No anomalies detected.</p>
          <p className="mv-notice-np">
            Anomaly detection reports nothing for this window. This is the
            normal resting state, not a loading failure.
          </p>
        </div>
      ) : (
        <div data-testid="anomalies-list">
          {anomalies.anomalies.map((_, i) => (
            <div key={i} data-testid="anomaly-row" />
          ))}
        </div>
      )}
    </div>
  )
}

// ── Component-detail section (designed error — always 503) ─────────────────

function ComponentDetailSection() {
  return (
    <div className="mv-panel">
      <h2>
        Component detail
        <span className="mv-soon">soon</span>
      </h2>
      <p className="mv-panel-sub">Per-component health</p>
      <div className="mv-notice" data-testid="component-detail-unavailable">
        <p>Per-component detail is unavailable.</p>
        <p className="mv-notice-np">
          The platform monitor is not initialised, so components cannot be
          inspected individually. The summary above still reflects live checks.
        </p>
      </div>
    </div>
  )
}

// ── Config section ─────────────────────────────────────────────────────────

function ConfigSection({
  config,
  configError,
}: {
  config: Record<string, Record<string, boolean | string | number>> | null
  configError: string | null
}) {
  if (configError !== null) {
    return (
      <div className="mv-panel">
        <h2>Monitoring configuration</h2>
        <SectionError message={configError} testId="config-error" />
      </div>
    )
  }

  return (
    <div className="mv-panel" data-testid="monitoring-config">
      <h2>Monitoring configuration</h2>
      <p className="mv-panel-sub">
        Read-only — authored in <span className="mv-mono">controller.cfg</span>
      </p>

      {config !== null && (
        <div className="mv-three">
          {Object.entries(config).map(([section, vals]) => (
            <div key={section} data-testid={`config-section-${section}`}>
              <span className="mv-lbl">{section.replace(/_/g, ' ')}</span>
              <dl className="mv-kv mv-mt6">
                {Object.entries(vals).map(([k, v]) => (
                  <div key={k} className="mv-kv-row">
                    <dt>{k.replace(/_/g, ' ')}</dt>
                    <dd className="mv-mono">
                      {v === '' ? (
                        <span className="mv-faint">—</span>
                      ) : (
                        String(v)
                      )}
                    </dd>
                  </div>
                ))}
              </dl>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ── Main view ──────────────────────────────────────────────────────────────

export default function MonitoringView() {
  const {
    health,
    config,
    anomalies,
    loading,
    healthError,
    configError,
    anomaliesError,
    retry,
  } = useMonitoring()

  if (loading) {
    return (
      <div className="mv-content" data-testid="monitoring-loading" aria-label="Loading monitoring data">
        <PageHeader />
        <div className="mv-panel" aria-hidden="true">
          <span className="mv-skel" style={{ height: '13px', width: '150px', display: 'block' }} />
          <div className="mv-cgrid mv-mt12">
            {[0, 1, 2, 3, 4, 5].map((i) => (
              <span key={i} className="mv-skel" style={{ height: '42px', display: 'block' }} />
            ))}
          </div>
        </div>
        <div className="mv-two" aria-hidden="true">
          <div className="mv-panel">
            <span className="mv-skel" style={{ height: '13px', width: '90px', display: 'block' }} />
            <span className="mv-skel" style={{ height: '60px', marginTop: '12px', display: 'block' }} />
          </div>
          <div className="mv-panel">
            <span className="mv-skel" style={{ height: '13px', width: '130px', display: 'block' }} />
            <span className="mv-skel" style={{ height: '60px', marginTop: '12px', display: 'block' }} />
          </div>
        </div>
        <div className="mv-panel" aria-hidden="true">
          <span className="mv-skel" style={{ height: '13px', width: '200px', display: 'block' }} />
          <div className="mv-three mv-mt12">
            {[0, 1, 2].map((i) => (
              <span key={i} className="mv-skel" style={{ height: '80px', display: 'block' }} />
            ))}
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="mv-content">
      <PageHeader />

      <HealthSection health={health} healthError={healthError} onRetry={retry} />

      <div className="mv-two">
        <AnomaliesSection anomalies={anomalies} anomaliesError={anomaliesError} />
        <ComponentDetailSection />
      </div>

      <ConfigSection config={config} configError={configError} />
    </div>
  )
}
