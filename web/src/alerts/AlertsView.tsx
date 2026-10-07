// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Alerts page (Issue #4584) — docs/design/mockups/visibility-surfaces.html.
 *
 * Shares one feed hook and the acknowledge/silence/unsilence actions with the
 * bell popover (AlertCenter). Filtering by severity is client-side; the Show
 * silenced toggle re-requests the feed with include_silenced=true. Silence and
 * Unsilence are step-up gated centrally by apiFetch.
 *
 * States: Loading, Error (with retry), Empty, Ready.
 */
import { useState } from 'react'
import AlertSeverity from '../shell/AlertSeverity.tsx'
import { useAlerts } from '../shell/useAlerts.ts'
import type { Alert } from '../shell/useAlerts.ts'
import '../compliance/ComplianceSummaryView.css'

const SILENCE_HOURS = 24

type SeverityFilter = 'all' | 'critical' | 'warning'

const FILTERS: { value: SeverityFilter; label: string }[] = [
  { value: 'all', label: 'Warning + critical' },
  { value: 'critical', label: 'Critical only' },
  { value: 'warning', label: 'Warning only' },
]

function matches(alert: Alert, filter: SeverityFilter): boolean {
  return filter === 'all' || alert.severity === filter
}

export default function AlertsView() {
  const [filter, setFilter] = useState<SeverityFilter>('all')
  const [showSilenced, setShowSilenced] = useState(false)
  const [actionError, setActionError] = useState<string | null>(null)
  const { alerts, loading, error, acknowledge, silence, unsilence, refresh } = useAlerts(true, {
    includeSilenced: showSilenced,
  })

  async function run(action: () => ReturnType<typeof acknowledge>) {
    setActionError(null)
    const result = await action()
    if (!result.ok) setActionError(result.error)
  }

  const rows = alerts.filter((a) => matches(a, filter))

  return (
    <div className="cs-content" data-testid="alerts-view">
      <div className="cs-header">
        <div>
          <h1>Alerts</h1>
          <p>Active alerts across the fleet.</p>
        </div>
        <div style={{ display: 'flex', gap: 'var(--space-3)', alignItems: 'center' }}>
          <label>
            <span style={{ marginRight: 'var(--space-2)' }}>Severity</span>
            <select
              aria-label="Severity filter"
              value={filter}
              onChange={(e) => setFilter(e.target.value as SeverityFilter)}
            >
              {FILTERS.map((f) => (
                <option key={f.value} value={f.value}>
                  {f.label}
                </option>
              ))}
            </select>
          </label>
          <label>
            <input
              type="checkbox"
              checked={showSilenced}
              onChange={(e) => setShowSilenced(e.target.checked)}
            />{' '}
            Show silenced
          </label>
        </div>
      </div>

      {actionError !== null && (
        <div className="cs-notice err" role="alert" data-testid="alerts-action-error">
          {actionError}
        </div>
      )}

      {loading && (
        <div className="cs-panel" data-testid="alerts-loading" aria-busy="true">
          {[0, 1, 2].map((i) => (
            <span
              key={i}
              className="cs-skel"
              style={{ height: '34px', marginTop: '10px', display: 'block' }}
            />
          ))}
        </div>
      )}

      {!loading && error !== null && (
        <div className="cs-notice err" role="alert" data-testid="alerts-error">
          <div className="cs-notice-body">
            <b>Could not load alerts.</b>
            <p className="cs-notice-sub">{error}</p>
            <button type="button" className="cs-btn" onClick={refresh}>
              Retry
            </button>
          </div>
        </div>
      )}

      {!loading && error === null && rows.length === 0 && (
        <div className="cs-notice" data-testid="alerts-empty">
          <p>No alerts.</p>
        </div>
      )}

      {!loading && error === null && rows.length > 0 && (
        <div className="cs-panel">
          <table className="cs-tbl" data-testid="alerts-table">
            <thead>
              <tr>
                <th className="cs-th">Severity</th>
                <th className="cs-th">Device</th>
                <th className="cs-th">Finding</th>
                <th className="cs-th">Actions</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((alert) => (
                <tr key={alert.id} data-testid="alerts-row">
                  <td>
                    <AlertSeverity severity={alert.severity} />
                  </td>
                  <td>{alert.device_id}</td>
                  <td>
                    <div>{alert.description}</div>
                    {alert.acknowledged && alert.acknowledged_by !== '' && (
                      <div className="cs-tile-sub">acknowledged by {alert.acknowledged_by}</div>
                    )}
                    {alert.silenced && alert.silenced_by !== '' && (
                      <div className="cs-tile-sub">silenced by {alert.silenced_by}</div>
                    )}
                  </td>
                  <td>
                    {!alert.acknowledged && (
                      <button
                        type="button"
                        className="cs-btn"
                        aria-label={`Acknowledge: ${alert.description}`}
                        onClick={() => void run(() => acknowledge(alert.id))}
                      >
                        Acknowledge
                      </button>
                    )}{' '}
                    {alert.silenced ? (
                      <button
                        type="button"
                        className="cs-btn"
                        aria-label={`Unsilence: ${alert.description}`}
                        onClick={() => void run(() => unsilence(alert.id))}
                      >
                        Unsilence
                      </button>
                    ) : (
                      <button
                        type="button"
                        className="cs-btn"
                        aria-label={`Silence: ${alert.description}`}
                        onClick={() =>
                          void run(() =>
                            silence(
                              alert.id,
                              new Date(Date.now() + SILENCE_HOURS * 60 * 60 * 1000),
                            ),
                          )
                        }
                      >
                        Silence
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
