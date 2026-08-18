// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Alert / notification center (Story #2496, Issue #3275) —
 * mockups/fleet-overview.html `#pop-notif`. Wired to the dashboard-alerts
 * feed via useAlerts; each alert can be acknowledged or silenced in-place.
 *
 * Silence duration is fixed at 24 hours (a date-picker UI is out of scope for
 * this story). The Silence action requires alert:silence (AssuranceStrong) —
 * apiFetch handles the CFGMS-StepUp 401 challenge centrally via the registered
 * onStepUpRequired listener (ADR-021 Decision 6); no bespoke step-up handling
 * is needed here.
 *
 * A refused action (403, a cancelled step-up ceremony, 5xx, network failure)
 * renders as an inline message above the list rather than silently re-fetching
 * unchanged state — same treatment as ModuleReviewQueue's action-error block.
 */
import { useEffect, useRef, useState } from 'react'
import { useAlerts } from './useAlerts.ts'

const SILENCE_HOURS = 24

function severityColor(severity: string): string {
  switch (severity) {
    case 'critical': return 'var(--state-crit)'
    case 'warning': return 'var(--state-warn)'
    default: return 'var(--text-faint)'
  }
}

export default function AlertCenter() {
  const [open, setOpen] = useState(false)
  const rootRef = useRef<HTMLDivElement>(null)
  const { alerts, totalAlerts, loading, error, acknowledge, silence } = useAlerts(open)
  const [actionError, setActionError] = useState<string | null>(null)

  async function handleAcknowledge(id: string) {
    setActionError(null)
    const result = await acknowledge(id)
    if (!result.ok) setActionError(result.error)
  }

  async function handleSilence(id: string) {
    setActionError(null)
    const until = new Date(Date.now() + SILENCE_HOURS * 60 * 60 * 1000)
    const result = await silence(id, until)
    if (!result.ok) setActionError(result.error)
  }

  useEffect(() => {
    if (!open) return
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') setOpen(false)
    }
    function onClickAway(event: MouseEvent) {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false)
    }
    document.addEventListener('keydown', onKeyDown)
    document.addEventListener('mousedown', onClickAway)
    return () => {
      document.removeEventListener('keydown', onKeyDown)
      document.removeEventListener('mousedown', onClickAway)
    }
  }, [open])

  return (
    <div className="alertcenter-root" ref={rootRef}>
      <button
        type="button"
        className="icobtn"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label="Notifications"
        onClick={() => {
          setActionError(null)
          setOpen((v) => !v)
        }}
      >
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path
            d="M6 9a6 6 0 1112 0c0 5 2 6 2 6H4s2-1 2-6z"
            stroke="currentColor"
            strokeWidth="1.6"
            strokeLinejoin="round"
          />
          <path d="M10 20a2 2 0 004 0" stroke="currentColor" strokeWidth="1.6" />
        </svg>
        {totalAlerts > 0 && (
          <span className="badge" data-testid="alert-badge">
            {totalAlerts}
          </span>
        )}
      </button>
      {open && (
        <div className="pop right open" role="menu">
          <h4>Notifications</h4>
          {actionError !== null && (
            <div className="alert-action-error" role="alert" data-testid="alert-action-error">
              {actionError}
            </div>
          )}
          {loading && alerts.length === 0 && (
            <div className="notice empty">
              <p>Loading…</p>
            </div>
          )}
          {!loading && error !== null && (
            <div className="notice empty">
              <p>Failed to load alerts.</p>
            </div>
          )}
          {!loading && error === null && alerts.length === 0 && (
            <div className="notice empty">
              <p>No notifications.</p>
            </div>
          )}
          {alerts.map((alert) => (
            <div key={alert.id} className="row" data-testid="alert-row">
              <span
                className="dot"
                aria-hidden="true"
                style={{ color: severityColor(alert.severity) }}
              />
              <div style={{ flex: 1, minWidth: 0 }}>
                <div>{alert.description}</div>
                <div className="sub">{alert.device_id}</div>
              </div>
              <div className="alert-actions">
                {!alert.acknowledged && (
                  <button
                    type="button"
                    className="alert-action-btn"
                    aria-label={`Acknowledge: ${alert.description}`}
                    onClick={() => void handleAcknowledge(alert.id)}
                  >
                    Acknowledge
                  </button>
                )}
                <button
                  type="button"
                  className="alert-action-btn"
                  aria-label={`Silence: ${alert.description}`}
                  onClick={() => void handleSilence(alert.id)}
                >
                  Silence
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
