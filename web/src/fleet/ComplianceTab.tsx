// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * ComplianceTab (Story #3273) — per-steward compliance status and detailed
 * report. Resolves the steward ID via useParams, following the DnaDrawer
 * self-contained panel pattern so it mounts directly as Panel: ComplianceTab
 * in StewardAssetPage's TABS array (no wrapper function required).
 *
 * Two endpoints fetched in parallel on mount:
 *   GET /api/v1/stewards/{id}/compliance        → status badge
 *   GET /api/v1/stewards/{id}/compliance/report → detailed report
 *
 * days_until_breach and missing_patches reflect current backend values:
 * placeholder zero and empty list (patch module integration is a separate
 * future story). The UI renders them as-is — no fabricated data.
 *
 * State pill tokens (.pill.ok / .pill.warn / .pill.crit) come from
 * FleetOverview.css, always bundled with the app (FleetOverview is not lazy).
 */
import { useEffect, useState } from 'react'
import { useParams } from 'react-router'
import { apiFetch } from '../api/client.ts'
import ErrorCard from '../shell/ErrorCard.tsx'

// Wire types — match handlers_compliance.go JSON struct tags exactly.
export interface ComplianceStatusResponse {
  device_id: string
  device_name: string
  status: string            // "compliant" | "warning" | "critical"
  connection_status: string // "online" | "offline" | …
  days_until_breach: number
  last_checked: string      // ISO 8601
  alert_level: string       // "info" | "warning" | "critical"
}

export interface MissingPatch {
  id: string
  title: string
  severity: string
  category: string
  release_date: string // ISO 8601
  days_overdue: number
  days_until_due: number
}

export interface PatchPolicy {
  critical_deadline_days: number
  important_deadline_days: number
  moderate_deadline_days: number
  low_deadline_days: number
  warning_threshold_days: number
  critical_threshold_days: number
  maintenance_windows_configured: boolean
}

export interface ComplianceReportResponse {
  device_id: string
  device_name: string
  status: string
  connection_status: string
  days_until_breach: number
  missing_patches: MissingPatch[]
  os_version: string
  last_patch_date: string     // ISO 8601
  report_generated_at: string // ISO 8601
  policy: PatchPolicy
}

interface FetchOutcome {
  key: string
  status?: ComplianceStatusResponse
  report?: ComplianceReportResponse
  error?: string
}

function statusPillClass(status: string): string {
  switch (status) {
    case 'compliant':
      return 'ok'
    case 'warning':
      return 'warn'
    case 'critical':
    case 'non_compliant':
      return 'crit'
    default:
      return 'neutral'
  }
}

function statusLabel(status: string): string {
  switch (status) {
    case 'compliant':
      return 'Compliant'
    case 'warning':
      return 'Warning'
    case 'critical':
      return 'Critical'
    case 'non_compliant':
      return 'Non-compliant'
    default:
      return status
  }
}

/** Per-steward compliance tab — mounts as Panel: ComplianceTab (no wrapper). */
export default function ComplianceTab({ stewardId: propId }: { stewardId?: string } = {}) {
  const { id: paramId = '' } = useParams<{ id: string }>()
  const stewardId = propId !== undefined ? propId : paramId
  const [attempt, setAttempt] = useState(0)
  const [outcome, setOutcome] = useState<FetchOutcome | null>(null)
  const key = `${stewardId}:${attempt}`

  useEffect(() => {
    let cancelled = false

    const statusPath = `/api/v1/stewards/${encodeURIComponent(stewardId)}/compliance`
    const reportPath = `/api/v1/stewards/${encodeURIComponent(stewardId)}/compliance/report`

    Promise.all([
      apiFetch(statusPath).then(async (r) => {
        if (!r.ok) throw new Error(`GET ${statusPath} — ${r.status}`)
        return (await r.json()) as ComplianceStatusResponse
      }),
      apiFetch(reportPath).then(async (r) => {
        if (!r.ok) throw new Error(`GET ${reportPath} — ${r.status}`)
        return (await r.json()) as ComplianceReportResponse
      }),
    ])
      .then(([status, report]) => {
        if (!cancelled) setOutcome({ key, status, report })
      })
      .catch((cause: unknown) => {
        if (cancelled) return
        setOutcome({
          key,
          error:
            cause instanceof Error && cause.message
              ? cause.message
              : 'request failed',
        })
      })

    return () => {
      cancelled = true
    }
  }, [key, stewardId])

  const current = outcome?.key === key ? outcome : null

  if (current === null) {
    return (
      <div className="det">
        <div className="db">
          <div data-testid="compliance-loading" aria-label="Loading compliance data">
            {Array.from({ length: 6 }, (_, i) => (
              <div className="kv" key={i}>
                <span className="skel" style={{ width: '30%' }} />
                <span className="skel" style={{ width: '40%' }} />
              </div>
            ))}
          </div>
        </div>
      </div>
    )
  }

  if (current.error !== undefined) {
    return (
      <div className="det">
        <div className="db">
          <ErrorCard
            heading="Couldn't load compliance data"
            detail={current.error}
            onRetry={() => setAttempt((n) => n + 1)}
          />
        </div>
      </div>
    )
  }

  const status = current.status!
  const report = current.report!

  return (
    <div className="det">
      <div className="db">
        {/* Status section */}
        <div>
          <div className="grp">
            <div className="lbl">Compliance Status</div>
          </div>
          <div className="kv">
            <span className="k">Status</span>
            <span
              className={`pill ${statusPillClass(status.status)}`}
              data-testid="compliance-pill"
            >
              <span className="dot" />
              {statusLabel(status.status)}
            </span>
          </div>
          <div className="kv">
            <span className="k">Alert level</span>
            <span className="v mono2">{status.alert_level}</span>
          </div>
          <div className="kv">
            <span className="k">Days until breach</span>
            <span className="v mono2">
              {status.days_until_breach > 0 ? String(status.days_until_breach) : '—'}
            </span>
          </div>
          <div className="kv">
            <span className="k">Connection</span>
            <span className="v mono2">{status.connection_status}</span>
          </div>
          <div className="kv">
            <span className="k">Last checked</span>
            <span className="v mono2">{status.last_checked}</span>
          </div>
          <div className="gsep" />
        </div>

        {/* System info section */}
        <div>
          <div className="grp">
            <div className="lbl">System</div>
          </div>
          {report.os_version !== '' && (
            <div className="kv">
              <span className="k">OS version</span>
              <span className="v mono2">{report.os_version}</span>
            </div>
          )}
          <div className="kv">
            <span className="k">Last patch date</span>
            <span className="v mono2">{report.last_patch_date}</span>
          </div>
          <div className="gsep" />
        </div>

        {/* Policy section */}
        <div>
          <div className="grp">
            <div className="lbl">Policy</div>
          </div>
          <div className="kv">
            <span className="k">Critical deadline</span>
            <span className="v mono2">{report.policy.critical_deadline_days} days</span>
          </div>
          <div className="kv">
            <span className="k">Important deadline</span>
            <span className="v mono2">{report.policy.important_deadline_days} days</span>
          </div>
          <div className="kv">
            <span className="k">Moderate deadline</span>
            <span className="v mono2">{report.policy.moderate_deadline_days} days</span>
          </div>
          <div className="kv">
            <span className="k">Low deadline</span>
            <span className="v mono2">{report.policy.low_deadline_days} days</span>
          </div>
          <div className="gsep" />
        </div>

        {/* Missing patches section */}
        <div>
          <div className="grp">
            <div className="lbl">Missing patches</div>
          </div>
          {report.missing_patches.length === 0 ? (
            <div className="notice" data-testid="no-missing-patches">
              <p>No missing patches.</p>
            </div>
          ) : (
            <table className="tbl" data-testid="patches-table">
              <thead>
                <tr>
                  <th>Title</th>
                  <th>Severity</th>
                  <th>Days overdue</th>
                </tr>
              </thead>
              <tbody>
                {report.missing_patches.map((patch) => (
                  <tr key={patch.id}>
                    <td>{patch.title}</td>
                    <td>{patch.severity}</td>
                    <td className="mono2">{patch.days_overdue}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  )
}
