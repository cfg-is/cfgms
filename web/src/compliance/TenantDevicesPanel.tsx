// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Tenant devices panel (Story #4586): per-device compliance list for one tenant
 * from GET /api/v1/compliance/tenants/{id}/devices. Opened from a By-tenant row
 * on the Compliance summary. Loading / Error / Empty / Ready states; each device
 * links to its steward page, whose Compliance tab carries policy deadlines and
 * outstanding patches. State pills use the --state-* tokens via .cs-pill.
 */
import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router'
import { apiFetch } from '../api/client.ts'

const PAGE_SIZE = 50

export interface TenantDevice {
  steward_id: string
  hostname: string
  status: string
}

interface Page {
  devices: TenantDevice[]
  total: number
}

const STATUS_LABEL: Record<string, { label: string; cls: string }> = {
  compliant: { label: 'No drift', cls: 'ok' },
  warning: { label: 'Drift', cls: 'warn' },
  critical: { label: 'Critical', cls: 'crit' },
}

function parsePage(body: unknown): Page {
  if (typeof body !== 'object' || body === null) {
    throw new Error('unexpected tenant devices response shape')
  }
  const r = body as Record<string, unknown>
  const devices: TenantDevice[] = []
  if (Array.isArray(r.devices)) {
    for (const d of r.devices) {
      if (typeof d !== 'object' || d === null) continue
      const x = d as Record<string, unknown>
      if (typeof x.steward_id !== 'string') continue
      devices.push({
        steward_id: x.steward_id,
        hostname: typeof x.hostname === 'string' ? x.hostname : '',
        status: typeof x.status === 'string' ? x.status : '',
      })
    }
  }
  return { devices, total: typeof r.total === 'number' ? r.total : devices.length }
}

interface FetchState {
  key: string
  page?: Page
  error?: string
}

export default function TenantDevicesPanel({
  tenantId,
  onClose,
}: {
  tenantId: string
  onClose: () => void
}) {
  const [offset, setOffset] = useState(0)
  const [attempt, setAttempt] = useState(0)
  const [state, setState] = useState<FetchState | null>(null)
  const retry = useCallback(() => setAttempt((n) => n + 1), [])

  const key = `${tenantId}:${offset}:${attempt}`

  useEffect(() => {
    let cancelled = false
    const url = `/api/v1/compliance/tenants/${encodeURIComponent(tenantId)}/devices?limit=${PAGE_SIZE}&offset=${offset}`
    apiFetch(url)
      .then(async (r) => {
        if (!r.ok) throw new Error(`GET ${url.split('?')[0]} — ${r.status}`)
        return parsePage((await r.json()) as unknown)
      })
      .then((page) => {
        if (!cancelled) setState({ key, page })
      })
      .catch((cause: unknown) => {
        if (cancelled) return
        setState({
          key,
          error: cause instanceof Error && cause.message ? cause.message : 'request failed',
        })
      })
    return () => {
      cancelled = true
    }
  }, [key, tenantId, offset])

  const current = state?.key === key ? state : null

  let body: React.ReactNode
  if (current === null) {
    body = (
      <div data-testid="tenant-devices-loading" aria-hidden="true">
        {[0, 1, 2].map((i) => (
          <span
            key={i}
            className="cs-skel"
            style={{ height: '30px', marginTop: '8px', display: 'block' }}
          />
        ))}
      </div>
    )
  } else if (current.error !== undefined) {
    body = (
      <div className="cs-notice err" role="alert">
        <div className="cs-notice-body">
          <b>Could not load the devices for this tenant.</b>
          <p className="cs-notice-sub">{current.error}</p>
          <button type="button" className="cs-btn" onClick={retry}>
            Retry
          </button>
        </div>
      </div>
    )
  } else if (!current.page || current.page.total === 0) {
    body = (
      <div className="cs-notice" data-testid="tenant-devices-empty">
        <p>No devices in this tenant.</p>
      </div>
    )
  } else {
    const { devices, total } = current.page
    body = (
      <>
        <table className="cs-tbl" data-testid="tenant-devices-table">
          <thead>
            <tr>
              <th className="cs-th">Device</th>
              <th className="cs-th">Status</th>
            </tr>
          </thead>
          <tbody>
            {devices.map((d) => {
              const s = STATUS_LABEL[d.status] ?? { label: d.status || 'Unknown', cls: 'neutral' }
              return (
                <tr key={d.steward_id} data-testid="tenant-device-row">
                  <td className="cs-td-tenant">
                    <Link to={`/stewards/${encodeURIComponent(d.steward_id)}`}>
                      {d.hostname || d.steward_id}
                    </Link>
                  </td>
                  <td>
                    <span className={`cs-pill ${s.cls}`}>{s.label}</span>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
        <div className="cs-pager">
          <span className="cs-panel-sub">
            {offset + 1}–{offset + devices.length} of {total.toLocaleString()}
          </span>
          <button
            type="button"
            className="cs-btn"
            disabled={offset === 0}
            onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
          >
            Previous
          </button>
          <button
            type="button"
            className="cs-btn"
            disabled={offset + devices.length >= total}
            onClick={() => setOffset(offset + PAGE_SIZE)}
          >
            Next
          </button>
        </div>
      </>
    )
  }

  return (
    <div className="cs-panel" data-testid="tenant-devices-panel" role="region" aria-label={`Devices in ${tenantId}`}>
      <div className="cs-table-head">
        <div>
          <h2>{tenantId}</h2>
          <p className="cs-panel-sub">Devices and drift status</p>
        </div>
        <button type="button" className="cs-btn" onClick={onClose}>
          Close
        </button>
      </div>
      {body}
    </div>
  )
}
