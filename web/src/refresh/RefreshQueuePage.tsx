// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Refresh-request queue page (Story #2941).
 * Fetches GET /api/v1/stewards/refresh/pending — bare-array response (no
 * {data:...} envelope). Shape-validated by parsePendingRefreshList before
 * any value reaches the DOM.
 *
 * Reject calls POST /api/v1/stewards/refresh/{pending_id}/reject and removes
 * the row on success; surfaces a row-level error without crashing on failure.
 *
 * Approve is out of scope for this story (Section 2 follow-on epic) — no
 * button, no disabled state, no deferred control of any kind.
 *
 * Security A9.1: all device-supplied and operator-influenced values render
 * as JSX text nodes only, never via dangerouslySetInnerHTML.
 */
import { Fragment, useCallback, useEffect, useState } from 'react'
import { apiFetch } from '../api/client.ts'
import ErrorCard from '../shell/ErrorCard.tsx'

// ── Types ─────────────────────────────────────────────────────────────────────

interface PendingRefreshEntry {
  pending_id: string
  device_id: string
  tenant_id: string
  source_ip: string
  provenance_matched_fields: number
  provenance_total_fields: number
  status: string
  created_at: string
}

interface FetchOutcome {
  key: string
  entries?: PendingRefreshEntry[]
  error?: string
}

// ── Parse helpers ─────────────────────────────────────────────────────────────

function str(v: unknown): string {
  return typeof v === 'string' ? v : ''
}

function num(v: unknown): number {
  return typeof v === 'number' ? v : 0
}

export function parsePendingRefreshEntry(value: unknown): PendingRefreshEntry | null {
  if (typeof value !== 'object' || value === null) return null
  const r = value as Record<string, unknown>
  const pending_id = str(r.pending_id)
  if (!pending_id) return null
  return {
    pending_id,
    device_id: str(r.device_id),
    tenant_id: str(r.tenant_id),
    source_ip: str(r.source_ip),
    provenance_matched_fields: num(r.provenance_matched_fields),
    provenance_total_fields: num(r.provenance_total_fields),
    status: str(r.status),
    created_at: str(r.created_at),
  }
}

export function parsePendingRefreshList(data: unknown): PendingRefreshEntry[] {
  if (!Array.isArray(data)) throw new Error('unexpected response shape')
  const list: PendingRefreshEntry[] = []
  for (const item of data) {
    const entry = parsePendingRefreshEntry(item)
    if (entry !== null) list.push(entry)
  }
  return list
}

// ── Sub-components ────────────────────────────────────────────────────────────

function LoadingRows() {
  return (
    <div data-testid="refresh-loading" aria-label="Loading pending refresh requests">
      {Array.from({ length: 3 }, (_, i) => (
        <div className="skrow" key={i}>
          <span className="skel" style={{ width: '20%' }} />
          <span className="skel" style={{ width: '20%' }} />
          <span className="skel" style={{ width: '15%' }} />
          <span className="skel" style={{ width: '12%' }} />
          <span className="skel" style={{ width: '18%' }} />
        </div>
      ))}
    </div>
  )
}

function EmptyState() {
  return (
    <div className="notice empty" data-testid="refresh-empty">
      <div className="ic">◍</div>
      <h3>No pending refresh requests</h3>
      <p>Steward device-credential rotations awaiting review will appear here.</p>
    </div>
  )
}

function ProvenanceBadge({
  matched,
  total,
  pendingId,
}: {
  matched: number
  total: number
  pendingId: string
}) {
  const isFullMatch = total > 0 && matched === total
  return (
    <span
      className={`badge ${isFullMatch ? 'b-ok' : 'b-warn'}`}
      data-testid={`provenance-badge-${pendingId}`}
    >
      <span className="dot" aria-hidden="true" />
      {matched} / {total}
    </span>
  )
}

// ── Main component ────────────────────────────────────────────────────────────

export default function RefreshQueuePage() {
  const [attempt, setAttempt] = useState(0)
  const [outcome, setOutcome] = useState<FetchOutcome | null>(null)
  const [rejectErrors, setRejectErrors] = useState<Map<string, string>>(new Map())

  const key = `refresh:${attempt}`
  const retry = useCallback(() => setAttempt((n) => n + 1), [])

  useEffect(() => {
    let cancelled = false
    apiFetch('/api/v1/stewards/refresh/pending')
      .then(async (response) => {
        if (!response.ok) {
          throw new Error(`GET /api/v1/stewards/refresh/pending — ${response.status}`)
        }
        const body: unknown = await response.json()
        const entries = parsePendingRefreshList(body)
        if (cancelled) return
        setOutcome({ key, entries })
      })
      .catch((cause: unknown) => {
        if (cancelled) return
        setOutcome({
          key,
          error:
            cause instanceof Error && cause.message
              ? cause.message
              : 'GET /api/v1/stewards/refresh/pending — request failed',
        })
      })
    return () => {
      cancelled = true
    }
  }, [key, attempt])

  async function handleReject(pendingId: string) {
    setRejectErrors((prev) => {
      const next = new Map(prev)
      next.delete(pendingId)
      return next
    })
    try {
      const response = await apiFetch(
        `/api/v1/stewards/refresh/${encodeURIComponent(pendingId)}/reject`,
        { method: 'POST' },
      )
      if (!response.ok) {
        setRejectErrors((prev) =>
          new Map(prev).set(pendingId, `Reject failed — ${response.status}`),
        )
        return
      }
      setOutcome((prev) => {
        if (!prev?.entries) return prev
        return { ...prev, entries: prev.entries.filter((e) => e.pending_id !== pendingId) }
      })
    } catch (cause: unknown) {
      setRejectErrors((prev) =>
        new Map(prev).set(
          pendingId,
          cause instanceof Error && cause.message ? cause.message : 'Reject request failed',
        ),
      )
    }
  }

  const current = outcome?.key === key ? outcome : null
  const loading = current === null
  const error = current?.error ?? null
  const entries = current?.entries ?? null

  return (
    <div className="page">
      <div className="page-head">
        <h1>Refresh requests</h1>
        <p>Pending steward device-credential rotations awaiting review.</p>
      </div>
      <section className="panel">
        {loading ? (
          <LoadingRows />
        ) : error !== null ? (
          <ErrorCard
            heading="Couldn't load pending refresh requests"
            detail={error}
            onRetry={retry}
          />
        ) : entries === null || entries.length === 0 ? (
          <EmptyState />
        ) : (
          <>
            <div className="ptool">
              <span className="cnt" data-testid="refresh-count">
                {entries.length} pending
              </span>
            </div>
            <table className="tbl" data-testid="refresh-table">
              <thead>
                <tr>
                  <th>Pending ID</th>
                  <th>Device ID</th>
                  <th>Tenant</th>
                  <th>Source IP</th>
                  <th>Provenance</th>
                  <th>Requested</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {entries.map((entry) => (
                  <Fragment key={entry.pending_id}>
                    <tr data-testid="refresh-row">
                      <td>
                        <span className="mono2">{entry.pending_id}</span>
                      </td>
                      <td>
                        <span className="mono2">{entry.device_id}</span>
                      </td>
                      <td>
                        <span className="mono2">{entry.tenant_id}</span>
                      </td>
                      <td>
                        <span className="mono2">{entry.source_ip}</span>
                      </td>
                      <td>
                        <ProvenanceBadge
                          matched={entry.provenance_matched_fields}
                          total={entry.provenance_total_fields}
                          pendingId={entry.pending_id}
                        />
                      </td>
                      <td>
                        <span className="mono2">{entry.created_at}</span>
                      </td>
                      <td>
                        <button
                          type="button"
                          className="wf-btn-sm-danger"
                          data-testid={`reject-btn-${entry.pending_id}`}
                          onClick={() => void handleReject(entry.pending_id)}
                        >
                          Reject
                        </button>
                      </td>
                    </tr>
                    {rejectErrors.has(entry.pending_id) && (
                      <tr>
                        <td colSpan={7}>
                          <span
                            className="wf-form-error"
                            data-testid={`reject-error-${entry.pending_id}`}
                            role="alert"
                          >
                            {rejectErrors.get(entry.pending_id)}
                          </span>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </>
        )}
      </section>
    </div>
  )
}
