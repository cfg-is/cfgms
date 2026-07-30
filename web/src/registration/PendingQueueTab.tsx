// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Pending registration queue (Story #2934).
 * Fetches GET /api/v1/registration/pending — bare-array response (no
 * {data:...} envelope, json.NewEncoder raw array). Shape-validated by
 * parsePendingRegistrations before any value reaches the DOM.
 *
 * Deny calls POST /api/v1/registration/{id}/deny and removes the row on
 * success; surfaces a row-level error without crashing on failure.
 *
 * Security A9.1: all steward-supplied and operator-influenced values render
 * as JSX text nodes only, never via dangerouslySetInnerHTML.
 */
import { Fragment, useCallback, useEffect, useState } from 'react'
import { apiFetch } from '../api/client.ts'
import ErrorCard from '../shell/ErrorCard.tsx'

// ── Types ─────────────────────────────────────────────────────────────────────

interface PendingEntry {
  pending_id: string
  steward_id: string
  source_ip: string
  registered_at: string
}

interface FetchOutcome {
  key: string
  entries?: PendingEntry[]
  error?: string
}

// ── Parse helpers ─────────────────────────────────────────────────────────────

function str(v: unknown): string {
  return typeof v === 'string' ? v : ''
}

export function parsePendingEntry(value: unknown): PendingEntry | null {
  if (typeof value !== 'object' || value === null) return null
  const r = value as Record<string, unknown>
  const pending_id = str(r.pending_id)
  if (!pending_id) return null
  return {
    pending_id,
    steward_id: str(r.steward_id),
    source_ip: str(r.source_ip),
    registered_at: str(r.registered_at),
  }
}

export function parsePendingRegistrations(data: unknown): PendingEntry[] {
  if (!Array.isArray(data)) throw new Error('unexpected response shape')
  const list: PendingEntry[] = []
  for (const item of data) {
    const entry = parsePendingEntry(item)
    if (entry !== null) list.push(entry)
  }
  return list
}

// ── Sub-components ────────────────────────────────────────────────────────────

function LoadingRows() {
  return (
    <div data-testid="pending-loading" aria-label="Loading pending registrations">
      {Array.from({ length: 3 }, (_, i) => (
        <div className="skrow" key={i}>
          <span className="skel" style={{ width: '20%' }} />
          <span className="skel" style={{ width: '25%' }} />
          <span className="skel" style={{ width: '15%' }} />
          <span className="skel" style={{ width: '20%' }} />
        </div>
      ))}
    </div>
  )
}

function EmptyState() {
  return (
    <div className="notice empty" data-testid="pending-empty">
      <div className="ic">◍</div>
      <h3>No pending registrations</h3>
      <p>Stewards awaiting approval will appear here.</p>
    </div>
  )
}

// ── Main component ────────────────────────────────────────────────────────────

export default function PendingQueueTab() {
  const [attempt, setAttempt] = useState(0)
  const [outcome, setOutcome] = useState<FetchOutcome | null>(null)
  const [denyErrors, setDenyErrors] = useState<Map<string, string>>(new Map())

  const key = `pending:${attempt}`
  const retry = useCallback(() => setAttempt((n) => n + 1), [])

  useEffect(() => {
    let cancelled = false
    apiFetch('/api/v1/registration/pending')
      .then(async (response) => {
        if (!response.ok) {
          throw new Error(`GET /api/v1/registration/pending — ${response.status}`)
        }
        const body: unknown = await response.json()
        const entries = parsePendingRegistrations(body)
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
              : 'GET /api/v1/registration/pending — request failed',
        })
      })
    return () => {
      cancelled = true
    }
  }, [key, attempt])

  async function handleDeny(pendingId: string) {
    setDenyErrors((prev) => {
      const next = new Map(prev)
      next.delete(pendingId)
      return next
    })
    try {
      const response = await apiFetch(
        `/api/v1/registration/${encodeURIComponent(pendingId)}/deny`,
        { method: 'POST' },
      )
      if (!response.ok) {
        setDenyErrors((prev) => new Map(prev).set(pendingId, `Deny failed — ${response.status}`))
        return
      }
      setOutcome((prev) => {
        if (!prev?.entries) return prev
        return { ...prev, entries: prev.entries.filter((e) => e.pending_id !== pendingId) }
      })
    } catch (cause: unknown) {
      setDenyErrors((prev) =>
        new Map(prev).set(
          pendingId,
          cause instanceof Error && cause.message ? cause.message : 'Deny request failed',
        ),
      )
    }
  }

  const current = outcome?.key === key ? outcome : null
  const loading = current === null
  const error = current?.error ?? null
  const entries = current?.entries ?? null

  return (
    <section className="panel">
      {loading ? (
        <LoadingRows />
      ) : error !== null ? (
        <ErrorCard
          heading="Couldn't load pending registrations"
          detail={error}
          onRetry={retry}
        />
      ) : entries === null || entries.length === 0 ? (
        <EmptyState />
      ) : (
        <>
          <div className="ptool">
            <span className="cnt" data-testid="pending-count">
              {entries.length} pending
            </span>
          </div>
          <table className="tbl" data-testid="pending-table">
            <thead>
              <tr>
                <th>Pending ID</th>
                <th>Steward ID</th>
                <th>Source IP</th>
                <th>Registered</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((entry) => (
                <Fragment key={entry.pending_id}>
                  <tr data-testid="pending-row">
                    <td>
                      <span className="mono2">{entry.pending_id}</span>
                    </td>
                    <td>
                      <span className="mono2">{entry.steward_id}</span>
                    </td>
                    <td>
                      <span className="mono2">{entry.source_ip}</span>
                    </td>
                    <td>
                      <span className="mono2">{entry.registered_at}</span>
                    </td>
                    <td>
                      <button
                        type="button"
                        className="wf-btn-sm-danger"
                        data-testid={`deny-btn-${entry.pending_id}`}
                        onClick={() => void handleDeny(entry.pending_id)}
                      >
                        Deny
                      </button>
                    </td>
                  </tr>
                  {denyErrors.has(entry.pending_id) && (
                    <tr>
                      <td colSpan={5}>
                        <span
                          className="wf-form-error"
                          data-testid={`deny-error-${entry.pending_id}`}
                          role="alert"
                        >
                          {denyErrors.get(entry.pending_id)}
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
  )
}
