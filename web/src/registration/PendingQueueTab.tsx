// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Pending registration queue (Story #2934, #2969).
 * Fetches GET /api/v1/registration/pending — bare-array response (no
 * {data:...} envelope, json.NewEncoder raw array). Shape-validated by
 * parsePendingRegistrations before any value reaches the DOM.
 *
 * Deny calls POST /api/v1/registration/{id}/deny and removes the row on
 * success; surfaces a row-level error without crashing on failure.
 *
 * Approve calls POST /api/v1/registration/{id}/approve and removes the row
 * on success; surfaces a row-level error without crashing on failure.
 *
 * Approve All calls POST /api/v1/registration/approve-all and refreshes the
 * list on success.
 *
 * Approve by CIDR (Story #2969): operator must preview (GET
 * /api/v1/registration/approve-by-cidr/preview?cidr=...) before the confirm
 * button becomes active. The mutation POST requires user-presence step-up,
 * handled transparently by apiFetch + StepUpModal in AuthContext.
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

interface CIDRPreview {
  count: number
  pending_ids: string[]
  source_ips: string[]
}

interface CIDRModalState {
  cidr: string
  preview: CIDRPreview | null
  previewLoading: boolean
  previewError: string | null
  approveLoading: boolean
  approveError: string | null
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
  const [approveErrors, setApproveErrors] = useState<Map<string, string>>(new Map())
  const [approveAllLoading, setApproveAllLoading] = useState(false)
  const [approveAllError, setApproveAllError] = useState<string | null>(null)
  const [cidrModal, setCidrModal] = useState<CIDRModalState | null>(null)

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

  async function handleApprove(pendingId: string) {
    setApproveErrors((prev) => {
      const next = new Map(prev)
      next.delete(pendingId)
      return next
    })
    try {
      const response = await apiFetch(
        `/api/v1/registration/${encodeURIComponent(pendingId)}/approve`,
        { method: 'POST' },
      )
      if (!response.ok) {
        setApproveErrors((prev) =>
          new Map(prev).set(pendingId, `Approve failed — ${response.status}`),
        )
        return
      }
      setOutcome((prev) => {
        if (!prev?.entries) return prev
        return { ...prev, entries: prev.entries.filter((e) => e.pending_id !== pendingId) }
      })
    } catch (cause: unknown) {
      setApproveErrors((prev) =>
        new Map(prev).set(
          pendingId,
          cause instanceof Error && cause.message ? cause.message : 'Approve request failed',
        ),
      )
    }
  }

  async function handleApproveAll() {
    setApproveAllError(null)
    setApproveAllLoading(true)
    try {
      const response = await apiFetch('/api/v1/registration/approve-all', { method: 'POST' })
      if (!response.ok) {
        setApproveAllError(`Approve all failed — ${response.status}`)
        return
      }
      retry()
    } catch (cause: unknown) {
      setApproveAllError(
        cause instanceof Error && cause.message ? cause.message : 'Approve all request failed',
      )
    } finally {
      setApproveAllLoading(false)
    }
  }

  function openCIDRModal() {
    setCidrModal({
      cidr: '',
      preview: null,
      previewLoading: false,
      previewError: null,
      approveLoading: false,
      approveError: null,
    })
  }

  async function handleCIDRPreview() {
    if (!cidrModal) return
    const cidr = cidrModal.cidr
    setCidrModal((prev) =>
      prev ? { ...prev, previewLoading: true, previewError: null, preview: null } : prev,
    )
    try {
      const response = await apiFetch(
        `/api/v1/registration/approve-by-cidr/preview?cidr=${encodeURIComponent(cidr)}`,
      )
      if (!response.ok) {
        setCidrModal((prev) =>
          prev
            ? { ...prev, previewLoading: false, previewError: `Preview failed — ${response.status}` }
            : prev,
        )
        return
      }
      const body = (await response.json()) as CIDRPreview
      setCidrModal((prev) => (prev ? { ...prev, previewLoading: false, preview: body } : prev))
    } catch (cause: unknown) {
      setCidrModal((prev) =>
        prev
          ? {
              ...prev,
              previewLoading: false,
              previewError:
                cause instanceof Error && cause.message
                  ? cause.message
                  : 'Preview request failed',
            }
          : prev,
      )
    }
  }

  async function handleCIDRApprove() {
    if (!cidrModal?.preview) return
    const cidr = cidrModal.cidr
    setCidrModal((prev) => (prev ? { ...prev, approveLoading: true, approveError: null } : prev))
    try {
      const response = await apiFetch('/api/v1/registration/approve-by-cidr', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ cidr }),
      })
      if (!response.ok) {
        setCidrModal((prev) =>
          prev
            ? { ...prev, approveLoading: false, approveError: `Approve failed — ${response.status}` }
            : prev,
        )
        return
      }
      setCidrModal(null)
      retry()
    } catch (cause: unknown) {
      setCidrModal((prev) =>
        prev
          ? {
              ...prev,
              approveLoading: false,
              approveError:
                cause instanceof Error && cause.message
                  ? cause.message
                  : 'Approve request failed',
            }
          : prev,
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
            <button
              type="button"
              className="wf-btn-sm"
              data-testid="approve-all-btn"
              disabled={approveAllLoading}
              onClick={() => void handleApproveAll()}
            >
              Approve All
            </button>
            <button
              type="button"
              className="wf-btn-sm"
              data-testid="approve-by-cidr-btn"
              onClick={openCIDRModal}
            >
              Approve by CIDR
            </button>
            {approveAllError !== null && (
              <span className="wf-form-error" role="alert" data-testid="approve-all-error">
                {approveAllError}
              </span>
            )}
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
                        className="wf-btn-sm"
                        data-testid={`approve-btn-${entry.pending_id}`}
                        onClick={() => void handleApprove(entry.pending_id)}
                      >
                        Approve
                      </button>
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
                  {approveErrors.has(entry.pending_id) && (
                    <tr>
                      <td colSpan={5}>
                        <span
                          className="wf-form-error"
                          data-testid={`approve-error-${entry.pending_id}`}
                          role="alert"
                        >
                          {approveErrors.get(entry.pending_id)}
                        </span>
                      </td>
                    </tr>
                  )}
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

      {cidrModal !== null && (
        <div
          className="modal-overlay"
          role="dialog"
          aria-modal="true"
          aria-label="Approve by CIDR"
          data-testid="cidr-modal"
        >
          <div className="modal-box">
            <h3>Approve registrations by CIDR</h3>
            <p className="modal-desc">
              Enter a CIDR range to preview which pending registrations match, then confirm to
              approve them. A user-presence verification will be required before approval.
            </p>
            <label className="field-label">
              CIDR range
              <input
                type="text"
                className="wf-input"
                data-testid="cidr-input"
                placeholder="e.g. 192.168.1.0/24"
                value={cidrModal.cidr}
                onChange={(e) =>
                  setCidrModal((prev) =>
                    prev ? { ...prev, cidr: e.target.value, preview: null } : prev,
                  )
                }
              />
            </label>
            <button
              type="button"
              className="wf-btn-sm"
              data-testid="cidr-preview-btn"
              disabled={!cidrModal.cidr || cidrModal.previewLoading}
              onClick={() => void handleCIDRPreview()}
            >
              {cidrModal.previewLoading ? 'Loading…' : 'Preview'}
            </button>
            {cidrModal.previewError !== null && (
              <span
                className="wf-form-error"
                role="alert"
                data-testid="cidr-preview-error"
              >
                {cidrModal.previewError}
              </span>
            )}
            {cidrModal.preview !== null && (
              <div className="cidr-preview" data-testid="cidr-preview-result">
                <p>
                  {cidrModal.preview.count} pending registration
                  {cidrModal.preview.count !== 1 ? 's' : ''} will be approved.
                </p>
              </div>
            )}
            <div className="modal-actions">
              <button
                type="button"
                className="wf-btn-sm-danger"
                data-testid="cidr-cancel-btn"
                onClick={() => setCidrModal(null)}
              >
                Cancel
              </button>
              <button
                type="button"
                className="wf-btn-sm"
                data-testid="cidr-confirm-btn"
                disabled={cidrModal.preview === null || cidrModal.approveLoading}
                onClick={() => void handleCIDRApprove()}
              >
                {cidrModal.approveLoading ? 'Approving…' : 'Confirm & Approve'}
              </button>
            </div>
            {cidrModal.approveError !== null && (
              <span
                className="wf-form-error"
                role="alert"
                data-testid="cidr-approve-error"
              >
                {cidrModal.approveError}
              </span>
            )}
          </div>
        </div>
      )}
    </section>
  )
}
