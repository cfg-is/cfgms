// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Credential-request approval tab (Issue #3723, Epic #3711 — browser-authenticated
 * CLI enrolment). Mirrors PendingQueueTab.tsx's loading/empty/error/list shape,
 * reading GET /api/v1/credential-requests (Issue #3717) and driving approve/deny
 * (Issue #3718 / #3717) through the client calls in ../api/client.ts.
 *
 * Fingerprint confirmation: approval always sends back the fingerprint value this
 * panel rendered for the row — never operator-retyped — so the server's own
 * fingerprint-match / still-pending checks (handlers_credential_requests_approve.go)
 * are the real guard, not client trust. A 409 (either check) is surfaced as a
 * "compare the fingerprint again" prompt with a fresh row fetch, never retried
 * silently with the stale fingerprint.
 *
 * Root-scope marker: never offered. The epic's amendment to this issue requires
 * it — principalHasCertifiedRootScope can never pass for a cookie-authenticated
 * caller, so offering the control here would let an operator press "approve" on a
 * grant the server always refuses, unable to tell "not allowed" from "not working".
 *
 * Admin / payload-signing marker availability is gated on principal.rootScope, the
 * only entitlement signal this cookie session exposes to the browser. That exactly
 * matches the server's own gate for a web-account principal on the admin marker
 * (implicitAdminWeb := acct.RootScope, middleware.go — principalMayAdministerController
 * checks ImplicitAdmin, handlers_credential_requests_approve.go). For the
 * payload-signing marker the true gate also checks a per-account permission
 * (signing-credential:request) this session has no way to read without a new
 * endpoint — out of scope here — so rootScope is used as a deliberately
 * conservative stand-in: a tenant-scoped operator who genuinely holds that
 * permission sees the control as unavailable rather than risking "not entitled"
 * being learned from a failed approval instead of from this panel.
 *
 * Security A9.1: every requester-supplied field (hostname, label, platform,
 * purpose, source_ip) renders as a JSX text node only — no dangerouslySetInnerHTML
 * anywhere in this file, and no requester-supplied value is placed into a link
 * target or a download name (this panel has neither).
 */
import { Fragment, useCallback, useEffect, useState } from 'react'
import {
  approveCredentialRequest,
  denyCredentialRequest,
  listCredentialRequests,
  type CredentialRequestEntry,
} from '../api/client.ts'
import { useAuth } from '../auth/AuthContext.tsx'
import ErrorCard from '../shell/ErrorCard.tsx'

// ── Types ─────────────────────────────────────────────────────────────────────

interface FetchOutcome {
  key: string
  entries?: CredentialRequestEntry[]
  error?: string
}

type RowStatus = 'pending' | 'approved' | 'denied' | 'expired'

interface RowOutcome {
  status: 'approved' | 'denied'
  grantedMarkers: string[]
}

// ── Status helpers ────────────────────────────────────────────────────────────

function isExpired(entry: CredentialRequestEntry, now: Date): boolean {
  if (!entry.expiresAt) return false
  const t = new Date(entry.expiresAt)
  return !Number.isNaN(t.getTime()) && t < now
}

function rowStatus(entry: CredentialRequestEntry, outcome: RowOutcome | undefined, now: Date): RowStatus {
  if (outcome !== undefined) return outcome.status
  if (isExpired(entry, now)) return 'expired'
  return 'pending'
}

function statusClass(s: RowStatus): string {
  if (s === 'approved') return 'pill ok'
  if (s === 'denied') return 'pill crit'
  if (s === 'expired') return 'pill neutral'
  return 'pill warn'
}

function statusLabel(s: RowStatus): string {
  if (s === 'approved') return 'Approved'
  if (s === 'denied') return 'Denied'
  if (s === 'expired') return 'Expired'
  return 'Pending'
}

// ── Sub-components ────────────────────────────────────────────────────────────

function LoadingRows() {
  return (
    <div data-testid="credential-requests-loading" aria-label="Loading credential requests">
      {Array.from({ length: 3 }, (_, i) => (
        <div className="skrow" key={i}>
          <span className="skel" style={{ width: '25%' }} />
          <span className="skel" style={{ width: '20%' }} />
          <span className="skel" style={{ width: '20%' }} />
          <span className="skel" style={{ width: '15%' }} />
        </div>
      ))}
    </div>
  )
}

function EmptyState() {
  return (
    <div className="notice empty" data-testid="credential-requests-empty">
      <div className="ic">◍</div>
      <h3>No pending credential requests</h3>
      <p>Enrolling machines that lodge a signing request will appear here.</p>
    </div>
  )
}

interface ApproveModalProps {
  entry: CredentialRequestEntry
  rootScope: boolean
  onCancel: () => void
  onApproved: (grantedMarkers: string[]) => void
  onConflict: () => void
}

function ApproveModal({ entry, rootScope, onCancel, onApproved, onConflict }: ApproveModalProps) {
  const [username, setUsername] = useState('')
  const [grantAdmin, setGrantAdmin] = useState(false)
  const [grantSigning, setGrantSigning] = useState(false)
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (username.trim() === '') {
      setError('Account username is required')
      return
    }
    setError(null)
    setPending(true)
    try {
      const result = await approveCredentialRequest({
        id: entry.id,
        // The fingerprint the administrator saw on screen — never operator-retyped.
        fingerprint: entry.publicKeyFingerprintShort,
        newAccountUsername: username.trim(),
        grantAdminMarker: grantAdmin,
        grantPayloadSigningMarker: grantSigning,
      })
      if (result.conflict) {
        onConflict()
        return
      }
      if (!result.ok) {
        setError(`Approve failed — ${result.status}${result.errorCode ? ` (${result.errorCode})` : ''}`)
        return
      }
      onApproved(result.grantedMarkers ?? [])
    } catch (cause: unknown) {
      setError(cause instanceof Error && cause.message ? cause.message : 'Approve request failed')
    } finally {
      setPending(false)
    }
  }

  return (
    <div
      className="modal-overlay"
      role="dialog"
      aria-modal="true"
      aria-labelledby="approve-modal-title"
      data-testid="approve-modal"
    >
      <div className="modal-panel">
        <h2 id="approve-modal-title">Approve credential request</h2>

        <p className="notice-warn" data-testid="fingerprint-instruction">
          This fingerprint must match what the enrolling machine printed — confirm it before approving.
        </p>
        <div className="secret-row" data-testid="approve-fingerprint-row">
          <code className="mono2 secret-value" data-testid="approve-fingerprint">
            {entry.publicKeyFingerprintShort}
          </code>
        </div>

        <form onSubmit={(e) => void handleSubmit(e)} className="wf-form">
          <div className="wf-field">
            <label htmlFor="approve-username">Account username</label>
            <input
              id="approve-username"
              type="text"
              className="wf-input"
              data-testid="approve-username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="e.g. the enrolling machine's hostname"
            />
          </div>

          <fieldset className="wf-field">
            <legend>Certificate markers — defaults to none granted</legend>

            <label className="field-label">
              <input
                type="checkbox"
                data-testid="marker-admin"
                checked={grantAdmin}
                disabled={!rootScope}
                onChange={(e) => setGrantAdmin(e.target.checked)}
              />
              Administrator
            </label>
            {!rootScope && (
              <p className="mut" data-testid="marker-admin-reason">
                Unavailable — requires platform administrator (root-scope) authority.
              </p>
            )}

            <label className="field-label">
              <input
                type="checkbox"
                data-testid="marker-payload-signing"
                checked={grantSigning}
                disabled={!rootScope}
                onChange={(e) => setGrantSigning(e.target.checked)}
              />
              Payload signing
            </label>
            {!rootScope && (
              <p className="mut" data-testid="marker-payload-signing-reason">
                Unavailable — requires platform administrator (root-scope) authority.
              </p>
            )}

            <div data-testid="marker-root-scope-unavailable">
              <span className="field-label">Root scope — not offered here</span>
              <p className="mut">
                A root-scope grant requires a certificate-authenticated approval and cannot be
                granted from this screen.
              </p>
            </div>
          </fieldset>

          {error !== null && (
            <span className="wf-form-error" role="alert" data-testid="approve-error">
              {error}
            </span>
          )}

          <div className="modal-actions">
            <button
              type="button"
              className="wf-btn-sm-danger"
              data-testid="approve-cancel-btn"
              onClick={onCancel}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="wf-btn-primary"
              data-testid="approve-submit-btn"
              disabled={pending}
            >
              {pending ? 'Approving…' : 'Approve'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ── Main component ────────────────────────────────────────────────────────────

export default function CredentialRequestsTab() {
  const { principal } = useAuth()
  const rootScope = principal?.rootScope ?? false

  const [attempt, setAttempt] = useState(0)
  const [outcome, setOutcome] = useState<FetchOutcome | null>(null)
  const [denyErrors, setDenyErrors] = useState<Map<string, string>>(new Map())
  const [denyPending, setDenyPending] = useState<Set<string>>(new Set())
  const [rowOutcomes, setRowOutcomes] = useState<Map<string, RowOutcome>>(new Map())
  const [reviewingId, setReviewingId] = useState<string | null>(null)
  const [conflictNotices, setConflictNotices] = useState<Map<string, string>>(new Map())

  const key = `credential-requests:${attempt}`
  const retry = useCallback(() => setAttempt((n) => n + 1), [])

  useEffect(() => {
    let cancelled = false
    listCredentialRequests()
      .then((result) => {
        if (cancelled) return
        if (!result.ok) {
          setOutcome({ key, error: `GET /api/v1/credential-requests — ${result.status}` })
          return
        }
        setOutcome({ key, entries: result.requests })
      })
      .catch((cause: unknown) => {
        if (cancelled) return
        setOutcome({
          key,
          error:
            cause instanceof Error && cause.message
              ? cause.message
              : 'GET /api/v1/credential-requests — request failed',
        })
      })
    return () => {
      cancelled = true
    }
  }, [key, attempt])

  async function handleDeny(id: string) {
    setDenyErrors((prev) => {
      const next = new Map(prev)
      next.delete(id)
      return next
    })
    setDenyPending((prev) => new Set([...prev, id]))
    try {
      const result = await denyCredentialRequest(id)
      if (!result.ok) {
        setDenyErrors((prev) => new Map(prev).set(id, `Deny failed — ${result.status}`))
        return
      }
      setRowOutcomes((prev) => new Map(prev).set(id, { status: 'denied', grantedMarkers: [] }))
    } finally {
      setDenyPending((prev) => {
        const next = new Set(prev)
        next.delete(id)
        return next
      })
    }
  }

  function handleApproved(id: string, grantedMarkers: string[]) {
    setRowOutcomes((prev) => new Map(prev).set(id, { status: 'approved', grantedMarkers }))
    setReviewingId(null)
  }

  function handleConflict(id: string) {
    setConflictNotices((prev) =>
      new Map(prev).set(id, 'This request changed since it was shown — compare the fingerprint again.'),
    )
    setReviewingId(null)
    retry()
  }

  const current = outcome?.key === key ? outcome : null
  const loading = current === null
  const error = current?.error ?? null
  const entries = current?.entries ?? null
  const now = new Date()
  const reviewEntry = reviewingId !== null ? (entries?.find((e) => e.id === reviewingId) ?? null) : null

  return (
    <section className="panel">
      {loading ? (
        <LoadingRows />
      ) : error !== null ? (
        <ErrorCard heading="Couldn't load credential requests" detail={error} onRetry={retry} />
      ) : entries === null || entries.length === 0 ? (
        <EmptyState />
      ) : (
        <>
          <div className="ptool">
            <span className="cnt" data-testid="credential-requests-count">
              {entries.length} pending
            </span>
            <button type="button" className="wf-btn-sm" data-testid="refresh-btn" onClick={retry}>
              Refresh
            </button>
          </div>
          <p className="mut" data-testid="fingerprint-match-notice">
            Compare each fingerprint against what the enrolling machine printed before approving —
            it must match what the enrolling machine printed.
          </p>
          <table className="tbl" data-testid="credential-requests-table">
            <thead>
              <tr>
                <th>Fingerprint</th>
                <th>Source</th>
                <th>Purpose</th>
                <th>Expires</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((entry) => {
                const outcomeForRow = rowOutcomes.get(entry.id)
                const status = rowStatus(entry, outcomeForRow, now)
                const actionable = status === 'pending'
                return (
                  <Fragment key={entry.id}>
                    <tr data-testid="credential-request-row">
                      <td>
                        <code className="mono2" data-testid={`fingerprint-${entry.id}`}>
                          {entry.publicKeyFingerprintShort}
                        </code>
                      </td>
                      <td data-testid={`source-${entry.id}`}>
                        <span className="mono2">{entry.sourceIp}</span>
                        {entry.hostname !== '' && <span className="mut"> · {entry.hostname}</span>}
                      </td>
                      <td data-testid={`purpose-${entry.id}`}>{entry.purpose || '—'}</td>
                      <td className="mono2" data-testid={`expires-${entry.id}`}>
                        {entry.expiresAt || '—'}
                      </td>
                      <td data-testid={`status-${entry.id}`}>
                        <span className={statusClass(status)}>
                          <span className="dot" />
                          {statusLabel(status)}
                        </span>
                        {outcomeForRow?.status === 'approved' && outcomeForRow.grantedMarkers.length > 0 && (
                          <div className="mut" data-testid={`granted-markers-${entry.id}`}>
                            Granted: {outcomeForRow.grantedMarkers.join(', ')}
                          </div>
                        )}
                      </td>
                      <td data-testid={`actions-${entry.id}`}>
                        {actionable && (
                          <>
                            <button
                              type="button"
                              className="wf-btn-sm"
                              data-testid={`approve-btn-${entry.id}`}
                              onClick={() => setReviewingId(entry.id)}
                            >
                              Review &amp; Approve
                            </button>
                            <button
                              type="button"
                              className="wf-btn-sm-danger"
                              data-testid={`deny-btn-${entry.id}`}
                              disabled={denyPending.has(entry.id)}
                              onClick={() => void handleDeny(entry.id)}
                            >
                              {denyPending.has(entry.id) ? '…' : 'Deny'}
                            </button>
                          </>
                        )}
                      </td>
                    </tr>
                    {denyErrors.has(entry.id) && (
                      <tr>
                        <td colSpan={6}>
                          <span
                            className="wf-form-error"
                            role="alert"
                            data-testid={`deny-error-${entry.id}`}
                          >
                            {denyErrors.get(entry.id)}
                          </span>
                        </td>
                      </tr>
                    )}
                    {conflictNotices.has(entry.id) && (
                      <tr>
                        <td colSpan={6}>
                          <span
                            className="wf-form-error"
                            role="alert"
                            data-testid={`conflict-${entry.id}`}
                          >
                            {conflictNotices.get(entry.id)}
                          </span>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                )
              })}
            </tbody>
          </table>
        </>
      )}

      {reviewEntry !== null && (
        <ApproveModal
          entry={reviewEntry}
          rootScope={rootScope}
          onCancel={() => setReviewingId(null)}
          onApproved={(markers) => handleApproved(reviewEntry.id, markers)}
          onConflict={() => handleConflict(reviewEntry.id)}
        />
      )}
    </section>
  )
}
