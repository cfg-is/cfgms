// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Crossing prompt (Story #4723, Epic #4701).
 *
 * Opens over the current view when a root-scoped operator reaches a tenant that
 * needs a crossing. Two paths, in order: MSP-granted support access (guidance
 * only) and break-glass (reason category + justification form). A pending
 * break-glass (second-approver setting on) shows a waiting state that polls the
 * active-crossings feed until the tenant appears.
 *
 * Visibility rule: a root-level user does not see MSP client tenant names. The
 * tenant is named only when it is in the caller's own visible tenant list;
 * otherwise the prompt says "this tenant" — never the ID or a path.
 *
 * The MSP name and the justification render as JSX text only. The justification
 * lives in component state and is never stored or logged.
 *
 * Design: docs/design/mockups/crossing-prompt.html. Modal conventions follow
 * auth/StepUpModal.tsx (title bar, focus trap), plus Escape to cancel.
 */
import { useEffect, useMemo, useRef, useState } from 'react'
import { apiFetch } from '../api/client.ts'
import {
  approvalStatePending,
  breakGlassReasons,
  fetchActiveCrossings,
  justificationMaxLen,
  justificationMinLen,
  requestBreakGlass,
  type Crossing,
} from './useTenantCrossings.ts'
import { notifyActiveCrossingsChanged } from '../shell/useActiveCrossings.ts'
import { parseTenantList, type TenantInfo } from './useTenants.ts'
import './CrossingPrompt.css'

const defaultPollIntervalMs = 5000
const errCodeNotRootScoped = 'NOT_ROOT_SCOPED'

export interface CrossingPromptProps {
  /** The challenged tenant. Never rendered; used only to address the request and match the visible list. */
  tenantId: string
  /** The caller's visible tenants. When omitted the prompt loads the list itself. */
  visibleTenants?: TenantInfo[]
  /** Reason categories the controller advertised; defaults to all four. */
  reasonCategories?: string[]
  /** The crossing is open (active break-glass, or the pending one appeared in the feed). */
  onGranted: (crossing: Crossing) => void
  onCancel: () => void
  /** Active-feed poll interval for the waiting state; tests shorten it. */
  pollIntervalMs?: number
}

type Phase = 'form' | 'waiting'

function formatClock(totalSeconds: number): string {
  const m = Math.floor(totalSeconds / 60)
  const s = totalSeconds % 60
  return `${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`
}

/** Loads the caller's visible tenant list once; null while loading or on failure. */
function useVisibleTenants(provided: TenantInfo[] | undefined): TenantInfo[] | null {
  const [loaded, setLoaded] = useState<TenantInfo[] | null>(null)
  useEffect(() => {
    if (provided !== undefined) return
    let cancelled = false
    apiFetch('/api/v1/tenants')
      .then(async (response) => {
        if (!response.ok) return
        const body = (await response.json()) as Record<string, unknown> | null
        if (!cancelled) setLoaded(parseTenantList(body?.data))
      })
      .catch(() => {
        // Without the list the prompt falls back to "this tenant".
      })
    return () => {
      cancelled = true
    }
  }, [provided])
  return provided ?? loaded
}

export default function CrossingPrompt({
  tenantId,
  visibleTenants,
  reasonCategories,
  onGranted,
  onCancel,
  pollIntervalMs = defaultPollIntervalMs,
}: CrossingPromptProps) {
  const tenants = useVisibleTenants(visibleTenants)
  const mspName = useMemo(() => {
    const match = tenants?.find((t) => t.id === tenantId)
    return match !== undefined && match.name !== '' ? match.name : null
  }, [tenants, tenantId])

  const reasons = useMemo(() => {
    if (reasonCategories === undefined || reasonCategories.length === 0) return breakGlassReasons
    const allowed = breakGlassReasons.filter((r) => reasonCategories.includes(r.value))
    return allowed.length > 0 ? allowed : breakGlassReasons
  }, [reasonCategories])

  const [phase, setPhase] = useState<Phase>('form')
  const [reason, setReason] = useState('')
  const [justification, setJustification] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [waitSeconds, setWaitSeconds] = useState(0)
  const modalRef = useRef<HTMLDivElement>(null)
  // Set on cancel/grant so an in-flight request or poll cannot fire a late callback.
  const closedRef = useRef(false)

  const trimmedLen = justification.trim().length
  const valid = reason !== '' && trimmedLen >= justificationMinLen && trimmedLen <= justificationMaxLen
  const label = mspName ?? 'this tenant'
  const reasonLabel = reasons.find((r) => r.value === reason)?.label ?? ''

  function cancel() {
    closedRef.current = true
    onCancel()
  }
  const cancelRef = useRef(cancel)
  useEffect(() => {
    cancelRef.current = cancel
  })

  function grant(crossing: Crossing) {
    if (closedRef.current) return
    closedRef.current = true
    // Refresh the shell's elevation banner now rather than at the next poll.
    notifyActiveCrossingsChanged()
    onGranted(crossing)
  }

  // Focus trap, initial focus and Escape. Previous focus is restored on unmount.
  useEffect(() => {
    const prevFocus = document.activeElement as HTMLElement | null
    const focusable = 'button:not([disabled]), select:not([disabled]), textarea:not([disabled])'

    function onKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        e.preventDefault()
        cancelRef.current()
        return
      }
      if (e.key !== 'Tab' || modalRef.current === null) return
      const items = [...modalRef.current.querySelectorAll<HTMLElement>(focusable)]
      if (items.length === 0) {
        e.preventDefault()
        return
      }
      const first = items[0]!
      const last = items[items.length - 1]!
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault()
        last.focus()
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault()
        first.focus()
      }
    }

    document.addEventListener('keydown', onKeyDown)
    const timer = setTimeout(() => {
      modalRef.current?.querySelector<HTMLElement>(focusable)?.focus()
    }, 0)
    return () => {
      clearTimeout(timer)
      document.removeEventListener('keydown', onKeyDown)
      prevFocus?.focus()
    }
  }, [])

  // Waiting state: clock plus poll of the active feed until the tenant appears.
  useEffect(() => {
    if (phase !== 'waiting') return
    let stopped = false
    let inFlight = false
    const clock = setInterval(() => setWaitSeconds((n) => n + 1), 1000)
    const poll = setInterval(() => {
      if (inFlight) return
      inFlight = true
      fetchActiveCrossings().then(
        (list) => {
          inFlight = false
          const hit = list.find((c) => c.tenantId === tenantId)
          if (!stopped && hit !== undefined) grant(hit)
        },
        () => {
          // A failed poll is retried on the next tick.
          inFlight = false
        },
      )
    }, pollIntervalMs)
    return () => {
      stopped = true
      clearInterval(clock)
      clearInterval(poll)
    }
    // grant only touches refs and the onGranted prop of this mount.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [phase, tenantId, pollIntervalMs])

  async function handleSubmit() {
    if (!valid || submitting) return
    setSubmitting(true)
    setError(null)
    try {
      const crossing = await requestBreakGlass(tenantId, {
        reasonCategory: reason,
        justification: justification.trim(),
      })
      if (closedRef.current) return
      if (crossing.approvalState === approvalStatePending) {
        setWaitSeconds(0)
        setPhase('waiting')
        setSubmitting(false)
        return
      }
      grant(crossing)
    } catch (cause: unknown) {
      if (closedRef.current) return
      const status = (cause as { status?: unknown })?.status
      const code = (cause as { code?: unknown })?.code
      if (status === 403 && code === errCodeNotRootScoped) {
        setError('Break-glass refused. Only a root-scoped session can use break-glass. Sign in with a root account and try again.')
      } else if (typeof status === 'number' && status >= 500) {
        setError('Break-glass request failed. Try again in a moment.')
      } else {
        setError(cause instanceof Error && cause.message ? cause.message : 'Break-glass request failed.')
      }
      setSubmitting(false)
    }
  }

  const titleText = phase === 'waiting' ? 'break-glass pending approval' : 'tenant access required'

  return (
    <div className="crossing-overlay" data-testid="crossing-prompt-overlay">
      <div
        className="crossing-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="crossing-title"
        ref={modalRef}
        data-testid="crossing-prompt"
      >
        <div className="crossing-titlebar">
          <span>{titleText}</span>
        </div>

        {phase === 'form' ? (
          <>
            <div className="crossing-body">
              <div className="crossing-head">
                <span className="crossing-ico" aria-hidden="true">
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <rect x="3" y="11" width="18" height="11" rx="2" />
                    <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                  </svg>
                </span>
                <div>
                  <h2 id="crossing-title">The MSP controls access to this tenant</h2>
                  <p>
                    You are signed in at root. To see inside{' '}
                    <span className="crossing-tid" data-testid="crossing-tenant-label">{label}</span>{' '}
                    and its clients, you need access that the MSP gives, or an audited emergency elevation.
                  </p>
                </div>
              </div>

              <div className="crossing-path crossing-p1" data-testid="crossing-path-grant">
                <div className="crossing-path-top">
                  <span className="crossing-num">1</span>
                  <h3>Ask the MSP for support access</h3>
                  <span className="crossing-pill">Recommended</span>
                </div>
                <p>
                  {mspName !== null ? `An ${mspName} administrator` : 'An administrator of the MSP'} can turn on{' '}
                  <b>support access</b> from their own console, for 1 to 24 hours. It opens the MSP to the whole
                  root support team, not to a named person. Access then opens by itself. You do not need to do
                  anything here.
                </p>
              </div>

              <div className="crossing-or">or, only in an emergency</div>

              <div className="crossing-path crossing-p2" data-testid="crossing-path-break-glass">
                <div className="crossing-path-top">
                  <span className="crossing-num">2</span>
                  <h3>Break-glass</h3>
                </div>
                <p className="crossing-lead">
                  Open {mspName ?? 'the MSP'} now, without the MSP. Use this only when the MSP cannot act, for
                  example when they are locked out.
                </p>
                <form
                  className="crossing-form"
                  noValidate
                  onSubmit={(e) => {
                    e.preventDefault()
                    void handleSubmit()
                  }}
                >
                  <div className="crossing-field">
                    <label htmlFor="crossing-reason">
                      Reason <span className="crossing-req">*</span>
                    </label>
                    <select
                      id="crossing-reason"
                      value={reason}
                      onChange={(e) => setReason(e.target.value)}
                      data-testid="crossing-reason"
                    >
                      <option value="">Choose a reason…</option>
                      {reasons.map((r) => (
                        <option key={r.value} value={r.value}>
                          {r.label}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div className="crossing-field">
                    <label htmlFor="crossing-justification">
                      Justification <span className="crossing-req">*</span>
                    </label>
                    <textarea
                      id="crossing-justification"
                      maxLength={justificationMaxLen}
                      value={justification}
                      onChange={(e) => setJustification(e.target.value)}
                      placeholder="What happened, and why the MSP cannot grant access. Include a ticket number if you have one."
                      data-testid="crossing-justification"
                    />
                    <div className="crossing-count">
                      <span
                        className={trimmedLen === 0 ? '' : trimmedLen < justificationMinLen ? 'bad' : 'ok'}
                        data-testid="crossing-hint"
                      >
                        {trimmedLen === 0
                          ? `At least ${justificationMinLen} characters.`
                          : trimmedLen < justificationMinLen
                            ? `${justificationMinLen - trimmedLen} more characters needed.`
                            : 'Looks good.'}
                      </span>
                      <span data-testid="crossing-count">
                        {justification.length} / {justificationMaxLen}
                      </span>
                    </div>
                  </div>
                  <div className="crossing-msg crossing-msg-warn">
                    <span>
                      <b>The MSP is told right away.</b> They see your name, reason and justification in their
                      console and audit log, and by email when email is set up.
                    </span>
                  </div>
                  {error !== null && (
                    <div className="crossing-msg crossing-msg-crit" role="alert" data-testid="crossing-error">
                      <span>{error}</span>
                    </div>
                  )}
                </form>
              </div>
            </div>
            <div className="crossing-foot">
              <span className="crossing-kbd">
                <kbd>Esc</kbd> to cancel
              </span>
              <button type="button" className="crossing-btn-sec" onClick={cancel} data-testid="crossing-cancel-btn">
                Cancel
              </button>
              <button
                type="button"
                className="crossing-btn-danger"
                disabled={!valid || submitting}
                onClick={() => void handleSubmit()}
                data-testid="crossing-submit-btn"
              >
                {submitting ? 'Requesting…' : 'Use break-glass'}
              </button>
            </div>
          </>
        ) : (
          <>
            <div className="crossing-body">
              <div className="crossing-wait" data-testid="crossing-waiting">
                <span className="crossing-wait-ico">
                  <span className="crossing-spin" aria-hidden="true" />
                </span>
                <h3 id="crossing-title">Waiting for a second approver</h3>
                <p>
                  Your break-glass request is in. This controller needs a second root operator to approve it.{' '}
                  {mspName ?? 'The MSP'} opens here as soon as they do.
                </p>
                <dl className="crossing-summary">
                  <dt>MSP</dt>
                  <dd>{label}</dd>
                  <dt>Reason</dt>
                  <dd>{reasonLabel}</dd>
                  <dt>Justification</dt>
                  <dd data-testid="crossing-wait-justification">{justification.trim()}</dd>
                </dl>
                <span className="crossing-poll">
                  <span className="crossing-dot" aria-hidden="true" />
                  Checking every {Math.round(pollIntervalMs / 1000)} s · waiting{' '}
                  <span className="crossing-clock">{formatClock(waitSeconds)}</span>
                </span>
              </div>
            </div>
            <div className="crossing-foot">
              <span className="crossing-kbd">The request stays open if you stop waiting.</span>
              <button type="button" className="crossing-btn-sec" onClick={cancel} data-testid="crossing-stop-btn">
                Stop waiting
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  )
}
