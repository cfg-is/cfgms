// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Support access page (Issue #4724, Epic #4701). Matches
 * docs/design/mockups/support-access.html.
 *
 * An MSP administrator, on their own tenant (principal.tenantId):
 *   - gives support access for a fixed duration (a grant names no person; it
 *     opens the tenant to all root support, each use audited by name),
 *   - sees every grant and break-glass elevation and revokes or denies one,
 *   - edits the addresses notified about break-glass.
 *
 * A root-scoped session sees an explanation and makes no grants or contacts
 * request. Issue, revoke and save are step-up gated server-side; apiFetch runs
 * the ceremony, and a cancelled one surfaces here as the original 401.
 *
 * Every server string (principal names, justification, tenant id) renders as a
 * JSX text node.
 */
import { useEffect, useState } from 'react'
import { useAuth } from '../auth/AuthContext.tsx'
import {
  approvalStatePending,
  approveBreakGlass,
  breakGlassReasons,
  createAccessGrant,
  endCrossing,
  useTenantCrossings,
  type Crossing,
} from './useTenantCrossings.ts'
import { saveAdminContacts, useAdminContacts } from './useSupportAccess.ts'
import { TenantApiError } from './useTenants.ts'
import './SupportAccessView.css'

/** Durations the server accepts for a grant (1, 4, 8 or 24 hours). */
const durations: ReadonlyArray<{ hours: number; label: string }> = [
  { hours: 1, label: '1 h' },
  { hours: 4, label: '4 h' },
  { hours: 8, label: '8 h' },
  { hours: 24, label: '24 h' },
]
const defaultHours = 4

const kindBreakGlass = 'break_glass'
const soonMs = 60 * 60_000

/** Message for a failed step-up-gated call; a cancelled ceremony returns the original 401. */
function actionError(cause: unknown, fallback: string): string {
  if (cause instanceof TenantApiError && cause.status === 401) {
    return 'The passkey check was cancelled. Try again.'
  }
  return cause instanceof Error && cause.message ? cause.message : fallback
}

function isLive(c: Crossing): boolean {
  return c.status === 'active' || c.status === 'pending'
}

function isBreakGlass(c: Crossing): boolean {
  return c.kind === kindBreakGlass
}

function reasonLabel(category: string): string {
  return breakGlassReasons.find((r) => r.value === category)?.label.split(':')[0] ?? category
}

function formatWhen(iso: string): string {
  const ms = Date.parse(iso)
  return Number.isFinite(ms) ? new Date(ms).toLocaleString() : '—'
}

function relative(c: Crossing, nowMs: number): { text: string; soon: boolean } {
  if (c.status === 'revoked') return { text: 'revoked', soon: false }
  if (c.status === 'pending') return { text: 'waiting for 2nd approver', soon: false }
  const exp = Date.parse(c.expiresAt)
  if (!Number.isFinite(exp)) return { text: '', soon: false }
  const diff = exp - nowMs
  if (c.status !== 'active' || diff <= 0) return { text: '', soon: false }
  const mins = Math.ceil(diff / 60_000)
  return { text: `in ${Math.floor(mins / 60)} h ${mins % 60} m`, soon: diff < soonMs }
}

function StatusPill({ status }: { status: string }) {
  const tone = status === 'active' ? 'ok' : status === 'pending' ? 'warn' : 'neutral'
  const label = status ? status.charAt(0).toUpperCase() + status.slice(1) : 'Unknown'
  return <span className={`sa-pill sa-pill-${tone}`}>{label}</span>
}

// ── Issue a grant ─────────────────────────────────────────────────────────────

function IssueGrant({ tenantId, onIssued }: { tenantId: string; onIssued: () => void }) {
  const [hours, setHours] = useState(defaultHours)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [done, setDone] = useState<string | null>(null)

  async function give() {
    setBusy(true)
    setError(null)
    setDone(null)
    try {
      await createAccessGrant(tenantId, { durationMinutes: hours * 60 })
      setDone(`Support access given for ${hours} h.`)
      onIssued()
    } catch (cause: unknown) {
      setError(actionError(cause, 'Give access failed'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="sa-panel" aria-labelledby="sa-issue-title" data-testid="issue-panel">
      <div className="sa-phead">
        <h2 id="sa-issue-title">Give support access</h2>
        <span className="sa-sub">
          Lets the CFGMS root support team see this tenant and every client under it. Ends by itself.
        </span>
      </div>
      <div className="sa-pbody">
        <div className="sa-issue">
          <div className="sa-field">
            <span className="sa-lbl">How long</span>
            <div className="sa-durseg" role="group" aria-label="Duration">
              {durations.map((d) => (
                <button
                  key={d.hours}
                  type="button"
                  aria-pressed={hours === d.hours}
                  onClick={() => setHours(d.hours)}
                  data-testid={`duration-${d.hours}`}
                >
                  {d.label}
                </button>
              ))}
            </div>
          </div>
          <button type="button" className="sa-btn" onClick={give} disabled={busy} data-testid="give-access-btn">
            Give access
          </button>
          {error !== null && (
            <div className="sa-msg sa-msg-crit" role="alert" data-testid="issue-error">
              <span>
                <b>Not given.</b> {error}
              </span>
            </div>
          )}
          {done !== null && (
            <div className="sa-msg sa-msg-ok" role="status" data-testid="issue-done">
              {done}
            </div>
          )}
        </div>
        <p className="sa-hint sa-issue-note">
          Any root support person can use it while it lasts. Each person who opens this tenant is recorded in your
          audit log. You confirm with your passkey, and you can revoke access at any time below.
        </p>
      </div>
    </section>
  )
}

// ── Crossing list ─────────────────────────────────────────────────────────────

function WhoCell({ c }: { c: Crossing }) {
  if (isBreakGlass(c)) {
    return <span className="sa-who">{c.principalName || c.principalId || '—'}</span>
  }
  return (
    <>
      <span className="sa-rc">All root support</span>
      <div className="sa-just">
        given by <span className="sa-who">{c.grantedBy || '—'}</span>
      </div>
    </>
  )
}

function actionLabel(c: Crossing): string {
  if (!isBreakGlass(c)) return 'Revoke'
  return c.status === 'pending' || c.approvalState === approvalStatePending ? 'Deny' : 'End now'
}

function ConfirmRow({
  c,
  busy,
  error,
  onKeep,
  onConfirm,
}: {
  c: Crossing
  busy: boolean
  error: string | null
  onKeep: () => void
  onConfirm: () => void
}) {
  const bg = isBreakGlass(c)
  const pending = c.status === 'pending'
  return (
    <tr className="sa-confirm" data-testid="confirm-row">
      <td colSpan={7}>
        <div className={`sa-confirm-in${bg ? ' sa-confirm-bg' : ''}`}>
          <span className="sa-confirm-text">
            {bg ? (
              <>
                <b>{pending ? 'Deny this emergency elevation?' : 'End this emergency elevation now?'}</b>{' '}
                <span className="sa-mono">{c.principalName || c.principalId}</span>{' '}
                {pending
                  ? 'will not get access to this tenant or its clients.'
                  : 'loses access to this tenant and all its clients at once.'}{' '}
                This ends an emergency elevation immediately and is recorded in your audit log.
              </>
            ) : (
              <>
                <b>Revoke support access?</b> CFGMS root support loses access to this tenant and its clients now.
              </>
            )}
            <span className="sa-confirm-sub">You confirm with your passkey.</span>
          </span>
          <button type="button" className="sa-btn-sec sa-sm" onClick={onKeep} disabled={busy} data-testid="confirm-keep-btn">
            Keep
          </button>
          <button
            type="button"
            className={`${bg ? 'sa-btn-danger' : 'sa-btn-danger-soft'} sa-sm`}
            onClick={onConfirm}
            disabled={busy}
            data-testid="confirm-revoke-btn"
          >
            {bg ? (pending ? 'Deny' : 'End elevation') : 'Revoke'}
          </button>
          {error !== null && (
            <div className="sa-msg sa-msg-crit sa-confirm-err" role="alert" data-testid="revoke-error">
              {error}
            </div>
          )}
        </div>
      </td>
    </tr>
  )
}

function isPendingBreakGlass(c: Crossing): boolean {
  return isBreakGlass(c) && c.approvalState === approvalStatePending && c.status === 'pending'
}

interface ApproveControls {
  /** Signed-in username; the client-side requester check compares it with the row. */
  username: string
  busy: boolean
  onApprove: (c: Crossing) => void
}

function CrossingRow({
  c,
  nowMs,
  onAction,
  approve,
  approveError,
}: {
  c: Crossing
  nowMs: number
  onAction: () => void
  approve: ApproveControls | null
  approveError: string | null
}) {
  const bg = isBreakGlass(c)
  const canApprove = approve !== null && isPendingBreakGlass(c)
  const isRequester = canApprove && approve.username !== '' && c.principalName === approve.username
  const live = isLive(c)
  const rel = relative(c, nowMs)
  const cls = `${bg && live ? 'sa-row-bg' : ''}${live ? '' : ' sa-row-dim'}`.trim()
  return (
    <tr className={cls} data-testid="crossing-row" data-crossing-id={c.id}>
      <td>
        <span className={`sa-kind${bg ? ' sa-kind-bg' : ''}`}>{bg ? 'Break-glass' : 'Support access'}</span>
      </td>
      <td>
        <StatusPill status={c.status} />
      </td>
      <td>
        <WhoCell c={c} />
      </td>
      <td>
        {bg ? (
          <>
            <span className="sa-rc">{reasonLabel(c.reasonCategory)}</span>
            <div className="sa-just">{c.justification}</div>
          </>
        ) : (
          <span className="sa-muted">—</span>
        )}
      </td>
      <td>
        <span className="sa-when">{formatWhen(c.createdAt)}</span>
      </td>
      <td>
        <span className="sa-when">
          {c.status === 'pending' ? '—' : formatWhen(c.expiresAt)}
          {rel.text !== '' && <span className={`sa-rel${rel.soon ? ' sa-rel-soon' : ''}`}>{rel.text}</span>}
        </span>
      </td>
      <td>
        {canApprove && (
          <>
            <button
              type="button"
              className="sa-btn sa-sm"
              onClick={() => approve.onApprove(c)}
              disabled={approve.busy || isRequester}
              data-testid="approve-btn"
            >
              Approve
            </button>
            {isRequester && (
              <div className="sa-hint" data-testid="approve-requester-note">
                You requested this, so a different root admin must approve it.
              </div>
            )}
            {approveError !== null && (
              <div className="sa-msg sa-msg-crit" role="alert" data-testid="approve-error">
                {approveError}
              </div>
            )}
          </>
        )}
        {live && (
          <button type="button" className="sa-btn-danger-soft sa-sm" onClick={onAction} data-testid="revoke-btn">
            {actionLabel(c)}
          </button>
        )}
      </td>
    </tr>
  )
}

function CrossingSection({ tenantId, version }: { tenantId: string; version: number }) {
  const { principal } = useAuth()
  const rootScope = principal?.rootScope === true
  const username = principal?.username ?? ''
  const { crossings, loading, error, refetch } = useTenantCrossings(tenantId, version)
  const [showAll, setShowAll] = useState(false)
  const [confirming, setConfirming] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [revokeError, setRevokeError] = useState<string | null>(null)
  const [nowMs, setNowMs] = useState(() => Date.now())

  useEffect(() => {
    const id = window.setInterval(() => setNowMs(Date.now()), 60_000)
    return () => window.clearInterval(id)
  }, [])

  const [approving, setApproving] = useState<string | null>(null)
  const [approveFailure, setApproveFailure] = useState<{ id: string; message: string } | null>(null)

  async function approve(c: Crossing) {
    setApproving(c.id)
    setApproveFailure(null)
    try {
      await approveBreakGlass(tenantId, c.id)
      refetch()
    } catch (cause: unknown) {
      setApproveFailure({ id: c.id, message: actionError(cause, 'Approve failed') })
    } finally {
      setApproving(null)
    }
  }

  async function confirmEnd(c: Crossing) {
    setBusy(true)
    setRevokeError(null)
    try {
      await endCrossing(tenantId, c.id)
      setConfirming(null)
      refetch()
    } catch (cause: unknown) {
      setRevokeError(actionError(cause, 'Revoke failed'))
    } finally {
      setBusy(false)
    }
  }

  const open = crossings.filter(isLive)
  const visible = showAll ? crossings : open
  const ready = !loading && error === null && crossings.length > 0

  return (
    <section className="sa-panel" aria-labelledby="sa-list-title" data-testid="crossing-panel">
      <div className="sa-phead">
        <h2 id="sa-list-title">
          Access to <span className="sa-mono">{tenantId}</span>
        </h2>
        {ready && (
          <>
            <div className="sa-filter" role="group" aria-label="Filter">
              <button type="button" aria-pressed={!showAll} onClick={() => setShowAll(false)} data-testid="filter-open">
                Active &amp; pending
              </button>
              <button type="button" aria-pressed={showAll} onClick={() => setShowAll(true)} data-testid="filter-all">
                All
              </button>
            </div>
            <span className="sa-count" data-testid="crossing-count">
              {open.length} open · {crossings.length} total
            </span>
          </>
        )}
      </div>

      {loading ? (
        <table className="sa-table" data-testid="crossing-loading" aria-busy="true">
          <tbody>
            {[0, 1].map((i) => (
              <tr key={i} className="sa-skrow">
                {[90, 60, 110, 180, 100, 100].map((w, j) => (
                  <td key={j}>
                    <div className="sa-skel" style={{ width: w }} />
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      ) : error !== null ? (
        <div className="sa-errcard" role="alert" data-testid="crossing-error">
          <div className="sa-errcard-text">
            <b>Could not load access records.</b>
            <span>{error} Your access settings have not changed.</span>
          </div>
          <button type="button" className="sa-btn-sec" onClick={refetch} data-testid="crossing-retry-btn">
            Try again
          </button>
        </div>
      ) : crossings.length === 0 ? (
        <div className="sa-empty" data-testid="crossing-empty">
          <h3>No one has access to this tenant</h3>
          <p>
            Support cannot see your tenants. Give access above when you open a support case. Any emergency
            break-glass also shows here.
          </p>
        </div>
      ) : (
        <div className="sa-table-wrap">
          <table className="sa-table" data-testid="crossing-table">
            <thead>
              <tr>
                <th>Kind</th>
                <th>Status</th>
                <th>Who</th>
                <th>Reason</th>
                <th>Started</th>
                <th>Ends</th>
                <th aria-label="Actions" />
              </tr>
            </thead>
            <tbody>
              {visible.length === 0 && (
                <tr>
                  <td colSpan={7} className="sa-muted">
                    Nothing open. Choose “All” to see past access.
                  </td>
                </tr>
              )}
              {visible.map((c) => (
                <FragmentRows
                  key={c.id}
                  c={c}
                  nowMs={nowMs}
                  confirming={confirming === c.id}
                  busy={busy}
                  error={revokeError}
                  approve={rootScope ? { username, busy: approving !== null, onApprove: (row) => void approve(row) } : null}
                  approveError={approveFailure?.id === c.id ? approveFailure.message : null}
                  onAction={() => {
                    setRevokeError(null)
                    setConfirming(c.id)
                  }}
                  onKeep={() => setConfirming(null)}
                  onConfirm={() => void confirmEnd(c)}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}

function FragmentRows({
  c,
  nowMs,
  confirming,
  busy,
  error,
  approve,
  approveError,
  onAction,
  onKeep,
  onConfirm,
}: {
  c: Crossing
  nowMs: number
  confirming: boolean
  busy: boolean
  error: string | null
  approve: ApproveControls | null
  approveError: string | null
  onAction: () => void
  onKeep: () => void
  onConfirm: () => void
}) {
  return (
    <>
      <CrossingRow c={c} nowMs={nowMs} onAction={onAction} approve={approve} approveError={approveError} />
      {confirming && <ConfirmRow c={c} busy={busy} error={error} onKeep={onKeep} onConfirm={onConfirm} />}
    </>
  )
}

// ── Contacts ──────────────────────────────────────────────────────────────────

function ContactsSection({ tenantId }: { tenantId: string }) {
  const { contacts, loading, error, refetch } = useAdminContacts(tenantId)
  // `saved` is the list the server last confirmed from this page; `draft` is the
  // unsaved edit (null while there is none).
  const [saved, setSaved] = useState<string[] | null>(null)
  const [draft, setDraft] = useState<string[] | null>(null)
  const [entry, setEntry] = useState('')
  const [busy, setBusy] = useState(false)
  const [saveError, setSaveError] = useState<string | null>(null)
  const [done, setDone] = useState(false)

  const base = saved ?? contacts
  const list = draft ?? base
  const dirty = draft !== null

  function add() {
    const v = entry.trim()
    if (v === '') return
    setDone(false)
    setSaveError(null)
    if (!list.includes(v)) setDraft([...list, v])
    setEntry('')
  }

  function remove(index: number) {
    setDone(false)
    setSaveError(null)
    setDraft(list.filter((_, i) => i !== index))
  }

  async function save() {
    if (draft === null) return
    setBusy(true)
    setSaveError(null)
    setDone(false)
    try {
      setSaved(await saveAdminContacts(tenantId, draft))
      setDraft(null)
      setDone(true)
    } catch (cause: unknown) {
      setSaveError(actionError(cause, 'Save contacts failed'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="sa-panel" aria-labelledby="sa-contacts-title" data-testid="contacts-panel">
      <div className="sa-phead">
        <h2 id="sa-contacts-title">Emergency contacts</h2>
        <span className="sa-sub">Who is emailed when root uses break-glass on this tenant.</span>
      </div>
      <div className="sa-pbody sa-contacts">
        {loading ? (
          <ul className="sa-clist" data-testid="contacts-loading" aria-busy="true">
            {[200, 160].map((w) => (
              <li key={w} className="sa-citem">
                <div className="sa-skel" style={{ width: w }} />
              </li>
            ))}
          </ul>
        ) : error !== null ? (
          <div className="sa-msg sa-msg-crit" role="alert" data-testid="contacts-error">
            <span>
              <b>Could not load contacts.</b> {error}{' '}
              <button type="button" className="sa-btn-sec sa-sm" onClick={refetch} data-testid="contacts-retry-btn">
                Try again
              </button>
            </span>
          </div>
        ) : (
          <>
            {list.length === 0 ? (
              <div className="sa-msg sa-msg-warn" data-testid="contacts-empty">
                <span>
                  <b>No contacts yet.</b> Add at least one address so a person hears about a break-glass right away.
                </span>
              </div>
            ) : (
              <ul className="sa-clist" data-testid="contacts-list">
                {list.map((addr, i) => {
                  const isNew = !base.includes(addr)
                  const bad = saveError !== null && saveError.includes(addr)
                  return (
                    <li
                      key={addr}
                      className={`sa-citem${isNew ? ' sa-citem-new' : ''}${bad ? ' sa-citem-bad' : ''}`}
                      data-testid="contact-item"
                    >
                      <span className="sa-citem-addr">{addr}</span>
                      <button
                        type="button"
                        className="sa-xbtn"
                        aria-label={`Remove ${addr}`}
                        onClick={() => remove(i)}
                        data-testid="contact-remove-btn"
                      >
                        ×
                      </button>
                    </li>
                  )
                })}
              </ul>
            )}
            <div className="sa-addrow">
              <input
                type="email"
                value={entry}
                placeholder="name@acme-corp.example"
                aria-label="New contact email"
                onChange={(e) => setEntry(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    e.preventDefault()
                    add()
                  }
                }}
                data-testid="contact-input"
              />
              <button type="button" className="sa-btn-sec" onClick={add} data-testid="contact-add-btn">
                Add
              </button>
            </div>
            {saveError !== null && (
              <div className="sa-msg sa-msg-crit" role="alert" data-testid="contacts-save-error">
                <span>
                  <b>Not saved.</b> {saveError}
                </span>
              </div>
            )}
            {done && (
              <div className="sa-msg sa-msg-ok" role="status" data-testid="contacts-saved">
                Contacts saved.
              </div>
            )}
            <div className="sa-savebar">
              <span className="sa-hint">
                Break-glass notifications are emailed to these addresses when the controller has email configured.
                Every break-glass also shows in the list above and in your audit log.
              </span>
              <span className="sa-savebar-gap" />
              {dirty && <span className="sa-dirty">Unsaved changes</span>}
              <button
                type="button"
                className="sa-btn"
                onClick={() => void save()}
                disabled={!dirty || busy}
                data-testid="contacts-save-btn"
              >
                Save contacts
              </button>
            </div>
          </>
        )}
      </div>
    </section>
  )
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function SupportAccessView() {
  const { principal } = useAuth()
  const tenantId = principal?.tenantId ?? ''
  // Root cannot grant or edit contacts; without a tenant there is nothing to operate on.
  const isRoot = principal?.rootScope === true || tenantId === ''
  const [version, setVersion] = useState(0)

  return (
    <div className="sa-content">
      <div className="sa-title">
        <h1>Support access</h1>
        {isRoot ? (
          <p>Support access is controlled by each MSP, from inside its own tenant.</p>
        ) : (
          <p>
            Decide when CFGMS root support can see <b className="sa-mono">{tenantId}</b> and its clients, see every
            access and emergency elevation, and choose who is told about emergencies.
          </p>
        )}
      </div>

      {isRoot ? (
        <>
        <section className="sa-panel" data-testid="root-state">
          <div className="sa-rootnote">
            <h3>This page is for MSP administrators</h3>
            <p>
              You are signed in at root. Root cannot give itself access to an MSP and cannot change who an MSP
              notifies. An MSP administrator issues support access from this page in their own console.
            </p>
            <p className="sa-hint">
              To read a client tenant now, open it from <b>Tenants</b>. You will be asked for MSP access or
              break-glass.
            </p>
          </div>
        </section>
        {/* A root admin who works on a tenant sees its access list to give a break-glass second approval. */}
        {principal?.rootScope === true && tenantId !== '' && <CrossingSection tenantId={tenantId} version={version} />}
        </>
      ) : (
        <>
          <IssueGrant tenantId={tenantId} onIssued={() => setVersion((v) => v + 1)} />
          <CrossingSection tenantId={tenantId} version={version} />
          <ContactsSection tenantId={tenantId} />
        </>
      )}
    </div>
  )
}
