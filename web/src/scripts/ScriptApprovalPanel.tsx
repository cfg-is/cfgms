// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * ScriptApprovalPanel (Issue #5856, Epic #5421) — the pre-approval state of each
 * script version, the inbox of pending changes with their diff, and the Approve
 * and Revoke approval actions (ADR-036 sections 2 and 3).
 *
 * Approve sends the hash the server holds in its record; the browser never
 * computes one. The Approve button sits beside the content shown for the exact
 * version it approves: the diff for a pending change, the version's hashes for a
 * row. Approve is presence-gated; the tap is handled centrally by apiFetch /
 * StepUpModal. Layout follows ScriptPrivilegePanel (panel) and the workflow
 * ApprovalsView (inbox).
 *
 * The diff is a plain-text unified diff shown in a <pre> text node. The cockpit
 * DriftDiffCard renders structured desired-versus-actual field comparisons from
 * an entity pin, so it cannot show a text diff as it is; that gap is reported
 * for the founder design gate.
 *
 * Security A9.1: script ids, versions, reasons and diff text are untrusted-origin
 * data and render as JSX text only, never as HTML.
 */
import { useState } from 'react'
import type {
  ApprovalState,
  PendingScriptChange,
  ScriptApprovalEntry,
  UseScriptApprovalsResult,
} from './useScriptApprovals.ts'

const STATE_LABEL: Record<ApprovalState, string> = {
  approved: 'Approved',
  pending: 'Pending',
  denied: 'Denied',
  unknown: 'Unknown',
}

const STATE_PILL: Record<ApprovalState, string> = {
  approved: 'pill ok',
  pending: 'pill warn',
  denied: 'pill crit',
  unknown: 'pill neutral',
}

const hashStyle = { wordBreak: 'break-all' as const }

function changeKey(c: { script_id: string; version: string; approval_hash: string }): string {
  return `${c.script_id}\u0000${c.version}\u0000${c.approval_hash}`
}

function PendingChangeCard({
  change,
  busy,
  onApprove,
}: {
  change: PendingScriptChange
  busy: boolean
  onApprove: () => void
}) {
  return (
    <div className="cfg-push-field" data-testid="pending-change">
      <span className="cfg-push-label">
        <span className="nm">{change.script_id}</span>{' '}
        <span className="mono2">
          {change.previous_version ? `${change.previous_version} → ` : ''}
          {change.version}
        </span>
      </span>
      {change.first_seen !== '' && <span className="mut">First seen {change.first_seen}</span>}
      {change.diff !== '' ? (
        <pre className="mono2" style={{ overflowX: 'auto' }} data-testid="pending-diff">
          {change.diff}
        </pre>
      ) : (
        <span className="mut" data-testid="pending-diff-unavailable">
          {change.diff_unavailable || 'No diff is available for this change.'}
        </span>
      )}
      <span className="mut">
        Approval hash <span className="mono2" style={hashStyle}>{change.approval_hash}</span>
      </span>
      <div className="cfg-push-actions">
        <button
          type="button"
          className="cfg-btn"
          disabled={busy}
          onClick={onApprove}
          aria-label={`Approve ${change.script_id} ${change.version}`}
          data-testid="pending-approve-btn"
        >
          {busy ? 'Approving…' : 'Approve'}
        </button>
      </div>
    </div>
  )
}

function VersionRow({
  entry,
  hasPendingDiff,
  busy,
  onApprove,
  onRevoke,
}: {
  entry: ScriptApprovalEntry
  hasPendingDiff: boolean
  busy: boolean
  onApprove: () => void
  onRevoke: () => void
}) {
  return (
    <tr data-testid="approval-version-row">
      <td>
        <span className="nm">{entry.script_id}</span>
      </td>
      <td>
        <span className="mono2">{entry.version}</span>
      </td>
      <td>
        <span className={STATE_PILL[entry.state]} data-testid="approval-state">
          {STATE_LABEL[entry.state]}
        </span>
        {entry.state === 'denied' && entry.reason !== '' && (
          <span className="mut" data-testid="approval-reason">
            {' '}
            {entry.reason}
          </span>
        )}
        {entry.approval !== null && (
          <span className="mut" data-testid="approval-by">
            {' '}
            by {entry.approval.approved_by} at {entry.approval.approved_at}
          </span>
        )}
      </td>
      <td>
        <span className="mono2" style={hashStyle} data-testid="approval-hash">
          {entry.approval_hash}
        </span>
      </td>
      <td>
        {entry.state === 'pending' && !hasPendingDiff && (
          <button
            type="button"
            className="cfg-btn"
            disabled={busy || entry.approval_hash === ''}
            onClick={onApprove}
            aria-label={`Approve ${entry.script_id} ${entry.version}`}
            data-testid="approval-approve-btn"
          >
            {busy ? 'Approving…' : 'Approve'}
          </button>
        )}
        {entry.state === 'pending' && hasPendingDiff && (
          <span className="mut">Approve beside the diff above</span>
        )}
        {entry.state === 'approved' && (
          <button
            type="button"
            className="cfg-btn-secondary"
            disabled={busy}
            onClick={onRevoke}
            aria-label={`Revoke approval of ${entry.script_id} ${entry.version}`}
            data-testid="approval-revoke-btn"
          >
            {busy ? 'Revoking…' : 'Revoke approval'}
          </button>
        )}
      </td>
    </tr>
  )
}

export default function ScriptApprovalPanel({
  approvals,
  scriptId = null,
}: {
  approvals: UseScriptApprovalsResult
  /** Limits the version list to one script; the pending inbox always shows every change. */
  scriptId?: string | null
}) {
  const { entries, pending, loading, error, retry, approve, revoke } = approvals
  const [busyKey, setBusyKey] = useState<string | null>(null)
  const [actionError, setActionError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)

  async function run(
    target: ScriptApprovalEntry | PendingScriptChange,
    action: () => ReturnType<typeof approve>,
    done: string,
  ) {
    setBusyKey(changeKey(target))
    setActionError(null)
    setNotice(null)
    const result = await action()
    setBusyKey(null)
    if (result.ok) setNotice(done)
    else setActionError(result.error)
  }

  const visible = scriptId === null ? entries : entries.filter((e) => e.script_id === scriptId)
  const pendingDiffKeys = new Set(pending.filter((c) => c.diff !== '').map(changeKey))

  return (
    <div className="cfg-push-panel" data-testid="script-approval-panel">
      <div className="cfg-push-form">
        <div className="cfg-push-field">
          <span className="cfg-push-label">Script approvals</span>
          <span className="mut">
            Approving a version covers exactly the content, shell, timeout and parameters shown by
            its approval hash. A changed version needs a new approval.
          </span>
        </div>

        {loading ? (
          <div className="mut" data-testid="approvals-loading">
            Loading approvals…
          </div>
        ) : error !== null ? (
          <div className="cfg-validation-err" data-testid="approvals-load-error">
            {error}{' '}
            <button type="button" className="cfg-btn-secondary" onClick={retry}>
              Retry
            </button>
          </div>
        ) : (
          <>
            <div className="cfg-push-field">
              <span className="cfg-push-label" data-testid="pending-count">
                Pending changes ({pending.length})
              </span>
              {pending.length === 0 ? (
                <span className="mut" data-testid="pending-empty">
                  No approved script has a changed version waiting.
                </span>
              ) : (
                pending.map((c) => (
                  <PendingChangeCard
                    key={changeKey(c)}
                    change={c}
                    busy={busyKey === changeKey(c)}
                    onApprove={() => void run(c, () => approve(c), 'Approval recorded.')}
                  />
                ))
              )}
            </div>

            <div className="cfg-push-field">
              <span className="cfg-push-label">Versions</span>
              {visible.length === 0 ? (
                <span className="mut" data-testid="approval-versions-empty">
                  No script versions to show.
                </span>
              ) : (
                <table className="tbl" data-testid="approval-versions-table">
                  <thead>
                    <tr>
                      <th>Script</th>
                      <th>Version</th>
                      <th>State</th>
                      <th>Approval hash</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {visible.map((e) => (
                      <VersionRow
                        key={changeKey(e)}
                        entry={e}
                        hasPendingDiff={pendingDiffKeys.has(changeKey(e))}
                        busy={busyKey === changeKey(e)}
                        onApprove={() => void run(e, () => approve(e), 'Approval recorded.')}
                        onRevoke={() => void run(e, () => revoke(e), 'Approval revoked.')}
                      />
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </>
        )}

        {actionError !== null && (
          <div className="cfg-validation-err" data-testid="approval-error">
            {actionError}
          </div>
        )}
        {notice !== null && (
          <div className="cfg-push-status" role="status" data-testid="approval-notice">
            {notice}
          </div>
        )}
      </div>
    </div>
  )
}
