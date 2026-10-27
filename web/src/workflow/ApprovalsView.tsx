// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Workflow approvals inbox (Issue #5450, Epic #5300) — the /approvals route.
 * Lists the tenant's pending workflow approvals (oldest first) and lets an
 * approver approve or reject each with a required justification. Layout follows
 * modules/ModuleReviewQueue.tsx (list, per-row approve/reject, outcome notice).
 *
 * Security: approval fields originate from workflow definitions and are
 * rendered as JSX text only, never as HTML.
 */
import { useState } from 'react'
import ErrorCard from '../shell/ErrorCard.tsx'
import {
  MAX_JUSTIFICATION_LENGTH,
  useApprovals,
  type Approval,
  type ApprovalDecision,
} from './useApprovals.ts'

function LoadingRows() {
  return (
    <div data-testid="approvals-loading" aria-label="Loading approvals">
      {Array.from({ length: 3 }, (_, i) => (
        <div className="skrow" key={i}>
          <span className="skel" style={{ width: '25%' }} />
          <span className="skel" style={{ width: '35%' }} />
          <span className="skel" style={{ width: '40%' }} />
        </div>
      ))}
    </div>
  )
}

function ApprovalsEmpty() {
  return (
    <div className="notice empty" data-testid="approvals-empty">
      <div className="ic">◍</div>
      <h3>No approvals pending</h3>
      <p>Workflow steps waiting for a decision will appear here.</p>
    </div>
  )
}

function ApprovalRow({
  approval,
  onDecide,
}: {
  approval: Approval
  onDecide: (decision: ApprovalDecision, justification: string) => Promise<string | null>
}) {
  const [justification, setJustification] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function submit(decision: ApprovalDecision) {
    const text = justification.trim()
    if (!text) {
      setError('A justification is required.')
      return
    }
    setError(null)
    setBusy(true)
    const failure = await onDecide(decision, text)
    setBusy(false)
    if (failure !== null) setError(failure)
  }

  return (
    <tr data-testid="approval-row">
      <td>
        <span className="nm">{approval.workflow_name}</span>
      </td>
      <td>
        <span className="mono2">{approval.step_name || approval.step_id}</span>
      </td>
      <td>
        <span data-testid="approval-message">{approval.message}</span>
      </td>
      <td>
        <span className="mono2">{approval.requested_by}</span>
      </td>
      <td>
        <span className="mono2">{approval.requested_at}</span>
      </td>
      <td>
        <input
          type="text"
          className="wf-input"
          aria-label={`Justification for ${approval.workflow_name}`}
          maxLength={MAX_JUSTIFICATION_LENGTH}
          value={justification}
          disabled={busy}
          onChange={(e) => setJustification(e.target.value)}
          data-testid="approval-justification"
        />
        {error !== null && (
          <div className="wf-form-error" data-testid="approval-row-error">
            {error}
          </div>
        )}
      </td>
      <td>
        <button
          type="button"
          className="wf-btn-sm"
          disabled={busy}
          onClick={() => void submit('approve')}
          data-testid="approval-approve-btn"
        >
          Approve
        </button>
        <button
          type="button"
          className="wf-btn-sm-danger"
          disabled={busy}
          onClick={() => void submit('reject')}
          data-testid="approval-reject-btn"
          style={{ marginLeft: '6px' }}
        >
          Reject
        </button>
      </td>
    </tr>
  )
}

export default function ApprovalsView() {
  const { approvals, loading, error, retry, decide } = useApprovals()
  const [notice, setNotice] = useState<string | null>(null)

  async function handleDecide(
    approval: Approval,
    decision: ApprovalDecision,
    justification: string,
  ): Promise<string | null> {
    setNotice(null)
    const result = await decide(approval.approval_id, decision, justification)
    if (!result.ok) return result.error
    setNotice(decision === 'approve' ? 'Approval recorded.' : 'Rejection recorded.')
    return null
  }

  return (
    <>
      <div className="htitle">
        <h1>Approvals</h1>
        <p>Approve or reject workflow steps awaiting a decision. A justification is required.</p>
      </div>

      <section className="panel">
        {!loading && error === null && (
          <div className="ptool">
            <span className="cnt" data-testid="approval-count">
              {approvals.length} pending
            </span>
          </div>
        )}

        {notice !== null && (
          <div role="status" style={{ padding: '8px 14px' }} data-testid="approval-notice">
            {notice}
          </div>
        )}

        {loading ? (
          <LoadingRows />
        ) : error !== null ? (
          <ErrorCard heading="Couldn&apos;t load approvals" detail={error} onRetry={retry} />
        ) : approvals.length === 0 ? (
          <ApprovalsEmpty />
        ) : (
          <table className="tbl" data-testid="approvals-table">
            <thead>
              <tr>
                <th>Workflow</th>
                <th>Step</th>
                <th>Message</th>
                <th>Requested by</th>
                <th>Requested</th>
                <th>Justification</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {approvals.map((approval) => (
                <ApprovalRow
                  key={approval.approval_id}
                  approval={approval}
                  onDecide={(d, j) => handleDecide(approval, d, j)}
                />
              ))}
            </tbody>
          </table>
        )}
      </section>
    </>
  )
}
