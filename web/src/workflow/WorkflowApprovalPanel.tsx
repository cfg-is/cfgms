// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * WorkflowApprovalPanel (Issue #5861, Epic #5421) — the pre-approval state of each
 * workflow version, with the Approve and Revoke approval actions an admin uses on a
 * version that did not come from a browser publish, such as a git-synced version
 * (ADR-036 section 2). Layout follows the Scripts view ScriptApprovalPanel.
 *
 * Approve sends the hash the server holds in its record; the browser never computes
 * one. The Approve button sits beside the definition shown for the exact version it
 * approves, so an admin reads what is approved. A version whose definition is not
 * loaded in the list cannot be approved here: the panel will not offer an approval of
 * content the admin has not been shown. Approve is presence-gated; the tap is handled
 * centrally by apiFetch / StepUpModal.
 *
 * Security A9.1: workflow ids, versions, reasons and the definition are
 * untrusted-origin data and render as JSX text only, never as HTML. The definition is
 * serialised to a string and shown in a <pre> text node.
 */
import { useState } from 'react'
import type { ApprovalState } from '../scripts/useScriptApprovals.ts'
import type { VersionedWorkflow } from './useWorkflows.ts'
import type {
  UseWorkflowApprovalsResult,
  WorkflowApprovalEntry,
} from './useWorkflowApprovals.ts'

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

// List-summary fields the list endpoint adds; they are not part of the definition.
const SUMMARY_FIELDS = ['trigger_count', 'enabled_trigger_count', 'last_execution']

function entryKey(e: { workflow_id: string; version: string; approval_hash: string }): string {
  return `${e.workflow_id}\u0000${e.version}\u0000${e.approval_hash}`
}

function semverLabel(w: VersionedWorkflow): string {
  const v = w.semantic_version
  return `${v.major}.${v.minor}.${v.patch}${v.pre_release ? `-${v.pre_release}` : ''}${v.build_meta ? `+${v.build_meta}` : ''}`
}

/** The definition of the exact version an entry names, or null when it is not loaded. */
function definitionFor(entry: WorkflowApprovalEntry, workflows: VersionedWorkflow[]): string | null {
  const match = workflows.find(
    (w) => w.name === entry.workflow_id && (w.version === entry.version || semverLabel(w) === entry.version),
  )
  if (match === undefined) return null
  const body = Object.fromEntries(
    Object.entries(match.raw ?? {}).filter(([k]) => !SUMMARY_FIELDS.includes(k)),
  )
  return JSON.stringify(body, null, 2)
}

function VersionCard({
  entry,
  definition,
  busy,
  onApprove,
  onRevoke,
}: {
  entry: WorkflowApprovalEntry
  definition: string | null
  busy: boolean
  onApprove: () => void
  onRevoke: () => void
}) {
  return (
    <div className="cfg-push-field" data-testid="workflow-approval-version">
      <span className="cfg-push-label">
        <span className="nm">{entry.workflow_id}</span> <span className="mono2">{entry.version}</span>{' '}
        <span className={STATE_PILL[entry.state]} data-testid="workflow-approval-state">
          {STATE_LABEL[entry.state]}
        </span>
      </span>
      {entry.reason !== '' && (
        <span className="mut" data-testid="workflow-approval-reason">
          {entry.reason}
        </span>
      )}
      {entry.approval !== null && (
        <span className="mut" data-testid="workflow-approval-by">
          Approved by {entry.approval.approved_by} at {entry.approval.approved_at}
        </span>
      )}
      {definition !== null ? (
        <pre className="mono2" style={{ overflowX: 'auto' }} data-testid="workflow-approval-definition">
          {definition}
        </pre>
      ) : (
        <span className="mut" data-testid="workflow-approval-definition-unavailable">
          The definition of this version is not loaded, so it cannot be approved here. Only the
          latest version of a workflow is shown.
        </span>
      )}
      <span className="mut">
        Approval hash{' '}
        <span className="mono2" style={hashStyle} data-testid="workflow-approval-hash">
          {entry.approval_hash}
        </span>
      </span>
      <div className="cfg-push-actions">
        {entry.state === 'pending' && (
          <button
            type="button"
            className="cfg-btn"
            disabled={busy || entry.approval_hash === '' || definition === null}
            onClick={onApprove}
            aria-label={`Approve ${entry.workflow_id} ${entry.version}`}
            data-testid="workflow-approve-btn"
          >
            {busy ? 'Approving…' : 'Approve'}
          </button>
        )}
        {entry.state === 'approved' && (
          <button
            type="button"
            className="cfg-btn-secondary"
            disabled={busy}
            onClick={onRevoke}
            aria-label={`Revoke approval of ${entry.workflow_id} ${entry.version}`}
            data-testid="workflow-revoke-btn"
          >
            {busy ? 'Revoking…' : 'Revoke approval'}
          </button>
        )}
      </div>
    </div>
  )
}

export default function WorkflowApprovalPanel({
  approvals,
  workflows,
  workflowId = null,
}: {
  approvals: UseWorkflowApprovalsResult
  /** The workflow list, the source of each version's definition. */
  workflows: VersionedWorkflow[]
  /** Limits the version list to one workflow. */
  workflowId?: string | null
}) {
  const { entries, loading, error, retry, approve, revoke } = approvals
  const [busyKey, setBusyKey] = useState<string | null>(null)
  const [actionError, setActionError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)

  async function run(
    target: WorkflowApprovalEntry,
    action: () => ReturnType<typeof approve>,
    done: string,
  ) {
    setBusyKey(entryKey(target))
    setActionError(null)
    setNotice(null)
    const result = await action()
    setBusyKey(null)
    if (result.ok) setNotice(done)
    else setActionError(result.error)
  }

  const visible = workflowId === null ? entries : entries.filter((e) => e.workflow_id === workflowId)

  return (
    <div className="cfg-push-panel" data-testid="workflow-approval-panel">
      <div className="cfg-push-form">
        <div className="cfg-push-field">
          <span className="cfg-push-label">Workflow approvals</span>
          <span className="mut">
            Approving a version covers exactly the definition shown by its approval hash. A changed
            version needs a new approval.
          </span>
        </div>

        {loading ? (
          <div className="mut" data-testid="workflow-approvals-loading">
            Loading approvals…
          </div>
        ) : error !== null ? (
          <div className="cfg-validation-err" data-testid="workflow-approvals-load-error">
            {error}{' '}
            <button type="button" className="cfg-btn-secondary" onClick={retry}>
              Retry
            </button>
          </div>
        ) : visible.length === 0 ? (
          <span className="mut" data-testid="workflow-approvals-empty">
            No workflow versions to show.
          </span>
        ) : (
          visible.map((e) => (
            <VersionCard
              key={entryKey(e)}
              entry={e}
              definition={definitionFor(e, workflows)}
              busy={busyKey === entryKey(e)}
              onApprove={() => void run(e, () => approve(e), 'Approval recorded.')}
              onRevoke={() => void run(e, () => revoke(e), 'Approval revoked.')}
            />
          ))
        )}

        {actionError !== null && (
          <div className="cfg-validation-err" data-testid="workflow-approval-error">
            {actionError}
          </div>
        )}
        {notice !== null && (
          <div className="cfg-push-status" role="status" data-testid="workflow-approval-notice">
            {notice}
          </div>
        )}
      </div>
    </div>
  )
}
