// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Module review queue (Issue #2732). The /modules route page. Renders the
 * module-bundle approval queue backed by:
 *   GET  /api/v1/modules/approvals
 *   POST /api/v1/modules/approvals/{address}/approve
 *   POST /api/v1/modules/approvals/{address}/reject
 *
 * Security: bundle metadata (publisher, content address) is attacker-influenced
 * — an unsigned or malicious bundle can carry arbitrary strings. All fields are
 * rendered as JSX text nodes only, never via dangerouslySetInnerHTML.
 *
 * Approve and reject each require an explicit confirm step that shows the
 * bundle's content address and publisher. Approving authorizes code execution
 * on every managed endpoint that requires that bundle; the confirm step
 * reflects that weight.
 */
import { useState } from 'react'
import { useModuleQueue } from './useModuleQueue.ts'
import type { ModuleApprovalEntry } from './useModuleQueue.ts'
import ErrorCard from '../shell/ErrorCard.tsx'

interface PendingAction {
  bundle: ModuleApprovalEntry
  action: 'approve' | 'reject'
}

function LoadingRows() {
  return (
    <div data-testid="modules-loading" aria-label="Loading module queue">
      {Array.from({ length: 3 }, (_, i) => (
        <div className="skrow" key={i}>
          <span className="skel" style={{ width: '25%' }} />
          <span className="skel" style={{ width: '15%' }} />
          <span className="skel" style={{ width: '20%' }} />
          <span className="skel" style={{ width: '55%' }} />
        </div>
      ))}
    </div>
  )
}


function ModuleEmpty() {
  return (
    <div className="notice empty" data-testid="modules-empty">
      <div className="ic">◍</div>
      <h3>No modules pending review</h3>
      <p>
        All module bundles have been reviewed. New bundles will appear here when submitted for
        approval.
      </p>
    </div>
  )
}

function BundleRow({
  bundle,
  onApprove,
  onReject,
}: {
  bundle: ModuleApprovalEntry
  onApprove: () => void
  onReject: () => void
}) {
  return (
    <tr data-testid="bundle-row">
      <td>
        <span className="nm">{bundle.name}</span>
      </td>
      <td>
        <span className="mono2">{bundle.version}</span>
      </td>
      <td>
        <span className="mono2">{bundle.publisher}</span>
      </td>
      <td>
        <span className="mono2">{bundle.address}</span>
      </td>
      <td onClick={(e) => e.stopPropagation()}>
        <button
          type="button"
          className="wf-btn-sm"
          onClick={onApprove}
          data-testid="bundle-approve-btn"
        >
          Approve
        </button>
        <button
          type="button"
          className="wf-btn-sm-danger"
          onClick={onReject}
          data-testid="bundle-reject-btn"
          style={{ marginLeft: '6px' }}
        >
          Reject
        </button>
      </td>
    </tr>
  )
}

export default function ModuleReviewQueue() {
  const { bundles, loading, error, retry, approve, reject } = useModuleQueue()
  const [pendingAction, setPendingAction] = useState<PendingAction | null>(null)
  const [actionError, setActionError] = useState<string | null>(null)

  async function handleConfirm() {
    if (!pendingAction) return
    const { bundle, action } = pendingAction
    setActionError(null)
    setPendingAction(null)
    const result = action === 'approve'
      ? await approve(bundle.address)
      : await reject(bundle.address)
    if (!result.ok) {
      setActionError(result.error)
    }
  }

  return (
    <>
      <div className="htitle">
        <h1>Modules</h1>
        <p>Review and approve or reject module bundles awaiting deployment authorization.</p>
      </div>

      <section className="panel">
        {!loading && error === null && (
          <div className="ptool">
            <span className="cnt" data-testid="bundle-count">
              {bundles.length} pending
            </span>
          </div>
        )}

        {actionError !== null && (
          <div className="wf-form-error" style={{ padding: '8px 14px' }} data-testid="action-error">
            {actionError}
          </div>
        )}

        {loading ? (
          <LoadingRows />
        ) : error !== null ? (
          <ErrorCard heading="Couldn&apos;t load module queue" detail={error} onRetry={retry} />
        ) : bundles.length === 0 ? (
          <ModuleEmpty />
        ) : (
          <table className="tbl" data-testid="modules-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Version</th>
                <th>Publisher</th>
                <th>Address</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {bundles.map((bundle) => (
                <BundleRow
                  key={bundle.address}
                  bundle={bundle}
                  onApprove={() => {
                    setActionError(null)
                    setPendingAction({ bundle, action: 'approve' })
                  }}
                  onReject={() => {
                    setActionError(null)
                    setPendingAction({ bundle, action: 'reject' })
                  }}
                />
              ))}
            </tbody>
          </table>
        )}
      </section>

      {pendingAction !== null && (
        <div
          className="wf-overlay"
          role="dialog"
          aria-modal="true"
          aria-labelledby="module-action-title"
        >
          <div className="wf-modal">
            <h3 id="module-action-title">
              {pendingAction.action === 'approve'
                ? 'Approve module bundle?'
                : 'Reject module bundle?'}
            </h3>
            <dl className="module-confirm-detail">
              <dt>Publisher</dt>
              <dd>
                <span className="mono2" data-testid="confirm-publisher">
                  {pendingAction.bundle.publisher}
                </span>
              </dd>
              <dt>Content address</dt>
              <dd>
                <span className="mono2" data-testid="confirm-address">
                  {pendingAction.bundle.address}
                </span>
              </dd>
            </dl>
            {pendingAction.action === 'approve' ? (
              <p>
                Approving this bundle authorizes it to execute on every managed endpoint that
                requires it. This action is recorded in the audit log.
              </p>
            ) : (
              <p>
                Rejecting this bundle blocks it from deployment to managed endpoints.
              </p>
            )}
            <div className="wf-modal-actions">
              <button
                type="button"
                className="wf-btn-secondary"
                onClick={() => setPendingAction(null)}
                data-testid="confirm-cancel-btn"
              >
                Cancel
              </button>
              {pendingAction.action === 'approve' ? (
                <button
                  type="button"
                  className="wf-btn"
                  onClick={handleConfirm}
                  data-testid="confirm-approve-btn"
                >
                  Approve bundle
                </button>
              ) : (
                <button
                  type="button"
                  className="wf-btn-danger"
                  onClick={handleConfirm}
                  data-testid="confirm-reject-btn"
                >
                  Reject bundle
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </>
  )
}
