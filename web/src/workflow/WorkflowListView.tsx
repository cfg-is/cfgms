// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Workflow list view (Stories #2731, #2984, #3039) — the /workflows route
 * entry point. Fetches GET /api/v1/workflows and renders a table. Selecting
 * a row opens the overlay drawer (WorkflowDrawer) without reflowing the list.
 *
 * Story #3039: stacked inline panels (create/edit form, trigger panel,
 * execution view) removed in favour of the overlay drawer shell. Tab content
 * (Run/Schedule/Preview) is mounted by sibling stories F3, #2986, and F4.
 *
 * Security A9.1: workflow name and description originate from user-supplied
 * content. Every value reaches the DOM as a JSX text node or controlled input
 * value — never dangerouslySetInnerHTML.
 */
import { useState } from 'react'
import { apiFetch } from '../api/client.ts'
import {
  useWorkflowList,
  type VersionedWorkflow,
} from './useWorkflows.ts'
import WorkflowDrawer from './WorkflowDrawer.tsx'
import ErrorCard from '../shell/ErrorCard.tsx'
import './Workflow.css'

// ── Loading skeleton ──────────────────────────────────────────────────────────

function LoadingRows() {
  return (
    <div data-testid="workflow-loading" aria-label="Loading workflows">
      {Array.from({ length: 4 }, (_, i) => (
        <div className="skrow" key={i}>
          <span className="skel" style={{ width: '65%' }} />
          <span className="skel" style={{ width: '40%' }} />
          <span className="skel" style={{ width: '25%' }} />
          <span className="skel" style={{ width: '55%' }} />
        </div>
      ))}
    </div>
  )
}

function WorkflowEmpty() {
  return (
    <div className="notice empty" data-testid="workflow-empty">
      <div className="ic">◍</div>
      <h3>No workflows found</h3>
      <p>No workflows have been created yet.</p>
    </div>
  )
}

// ── Workflow table row ────────────────────────────────────────────────────────

function WorkflowRow({
  workflow,
  selected,
  onClick,
  onDelete,
}: {
  workflow: VersionedWorkflow
  selected: boolean
  onClick: () => void
  onDelete: () => void
}) {
  return (
    <tr
      className={selected ? 'selected' : ''}
      onClick={onClick}
      data-testid="workflow-row"
    >
      <td>
        <span className="nm">{workflow.name}</span>
      </td>
      <td>
        <span className="mono2">{workflow.version || '—'}</span>
      </td>
      <td>
        <span className="mono2">{workflow.steps.length}</span>
      </td>
      <td>
        <span className="mut">{workflow.description || '—'}</span>
      </td>
      <td
        onClick={(e) => e.stopPropagation()}
        style={{ whiteSpace: 'nowrap' }}
      >
        <button
          type="button"
          className="wf-btn-sm-danger"
          onClick={onDelete}
          data-testid="workflow-delete-btn"
        >
          Delete
        </button>
      </td>
      <td className="c-spacer" />
    </tr>
  )
}

// ── Main view ─────────────────────────────────────────────────────────────────

export default function WorkflowListView() {
  const { workflows, loading, error, retry } = useWorkflowList()
  const [selectedName, setSelectedName] = useState<string | null>(null)
  const [deletingWorkflow, setDeletingWorkflow] = useState<VersionedWorkflow | null>(null)
  const [deleteError, setDeleteError] = useState<string | null>(null)
  const [deleting, setDeleting] = useState(false)

  const selectedWorkflow = workflows.find((w) => w.name === selectedName) ?? null

  function handleRowClick(name: string) {
    setSelectedName((prev) => (prev === name ? null : name))
  }

  async function handleConfirmDelete() {
    if (!deletingWorkflow) return
    const name = deletingWorkflow.name
    setDeleting(true)
    setDeleteError(null)
    setDeletingWorkflow(null)
    try {
      const response = await apiFetch(
        `/api/v1/workflows/${encodeURIComponent(name)}`,
        { method: 'DELETE' },
      )
      if (!response.ok) {
        const errBody = (await response.json().catch(() => ({}))) as Record<
          string,
          unknown
        >
        throw new Error(
          (errBody?.error as string) || `Delete failed — ${response.status}`,
        )
      }
      if (selectedName === name) setSelectedName(null)
      retry()
    } catch (cause: unknown) {
      setDeleteError(
        cause instanceof Error && cause.message ? cause.message : 'Delete failed',
      )
    } finally {
      setDeleting(false)
    }
  }

  return (
    <>
      <div className="htitle">
        <h1>Workflows</h1>
        <p>Author, schedule, and run automations. Select a workflow to run it or open the builder.</p>
      </div>

      <div className="workspace">
        <section className="panel">
          <div className="ptool">
            {!loading && error === null && (
              <span className="cnt" data-testid="workflow-count">
                {workflows.length} workflow{workflows.length !== 1 ? 's' : ''}
              </span>
            )}
          </div>

          {deleteError && (
            <div className="wf-form-error" style={{ padding: '8px 14px' }} data-testid="delete-error">
              {deleteError}
            </div>
          )}

          {loading ? (
            <LoadingRows />
          ) : error !== null ? (
            <ErrorCard heading="Couldn&apos;t load workflows" detail={error} onRetry={retry} />
          ) : workflows.length === 0 ? (
            <WorkflowEmpty />
          ) : (
            <table className="tbl" data-testid="workflow-table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Version</th>
                  <th>Steps</th>
                  <th>Description</th>
                  <th>Actions</th>
                  <th className="c-spacer" aria-hidden="true" />
                </tr>
              </thead>
              <tbody>
                {workflows.map((wf) => (
                  <WorkflowRow
                    key={wf.name}
                    workflow={wf}
                    selected={selectedName === wf.name}
                    onClick={() => handleRowClick(wf.name)}
                    onDelete={() => {
                      setDeleteError(null)
                      setDeletingWorkflow(wf)
                    }}
                  />
                ))}
              </tbody>
            </table>
          )}
        </section>

        {selectedName !== null && selectedWorkflow !== null && (
          <WorkflowDrawer
            workflow={selectedWorkflow}
            onClose={() => setSelectedName(null)}
          />
        )}
      </div>

      {deletingWorkflow !== null && (
        <div
          className="wf-overlay"
          role="dialog"
          aria-modal="true"
          aria-labelledby="delete-confirm-title"
        >
          <div className="wf-modal">
            <h3 id="delete-confirm-title">Delete workflow?</h3>
            <p>
              This will permanently delete{' '}
              <b>{deletingWorkflow.name}</b> and all its versions.
            </p>
            <p>This action cannot be undone.</p>
            <div className="wf-modal-actions">
              <button
                type="button"
                className="wf-btn-secondary"
                disabled={deleting}
                onClick={() => setDeletingWorkflow(null)}
              >
                Cancel
              </button>
              <button
                type="button"
                className="wf-btn-danger"
                disabled={deleting}
                onClick={handleConfirmDelete}
                data-testid="delete-confirm-btn"
              >
                {deleting ? 'Deleting…' : 'Delete workflow'}
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  )
}
