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
  parseTriggerList,
  useWorkflowList,
  type VersionedWorkflow,
} from './useWorkflows.ts'
import WorkflowDrawer from './WorkflowDrawer.tsx'
import NewWorkflowDialog from './NewWorkflowDialog.tsx'
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

function WorkflowEmpty({ onCreate }: { onCreate: () => void }) {
  return (
    <div className="notice empty" data-testid="workflow-empty">
      <div className="ic">◍</div>
      <h3>No workflows found</h3>
      <p>No workflows have been created yet.</p>
      <button
        type="button"
        className="wf-btn"
        onClick={onCreate}
        data-testid="workflow-empty-create-btn"
      >
        + New workflow
      </button>
    </div>
  )
}

function lastRunTone(status: string): { tone: string; icon: string } {
  switch (status) {
    case 'completed':
      return { tone: 'ok', icon: '✓' }
    case 'failed':
    case 'cancelled':
      return { tone: 'crit', icon: '✕' }
    case 'running':
    case 'pending':
    case 'paused':
      return { tone: 'warn', icon: '◔' }
    default:
      return { tone: 'neutral', icon: '–' }
  }
}

function formatRunTime(iso: string): string {
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? '' : d.toLocaleString()
}

// ── Workflow table row ────────────────────────────────────────────────────────

function WorkflowRow({
  workflow,
  selected,
  onClick,
  onDelete,
  onToggle,
  toggling,
}: {
  workflow: VersionedWorkflow
  selected: boolean
  onClick: () => void
  onDelete: () => void
  onToggle: () => void
  toggling: boolean
}) {
  const last = workflow.last_execution
  const lastTone = last ? lastRunTone(last.status) : null
  const noTriggers = workflow.trigger_count === 0
  const enabled = workflow.enabled_trigger_count > 0
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
      <td data-testid="workflow-triggers">
        {noTriggers ? (
          <span className="mut">manual</span>
        ) : (
          <span className="mono2">{workflow.trigger_count}</span>
        )}
      </td>
      <td data-testid="workflow-last-run">
        {last && lastTone ? (
          <>
            <span className={`pill ${lastTone.tone}`}>
              <span aria-hidden="true">{lastTone.icon}</span>
              {last.status}
            </span>{' '}
            <span className="mut">{formatRunTime(last.start_time)}</span>
          </>
        ) : (
          <span className="mut">Never run</span>
        )}
      </td>
      <td onClick={(e) => e.stopPropagation()}>
        <label style={{ whiteSpace: 'nowrap' }}>
          <input
            type="checkbox"
            role="switch"
            checked={enabled}
            disabled={noTriggers || toggling}
            onChange={onToggle}
            aria-label={`Enabled: ${workflow.name}`}
            data-testid="workflow-enabled-toggle"
          />{' '}
          {noTriggers ? '—' : enabled ? 'Enabled' : 'Disabled'}
        </label>
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
  const [creating, setCreating] = useState(false)
  const [togglingWorkflow, setTogglingWorkflow] = useState<VersionedWorkflow | null>(null)
  const [toggleBusy, setToggleBusy] = useState(false)
  const [toggleError, setToggleError] = useState<string | null>(null)

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

  // Enable/disable every trigger of the workflow, then refresh the list.
  async function handleConfirmToggle() {
    if (!togglingWorkflow) return
    const wf = togglingWorkflow
    const action = wf.enabled_trigger_count > 0 ? 'disable' : 'enable'
    setToggleBusy(true)
    setToggleError(null)
    setTogglingWorkflow(null)
    try {
      const listResp = await apiFetch('/api/v1/triggers')
      if (!listResp.ok) throw new Error(`Failed to load triggers — ${listResp.status}`)
      const body = (await listResp.json()) as Record<string, unknown> | null
      const ids = parseTriggerList(body?.triggers)
        .filter((t) => t.workflow_name === wf.name)
        .map((t) => t.id)
      for (const id of ids) {
        const response = await apiFetch(
          `/api/v1/triggers/${encodeURIComponent(id)}/${action}`,
          { method: 'POST' },
        )
        if (!response.ok) {
          const errBody = (await response.json().catch(() => ({}))) as Record<
            string,
            unknown
          >
          throw new Error(
            (errBody?.error as string) ||
              `${action === 'enable' ? 'Enable' : 'Disable'} failed — ${response.status}`,
          )
        }
      }
    } catch (cause: unknown) {
      setToggleError(
        cause instanceof Error && cause.message ? cause.message : 'Update failed',
      )
    } finally {
      setToggleBusy(false)
      retry()
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
            <button
              type="button"
              className="wf-btn"
              style={{ marginLeft: 'auto' }}
              onClick={() => setCreating(true)}
              data-testid="new-workflow-btn"
            >
              + New workflow
            </button>
          </div>

          {deleteError && (
            <div className="wf-form-error" style={{ padding: '8px 14px' }} data-testid="delete-error">
              {deleteError}
            </div>
          )}

          {toggleError && (
            <div className="wf-form-error" style={{ padding: '8px 14px' }} data-testid="toggle-error">
              {toggleError}
            </div>
          )}

          {loading ? (
            <LoadingRows />
          ) : error !== null ? (
            <ErrorCard heading="Couldn&apos;t load workflows" detail={error} onRetry={retry} />
          ) : workflows.length === 0 ? (
            <WorkflowEmpty onCreate={() => setCreating(true)} />
          ) : (
            <table className="tbl" data-testid="workflow-table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Version</th>
                  <th>Steps</th>
                  <th>Description</th>
                  <th>Triggers</th>
                  <th>Last run</th>
                  <th>Enabled</th>
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
                    toggling={toggleBusy}
                    onToggle={() => {
                      setToggleError(null)
                      setTogglingWorkflow(wf)
                    }}
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

      {creating && (
        <NewWorkflowDialog
          onClose={() => setCreating(false)}
          onCreated={(name) => {
            setCreating(false)
            setSelectedName(name)
            retry()
          }}
        />
      )}

      {togglingWorkflow !== null && (
        <div
          className="wf-overlay"
          role="dialog"
          aria-modal="true"
          aria-labelledby="toggle-confirm-title"
        >
          <div className="wf-modal">
            <h3 id="toggle-confirm-title">
              {togglingWorkflow.enabled_trigger_count > 0 ? 'Disable' : 'Enable'} triggers?
            </h3>
            <p>
              This will {togglingWorkflow.enabled_trigger_count > 0 ? 'disable' : 'enable'} all{' '}
              {togglingWorkflow.trigger_count} trigger
              {togglingWorkflow.trigger_count !== 1 ? 's' : ''} of{' '}
              <b>{togglingWorkflow.name}</b>.
            </p>
            <div className="wf-modal-actions">
              <button
                type="button"
                className="wf-btn-secondary"
                onClick={() => setTogglingWorkflow(null)}
              >
                Cancel
              </button>
              <button
                type="button"
                className="wf-btn"
                onClick={handleConfirmToggle}
                data-testid="toggle-confirm-btn"
              >
                Confirm
              </button>
            </div>
          </div>
        </div>
      )}

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
