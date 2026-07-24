// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Workflow list view (Story #2731) — the /workflows route entry point.
 * Fetches GET /api/v1/workflows, renders a table, and exposes workflow
 * create/edit/delete, execution tracking, and trigger management.
 *
 * Security A9.1: workflow name, description, and step values originate
 * from user-supplied content. Every value reaches the DOM as a JSX text
 * node — never dangerouslySetInnerHTML.
 */
import { useState } from 'react'
import { apiFetch } from '../api/client.ts'
import {
  useWorkflowList,
  type VersionedWorkflow,
} from './useWorkflows.ts'
import WorkflowExecutionView from './WorkflowExecutionView.tsx'
import TriggerPanel from './TriggerPanel.tsx'
import ErrorCard from '../shell/ErrorCard.tsx'
import './Workflow.css'

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
      <p>No workflows have been created yet. Use New workflow to get started.</p>
    </div>
  )
}

function WorkflowRow({
  workflow,
  selected,
  onClick,
  onEdit,
  onDelete,
}: {
  workflow: VersionedWorkflow
  selected: boolean
  onClick: () => void
  onEdit: () => void
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
          className="wf-btn-sm"
          onClick={onEdit}
          data-testid="workflow-edit-btn"
        >
          Edit
        </button>
        <button
          type="button"
          className="wf-btn-sm-danger"
          onClick={onDelete}
          data-testid="workflow-delete-btn"
          style={{ marginLeft: 4 }}
        >
          Delete
        </button>
      </td>
      <td className="c-spacer" />
    </tr>
  )
}

interface FormState {
  name: string
  description: string
  version: string
  stepsJson: string
  variablesJson: string
}

function defaultForm(wf: VersionedWorkflow | null): FormState {
  if (wf === null) {
    return {
      name: '',
      description: '',
      version: '1.0.0',
      stepsJson: '[{"name":"step-1","type":"script","config":{}}]',
      variablesJson: '',
    }
  }
  return {
    name: wf.name,
    description: wf.description,
    version: wf.version || '1.0.0',
    stepsJson: JSON.stringify(wf.steps, null, 2),
    variablesJson: wf.variables ? JSON.stringify(wf.variables, null, 2) : '',
  }
}

function WorkflowFormPanel({
  mode,
  initial,
  onSaved,
  onClose,
}: {
  mode: 'create' | 'edit'
  initial: VersionedWorkflow | null
  onSaved: () => void
  onClose: () => void
}) {
  const [form, setForm] = useState<FormState>(() => defaultForm(initial))
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState<string | null>(null)

  function set<K extends keyof FormState>(key: K, value: FormState[K]) {
    setForm((prev) => ({ ...prev, [key]: value }))
  }

  async function handleSubmit() {
    if (mode === 'create' && !form.name.trim()) {
      setSaveError('Workflow name is required')
      return
    }

    let steps: unknown[]
    try {
      steps = JSON.parse(form.stepsJson)
      if (!Array.isArray(steps) || steps.length === 0) {
        setSaveError('Steps must be a JSON array with at least one step')
        return
      }
    } catch {
      setSaveError('Steps must be valid JSON array')
      return
    }

    let variables: Record<string, unknown> | undefined
    if (form.variablesJson.trim()) {
      try {
        const v = JSON.parse(form.variablesJson)
        if (typeof v !== 'object' || Array.isArray(v) || v === null) {
          setSaveError('Variables must be a JSON object')
          return
        }
        variables = v as Record<string, unknown>
      } catch {
        setSaveError('Variables must be valid JSON object')
        return
      }
    }

    setSaving(true)
    setSaveError(null)

    const bodyObj = {
      name: form.name.trim(),
      description: form.description.trim(),
      version: form.version.trim() || '1.0.0',
      steps,
      ...(variables !== undefined && { variables }),
    }

    try {
      const url =
        mode === 'create'
          ? '/api/v1/workflows'
          : `/api/v1/workflows/${encodeURIComponent(form.name.trim())}`
      const response = await apiFetch(url, {
        method: mode === 'create' ? 'POST' : 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(bodyObj),
      })
      if (!response.ok) {
        const errBody = (await response.json().catch(() => ({}))) as Record<
          string,
          unknown
        >
        throw new Error(
          (errBody?.error as string) || `Save failed — ${response.status}`,
        )
      }
      onSaved()
    } catch (cause: unknown) {
      setSaveError(
        cause instanceof Error && cause.message ? cause.message : 'Save failed',
      )
    } finally {
      setSaving(false)
    }
  }

  const isEdit = mode === 'edit'

  return (
    <div className="wf-form-panel" data-testid="workflow-form-panel">
      <div className="wf-form">
        <div className="wf-form-row">
          <div className="wf-form-field">
            <span className="wf-form-label">Name {isEdit ? '' : '*'}</span>
            <input
              type="text"
              aria-label="Workflow name"
              placeholder="my-workflow"
              value={form.name}
              disabled={isEdit}
              onChange={(e) => set('name', e.target.value)}
              data-testid="workflow-name-input"
            />
          </div>
          <div className="wf-form-field">
            <span className="wf-form-label">Description</span>
            <input
              type="text"
              aria-label="Description"
              placeholder="Optional description"
              value={form.description}
              onChange={(e) => set('description', e.target.value)}
              className="wide"
            />
          </div>
          <div className="wf-form-field">
            <span className="wf-form-label">Version</span>
            <input
              type="text"
              aria-label="Version"
              placeholder="1.0.0"
              value={form.version}
              onChange={(e) => set('version', e.target.value)}
            />
          </div>
        </div>

        <div className="wf-form-row">
          <div className="wf-form-field">
            <span className="wf-form-label">Steps (JSON array) *</span>
            <textarea
              aria-label="Steps JSON"
              value={form.stepsJson}
              onChange={(e) => set('stepsJson', e.target.value)}
              data-testid="workflow-steps-input"
            />
          </div>
          <div className="wf-form-field">
            <span className="wf-form-label">Variables (JSON object)</span>
            <textarea
              aria-label="Variables JSON"
              placeholder="{}"
              value={form.variablesJson}
              onChange={(e) => set('variablesJson', e.target.value)}
            />
          </div>
        </div>

        <div className="wf-form-actions">
          <button
            type="button"
            className="wf-btn"
            disabled={saving}
            onClick={handleSubmit}
            data-testid="workflow-save-btn"
          >
            {saving ? 'Saving…' : isEdit ? 'Save changes' : 'Create workflow'}
          </button>
          <button
            type="button"
            className="wf-btn-secondary"
            onClick={onClose}
          >
            Cancel
          </button>
          {saveError && (
            <span className="wf-form-error" data-testid="workflow-save-error">
              {saveError}
            </span>
          )}
        </div>
      </div>
    </div>
  )
}

export default function WorkflowListView() {
  const { workflows, loading, error, retry } = useWorkflowList()
  const [selectedName, setSelectedName] = useState<string | null>(null)
  const [formMode, setFormMode] = useState<'create' | 'edit' | null>(null)
  const [editingWorkflow, setEditingWorkflow] = useState<VersionedWorkflow | null>(null)
  const [deletingWorkflow, setDeletingWorkflow] = useState<VersionedWorkflow | null>(null)
  const [showTriggers, setShowTriggers] = useState(false)
  const [deleteError, setDeleteError] = useState<string | null>(null)
  const [deleting, setDeleting] = useState(false)

  function handleRowClick(name: string) {
    setSelectedName((prev) => (prev === name ? null : name))
    setFormMode(null)
    setEditingWorkflow(null)
  }

  function handleOpenCreate() {
    setFormMode('create')
    setEditingWorkflow(null)
    setSelectedName(null)
    setShowTriggers(false)
  }

  function handleOpenEdit(wf: VersionedWorkflow) {
    setFormMode('edit')
    setEditingWorkflow(wf)
    setSelectedName(null)
    setShowTriggers(false)
  }

  function handleFormSaved() {
    setFormMode(null)
    setEditingWorkflow(null)
    retry()
  }

  function handleFormClose() {
    setFormMode(null)
    setEditingWorkflow(null)
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
        <p>Manage automated workflows, view execution history, and configure triggers.</p>
      </div>

      <section className="panel">
        <div className="ptool">
          <button
            type="button"
            className={formMode === 'create' ? 'wf-btn' : 'wf-btn-secondary'}
            onClick={formMode === 'create' ? handleFormClose : handleOpenCreate}
            data-testid="toggle-create-btn"
          >
            {formMode === 'create' ? 'Close' : '+ New workflow'}
          </button>
          <button
            type="button"
            className={showTriggers ? 'wf-btn' : 'wf-btn-secondary'}
            onClick={() => {
              setShowTriggers((v) => !v)
              setFormMode(null)
            }}
            data-testid="toggle-triggers-btn"
          >
            {showTriggers ? 'Close triggers' : 'Triggers'}
          </button>
          {!loading && error === null && (
            <span className="cnt" data-testid="workflow-count">
              {workflows.length} workflow{workflows.length !== 1 ? 's' : ''}
            </span>
          )}
        </div>

        {formMode === 'create' && (
          <WorkflowFormPanel
            mode="create"
            initial={null}
            onSaved={handleFormSaved}
            onClose={handleFormClose}
          />
        )}

        {formMode === 'edit' && editingWorkflow && (
          <WorkflowFormPanel
            mode="edit"
            initial={editingWorkflow}
            onSaved={handleFormSaved}
            onClose={handleFormClose}
          />
        )}

        {showTriggers && (
          <TriggerPanel onClose={() => setShowTriggers(false)} />
        )}

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
                  onEdit={() => handleOpenEdit(wf)}
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

      {selectedName !== null && (
        <WorkflowExecutionView
          workflowName={selectedName}
          onClose={() => setSelectedName(null)}
        />
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
