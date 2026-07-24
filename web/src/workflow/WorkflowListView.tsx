// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Workflow list view (Stories #2731, #2984) — the /workflows route entry point.
 * Fetches GET /api/v1/workflows, renders a table, and exposes workflow
 * create/edit/delete, execution tracking, and trigger management.
 *
 * Security A9.1: workflow name, description, step names, step values, and
 * variable keys/values originate from user-supplied content. Every value
 * reaches the DOM as a JSX text node or controlled input value —
 * never dangerouslySetInnerHTML.
 */
import { useState } from 'react'
import { apiFetch } from '../api/client.ts'
import {
  useWorkflowList,
  type VersionedWorkflow,
  type WorkflowStep,
} from './useWorkflows.ts'
import WorkflowExecutionView from './WorkflowExecutionView.tsx'
import TriggerPanel from './TriggerPanel.tsx'
import ErrorCard from '../shell/ErrorCard.tsx'
import './Workflow.css'

// ── Row ID counter (used only as React key, never surfaced to DOM) ────────────

let _rowId = 0
function mkid(): string {
  _rowId += 1
  return String(_rowId)
}

// ── Step builder types ────────────────────────────────────────────────────────

const STEP_TYPES = ['script', 'shell', 'http', 'notification', 'approval'] as const

interface StepRow {
  id: string
  name: string
  type: string
  scriptBody: string   // config.script for type === 'script'
  configJson: string   // raw config JSON (for non-script types or advanced mode)
  rawOpen: boolean     // whether the Raw config details panel is expanded
}

// ── Variable editor types ─────────────────────────────────────────────────────

interface VarRow {
  id: string
  key: string
  value: string
}

// ── Form state ────────────────────────────────────────────────────────────────

interface FormState {
  name: string
  description: string
  version: string
  steps: StepRow[]
  variables: VarRow[]
}

function defaultStep(): StepRow {
  return { id: mkid(), name: 'step-1', type: 'script', scriptBody: '', configJson: '{}', rawOpen: false }
}

function stepToRow(step: WorkflowStep): StepRow {
  const cfg = step.config ?? {}
  const scriptBody = step.type === 'script' && typeof cfg.script === 'string' ? cfg.script : ''
  // Show raw config when there are keys beyond 'script' (for script type) or any keys (for other types)
  const hasExtra = step.type === 'script'
    ? Object.keys(cfg).some((k) => k !== 'script')
    : Object.keys(cfg).length > 0
  return {
    id: mkid(),
    name: step.name,
    type: step.type,
    scriptBody,
    configJson: hasExtra ? JSON.stringify(cfg, null, 2) : '{}',
    rawOpen: hasExtra,
  }
}

function defaultForm(wf: VersionedWorkflow | null): FormState {
  if (wf === null) {
    return {
      name: '',
      description: '',
      version: '1.0.0',
      steps: [defaultStep()],
      variables: [],
    }
  }
  return {
    name: wf.name,
    description: wf.description,
    version: wf.version || '1.0.0',
    steps: wf.steps.length > 0 ? wf.steps.map(stepToRow) : [defaultStep()],
    variables: wf.variables
      ? Object.entries(wf.variables).map(([k, v]) => ({
          id: mkid(),
          key: k,
          value: typeof v === 'string' ? v : JSON.stringify(v),
        }))
      : [],
  }
}

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
      <p>No workflows have been created yet. Use New workflow to get started.</p>
    </div>
  )
}

// ── Workflow table row ────────────────────────────────────────────────────────

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

// ── Step builder row ──────────────────────────────────────────────────────────

function StepBuilderRow({
  step,
  index,
  canRemove,
  onChange,
  onRemove,
}: {
  step: StepRow
  index: number
  canRemove: boolean
  onChange: (updated: StepRow) => void
  onRemove: () => void
}) {
  const isScriptType = step.type === 'script'
  const isKnownType = (STEP_TYPES as readonly string[]).includes(step.type)

  return (
    <div className="wf-step-row" data-testid="step-row">
      <div className="wf-form-row">
        <div className="wf-form-field">
          <span className="wf-form-label">Step {index + 1} name *</span>
          <input
            type="text"
            aria-label={`Step ${index + 1} name`}
            placeholder={`step-${index + 1}`}
            value={step.name}
            onChange={(e) => onChange({ ...step, name: e.target.value })}
            data-testid="step-name-input"
          />
        </div>
        <div className="wf-form-field">
          <span className="wf-form-label">Type</span>
          <select
            aria-label={`Step ${index + 1} type`}
            value={step.type}
            onChange={(e) =>
              onChange({ ...step, type: e.target.value, scriptBody: '', configJson: '{}', rawOpen: false })
            }
            data-testid="step-type-select"
          >
            {STEP_TYPES.map((t) => (
              <option key={t} value={t}>{t}</option>
            ))}
            {!isKnownType && (
              <option value={step.type}>{step.type}</option>
            )}
          </select>
        </div>
        {isScriptType && (
          <div className="wf-form-field">
            <span className="wf-form-label">Script</span>
            <textarea
              aria-label={`Step ${index + 1} script`}
              placeholder="echo hello"
              value={step.scriptBody}
              onChange={(e) => onChange({ ...step, scriptBody: e.target.value })}
              data-testid="step-script-input"
            />
          </div>
        )}
        {!isScriptType && (
          <div className="wf-form-field">
            <span className="wf-form-label">Config (JSON)</span>
            <textarea
              aria-label={`Step ${index + 1} config JSON`}
              placeholder="{}"
              value={step.configJson}
              onChange={(e) => onChange({ ...step, configJson: e.target.value })}
              data-testid="step-config-json"
            />
          </div>
        )}
        {canRemove && (
          <button
            type="button"
            className="wf-btn-sm-danger wf-step-remove"
            onClick={onRemove}
            aria-label={`Remove step ${index + 1}`}
            data-testid="step-remove-btn"
          >
            Remove
          </button>
        )}
      </div>
      {isScriptType && (
        <details
          open={step.rawOpen}
          onToggle={(e) =>
            onChange({ ...step, rawOpen: (e.currentTarget as HTMLDetailsElement).open })
          }
          className="wf-raw-config"
        >
          <summary className="wf-raw-config-toggle">Raw config JSON</summary>
          <div className="wf-form-row" style={{ marginTop: 6 }}>
            <div className="wf-form-field">
              <textarea
                aria-label={`Step ${index + 1} raw config JSON`}
                placeholder="{}"
                value={step.configJson}
                onChange={(e) => onChange({ ...step, configJson: e.target.value })}
                data-testid="step-config-json"
              />
            </div>
          </div>
        </details>
      )}
    </div>
  )
}

// ── Variable key/value row ────────────────────────────────────────────────────

function VarBuilderRow({
  varRow,
  onChange,
  onRemove,
}: {
  varRow: VarRow
  onChange: (updated: VarRow) => void
  onRemove: () => void
}) {
  return (
    <div className="wf-var-row wf-form-row" data-testid="var-row">
      <div className="wf-form-field">
        <span className="wf-form-label">Key</span>
        <input
          type="text"
          aria-label="Variable key"
          placeholder="var-name"
          value={varRow.key}
          onChange={(e) => onChange({ ...varRow, key: e.target.value })}
          data-testid="var-key-input"
        />
      </div>
      <div className="wf-form-field">
        <span className="wf-form-label">Value</span>
        <input
          type="text"
          aria-label="Variable value"
          placeholder="value"
          value={varRow.value}
          onChange={(e) => onChange({ ...varRow, value: e.target.value })}
          data-testid="var-value-input"
        />
      </div>
      <button
        type="button"
        className="wf-btn-sm-danger wf-var-remove"
        onClick={onRemove}
        aria-label="Remove variable"
        data-testid="var-remove-btn"
      >
        Remove
      </button>
    </div>
  )
}

// ── Workflow form panel ───────────────────────────────────────────────────────

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

  // Step operations
  function addStep() {
    const num = form.steps.length + 1
    setForm((prev) => ({
      ...prev,
      steps: [
        ...prev.steps,
        { id: mkid(), name: `step-${num}`, type: 'script', scriptBody: '', configJson: '{}', rawOpen: false },
      ],
    }))
  }

  function removeStep(idx: number) {
    setForm((prev) => ({ ...prev, steps: prev.steps.filter((_, i) => i !== idx) }))
  }

  function updateStep(idx: number, updated: StepRow) {
    setForm((prev) => ({
      ...prev,
      steps: prev.steps.map((s, i) => (i === idx ? updated : s)),
    }))
  }

  // Variable operations
  function addVar() {
    setForm((prev) => ({
      ...prev,
      variables: [...prev.variables, { id: mkid(), key: '', value: '' }],
    }))
  }

  function removeVar(idx: number) {
    setForm((prev) => ({ ...prev, variables: prev.variables.filter((_, i) => i !== idx) }))
  }

  function updateVar(idx: number, updated: VarRow) {
    setForm((prev) => ({
      ...prev,
      variables: prev.variables.map((v, i) => (i === idx ? updated : v)),
    }))
  }

  async function handleSubmit() {
    if (mode === 'create' && !form.name.trim()) {
      setSaveError('Workflow name is required')
      return
    }
    if (form.steps.length === 0) {
      setSaveError('At least one step is required')
      return
    }
    for (const s of form.steps) {
      if (!s.name.trim()) {
        setSaveError('All steps must have a name')
        return
      }
    }
    for (const s of form.steps) {
      if (s.rawOpen || s.type !== 'script') {
        try {
          JSON.parse(s.configJson || '{}')
        } catch {
          setSaveError(`Step "${s.name}": config must be valid JSON`)
          return
        }
      }
    }

    // Build steps array from structured state
    const steps = form.steps.map((s) => {
      let config: Record<string, unknown> = {}
      if (s.rawOpen || s.type !== 'script') {
        config = JSON.parse(s.configJson || '{}') as Record<string, unknown>
      } else if (s.scriptBody.trim()) {
        config = { script: s.scriptBody }
      }
      return { name: s.name.trim(), type: s.type, config }
    })

    // Build variables object, omitting rows with empty keys
    const varEntries = form.variables.filter((v) => v.key.trim())
    const variables: Record<string, unknown> | undefined =
      varEntries.length > 0
        ? Object.fromEntries(varEntries.map((v) => [v.key.trim(), v.value]))
        : undefined

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
        {/* Workflow metadata row */}
        <div className="wf-form-row">
          <div className="wf-form-field">
            <span className="wf-form-label">Name {isEdit ? '' : '*'}</span>
            <input
              type="text"
              aria-label="Workflow name"
              placeholder="my-workflow"
              value={form.name}
              disabled={isEdit}
              onChange={(e) => setForm((prev) => ({ ...prev, name: e.target.value }))}
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
              onChange={(e) => setForm((prev) => ({ ...prev, description: e.target.value }))}
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
              onChange={(e) => setForm((prev) => ({ ...prev, version: e.target.value }))}
            />
          </div>
        </div>

        {/* Step builder */}
        <div className="wf-builder-section">
          <div className="wf-builder-header">
            <span className="wf-form-label">Steps *</span>
            <button
              type="button"
              className="wf-btn-sm"
              onClick={addStep}
              data-testid="add-step-btn"
            >
              + Add step
            </button>
          </div>
          {form.steps.map((step, idx) => (
            <StepBuilderRow
              key={step.id}
              step={step}
              index={idx}
              canRemove={form.steps.length > 1}
              onChange={(updated) => updateStep(idx, updated)}
              onRemove={() => removeStep(idx)}
            />
          ))}
        </div>

        {/* Variables editor */}
        <div className="wf-builder-section">
          <div className="wf-builder-header">
            <span className="wf-form-label">Variables</span>
            <button
              type="button"
              className="wf-btn-sm"
              onClick={addVar}
              data-testid="add-var-btn"
            >
              + Add variable
            </button>
          </div>
          {form.variables.length === 0 && (
            <p className="wf-var-empty">No variables defined.</p>
          )}
          {form.variables.map((v, idx) => (
            <VarBuilderRow
              key={v.id}
              varRow={v}
              onChange={(updated) => updateVar(idx, updated)}
              onRemove={() => removeVar(idx)}
            />
          ))}
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

// ── Main view ─────────────────────────────────────────────────────────────────

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
