// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Trigger panel (Story #2731) — list, create, and delete workflow triggers.
 * Covers the RegisterTriggerRoutes surface: GET/POST /api/v1/triggers and
 * DELETE /api/v1/triggers/{id}.
 *
 * Security A9.1: trigger id, name, type, and workflow_name originate from
 * user-supplied content. Every value reaches the DOM as a JSX text node —
 * never dangerouslySetInnerHTML.
 */
import { useState } from 'react'
import { apiFetch } from '../api/client.ts'
import { useTriggerList, type TriggerItem } from './useWorkflows.ts'

const TRIGGER_TYPES = ['schedule', 'webhook', 'siem', 'manual'] as const

function triggerStatusTone(status: string): string {
  switch (status) {
    case 'active':
      return 'ok'
    case 'inactive':
    case 'paused':
      return 'neutral'
    case 'error':
      return 'crit'
    default:
      return 'neutral'
  }
}

interface TriggerPanelProps {
  onClose: () => void
}

interface CreateForm {
  name: string
  type: string
  workflowName: string
  description: string
}

function defaultCreateForm(): CreateForm {
  return { name: '', type: 'manual', workflowName: '', description: '' }
}

export default function TriggerPanel({ onClose }: TriggerPanelProps) {
  const { triggers, loading, error, retry } = useTriggerList()

  const [showCreateForm, setShowCreateForm] = useState(false)
  const [createForm, setCreateForm] = useState<CreateForm>(defaultCreateForm)
  const [creating, setCreating] = useState(false)
  const [createError, setCreateError] = useState<string | null>(null)

  const [deletingId, setDeletingId] = useState<string | null>(null)
  const [deletingName, setDeletingName] = useState<string>('')
  const [deleting, setDeleting] = useState(false)
  const [deleteError, setDeleteError] = useState<string | null>(null)

  function setField<K extends keyof CreateForm>(key: K, value: CreateForm[K]) {
    setCreateForm((prev) => ({ ...prev, [key]: value }))
  }

  async function handleCreate() {
    if (!createForm.name.trim()) {
      setCreateError('Trigger name is required')
      return
    }
    if (!createForm.workflowName.trim()) {
      setCreateError('Workflow name is required')
      return
    }

    setCreating(true)
    setCreateError(null)

    try {
      const body = {
        name: createForm.name.trim(),
        type: createForm.type,
        workflow_name: createForm.workflowName.trim(),
        description: createForm.description.trim() || undefined,
      }
      const response = await apiFetch('/api/v1/triggers', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      if (!response.ok) {
        const errBody = (await response.json().catch(() => ({}))) as Record<
          string,
          unknown
        >
        throw new Error(
          (errBody?.error as string) || `Create failed — ${response.status}`,
        )
      }
      setShowCreateForm(false)
      setCreateForm(defaultCreateForm())
      retry()
    } catch (cause: unknown) {
      setCreateError(
        cause instanceof Error && cause.message ? cause.message : 'Create failed',
      )
    } finally {
      setCreating(false)
    }
  }

  async function handleConfirmDelete() {
    if (!deletingId) return
    const id = deletingId
    setDeletingId(null)
    setDeleting(true)
    setDeleteError(null)
    try {
      const response = await apiFetch(
        `/api/v1/triggers/${encodeURIComponent(id)}`,
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
    <div className="wf-trigger-panel" data-testid="trigger-panel">
      <div className="wf-trigger-header">
        <h3>Triggers</h3>
        <button
          type="button"
          className="wf-btn-secondary"
          onClick={() => {
            setShowCreateForm((v) => !v)
            setCreateError(null)
          }}
          data-testid="toggle-trigger-create-btn"
        >
          {showCreateForm ? 'Close' : '+ New trigger'}
        </button>
        <button
          type="button"
          className="wf-btn-secondary"
          style={{ marginLeft: 'auto' }}
          onClick={onClose}
        >
          Close triggers
        </button>
      </div>

      {showCreateForm && (
        <div className="wf-trigger-form" data-testid="trigger-create-form">
          <div className="wf-form-row">
            <div className="wf-form-field">
              <span className="wf-form-label">Name *</span>
              <input
                type="text"
                aria-label="Trigger name"
                placeholder="my-trigger"
                value={createForm.name}
                onChange={(e) => setField('name', e.target.value)}
                data-testid="trigger-name-input"
              />
            </div>
            <div className="wf-form-field">
              <span className="wf-form-label">Type</span>
              <select
                aria-label="Trigger type"
                value={createForm.type}
                onChange={(e) => setField('type', e.target.value)}
              >
                {TRIGGER_TYPES.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>
            </div>
            <div className="wf-form-field">
              <span className="wf-form-label">Workflow name *</span>
              <input
                type="text"
                aria-label="Workflow name for trigger"
                placeholder="my-workflow"
                value={createForm.workflowName}
                onChange={(e) => setField('workflowName', e.target.value)}
                data-testid="trigger-workflow-input"
              />
            </div>
            <div className="wf-form-field">
              <span className="wf-form-label">Description</span>
              <input
                type="text"
                aria-label="Trigger description"
                placeholder="Optional"
                value={createForm.description}
                onChange={(e) => setField('description', e.target.value)}
                className="wide"
              />
            </div>
          </div>
          <div className="wf-form-actions">
            <button
              type="button"
              className="wf-btn"
              disabled={creating}
              onClick={handleCreate}
              data-testid="trigger-create-submit-btn"
            >
              {creating ? 'Creating…' : 'Create trigger'}
            </button>
            <button
              type="button"
              className="wf-btn-secondary"
              onClick={() => {
                setShowCreateForm(false)
                setCreateError(null)
              }}
            >
              Cancel
            </button>
            {createError && (
              <span className="wf-form-error" data-testid="trigger-create-error">
                {createError}
              </span>
            )}
          </div>
        </div>
      )}

      {deleteError && (
        <div
          className="wf-form-error"
          style={{ padding: '8px 14px' }}
          data-testid="trigger-delete-error"
        >
          {deleteError}
        </div>
      )}

      {loading ? (
        <div data-testid="trigger-loading" aria-label="Loading triggers">
          {Array.from({ length: 3 }, (_, i) => (
            <div className="skrow" key={i}>
              <span className="skel" style={{ width: '55%' }} />
              <span className="skel" style={{ width: '30%' }} />
              <span className="skel" style={{ width: '35%' }} />
              <span className="skel" style={{ width: '40%' }} />
            </div>
          ))}
        </div>
      ) : error !== null ? (
        <div className="notice err" role="alert">
          <div className="ic">!</div>
          <h3>Couldn&apos;t load triggers</h3>
          <span className="mono2 detail">{error}</span>
          <button type="button" className="btn" onClick={retry}>
            Retry
          </button>
        </div>
      ) : triggers.length === 0 ? (
        <div className="notice empty" data-testid="trigger-empty">
          <div className="ic">◍</div>
          <h3>No triggers configured</h3>
          <p>Create a trigger to automate workflow execution.</p>
        </div>
      ) : (
        <table className="tbl" data-testid="trigger-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Type</th>
              <th>Workflow</th>
              <th>Status</th>
              <th>Actions</th>
              <th className="c-spacer" aria-hidden="true" />
            </tr>
          </thead>
          <tbody>
            {triggers.map((t) => (
              <TriggerRow
                key={t.id}
                trigger={t}
                onDelete={(id, name) => {
                  setDeleteError(null)
                  setDeletingId(id)
                  setDeletingName(name)
                }}
              />
            ))}
          </tbody>
        </table>
      )}

      {deletingId !== null && (
        <div
          className="wf-overlay"
          role="dialog"
          aria-modal="true"
          aria-labelledby="trigger-delete-title"
        >
          <div className="wf-modal">
            <h3 id="trigger-delete-title">Delete trigger?</h3>
            <p>
              This will permanently delete trigger <b>{deletingName}</b>.
            </p>
            <div className="wf-modal-actions">
              <button
                type="button"
                className="wf-btn-secondary"
                disabled={deleting}
                onClick={() => setDeletingId(null)}
              >
                Cancel
              </button>
              <button
                type="button"
                className="wf-btn-danger"
                disabled={deleting}
                onClick={handleConfirmDelete}
                data-testid="trigger-delete-confirm-btn"
              >
                {deleting ? 'Deleting…' : 'Delete trigger'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

function TriggerRow({
  trigger,
  onDelete,
}: {
  trigger: TriggerItem
  onDelete: (id: string, name: string) => void
}) {
  return (
    <tr data-testid="trigger-row">
      <td>
        <span className="nm">{trigger.name}</span>
      </td>
      <td>
        <span className="mono2">{trigger.type}</span>
      </td>
      <td>
        <span className="mono2">{trigger.workflow_name || '—'}</span>
      </td>
      <td>
        <span className={`pill ${triggerStatusTone(trigger.status)}`}>
          <span className="dot" />
          {trigger.status}
        </span>
      </td>
      <td>
        <button
          type="button"
          className="wf-btn-sm-danger"
          onClick={() => onDelete(trigger.id, trigger.name)}
          data-testid="trigger-delete-btn"
        >
          Delete
        </button>
      </td>
      <td className="c-spacer" />
    </tr>
  )
}
