// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Trigger panel (Story #2731, Story #2986) — list, create, edit, delete, and
 * enable/disable workflow triggers.
 * Covers the RegisterTriggerRoutes surface: GET/POST /api/v1/triggers,
 * GET/PUT/DELETE /api/v1/triggers/{id}, and POST /api/v1/triggers/{id}/enable|disable.
 *
 * Security A9.1: trigger id, name, type, workflow_name, schedule expression, and
 * webhook path originate from user-supplied content. Every value reaches the DOM
 * as a JSX text node or controlled input value — never dangerouslySetInnerHTML.
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

interface TriggerForm {
  name: string
  type: string
  workflowName: string
  description: string
  scheduleExpression: string
  webhookPath: string
}

function defaultForm(): TriggerForm {
  return {
    name: '',
    type: 'manual',
    workflowName: '',
    description: '',
    scheduleExpression: '',
    webhookPath: '',
  }
}

export default function TriggerPanel({ onClose }: TriggerPanelProps) {
  const { triggers, loading, error, retry } = useTriggerList()

  const [formMode, setFormMode] = useState<'create' | 'edit' | null>(null)
  const [editingTriggerId, setEditingTriggerId] = useState<string | null>(null)
  const [form, setForm] = useState<TriggerForm>(defaultForm)
  const [submitting, setSubmitting] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)

  const [deletingId, setDeletingId] = useState<string | null>(null)
  const [deletingName, setDeletingName] = useState<string>('')
  const [deleting, setDeleting] = useState(false)
  const [deleteError, setDeleteError] = useState<string | null>(null)

  const [togglingId, setTogglingId] = useState<string | null>(null)
  const [toggleError, setToggleError] = useState<string | null>(null)

  function setField<K extends keyof TriggerForm>(key: K, value: TriggerForm[K]) {
    setForm((prev) => ({ ...prev, [key]: value }))
  }

  async function handleSubmit() {
    if (!form.name.trim()) {
      setFormError('Trigger name is required')
      return
    }
    if (!form.workflowName.trim()) {
      setFormError('Workflow name is required')
      return
    }

    setSubmitting(true)
    setFormError(null)

    try {
      const body: Record<string, unknown> = {
        name: form.name.trim(),
        type: form.type,
        workflow_name: form.workflowName.trim(),
        description: form.description.trim() || undefined,
      }

      if (form.type === 'schedule' && form.scheduleExpression.trim()) {
        body.schedule = { cron_expression: form.scheduleExpression.trim() }
      }
      if (form.type === 'webhook' && form.webhookPath.trim()) {
        body.webhook = { path: form.webhookPath.trim() }
      }

      const isEdit = formMode === 'edit' && editingTriggerId !== null
      const url = isEdit
        ? `/api/v1/triggers/${encodeURIComponent(editingTriggerId!)}`
        : '/api/v1/triggers'
      const method = isEdit ? 'PUT' : 'POST'

      const response = await apiFetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      if (!response.ok) {
        const errBody = (await response.json().catch(() => ({}))) as Record<
          string,
          unknown
        >
        const verb = isEdit ? 'Update' : 'Create'
        throw new Error(
          (errBody?.error as string) || `${verb} failed — ${response.status}`,
        )
      }
      setFormMode(null)
      setEditingTriggerId(null)
      setForm(defaultForm())
      retry()
    } catch (cause: unknown) {
      const verb = formMode === 'edit' ? 'Update' : 'Create'
      setFormError(
        cause instanceof Error && cause.message
          ? cause.message
          : `${verb} failed`,
      )
    } finally {
      setSubmitting(false)
    }
  }

  async function handleOpenEdit(id: string) {
    setFormError(null)
    try {
      const response = await apiFetch(
        `/api/v1/triggers/${encodeURIComponent(id)}`,
      )
      if (!response.ok) {
        throw new Error(`Failed to load trigger — ${response.status}`)
      }
      const trigger = (await response.json()) as Record<string, unknown>
      const sched = trigger.schedule as Record<string, unknown> | null | undefined
      const wh = trigger.webhook as Record<string, unknown> | null | undefined
      setForm({
        name: String(trigger.name ?? ''),
        type: String(trigger.type ?? 'manual'),
        workflowName: String(trigger.workflow_name ?? ''),
        description: String(trigger.description ?? ''),
        scheduleExpression: String(sched?.cron_expression ?? ''),
        webhookPath: String(wh?.path ?? ''),
      })
      setEditingTriggerId(id)
      setFormMode('edit')
    } catch (cause: unknown) {
      setFormError(
        cause instanceof Error && cause.message
          ? cause.message
          : 'Failed to load trigger for editing',
      )
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

  async function handleToggle(id: string, enable: boolean) {
    setTogglingId(id)
    setToggleError(null)
    try {
      const action = enable ? 'enable' : 'disable'
      const response = await apiFetch(
        `/api/v1/triggers/${encodeURIComponent(id)}/${action}`,
        { method: 'POST' },
      )
      if (!response.ok) {
        const errBody = (await response.json().catch(() => ({}))) as Record<
          string,
          unknown
        >
        const verb = enable ? 'Enable' : 'Disable'
        throw new Error(
          (errBody?.error as string) || `${verb} failed — ${response.status}`,
        )
      }
      retry()
    } catch (cause: unknown) {
      const verb = enable ? 'Enable' : 'Disable'
      setToggleError(
        cause instanceof Error && cause.message
          ? cause.message
          : `${verb} failed`,
      )
    } finally {
      setTogglingId(null)
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
            if (formMode === 'create') {
              setFormMode(null)
              setFormError(null)
            } else {
              setFormMode('create')
              setEditingTriggerId(null)
              setForm(defaultForm())
              setFormError(null)
            }
          }}
          data-testid="toggle-trigger-create-btn"
        >
          {formMode === 'create' ? 'Close' : '+ New trigger'}
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

      {formMode !== null && (
        <div className="wf-trigger-form" data-testid="trigger-create-form">
          <div className="wf-form-row">
            <div className="wf-form-field">
              <span className="wf-form-label">Name *</span>
              <input
                type="text"
                aria-label="Trigger name"
                placeholder="my-trigger"
                value={form.name}
                onChange={(e) => setField('name', e.target.value)}
                data-testid="trigger-name-input"
              />
            </div>
            <div className="wf-form-field">
              <span className="wf-form-label">Type</span>
              <select
                aria-label="Trigger type"
                value={form.type}
                onChange={(e) => setField('type', e.target.value)}
                data-testid="trigger-type-select"
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
                value={form.workflowName}
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
                value={form.description}
                onChange={(e) => setField('description', e.target.value)}
                className="wide"
              />
            </div>
            {form.type === 'schedule' && (
              <div className="wf-form-field">
                <span className="wf-form-label">Cron expression</span>
                <input
                  type="text"
                  aria-label="Cron expression"
                  placeholder="0 * * * *"
                  value={form.scheduleExpression}
                  onChange={(e) => setField('scheduleExpression', e.target.value)}
                  data-testid="trigger-schedule-expression-input"
                />
              </div>
            )}
            {form.type === 'webhook' && (
              <div className="wf-form-field">
                <span className="wf-form-label">Webhook path</span>
                <input
                  type="text"
                  aria-label="Webhook path"
                  placeholder="/webhooks/my-trigger"
                  value={form.webhookPath}
                  onChange={(e) => setField('webhookPath', e.target.value)}
                  data-testid="trigger-webhook-path-input"
                />
              </div>
            )}
          </div>
          <div className="wf-form-actions">
            <button
              type="button"
              className="wf-btn"
              disabled={submitting}
              onClick={handleSubmit}
              data-testid="trigger-create-submit-btn"
            >
              {submitting
                ? formMode === 'edit'
                  ? 'Saving…'
                  : 'Creating…'
                : formMode === 'edit'
                  ? 'Save changes'
                  : 'Create trigger'}
            </button>
            <button
              type="button"
              className="wf-btn-secondary"
              onClick={() => {
                setFormMode(null)
                setEditingTriggerId(null)
                setForm(defaultForm())
                setFormError(null)
              }}
            >
              Cancel
            </button>
            {formError && (
              <span className="wf-form-error" data-testid="trigger-create-error">
                {formError}
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

      {toggleError && (
        <div
          className="wf-form-error"
          style={{ padding: '8px 14px' }}
          data-testid="trigger-toggle-error"
        >
          {toggleError}
        </div>
      )}

      {formMode === null && formError && (
        <div
          className="wf-form-error"
          style={{ padding: '8px 14px' }}
          data-testid="trigger-create-error"
        >
          {formError}
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
                isToggling={togglingId === t.id}
                onDelete={(id, name) => {
                  setDeleteError(null)
                  setDeletingId(id)
                  setDeletingName(name)
                }}
                onEdit={(id) => {
                  setFormError(null)
                  void handleOpenEdit(id)
                }}
                onToggle={(id, enable) => {
                  void handleToggle(id, enable)
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
  isToggling,
  onDelete,
  onEdit,
  onToggle,
}: {
  trigger: TriggerItem
  isToggling: boolean
  onDelete: (id: string, name: string) => void
  onEdit: (id: string) => void
  onToggle: (id: string, enable: boolean) => void
}) {
  const canToggle =
    trigger.status === 'active' ||
    trigger.status === 'inactive' ||
    trigger.status === 'paused'
  const shouldEnable = trigger.status !== 'active'

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
          className="wf-btn-sm"
          onClick={() => onEdit(trigger.id)}
          data-testid="trigger-edit-btn"
        >
          Edit
        </button>
        {canToggle && (
          <button
            type="button"
            className="wf-btn-sm"
            disabled={isToggling}
            onClick={() => onToggle(trigger.id, shouldEnable)}
            data-testid="trigger-toggle-btn"
          >
            {shouldEnable ? 'Enable' : 'Disable'}
          </button>
        )}
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
