// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * "+ New workflow" dialog (Issue #4582).
 *
 * Sends POST /api/v1/workflows with the fields CreateWorkflowRequest accepts
 * (name, description, steps). 409 renders as a name field error; 400 renders
 * as a form-level error. Submit stays enabled after an error so the operator
 * can correct and retry.
 *
 * Security A9.1: all server-supplied strings render as text nodes only.
 */
import { useState, type FormEvent } from 'react'
import { apiFetch } from '../api/client.ts'

interface NewWorkflowDialogProps {
  onClose: () => void
  onCreated: (name: string) => void
}

async function errorMessage(response: Response, fallback: string): Promise<string> {
  const body = (await response.json().catch(() => ({}))) as Record<string, unknown> | null
  const msg = body?.error
  return typeof msg === 'string' && msg ? msg : fallback
}

export default function NewWorkflowDialog({ onClose, onCreated }: NewWorkflowDialogProps) {
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [stepName, setStepName] = useState('')
  const [module, setModule] = useState('')
  const [nameError, setNameError] = useState<string | null>(null)
  const [stepError, setStepError] = useState<string | null>(null)
  const [formError, setFormError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    const trimmedName = name.trim()
    const trimmedStep = stepName.trim()
    setNameError(trimmedName ? null : 'Workflow name is required')
    setStepError(trimmedStep ? null : 'Step name is required')
    setFormError(null)
    if (!trimmedName || !trimmedStep) return

    const step: Record<string, unknown> = { name: trimmedStep, type: 'task' }
    if (module.trim()) step.module = module.trim()
    const payload: Record<string, unknown> = { name: trimmedName, steps: [step] }
    if (description.trim()) payload.description = description.trim()

    setSubmitting(true)
    try {
      const response = await apiFetch('/api/v1/workflows', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      })
      if (response.status === 409) {
        setNameError(await errorMessage(response, 'A workflow with this name already exists'))
        return
      }
      if (!response.ok) {
        setFormError(await errorMessage(response, `Create failed — ${response.status}`))
        return
      }
      onCreated(trimmedName)
    } catch (cause: unknown) {
      setFormError(cause instanceof Error && cause.message ? cause.message : 'Create failed')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div
      className="wf-overlay"
      role="dialog"
      aria-modal="true"
      aria-labelledby="new-workflow-title"
    >
      <form className="wf-modal" onSubmit={handleSubmit} noValidate>
        <h3 id="new-workflow-title">New workflow</h3>
        <div className="wf-form">
          <label className="wf-form-field">
            <span className="wf-form-label">Name</span>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              data-testid="new-wf-name"
            />
            {nameError && (
              <span className="wf-form-error" role="alert" data-testid="new-wf-name-error">
                {nameError}
              </span>
            )}
          </label>
          <label className="wf-form-field">
            <span className="wf-form-label">Description</span>
            <input
              type="text"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              data-testid="new-wf-description"
            />
          </label>
          <label className="wf-form-field">
            <span className="wf-form-label">First step name</span>
            <input
              type="text"
              value={stepName}
              onChange={(e) => setStepName(e.target.value)}
              data-testid="new-wf-step-name"
            />
            {stepError && (
              <span className="wf-form-error" role="alert" data-testid="new-wf-step-error">
                {stepError}
              </span>
            )}
          </label>
          <label className="wf-form-field">
            <span className="wf-form-label">Step module (optional)</span>
            <input
              type="text"
              value={module}
              onChange={(e) => setModule(e.target.value)}
              data-testid="new-wf-step-module"
            />
          </label>
          {formError && (
            <div className="wf-form-error" role="alert" data-testid="new-wf-form-error">
              {formError}
            </div>
          )}
        </div>
        <div className="wf-modal-actions">
          <button type="button" className="wf-btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button
            type="submit"
            className="wf-btn"
            disabled={submitting}
            data-testid="new-wf-submit"
          >
            {submitting ? 'Creating…' : 'Create workflow'}
          </button>
        </div>
      </form>
    </div>
  )
}
