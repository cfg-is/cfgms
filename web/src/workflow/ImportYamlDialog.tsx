// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * "Import YAML" dialog (Issue #4619).
 *
 * The operator pastes or picks a YAML document. It is sent to
 * POST /api/v1/workflows/parse-yaml, which is the authority on validity. Only
 * a document the server reports as valid is then created with
 * POST /api/v1/workflows; an invalid one shows the server's issues and
 * creates nothing.
 *
 * Security A9.1: all server-supplied strings render as text nodes only.
 */
import { useState, type ChangeEvent, type FormEvent } from 'react'
import { apiFetch } from '../api/client.ts'

interface ImportYamlDialogProps {
  onClose: () => void
  onCreated: (name: string) => void
}

interface Issue {
  path: string
  message: string
}

// Fields POST /api/v1/workflows accepts; anything else on the parsed workflow
// (e.g. server-assigned step ids aside) is not forwarded.
const CREATE_FIELDS: string[] = [
  'name',
  'description',
  'version',
  'steps',
  'variables',
  'inputs',
  'timeout',
  'on_failure',
  'error_workflows',
]

async function errorMessage(response: Response, fallback: string): Promise<string> {
  const body = (await response.json().catch(() => ({}))) as Record<string, unknown> | null
  const msg = body?.error
  return typeof msg === 'string' && msg ? msg : fallback
}

export default function ImportYamlDialog({ onClose, onCreated }: ImportYamlDialogProps) {
  const [text, setText] = useState('')
  const [issues, setIssues] = useState<Issue[]>([])
  const [formError, setFormError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  async function handleFile(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (!file) return
    try {
      setText(await file.text())
      setIssues([])
      setFormError(null)
    } catch {
      setFormError('Could not read the selected file')
    }
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setIssues([])
    setFormError(null)
    if (!text.trim()) {
      setFormError('Paste a YAML document or choose a file')
      return
    }

    setSubmitting(true)
    try {
      const parsed = await apiFetch('/api/v1/workflows/parse-yaml', {
        method: 'POST',
        headers: { 'Content-Type': 'application/yaml' },
        body: text,
      })
      if (!parsed.ok) {
        setFormError(await errorMessage(parsed, `Import failed — ${parsed.status}`))
        return
      }
      const result = (await parsed.json()) as {
        workflow?: Record<string, unknown>
        valid?: boolean
        issues?: Issue[]
      }
      if (result.valid !== true || !result.workflow) {
        const found = Array.isArray(result.issues) ? result.issues : []
        setIssues(found)
        if (found.length === 0) setFormError('The server rejected this document')
        return
      }

      const payload: Record<string, unknown> = {}
      for (const [field, v] of Object.entries(result.workflow)) {
        if (CREATE_FIELDS.includes(field) && v !== undefined && v !== null && v !== '') {
          Object.defineProperty(payload, field, { value: v, enumerable: true })
        }
      }
      const response = await apiFetch('/api/v1/workflows', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      })
      if (!response.ok) {
        setFormError(
          await errorMessage(
            response,
            response.status === 409
              ? 'A workflow with this name already exists'
              : `Create failed — ${response.status}`,
          ),
        )
        return
      }
      onCreated(String(result.workflow.name ?? ''))
    } catch (cause: unknown) {
      setFormError(cause instanceof Error && cause.message ? cause.message : 'Import failed')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div
      className="wf-overlay"
      role="dialog"
      aria-modal="true"
      aria-labelledby="import-yaml-title"
    >
      <form className="wf-modal" onSubmit={handleSubmit} noValidate>
        <h3 id="import-yaml-title">Import YAML</h3>
        <div className="wf-form">
          <label className="wf-form-field">
            <span className="wf-form-label">YAML file</span>
            <input
              type="file"
              accept=".yaml,.yml,text/yaml,application/yaml"
              onChange={(e) => void handleFile(e)}
              data-testid="import-yaml-file"
            />
          </label>
          <label className="wf-form-field">
            <span className="wf-form-label">Workflow document</span>
            <textarea
              rows={12}
              spellCheck={false}
              value={text}
              onChange={(e) => setText(e.target.value)}
              data-testid="import-yaml-text"
            />
          </label>
          {issues.length > 0 && (
            <ul className="wf-form-error" role="alert" data-testid="import-yaml-issues">
              {issues.map((i, n) => (
                <li key={n}>
                  {i.path ? `${i.path}: ` : ''}
                  {i.message}
                </li>
              ))}
            </ul>
          )}
          {formError && (
            <div className="wf-form-error" role="alert" data-testid="import-yaml-error">
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
            data-testid="import-yaml-submit"
          >
            {submitting ? 'Importing…' : 'Import'}
          </button>
        </div>
      </form>
    </div>
  )
}
