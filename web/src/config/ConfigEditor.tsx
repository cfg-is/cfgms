// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Config editor (Story #2730): per-steward configuration view, edit, validate,
 * effective-config view, delete, and rollback — all via the steward's REST
 * surface:
 *   GET    /api/v1/stewards/{id}/config
 *   PUT    /api/v1/stewards/{id}/config
 *   DELETE /api/v1/stewards/{id}/config
 *   POST   /api/v1/stewards/{id}/config/validate
 *   GET    /api/v1/stewards/{id}/config/effective
 *
 * Security A9.1: configuration content is rendered inside a <pre> text node
 * (never dangerouslySetInnerHTML) since it may contain attacker-influenced data.
 */
import { useState } from 'react'
import { apiFetch } from '../api/client.ts'
import { useStewardConfig, type ConfigValidationResult } from './useConfigs.ts'
import RollbackPanel from './RollbackPanel.tsx'

interface ConfigEditorProps {
  stewardId: string
  onClose: () => void
}

type EditorView = 'config' | 'effective' | 'rollback'

export default function ConfigEditor({ stewardId, onClose }: ConfigEditorProps) {
  const [view, setView] = useState<EditorView>('config')
  const [editing, setEditing] = useState(false)
  const [editText, setEditText] = useState('')

  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState<string | null>(null)

  const [validating, setValidating] = useState(false)
  const [validationResult, setValidationResult] = useState<ConfigValidationResult | null>(null)

  const [deleting, setDeleting] = useState(false)
  const [deleteConfirm, setDeleteConfirm] = useState(false)
  const [deleteError, setDeleteError] = useState<string | null>(null)
  const [deleted, setDeleted] = useState(false)

  const [effective, setEffective] = useState<unknown>(null)
  const [effectiveLoading, setEffectiveLoading] = useState(false)
  const [effectiveError, setEffectiveError] = useState<string | null>(null)

  const { config, loading, error, retry } = useStewardConfig(stewardId)

  const configText = config ? JSON.stringify(config.config, null, 2) : ''

  function handleStartEdit() {
    setEditText(configText)
    setEditing(true)
    setSaveError(null)
    setValidationResult(null)
  }

  function handleCancelEdit() {
    setEditing(false)
    setSaveError(null)
    setValidationResult(null)
  }

  async function handleSave() {
    setSaving(true)
    setSaveError(null)
    try {
      let parsed: unknown
      try {
        parsed = JSON.parse(editText)
      } catch {
        throw new Error('Invalid JSON — fix syntax errors before saving')
      }
      const response = await apiFetch(
        `/api/v1/stewards/${encodeURIComponent(stewardId)}/config`,
        {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(parsed),
        },
      )
      if (!response.ok) {
        const errBody = (await response.json().catch(() => ({}))) as Record<string, unknown>
        const msg = errBody?.error as string | undefined
        throw new Error(msg || `Save failed — ${response.status}`)
      }
      setEditing(false)
      retry()
    } catch (cause: unknown) {
      setSaveError(cause instanceof Error && cause.message ? cause.message : 'Save failed')
    } finally {
      setSaving(false)
    }
  }

  async function handleValidate() {
    setValidating(true)
    setValidationResult(null)
    const textToValidate = editing ? editText : configText
    try {
      let parsed: unknown
      try {
        parsed = JSON.parse(textToValidate)
      } catch {
        throw new Error('Invalid JSON — cannot validate')
      }
      const response = await apiFetch(
        `/api/v1/stewards/${encodeURIComponent(stewardId)}/config/validate`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ config: parsed }),
        },
      )
      if (!response.ok) throw new Error(`Validate failed — ${response.status}`)
      const body = (await response.json()) as Record<string, unknown>
      const data = (body?.data ?? body) as Record<string, unknown>
      setValidationResult({
        valid: typeof data.valid === 'boolean' ? data.valid : false,
        errors: Array.isArray(data.errors) ? (data.errors as ConfigValidationResult['errors']) : [],
        metadata:
          typeof data.metadata === 'object' && data.metadata !== null
            ? (data.metadata as Record<string, string>)
            : {},
      })
    } catch (cause: unknown) {
      setSaveError(cause instanceof Error && cause.message ? cause.message : 'Validation failed')
    } finally {
      setValidating(false)
    }
  }

  async function handleDelete() {
    setDeleting(true)
    setDeleteError(null)
    try {
      const response = await apiFetch(
        `/api/v1/stewards/${encodeURIComponent(stewardId)}/config`,
        { method: 'DELETE' },
      )
      if (!response.ok && response.status !== 204) {
        throw new Error(`Delete failed — ${response.status}`)
      }
      setDeleted(true)
      setDeleteConfirm(false)
      onClose()
    } catch (cause: unknown) {
      setDeleteError(cause instanceof Error && cause.message ? cause.message : 'Delete failed')
    } finally {
      setDeleting(false)
    }
  }

  async function handleLoadEffective() {
    if (view !== 'effective') {
      setView('effective')
    }
    if (effective !== null) return
    setEffectiveLoading(true)
    setEffectiveError(null)
    try {
      const response = await apiFetch(
        `/api/v1/stewards/${encodeURIComponent(stewardId)}/config/effective`,
      )
      if (!response.ok) throw new Error(`Get effective config failed — ${response.status}`)
      const body = (await response.json()) as Record<string, unknown>
      setEffective(body?.data ?? body)
    } catch (cause: unknown) {
      setEffectiveError(
        cause instanceof Error && cause.message ? cause.message : 'Request failed',
      )
    } finally {
      setEffectiveLoading(false)
    }
  }

  if (deleted) return null

  return (
    <div className="cfg-editor" data-testid="config-editor">
      <div className="cfg-editor-header">
        <h2>{stewardId}</h2>
        <button
          type="button"
          className="cfg-editor-close"
          aria-label="Close config editor"
          onClick={onClose}
        >
          ×
        </button>
      </div>

      <div className="cfg-editor-tabs">
        <button
          type="button"
          className={`cfg-editor-tab${view === 'config' ? ' active' : ''}`}
          onClick={() => setView('config')}
        >
          Config
        </button>
        <button
          type="button"
          className={`cfg-editor-tab${view === 'effective' ? ' active' : ''}`}
          onClick={handleLoadEffective}
        >
          Effective
        </button>
        <button
          type="button"
          className={`cfg-editor-tab${view === 'rollback' ? ' active' : ''}`}
          onClick={() => setView('rollback')}
        >
          Rollback
        </button>
      </div>

      <div className="cfg-editor-body">
        {view === 'config' && (
          <>
            <div className="cfg-editor-actions">
              {!editing ? (
                <>
                  <button
                    type="button"
                    className="cfg-btn-secondary"
                    onClick={handleStartEdit}
                    disabled={loading || !!error}
                    data-testid="editor-edit-btn"
                  >
                    Edit
                  </button>
                  <button
                    type="button"
                    className="cfg-btn-secondary"
                    onClick={handleValidate}
                    disabled={loading || !!error || validating}
                    data-testid="editor-validate-btn"
                  >
                    {validating ? 'Validating…' : 'Validate'}
                  </button>
                  <button
                    type="button"
                    className="cfg-btn-danger"
                    onClick={() => setDeleteConfirm(true)}
                    disabled={loading || !!error}
                    data-testid="editor-delete-btn"
                  >
                    Delete
                  </button>
                </>
              ) : (
                <>
                  <button
                    type="button"
                    className="cfg-btn"
                    onClick={handleSave}
                    disabled={saving}
                    data-testid="editor-save-btn"
                  >
                    {saving ? 'Saving…' : 'Save'}
                  </button>
                  <button
                    type="button"
                    className="cfg-btn-secondary"
                    onClick={handleValidate}
                    disabled={validating || saving}
                    data-testid="editor-validate-btn"
                  >
                    {validating ? 'Validating…' : 'Validate'}
                  </button>
                  <button
                    type="button"
                    className="cfg-btn-secondary"
                    onClick={handleCancelEdit}
                    disabled={saving}
                  >
                    Cancel
                  </button>
                </>
              )}
            </div>

            {loading && (
              <div data-testid="editor-loading">
                {Array.from({ length: 4 }, (_, i) => (
                  <div className="skrow" key={i}>
                    <span className="skel" style={{ width: '80%' }} />
                    <span className="skel" style={{ width: '55%' }} />
                    <span className="skel" style={{ width: '65%' }} />
                    <span className="skel" style={{ width: '70%' }} />
                    <span className="skel" style={{ width: '50%' }} />
                  </div>
                ))}
              </div>
            )}

            {error !== null && (
              <div className="notice err" role="alert">
                <div className="ic">!</div>
                <h3>Couldn&apos;t load configuration</h3>
                <p>{error}</p>
                <button type="button" className="btn" onClick={retry}>
                  Retry
                </button>
              </div>
            )}

            {!loading && error === null && !editing && config && (
              <pre className="cfg-editor-pre" data-testid="editor-config-pre">
                {configText}
              </pre>
            )}

            {!loading && error === null && editing && (
              <textarea
                className="cfg-editor-textarea"
                aria-label="Edit configuration"
                value={editText}
                onChange={(e) => setEditText(e.target.value)}
                data-testid="editor-textarea"
                spellCheck={false}
              />
            )}

            {saveError && (
              <div className="cfg-validation-result">
                <span className="cfg-validation-err" data-testid="editor-save-error">
                  {saveError}
                </span>
              </div>
            )}

            {validationResult !== null && (
              <div className="cfg-validation-result" data-testid="editor-validation-result">
                {validationResult.valid ? (
                  <span className="cfg-validation-ok">Configuration is valid</span>
                ) : (
                  <>
                    <span className="cfg-validation-err">Validation failed</span>
                    {validationResult.errors.length > 0 && (
                      <ul className="cfg-validation-err-list">
                        {validationResult.errors.map((err, i) => (
                          <li key={i} className="cfg-validation-err-item">
                            {err.field ? `${err.field}: ` : ''}{err.message}
                          </li>
                        ))}
                      </ul>
                    )}
                  </>
                )}
              </div>
            )}
          </>
        )}

        {view === 'effective' && (
          <div data-testid="editor-effective">
            {effectiveLoading && (
              <div data-testid="editor-effective-loading">
                {Array.from({ length: 3 }, (_, i) => (
                  <div className="skrow" key={i}>
                    <span className="skel" style={{ width: '70%' }} />
                    <span className="skel" style={{ width: '50%' }} />
                    <span className="skel" style={{ width: '60%' }} />
                    <span className="skel" style={{ width: '40%' }} />
                    <span className="skel" style={{ width: '50%' }} />
                  </div>
                ))}
              </div>
            )}
            {effectiveError && (
              <div className="notice err" role="alert">
                <div className="ic">!</div>
                <h3>Couldn&apos;t load effective configuration</h3>
                <p>{effectiveError}</p>
                <button
                  type="button"
                  className="btn"
                  onClick={() => {
                    setEffective(null)
                    handleLoadEffective()
                  }}
                >
                  Retry
                </button>
              </div>
            )}
            {!effectiveLoading && !effectiveError && effective !== null && (
              <pre className="cfg-editor-pre" data-testid="editor-effective-pre">
                {JSON.stringify(effective, null, 2)}
              </pre>
            )}
          </div>
        )}

        {view === 'rollback' && <RollbackPanel stewardId={stewardId} />}
      </div>

      {deleteConfirm && (
        <div className="cfg-overlay" role="dialog" aria-modal="true" aria-labelledby="cfg-delete-title">
          <div className="cfg-modal">
            <h3 id="cfg-delete-title">Delete configuration</h3>
            <p>
              Delete the configuration for <b>{stewardId}</b>?
            </p>
            <p>The steward will revert to inherited defaults on next sync.</p>
            {deleteError && (
              <p className="cfg-validation-err" data-testid="editor-delete-error">
                {deleteError}
              </p>
            )}
            <div className="cfg-modal-actions">
              <button
                type="button"
                className="cfg-btn-secondary"
                disabled={deleting}
                onClick={() => setDeleteConfirm(false)}
              >
                Cancel
              </button>
              <button
                type="button"
                className="cfg-btn-danger"
                disabled={deleting}
                onClick={handleDelete}
                data-testid="editor-confirm-delete-btn"
              >
                {deleting ? 'Deleting���' : 'Delete'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
