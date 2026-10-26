// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * ScriptPrivilegePanel (Issue #5447) — edits a library script's required API
 * scopes (one per line) and parameter→platform bindings (key/value rows).
 * Saves via PUT /api/v1/scripts/{id}/privilege; script:admin is presence-gated,
 * so the passkey tap is handled centrally by apiFetch / StepUpModal.
 *
 * Security A9.1: script and parameter names are untrusted-origin data and
 * render as JSX text only.
 */
import { useState } from 'react'
import { setPrivilege, type ScriptMetadata } from './useScripts.ts'

interface BindingRow {
  key: number
  param: string
  platform: string
}

export function parseScopes(text: string): string[] {
  return text
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line !== '')
}

export default function ScriptPrivilegePanel({ script }: { script: ScriptMetadata }) {
  const [scopeText, setScopeText] = useState('')
  const [rows, setRows] = useState<BindingRow[]>([])
  const [nextKey, setNextKey] = useState(0)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)

  function updateRow(key: number, patch: Partial<BindingRow>) {
    setRows((prev) => prev.map((r) => (r.key === key ? { ...r, ...patch } : r)))
    setSaved(false)
  }

  async function handleSave() {
    setSaving(true)
    setError(null)
    setSaved(false)
    const bindings = new Map<string, string>()
    for (const r of rows) {
      const param = r.param.trim()
      if (param !== '') bindings.set(param, r.platform.trim())
    }
    try {
      await setPrivilege(script.id, {
        required_api_scope: parseScopes(scopeText),
        param_platform_bindings: Object.fromEntries(bindings),
      })
      setSaved(true)
    } catch (cause: unknown) {
      setError(cause instanceof Error && cause.message ? cause.message : 'Saving privilege failed')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="cfg-push-panel" data-testid="privilege-panel">
      <div className="cfg-push-form">
        <div className="cfg-push-field">
          <span className="cfg-push-label">Privilege for {script.name}</span>
          <span className="mut">
            Saving replaces the script&apos;s current scopes and bindings with the values below.
          </span>
        </div>
        <div className="cfg-push-field">
          <span className="cfg-push-label">Required API scopes (one per line)</span>
          <textarea
            aria-label="Required API scopes"
            className="wide mono2"
            rows={3}
            value={scopeText}
            onChange={(e) => {
              setScopeText(e.target.value)
              setSaved(false)
            }}
            data-testid="privilege-scopes"
          />
        </div>

        <div className="cfg-push-field">
          <span className="cfg-push-label">Platform bindings (parameter → platform)</span>
          {rows.map((r, i) => (
            <div className="cfg-push-row" key={r.key}>
              <input
                aria-label={`Binding parameter ${i + 1}`}
                className="mono2"
                value={r.param}
                onChange={(e) => updateRow(r.key, { param: e.target.value })}
              />
              <input
                aria-label={`Binding platform ${i + 1}`}
                className="mono2"
                value={r.platform}
                onChange={(e) => updateRow(r.key, { platform: e.target.value })}
              />
              <button
                type="button"
                className="cfg-btn-secondary"
                onClick={() => setRows((prev) => prev.filter((x) => x.key !== r.key))}
                aria-label={`Remove binding ${i + 1}`}
              >
                Remove
              </button>
            </div>
          ))}
          <div className="cfg-push-actions">
            <button
              type="button"
              className="cfg-btn-secondary"
              onClick={() => {
                setRows((prev) => [...prev, { key: nextKey, param: '', platform: '' }])
                setNextKey((n) => n + 1)
              }}
              data-testid="privilege-add-binding-btn"
            >
              Add binding
            </button>
          </div>
        </div>

        <div className="cfg-push-actions">
          <button
            type="button"
            className="cfg-btn"
            disabled={saving}
            onClick={() => void handleSave()}
            data-testid="privilege-save-btn"
          >
            {saving ? 'Saving…' : 'Save privilege'}
          </button>
        </div>

        {error !== null && (
          <div className="cfg-validation-err" data-testid="privilege-error">
            {error}
          </div>
        )}
        {saved && (
          <div className="cfg-push-status" data-testid="privilege-saved">
            Privilege saved
          </div>
        )}
      </div>
    </div>
  )
}
