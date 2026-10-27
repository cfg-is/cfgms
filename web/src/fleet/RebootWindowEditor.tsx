// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Reboot window editor (Issue #5458, Epic #5300), shared by the tenant
 * settings panel and the steward drawer. The schedule is the YAML text the
 * API takes; the timezone field appears on the tenant scope only. Server text
 * (status, next occurrence, validation errors) renders as JSX text only.
 */
import { useEffect, useState } from 'react'
import { useRebootWindow, type RebootWindow, type RebootWindowScope } from './useRebootWindow.ts'

function errorText(cause: unknown, fallback: string): string {
  return cause instanceof Error && cause.message ? cause.message : fallback
}

type Load = { kind: 'loading' } | { kind: 'error'; message: string } | { kind: 'ready'; value: RebootWindow }

export default function RebootWindowEditor({ scope, id }: { scope: RebootWindowScope; id: string }) {
  const api = useRebootWindow(scope)
  const [load, setLoad] = useState<Load>({ kind: 'loading' })
  const [nonce, setNonce] = useState(0)

  useEffect(() => {
    let cancelled = false
    api.get(id).then(
      (value) => { if (!cancelled) setLoad({ kind: 'ready', value }) },
      (cause: unknown) => { if (!cancelled) setLoad({ kind: 'error', message: errorText(cause, 'Load failed') }) },
    )
    return () => { cancelled = true }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- `api` is rebuilt every render; scope, id and nonce identify the request
  }, [scope, id, nonce])

  return (
    <section aria-labelledby={`reboot-window-heading-${scope}`} data-testid="reboot-window-section" className="wf-form-panel">
      <h3 id={`reboot-window-heading-${scope}`}>Reboot window</h3>
      {load.kind === 'loading' && <span className="mut" data-testid="reboot-window-loading">Loading reboot window…</span>}
      {load.kind === 'error' && (
        <div className="wf-form-actions">
          <span className="wf-form-error" role="alert" data-testid="reboot-window-load-error">{load.message}</span>
          <button
            type="button"
            className="wf-btn-secondary"
            onClick={() => { setLoad({ kind: 'loading' }); setNonce((n) => n + 1) }}
          >
            Retry
          </button>
        </div>
      )}
      {load.kind === 'ready' && <RebootWindowForm scope={scope} id={id} initial={load.value} />}
    </section>
  )
}

function RebootWindowForm({ scope, id, initial }: { scope: RebootWindowScope; id: string; initial: RebootWindow }) {
  const api = useRebootWindow(scope)
  const [current, setCurrent] = useState(initial)
  const [yaml, setYaml] = useState(initial.declared_schedule_yaml ?? '')
  const [timezone, setTimezone] = useState(initial.tenant_default_timezone ?? '')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)

  async function handleSave() {
    setSaving(true)
    setError(null)
    setSaved(false)
    try {
      const input = scope === 'tenants' ? { schedule_yaml: yaml, tenant_default_timezone: timezone.trim() } : { schedule_yaml: yaml }
      setCurrent(await api.save(id, input))
      setSaved(true)
    } catch (cause: unknown) {
      setError(errorText(cause, 'Save failed'))
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="wf-form">
      <p className="mut">
        When reboots may run, as YAML schedule text.
        {scope === 'stewards' ? ' Overrides the tenant window for this steward.' : ''}
      </p>
      <div className="mut" data-testid="reboot-window-status">
        <span>Status: {current.status}</span>
        {current.next_occurrence_display && (
          <span data-testid="reboot-window-next"> · Next window: {current.next_occurrence_display}</span>
        )}
      </div>
      {scope === 'tenants' && (
        <div className="wf-form-field">
          <span className="wf-form-label">Default timezone</span>
          <input
            type="text"
            aria-label="Default timezone"
            placeholder="e.g. America/New_York"
            value={timezone}
            onChange={(e) => { setTimezone(e.target.value); setSaved(false) }}
            data-testid="reboot-window-timezone"
          />
        </div>
      )}
      <div className="wf-form-field">
        <span className="wf-form-label">Schedule (YAML)</span>
        <textarea
          aria-label="Reboot window schedule YAML"
          rows={6}
          spellCheck={false}
          value={yaml}
          onChange={(e) => { setYaml(e.target.value); setSaved(false) }}
          style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-sm)' }}
          data-testid="reboot-window-yaml"
        />
      </div>
      <div className="wf-form-actions">
        <button type="button" className="wf-btn" disabled={saving} onClick={() => void handleSave()} data-testid="reboot-window-save-btn">
          {saving ? 'Saving…' : 'Save reboot window'}
        </button>
        {saved && <span className="mut" role="status" data-testid="reboot-window-saved">Saved</span>}
        {error && <span className="wf-form-error" role="alert" data-testid="reboot-window-save-error">{error}</span>}
      </div>
    </div>
  )
}
