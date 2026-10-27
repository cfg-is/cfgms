// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Tenant settings panel (Issue #5444, Epic #5300).
 *
 * Expands in place under a tenant row (the AccountsView account-row pattern).
 * A sectioned container: one labelled <section> per setting, so later stories
 * add sections without restructuring. Server text and tenant data render as
 * JSX text only, never as HTML.
 */
import { useEffect, useState } from 'react'
import {
  getAssurancePolicy,
  getRefreshPolicy,
  putAssurancePolicy,
  putRefreshPolicy,
  refreshModes,
  type AssuranceOverride,
  type MinOverride,
  type RefreshMode,
} from './useTenantPolicies.ts'
import {
  configSourceCredentialMaxTokenLen,
  putConfigSourceCredential,
  testConfigSource,
  type ConfigSourceCredentialResult,
  type ConfigSourceTestResult,
} from './useTenantConfigSource.ts'

function modeLabel(mode: RefreshMode): string {
  switch (mode) {
    case 'auto_accept':
      return 'Auto-accept'
    case 'require_approval':
      return 'Require approval'
    case 'reject':
      return 'Reject'
  }
}

function errorText(cause: unknown, fallback: string): string {
  return cause instanceof Error && cause.message ? cause.message : fallback
}

type LoadState<T> =
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | { kind: 'ready'; value: T }

function useLoaded<T>(load: () => Promise<T>, key: string): LoadState<T> & { reload: () => void } {
  const [state, setState] = useState<LoadState<T>>({ kind: 'loading' })
  const [nonce, setNonce] = useState(0)
  useEffect(() => {
    let cancelled = false
    load().then(
      (value) => { if (!cancelled) setState({ kind: 'ready', value }) },
      (cause: unknown) => { if (!cancelled) setState({ kind: 'error', message: errorText(cause, 'Load failed') }) },
    )
    return () => { cancelled = true }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- `load` is rebuilt every render; key + nonce identify the request
  }, [key, nonce])
  return {
    ...state,
    reload: () => { setState({ kind: 'loading' }); setNonce((n) => n + 1) },
  }
}

// ── Refresh policy ────────────────────────────────────────────────────────────

function RefreshPolicySection({ tenantId }: { tenantId: string }) {
  const loaded = useLoaded(() => getRefreshPolicy(tenantId), tenantId)
  return (
    <section aria-labelledby="refresh-policy-heading" data-testid="refresh-policy-section" className="wf-form-panel">
      <h3 id="refresh-policy-heading">Refresh policy</h3>
      {loaded.kind === 'loading' && <span className="mut" data-testid="refresh-policy-loading">Loading refresh policy…</span>}
      {loaded.kind === 'error' && (
        <div className="wf-form-actions">
          <span className="wf-form-error" role="alert" data-testid="refresh-policy-load-error">{loaded.message}</span>
          <button type="button" className="wf-btn-secondary" onClick={loaded.reload}>Retry</button>
        </div>
      )}
      {loaded.kind === 'ready' && (
        <RefreshPolicyForm
          tenantId={tenantId}
          initialMode={loaded.value.mode}
          initialDays={loaded.value.max_dormancy_days}
        />
      )}
    </section>
  )
}

function RefreshPolicyForm({
  tenantId,
  initialMode,
  initialDays,
}: {
  tenantId: string
  initialMode: RefreshMode
  initialDays: number | undefined
}) {
  const [mode, setMode] = useState<RefreshMode>(initialMode)
  const [days, setDays] = useState(initialDays === undefined ? '' : String(initialDays))
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)

  async function handleSave() {
    const trimmed = days.trim()
    let max: number | undefined
    if (trimmed !== '') {
      if (!/^\d+$/.test(trimmed)) {
        setError('Maximum dormancy must be a whole number of days')
        return
      }
      max = Number(trimmed)
    }
    setSaving(true)
    setError(null)
    setSaved(false)
    try {
      await putRefreshPolicy(tenantId, max === undefined ? { mode } : { mode, max_dormancy_days: max })
      setSaved(true)
    } catch (cause: unknown) {
      setError(errorText(cause, 'Save failed'))
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="wf-form">
      <p className="mut">How the tenant handles steward credential refresh requests. Saving asks for a passkey tap.</p>
      <div className="wf-form-row">
        <div className="wf-form-field">
          <span className="wf-form-label">Mode</span>
          <select
            aria-label="Refresh mode"
            value={mode}
            onChange={(e) => { setMode(e.target.value as RefreshMode); setSaved(false) }}
            data-testid="refresh-mode-select"
          >
            {refreshModes.map((m) => (
              <option key={m} value={m}>{modeLabel(m)}</option>
            ))}
          </select>
        </div>
        <div className="wf-form-field">
          <span className="wf-form-label">Maximum dormancy (days)</span>
          <input
            type="text"
            inputMode="numeric"
            aria-label="Maximum dormancy days"
            placeholder="No limit"
            value={days}
            onChange={(e) => { setDays(e.target.value); setSaved(false) }}
            data-testid="refresh-dormancy-input"
          />
        </div>
      </div>
      <div className="wf-form-actions">
        <button type="button" className="wf-btn" disabled={saving} onClick={() => void handleSave()} data-testid="refresh-save-btn">
          {saving ? 'Saving…' : 'Save refresh policy'}
        </button>
        {saved && <span className="mut" role="status" data-testid="refresh-saved">Saved</span>}
        {error && <span className="wf-form-error" role="alert" data-testid="refresh-save-error">{error}</span>}
      </div>
    </div>
  )
}

// ── Assurance policy ──────────────────────────────────────────────────────────

interface OverrideDraft {
  permission_id: string
  min: '' | MinOverride
  presence: boolean
}

function AssurancePolicySection({ tenantId }: { tenantId: string }) {
  const loaded = useLoaded(() => getAssurancePolicy(tenantId), tenantId)
  return (
    <section aria-labelledby="assurance-policy-heading" data-testid="assurance-policy-section" className="wf-form-panel">
      <h3 id="assurance-policy-heading">Assurance policy</h3>
      {loaded.kind === 'loading' && <span className="mut" data-testid="assurance-policy-loading">Loading assurance policy…</span>}
      {loaded.kind === 'error' && (
        <div className="wf-form-actions">
          <span className="wf-form-error" role="alert" data-testid="assurance-policy-load-error">{loaded.message}</span>
          <button type="button" className="wf-btn-secondary" onClick={loaded.reload}>Retry</button>
        </div>
      )}
      {loaded.kind === 'ready' && <AssuranceForm tenantId={tenantId} initial={loaded.value.overrides} />}
    </section>
  )
}

function toDraft(o: AssuranceOverride): OverrideDraft {
  return { permission_id: o.permission_id, min: o.min_override ?? '', presence: o.require_user_presence }
}

function AssuranceForm({ tenantId, initial }: { tenantId: string; initial: AssuranceOverride[] }) {
  const [rows, setRows] = useState<OverrideDraft[]>(() => initial.map(toDraft))
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)

  function update(i: number, patch: Partial<OverrideDraft>) {
    setRows((prev) => prev.map((r, idx) => (idx === i ? { ...r, ...patch } : r)))
    setSaved(false)
  }

  async function handleSave() {
    if (rows.some((r) => r.permission_id.trim() === '')) {
      setError('Every override needs a permission ID')
      return
    }
    setSaving(true)
    setError(null)
    setSaved(false)
    try {
      await putAssurancePolicy(tenantId, {
        overrides: rows.map((r) => ({
          permission_id: r.permission_id.trim(),
          ...(r.min === '' ? {} : { min_override: r.min }),
          require_user_presence: r.presence,
        })),
      })
      setSaved(true)
    } catch (cause: unknown) {
      setError(errorText(cause, 'Save failed'))
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="wf-form">
      <p className="mut" data-testid="assurance-raise-only-note">
        Overrides can only raise the bar: a tenant can require stronger assurance or a passkey tap
        for a permission, never weaken the platform default.
      </p>
      {rows.length === 0 && <span className="mut" data-testid="assurance-no-overrides">No overrides set</span>}
      {rows.map((row, i) => (
        <div className="wf-form-row" key={i} data-testid="assurance-override-row">
          <div className="wf-form-field">
            <span className="wf-form-label">Permission ID</span>
            <input
              type="text"
              aria-label={`Permission ID ${i + 1}`}
              placeholder="refresh:set-policy"
              value={row.permission_id}
              onChange={(e) => update(i, { permission_id: e.target.value })}
            />
          </div>
          <div className="wf-form-field">
            <span className="wf-form-label">Minimum assurance</span>
            <select
              aria-label={`Minimum assurance ${i + 1}`}
              value={row.min}
              onChange={(e) => update(i, { min: e.target.value as '' | MinOverride })}
            >
              <option value="">No change</option>
              <option value="basic">Basic</option>
              <option value="strong">Strong</option>
            </select>
          </div>
          <div className="wf-form-field">
            <label className="wf-form-label">
              <input
                type="checkbox"
                aria-label={`Require user presence ${i + 1}`}
                checked={row.presence}
                onChange={(e) => update(i, { presence: e.target.checked })}
              />{' '}
              Require passkey tap
            </label>
          </div>
          <button
            type="button"
            className="wf-btn-sm-secondary"
            onClick={() => { setRows((prev) => prev.filter((_, idx) => idx !== i)); setSaved(false) }}
          >
            Remove
          </button>
        </div>
      ))}
      <div className="wf-form-actions">
        <button
          type="button"
          className="wf-btn-secondary"
          onClick={() => { setRows((prev) => [...prev, { permission_id: '', min: '', presence: false }]); setSaved(false) }}
          data-testid="assurance-add-btn"
        >
          Add override
        </button>
        <button type="button" className="wf-btn" disabled={saving} onClick={() => void handleSave()} data-testid="assurance-save-btn">
          {saving ? 'Saving…' : 'Save assurance policy'}
        </button>
        {saved && <span className="mut" role="status" data-testid="assurance-saved">Saved</span>}
        {error && <span className="wf-form-error" role="alert" data-testid="assurance-save-error">{error}</span>}
      </div>
    </div>
  )
}

// ── Config source ─────────────────────────────────────────────────────────────

function ConfigSourceSection({ tenantId }: { tenantId: string }) {
  const [url, setUrl] = useState('')
  const [token, setToken] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<ConfigSourceCredentialResult | null>(null)
  const [testing, setTesting] = useState(false)
  const [testError, setTestError] = useState<string | null>(null)
  const [testResult, setTestResult] = useState<ConfigSourceTestResult | null>(null)

  async function handleSave() {
    if (url.trim() === '') {
      setError('Repository URL is required')
      return
    }
    if (token.length === 0) {
      setError('Token is required')
      return
    }
    if (token.length > configSourceCredentialMaxTokenLen) {
      setError(`Token must be at most ${configSourceCredentialMaxTokenLen} characters`)
      return
    }
    setSaving(true)
    setError(null)
    setResult(null)
    try {
      setResult(await putConfigSourceCredential(tenantId, url.trim(), token))
    } catch (cause: unknown) {
      setError(errorText(cause, 'Save failed'))
    } finally {
      // The token is write-only: drop it from state whether or not the save worked.
      setToken('')
      setSaving(false)
    }
  }

  async function handleTest() {
    setTesting(true)
    setTestError(null)
    setTestResult(null)
    try {
      setTestResult(await testConfigSource(tenantId))
    } catch (cause: unknown) {
      setTestError(errorText(cause, 'Connection test failed'))
    } finally {
      setTesting(false)
    }
  }

  return (
    <section aria-labelledby="config-source-heading" data-testid="config-source-section" className="wf-form-panel">
      <h3 id="config-source-heading">Config source</h3>
      <div className="wf-form">
        <p className="mut">
          The token is bound to one repository URL and can be replaced but never read back.
          Saving and testing ask for a strong session.
        </p>
        <div className="wf-form-row">
          <div className="wf-form-field">
            <span className="wf-form-label">Repository URL</span>
            <input
              type="text"
              aria-label="Repository URL"
              placeholder="https://git.example.com/org/configs.git"
              value={url}
              onChange={(e) => { setUrl(e.target.value); setResult(null) }}
              data-testid="config-source-url-input"
            />
          </div>
          <div className="wf-form-field">
            <span className="wf-form-label">Access token</span>
            <input
              type="password"
              autoComplete="off"
              aria-label="Access token"
              value={token}
              onChange={(e) => { setToken(e.target.value); setResult(null) }}
              data-testid="config-source-token-input"
            />
          </div>
        </div>
        <div className="wf-form-actions">
          <button type="button" className="wf-btn" disabled={saving} onClick={() => void handleSave()} data-testid="config-source-save-btn">
            {saving ? 'Saving…' : 'Save credential'}
          </button>
          <button type="button" className="wf-btn-secondary" disabled={testing} onClick={() => void handleTest()} data-testid="config-source-test-btn">
            {testing ? 'Testing…' : 'Test connection'}
          </button>
          {result && (
            <span className="mut" role="status" data-testid="config-source-saved">
              Saved as {result.credential_ref} for {result.bound_repository_url}
            </span>
          )}
          {error && <span className="wf-form-error" role="alert" data-testid="config-source-save-error">{error}</span>}
        </div>
        <div className="wf-form-actions">
          {testResult && (
            <span className="mut" role="status" data-testid="config-source-test-result">
              {testResult.reachable ? 'Reachable' : 'Not reachable'}
              {testResult.error ? `: ${testResult.error}` : ''}
            </span>
          )}
          {testError && <span className="wf-form-error" role="alert" data-testid="config-source-test-error">{testError}</span>}
        </div>
      </div>
    </section>
  )
}

// ── Panel ─────────────────────────────────────────────────────────────────────

export default function TenantSettingsPanel({ tenantId }: { tenantId: string }) {
  return (
    <div data-testid="tenant-settings-panel" style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
      <RefreshPolicySection tenantId={tenantId} />
      <AssurancePolicySection tenantId={tenantId} />
      <ConfigSourceSection tenantId={tenantId} />
    </div>
  )
}
