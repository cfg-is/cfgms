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
import {
  deleteM365Connection,
  getM365Connection,
  linkGdapCustomers,
  listGdapCustomers,
  putM365Connection,
  type GdapCustomer,
  type M365Connection,
} from './useTenantM365.ts'
import { PolicyApiError } from './useTenantPolicies.ts'

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

// ── M365 connection ───────────────────────────────────────────────────────────

function isConflict(cause: unknown): boolean {
  return cause instanceof PolicyApiError && cause.status === 409
}

function M365Section({ tenantId }: { tenantId: string }) {
  const loaded = useLoaded(() => getM365Connection(tenantId), tenantId)
  return (
    <section aria-labelledby="m365-heading" data-testid="m365-section" className="wf-form-panel">
      <h3 id="m365-heading">M365 connection</h3>
      {loaded.kind === 'loading' && <span className="mut" data-testid="m365-loading">Loading M365 connection…</span>}
      {loaded.kind === 'error' && (
        <div className="wf-form-actions">
          <span className="wf-form-error" role="alert" data-testid="m365-load-error">{loaded.message}</span>
          <button type="button" className="wf-btn-secondary" onClick={loaded.reload}>Retry</button>
        </div>
      )}
      {loaded.kind === 'ready' && (
        <M365DirectForm tenantId={tenantId} connection={loaded.value} onChanged={loaded.reload} />
      )}
      {/* Outside the load gate so a reload after linking keeps the result message. */}
      <GdapDiscovery tenantId={tenantId} onLinked={loaded.reload} />
    </section>
  )
}

function M365DirectForm({
  tenantId,
  connection,
  onChanged,
}: {
  tenantId: string
  connection: M365Connection | null
  onChanged: () => void
}) {
  const [appId, setAppId] = useState('')
  const [m365Tenant, setM365Tenant] = useState('')
  const [secret, setSecret] = useState('')
  const [replace, setReplace] = useState(false)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [confirming, setConfirming] = useState(false)
  const [clearing, setClearing] = useState(false)
  const [clearError, setClearError] = useState<string | null>(null)

  async function handleSave() {
    if (appId.trim() === '' || m365Tenant.trim() === '') {
      setError('App ID and M365 tenant ID are required')
      return
    }
    if (secret.length === 0) {
      setError('Client secret is required')
      return
    }
    setSaving(true)
    setError(null)
    try {
      await putM365Connection(tenantId, {
        app_id: appId.trim(),
        m365_tenant_id: m365Tenant.trim(),
        client_secret: secret,
        replace,
      })
      setAppId('')
      setM365Tenant('')
      setReplace(false)
      onChanged()
    } catch (cause: unknown) {
      if (isConflict(cause)) {
        setReplace(true)
        setError('A connection already exists. Enter the client secret again and choose Replace to overwrite it.')
      } else {
        setError(errorText(cause, 'Save failed'))
      }
    } finally {
      // The secret is write-only: drop it from state whether or not the save worked.
      setSecret('')
      setSaving(false)
    }
  }

  async function handleClear() {
    setClearing(true)
    setClearError(null)
    try {
      await deleteM365Connection(tenantId)
      setConfirming(false)
      onChanged()
    } catch (cause: unknown) {
      setClearError(errorText(cause, 'Clear failed'))
    } finally {
      setClearing(false)
    }
  }

  return (
    <div className="wf-form">
      <p className="mut">
        Connects this client tenant to Microsoft 365. The client secret can be replaced but never read back.
        Changes ask for a strong session.
      </p>
      {connection ? (
        <div className="wf-form-actions" data-testid="m365-current">
          <span>
            <b>{connection.mode}</b> · app <span data-testid="m365-current-app">{connection.app_id}</span> · M365 tenant{' '}
            <span data-testid="m365-current-tenant">{connection.m365_tenant_id}</span>
            {connection.partner_tenant_id ? <> · partner {connection.partner_tenant_id}</> : null}
            {connection.gdap_roles && connection.gdap_roles.length > 0 ? <> · roles {connection.gdap_roles.join(', ')}</> : null}
          </span>
          <span className="mut" data-testid="m365-secret-badge">
            {connection.has_client_secret ? 'Client secret set' : 'No client secret'}
          </span>
          {!confirming && (
            <button type="button" className="wf-btn-sm-secondary" onClick={() => setConfirming(true)} data-testid="m365-clear-btn">
              Clear
            </button>
          )}
          {confirming && (
            <span role="group" aria-label="Confirm clear" data-testid="m365-clear-confirm">
              <b>Clear this M365 connection?</b>{' '}
              <button type="button" className="wf-btn-sm-secondary" disabled={clearing} onClick={() => { setConfirming(false); setClearError(null) }} data-testid="m365-clear-cancel-btn">
                Cancel
              </button>{' '}
              <button type="button" className="wf-btn-sm-danger" disabled={clearing} onClick={() => void handleClear()} data-testid="m365-clear-confirm-btn">
                {clearing ? 'Clearing…' : 'Confirm'}
              </button>
            </span>
          )}
          {clearError && <span className="wf-form-error" role="alert" data-testid="m365-clear-error">{clearError}</span>}
        </div>
      ) : (
        <span className="mut" data-testid="m365-none">No M365 connection</span>
      )}
      <div className="wf-form-row">
        <div className="wf-form-field">
          <span className="wf-form-label">App ID</span>
          <input type="text" aria-label="M365 app ID" value={appId} onChange={(e) => setAppId(e.target.value)} data-testid="m365-app-id-input" />
        </div>
        <div className="wf-form-field">
          <span className="wf-form-label">M365 tenant ID</span>
          <input type="text" aria-label="M365 tenant ID" value={m365Tenant} onChange={(e) => setM365Tenant(e.target.value)} data-testid="m365-tenant-id-input" />
        </div>
        <div className="wf-form-field">
          <span className="wf-form-label">Client secret</span>
          <input
            type="password"
            autoComplete="off"
            aria-label="M365 client secret"
            value={secret}
            onChange={(e) => setSecret(e.target.value)}
            data-testid="m365-secret-input"
          />
        </div>
      </div>
      <div className="wf-form-actions">
        <button type="button" className="wf-btn" disabled={saving} onClick={() => void handleSave()} data-testid="m365-save-btn">
          {saving ? 'Saving…' : replace ? 'Replace connection' : 'Save connection'}
        </button>
        {error && <span className="wf-form-error" role="alert" data-testid="m365-save-error">{error}</span>}
      </div>
    </div>
  )
}

function GdapDiscovery({ tenantId, onLinked }: { tenantId: string; onLinked: () => void }) {
  const [partner, setPartner] = useState('')
  const [appId, setAppId] = useState('')
  const [secret, setSecret] = useState('')
  const [roles, setRoles] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [customers, setCustomers] = useState<GdapCustomer[] | null>(null)
  const [targets, setTargets] = useState<Record<string, string>>({})
  const [replace, setReplace] = useState(false)
  const [linked, setLinked] = useState<number | null>(null)

  function partnerInput() {
    return { partner_tenant_id: partner.trim(), app_id: appId.trim(), client_secret: secret }
  }

  function validate(): string | null {
    if (partner.trim() === '' || appId.trim() === '') return 'Partner tenant ID and app ID are required'
    if (secret.length === 0) return 'Client secret is required'
    return null
  }

  async function handleDiscover() {
    const problem = validate()
    if (problem) {
      setError(problem)
      return
    }
    setBusy(true)
    setError(null)
    setLinked(null)
    try {
      setCustomers(await listGdapCustomers(tenantId, partnerInput()))
      setTargets({})
      setReplace(false)
    } catch (cause: unknown) {
      setError(errorText(cause, 'Could not list GDAP customers'))
    } finally {
      setSecret('')
      setBusy(false)
    }
  }

  async function handleLink() {
    const problem = validate()
    if (problem) {
      setError(problem)
      return
    }
    const links = Object.entries(targets)
      .filter(([, t]) => t.trim() !== '')
      .map(([customer, t]) => ({ customer_tenant_id: customer, tenant_id: t.trim() }))
    if (links.length === 0) {
      setError('Choose a client tenant for at least one customer')
      return
    }
    setBusy(true)
    setError(null)
    setLinked(null)
    try {
      const done = await linkGdapCustomers(tenantId, {
        ...partnerInput(),
        links,
        gdap_roles: roles.split(',').map((r) => r.trim()).filter((r) => r !== ''),
        replace,
      })
      setLinked(done.length)
      setCustomers(null)
      setTargets({})
      setReplace(false)
      onLinked()
    } catch (cause: unknown) {
      if (isConflict(cause)) {
        setReplace(true)
        setError(`${errorText(cause, 'Conflict')} Enter the client secret again and choose Replace to overwrite existing connections.`)
      } else {
        setError(errorText(cause, 'Could not link GDAP customers'))
      }
    } finally {
      setSecret('')
      setBusy(false)
    }
  }

  return (
    <div className="wf-form" data-testid="gdap-discovery">
      <h4>GDAP customers</h4>
      <p className="mut">
        Run on an MSP tenant: discover its active GDAP customers, then link each to an existing client tenant.
        The secret is cleared after every request.
      </p>
      <div className="wf-form-row">
        <div className="wf-form-field">
          <span className="wf-form-label">Partner tenant ID</span>
          <input type="text" aria-label="Partner tenant ID" value={partner} onChange={(e) => setPartner(e.target.value)} data-testid="gdap-partner-input" />
        </div>
        <div className="wf-form-field">
          <span className="wf-form-label">App ID</span>
          <input type="text" aria-label="Partner app ID" value={appId} onChange={(e) => setAppId(e.target.value)} data-testid="gdap-app-id-input" />
        </div>
        <div className="wf-form-field">
          <span className="wf-form-label">Client secret</span>
          <input
            type="password"
            autoComplete="off"
            aria-label="Partner client secret"
            value={secret}
            onChange={(e) => setSecret(e.target.value)}
            data-testid="gdap-secret-input"
          />
        </div>
      </div>
      <div className="wf-form-actions">
        <button type="button" className="wf-btn-secondary" disabled={busy} onClick={() => void handleDiscover()} data-testid="gdap-discover-btn">
          {busy && customers === null ? 'Working…' : 'Discover customers'}
        </button>
        {linked !== null && <span className="mut" role="status" data-testid="gdap-linked">Linked {linked} customer{linked === 1 ? '' : 's'}</span>}
        {error && <span className="wf-form-error" role="alert" data-testid="gdap-error">{error}</span>}
      </div>
      {customers !== null && customers.length === 0 && <span className="mut" data-testid="gdap-empty">No active GDAP customers</span>}
      {customers !== null && customers.length > 0 && (
        <>
          {customers.map((c) => (
            <div className="wf-form-row" key={c.customer_tenant_id} data-testid="gdap-customer-row">
              <div className="wf-form-field">
                <span className="wf-form-label">{c.name}</span>
                <span className="mut">
                  {c.customer_tenant_id} · {c.status} · expires {c.expires_at}
                  {c.roles.length > 0 ? ` · ${c.roles.join(', ')}` : ''}
                  {c.link_state === 'linked' ? ` · linked to ${c.linked_to ?? 'a client tenant'}` : ''}
                </span>
              </div>
              <div className="wf-form-field">
                <span className="wf-form-label">Client tenant</span>
                <input
                  type="text"
                  aria-label={`Client tenant for ${c.customer_tenant_id}`}
                  placeholder="root/msp-a/client-1"
                  value={targets[c.customer_tenant_id] ?? ''}
                  onChange={(e) => setTargets((prev) => ({ ...prev, [c.customer_tenant_id]: e.target.value }))}
                />
              </div>
            </div>
          ))}
          <div className="wf-form-row">
            <div className="wf-form-field">
              <span className="wf-form-label">GDAP roles (comma separated, optional)</span>
              <input type="text" aria-label="GDAP roles" value={roles} onChange={(e) => setRoles(e.target.value)} data-testid="gdap-roles-input" />
            </div>
          </div>
          <div className="wf-form-actions">
            <button type="button" className="wf-btn" disabled={busy} onClick={() => void handleLink()} data-testid="gdap-link-btn">
              {replace ? 'Replace links' : 'Link customers'}
            </button>
          </div>
        </>
      )}
    </div>
  )
}

// ── Panel ─────────────────────────────────────────────────────────────────────

export default function TenantSettingsPanel({ tenantId }: { tenantId: string }) {
  return (
    <div data-testid="tenant-settings-panel" style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
      <RefreshPolicySection tenantId={tenantId} />
      <AssurancePolicySection tenantId={tenantId} />
      <ConfigSourceSection tenantId={tenantId} />
      <M365Section tenantId={tenantId} />
    </div>
  )
}
