// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Automation grants page (Issue #5855, Epic #5421) — the /automation/grants route.
 * Lists grants (GET /api/v1/automation/grants) with a status derived from the server
 * fields, creates a grant and shows its credential exactly once (POST), and revokes a
 * grant behind a per-row inline confirm (DELETE). Layout mirrors
 * apikeys/ApiKeysView.tsx (list table, create form, show-once panel).
 *
 * Create takes a Strong step-up and a presence tap; revoke a Strong step-up only. Both
 * are handled transparently by the apiFetch interceptor and StepUpModal, so this view
 * never sees or sends a presence token.
 *
 * Credential handling: the credential lives in this view's state only, rendered in a
 * read-only field with a copy button, and is discarded (state set to null, panel
 * unmounted) when the panel closes. It is never written to storage, the URL, or a log.
 *
 * Security A9.1: all wire values render as JSX text, never as HTML.
 */
import { useEffect, useRef, useState } from 'react'
import { useAuth } from '../auth/AuthContext.tsx'
import ErrorCard from '../shell/ErrorCard.tsx'
import {
  createAutomationGrant,
  expiryFromDate,
  grantStatus,
  latestExpiryDate,
  maxGrantLifetimeDays,
  revokeAutomationGrant,
  useAutomationGrantList,
  type AutomationGrant,
} from './useAutomationGrants.ts'

function errorText(cause: unknown, fallback: string): string {
  return cause instanceof Error && cause.message ? cause.message : fallback
}

function CredentialPanel({ credential, onClose }: { credential: string; onClose: () => void }) {
  const [copied, setCopied] = useState(false)
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => {
    return () => {
      if (timer.current !== null) clearTimeout(timer.current)
    }
  }, [])

  function handleCopy() {
    navigator.clipboard
      .writeText(credential)
      .then(() => {
        setCopied(true)
        if (timer.current !== null) clearTimeout(timer.current)
        timer.current = setTimeout(() => setCopied(false), 2000)
      })
      .catch(() => {})
  }

  return (
    <section className="panel" role="status" data-testid="grant-credential-panel">
      <h3>Automation grant created — copy the credential now</h3>
      <p className="notice-warn" data-testid="grant-credential-warning">
        This credential will not be shown again. Copy it before closing.
      </p>
      <div className="secret-row">
        <input
          type="text"
          readOnly
          className="wf-input mono2 secret-value"
          aria-label="Automation grant credential"
          value={credential}
          data-testid="grant-credential-value"
        />
        <button
          type="button"
          className="wf-btn-sm"
          onClick={handleCopy}
          data-testid="grant-copy-btn"
          aria-label="Copy credential to clipboard"
        >
          {copied ? 'Copied!' : 'Copy'}
        </button>
      </div>
      <button type="button" className="wf-btn-primary" onClick={onClose} data-testid="grant-credential-close-btn">
        I have copied the credential — close
      </button>
    </section>
  )
}

function CreateForm({ onCreated }: { onCreated: (credential: string) => void }) {
  const { principal } = useAuth()
  const callerTenant = principal?.tenantId ?? ''
  const [name, setName] = useState('')
  // Blank means the caller's own tenant; the field shows it as the default.
  const [tenant, setTenant] = useState<string | null>(null)
  const [expiry, setExpiry] = useState('')
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const tenantValue = tenant ?? callerTenant

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (name.trim() === '') {
      setError('Name is required')
      return
    }
    const expiresAt = expiryFromDate(expiry)
    if (expiresAt === '') {
      setError('Expiry date is required')
      return
    }
    setError(null)
    setPending(true)
    try {
      const result = await createAutomationGrant({
        name: name.trim(),
        tenantId: tenantValue.trim(),
        expiresAt,
      })
      setName('')
      setTenant(null)
      setExpiry('')
      onCreated(result.credential)
    } catch (cause: unknown) {
      setError(errorText(cause, 'Create request failed'))
    } finally {
      setPending(false)
    }
  }

  return (
    <form className="wf-form" onSubmit={(e) => void handleSubmit(e)} data-testid="grant-form">
      <h3>Create automation grant</h3>
      <div className="wf-field">
        <label htmlFor="grant-name">Name</label>
        <input
          id="grant-name"
          type="text"
          className="wf-input"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="nightly-patching"
          data-testid="grant-name"
        />
      </div>
      <div className="wf-field">
        <label htmlFor="grant-tenant">Tenant</label>
        <input
          id="grant-tenant"
          type="text"
          className="wf-input mono2"
          value={tenantValue}
          onChange={(e) => setTenant(e.target.value)}
          placeholder="Your tenant"
          data-testid="grant-tenant"
        />
      </div>
      <div className="wf-field">
        <label htmlFor="grant-expiry">Expires (00:00 UTC on this date)</label>
        <input
          id="grant-expiry"
          type="date"
          className="wf-input"
          value={expiry}
          max={latestExpiryDate()}
          onChange={(e) => setExpiry(e.target.value)}
          data-testid="grant-expiry"
        />
        <span data-testid="grant-expiry-cap">
          The controller allows at most {maxGrantLifetimeDays} days from now.
        </span>
      </div>
      {error !== null && (
        <span className="wf-form-error" role="alert" data-testid="grant-create-error">
          {error}
        </span>
      )}
      <button type="submit" className="wf-btn-primary" disabled={pending} data-testid="grant-create-btn">
        {pending ? 'Creating…' : 'Create grant'}
      </button>
    </form>
  )
}

function GrantRow({
  grant,
  confirming,
  busy,
  error,
  onAskRevoke,
  onKeep,
  onConfirm,
}: {
  grant: AutomationGrant
  confirming: boolean
  busy: boolean
  error: string | null
  onAskRevoke: () => void
  onKeep: () => void
  onConfirm: () => void
}) {
  const status = grantStatus(grant)
  return (
    <>
      <tr data-testid="grant-row">
        <td className="mono2" data-testid="grant-id">{grant.id}</td>
        <td data-testid="grant-name-cell">{grant.name || '—'}</td>
        <td className="mono2" data-testid="grant-tenant-cell">{grant.tenant_id || '—'}</td>
        <td className="mono2" data-testid="grant-created">{grant.created_at || '—'}</td>
        <td className="mono2" data-testid="grant-expires">{grant.expires_at || '—'}</td>
        <td data-testid="grant-status">{status}</td>
        <td>
          {status !== 'revoked' && !confirming && (
            <button
              type="button"
              className="wf-btn-sm-danger"
              onClick={onAskRevoke}
              data-testid={`grant-revoke-btn-${grant.id}`}
            >
              Revoke
            </button>
          )}
        </td>
      </tr>
      {confirming && (
        <tr data-testid="grant-confirm-row">
          <td colSpan={7}>
            <b>Revoke this grant?</b> Anything using its credential stops working immediately.{' '}
            <button
              type="button"
              className="wf-btn-sm"
              disabled={busy}
              onClick={onKeep}
              data-testid="grant-cancel-btn"
            >
              Cancel
            </button>
            <button
              type="button"
              className="wf-btn-sm-danger"
              disabled={busy}
              onClick={onConfirm}
              data-testid="grant-confirm-btn"
            >
              {busy ? 'Revoking…' : 'Confirm'}
            </button>
            {error !== null && (
              <span className="wf-form-error" role="alert" data-testid="grant-revoke-error">
                {error}
              </span>
            )}
          </td>
        </tr>
      )}
    </>
  )
}

export default function AutomationGrantsView() {
  const { grants, loading, error, retry } = useAutomationGrantList()
  // The one-time credential: component state only, cleared on close.
  const [credential, setCredential] = useState<string | null>(null)
  const [confirming, setConfirming] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [revokeError, setRevokeError] = useState<string | null>(null)

  async function confirmRevoke(id: string) {
    setBusy(true)
    setRevokeError(null)
    try {
      await revokeAutomationGrant(id)
      setConfirming(null)
      retry()
    } catch (cause: unknown) {
      setRevokeError(errorText(cause, 'Revoke failed'))
    } finally {
      setBusy(false)
    }
  }

  function handleCreated(value: string) {
    setCredential(value)
    retry()
  }

  return (
    <>
      <div className="htitle">
        <h1>Automation grants</h1>
        <p>
          Create, list and revoke automation grants. A grant&apos;s credential is shown once, at creation.
        </p>
      </div>

      {credential !== null && <CredentialPanel credential={credential} onClose={() => setCredential(null)} />}

      {loading ? (
        <div data-testid="grants-loading" aria-label="Loading automation grants">
          {Array.from({ length: 3 }, (_, i) => (
            <div className="skrow" key={i}>
              <span className="skel" style={{ width: '30%' }} />
              <span className="skel" style={{ width: '40%' }} />
              <span className="skel" style={{ width: '20%' }} />
            </div>
          ))}
        </div>
      ) : error !== null ? (
        <ErrorCard heading="Couldn't load automation grants" detail={error} onRetry={retry} />
      ) : grants.length === 0 ? (
        <div className="notice empty" data-testid="grants-empty">
          <div className="ic">◍</div>
          <h3>No automation grants</h3>
          <p>Grants created for this tenant will appear here.</p>
        </div>
      ) : (
        <section className="panel">
          <table className="tbl" data-testid="grants-table">
            <thead>
              <tr>
                <th>Grant ID</th>
                <th>Name</th>
                <th>Tenant</th>
                <th>Created</th>
                <th>Expires</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {grants.map((grant) => (
                <GrantRow
                  key={grant.id}
                  grant={grant}
                  confirming={confirming === grant.id}
                  busy={busy}
                  error={confirming === grant.id ? revokeError : null}
                  onAskRevoke={() => {
                    setRevokeError(null)
                    setConfirming(grant.id)
                  }}
                  onKeep={() => setConfirming(null)}
                  onConfirm={() => void confirmRevoke(grant.id)}
                />
              ))}
            </tbody>
          </table>
        </section>
      )}

      <section className="panel">
        <CreateForm onCreated={handleCreated} />
      </section>
    </>
  )
}
