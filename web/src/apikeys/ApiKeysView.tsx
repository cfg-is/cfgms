// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * API keys page (Issue #5441, Epic #5300) — the /api-keys route.
 * Lists keys (GET /api/v1/api-keys), creates a key and shows its secret exactly
 * once (POST), and deletes a key behind a per-row inline confirm (DELETE).
 * Layout follows registration/TokensTab.tsx (list table, mint form, show-once
 * banner); the inline confirm follows tenants/SupportAccessView.tsx.
 *
 * Create and delete are Strong-only step-up actions, handled transparently by
 * the apiFetch interceptor (no presence token).
 *
 * Secret handling: the secret lives in component state only, rendered in a
 * read-only field with a copy button, and is discarded when the panel closes.
 * It is never written to storage, the URL, or a log.
 *
 * Security A9.1: all wire values render as JSX text, never as HTML.
 */
import { useEffect, useRef, useState } from 'react'
import ErrorCard from '../shell/ErrorCard.tsx'
import {
  createApiKey,
  deleteApiKey,
  splitPermissions,
  useApiKeyList,
  type ApiKeyInfo,
} from './useApiKeys.ts'

function errorText(cause: unknown, fallback: string): string {
  return cause instanceof Error && cause.message ? cause.message : fallback
}

function SecretPanel({ secret, onClose }: { secret: string; onClose: () => void }) {
  const [copied, setCopied] = useState(false)
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => {
    return () => {
      if (timer.current !== null) clearTimeout(timer.current)
    }
  }, [])

  function handleCopy() {
    navigator.clipboard
      .writeText(secret)
      .then(() => {
        setCopied(true)
        if (timer.current !== null) clearTimeout(timer.current)
        timer.current = setTimeout(() => setCopied(false), 2000)
      })
      .catch(() => {})
  }

  return (
    <section className="panel" role="status" data-testid="api-key-secret-panel">
      <h3>API key created — copy it now</h3>
      <p className="notice-warn" data-testid="api-key-secret-warning">
        This key will not be shown again. Copy it before closing.
      </p>
      <div className="secret-row">
        <input
          type="text"
          readOnly
          className="wf-input mono2 secret-value"
          aria-label="API key secret"
          value={secret}
          data-testid="api-key-secret-value"
        />
        <button
          type="button"
          className="wf-btn-sm"
          onClick={handleCopy}
          data-testid="api-key-copy-btn"
          aria-label="Copy API key to clipboard"
        >
          {copied ? 'Copied!' : 'Copy'}
        </button>
      </div>
      <button type="button" className="wf-btn-primary" onClick={onClose} data-testid="api-key-secret-close-btn">
        I have copied the key — close
      </button>
    </section>
  )
}

function CreateForm({ onCreated }: { onCreated: (secret: string) => void }) {
  const [name, setName] = useState('')
  const [permissions, setPermissions] = useState('')
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (name.trim() === '') {
      setError('Name is required')
      return
    }
    setError(null)
    setPending(true)
    try {
      const result = await createApiKey({
        name: name.trim(),
        permissions: splitPermissions(permissions),
      })
      setName('')
      setPermissions('')
      onCreated(result.key)
    } catch (cause: unknown) {
      setError(errorText(cause, 'Create request failed'))
    } finally {
      setPending(false)
    }
  }

  return (
    <form className="wf-form" onSubmit={(e) => void handleSubmit(e)} data-testid="api-key-form">
      <h3>Create API key</h3>
      <div className="wf-field">
        <label htmlFor="api-key-name">Name</label>
        <input
          id="api-key-name"
          type="text"
          className="wf-input"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="ci-deploy"
          data-testid="api-key-name"
        />
      </div>
      <div className="wf-field">
        <label htmlFor="api-key-permissions">Permissions (comma- or line-separated)</label>
        <textarea
          id="api-key-permissions"
          className="wf-input"
          value={permissions}
          onChange={(e) => setPermissions(e.target.value)}
          placeholder="steward:list, steward:read"
          data-testid="api-key-permissions"
        />
      </div>
      {error !== null && (
        <span className="wf-form-error" role="alert" data-testid="api-key-create-error">
          {error}
        </span>
      )}
      <button type="submit" className="wf-btn-primary" disabled={pending} data-testid="api-key-create-btn">
        {pending ? 'Creating…' : 'Create key'}
      </button>
    </form>
  )
}

function KeyRow({
  info,
  confirming,
  busy,
  error,
  onAskDelete,
  onKeep,
  onConfirm,
}: {
  info: ApiKeyInfo
  confirming: boolean
  busy: boolean
  error: string | null
  onAskDelete: () => void
  onKeep: () => void
  onConfirm: () => void
}) {
  return (
    <>
      <tr data-testid="api-key-row">
        <td className="mono2" data-testid="api-key-id">{info.id}</td>
        <td data-testid="api-key-name-cell">{info.name || '—'}</td>
        <td className="mono2" data-testid="api-key-scope">
          {info.permissions.length > 0 ? info.permissions.join(', ') : '—'}
        </td>
        <td className="mono2" data-testid="api-key-created">{info.created_at || '—'}</td>
        <td className="mono2" data-testid="api-key-expires">{info.expires_at ?? '—'}</td>
        <td>
          {!confirming && (
            <button
              type="button"
              className="wf-btn-sm-danger"
              onClick={onAskDelete}
              data-testid={`api-key-delete-btn-${info.id}`}
            >
              Delete
            </button>
          )}
        </td>
      </tr>
      {confirming && (
        <tr data-testid="api-key-confirm-row">
          <td colSpan={6}>
            <b>Delete this API key?</b> Anything using it stops working immediately.{' '}
            <button
              type="button"
              className="wf-btn-sm"
              disabled={busy}
              onClick={onKeep}
              data-testid="api-key-cancel-btn"
            >
              Cancel
            </button>
            <button
              type="button"
              className="wf-btn-sm-danger"
              disabled={busy}
              onClick={onConfirm}
              data-testid="api-key-confirm-btn"
            >
              {busy ? 'Deleting…' : 'Confirm'}
            </button>
            {error !== null && (
              <span className="wf-form-error" role="alert" data-testid="api-key-delete-error">
                {error}
              </span>
            )}
          </td>
        </tr>
      )}
    </>
  )
}

export default function ApiKeysView() {
  const { keys, loading, error, retry } = useApiKeyList()
  // The one-time secret: component state only, cleared on close.
  const [secret, setSecret] = useState<string | null>(null)
  const [confirming, setConfirming] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [deleteError, setDeleteError] = useState<string | null>(null)

  async function confirmDelete(id: string) {
    setBusy(true)
    setDeleteError(null)
    try {
      await deleteApiKey(id)
      setConfirming(null)
      retry()
    } catch (cause: unknown) {
      setDeleteError(errorText(cause, 'Delete failed'))
    } finally {
      setBusy(false)
    }
  }

  function handleCreated(value: string) {
    setSecret(value)
    retry()
  }

  return (
    <>
      <div className="htitle">
        <h1>API keys</h1>
        <p>Create, list and delete API keys. A key&apos;s secret is shown once, at creation.</p>
      </div>

      {secret !== null && <SecretPanel secret={secret} onClose={() => setSecret(null)} />}

      {loading ? (
        <div data-testid="api-keys-loading" aria-label="Loading API keys">
          {Array.from({ length: 3 }, (_, i) => (
            <div className="skrow" key={i}>
              <span className="skel" style={{ width: '30%' }} />
              <span className="skel" style={{ width: '40%' }} />
              <span className="skel" style={{ width: '20%' }} />
            </div>
          ))}
        </div>
      ) : error !== null ? (
        <ErrorCard heading="Couldn't load API keys" detail={error} onRetry={retry} />
      ) : keys.length === 0 ? (
        <div className="notice empty" data-testid="api-keys-empty">
          <div className="ic">◍</div>
          <h3>No API keys</h3>
          <p>Keys created for this tenant will appear here.</p>
        </div>
      ) : (
        <section className="panel">
          <table className="tbl" data-testid="api-keys-table">
            <thead>
              <tr>
                <th>Key ID</th>
                <th>Name</th>
                <th>Scope</th>
                <th>Created</th>
                <th>Expires</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {keys.map((info) => (
                <KeyRow
                  key={info.id}
                  info={info}
                  confirming={confirming === info.id}
                  busy={busy}
                  error={confirming === info.id ? deleteError : null}
                  onAskDelete={() => {
                    setDeleteError(null)
                    setConfirming(info.id)
                  }}
                  onKeep={() => setConfirming(null)}
                  onConfirm={() => void confirmDelete(info.id)}
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
