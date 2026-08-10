// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Accounts view (Issue #2733, #2974) — the /accounts route entry point.
 * Fetches GET /api/v1/web/accounts, renders a table, and exposes
 * account create and delete. Roles are surfaced read-only in a tab.
 *
 * Issue #2974: "+ New account" is step-up gated (AssuranceStrong) via the
 * apiFetch interceptor — the StepUpModal appears automatically on 401 CFGMS-StepUp.
 * On successful create, a single-use enrollment magic link is shown once
 * (copy-to-clipboard) for out-of-band handoff. No password is ever set.
 * Admins can revoke an outstanding unredeemed link before it is used.
 *
 * Security A9.1: username values originate from user-supplied content.
 * Every value reaches the DOM as a JSX text node — never dangerouslySetInnerHTML.
 * Passwords are never sent, stored, or echoed (passkey-only, ADR-021 Amendment 1).
 *
 * Delete requires a confirm step (modal) per implementation notes.
 */
import { useState } from 'react'
import { apiFetch } from '../api/client.ts'
import {
  useWebAccountList,
  createWebAccount,
  revokeEnrollmentLink,
  type WebAccountInfo,
} from './useWebAccounts.ts'
import RolesView from './RolesView.tsx'

function LoadingRows() {
  return (
    <div data-testid="accounts-loading" aria-label="Loading accounts">
      {Array.from({ length: 3 }, (_, i) => (
        <div className="skrow" key={i}>
          <span className="skel" style={{ width: '40%' }} />
          <span className="skel" style={{ width: '30%' }} />
          <span className="skel" style={{ width: '50%' }} />
          <span className="skel" style={{ width: '20%' }} />
        </div>
      ))}
    </div>
  )
}

function ErrorNotice({ detail, onRetry }: { detail: string; onRetry: () => void }) {
  return (
    <div className="notice err" role="alert">
      <div className="ic">!</div>
      <h3>Couldn&apos;t load accounts</h3>
      <p>The account list request failed. Check your connection and try again.</p>
      <span className="mono2 detail">{detail}</span>
      <button type="button" className="btn" onClick={onRetry}>
        Retry
      </button>
    </div>
  )
}

function AccountEmpty() {
  return (
    <div className="notice empty" data-testid="accounts-empty">
      <div className="ic">◍</div>
      <h3>No accounts found</h3>
      <p>No web admin accounts have been created yet. Use New account to get started.</p>
    </div>
  )
}

/**
 * EnrollmentLinkPanel is shown exactly once after a successful account creation
 * (Issue #2974). It displays the raw enrollment magic link for copy-to-clipboard
 * and an email delivery toggle (disabled until a notification provider is built).
 */
function EnrollmentLinkPanel({
  username,
  rawToken,
  onDismiss,
}: {
  username: string
  rawToken: string
  onDismiss: () => void
}) {
  const [copied, setCopied] = useState(false)
  const enrollLink = `${window.location.origin}/enroll?token=${rawToken}`

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(enrollLink)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      // Clipboard API may not be available in all environments.
    }
  }

  return (
    <div
      className="wf-form-panel"
      data-testid="enrollment-link-panel"
      role="region"
      aria-label="Enrollment link"
    >
      <div className="wf-form">
        <div className="wf-form-row">
          <div className="wf-form-field" style={{ flexGrow: 1 }}>
            <span className="wf-form-label">
              Account <b>{username}</b> created — share this enrollment link
            </span>
            <p style={{ margin: '4px 0 8px', fontSize: '0.875rem', color: 'var(--color-muted)' }}>
              This link is shown <b>once</b>. Copy it and send it to the new admin out-of-band.
              It expires in 72 hours and can be revoked if compromised.
            </p>
            <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
              <input
                type="text"
                readOnly
                value={enrollLink}
                aria-label="Enrollment link"
                data-testid="enrollment-link-value"
                style={{ flexGrow: 1 }}
                onFocus={(e) => e.target.select()}
              />
              <button
                type="button"
                className="wf-btn"
                onClick={() => void handleCopy()}
                data-testid="enrollment-link-copy-btn"
              >
                {copied ? 'Copied!' : 'Copy'}
              </button>
            </div>
          </div>
        </div>
        <div className="wf-form-row">
          <div className="wf-form-field">
            <label style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'not-allowed' }}>
              <input
                type="checkbox"
                disabled
                aria-label="Send via email (not yet available)"
                data-testid="enrollment-email-toggle"
              />
              <span style={{ color: 'var(--color-muted)' }}>
                Send via email
              </span>
              <span
                className="mono2"
                style={{ fontSize: '0.75rem' }}
                title="Email delivery is not yet available — a notification provider is required."
              >
                (coming soon)
              </span>
            </label>
          </div>
        </div>
        <div className="wf-form-actions">
          <button
            type="button"
            className="wf-btn-secondary"
            onClick={onDismiss}
            data-testid="enrollment-link-dismiss-btn"
          >
            Done
          </button>
        </div>
      </div>
    </div>
  )
}

function AccountRow({
  account,
  onDelete,
  onRevoke,
}: {
  account: WebAccountInfo
  onDelete: () => void
  onRevoke: () => void
}) {
  return (
    <tr data-testid="account-row">
      <td>
        <span className="nm">{account.username}</span>
      </td>
      <td>
        <span className="mono2">{account.tenant_id || '—'}</span>
      </td>
      <td>
        <span className="mono2">{account.permissions.length > 0 ? account.permissions.join(', ') : '—'}</span>
      </td>
      <td>
        <span className="mono2">{account.created_at ? new Date(account.created_at).toLocaleDateString() : '—'}</span>
      </td>
      <td onClick={(e) => e.stopPropagation()}>
        {account.has_outstanding_enrollment_link && (
          <button
            type="button"
            className="wf-btn-sm-secondary"
            onClick={onRevoke}
            data-testid="enrollment-revoke-btn"
            title="Revoke the outstanding enrollment link for this account"
          >
            Revoke link
          </button>
        )}{' '}
        <button
          type="button"
          className="wf-btn-sm-danger"
          onClick={onDelete}
          data-testid="account-delete-btn"
        >
          Delete
        </button>
      </td>
    </tr>
  )
}

interface CreateFormState {
  username: string
  tenantId: string
  permissions: string
}

function defaultCreateForm(): CreateFormState {
  return { username: '', tenantId: '', permissions: '' }
}

function CreateAccountPanel({
  onSaved,
  onClose,
}: {
  onSaved: (username: string, enrollmentLink: string) => void
  onClose: () => void
}) {
  const [form, setForm] = useState<CreateFormState>(defaultCreateForm)
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState<string | null>(null)

  function set<K extends keyof CreateFormState>(key: K, value: CreateFormState[K]) {
    setForm((prev) => ({ ...prev, [key]: value }))
  }

  async function handleSubmit() {
    if (!form.username.trim()) {
      setSaveError('Username is required')
      return
    }

    const permissions = form.permissions
      .split(',')
      .map((p) => p.trim())
      .filter(Boolean)

    setSaving(true)
    setSaveError(null)
    try {
      const result = await createWebAccount(
        form.username.trim(),
        form.tenantId.trim() || undefined,
        permissions.length > 0 ? permissions : undefined,
      )
      onSaved(result.account.username, result.enrollment_magic_link)
    } catch (cause: unknown) {
      setSaveError(
        cause instanceof Error && cause.message ? cause.message : 'Create failed',
      )
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="wf-form-panel" data-testid="account-form-panel">
      <div className="wf-form">
        <div className="wf-form-row">
          <div className="wf-form-field">
            <span className="wf-form-label">Username *</span>
            <input
              type="text"
              aria-label="Username"
              placeholder="fleet-admin"
              value={form.username}
              onChange={(e) => set('username', e.target.value)}
              data-testid="account-username-input"
            />
          </div>
          <div className="wf-form-field">
            <span className="wf-form-label">Tenant ID</span>
            <input
              type="text"
              aria-label="Tenant ID"
              placeholder="default"
              value={form.tenantId}
              onChange={(e) => set('tenantId', e.target.value)}
            />
          </div>
        </div>
        <div className="wf-form-row">
          <div className="wf-form-field">
            <span className="wf-form-label">Permissions (comma-separated)</span>
            <input
              type="text"
              aria-label="Permissions"
              placeholder="steward:list, steward:read"
              value={form.permissions}
              onChange={(e) => set('permissions', e.target.value)}
              className="wide"
              data-testid="account-permissions-input"
            />
          </div>
        </div>
        <div className="wf-form-actions">
          <button
            type="button"
            className="wf-btn"
            disabled={saving}
            onClick={() => void handleSubmit()}
            data-testid="account-save-btn"
          >
            {saving ? 'Creating…' : 'Create account'}
          </button>
          <button type="button" className="wf-btn-secondary" onClick={onClose}>
            Cancel
          </button>
          {saveError && (
            <span className="wf-form-error" data-testid="account-save-error">
              {saveError}
            </span>
          )}
        </div>
      </div>
    </div>
  )
}

export default function AccountsView() {
  const { accounts, loading, error, retry } = useWebAccountList()
  const [tab, setTab] = useState<'accounts' | 'roles'>('accounts')
  const [showCreate, setShowCreate] = useState(false)
  const [deletingAccount, setDeletingAccount] = useState<WebAccountInfo | null>(null)
  const [deleteError, setDeleteError] = useState<string | null>(null)
  const [deleting, setDeleting] = useState(false)
  // Issue #2974: enrollment link shown once after create.
  const [enrollmentLink, setEnrollmentLink] = useState<{ username: string; token: string } | null>(null)
  const [revokeError, setRevokeError] = useState<string | null>(null)

  function handleCreateSaved(username: string, token: string) {
    setShowCreate(false)
    // The controller mints no enrollment link when the target account already
    // holds a passkey (ADR-021 Amendment 1 Decision 3), so the response may carry
    // no token. Only show the shown-once panel when a link was actually issued.
    setEnrollmentLink(token ? { username, token } : null)
    retry()
  }

  function handleEnrollmentLinkDismiss() {
    setEnrollmentLink(null)
  }

  async function handleConfirmDelete() {
    if (!deletingAccount) return
    const username = deletingAccount.username
    setDeleting(true)
    setDeleteError(null)
    setDeletingAccount(null)
    try {
      const response = await apiFetch(
        `/api/v1/web/accounts/${encodeURIComponent(username)}`,
        { method: 'DELETE' },
      )
      if (!response.ok) {
        const errBody = (await response.json().catch(() => ({}))) as Record<string, unknown>
        const errMsg =
          (errBody?.error as Record<string, unknown>)?.message as string ||
          `Delete failed — ${response.status}`
        throw new Error(errMsg)
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

  async function handleRevokeLink(username: string) {
    setRevokeError(null)
    try {
      await revokeEnrollmentLink(username)
      retry()
    } catch (cause: unknown) {
      setRevokeError(
        cause instanceof Error && cause.message ? cause.message : 'Revoke failed',
      )
    }
  }

  return (
    <>
      <div className="htitle">
        <h1>Accounts</h1>
        <p>Manage web admin accounts and view roles and their permissions.</p>
      </div>

      <div className="wf-tabs" role="tablist">
        <button
          type="button"
          role="tab"
          aria-selected={tab === 'accounts'}
          className={tab === 'accounts' ? 'wf-tab active' : 'wf-tab'}
          onClick={() => setTab('accounts')}
          data-testid="tab-accounts"
        >
          Accounts
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={tab === 'roles'}
          className={tab === 'roles' ? 'wf-tab active' : 'wf-tab'}
          onClick={() => setTab('roles')}
          data-testid="tab-roles"
        >
          Roles
        </button>
      </div>

      {tab === 'accounts' && (
        <section className="panel">
          <div className="ptool">
            <button
              type="button"
              className={showCreate ? 'wf-btn' : 'wf-btn-secondary'}
              onClick={() => setShowCreate((v) => !v)}
              data-testid="toggle-create-btn"
            >
              {showCreate ? 'Close' : '+ New account'}
            </button>
            {!loading && error === null && (
              <span className="cnt" data-testid="account-count">
                {accounts.length} account{accounts.length !== 1 ? 's' : ''}
              </span>
            )}
          </div>

          {showCreate && (
            <CreateAccountPanel
              onSaved={handleCreateSaved}
              onClose={() => setShowCreate(false)}
            />
          )}

          {enrollmentLink !== null && (
            <EnrollmentLinkPanel
              username={enrollmentLink.username}
              rawToken={enrollmentLink.token}
              onDismiss={handleEnrollmentLinkDismiss}
            />
          )}

          {deleteError && (
            <div className="wf-form-error" style={{ padding: '8px 14px' }} data-testid="delete-error">
              {deleteError}
            </div>
          )}

          {revokeError && (
            <div className="wf-form-error" style={{ padding: '8px 14px' }} data-testid="revoke-error">
              {revokeError}
            </div>
          )}

          {loading ? (
            <LoadingRows />
          ) : error !== null ? (
            <ErrorNotice detail={error} onRetry={retry} />
          ) : accounts.length === 0 ? (
            <AccountEmpty />
          ) : (
            <table className="tbl" data-testid="accounts-table">
              <thead>
                <tr>
                  <th>Username</th>
                  <th>Tenant</th>
                  <th>Permissions</th>
                  <th>Created</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {accounts.map((account) => (
                  <AccountRow
                    key={account.id}
                    account={account}
                    onDelete={() => {
                      setDeleteError(null)
                      setDeletingAccount(account)
                    }}
                    onRevoke={() => void handleRevokeLink(account.username)}
                  />
                ))}
              </tbody>
            </table>
          )}
        </section>
      )}

      {tab === 'roles' && <RolesView />}

      {deletingAccount !== null && (
        <div
          className="wf-overlay"
          role="dialog"
          aria-modal="true"
          aria-labelledby="delete-account-title"
        >
          <div className="wf-modal">
            <h3 id="delete-account-title">Delete account?</h3>
            <p>
              This will permanently delete the account for{' '}
              <b>{deletingAccount.username}</b>.
            </p>
            <p>This action cannot be undone.</p>
            <div className="wf-modal-actions">
              <button
                type="button"
                className="wf-btn-secondary"
                disabled={deleting}
                onClick={() => setDeletingAccount(null)}
              >
                Cancel
              </button>
              <button
                type="button"
                className="wf-btn-danger"
                disabled={deleting}
                onClick={() => void handleConfirmDelete()}
                data-testid="delete-confirm-btn"
              >
                {deleting ? 'Deleting…' : 'Delete account'}
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  )
}
