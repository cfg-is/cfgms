// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Registration token list tab (Story #2935, #2970) — read + write operations.
 * Fetches GET /api/v1/registration/tokens — {tokens:[...], total:N} shape
 * per handlers_registration_tokens.go (no {data:...} envelope).
 * Shape-validated by parseTokenList before any value reaches the DOM.
 *
 * Renders: token_prefix, tenant_id, group, created_at, expires_at, revoked.
 * expires_at / revoked_at are optional (Go omitempty on pointer types) —
 * renders '—' when absent, matching the columns.ts em-dash convention.
 *
 * Write operations (Story #2970): all four actions are behind AssuranceStrong
 * (CFGMS-StepUp) — handled transparently by apiFetch → AuthProvider → StepUpModal.
 *   Mint:   POST /api/v1/registration/tokens
 *   Rotate: POST /api/v1/registration/tokens/{tenant_id}/rotate
 *   Revoke: POST /api/v1/registration/tokens/{token_id}/revoke
 *   Delete: DELETE /api/v1/registration/tokens/{token_id}
 *
 * Secret-once guarantee (AC Story #2970): mint and rotate return the full token
 * in the response. SecretOnceModal renders it once and discards it — the value
 * is never stored in a ref, localStorage, or any other durable location.
 * The modal is dismissed by clearing state; the secret is gone after that point.
 *
 * Security A9.1: all wire values render as JSX text nodes only, never markup.
 * parseToken never reads the token field from wire data — only token_prefix and
 * token_id are stored in RegistrationToken; the mint/rotate response token is
 * held transiently in pendingSecret and passed directly to SecretOnceModal.
 */
import { useCallback, useEffect, useRef, useState } from 'react'
import { apiFetch } from '../api/client.ts'
import { useAuth } from '../auth/AuthContext.tsx'
import ErrorCard from '../shell/ErrorCard.tsx'

// ── Types ─────────────────────────────────────────────────────────────────────

export interface RegistrationToken {
  token_id: string   // stable UUID — safe to expose, used to address revoke/delete
  token_prefix: string
  tenant_id: string
  group: string
  created_at: string
  expires_at: string | null
  revoked: boolean
  revoked_at: string | null
}

interface FetchOutcome {
  key: string
  tokens?: RegistrationToken[]
  error?: string
}

// ── Parse helpers ─────────────────────────────────────────────────────────────

function str(v: unknown): string {
  return typeof v === 'string' ? v : ''
}

function optStr(v: unknown): string | null {
  return typeof v === 'string' ? v : null
}

function bool(v: unknown): boolean {
  return typeof v === 'boolean' && v
}

export function parseToken(value: unknown): RegistrationToken | null {
  if (typeof value !== 'object' || value === null) return null
  const r = value as Record<string, unknown>
  const token_prefix = str(r.token_prefix)
  if (!token_prefix) return null
  return {
    token_id: str(r.token_id),
    token_prefix,
    tenant_id: str(r.tenant_id),
    group: str(r.group),
    created_at: str(r.created_at),
    expires_at: optStr(r.expires_at),
    revoked: bool(r.revoked),
    revoked_at: optStr(r.revoked_at),
  }
}

export function parseTokenList(data: unknown): RegistrationToken[] {
  if (typeof data !== 'object' || data === null || Array.isArray(data)) {
    throw new Error('unexpected response shape')
  }
  const r = data as Record<string, unknown>
  if (!Array.isArray(r.tokens)) throw new Error('unexpected response shape')
  const list: RegistrationToken[] = []
  for (const item of r.tokens) {
    const parsed = parseToken(item)
    if (parsed !== null) list.push(parsed)
  }
  return list
}

// ── Status helpers ────────────────────────────────────────────────────────────

type TokenStatus = 'active' | 'expired' | 'revoked'

function tokenStatus(token: RegistrationToken): TokenStatus {
  if (token.revoked) return 'revoked'
  if (token.expires_at !== null && new Date(token.expires_at) < new Date()) return 'expired'
  return 'active'
}

function statusClass(s: TokenStatus): string {
  if (s === 'active') return 'pill ok'
  if (s === 'expired') return 'pill neutral'
  return 'pill crit'
}

function statusLabel(s: TokenStatus): string {
  if (s === 'active') return 'Active'
  if (s === 'expired') return 'Expired'
  return 'Revoked'
}

// ── SecretOnceModal ───────────────────────────────────────────────────────────

/*
 * Renders the minted or rotated secret exactly once. On dismiss, the secret is
 * cleared from state and is unrecoverable from the client. No ref, no
 * localStorage, no clipboard persistence beyond the copy affordance.
 * Security AC Story #2970: secret shown once, unrecoverable after dismiss.
 */
interface SecretOnceModalProps {
  secret: string         // full token — passed transiently, never stored
  action: 'minted' | 'rotated'
  onDismiss: () => void  // caller clears pendingSecret on dismiss
}

export function SecretOnceModal({ secret, action, onDismiss }: SecretOnceModalProps) {
  const [copied, setCopied] = useState(false)
  const copyRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  function handleCopy() {
    navigator.clipboard.writeText(secret).then(() => {
      setCopied(true)
      if (copyRef.current !== null) clearTimeout(copyRef.current)
      copyRef.current = setTimeout(() => setCopied(false), 2000)
    }).catch(() => {})
  }

  // Clean up timeout on unmount.
  useEffect(() => {
    return () => {
      if (copyRef.current !== null) clearTimeout(copyRef.current)
    }
  }, [])

  const verb = action === 'minted' ? 'Minted' : 'Rotated'

  return (
    <div
      className="modal-overlay"
      role="dialog"
      aria-modal="true"
      aria-labelledby="secret-modal-title"
      data-testid="secret-once-modal"
    >
      <div className="modal-panel">
        <h2 id="secret-modal-title">{verb} — copy your token now</h2>
        <p className="notice-warn" data-testid="secret-once-warning">
          This token will not be shown again. Copy it before dismissing.
        </p>
        <div className="secret-row" data-testid="secret-value-row">
          <code className="mono2 secret-value" data-testid="secret-value">
            {secret}
          </code>
          <button
            type="button"
            className="wf-btn-sm"
            onClick={handleCopy}
            data-testid="copy-secret-btn"
            aria-label="Copy token to clipboard"
          >
            {copied ? 'Copied!' : 'Copy'}
          </button>
        </div>
        <button
          type="button"
          className="wf-btn-primary"
          onClick={onDismiss}
          data-testid="dismiss-secret-btn"
          aria-label="Dismiss — token will not be shown again"
        >
          I have copied the token — dismiss
        </button>
      </div>
    </div>
  )
}

// ── Mint form ─────────────────────────────────────────────────────────────────

interface MintFormProps {
  tenantId: string
  onMinted: (secret: string) => void
  onReload: () => void
}

function MintForm({ tenantId, onMinted, onReload }: MintFormProps) {
  const [group, setGroup] = useState('')
  const [controllerUrl, setControllerUrl] = useState('')
  const [expiresIn, setExpiresIn] = useState('')
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (controllerUrl.trim() === '') {
      setError('Controller URL is required')
      return
    }
    setError(null)
    setPending(true)
    try {
      const body: Record<string, unknown> = {
        tenant_id: tenantId,
        controller_url: controllerUrl.trim(),
      }
      if (group.trim() !== '') body.group = group.trim()
      if (expiresIn.trim() !== '') body.expires_in = expiresIn.trim()

      const response = await apiFetch('/api/v1/registration/tokens', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      if (!response.ok) {
        setError(`Mint failed — ${response.status}`)
        return
      }
      const data = (await response.json()) as Record<string, unknown>
      const secret = typeof data.token === 'string' ? data.token : ''
      setGroup('')
      setControllerUrl('')
      setExpiresIn('')
      onReload()
      if (secret.length > 0) onMinted(secret)
    } catch (cause: unknown) {
      setError(cause instanceof Error && cause.message ? cause.message : 'Mint request failed')
    } finally {
      setPending(false)
    }
  }

  return (
    <form className="wf-form" onSubmit={handleSubmit} data-testid="mint-form">
      <h3>Mint new token</h3>
      <div className="wf-field">
        <label htmlFor="mint-controller-url">Controller URL</label>
        <input
          id="mint-controller-url"
          type="text"
          className="wf-input"
          value={controllerUrl}
          onChange={(e) => setControllerUrl(e.target.value)}
          placeholder="https://controller.example.com"
          data-testid="mint-controller-url"
          required
        />
      </div>
      <div className="wf-field">
        <label htmlFor="mint-group">Group (optional)</label>
        <input
          id="mint-group"
          type="text"
          className="wf-input"
          value={group}
          onChange={(e) => setGroup(e.target.value)}
          placeholder="prod-enroll"
          data-testid="mint-group"
        />
      </div>
      <div className="wf-field">
        <label htmlFor="mint-expires-in">Expires in (optional, e.g. 30d)</label>
        <input
          id="mint-expires-in"
          type="text"
          className="wf-input"
          value={expiresIn}
          onChange={(e) => setExpiresIn(e.target.value)}
          placeholder="30d"
          data-testid="mint-expires-in"
        />
      </div>
      {error !== null && (
        <span className="wf-form-error" role="alert" data-testid="mint-error">
          {error}
        </span>
      )}
      <button
        type="submit"
        className="wf-btn-primary"
        disabled={pending}
        data-testid="mint-btn"
      >
        {pending ? 'Minting…' : 'Mint token'}
      </button>
    </form>
  )
}

// ── Sub-components ────────────────────────────────────────────────────────────

function LoadingRows() {
  return (
    <div data-testid="tokens-loading" aria-label="Loading registration tokens">
      {Array.from({ length: 3 }, (_, i) => (
        <div className="skrow" key={i}>
          <span className="skel" style={{ width: '18%' }} />
          <span className="skel" style={{ width: '22%' }} />
          <span className="skel" style={{ width: '18%' }} />
          <span className="skel" style={{ width: '15%' }} />
          <span className="skel" style={{ width: '15%' }} />
          <span className="skel" style={{ width: '10%' }} />
        </div>
      ))}
    </div>
  )
}

function EmptyState({ tenantId, onMinted, onReload }: { tenantId: string; onMinted: (s: string) => void; onReload: () => void }) {
  return (
    <div>
      <div className="notice empty" data-testid="tokens-empty">
        <div className="ic">◍</div>
        <h3>No registration tokens</h3>
        <p>Tokens minted for this tenant will appear here.</p>
      </div>
      <MintForm tenantId={tenantId} onMinted={onMinted} onReload={onReload} />
    </div>
  )
}

function StatusBadge({ token }: { token: RegistrationToken }) {
  const status = tokenStatus(token)
  return (
    <span className={statusClass(status)} data-testid="token-status">
      <span className="dot" />
      {statusLabel(status)}
    </span>
  )
}

// ── TokenRow ──────────────────────────────────────────────────────────────────

// rowKeyFor identifies a row in per-token UI state (pending/error maps, test ids).
// token_id is the identity everywhere it exists; token_prefix is the fallback for
// legacy rows that have no id yet, so their state never collides on the empty string.
function rowKeyFor(token: RegistrationToken): string {
  return token.token_id || token.token_prefix
}

interface TokenRowProps {
  token: RegistrationToken
  onAction: (action: 'rotate' | 'revoke' | 'delete', token: RegistrationToken) => void
  actionPending: boolean
  actionError: string | null
}

function TokenRow({ token, onAction, actionPending, actionError }: TokenRowProps) {
  // Revoke and delete address the token by its stable UUID. A token without one
  // (a row that predates the id column and has not been migrated) cannot be
  // addressed at all — the action is disabled rather than issuing a request to a
  // degenerate URL that would 404 with no explanation.
  const rowKey = rowKeyFor(token)
  const addressable = token.token_id.length > 0
  const unaddressableTitle = 'Token has no identifier — restart the controller to migrate legacy tokens'
  return (
    <>
      <tr data-testid="token-row">
        <td className="mono2" data-testid="token-prefix">
          {token.token_prefix}
        </td>
        <td data-testid="token-tenant">{token.tenant_id || '—'}</td>
        <td data-testid="token-group">{token.group || '—'}</td>
        <td className="mono2" data-testid="token-created">
          {token.created_at || '—'}
        </td>
        <td className="mono2" data-testid="token-expires">
          {token.expires_at ?? '—'}
        </td>
        <td data-testid="token-status-cell">
          <StatusBadge token={token} />
        </td>
        <td data-testid="token-actions">
          {!token.revoked && (
            <button
              type="button"
              className="wf-btn-sm"
              disabled={actionPending}
              onClick={() => onAction('rotate', token)}
              data-testid={`rotate-btn-${rowKey}`}
            >
              {actionPending ? '…' : 'Rotate'}
            </button>
          )}
          {!token.revoked && (
            <button
              type="button"
              className="wf-btn-sm-danger"
              disabled={actionPending || !addressable}
              title={addressable ? undefined : unaddressableTitle}
              onClick={() => onAction('revoke', token)}
              data-testid={`revoke-btn-${rowKey}`}
            >
              {actionPending ? '…' : 'Revoke'}
            </button>
          )}
          <button
            type="button"
            className="wf-btn-sm-danger"
            disabled={actionPending || !addressable}
            title={addressable ? undefined : unaddressableTitle}
            onClick={() => onAction('delete', token)}
            data-testid={`delete-btn-${rowKey}`}
          >
            {actionPending ? '…' : 'Delete'}
          </button>
        </td>
      </tr>
      {actionError !== null && (
        <tr>
          <td colSpan={7}>
            <span
              className="wf-form-error"
              role="alert"
              data-testid={`action-error-${rowKey}`}
            >
              {actionError}
            </span>
          </td>
        </tr>
      )}
    </>
  )
}

// ── Main component ────────────────────────────────────────────────────────────

const TOKENS_ENDPOINT = '/api/v1/registration/tokens'

export default function TokensTab() {
  const { principal } = useAuth()
  const tenantId = principal?.tenantId ?? ''

  const [attempt, setAttempt] = useState(0)
  const [outcome, setOutcome] = useState<FetchOutcome | null>(null)

  // pendingSecret holds the minted/rotated secret transiently for SecretOnceModal.
  // It is never written to any durable store; cleared on modal dismiss.
  const [pendingSecret, setPendingSecret] = useState<{ secret: string; action: 'minted' | 'rotated' } | null>(null)

  // Per-token action state keyed by token_id.
  const [actionPending, setActionPending] = useState<Set<string>>(new Set())
  const [actionErrors, setActionErrors] = useState<Map<string, string>>(new Map())

  const key = `tokens:${attempt}`
  const retry = useCallback(() => setAttempt((n) => n + 1), [])

  useEffect(() => {
    let cancelled = false
    apiFetch(TOKENS_ENDPOINT)
      .then(async (response) => {
        if (!response.ok) {
          throw new Error(`GET ${TOKENS_ENDPOINT} — ${response.status}`)
        }
        const body: unknown = await response.json()
        const tokens = parseTokenList(body)
        if (cancelled) return
        setOutcome({ key, tokens })
      })
      .catch((cause: unknown) => {
        if (cancelled) return
        setOutcome({
          key,
          error:
            cause instanceof Error && cause.message
              ? cause.message
              : `GET ${TOKENS_ENDPOINT} — request failed`,
        })
      })
    return () => {
      cancelled = true
    }
  }, [key, attempt])

  function handleMinted(secret: string) {
    setPendingSecret({ secret, action: 'minted' })
  }

  function handleRotated(secret: string) {
    setPendingSecret({ secret, action: 'rotated' })
  }

  function dismissSecret() {
    setPendingSecret(null)
  }

  async function handleTokenAction(action: 'rotate' | 'revoke' | 'delete', token: RegistrationToken) {
    const id = token.token_id
    const rowKey = rowKeyFor(token)
    setActionErrors((prev) => { const m = new Map(prev); m.delete(rowKey); return m })

    // Revoke and delete address the token by UUID; without one there is no URL to
    // call. Report it instead of requesting `/tokens//revoke` or `/tokens/`.
    if (action !== 'rotate' && id.length === 0) {
      setActionErrors((prev) =>
        new Map(prev).set(rowKey, `${action} unavailable — token has no identifier`),
      )
      return
    }

    setActionPending((prev) => new Set([...prev, rowKey]))

    try {
      let response: Response
      if (action === 'rotate') {
        response = await apiFetch(`${TOKENS_ENDPOINT}/${encodeURIComponent(token.tenant_id)}/rotate`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ group: token.group }),
        })
      } else if (action === 'revoke') {
        response = await apiFetch(`${TOKENS_ENDPOINT}/${encodeURIComponent(id)}/revoke`, {
          method: 'POST',
        })
      } else {
        response = await apiFetch(`${TOKENS_ENDPOINT}/${encodeURIComponent(id)}`, {
          method: 'DELETE',
        })
      }

      if (!response.ok) {
        setActionErrors((prev) => new Map(prev).set(rowKey, `${action} failed — ${response.status}`))
        return
      }

      if (action === 'rotate') {
        const data = (await response.json()) as Record<string, unknown>
        const secret = typeof data.token === 'string' ? data.token : ''
        if (secret.length > 0) handleRotated(secret)
      }

      setAttempt((n) => n + 1)
    } catch (cause: unknown) {
      setActionErrors((prev) =>
        new Map(prev).set(
          rowKey,
          cause instanceof Error && cause.message ? cause.message : `${action} request failed`,
        ),
      )
    } finally {
      setActionPending((prev) => {
        const next = new Set(prev)
        next.delete(rowKey)
        return next
      })
    }
  }

  const current = outcome?.key === key ? outcome : null

  if (current === null) return <LoadingRows />

  if (current.error !== undefined) {
    return (
      <ErrorCard
        heading="Couldn't load tokens"
        detail={current.error}
        onRetry={retry}
      />
    )
  }

  const tokens = current.tokens ?? []

  return (
    <>
      {pendingSecret !== null && (
        <SecretOnceModal
          secret={pendingSecret.secret}
          action={pendingSecret.action}
          onDismiss={dismissSecret}
        />
      )}
      {tokens.length === 0 ? (
        <EmptyState tenantId={tenantId} onMinted={handleMinted} onReload={retry} />
      ) : (
        <section className="panel">
          <table className="tbl" data-testid="tokens-table">
            <thead>
              <tr>
                <th>Token</th>
                <th>Tenant</th>
                <th>Group</th>
                <th>Created</th>
                <th>Expires</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {tokens.map((token) => (
                <TokenRow
                  key={rowKeyFor(token)}
                  token={token}
                  onAction={handleTokenAction}
                  actionPending={actionPending.has(rowKeyFor(token))}
                  actionError={actionErrors.get(rowKeyFor(token)) ?? null}
                />
              ))}
            </tbody>
          </table>
          <p className="mono2" style={{ fontSize: 'var(--text-sm)', marginTop: '8px' }}>
            Only the token prefix is ever shown — the full secret is displayed once at mint and never
            again.
          </p>
          <MintForm tenantId={tenantId} onMinted={handleMinted} onReload={retry} />
        </section>
      )}
    </>
  )
}
