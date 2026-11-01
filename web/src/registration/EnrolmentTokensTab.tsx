// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Enrolment tokens tab (Issue #5451, Epic #5300).
 *   List:           GET  /api/v1/enrolment-tokens
 *   Mint:           POST /api/v1/enrolment-tokens {tenant_id}   (429 when rate limited)
 *   Revoke:         POST /api/v1/enrolment-tokens/{id}/revoke   (active rows only)
 *   Revoke issued:  POST /api/v1/enrolment-tokens/{id}/revoke-issued-credentials
 * All four are Strong-assurance only: the CFGMS-StepUp 401 is handled by apiFetch →
 * AuthProvider → StepUpModal, and the elevation path attaches no presence token.
 *
 * Secret-once: the mint response's token is held only in transient component state
 * for SecretOnceModal and discarded on dismiss. The list parser never reads a
 * token value, so a list row cannot render one.
 *
 * Security A9.1: every wire value renders as JSX text, never markup.
 */
import { useCallback, useEffect, useState } from 'react'
import { apiFetch, unwrapEnvelope } from '../api/client.ts'
import { useAuth } from '../auth/AuthContext.tsx'
import ErrorCard from '../shell/ErrorCard.tsx'
import '../tenants/SupportAccessView.css'
import { SecretOnceModal } from './TokensTab.tsx'

type EnrolmentStatus = 'active' | 'spent' | 'revoked' | 'expired' | 'unknown'

export interface EnrolmentToken {
  id: string
  token_prefix: string
  tenant_id: string
  created_at: string
  expires_at: string
  status: EnrolmentStatus
}

const ENDPOINT = '/api/v1/enrolment-tokens'

function str(v: unknown): string {
  return typeof v === 'string' ? v : ''
}

function parseStatus(v: unknown): EnrolmentStatus {
  return v === 'active' || v === 'spent' || v === 'revoked' || v === 'expired' ? v : 'unknown'
}

export function parseEnrolmentToken(value: unknown): EnrolmentToken | null {
  if (typeof value !== 'object' || value === null) return null
  const r = value as Record<string, unknown>
  const id = str(r.id)
  if (!id) return null
  // The token value is deliberately never read.
  return {
    id,
    token_prefix: str(r.token_prefix),
    tenant_id: str(r.tenant_id),
    created_at: str(r.created_at),
    expires_at: str(r.expires_at),
    status: parseStatus(r.status),
  }
}

export function parseEnrolmentTokenList(body: unknown): EnrolmentToken[] {
  const data = unwrapEnvelope<unknown>(body)
  if (!Array.isArray(data)) throw new Error('unexpected response shape')
  const out: EnrolmentToken[] = []
  for (const item of data) {
    const t = parseEnrolmentToken(item)
    if (t !== null) out.push(t)
  }
  return out
}

const STATUS_LABEL: Record<EnrolmentStatus, string> = {
  active: 'Active',
  spent: 'Spent',
  revoked: 'Revoked',
  expired: 'Expired',
  unknown: 'Unknown',
}

const STATUS_CLASS: Record<EnrolmentStatus, string> = {
  active: 'pill ok',
  spent: 'pill neutral',
  revoked: 'pill crit',
  expired: 'pill neutral',
  unknown: 'pill neutral',
}

type RowAction = 'revoke' | 'revoke-issued'

function actionPath(action: RowAction): string {
  return action === 'revoke' ? 'revoke' : 'revoke-issued-credentials'
}

// ── Mint form ─────────────────────────────────────────────────────────────────

function MintForm({ defaultTenant, onMinted }: { defaultTenant: string; onMinted: (secret: string) => void }) {
  const [tenant, setTenant] = useState(defaultTenant)
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    if (tenant.trim() === '') {
      setError('Tenant is required')
      return
    }
    setError(null)
    setPending(true)
    try {
      const response = await apiFetch(ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tenant_id: tenant.trim() }),
      })
      if (response.status === 429) {
        setError('Too many enrolment tokens minted recently. Wait a moment and try again.')
        return
      }
      if (!response.ok) {
        setError(`Mint failed — ${response.status}`)
        return
      }
      const data = unwrapEnvelope<Record<string, unknown> | null>(await response.json())
      const secret = data !== null && typeof data.token === 'string' ? data.token : ''
      if (secret.length === 0) {
        setError('Mint failed — response carried no token')
        return
      }
      onMinted(secret)
    } catch (cause: unknown) {
      setError(cause instanceof Error && cause.message ? cause.message : 'Mint request failed')
    } finally {
      setPending(false)
    }
  }

  return (
    <form className="wf-form" onSubmit={(e) => void submit(e)} data-testid="et-mint-form">
      <h3>Mint enrolment token</h3>
      <div className="wf-field">
        <label htmlFor="et-mint-tenant">Tenant</label>
        <input
          id="et-mint-tenant"
          type="text"
          className="wf-input"
          value={tenant}
          onChange={(e) => setTenant(e.target.value)}
          placeholder="root/msp-a/client-1"
          data-testid="et-mint-tenant"
          required
        />
      </div>
      {error !== null && (
        <span className="wf-form-error" role="alert" data-testid="et-mint-error">
          {error}
        </span>
      )}
      <button type="submit" className="wf-btn-primary" disabled={pending} data-testid="et-mint-btn">
        {pending ? 'Minting…' : 'Mint token'}
      </button>
    </form>
  )
}

// ── Rows ──────────────────────────────────────────────────────────────────────

function ConfirmRow({
  action,
  busy,
  onCancel,
  onConfirm,
}: {
  action: RowAction
  busy: boolean
  onCancel: () => void
  onConfirm: () => void
}) {
  return (
    <tr className="sa-confirm" data-testid="et-confirm-row">
      <td colSpan={6}>
        <div className="sa-confirm-in">
          <span className="sa-confirm-text">
            {action === 'revoke' ? (
              <>
                <b>Revoke this enrolment token?</b> It can no longer be used to enrol.
              </>
            ) : (
              <>
                <b>Revoke issued credentials?</b> Every credential this token issued stops working now.
              </>
            )}
            <span className="sa-confirm-sub">You confirm with your passkey.</span>
          </span>
          <button type="button" className="sa-btn-sec sa-sm" onClick={onCancel} disabled={busy} data-testid="et-cancel-btn">
            Cancel
          </button>
          <button type="button" className="sa-btn-danger sa-sm" onClick={onConfirm} disabled={busy} data-testid="et-confirm-btn">
            {busy ? '…' : 'Confirm'}
          </button>
        </div>
      </td>
    </tr>
  )
}

// ── Main component ────────────────────────────────────────────────────────────

interface Outcome {
  key: string
  tokens?: EnrolmentToken[]
  error?: string
}

export default function EnrolmentTokensTab() {
  const { principal } = useAuth()
  const [attempt, setAttempt] = useState(0)
  const [outcome, setOutcome] = useState<Outcome | null>(null)
  const [secret, setSecret] = useState<string | null>(null)
  const [confirming, setConfirming] = useState<{ id: string; action: RowAction } | null>(null)
  const [busy, setBusy] = useState(false)
  const [actionError, setActionError] = useState<string | null>(null)

  const key = `enrolment-tokens:${attempt}`
  const reload = useCallback(() => setAttempt((n) => n + 1), [])

  useEffect(() => {
    let cancelled = false
    apiFetch(ENDPOINT)
      .then(async (response) => {
        if (!response.ok) throw new Error(`GET ${ENDPOINT} — ${response.status}`)
        const tokens = parseEnrolmentTokenList(await response.json())
        if (!cancelled) setOutcome({ key, tokens })
      })
      .catch((cause: unknown) => {
        if (cancelled) return
        setOutcome({
          key,
          error: cause instanceof Error && cause.message ? cause.message : `GET ${ENDPOINT} — request failed`,
        })
      })
    return () => {
      cancelled = true
    }
  }, [key])

  async function runAction() {
    if (confirming === null) return
    const { id, action } = confirming
    setBusy(true)
    setActionError(null)
    try {
      const response = await apiFetch(`${ENDPOINT}/${encodeURIComponent(id)}/${actionPath(action)}`, {
        method: 'POST',
      })
      if (!response.ok) {
        setActionError(`${action === 'revoke' ? 'Revoke' : 'Revoke issued credentials'} failed — ${response.status}`)
        return
      }
      setConfirming(null)
      reload()
    } catch (cause: unknown) {
      setActionError(cause instanceof Error && cause.message ? cause.message : 'Request failed')
    } finally {
      setBusy(false)
    }
  }

  function startConfirm(id: string, action: RowAction) {
    setActionError(null)
    setConfirming({ id, action })
  }

  const current = outcome?.key === key ? outcome : null
  if (current === null) {
    return (
      <div data-testid="enrolment-tokens-loading" aria-label="Loading enrolment tokens">
        {Array.from({ length: 3 }, (_, i) => (
          <div className="skrow" key={i}>
            <span className="skel" style={{ width: '25%' }} />
            <span className="skel" style={{ width: '25%' }} />
            <span className="skel" style={{ width: '25%' }} />
          </div>
        ))}
      </div>
    )
  }
  if (current.error !== undefined) {
    return <ErrorCard heading="Couldn't load enrolment tokens" detail={current.error} onRetry={reload} />
  }

  const tokens = current.tokens ?? []
  const mint = (
    <MintForm
      defaultTenant={principal?.tenantId ?? ''}
      onMinted={(s) => {
        setSecret(s)
        reload()
      }}
    />
  )

  return (
    <>
      {secret !== null && <SecretOnceModal secret={secret} action="minted" onDismiss={() => setSecret(null)} />}
      {tokens.length === 0 ? (
        <div>
          <div className="notice empty" data-testid="enrolment-tokens-empty">
            <div className="ic">◍</div>
            <h3>No enrolment tokens</h3>
            <p>Tokens minted for headless enrolment will appear here.</p>
          </div>
          {mint}
        </div>
      ) : (
        <>
          <section className="panel">
            <table className="tbl" data-testid="enrolment-tokens-table">
              <thead>
                <tr>
                  <th>Token</th>
                  <th>Tenant</th>
                  <th>Created</th>
                  <th>Expires</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {tokens.map((t) => (
                  <RowGroup
                    key={t.id}
                    token={t}
                    confirming={confirming?.id === t.id ? confirming.action : null}
                    busy={busy}
                    error={confirming?.id === t.id ? actionError : null}
                    onStart={startConfirm}
                    onCancel={() => setConfirming(null)}
                    onConfirm={() => void runAction()}
                  />
                ))}
              </tbody>
            </table>
          </section>
          {mint}
        </>
      )}
    </>
  )
}

function RowGroup({
  token,
  confirming,
  busy,
  error,
  onStart,
  onCancel,
  onConfirm,
}: {
  token: EnrolmentToken
  confirming: RowAction | null
  busy: boolean
  error: string | null
  onStart: (id: string, action: RowAction) => void
  onCancel: () => void
  onConfirm: () => void
}) {
  return (
    <>
      <tr data-testid="enrolment-token-row">
        <td className="mono2">{token.token_prefix || '—'}</td>
        <td>{token.tenant_id || '—'}</td>
        <td className="mono2">{token.created_at || '—'}</td>
        <td className="mono2">{token.expires_at || '—'}</td>
        <td>
          <span className={STATUS_CLASS[token.status]} data-testid="enrolment-token-status">
            <span className="dot" />
            {STATUS_LABEL[token.status]}
          </span>
        </td>
        <td>
          {token.status === 'active' && (
            <button
              type="button"
              className="wf-btn-sm-danger"
              onClick={() => onStart(token.id, 'revoke')}
              data-testid={`et-revoke-btn-${token.id}`}
            >
              Revoke
            </button>
          )}
          <button
            type="button"
            className="wf-btn-sm-danger"
            onClick={() => onStart(token.id, 'revoke-issued')}
            data-testid={`et-revoke-issued-btn-${token.id}`}
          >
            Revoke issued credentials
          </button>
        </td>
      </tr>
      {confirming !== null && (
        <>
          <ConfirmRow action={confirming} busy={busy} onCancel={onCancel} onConfirm={onConfirm} />
          {error !== null && (
            <tr>
              <td colSpan={6}>
                <span className="wf-form-error" role="alert" data-testid="et-action-error">
                  {error}
                </span>
              </td>
            </tr>
          )}
        </>
      )}
    </>
  )
}
