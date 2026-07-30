// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Registration token list tab (Story #2935) — read-only view.
 * Fetches GET /api/v1/registration/tokens — {tokens:[...], total:N} shape
 * per handlers_registration_tokens.go (no {data:...} envelope).
 * Shape-validated by parseTokenList before any value reaches the DOM.
 *
 * Renders: token_prefix, tenant_id, group, created_at, expires_at, revoked.
 * expires_at / revoked_at are optional (Go omitempty on pointer types) —
 * renders '—' when absent, matching the columns.ts em-dash convention.
 *
 * No mint, rotate, revoke, or delete affordance of any kind — those are
 * Section 2's follow-on epic.
 *
 * Security A9.1: all wire values render as JSX text nodes only, never markup.
 * The component reads only token_prefix from wire data, never the full secret
 * (token field) — the list endpoint contract omits it and parseToken enforces
 * this by not reading the token field at all.
 */
import { useCallback, useEffect, useState } from 'react'
import { apiFetch } from '../api/client.ts'
import ErrorCard from '../shell/ErrorCard.tsx'

// ── Types ─────────────────────────────────────────────────────────────────────

export interface RegistrationToken {
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

function EmptyState() {
  return (
    <div className="notice empty" data-testid="tokens-empty">
      <div className="ic">◍</div>
      <h3>No registration tokens</h3>
      <p>Tokens minted for this tenant will appear here.</p>
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

// ── Main component ────────────────────────────────────────────────────────────

export default function TokensTab() {
  const [attempt, setAttempt] = useState(0)
  const [outcome, setOutcome] = useState<FetchOutcome | null>(null)

  const key = `tokens:${attempt}`
  const retry = useCallback(() => setAttempt((n) => n + 1), [])

  useEffect(() => {
    let cancelled = false
    apiFetch('/api/v1/registration/tokens')
      .then(async (response) => {
        if (!response.ok) {
          throw new Error(`GET /api/v1/registration/tokens — ${response.status}`)
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
              : 'GET /api/v1/registration/tokens — request failed',
        })
      })
    return () => {
      cancelled = true
    }
  }, [key, attempt])

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
  if (tokens.length === 0) return <EmptyState />

  return (
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
          </tr>
        </thead>
        <tbody>
          {tokens.map((token) => (
            <tr key={token.token_prefix} data-testid="token-row">
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
            </tr>
          ))}
        </tbody>
      </table>
      <p className="mono2" style={{ fontSize: 'var(--text-sm)', marginTop: '8px' }}>
        Only the token prefix is ever shown — the full secret is displayed once at mint and never
        again.
      </p>
    </section>
  )
}
