// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Orphaned credentials tab (Issue #5455, Epic #5300).
 *   List:   GET  /api/v1/credential-requests/orphaned
 *   Revoke: POST /api/v1/credential-requests/orphaned/{serial}/revoke
 * Revoke is Strong-assurance only: the CFGMS-StepUp 401 is handled by apiFetch →
 * AuthProvider → StepUpModal, and the elevation path attaches no presence token.
 * Nothing is sent until the inline Confirm.
 *
 * Security A9.1: every wire value renders as JSX text, never markup; the serial is
 * only ever placed in a URL through encodeURIComponent.
 */
import { useCallback, useEffect, useState } from 'react'
import { apiFetch, unwrapEnvelope } from '../api/client.ts'
import ErrorCard from '../shell/ErrorCard.tsx'
import '../tenants/SupportAccessView.css'

export interface OrphanedCredential {
  serial: string
  requestId: string
  tenantId: string
  accountId: string
  collectedAt: string
}

const ENDPOINT = '/api/v1/credential-requests/orphaned'

function str(v: unknown): string {
  return typeof v === 'string' ? v : ''
}

export function parseOrphanedCredential(value: unknown): OrphanedCredential | null {
  if (typeof value !== 'object' || value === null) return null
  const r = value as Record<string, unknown>
  if (typeof r.serial !== 'string' || r.serial === '') return null
  return {
    serial: r.serial,
    requestId: str(r.request_id),
    tenantId: str(r.tenant_id),
    accountId: str(r.account_id),
    collectedAt: str(r.collected_at),
  }
}

export function parseOrphanedCredentialList(body: unknown): OrphanedCredential[] {
  const data = unwrapEnvelope<unknown>(body)
  if (!Array.isArray(data)) throw new Error('unexpected response shape')
  const out: OrphanedCredential[] = []
  for (const item of data) {
    const c = parseOrphanedCredential(item)
    if (c !== null) out.push(c)
  }
  return out
}

interface Outcome {
  key: string
  items?: OrphanedCredential[]
  error?: string
}

export default function OrphanedCredentialsTab() {
  const [attempt, setAttempt] = useState(0)
  const [outcome, setOutcome] = useState<Outcome | null>(null)
  const [confirming, setConfirming] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [actionError, setActionError] = useState<string | null>(null)

  const key = `orphaned-credentials:${attempt}`
  const reload = useCallback(() => setAttempt((n) => n + 1), [])

  useEffect(() => {
    let cancelled = false
    apiFetch(ENDPOINT)
      .then(async (response) => {
        if (!response.ok) throw new Error(`GET ${ENDPOINT} — ${response.status}`)
        const items = parseOrphanedCredentialList(await response.json())
        if (!cancelled) setOutcome({ key, items })
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

  async function runRevoke() {
    if (confirming === null) return
    setBusy(true)
    setActionError(null)
    try {
      const response = await apiFetch(`${ENDPOINT}/${encodeURIComponent(confirming)}/revoke`, {
        method: 'POST',
      })
      if (!response.ok) {
        setActionError(`Revoke failed — ${response.status}`)
        return
      }
      setConfirming(null)
      reload()
    } catch (cause: unknown) {
      setActionError(cause instanceof Error && cause.message ? cause.message : 'Revoke request failed')
    } finally {
      setBusy(false)
    }
  }

  const current = outcome?.key === key ? outcome : null
  if (current === null) {
    return (
      <div data-testid="orphaned-loading" aria-label="Loading orphaned credentials">
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
    return <ErrorCard heading="Couldn't load orphaned credentials" detail={current.error} onRetry={reload} />
  }

  const items = current.items ?? []
  if (items.length === 0) {
    return (
      <div className="notice empty" data-testid="orphaned-empty">
        <div className="ic">◍</div>
        <h3>No orphaned credentials</h3>
        <p>Enrolment-flow certificates with no account bound to them will appear here.</p>
      </div>
    )
  }

  return (
    <section className="panel">
      <table className="tbl" data-testid="orphaned-table">
        <thead>
          <tr>
            <th>Serial</th>
            <th>Request</th>
            <th>Tenant</th>
            <th>Account</th>
            <th>Collected</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {items.map((c) => (
            <OrphanedRow
              key={c.serial}
              item={c}
              confirming={confirming === c.serial}
              busy={busy}
              error={confirming === c.serial ? actionError : null}
              onStart={() => {
                setActionError(null)
                setConfirming(c.serial)
              }}
              onCancel={() => setConfirming(null)}
              onConfirm={() => void runRevoke()}
            />
          ))}
        </tbody>
      </table>
    </section>
  )
}

function OrphanedRow({
  item,
  confirming,
  busy,
  error,
  onStart,
  onCancel,
  onConfirm,
}: {
  item: OrphanedCredential
  confirming: boolean
  busy: boolean
  error: string | null
  onStart: () => void
  onCancel: () => void
  onConfirm: () => void
}) {
  return (
    <>
      <tr data-testid="orphaned-row">
        <td className="mono2">{item.serial}</td>
        <td className="mono2">{item.requestId || '—'}</td>
        <td>{item.tenantId || '—'}</td>
        <td className="mono2">{item.accountId || '—'}</td>
        <td className="mono2">{item.collectedAt || '—'}</td>
        <td>
          <button
            type="button"
            className="wf-btn-sm-danger"
            onClick={onStart}
            data-testid={`orphaned-revoke-btn-${item.serial}`}
          >
            Revoke
          </button>
        </td>
      </tr>
      {confirming && (
        <>
          <tr className="sa-confirm" data-testid="orphaned-confirm-row">
            <td colSpan={6}>
              <div className="sa-confirm-in">
                <span className="sa-confirm-text">
                  <b>Revoke this certificate?</b> It stops working now and cannot be restored.
                  <span className="sa-confirm-sub">You confirm with your passkey.</span>
                </span>
                <button
                  type="button"
                  className="sa-btn-sec sa-sm"
                  onClick={onCancel}
                  disabled={busy}
                  data-testid="orphaned-cancel-btn"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  className="sa-btn-danger sa-sm"
                  onClick={onConfirm}
                  disabled={busy}
                  data-testid="orphaned-confirm-btn"
                >
                  {busy ? '…' : 'Confirm'}
                </button>
              </div>
            </td>
          </tr>
          {error !== null && (
            <tr>
              <td colSpan={6}>
                <span className="wf-form-error" role="alert" data-testid="orphaned-action-error">
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
