// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * IP-Trust tab (Story #2936, #2971) — trusted CIDR ranges for the caller's tenant
 * scope, mounted as a panel on the RegistrationConsolePage tab strip (Story #2934).
 *
 * Fetches GET /api/v1/registration/ip-trust, which uses the newer {data: [...]}
 * array-envelope shape (distinct from the bare-array the Pending tab uses).
 *
 * Renders: cidr, pre_seeded, trusted_since, last_activity, revoked.
 * Add: POST /api/v1/registration/ip-trust — requires AssuranceStrong (CFGMS-StepUp S1).
 * Revoke: DELETE /api/v1/registration/ip-trust/{tenant_id}/{cidr} — same gate.
 * Step-up is handled transparently by apiFetch → AuthProvider → StepUpModal (#2967).
 * Per-action audit is emitted by the backend (registration:manage-ip-trust).
 *
 * Security: all API-supplied values render as JSX text nodes only (A9.1).
 */
import { Fragment, useCallback, useEffect, useState } from 'react'
import { apiFetch } from '../api/client.ts'
import { useAuth } from '../auth/AuthContext.tsx'
import ErrorCard from '../shell/ErrorCard.tsx'

export interface IPTrustEntry {
  cidr: string
  tenantId: string
  preSeeded: boolean
  trustedSince: string
  lastActivity: string
  revoked: boolean
}

/** Validate the {data: [...]} envelope (untrusted wire data). Throws on bad shape. */
export function parseIPTrustList(data: unknown): IPTrustEntry[] {
  if (!Array.isArray(data)) {
    throw new Error('unexpected response shape: expected array under data')
  }
  const entries: IPTrustEntry[] = []
  for (const item of data) {
    if (typeof item !== 'object' || item === null) continue
    const r = item as Record<string, unknown>
    const cidr = typeof r.cidr === 'string' ? r.cidr : ''
    if (cidr === '') continue
    entries.push({
      cidr,
      tenantId: typeof r.tenant_id === 'string' ? r.tenant_id : '',
      preSeeded: r.pre_seeded === true,
      trustedSince: typeof r.trusted_since === 'string' ? r.trusted_since : '',
      lastActivity: typeof r.last_activity === 'string' ? r.last_activity : '',
      revoked: r.revoked === true,
    })
  }
  return entries
}

interface FetchOutcome {
  key: string
  entries?: IPTrustEntry[]
  error?: string
}

function LoadingRows() {
  return (
    <div data-testid="iptrust-loading" aria-label="Loading IP trust entries">
      {Array.from({ length: 3 }, (_, i) => (
        <div className="skrow" key={i}>
          <span className="skel" style={{ width: '20%' }} />
          <span className="skel" style={{ width: '15%' }} />
          <span className="skel" style={{ width: '22%' }} />
          <span className="skel" style={{ width: '22%' }} />
        </div>
      ))}
    </div>
  )
}

function EmptyState() {
  return (
    <div className="notice empty" data-testid="iptrust-empty">
      <div className="ic">◍</div>
      <h3>No trusted CIDR ranges</h3>
      <p>
        No IP ranges have been added to this tenant&apos;s trust list. Trusted ranges allow
        stewards connecting from those addresses to register without an explicit token.
      </p>
    </div>
  )
}

function SourceBadge({ preSeeded }: { preSeeded: boolean }) {
  if (preSeeded) {
    return (
      <span className="badge b-plain" data-testid="badge-preseeded">
        Pre-seeded
      </span>
    )
  }
  return (
    <span className="badge b-ok" data-testid="badge-manual">
      <span className="dot" aria-hidden="true" />
      Manual
    </span>
  )
}

function EntryRow({
  entry,
  onRevoke,
  revoking,
  revokeError,
}: {
  entry: IPTrustEntry
  onRevoke: (entry: IPTrustEntry) => void
  revoking: boolean
  revokeError: string | null
}) {
  return (
    <Fragment>
      <tr data-testid="iptrust-row">
        <td>
          <span className="mono2">{entry.cidr}</span>
        </td>
        <td>
          <SourceBadge preSeeded={entry.preSeeded} />
        </td>
        <td>
          <span className="mono2">{entry.trustedSince}</span>
        </td>
        <td>
          <span className="mono2">{entry.lastActivity}</span>
        </td>
        <td>
          {entry.revoked && (
            <span className="badge b-crit" data-testid="badge-revoked">
              <span className="dot" aria-hidden="true" />
              Revoked
            </span>
          )}
        </td>
        <td>
          {!entry.revoked && (
            <button
              type="button"
              className="wf-btn-sm-danger"
              data-testid={`revoke-btn-${entry.cidr}`}
              disabled={revoking}
              onClick={() => onRevoke(entry)}
            >
              {revoking ? 'Revoking…' : 'Revoke'}
            </button>
          )}
        </td>
      </tr>
      {revokeError !== null && (
        <tr>
          <td colSpan={6}>
            <span
              className="wf-form-error"
              data-testid={`revoke-error-${entry.cidr}`}
              role="alert"
            >
              {revokeError}
            </span>
          </td>
        </tr>
      )}
    </Fragment>
  )
}

const ENDPOINT = '/api/v1/registration/ip-trust'

export default function IPTrustTab() {
  const { principal } = useAuth()
  const [attempt, setAttempt] = useState(0)
  const [outcome, setOutcome] = useState<FetchOutcome | null>(null)
  const key = `iptrust:${attempt}`

  // Add form state
  const [cidrInput, setCidrInput] = useState('')
  const [preSeeded, setPreSeeded] = useState(false)
  const [addError, setAddError] = useState<string | null>(null)
  const [addPending, setAddPending] = useState(false)

  // Per-row revoke state
  const [revokeErrors, setRevokeErrors] = useState<Map<string, string>>(new Map())
  const [revokingSet, setRevokingSet] = useState<Set<string>>(new Set())

  const retry = useCallback(() => setAttempt((n) => n + 1), [])

  useEffect(() => {
    let cancelled = false
    apiFetch(ENDPOINT)
      .then(async (response) => {
        if (!response.ok) {
          throw new Error(`GET ${ENDPOINT} — ${response.status}`)
        }
        const body: unknown = await response.json()
        const parsed = parseIPTrustList(
          (body as Record<string, unknown> | null)?.data,
        )
        if (!cancelled) setOutcome({ key, entries: parsed })
      })
      .catch((cause: unknown) => {
        if (cancelled) return
        setOutcome({
          key,
          error:
            cause instanceof Error && cause.message
              ? cause.message
              : `GET ${ENDPOINT} — request failed`,
        })
      })
    return () => {
      cancelled = true
    }
  }, [key, attempt])

  async function handleAdd(e: React.FormEvent) {
    e.preventDefault()
    const cidr = cidrInput.trim()
    if (cidr === '') {
      setAddError('CIDR is required')
      return
    }
    setAddError(null)
    setAddPending(true)
    try {
      const response = await apiFetch(ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          tenant_id: principal?.tenantId ?? '',
          cidr,
          pre_seeded: preSeeded,
        }),
      })
      if (!response.ok) {
        setAddError(`Add failed — ${response.status}`)
        return
      }
      setCidrInput('')
      setPreSeeded(false)
      setAttempt((n) => n + 1)
    } catch (cause: unknown) {
      setAddError(
        cause instanceof Error && cause.message ? cause.message : 'Add request failed',
      )
    } finally {
      setAddPending(false)
    }
  }

  async function handleRevoke(entry: IPTrustEntry) {
    const { cidr, tenantId } = entry
    setRevokeErrors((prev) => {
      const m = new Map(prev)
      m.delete(cidr)
      return m
    })
    setRevokingSet((prev) => new Set([...prev, cidr]))
    try {
      const url =
        `${ENDPOINT}/${encodeURIComponent(tenantId)}/${encodeURIComponent(cidr)}`
      const response = await apiFetch(url, { method: 'DELETE' })
      if (!response.ok) {
        setRevokeErrors((prev) => new Map(prev).set(cidr, `Revoke failed — ${response.status}`))
        return
      }
      setAttempt((n) => n + 1)
    } catch (cause: unknown) {
      setRevokeErrors((prev) =>
        new Map(prev).set(
          cidr,
          cause instanceof Error && cause.message ? cause.message : 'Revoke request failed',
        ),
      )
    } finally {
      setRevokingSet((prev) => {
        const s = new Set(prev)
        s.delete(cidr)
        return s
      })
    }
  }

  const current = outcome?.key === key ? outcome : null
  const loading = current === null
  const error = current?.error ?? null
  const entries = current?.entries ?? []

  return (
    <section className="panel">
      <form
        className="iptrust-add-form"
        data-testid="iptrust-add-form"
        onSubmit={(e) => void handleAdd(e)}
      >
        <input
          type="text"
          className="wf-input"
          data-testid="iptrust-cidr-input"
          placeholder="10.0.0.0/8"
          aria-label="CIDR range"
          value={cidrInput}
          onChange={(e) => setCidrInput(e.target.value)}
          disabled={addPending}
        />
        <label className="iptrust-preseeded-label">
          <input
            type="checkbox"
            data-testid="iptrust-preseeded-checkbox"
            checked={preSeeded}
            onChange={(e) => setPreSeeded(e.target.checked)}
            disabled={addPending}
          />
          {' '}Pre-seeded
        </label>
        <button
          type="submit"
          className="btn"
          data-testid="iptrust-add-btn"
          disabled={addPending}
        >
          {addPending ? 'Adding…' : 'Add'}
        </button>
        {addError !== null && (
          <span
            className="wf-form-error"
            data-testid="iptrust-add-error"
            role="alert"
          >
            {addError}
          </span>
        )}
      </form>

      {loading ? (
        <LoadingRows />
      ) : error !== null ? (
        <ErrorCard heading="Couldn't load IP trust list" detail={error} onRetry={retry} />
      ) : entries.length === 0 ? (
        <EmptyState />
      ) : (
        <table className="tbl" data-testid="iptrust-table">
          <thead>
            <tr>
              <th>CIDR</th>
              <th>Source</th>
              <th>Trusted since</th>
              <th>Last activity</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((entry) => (
              <EntryRow
                key={entry.cidr}
                entry={entry}
                onRevoke={(e) => void handleRevoke(e)}
                revoking={revokingSet.has(entry.cidr)}
                revokeError={revokeErrors.get(entry.cidr) ?? null}
              />
            ))}
          </tbody>
        </table>
      )}
    </section>
  )
}
