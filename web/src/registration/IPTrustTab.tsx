// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * IP-Trust tab (Story #2936) — read-only list of trusted CIDR ranges for the
 * caller's tenant scope, mounted as a panel on the RegistrationConsolePage tab
 * strip (Story #2934).
 *
 * Fetches GET /api/v1/registration/ip-trust, which uses the newer {data: [...]}
 * array-envelope shape (distinct from the bare-array the Pending tab uses).
 *
 * Renders: cidr, pre_seeded, trusted_since, last_activity, revoked.
 * No add/revoke affordance exists — those are Section 2's follow-on epic.
 *
 * Security: all API-supplied values render as JSX text nodes only (A9.1).
 */
import { useCallback, useEffect, useState } from 'react'
import { apiFetch } from '../api/client.ts'
import ErrorCard from '../shell/ErrorCard.tsx'

export interface IPTrustEntry {
  cidr: string
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

function EntryRow({ entry }: { entry: IPTrustEntry }) {
  return (
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
    </tr>
  )
}

const ENDPOINT = '/api/v1/registration/ip-trust'

export default function IPTrustTab() {
  const [attempt, setAttempt] = useState(0)
  const [outcome, setOutcome] = useState<FetchOutcome | null>(null)
  const key = `iptrust:${attempt}`

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

  const current = outcome?.key === key ? outcome : null
  const loading = current === null
  const error = current?.error ?? null
  const entries = current?.entries ?? []

  return (
    <section className="panel">
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
            </tr>
          </thead>
          <tbody>
            {entries.map((entry) => (
              <EntryRow key={entry.cidr} entry={entry} />
            ))}
          </tbody>
        </table>
      )}
    </section>
  )
}
