// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * CaseListView (Story #3614) — the /cases index route.
 *
 * Fetches GET /api/v1/cases and renders a triage-oriented table. Server-side
 * tenant filtering is trusted; this view applies no client-side filter of its
 * own. Row click navigates to /cases/:id (Story #3608) — a full route change,
 * not a drawer toggle.
 *
 * Column set (founder decision, 2026-08-26): Title, Client, Priority, Status,
 * Last updated. Client and Priority may legitimately be empty on a young case;
 * unfilled fields render a muted "—" marker, never a blank cell.
 *
 * Pattern: WorkflowListView (loading/empty/error skeleton) + FleetTable
 * (row-to-detail-route anchor via encodeURIComponent on the id).
 *
 * Security A9.1: all case field values reach the DOM as JSX text nodes only.
 */
import { useEffect, useState } from 'react'
import { Link } from 'react-router'
import { apiFetch } from '../api/client.ts'
import type { Case } from './caseTypes.ts'
import ErrorCard from '../shell/ErrorCard.tsx'

// ── Loading skeleton ──────────────────────────────────────────────────────────

function LoadingRows() {
  return (
    <div data-testid="case-loading" aria-label="Loading cases">
      {Array.from({ length: 4 }, (_, i) => (
        <div className="skrow" key={i}>
          <span className="skel" style={{ width: '45%' }} />
          <span className="skel" style={{ width: '25%' }} />
          <span className="skel" style={{ width: '15%' }} />
          <span className="skel" style={{ width: '20%' }} />
          <span className="skel" style={{ width: '30%' }} />
        </div>
      ))}
    </div>
  )
}

// ── Empty state ───────────────────────────────────────────────────────────────

function CasesEmpty() {
  return (
    <div className="notice empty" data-testid="cases-empty">
      <div className="ic">◍</div>
      <h3>No cases yet</h3>
      <p>Cases opened for your tenant will appear here.</p>
    </div>
  )
}

// ── Missing value marker ──────────────────────────────────────────────────────

function MissingMarker() {
  return <span className="mut">—</span>
}

// ── Case table row ────────────────────────────────────────────────────────────

function CaseRow({ caseData }: { caseData: Case }) {
  const { ticket } = caseData
  const href = `/cases/${encodeURIComponent(caseData.id)}`

  return (
    <tr data-testid="case-row">
      <td>
        <Link to={href} className="nm row-link">
          {ticket.title.filled ? ticket.title.value : <MissingMarker />}
        </Link>
      </td>
      <td>
        {ticket.client.filled
          ? <span className="nm">{ticket.client.value}</span>
          : <MissingMarker />}
      </td>
      <td>
        {ticket.priority.filled
          ? <span className="nm">{ticket.priority.value}</span>
          : <MissingMarker />}
      </td>
      <td>
        <span className="mono2">{caseData.status}</span>
      </td>
      <td>
        <span className="mono2">{new Date(caseData.updated_at).toLocaleDateString()}</span>
      </td>
      <td className="c-spacer" />
    </tr>
  )
}

// ── Fetch state ───────────────────────────────────────────────────────────────

interface FetchOutcome {
  key: string
  cases?: Case[]
  error?: string
}

// ── Main view ─────────────────────────────────────────────────────────────────

export default function CaseListView() {
  const [attempt, setAttempt] = useState(0)
  const [outcome, setOutcome] = useState<FetchOutcome | null>(null)
  const key = `cases:${attempt}`

  useEffect(() => {
    let cancelled = false
    void apiFetch('/api/v1/cases')
      .then(async (res) => {
        if (cancelled) return
        if (!res.ok) {
          setOutcome({ key, error: `Load failed — ${res.status}` })
          return
        }
        const body = (await res.json()) as { data: Case[] }
        if (!cancelled) {
          setOutcome({ key, cases: body.data ?? [] })
        }
      })
      .catch(() => {
        if (!cancelled) setOutcome({ key, error: 'Failed to load cases' })
      })
    return () => {
      cancelled = true
    }
  }, [key])

  const current = outcome?.key === key ? outcome : null
  const loading = current === null
  const error = current?.error ?? null
  const cases = current?.cases ?? []

  return (
    <>
      <div className="htitle">
        <h1>Cases</h1>
        <p>Troubleshooting cases scoped to your tenant.</p>
      </div>

      <div className="workspace">
        <section className="panel">
          <div className="ptool">
            {!loading && error === null && (
              <span className="cnt" data-testid="cases-count">
                {cases.length} case{cases.length !== 1 ? 's' : ''}
              </span>
            )}
          </div>

          {loading ? (
            <LoadingRows />
          ) : error !== null ? (
            <ErrorCard
              heading="Couldn't load cases"
              detail={error}
              onRetry={() => setAttempt((n) => n + 1)}
            />
          ) : cases.length === 0 ? (
            <CasesEmpty />
          ) : (
            <table className="tbl" data-testid="cases-table">
              <thead>
                <tr>
                  <th>Title</th>
                  <th>Client</th>
                  <th>Priority</th>
                  <th>Status</th>
                  <th>Last updated</th>
                  <th className="c-spacer" aria-hidden="true" />
                </tr>
              </thead>
              <tbody>
                {cases.map((c) => (
                  <CaseRow key={c.id} caseData={c} />
                ))}
              </tbody>
            </table>
          )}
        </section>
      </div>
    </>
  )
}
