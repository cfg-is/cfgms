// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * CockpitView (Story #3608) — the /cases/:id route shell.
 *
 * Fetches the case via GET /api/v1/cases/{id} and renders:
 *  - Loading state: spinner (role=status) while the fetch is in-flight.
 *  - Error state: error message (role=alert) on 404 or any non-OK response.
 *    A 404 (including the cross-tenant-disguised-as-404 case per the backend
 *    contract) is indistinguishable from "not found" in the UI — both render
 *    the same error state (Story #3608 Implementation Notes).
 *  - Ready state: CaseBar + TicketQuickReference + InvestigationRail + EvidenceCanvas.
 *
 * EvidenceCanvas (Story #3607) is mounted directly with case.pins — there is
 * no local placeholder canvas in this story's code (Story #3607 is a
 * dependency, not a follow-on).
 *
 * Inline ticket field edits are handled by TicketQuickReference via PUT
 * /api/v1/cases/{id}. On a successful PUT the server's updated ticket is
 * reflected locally via the onTicketUpdated callback, which sets the case
 * ticket state in CockpitView — no full re-fetch is needed.
 *
 * State model (DnaDrawer key pattern): outcome carries the caseId key it was
 * fetched for. `current = outcome?.key === caseId ? outcome : null` derives the
 * loading state from key mismatch rather than explicit setState, so the effect
 * never calls setState synchronously in its body.
 */
import { useEffect, useState } from 'react'
import { useParams } from 'react-router'
import { apiFetch } from '../api/client.ts'
import type { Case, Ticket } from './caseTypes.ts'
import CaseBar from './CaseBar.tsx'
import TicketQuickReference from './TicketQuickReference.tsx'
import InvestigationRail from './InvestigationRail.tsx'
import EvidenceCanvas from './EvidenceCanvas.tsx'
import { useCaseWatch, WatchEventContext } from './useCaseWatch.ts'
import './CockpitView.css'

interface FetchOutcome {
  key: string
  caseData?: Case
  error?: true
}

export default function CockpitView() {
  const { id: caseId = '' } = useParams<{ id: string }>()
  const [outcome, setOutcome] = useState<FetchOutcome | null>(null)
  const { isLive, connectedSince, lastEvent } = useCaseWatch(caseId)

  useEffect(() => {
    const key = caseId
    let cancelled = false
    void apiFetch(`/api/v1/cases/${encodeURIComponent(caseId)}`)
      .then(async (res) => {
        if (cancelled) return
        if (!res.ok) {
          setOutcome({ key, error: true })
          return
        }
        const body = (await res.json()) as { data: Case }
        if (!cancelled) {
          setOutcome({ key, caseData: body.data })
        }
      })
      .catch(() => {
        if (!cancelled) setOutcome({ key, error: true })
      })
    return () => {
      cancelled = true
    }
  }, [caseId])

  function onTicketUpdated(ticket: Ticket) {
    setOutcome((prev) => {
      if (prev?.caseData) {
        return { ...prev, caseData: { ...prev.caseData, ticket } }
      }
      return prev
    })
  }

  // While fetching (or on caseId change), outcome is null or stale.
  const current = outcome?.key === caseId ? outcome : null

  if (current === null) {
    return (
      <div className="cockpit-loading">
        <span role="status" aria-label="Loading case">
          <span className="cockpit-loading__spinner" aria-hidden="true" />
        </span>
      </div>
    )
  }

  if (current.error) {
    return (
      <div className="cockpit-error" role="alert">
        <p className="cockpit-error__title">Case not found</p>
        <p className="cockpit-error__body">
          This case does not exist or you do not have access to it.
        </p>
      </div>
    )
  }

  const caseData = current.caseData!

  return (
    <WatchEventContext.Provider value={lastEvent}>
      <div className="cockpit">
        <CaseBar caseData={caseData} />
        <div className="cockpit-work">
          <div className="cockpit-leftcol">
            <TicketQuickReference
              caseId={caseId}
              ticket={caseData.ticket}
              onTicketUpdated={onTicketUpdated}
            />
            <InvestigationRail
              content={caseData.content}
              isLive={isLive}
              connectedSince={connectedSince}
            />
          </div>
          <main className="cockpit-canvas">
            <EvidenceCanvas pins={caseData.pins} />
          </main>
        </div>
      </div>
    </WatchEventContext.Provider>
  )
}
