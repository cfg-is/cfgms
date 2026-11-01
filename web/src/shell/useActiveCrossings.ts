// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Active-crossings feed for the elevation banner (Issue #4725, Epic #4701).
 *
 * Polls GET /api/v1/tenant-crossings/active on mount and every 30 seconds, and
 * immediately when refresh() is called or notifyActiveCrossingsChanged() fires
 * (the crossing prompt raises it after a break-glass resolves). The feed is the
 * only source of truth: a crossing that drops out of it (expiry, revoke) drops
 * out of the returned list. Nothing is kept in browser storage.
 *
 * The parser and fetch live in tenants/useTenantCrossings.ts (fetchActiveCrossings).
 */
import { useCallback, useEffect, useState } from 'react'
import { fetchActiveCrossings, type ActiveCrossing } from '../tenants/useTenantCrossings.ts'

export const activeCrossingsPollMs = 30_000

const changedEvent = 'cfgms:active-crossings-changed'

/** Ask every mounted useActiveCrossings to refetch the feed now. */
export function notifyActiveCrossingsChanged(): void {
  window.dispatchEvent(new Event(changedEvent))
}

export interface UseActiveCrossingsResult {
  crossings: ActiveCrossing[]
  /** True until the first fetch settles. */
  loading: boolean
  /** Set when the latest fetch failed and no earlier result is held. */
  error: string | null
  /** Refetch now. */
  refresh: () => void
}

export function useActiveCrossings(): UseActiveCrossingsResult {
  const [crossings, setCrossings] = useState<ActiveCrossing[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [gen, setGen] = useState(0)
  const refresh = useCallback(() => setGen((n) => n + 1), [])

  // Fetch on mount and whenever refresh() bumps `gen`.
  useEffect(() => {
    let cancelled = false
    fetchActiveCrossings().then(
      (list) => {
        if (cancelled) return
        setCrossings(list)
        setError(null)
      },
      (cause: unknown) => {
        if (cancelled) return
        setError(cause instanceof Error && cause.message ? cause.message : 'Failed to load active crossings')
      },
    )
    return () => {
      cancelled = true
    }
  }, [gen])

  useEffect(() => {
    const timer = window.setInterval(refresh, activeCrossingsPollMs)
    window.addEventListener(changedEvent, refresh)
    return () => {
      window.clearInterval(timer)
      window.removeEventListener(changedEvent, refresh)
    }
  }, [refresh])

  return {
    crossings: crossings ?? [],
    loading: crossings === null && error === null,
    error: crossings === null ? error : null,
    refresh,
  }
}
