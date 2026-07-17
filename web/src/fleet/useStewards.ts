// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Fleet data hook (Story #2497): one server page of stewards from
 * GET /api/v1/stewards?limit&offset via the #2495 cookie/CSRF client.
 *
 * Scale posture: only the current page is ever held in memory; the fleet
 * count comes from the server `total` (post-filter, pre-slice — the #2489
 * contract), so the view works unchanged at 48k+ stewards. A 401 is handled
 * centrally by apiFetch (session expired → login screen); everything else
 * surfaces here as the view's error state.
 *
 * Tenant scope (#2496): observed tenant paths are reported to the scope
 * context so the switcher can offer them. The response body is untrusted
 * wire data — parseStewardPage validates shape before anything renders.
 */
import { useCallback, useEffect, useState } from 'react'
import { apiFetch } from '../api/client.ts'
import { useTenantScope } from '../shell/TenantScopeContext.tsx'
import type { Steward, StewardPage } from './columns.ts'

export interface UseStewardsResult {
  page: StewardPage | null
  loading: boolean
  /** User-presentable failure line, e.g. "GET /api/v1/stewards — 503". */
  error: string | null
  /** Wall-clock stamp of when the page arrived; anchors relative times. */
  fetchedAtMs: number
  retry: () => void
}

function parseSteward(value: unknown): Steward | null {
  if (typeof value !== 'object' || value === null) return null
  const record = value as Record<string, unknown>
  if (typeof record.id !== 'string' || record.id === '') return null
  const steward: Steward = { id: record.id }
  if (typeof record.status === 'string') steward.status = record.status
  if (typeof record.last_seen === 'string') steward.last_seen = record.last_seen
  if (typeof record.version === 'string') steward.version = record.version
  if (typeof record.dna === 'object' && record.dna !== null) {
    const dna = record.dna as Record<string, unknown>
    let attributes: Record<string, string> = {}
    if (typeof dna.attributes === 'object' && dna.attributes !== null) {
      attributes = Object.fromEntries(
        Object.entries(dna.attributes).filter(
          (entry): entry is [string, string] => typeof entry[1] === 'string',
        ),
      )
    }
    steward.dna = {
      hostname: typeof dna.hostname === 'string' ? dna.hostname : undefined,
      os: typeof dna.os === 'string' ? dna.os : undefined,
      architecture:
        typeof dna.architecture === 'string' ? dna.architecture : undefined,
      attributes,
    }
  }
  return steward
}

/** Validate the paginated envelope (untrusted wire data). */
export function parseStewardPage(data: unknown): StewardPage {
  if (typeof data !== 'object' || data === null) {
    throw new Error('unexpected response shape')
  }
  const record = data as Record<string, unknown>
  if (
    !Array.isArray(record.stewards) ||
    typeof record.total !== 'number' ||
    typeof record.limit !== 'number' ||
    typeof record.offset !== 'number'
  ) {
    throw new Error('unexpected response shape')
  }
  const stewards: Steward[] = []
  for (const entry of record.stewards) {
    const steward = parseSteward(entry)
    if (steward !== null) stewards.push(steward)
  }
  return {
    stewards,
    total: record.total,
    limit: record.limit,
    offset: record.offset,
  }
}

interface FetchOutcome {
  /** Which (limit, offset, attempt) request this outcome answers. */
  key: string
  page?: StewardPage
  error?: string
  fetchedAtMs: number
}

export function useStewards(limit: number, offset: number, selector = ''): UseStewardsResult {
  const { registerObservedPath } = useTenantScope()
  const [attempt, setAttempt] = useState(0)
  const [outcome, setOutcome] = useState<FetchOutcome | null>(null)

  const retry = useCallback(() => setAttempt((n) => n + 1), [])

  // Loading is derived, not set: the view is loading whenever the latest
  // outcome doesn't answer the current request key.
  const key = `${limit}:${offset}:${selector}:${attempt}`

  useEffect(() => {
    let cancelled = false
    const params = new URLSearchParams({
      limit: String(limit),
      offset: String(offset),
    })
    const selectorTrimmed = selector.trim()
    if (selectorTrimmed !== '') {
      params.set('q', selectorTrimmed)
    }
    apiFetch(`/api/v1/stewards?${params.toString()}`)
      .then(async (response) => {
        if (!response.ok) {
          throw new Error(`GET /api/v1/stewards — ${response.status}`)
        }
        const body: unknown = await response.json()
        const parsed = parseStewardPage(
          (body as Record<string, unknown> | null)?.data,
        )
        if (cancelled) return
        for (const steward of parsed.stewards) {
          const tenantPath = steward.dna?.attributes?.['tenant']
          if (tenantPath) registerObservedPath(tenantPath)
        }
        setOutcome({ key, page: parsed, fetchedAtMs: Date.now() })
      })
      .catch((cause: unknown) => {
        if (cancelled) return
        setOutcome({
          key,
          error:
            cause instanceof Error && cause.message
              ? cause.message
              : 'GET /api/v1/stewards — request failed',
          fetchedAtMs: Date.now(),
        })
      })
    return () => {
      cancelled = true
    }
  }, [key, limit, offset, selector, registerObservedPath])

  const current = outcome?.key === key ? outcome : null
  return {
    page: current?.page ?? null,
    loading: current === null,
    error: current?.error ?? null,
    fetchedAtMs: current?.fetchedAtMs ?? 0,
    retry,
  }
}
