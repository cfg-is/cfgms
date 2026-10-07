// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Tenant-crossing hooks and helpers (Issue #4588, ADR-025 Decision 2).
 *
 * Endpoints covered:
 *   GET    /api/v1/tenants/{id}/access-grants                  → useTenantCrossings
 *   POST   /api/v1/tenants/{id}/access-grants                  → createAccessGrant (MSP admin)
 *   POST   /api/v1/tenants/{id}/break-glass                    → requestBreakGlass (root operator)
 *   DELETE /api/v1/tenants/{id}/access-grants/{crossing_id}    → endCrossing
 *
 * The controller serialises business.TenantCrossing without JSON tags, so a
 * crossing arrives with Go field names (`ExpiresAt`); the parser also accepts
 * snake_case so a future tagged response keeps working.
 *
 * Banner persistence: a root operator cannot enumerate its own crossings (GET
 * access-grants on a walled tenant returns the crossing challenge), so the
 * break-glass response is kept in sessionStorage — non-secret — and
 * re-validated against the server on mount (useCrossingBanner).
 *
 * The justification is sent once and never held client-side beyond the
 * request; the only text kept is the server-echoed `reason` shown in the banner.
 */
import { useCallback, useEffect, useRef, useState } from 'react'
import { apiFetch } from '../api/client.ts'
import { TenantApiError } from './useTenants.ts'

// ── Server-fixed bounds (handlers_tenant_crossing.go) ─────────────────────────

export const justificationMinLen = 10
export const justificationMaxLen = 1000
export const breakGlassWindowMinutes = 30
export const grantMinMinutes = 1
export const grantMaxMinutes = 1440

/** Machine code of the 400 the controller returns for an empty principal_id. */
export const errCodeMissingPrincipalID = 'MISSING_PRINCIPAL_ID'
/** `error` value of the 401 crossing challenge body. */
export const crossingChallengeError = 'tenant_crossing_required'

// ── Types ─────────────────────────────────────────────────────────────────────

export type CrossingKind = 'grant' | 'break_glass' | string

export interface Crossing {
  id: string
  tenantId: string
  principalId: string
  kind: CrossingKind
  grantedBy: string
  justification: string
  createdAt: string
  expiresAt: string
  revokedAt: string | null
}

function pick(snake: unknown, pascal: unknown): unknown {
  return snake !== undefined ? snake : pascal
}

function s(value: unknown): string {
  return typeof value === 'string' ? value : ''
}

export function parseCrossing(value: unknown): Crossing | null {
  if (typeof value !== 'object' || value === null) return null
  const r = value as Record<string, unknown>
  const id = s(pick(r.id, r.ID))
  if (!id) return null
  const revoked = pick(r.revoked_at, r.RevokedAt)
  return {
    id,
    tenantId: s(pick(r.tenant_id, r.TenantID)),
    principalId: s(pick(r.principal_id, r.PrincipalID)),
    kind: s(pick(r.kind, r.Kind)),
    grantedBy: s(pick(r.granted_by, r.GrantedBy)),
    justification: s(pick(r.justification, r.Justification)),
    createdAt: s(pick(r.created_at, r.CreatedAt)),
    expiresAt: s(pick(r.expires_at, r.ExpiresAt)),
    revokedAt: typeof revoked === 'string' && revoked !== '' ? revoked : null,
  }
}

export function parseCrossingList(data: unknown): Crossing[] {
  if (!Array.isArray(data)) return []
  const out: Crossing[] = []
  for (const item of data) {
    const c = parseCrossing(item)
    if (c !== null) out.push(c)
  }
  return out
}

/** True while the crossing is neither revoked nor past its expiry. */
export function isCrossingActive(c: Crossing, nowMs: number): boolean {
  if (c.revokedAt !== null) return false
  const exp = Date.parse(c.expiresAt)
  return Number.isFinite(exp) && exp > nowMs
}

// ── Request helpers ───────────────────────────────────────────────────────────

async function crossingError(response: Response, fallback: string): Promise<TenantApiError> {
  const body = (await response.json().catch(() => ({}))) as Record<string, unknown>
  const raw = body?.error
  if (typeof raw === 'string') {
    // The crossing challenge: `{ "error": "tenant_crossing_required", ... }`.
    const message =
      raw === crossingChallengeError
        ? 'A break-glass crossing is required to reach this tenant.'
        : `${fallback} — ${response.status}`
    return new TenantApiError(message, raw, response.status)
  }
  const envelope = raw as Record<string, unknown> | undefined
  const message =
    typeof envelope?.message === 'string' && envelope.message
      ? envelope.message
      : `${fallback} — ${response.status}`
  const code = typeof envelope?.code === 'string' ? envelope.code : ''
  return new TenantApiError(message, code, response.status)
}

function crossingsPath(tenantId: string): string {
  return `/api/v1/tenants/${encodeURIComponent(tenantId)}/access-grants`
}

function unwrap(body: unknown): unknown {
  const r = body as Record<string, unknown> | null
  return r?.data ?? r
}

export async function listCrossings(tenantId: string): Promise<Crossing[]> {
  const response = await apiFetch(crossingsPath(tenantId))
  if (!response.ok) throw await crossingError(response, 'List access grants failed')
  return parseCrossingList(unwrap(await response.json()))
}

/** Break-glass: the justification travels only in the X-Justification header. */
export async function requestBreakGlass(tenantId: string, justification: string): Promise<Crossing> {
  const response = await apiFetch(`/api/v1/tenants/${encodeURIComponent(tenantId)}/break-glass`, {
    method: 'POST',
    headers: { 'X-Justification': justification },
  })
  if (!response.ok) throw await crossingError(response, 'Break-glass request failed')
  const crossing = parseCrossing(unwrap(await response.json()))
  if (crossing === null) throw new Error('Unexpected response shape from break-glass')
  return crossing
}

export interface CreateGrantRequest {
  principalId: string
  durationMinutes: number
  justification?: string
}

export async function createAccessGrant(tenantId: string, req: CreateGrantRequest): Promise<Crossing> {
  const body: Record<string, unknown> = {
    principal_id: req.principalId,
    duration_minutes: req.durationMinutes,
  }
  if (req.justification) body.justification = req.justification
  const response = await apiFetch(crossingsPath(tenantId), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!response.ok) throw await crossingError(response, 'Grant support access failed')
  const crossing = parseCrossing(unwrap(await response.json()))
  if (crossing === null) throw new Error('Unexpected response shape from access grant')
  return crossing
}

export async function endCrossing(tenantId: string, crossingId: string): Promise<void> {
  const response = await apiFetch(`${crossingsPath(tenantId)}/${encodeURIComponent(crossingId)}`, {
    method: 'DELETE',
  })
  if (!response.ok) throw await crossingError(response, 'End session failed')
}

// ── useTenantCrossings ────────────────────────────────────────────────────────

export interface UseTenantCrossingsResult {
  crossings: Crossing[]
  loading: boolean
  error: string | null
  refetch: () => void
}

interface ListOutcome {
  key: string
  data?: Crossing[]
  error?: string
}

/** Lists the crossings of `tenantId`; `null` disables the fetch. */
export function useTenantCrossings(tenantId: string | null, version = 0): UseTenantCrossingsResult {
  const [attempt, setAttempt] = useState(0)
  const [outcome, setOutcome] = useState<ListOutcome | null>(null)
  const refetch = useCallback(() => setAttempt((n) => n + 1), [])
  const key = `${tenantId ?? ''}:${attempt}:${version}`

  useEffect(() => {
    if (tenantId === null) return
    let cancelled = false
    listCrossings(tenantId).then(
      (data) => {
        if (!cancelled) setOutcome({ key, data })
      },
      (cause: unknown) => {
        if (cancelled) return
        setOutcome({
          key,
          error: cause instanceof Error && cause.message ? cause.message : 'Request failed',
        })
      },
    )
    return () => {
      cancelled = true
    }
  }, [key, tenantId])

  if (tenantId === null) return { crossings: [], loading: false, error: null, refetch }
  const current = outcome?.key === key ? outcome : null
  return {
    crossings: current?.data ?? [],
    loading: current === null,
    error: current?.error ?? null,
    refetch,
  }
}

// ── Persisted banner state ────────────────────────────────────────────────────

export interface BannerEntry {
  tenantId: string
  crossingId: string
  expiresAt: string
  reason: string
}

export const bannerStorageKey = 'cfgms.tenants.crossingBanner'

export function readBannerEntry(): BannerEntry | null {
  try {
    const raw = window.sessionStorage.getItem('cfgms.tenants.crossingBanner')
    if (raw === null) return null
    const v = JSON.parse(raw) as Record<string, unknown>
    if (typeof v.tenantId !== 'string' || typeof v.crossingId !== 'string' || typeof v.expiresAt !== 'string') {
      return null
    }
    return {
      tenantId: v.tenantId,
      crossingId: v.crossingId,
      expiresAt: v.expiresAt,
      reason: typeof v.reason === 'string' ? v.reason : '',
    }
  } catch {
    return null
  }
}

function writeBannerEntry(entry: BannerEntry | null): void {
  try {
    if (entry === null) window.sessionStorage.removeItem('cfgms.tenants.crossingBanner')
    else window.sessionStorage.setItem('cfgms.tenants.crossingBanner', JSON.stringify(entry))
  } catch {
    // Storage unavailable (private mode / quota): the banner just won't survive a reload.
  }
}

export function entryFromCrossing(c: Crossing): BannerEntry {
  return { tenantId: c.tenantId, crossingId: c.id, expiresAt: c.expiresAt, reason: c.justification }
}

export interface UseCrossingBannerResult {
  entry: BannerEntry | null
  /** Adopt a freshly invoked break-glass crossing and persist it. */
  adopt: (c: Crossing) => void
  /** Re-check the crossing with the server; drops the entry unless still active. */
  revalidate: () => void
  /** Drop the entry (after End session). */
  clear: () => void
}

/**
 * Banner state for the operator's own active break-glass crossing. On mount a
 * persisted entry is re-validated with GET access-grants and dropped when the
 * crossing is expired, revoked or not found.
 */
export function useCrossingBanner(): UseCrossingBannerResult {
  const [entry, setEntry] = useState<BannerEntry | null>(() => readBannerEntry())
  const entryRef = useRef(entry)
  useEffect(() => {
    entryRef.current = entry
  }, [entry])

  const drop = useCallback(() => {
    writeBannerEntry(null)
    setEntry(null)
  }, [])

  const validate = useCallback(
    (target: BannerEntry, isCancelled: () => boolean, dropOnError: boolean) => {
      listCrossings(target.tenantId).then(
        (list) => {
          if (isCancelled()) return
          const match = list.find((c) => c.id === target.crossingId)
          if (match === undefined || !isCrossingActive(match, Date.now())) {
            drop()
            return
          }
          const next = entryFromCrossing(match)
          next.reason = match.justification || target.reason
          writeBannerEntry(next)
          setEntry(next)
        },
        (cause: unknown) => {
          if (isCancelled()) return
          // Not found → gone. On mount any other failure (network blip) keeps the
          // entry; at countdown zero the entry is already expired, so it goes too.
          if (dropOnError || (cause instanceof TenantApiError && cause.status === 404)) drop()
        },
      )
    },
    [drop],
  )

  useEffect(() => {
    const persisted = readBannerEntry()
    if (persisted === null) return
    let cancelled = false
    validate(persisted, () => cancelled, false)
    return () => {
      cancelled = true
    }
  }, [validate])

  const adopt = useCallback((c: Crossing) => {
    const next = entryFromCrossing(c)
    writeBannerEntry(next)
    setEntry(next)
  }, [])

  const revalidate = useCallback(() => {
    const current = entryRef.current
    if (current === null) return
    // Past its expiry by the server's own timestamp: the refetch decides, and
    // anything not confirmed active is dropped.
    validate(current, () => false, true)
  }, [validate])

  return { entry, adopt, revalidate, clear: drop }
}
