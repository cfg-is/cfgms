// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Tenant-crossing hooks and helpers (Issue #4588, ADR-025 Decision 2).
 *
 * Endpoints covered:
 *   GET    /api/v1/tenants/{id}/access-grants                  → useTenantCrossings
 *   POST   /api/v1/tenants/{id}/access-grants                  → createAccessGrant (MSP admin)
 *   POST   /api/v1/tenants/{id}/break-glass                    → requestBreakGlass (root operator)
 *   GET    /api/v1/tenant-crossings/active                     → fetchActiveCrossings
 *   DELETE /api/v1/tenants/{id}/access-grants/{crossing_id}    → endCrossing
 *
 * The controller serialises a crossing with snake_case keys (`expires_at`); the
 * parser also accepts the Go field names (`ExpiresAt`) and coerces every string.
 *
 * The justification is sent once and never held client-side beyond the request.
 * Nothing about a crossing is kept in browser storage; the shell's elevation
 * banner reads the active feed (shell/useActiveCrossings.ts).
 */
import { useCallback, useEffect, useState } from 'react'
import { apiFetch } from '../api/client.ts'
import { TenantApiError } from './useTenants.ts'

// ── Server-fixed bounds (handlers_tenant_crossing.go) ─────────────────────────

export const justificationMinLen = 10
export const justificationMaxLen = 1000
export const breakGlassWindowMinutes = 30

/** `error` value of the 401 crossing challenge body. */
export const crossingChallengeError = 'tenant_crossing_required'

// ── Types ─────────────────────────────────────────────────────────────────────

export type CrossingKind = 'grant' | 'break_glass' | string

export interface Crossing {
  id: string
  tenantId: string
  principalId: string
  kind: CrossingKind
  /** Break-glass invoker's display name (best effort); empty for a grant. */
  principalName: string
  grantedBy: string
  justification: string
  createdAt: string
  expiresAt: string
  revokedAt: string | null
  /** Break-glass reason category; empty for a grant. */
  reasonCategory: string
  /** `approved` or `pending` (awaiting a second approver); empty when the server omits it. */
  approvalState: string
  /** Server-derived: `active`, `pending`, `expired` or `revoked`; empty when the server omits it. */
  status: string
}

/** Break-glass reason categories with the plain-words labels the prompt shows. */
export const breakGlassReasons: ReadonlyArray<{ value: string; label: string }> = [
  { value: 'account_recovery', label: 'Account recovery: the MSP is locked out' },
  { value: 'security_incident', label: 'Security incident' },
  { value: 'legal_request', label: 'Legal request' },
  { value: 'billing_dispute', label: 'Billing dispute' },
]

/** `approval_state` of a break-glass awaiting a second approver. */
export const approvalStatePending = 'pending'

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
    principalName: s(pick(r.principal_name, r.PrincipalName)),
    kind: s(pick(r.kind, r.Kind)),
    grantedBy: s(pick(r.granted_by, r.GrantedBy)),
    justification: s(pick(r.justification, r.Justification)),
    createdAt: s(pick(r.created_at, r.CreatedAt)),
    expiresAt: s(pick(r.expires_at, r.ExpiresAt)),
    revokedAt: typeof revoked === 'string' && revoked !== '' ? revoked : null,
    reasonCategory: s(pick(r.reason_category, r.ReasonCategory)),
    approvalState: s(pick(r.approval_state, r.ApprovalState)),
    status: s(pick(r.status, r.Status)),
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

export interface BreakGlassRequest {
  reasonCategory: string
  justification: string
}

/** Break-glass: reason category and justification travel in the JSON body. */
export async function requestBreakGlass(tenantId: string, req: BreakGlassRequest): Promise<Crossing> {
  const response = await apiFetch(`/api/v1/tenants/${encodeURIComponent(tenantId)}/break-glass`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ reason_category: req.reasonCategory, justification: req.justification }),
  })
  if (!response.ok) throw await crossingError(response, 'Break-glass request failed')
  const crossing = parseCrossing(unwrap(await response.json()))
  if (crossing === null) throw new Error('Unexpected response shape from break-glass')
  return crossing
}

/** One entry of the active-crossings feed: a crossing plus its tenant's display name. */
export interface ActiveCrossing extends Crossing {
  /** Filled by the server only for tenants visible to the caller; empty otherwise. */
  tenantName: string
}

/** Parses the GET /api/v1/tenant-crossings/active payload; malformed entries are dropped. */
export function parseActiveCrossingList(data: unknown): ActiveCrossing[] {
  if (!Array.isArray(data)) return []
  const out: ActiveCrossing[] = []
  for (const item of data) {
    const c = parseCrossing(item)
    if (c === null) continue
    const name = (item as Record<string, unknown>).tenant_name
    out.push({ ...c, tenantName: typeof name === 'string' ? name : '' })
  }
  return out
}

/** One GET of the active-crossings feed (approved, unexpired, unrevoked crossings the caller may see). */
export async function fetchActiveCrossings(): Promise<ActiveCrossing[]> {
  const response = await apiFetch('/api/v1/tenant-crossings/active')
  if (!response.ok) throw await crossingError(response, 'List active crossings failed')
  return parseActiveCrossingList(unwrap(await response.json()))
}

/** A grant names no person: it opens the tenant to all root support for the duration. */
export interface CreateGrantRequest {
  durationMinutes: number
}

export async function createAccessGrant(tenantId: string, req: CreateGrantRequest): Promise<Crossing> {
  const response = await apiFetch(crossingsPath(tenantId), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ duration_minutes: req.durationMinutes }),
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
