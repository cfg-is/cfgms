// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Tenant fetch hooks (Issue #3131).
 *
 * Endpoints covered:
 *   GET    /api/v1/tenants                            → useTenantList
 *   GET    /api/v1/tenants/{id}/delete                → (augments useTenantList for suspended tenants)
 *   POST   /api/v1/tenants                            → createTenant
 *   PUT    /api/v1/tenants/{id}                       → updateTenant
 *   POST   /api/v1/tenants/{id}/suspend               → suspendTenant (cascade, ADR-027 Decision 1)
 *   POST   /api/v1/tenants/{id}/restore               → restoreTenant (provenance-aware, ADR-027 Decision 2)
 *   POST   /api/v1/tenants/{id}/delete                → requestTenantDeletion (starts hold pipeline, ADR-027 Decision 3)
 *   DELETE /api/v1/tenants/{id}/delete                → cancelTenantDeletion
 *   POST   /api/v1/tenants/{id}/delete/approve        → approveTenantDeletion (dual-control, ADR-027 Decision 4)
 *
 * Security A9.1: tenant name/description values originate from user-supplied
 * content. All string fields are coerced via str(). Callers must render them
 * as text nodes only, never via dangerouslySetInnerHTML.
 *
 * Response shape: list endpoints return the standard { data: [...] } envelope.
 * Pending-deletion state is augmented per-tenant by querying
 * GET /api/v1/tenants/{id}/delete for directly-suspended tenants; 404 means
 * no pending deletion for that subtree root.
 */
import { useCallback, useEffect, useState } from 'react'
import { apiFetch } from '../api/client.ts'

// ── Primitive coercers ────────────────────────────────────────────────────────

function str(value: unknown): string {
  return typeof value === 'string' ? value : ''
}

function strOrNull(value: unknown): string | null {
  return typeof value === 'string' ? value : null
}

function strArr(value: unknown): string[] {
  if (!Array.isArray(value)) return []
  return value.filter((v): v is string => typeof v === 'string')
}

// ── Types ─────────────────────────────────────────────────────────────────────

export type TenantStatus = 'active' | 'suspended' | 'deleted'
export type DeletionState = 'hold' | 'eligible'

export interface PendingDeletionInfo {
  subtree_root_id: string
  requested_by: string
  requested_at: string
  eligible_at: string
  state: DeletionState
  pinned_member_ids: string[]
}

export interface TenantInfo {
  id: string
  name: string
  description: string
  parent_id: string
  status: TenantStatus
  directly_suspended: boolean
  cascade_suspended_from: string | null
  created_at: string
  updated_at: string
  pending_deletion?: PendingDeletionInfo | null
}

// ── Parse helpers ─────────────────────────────────────────────────────────────

export function parsePendingDeletion(value: unknown): PendingDeletionInfo | null {
  if (typeof value !== 'object' || value === null) return null
  const r = value as Record<string, unknown>
  const subtreeRootId = str(r.subtree_root_id)
  if (!subtreeRootId) return null
  const state = str(r.state)
  if (state !== 'hold' && state !== 'eligible') return null
  return {
    subtree_root_id: subtreeRootId,
    requested_by: str(r.requested_by),
    requested_at: str(r.requested_at),
    eligible_at: str(r.eligible_at),
    state,
    pinned_member_ids: strArr(r.pinned_member_ids),
  }
}

export function parseTenantInfo(value: unknown): TenantInfo | null {
  if (typeof value !== 'object' || value === null) return null
  const r = value as Record<string, unknown>
  const id = str(r.id)
  if (!id) return null
  const rawStatus = str(r.status)
  const status: TenantStatus =
    rawStatus === 'suspended' ? 'suspended' :
    rawStatus === 'deleted' ? 'deleted' :
    'active'
  return {
    id,
    name: str(r.name),
    description: str(r.description),
    parent_id: str(r.parent_id),
    status,
    directly_suspended: r.directly_suspended === true,
    cascade_suspended_from: strOrNull(r.cascade_suspended_from),
    created_at: str(r.created_at),
    updated_at: str(r.updated_at),
  }
}

export function parseTenantList(data: unknown): TenantInfo[] {
  if (!Array.isArray(data)) throw new Error('unexpected response shape')
  const list: TenantInfo[] = []
  for (const item of data) {
    const t = parseTenantInfo(item)
    if (t !== null) list.push(t)
  }
  return list
}

// ── Generic fetch outcome ─────────────────────────────────────────────────────

interface FetchOutcome<T> {
  key: string
  data?: T
  error?: string
  fetchedAtMs: number
}

// ── useTenantList ─────────────────────────────────────────────────────────────

export interface UseTenantListResult {
  tenants: TenantInfo[]
  loading: boolean
  error: string | null
  retry: () => void
}

/**
 * Fetch the full tenant list and augment directly-suspended tenants with their
 * pending-deletion state (GET /api/v1/tenants/{id}/delete). 404 from the
 * deletion endpoint means no pending deletion for that subtree root.
 */
export function useTenantList(): UseTenantListResult {
  const [attempt, setAttempt] = useState(0)
  const [outcome, setOutcome] = useState<FetchOutcome<TenantInfo[]> | null>(null)
  const retry = useCallback(() => setAttempt((n) => n + 1), [])
  const key = `tenants:${attempt}`

  useEffect(() => {
    let cancelled = false

    async function load() {
      // Fetch the flat tenant list.
      const response = await apiFetch('/api/v1/tenants')
      if (!response.ok) throw new Error(`GET /api/v1/tenants — ${response.status}`)
      const body: unknown = await response.json()
      const tenants = parseTenantList((body as Record<string, unknown> | null)?.data)
      if (cancelled) return

      // For directly-suspended tenants, try to fetch pending deletion state.
      // These tenants may be subtree roots with an in-progress deletion pipeline.
      // 404 means no pending deletion; any other error is silently ignored (the
      // tenant will render without deletion state rather than blocking the entire view).
      const suspended = tenants.filter((t) => t.directly_suspended)
      if (suspended.length > 0) {
        const deletionResults = await Promise.allSettled(
          suspended.map(async (t) => {
            const r = await apiFetch(`/api/v1/tenants/${encodeURIComponent(t.id)}/delete`)
            if (r.status === 404) return { id: t.id, pending: null }
            if (!r.ok) return { id: t.id, pending: null }
            const delBody: unknown = await r.json()
            const pending = parsePendingDeletion(
              (delBody as Record<string, unknown> | null)?.data ??
              (delBody as Record<string, unknown> | null),
            )
            return { id: t.id, pending }
          }),
        )
        if (cancelled) return

        const pendingByTenantId = new Map<string, PendingDeletionInfo | null>()
        for (const result of deletionResults) {
          if (result.status === 'fulfilled') {
            pendingByTenantId.set(result.value.id, result.value.pending)
          }
        }

        const augmented = tenants.map((t) => {
          if (pendingByTenantId.has(t.id)) {
            return { ...t, pending_deletion: pendingByTenantId.get(t.id) }
          }
          return t
        })
        setOutcome({ key, data: augmented, fetchedAtMs: Date.now() })
      } else {
        setOutcome({ key, data: tenants, fetchedAtMs: Date.now() })
      }
    }

    load().catch((cause: unknown) => {
      if (cancelled) return
      setOutcome({
        key,
        error:
          cause instanceof Error && cause.message
            ? cause.message
            : 'GET /api/v1/tenants — request failed',
        fetchedAtMs: Date.now(),
      })
    })

    return () => {
      cancelled = true
    }
  }, [key, attempt])

  const current = outcome?.key === key ? outcome : null
  return {
    tenants: current?.data ?? [],
    loading: current === null,
    error: current?.error ?? null,
    retry,
  }
}

// ── Mutation helpers ──────────────────────────────────────────────────────────

/**
 * Machine-readable code the controller returns when a deletion approval is
 * refused because the approver is the principal who requested it
 * (`handleApproveTenantDeletion` → 403 SAME_APPROVER). This is the authoritative
 * dual-control signal: the browser session never learns its own server-side
 * principal ID, so the server's verdict — not a client-side identity guess — is
 * what tells the UI a subtree is locked for this operator (ADR-027 Decision 4).
 */
export const errCodeSameApprover = 'SAME_APPROVER'

/**
 * Error carrying the controller's `{ error: { code, message } }` envelope so
 * callers can branch on the code instead of matching message text.
 */
export class TenantApiError extends Error {
  readonly code: string
  readonly status: number

  constructor(message: string, code: string, status: number) {
    super(message)
    this.name = 'TenantApiError'
    this.code = code
    this.status = status
  }
}

async function apiError(response: Response, fallback: string): Promise<TenantApiError> {
  const errBody = (await response.json().catch(() => ({}))) as Record<string, unknown>
  const envelope = errBody?.error as Record<string, unknown> | undefined
  const message =
    typeof envelope?.message === 'string' && envelope.message
      ? envelope.message
      : `${fallback} — ${response.status}`
  const code = typeof envelope?.code === 'string' ? envelope.code : ''
  return new TenantApiError(message, code, response.status)
}

// ── suspendTenant ─────────────────────────────────────────────────────────────

export interface SuspendResult {
  target: string
  newly_cascade_suspended: string[]
  already_suspended: string[]
}

function parseSuspendResult(data: unknown): SuspendResult {
  if (typeof data !== 'object' || data === null) return { target: '', newly_cascade_suspended: [], already_suspended: [] }
  const r = data as Record<string, unknown>
  return {
    target: str(r.target),
    newly_cascade_suspended: strArr(r.newly_cascade_suspended),
    already_suspended: strArr(r.already_suspended),
  }
}

/**
 * Cascade-suspend a tenant and its entire subtree (ADR-027 Decision 1).
 * Returns provenance-aware result listing which descendants were newly
 * cascade-suspended vs already independently suspended.
 */
export async function suspendTenant(id: string): Promise<SuspendResult> {
  const response = await apiFetch(`/api/v1/tenants/${encodeURIComponent(id)}/suspend`, {
    method: 'POST',
  })
  if (!response.ok) {
    throw await apiError(response, 'Suspend failed')
  }
  const body = (await response.json()) as Record<string, unknown>
  return parseSuspendResult(body.data ?? body)
}

// ── restoreTenant ─────────────────────────────────────────────────────────────

export interface RestoreResult {
  target: string
  restored: string[]
  still_suspended: string[]
}

function parseRestoreResult(data: unknown): RestoreResult {
  if (typeof data !== 'object' || data === null) return { target: '', restored: [], still_suspended: [] }
  const r = data as Record<string, unknown>
  return {
    target: str(r.target),
    restored: strArr(r.restored),
    still_suspended: strArr(r.still_suspended),
  }
}

/**
 * Restore a tenant and lift cascade-suspended state from its subtree (ADR-027 Decision 2).
 * Descendants that carry their own DirectlySuspended flag remain suspended.
 */
export async function restoreTenant(id: string): Promise<RestoreResult> {
  const response = await apiFetch(`/api/v1/tenants/${encodeURIComponent(id)}/restore`, {
    method: 'POST',
  })
  if (!response.ok) {
    throw await apiError(response, 'Restore failed')
  }
  const body = (await response.json()) as Record<string, unknown>
  return parseRestoreResult(body.data ?? body)
}

// ── createTenant ──────────────────────────────────────────────────────────────

export interface CreateTenantRequest {
  name: string
  description?: string
  parent_id?: string
}

export async function createTenant(req: CreateTenantRequest): Promise<TenantInfo> {
  const body: Record<string, unknown> = { name: req.name }
  if (req.description) body.description = req.description
  if (req.parent_id) body.parent_id = req.parent_id

  const response = await apiFetch('/api/v1/tenants', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!response.ok) {
    throw await apiError(response, 'Create failed')
  }
  const respBody = (await response.json()) as Record<string, unknown>
  const tenant = parseTenantInfo(respBody.data ?? respBody)
  if (tenant === null) throw new Error('Unexpected response shape from tenant create')
  return tenant
}

// ── updateTenant ──────────────────────────────────────────────────────────────

export interface UpdateTenantRequest {
  name?: string
  description?: string
}

export async function updateTenant(id: string, req: UpdateTenantRequest): Promise<TenantInfo> {
  const body: Record<string, unknown> = {}
  if (req.name !== undefined) body.name = req.name
  if (req.description !== undefined) body.description = req.description

  const response = await apiFetch(`/api/v1/tenants/${encodeURIComponent(id)}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!response.ok) {
    throw await apiError(response, 'Update failed')
  }
  const respBody = (await response.json()) as Record<string, unknown>
  const tenant = parseTenantInfo(respBody.data ?? respBody)
  if (tenant === null) throw new Error('Unexpected response shape from tenant update')
  return tenant
}

// ── requestTenantDeletion ─────────────────────────────────────────────────────

/**
 * Request deletion of a tenant's subtree (ADR-027 Decision 3, step 1: start hold).
 * The entire subtree must be fully suspended — if any descendant is not suspended,
 * the server rejects with a message naming the offending descendant.
 */
export async function requestTenantDeletion(id: string): Promise<PendingDeletionInfo> {
  const response = await apiFetch(`/api/v1/tenants/${encodeURIComponent(id)}/delete`, {
    method: 'POST',
  })
  if (!response.ok) {
    throw await apiError(response, 'Request deletion failed')
  }
  const body = (await response.json()) as Record<string, unknown>
  const pending = parsePendingDeletion(body.data ?? body)
  if (pending === null) throw new Error('Unexpected response shape from deletion request')
  return pending
}

// ── cancelTenantDeletion ──────────────────────────────────────────────────────

/**
 * Cancel a pending-deletion pipeline entry (ADR-027 Decision 4).
 * Returns the subtree to plain Suspended state.
 */
export async function cancelTenantDeletion(id: string): Promise<void> {
  const response = await apiFetch(`/api/v1/tenants/${encodeURIComponent(id)}/delete`, {
    method: 'DELETE',
  })
  if (!response.ok) {
    throw await apiError(response, 'Cancel deletion failed')
  }
}

// ── approveTenantDeletion ─────────────────────────────────────────────────────

/**
 * Approve and execute terminal deletion of a held-past-eligibility subtree
 * (ADR-027 Decision 3, step 4: dual-control terminal delete).
 * The server enforces that the approver must differ from the requester when
 * dual-control is enabled (config default: on).
 */
export async function approveTenantDeletion(id: string): Promise<string[]> {
  const response = await apiFetch(`/api/v1/tenants/${encodeURIComponent(id)}/delete/approve`, {
    method: 'POST',
  })
  if (!response.ok) {
    throw await apiError(response, 'Approve deletion failed')
  }
  const body = (await response.json()) as Record<string, unknown>
  const data = (body.data ?? body) as Record<string, unknown>
  return strArr(data.deleted_ids)
}
