// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Web account fetch hooks (Issue #2733, #3133).
 *
 * Endpoints covered:
 *   GET    /api/v1/web/accounts          → useWebAccountList
 *   GET    /api/v1/rbac/roles            → useRoleList
 *   GET    /api/v1/rbac/permissions      → usePermissionList
 *   POST   /api/v1/rbac/roles            → createRole
 *   PUT    /api/v1/rbac/roles/{id}       → updateRole
 *   DELETE /api/v1/rbac/roles/{id}       → deleteRole
 *
 * Security A9.1: username/role name/description values originate from
 * user-supplied content. All string fields are coerced via str(). Callers
 * must render them as text nodes only, never via dangerouslySetInnerHTML.
 *
 * M-AUTH-2: role create/update/delete are sensitive operations. Each carries
 * an operator justification in the X-Justification header — the controller
 * rejects the operation and records an audit failure without one.
 *
 * Response shape: list endpoints return the standard { data: [...] }
 * envelope, matching writeSuccessResponse in the server.
 */
import { useCallback, useEffect, useState } from 'react'
import { apiFetch } from '../api/client.ts'

// ── Primitive coercers ────────────────────────────────────────────────────────

function str(value: unknown): string {
  return typeof value === 'string' ? value : ''
}

function strArr(value: unknown): string[] {
  if (!Array.isArray(value)) return []
  return value.filter((v): v is string => typeof v === 'string')
}

// ── Types ─────────────────────────────────────────────────────────────────────

export interface WebAccountInfo {
  id: string
  username: string
  tenant_id: string
  permissions: string[]
  created_at: string
}

export interface RoleInfo {
  id: string
  name: string
  description: string
  permissions: string[]
  tenant_id: string
  created_at: string
  updated_at: string
}

export interface PermissionInfo {
  id: string
  name: string
  description: string
  resource_type: string
  actions: string[]
}

// ── Parse helpers ─────────────────────────────────────────────────────────────

export function parseWebAccountInfo(value: unknown): WebAccountInfo | null {
  if (typeof value !== 'object' || value === null) return null
  const r = value as Record<string, unknown>
  const id = str(r.id)
  if (!id) return null
  return {
    id,
    username: str(r.username),
    tenant_id: str(r.tenant_id),
    permissions: strArr(r.permissions),
    created_at: str(r.created_at),
  }
}

export function parseWebAccountList(data: unknown): WebAccountInfo[] {
  if (!Array.isArray(data)) throw new Error('unexpected response shape')
  const list: WebAccountInfo[] = []
  for (const item of data) {
    const a = parseWebAccountInfo(item)
    if (a !== null) list.push(a)
  }
  return list
}

export function parseRoleInfo(value: unknown): RoleInfo | null {
  if (typeof value !== 'object' || value === null) return null
  const r = value as Record<string, unknown>
  const id = str(r.id)
  if (!id) return null
  return {
    id,
    name: str(r.name),
    description: str(r.description),
    permissions: strArr(r.permissions),
    tenant_id: str(r.tenant_id),
    created_at: str(r.created_at),
    updated_at: str(r.updated_at),
  }
}

export function parseRoleList(data: unknown): RoleInfo[] {
  if (!Array.isArray(data)) throw new Error('unexpected response shape')
  const list: RoleInfo[] = []
  for (const item of data) {
    const r = parseRoleInfo(item)
    if (r !== null) list.push(r)
  }
  return list
}

export function parsePermissionInfo(value: unknown): PermissionInfo | null {
  if (typeof value !== 'object' || value === null) return null
  const r = value as Record<string, unknown>
  const id = str(r.id)
  if (!id) return null
  return {
    id,
    name: str(r.name),
    description: str(r.description),
    resource_type: str(r.resource_type),
    actions: strArr(r.actions),
  }
}

export function parsePermissionList(data: unknown): PermissionInfo[] {
  if (!Array.isArray(data)) throw new Error('unexpected response shape')
  const list: PermissionInfo[] = []
  for (const item of data) {
    const p = parsePermissionInfo(item)
    if (p !== null) list.push(p)
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

// ── useWebAccountList ─────────────────────────────────────────────────────────

export interface UseWebAccountListResult {
  accounts: WebAccountInfo[]
  loading: boolean
  error: string | null
  retry: () => void
}

export function useWebAccountList(): UseWebAccountListResult {
  const [attempt, setAttempt] = useState(0)
  const [outcome, setOutcome] = useState<FetchOutcome<WebAccountInfo[]> | null>(null)
  const retry = useCallback(() => setAttempt((n) => n + 1), [])
  const key = `web-accounts:${attempt}`

  useEffect(() => {
    let cancelled = false
    apiFetch('/api/v1/web/accounts')
      .then(async (response) => {
        if (!response.ok)
          throw new Error(`GET /api/v1/web/accounts — ${response.status}`)
        const body: unknown = await response.json()
        const parsed = parseWebAccountList(
          (body as Record<string, unknown> | null)?.data,
        )
        if (cancelled) return
        setOutcome({ key, data: parsed, fetchedAtMs: Date.now() })
      })
      .catch((cause: unknown) => {
        if (cancelled) return
        setOutcome({
          key,
          error:
            cause instanceof Error && cause.message
              ? cause.message
              : 'GET /api/v1/web/accounts — request failed',
          fetchedAtMs: Date.now(),
        })
      })
    return () => {
      cancelled = true
    }
  }, [key, attempt])

  const current = outcome?.key === key ? outcome : null
  return {
    accounts: current?.data ?? [],
    loading: current === null,
    error: current?.error ?? null,
    retry,
  }
}

// ── useRoleList ───────────────────────────────────────────────────────────────

export interface UseRoleListResult {
  roles: RoleInfo[]
  loading: boolean
  error: string | null
  retry: () => void
}

export function useRoleList(): UseRoleListResult {
  const [attempt, setAttempt] = useState(0)
  const [outcome, setOutcome] = useState<FetchOutcome<RoleInfo[]> | null>(null)
  const retry = useCallback(() => setAttempt((n) => n + 1), [])
  const key = `roles:${attempt}`

  useEffect(() => {
    let cancelled = false
    apiFetch('/api/v1/rbac/roles')
      .then(async (response) => {
        if (!response.ok)
          throw new Error(`GET /api/v1/rbac/roles — ${response.status}`)
        const body: unknown = await response.json()
        const parsed = parseRoleList(
          (body as Record<string, unknown> | null)?.data,
        )
        if (cancelled) return
        setOutcome({ key, data: parsed, fetchedAtMs: Date.now() })
      })
      .catch((cause: unknown) => {
        if (cancelled) return
        setOutcome({
          key,
          error:
            cause instanceof Error && cause.message
              ? cause.message
              : 'GET /api/v1/rbac/roles — request failed',
          fetchedAtMs: Date.now(),
        })
      })
    return () => {
      cancelled = true
    }
  }, [key, attempt])

  const current = outcome?.key === key ? outcome : null
  return {
    roles: current?.data ?? [],
    loading: current === null,
    error: current?.error ?? null,
    retry,
  }
}

// ── usePermissionList ─────────────────────────────────────────────────────────

export interface UsePermissionListResult {
  permissions: PermissionInfo[]
  loading: boolean
  error: string | null
}

export function usePermissionList(): UsePermissionListResult {
  const [outcome, setOutcome] = useState<FetchOutcome<PermissionInfo[]> | null>(null)
  const key = 'permissions:0'

  useEffect(() => {
    let cancelled = false
    apiFetch('/api/v1/rbac/permissions')
      .then(async (response) => {
        if (!response.ok)
          throw new Error(`GET /api/v1/rbac/permissions — ${response.status}`)
        const body: unknown = await response.json()
        const parsed = parsePermissionList(
          (body as Record<string, unknown> | null)?.data,
        )
        if (cancelled) return
        setOutcome({ key, data: parsed, fetchedAtMs: Date.now() })
      })
      .catch((cause: unknown) => {
        if (cancelled) return
        setOutcome({
          key,
          error:
            cause instanceof Error && cause.message
              ? cause.message
              : 'GET /api/v1/rbac/permissions — request failed',
          fetchedAtMs: Date.now(),
        })
      })
    return () => {
      cancelled = true
    }
  }, [key])

  const current = outcome?.key === key ? outcome : null
  return {
    permissions: current?.data ?? [],
    loading: current === null,
    error: current?.error ?? null,
  }
}

// ── Justification (M-AUTH-2) ──────────────────────────────────────────────────

/** Server floor: features/rbac/sensitive_operations.go rejects shorter values. */
export const JUSTIFICATION_MIN_LENGTH = 10
/** Server ceiling: features/rbac/sensitive_operations.go rejects longer values. */
export const JUSTIFICATION_MAX_LENGTH = 1000

/**
 * Validate an operator-supplied justification against the same bounds the
 * controller enforces, returning an operator-facing message or null when valid.
 *
 * M-AUTH-2: role create/update/delete are sensitive operations. The RBAC
 * manager rejects them before any store write unless a justification of
 * 10–1000 characters is present, and records it on the audit event. Checking
 * here keeps the feedback specific instead of surfacing a generic 500.
 *
 * The value travels as an HTTP header, so it must also be a valid header
 * value: no control characters (header injection / request splitting) and no
 * code points above U+00FF (the fetch Headers ByteString limit — a pasted
 * smart quote would otherwise throw inside apiFetch).
 */
export function validateJustification(justification: string): string | null {
  const trimmed = justification.trim()
  if (trimmed.length === 0) return 'Justification is required'
  if (trimmed.length < JUSTIFICATION_MIN_LENGTH)
    return `Justification must be at least ${JUSTIFICATION_MIN_LENGTH} characters`
  if (trimmed.length > JUSTIFICATION_MAX_LENGTH)
    return `Justification must be at most ${JUSTIFICATION_MAX_LENGTH} characters`
  if (/[^\x20-\x7E\xA0-\xFF]/.test(trimmed))
    return 'Justification must use plain text characters only'
  return null
}

/**
 * Build the request headers for a role mutation, throwing when the
 * justification is unusable so no request leaves the browser without one.
 */
function mutationHeaders(justification: string, withBody: boolean): Headers {
  const invalid = validateJustification(justification)
  if (invalid !== null) throw new Error(invalid)
  const headers = new Headers({ 'X-Justification': justification.trim() })
  if (withBody) headers.set('Content-Type', 'application/json')
  return headers
}

// ── Role mutations ────────────────────────────────────────────────────────────

/*
 * No tenant_id is sent by any role mutation: the caller's tenant is authoritative
 * only on the server, which derives it from the session context
 * (handlers_rbac.go — callerTenantForRole) and rejects a mismatched body value
 * with 403 TENANT_MISMATCH. A browser-supplied tenant would be a cross-tenant
 * write vector, so the client never sends one.
 */
export async function createRole(
  name: string,
  description: string,
  permissionIds: string[],
  justification: string,
): Promise<void> {
  const response = await apiFetch('/api/v1/rbac/roles', {
    method: 'POST',
    headers: mutationHeaders(justification, true),
    body: JSON.stringify({ name, description, permissions: permissionIds }),
  })
  if (!response.ok) {
    const errBody = (await response.json().catch(() => ({}))) as Record<string, unknown>
    const errMsg =
      (errBody?.error as Record<string, unknown>)?.message as string ||
      `Create failed — ${response.status}`
    throw new Error(errMsg)
  }
}

/*
 * The role's tenant attribution survives the edit without the client sending it:
 * handleUpdateRole loads the stored role, refuses the write when it belongs to
 * another tenant (404) or is a system role (403), and carries the stored
 * tenant_id — plus hierarchy links and creation time — into the replacement
 * record itself.
 */
export async function updateRole(
  id: string,
  name: string,
  description: string,
  permissionIds: string[],
  justification: string,
): Promise<void> {
  const response = await apiFetch(`/api/v1/rbac/roles/${encodeURIComponent(id)}`, {
    method: 'PUT',
    headers: mutationHeaders(justification, true),
    body: JSON.stringify({ name, description, permissions: permissionIds }),
  })
  if (!response.ok) {
    const errBody = (await response.json().catch(() => ({}))) as Record<string, unknown>
    const errMsg =
      (errBody?.error as Record<string, unknown>)?.message as string ||
      `Update failed — ${response.status}`
    throw new Error(errMsg)
  }
}

export async function deleteRole(id: string, justification: string): Promise<void> {
  const response = await apiFetch(`/api/v1/rbac/roles/${encodeURIComponent(id)}`, {
    method: 'DELETE',
    headers: mutationHeaders(justification, false),
  })
  if (!response.ok) {
    const errBody = (await response.json().catch(() => ({}))) as Record<string, unknown>
    const errMsg =
      (errBody?.error as Record<string, unknown>)?.message as string ||
      `Delete failed — ${response.status}`
    throw new Error(errMsg)
  }
}
