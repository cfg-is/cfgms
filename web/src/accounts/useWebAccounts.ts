// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Web account fetch hooks (Issue #2733).
 *
 * Endpoints covered:
 *   GET  /api/v1/web/accounts   → useWebAccountList
 *
 * Security A9.1: username values originate from user-supplied content.
 * All string fields are coerced via str(). Callers must render them as
 * text nodes only, never via dangerouslySetInnerHTML.
 *
 * Response shape: the list endpoint returns the standard { data: [...] }
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
