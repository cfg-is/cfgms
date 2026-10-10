// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Administrator notification contacts for the Support access page (Issue #4724).
 *
 * Endpoints covered:
 *   GET /api/v1/tenants/{id}/admin-contacts  → fetchAdminContacts / useAdminContacts
 *   PUT /api/v1/tenants/{id}/admin-contacts  → saveAdminContacts (step-up gated)
 *
 * Grant list, issue and revoke live in useTenantCrossings.ts. A refused PUT keeps
 * the server's message (INVALID_CONTACTS names the offending address); a cancelled
 * step-up ceremony comes back as the original 401, which the page words itself.
 */
import { useCallback, useEffect, useState } from 'react'
import { apiFetch } from '../api/client.ts'
import { TenantApiError } from './useTenants.ts'

/** Parses the `{ contacts: [...] }` payload; every entry is coerced to a string and blanks dropped. */
export function parseAdminContacts(data: unknown): string[] {
  const body = data as Record<string, unknown> | null
  const list = typeof body === 'object' && body !== null ? body.contacts : null
  if (!Array.isArray(list)) return []
  const out: string[] = []
  for (const item of list) {
    if (typeof item === 'string' && item !== '') out.push(item)
  }
  return out
}

async function contactsError(response: Response, fallback: string): Promise<TenantApiError> {
  const body = (await response.json().catch(() => ({}))) as Record<string, unknown> | null
  const envelope = body?.error as Record<string, unknown> | undefined
  const message =
    typeof envelope?.message === 'string' && envelope.message
      ? envelope.message
      : `${fallback} — ${response.status}`
  const code = typeof envelope?.code === 'string' ? envelope.code : ''
  return new TenantApiError(message, code, response.status)
}

function contactsPath(tenantId: string): string {
  return `/api/v1/tenants/${encodeURIComponent(tenantId)}/admin-contacts`
}

function unwrap(body: unknown): unknown {
  const r = body as Record<string, unknown> | null
  return r?.data ?? r
}

export async function fetchAdminContacts(tenantId: string): Promise<string[]> {
  const response = await apiFetch(contactsPath(tenantId))
  if (!response.ok) throw await contactsError(response, 'Load contacts failed')
  return parseAdminContacts(unwrap(await response.json()))
}

/** Replaces the whole list; resolves with the list the server stored. */
export async function saveAdminContacts(tenantId: string, contacts: string[]): Promise<string[]> {
  const response = await apiFetch(contactsPath(tenantId), {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ contacts }),
  })
  if (!response.ok) throw await contactsError(response, 'Save contacts failed')
  return parseAdminContacts(unwrap(await response.json()))
}

export interface UseAdminContactsResult {
  contacts: string[]
  loading: boolean
  error: string | null
  refetch: () => void
}

interface Outcome {
  key: string
  data?: string[]
  error?: string
}

/** Loads the contacts of `tenantId`; `null` disables the fetch. */
export function useAdminContacts(tenantId: string | null): UseAdminContactsResult {
  const [attempt, setAttempt] = useState(0)
  const [outcome, setOutcome] = useState<Outcome | null>(null)
  const refetch = useCallback(() => setAttempt((n) => n + 1), [])
  const key = `${tenantId ?? ''}:${attempt}`

  useEffect(() => {
    if (tenantId === null) return
    let cancelled = false
    fetchAdminContacts(tenantId).then(
      (data) => {
        if (!cancelled) setOutcome({ key, data })
      },
      (cause: unknown) => {
        if (cancelled) return
        setOutcome({ key, error: cause instanceof Error && cause.message ? cause.message : 'Request failed' })
      },
    )
    return () => {
      cancelled = true
    }
  }, [key, tenantId])

  if (tenantId === null) return { contacts: [], loading: false, error: null, refetch }
  const current = outcome?.key === key ? outcome : null
  return { contacts: current?.data ?? [], loading: current === null, error: current?.error ?? null, refetch }
}
