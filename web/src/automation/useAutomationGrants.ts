// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Automation grant hooks (Issue #5855, Epic #5421).
 *
 * Endpoints covered:
 *   GET    /api/v1/automation/grants        → useAutomationGrantList (automation-grant:read)
 *   POST   /api/v1/automation/grants        → createAutomationGrant (Strong step-up + presence tap)
 *   DELETE /api/v1/automation/grants/{id}   → revokeAutomationGrant (Strong step-up, no tap)
 *
 * Step-up and the presence tap are handled transparently by the apiFetch
 * interceptor (StepUpModal); this module never reads or sends a presence token.
 *
 * Security A9.1: every wire value is coerced through a parse* validator and must
 * be rendered as JSX text only. The list shape has no credential field; the create
 * response's `credential` is read only by parseAutomationGrantCreateResult and
 * handed to the caller, which holds it in component state alone.
 */
import { useCallback, useEffect, useState } from 'react'
import { apiFetch, unwrapEnvelope } from '../api/client.ts'

const grantsPath = '/api/v1/automation/grants'

/**
 * Longest lifetime the controller accepts for a grant (MaxGrantLifetime in
 * features/controller/api/automation_grant_store.go). The controller enforces it;
 * the create dialog only shows it.
 */
export const maxGrantLifetimeDays = 90

export type AutomationGrantStatus = 'active' | 'expired' | 'revoked'

export interface AutomationGrant {
  id: string
  tenant_id: string
  name: string
  created_by: string
  created_at: string
  expires_at: string
  revoked_at: string | null
  revoked_by: string
}

export interface AutomationGrantCreateResult {
  grant: AutomationGrant
  /** The one-time credential. Never persisted by this module. */
  credential: string
}

export interface AutomationGrantCreateInput {
  name: string
  /** Empty means the caller's own tenant (the controller's default). */
  tenantId: string
  /** RFC 3339 timestamp. */
  expiresAt: string
}

function str(value: unknown): string {
  return typeof value === 'string' ? value : ''
}

export function parseAutomationGrant(value: unknown): AutomationGrant | null {
  if (typeof value !== 'object' || value === null) return null
  const r = value as Record<string, unknown>
  const id = str(r.id)
  if (!id) return null
  return {
    id,
    tenant_id: str(r.tenant_id),
    name: str(r.name),
    created_by: str(r.created_by),
    created_at: str(r.created_at),
    expires_at: str(r.expires_at),
    revoked_at: typeof r.revoked_at === 'string' && r.revoked_at ? r.revoked_at : null,
    revoked_by: str(r.revoked_by),
  }
}

/** Accepts the list payload `{ grants, count }`; null/absent grants is an empty list. */
export function parseAutomationGrantList(data: unknown): AutomationGrant[] {
  if (data === null || data === undefined) return []
  if (typeof data !== 'object' || Array.isArray(data)) throw new Error('unexpected response shape')
  const grants = (data as Record<string, unknown>).grants
  if (grants === null || grants === undefined) return []
  if (!Array.isArray(grants)) throw new Error('unexpected response shape')
  const list: AutomationGrant[] = []
  for (const item of grants) {
    const parsed = parseAutomationGrant(item)
    if (parsed !== null) list.push(parsed)
  }
  return list
}

export function parseAutomationGrantCreateResult(data: unknown): AutomationGrantCreateResult | null {
  if (typeof data !== 'object' || data === null) return null
  const r = data as Record<string, unknown>
  const grant = parseAutomationGrant(r.grant)
  const credential = str(r.credential)
  if (grant === null || !credential) return null
  return { grant, credential }
}

/**
 * Status from the server fields alone: a revocation wins over expiry, and a grant
 * whose expiry is unreadable is not reported active.
 */
export function grantStatus(grant: AutomationGrant, now: number = Date.now()): AutomationGrantStatus {
  if (grant.revoked_at !== null) return 'revoked'
  const expires = Date.parse(grant.expires_at)
  if (Number.isNaN(expires) || expires <= now) return 'expired'
  return 'active'
}

/**
 * Converts a date-input value (YYYY-MM-DD) to the RFC 3339 instant the grant
 * expires at: 00:00 UTC on that date. Returns '' for anything else.
 */
export function expiryFromDate(date: string): string {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return ''
  const parsed = new Date(`${date}T00:00:00Z`)
  return Number.isNaN(parsed.getTime()) ? '' : parsed.toISOString()
}

/** Latest date (YYYY-MM-DD, UTC) whose 00:00 UTC expiry is within the controller cap. */
export function latestExpiryDate(now: number = Date.now()): string {
  return new Date(now + maxGrantLifetimeDays * 24 * 60 * 60 * 1000).toISOString().slice(0, 10)
}

async function failureMessage(response: Response, fallback: string): Promise<string> {
  const body = (await response.json().catch(() => ({}))) as Record<string, unknown> | null
  const err = body?.error
  if (typeof err === 'string' && err) return err
  if (typeof err === 'object' && err !== null) {
    const message = (err as Record<string, unknown>).message
    if (typeof message === 'string' && message) return message
  }
  return `${fallback} — ${response.status}`
}

export interface UseAutomationGrantListResult {
  grants: AutomationGrant[]
  loading: boolean
  error: string | null
  retry: () => void
}

interface Outcome {
  key: string
  data?: AutomationGrant[]
  error?: string
}

export function useAutomationGrantList(): UseAutomationGrantListResult {
  const [attempt, setAttempt] = useState(0)
  const [outcome, setOutcome] = useState<Outcome | null>(null)
  const retry = useCallback(() => setAttempt((n) => n + 1), [])
  const key = `automation-grants:${attempt}`

  useEffect(() => {
    let cancelled = false
    apiFetch(grantsPath)
      .then(async (response) => {
        if (!response.ok) throw new Error(`GET ${grantsPath} — ${response.status}`)
        const parsed = parseAutomationGrantList(unwrapEnvelope<unknown>(await response.json()))
        if (cancelled) return
        setOutcome({ key, data: parsed })
      })
      .catch((cause: unknown) => {
        if (cancelled) return
        setOutcome({
          key,
          error:
            cause instanceof Error && cause.message ? cause.message : `GET ${grantsPath} — request failed`,
        })
      })
    return () => {
      cancelled = true
    }
  }, [key])

  const current = outcome?.key === key ? outcome : null
  return {
    grants: current?.data ?? [],
    loading: current === null,
    error: current?.error ?? null,
    retry,
  }
}

export async function createAutomationGrant(
  input: AutomationGrantCreateInput,
): Promise<AutomationGrantCreateResult> {
  const body: Record<string, string> = { name: input.name, expires_at: input.expiresAt }
  if (input.tenantId !== '') body.tenant_id = input.tenantId
  const response = await apiFetch(grantsPath, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!response.ok) throw new Error(await failureMessage(response, 'Create failed'))
  const result = parseAutomationGrantCreateResult(unwrapEnvelope<unknown>(await response.json()))
  if (result === null) throw new Error('Unexpected response shape from automation grant create')
  return result
}

export async function revokeAutomationGrant(id: string): Promise<void> {
  const response = await apiFetch(`${grantsPath}/${encodeURIComponent(id)}`, { method: 'DELETE' })
  if (!response.ok) throw new Error(await failureMessage(response, 'Revoke failed'))
}
