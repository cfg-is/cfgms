// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * API key hooks (Issue #5441, Epic #5300).
 *
 * Endpoints covered:
 *   GET    /api/v1/api-keys        → useApiKeyList (api-key:list)
 *   POST   /api/v1/api-keys        → createApiKey (Strong step-up, no presence)
 *   DELETE /api/v1/api-keys/{id}   → deleteApiKey (Strong step-up, no presence)
 *
 * Step-up is handled transparently by the apiFetch interceptor.
 *
 * Security A9.1: every wire value is coerced through a parse* validator and
 * must be rendered as JSX text only. The list shape has no secret field; the
 * create response's `key` is read only by parseApiKeyCreateResult and handed to
 * the caller, which holds it in component state alone.
 */
import { useCallback, useEffect, useState } from 'react'
import { apiFetch, unwrapEnvelope } from '../api/client.ts'

export interface ApiKeyInfo {
  id: string
  name: string
  permissions: string[]
  created_at: string
  expires_at: string | null
  tenant_id: string
}

export interface ApiKeyCreateResult {
  info: ApiKeyInfo
  /** The one-time secret. Never persisted by this module. */
  key: string
}

export interface ApiKeyCreateInput {
  name: string
  permissions: string[]
}

function str(value: unknown): string {
  return typeof value === 'string' ? value : ''
}

function strArr(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : []
}

export function parseApiKeyInfo(value: unknown): ApiKeyInfo | null {
  if (typeof value !== 'object' || value === null) return null
  const r = value as Record<string, unknown>
  const id = str(r.id)
  if (!id) return null
  return {
    id,
    name: str(r.name),
    permissions: strArr(r.permissions),
    created_at: str(r.created_at),
    expires_at: typeof r.expires_at === 'string' && r.expires_at ? r.expires_at : null,
    tenant_id: str(r.tenant_id),
  }
}

export function parseApiKeyList(data: unknown): ApiKeyInfo[] {
  if (data === null || data === undefined) return []
  if (!Array.isArray(data)) throw new Error('unexpected response shape')
  const list: ApiKeyInfo[] = []
  for (const item of data) {
    const parsed = parseApiKeyInfo(item)
    if (parsed !== null) list.push(parsed)
  }
  return list
}

export function parseApiKeyCreateResult(data: unknown): ApiKeyCreateResult | null {
  const info = parseApiKeyInfo(data)
  if (info === null) return null
  const key = str((data as Record<string, unknown>).key)
  if (!key) return null
  return { info, key }
}

/** Splits a comma- or line-separated permissions field; entries pass through unvalidated. */
export function splitPermissions(text: string): string[] {
  return text
    .split(/[,\n]/)
    .map((p) => p.trim())
    .filter(Boolean)
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

export interface UseApiKeyListResult {
  keys: ApiKeyInfo[]
  loading: boolean
  error: string | null
  retry: () => void
}

interface Outcome {
  key: string
  data?: ApiKeyInfo[]
  error?: string
}

export function useApiKeyList(): UseApiKeyListResult {
  const [attempt, setAttempt] = useState(0)
  const [outcome, setOutcome] = useState<Outcome | null>(null)
  const retry = useCallback(() => setAttempt((n) => n + 1), [])
  const key = `api-keys:${attempt}`

  useEffect(() => {
    let cancelled = false
    apiFetch('/api/v1/api-keys')
      .then(async (response) => {
        if (!response.ok) throw new Error(`GET /api/v1/api-keys — ${response.status}`)
        const parsed = parseApiKeyList(unwrapEnvelope<unknown>(await response.json()))
        if (cancelled) return
        setOutcome({ key, data: parsed })
      })
      .catch((cause: unknown) => {
        if (cancelled) return
        setOutcome({
          key,
          error:
            cause instanceof Error && cause.message
              ? cause.message
              : 'GET /api/v1/api-keys — request failed',
        })
      })
    return () => {
      cancelled = true
    }
  }, [key])

  const current = outcome?.key === key ? outcome : null
  return {
    keys: current?.data ?? [],
    loading: current === null,
    error: current?.error ?? null,
    retry,
  }
}

export async function createApiKey(input: ApiKeyCreateInput): Promise<ApiKeyCreateResult> {
  const response = await apiFetch('/api/v1/api-keys', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: input.name, permissions: input.permissions }),
  })
  if (!response.ok) throw new Error(await failureMessage(response, 'Create failed'))
  const result = parseApiKeyCreateResult(unwrapEnvelope<unknown>(await response.json()))
  if (result === null) throw new Error('Unexpected response shape from API key create')
  return result
}

export async function deleteApiKey(id: string): Promise<void> {
  const response = await apiFetch(`/api/v1/api-keys/${encodeURIComponent(id)}`, {
    method: 'DELETE',
  })
  if (!response.ok) throw new Error(await failureMessage(response, 'Delete failed'))
}
