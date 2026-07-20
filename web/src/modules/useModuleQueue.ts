// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Module review-queue hook (Issue #2732). Wraps:
 *   GET  /api/v1/modules/approvals             → pending bundle list
 *   POST /api/v1/modules/approvals/{address}/approve
 *   POST /api/v1/modules/approvals/{address}/reject
 *
 * Security: bundle metadata (publisher, content address) originates from
 * potentially untrusted sources — an unsigned bundle can carry arbitrary
 * strings. All fields are coerced to plain strings. Callers must render as
 * text nodes only, never via dangerouslySetInnerHTML.
 */
import { useCallback, useEffect, useState } from 'react'
import { apiFetch } from '../api/client.ts'

// ── Types ─────────────────────────────────────────────────────────────────────

export interface ModuleApprovalEntry {
  address: string
  publisher: string
  name: string
  version: string
  content_hash: string
}

export type ActionResult = { ok: true } | { ok: false; error: string }

export interface UseModuleQueueResult {
  bundles: ModuleApprovalEntry[]
  loading: boolean
  error: string | null
  retry: () => void
  approve: (address: string) => Promise<ActionResult>
  reject: (address: string) => Promise<ActionResult>
}

// ── Parse helpers ─────────────────────────────────────────────────────────────

function str(value: unknown): string {
  return typeof value === 'string' ? value : ''
}

export function parseModuleApprovalEntry(value: unknown): ModuleApprovalEntry | null {
  if (typeof value !== 'object' || value === null) return null
  const r = value as Record<string, unknown>
  const address = str(r.address)
  if (!address) return null
  return {
    address,
    publisher: str(r.publisher),
    name: str(r.name),
    version: str(r.version),
    content_hash: str(r.content_hash),
  }
}

export function parseModuleApprovalList(data: unknown): ModuleApprovalEntry[] {
  if (typeof data !== 'object' || data === null) throw new Error('unexpected response shape')
  const obj = data as Record<string, unknown>
  if (!Array.isArray(obj.pending)) throw new Error('unexpected response shape')
  const list: ModuleApprovalEntry[] = []
  for (const item of obj.pending) {
    const entry = parseModuleApprovalEntry(item)
    if (entry !== null) list.push(entry)
  }
  return list
}

// ── Action helper ─────────────────────────────────────────────────────────────

async function postAction(path: string): Promise<ActionResult> {
  try {
    const response = await apiFetch(path, { method: 'POST' })
    if (!response.ok) {
      const errBody = (await response.json().catch(() => ({}))) as Record<string, unknown>
      const errMsg =
        ((errBody?.error as Record<string, unknown>)?.message as string) ||
        `Request failed — ${response.status}`
      return { ok: false, error: errMsg }
    }
    return { ok: true }
  } catch (cause: unknown) {
    return {
      ok: false,
      error: cause instanceof Error && cause.message ? cause.message : 'Request failed',
    }
  }
}

// ── Hook ─────────────────────────────────────────────────────────────────────

interface FetchOutcome {
  key: string
  bundles?: ModuleApprovalEntry[]
  error?: string
}

export function useModuleQueue(): UseModuleQueueResult {
  const [attempt, setAttempt] = useState(0)
  const [outcome, setOutcome] = useState<FetchOutcome | null>(null)
  const retry = useCallback(() => setAttempt((n) => n + 1), [])
  const key = `module-approvals:${attempt}`

  useEffect(() => {
    let cancelled = false
    apiFetch('/api/v1/modules/approvals')
      .then(async (response) => {
        if (!response.ok)
          throw new Error(`GET /api/v1/modules/approvals — ${response.status}`)
        const body: unknown = await response.json()
        const parsed = parseModuleApprovalList(
          (body as Record<string, unknown> | null)?.data,
        )
        if (cancelled) return
        setOutcome({ key, bundles: parsed })
      })
      .catch((cause: unknown) => {
        if (cancelled) return
        setOutcome({
          key,
          error:
            cause instanceof Error && cause.message
              ? cause.message
              : 'GET /api/v1/modules/approvals — request failed',
        })
      })
    return () => {
      cancelled = true
    }
  }, [key, attempt])

  const approve = useCallback(
    async (address: string): Promise<ActionResult> => {
      const result = await postAction(
        `/api/v1/modules/approvals/${encodeURIComponent(address)}/approve`,
      )
      if (result.ok) retry()
      return result
    },
    [retry],
  )

  const reject = useCallback(
    async (address: string): Promise<ActionResult> => {
      const result = await postAction(
        `/api/v1/modules/approvals/${encodeURIComponent(address)}/reject`,
      )
      if (result.ok) retry()
      return result
    },
    [retry],
  )

  const current = outcome?.key === key ? outcome : null
  return {
    bundles: current?.bundles ?? [],
    loading: current === null,
    error: current?.error ?? null,
    retry,
    approve,
    reject,
  }
}
