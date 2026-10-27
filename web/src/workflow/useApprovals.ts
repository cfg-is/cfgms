// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Workflow approvals hook (Issue #5450, Epic #5300). Wraps:
 *   GET  /api/v1/workflows/approvals                       → pending approvals, oldest first
 *   POST /api/v1/workflows/approvals/{approval_id}/decision → {decision, justification}
 *
 * The decision is a Strong-only step-up action handled transparently by the
 * apiFetch interceptor (elevation, no presence token).
 *
 * Security: every wire value is coerced through parseApproval and must be
 * rendered as JSX text only, never as HTML.
 */
import { useCallback, useEffect, useState } from 'react'
import { apiFetch, unwrapEnvelope } from '../api/client.ts'

/** Client-side justification bound; far below the server's 16 KiB body cap. */
export const MAX_JUSTIFICATION_LENGTH = 4000

export type ApprovalDecision = 'approve' | 'reject'

export interface Approval {
  approval_id: string
  workflow_name: string
  execution_id: string
  step_id: string
  step_name: string
  message: string
  approver_permission: string
  requested_by: string
  status: string
  requested_at: string
  expires_at: string
}

export type DecisionResult = { ok: true } | { ok: false; error: string }

function str(value: unknown): string {
  return typeof value === 'string' ? value : ''
}

export function parseApproval(value: unknown): Approval | null {
  if (typeof value !== 'object' || value === null) return null
  const r = value as Record<string, unknown>
  const approval_id = str(r.approval_id)
  if (!approval_id) return null
  return {
    approval_id,
    workflow_name: str(r.workflow_name),
    execution_id: str(r.execution_id),
    step_id: str(r.step_id),
    step_name: str(r.step_name),
    message: str(r.message),
    approver_permission: str(r.approver_permission),
    requested_by: str(r.requested_by),
    status: str(r.status),
    requested_at: str(r.requested_at),
    expires_at: str(r.expires_at),
  }
}

export function parseApprovalList(data: unknown): Approval[] {
  if (data === null || data === undefined) return []
  if (!Array.isArray(data)) throw new Error('unexpected response shape')
  const list: Approval[] = []
  for (const item of data) {
    const parsed = parseApproval(item)
    if (parsed !== null) list.push(parsed)
  }
  return list
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

export interface UseApprovalsResult {
  approvals: Approval[]
  loading: boolean
  error: string | null
  retry: () => void
  decide: (id: string, decision: ApprovalDecision, justification: string) => Promise<DecisionResult>
}

interface FetchOutcome {
  key: string
  approvals?: Approval[]
  error?: string
}

export function useApprovals(): UseApprovalsResult {
  const [attempt, setAttempt] = useState(0)
  const [outcome, setOutcome] = useState<FetchOutcome | null>(null)
  const retry = useCallback(() => setAttempt((n) => n + 1), [])
  const key = `workflow-approvals:${attempt}`

  useEffect(() => {
    let cancelled = false
    apiFetch('/api/v1/workflows/approvals')
      .then(async (response) => {
        if (!response.ok) throw new Error(`GET /api/v1/workflows/approvals — ${response.status}`)
        const parsed = parseApprovalList(unwrapEnvelope<unknown>(await response.json()))
        if (cancelled) return
        setOutcome({ key, approvals: parsed })
      })
      .catch((cause: unknown) => {
        if (cancelled) return
        setOutcome({
          key,
          error:
            cause instanceof Error && cause.message
              ? cause.message
              : 'GET /api/v1/workflows/approvals — request failed',
        })
      })
    return () => {
      cancelled = true
    }
  }, [key])

  const decide = useCallback(
    async (id: string, decision: ApprovalDecision, justification: string): Promise<DecisionResult> => {
      try {
        const response = await apiFetch(
          `/api/v1/workflows/approvals/${encodeURIComponent(id)}/decision`,
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ decision, justification }),
          },
        )
        if (!response.ok) {
          return { ok: false, error: await failureMessage(response, 'Decision failed') }
        }
        retry()
        return { ok: true }
      } catch (cause: unknown) {
        return {
          ok: false,
          error: cause instanceof Error && cause.message ? cause.message : 'Request failed',
        }
      }
    },
    [retry],
  )

  const current = outcome?.key === key ? outcome : null
  return {
    approvals: current?.approvals ?? [],
    loading: current === null,
    error: current?.error ?? null,
    retry,
    decide,
  }
}
