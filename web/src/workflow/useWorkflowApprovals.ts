// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Workflow approval hook (Issue #5861, Epic #5421) — the pre-approval state of each
 * workflow version, and the approve and revoke actions an admin uses on a version that
 * did not come from a browser publish (a git-synced version), ADR-036 section 2.
 *
 * Endpoints covered:
 *   GET    /api/v1/automation/approvals/workflows                              → versions + state
 *   POST   /api/v1/automation/approvals/workflows                              → approve (presence tap)
 *   DELETE /api/v1/automation/approvals/workflows/{id}/{version}/{approval_hash} → revoke
 *
 * The library mode (GET/PUT /api/v1/automation/libraries/workflow/mode) is the shared
 * useLibraryMode / LibraryModePanel of the Scripts view, used with kind "workflow".
 *
 * The presence tap is handled centrally by apiFetch / StepUpModal: a gated request is
 * retried once with the X-Presence-Token. A 401 that survives apiFetch means the tap was
 * cancelled or failed and nothing was changed.
 *
 * Hashes are taken verbatim from the server record and sent back unchanged; the browser
 * never computes a hash. Every string field (workflow ids, versions, reasons) is
 * untrusted-origin data: it is coerced through str() and must be rendered as JSX text
 * only, never as HTML.
 */
import { useCallback, useEffect, useState } from 'react'
import { apiFetch, unwrapEnvelope } from '../api/client.ts'
import {
  parseLibraryMode,
  type ActionResult,
  type ApprovalInfo,
  type ApprovalState,
  type LibraryMode,
} from '../scripts/useScriptApprovals.ts'

// ── Types ─────────────────────────────────────────────────────────────────────

export interface WorkflowApprovalEntry {
  workflow_id: string
  version: string
  content_hash: string
  approval_hash: string
  state: ApprovalState
  /** Why the version is in its state; empty when the server gives none. */
  reason: string
  approval: ApprovalInfo | null
}

export interface WorkflowApprovalListing {
  mode: LibraryMode
  entries: WorkflowApprovalEntry[]
}

// ── Parse helpers ─────────────────────────────────────────────────────────────

function str(value: unknown): string {
  return typeof value === 'string' ? value : ''
}

function record(value: unknown): Record<string, unknown> | null {
  return typeof value === 'object' && value !== null ? (value as Record<string, unknown>) : null
}

function parseState(value: unknown): ApprovalState {
  switch (value) {
    case 'approved':
    case 'pending':
    case 'denied':
      return value
    default:
      return 'unknown'
  }
}

export function parseWorkflowApprovalEntry(value: unknown): WorkflowApprovalEntry | null {
  const r = record(value)
  if (r === null) return null
  const workflow_id = str(r.workflow_id)
  const version = str(r.version)
  if (!workflow_id || !version) return null
  const info = record(r.approval)
  return {
    workflow_id,
    version,
    content_hash: str(r.content_hash),
    approval_hash: str(r.approval_hash),
    state: parseState(r.state),
    reason: str(r.reason),
    approval:
      info === null
        ? null
        : { approved_by: str(info.approved_by), approved_at: str(info.approved_at), method: str(info.method) },
  }
}

export function parseWorkflowApprovalListing(data: unknown): WorkflowApprovalListing {
  const r = record(data)
  if (r === null) throw new Error('unexpected response shape')
  // An unrecognised mode is never presented as one of the three.
  const mode = parseLibraryMode(r.mode)
  if (mode === null) throw new Error('unexpected response shape')
  const raw = r.workflows ?? []
  if (!Array.isArray(raw)) throw new Error('unexpected response shape')
  const entries: WorkflowApprovalEntry[] = []
  for (const item of raw) {
    const parsed = parseWorkflowApprovalEntry(item)
    if (parsed !== null) entries.push(parsed)
  }
  return { mode, entries }
}

// ── Request helpers ───────────────────────────────────────────────────────────

const APPROVALS_URL = '/api/v1/automation/approvals/workflows'

//duplication:justified web/src/scripts/useScriptApprovals.ts -- the script hook keeps failureMessage, refusal and thrownMessage module-private and that file is outside this story's scope; the workflow routes answer with the same error shapes
async function failureMessage(response: Response, fallback: string): Promise<string> {
  const body = (await response.json().catch(() => null)) as Record<string, unknown> | null
  const err = body?.error
  const message =
    typeof err === 'string'
      ? err
      : typeof err === 'object' && err !== null
        ? str((err as Record<string, unknown>).message)
        : ''
  return message || `${fallback} — ${response.status}`
}

/**
 * Turns a non-ok response into the message shown to the operator. A 401 that
 * survived apiFetch means the presence tap was cancelled or failed.
 */
async function refusal(response: Response, fallback: string, unchanged: string): Promise<string> {
  if (response.status === 401) {
    return `Passkey confirmation was cancelled or failed — ${unchanged}`
  }
  return failureMessage(response, fallback)
}

function thrownMessage(cause: unknown): string {
  return cause instanceof Error && cause.message ? cause.message : 'Request failed'
}

// ── Mutations ─────────────────────────────────────────────────────────────────

/**
 * POST /api/v1/automation/approvals/workflows. approval_hash and content_hash are the
 * server record's own values; they are sent back unchanged so the controller can refuse
 * the approval if the version moved since the record was read.
 */
export async function approveWorkflowVersion(
  entry: Pick<WorkflowApprovalEntry, 'workflow_id' | 'version' | 'approval_hash' | 'content_hash'>,
): Promise<ActionResult> {
  try {
    const response = await apiFetch(APPROVALS_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        workflow_id: entry.workflow_id,
        version: entry.version,
        approval_hash: entry.approval_hash,
        content_hash: entry.content_hash,
      }),
    })
    if (response.ok) return { ok: true }
    return { ok: false, error: await refusal(response, 'Approval failed', 'nothing was approved') }
  } catch (cause: unknown) {
    return { ok: false, error: thrownMessage(cause) }
  }
}

/** DELETE /api/v1/automation/approvals/workflows/{id}/{version}/{approval_hash}. */
export async function revokeWorkflowApproval(
  entry: Pick<WorkflowApprovalEntry, 'workflow_id' | 'version' | 'approval_hash'>,
): Promise<ActionResult> {
  const path = [entry.workflow_id, entry.version, entry.approval_hash].map(encodeURIComponent).join('/')
  try {
    const response = await apiFetch(`${APPROVALS_URL}/${path}`, { method: 'DELETE' })
    if (response.ok) return { ok: true }
    return { ok: false, error: await refusal(response, 'Revoke failed', 'nothing was revoked') }
  } catch (cause: unknown) {
    return { ok: false, error: thrownMessage(cause) }
  }
}

// ── useWorkflowApprovals ──────────────────────────────────────────────────────

interface ApprovalsOutcome {
  key: string
  listing?: WorkflowApprovalListing
  error?: string
}

export interface UseWorkflowApprovalsResult {
  /** The library mode as the server reports it with the list; null until loaded. */
  mode: LibraryMode | null
  entries: WorkflowApprovalEntry[]
  loading: boolean
  error: string | null
  /** Refetches the list. */
  retry: () => void
  approve: (entry: WorkflowApprovalEntry) => Promise<ActionResult>
  revoke: (entry: WorkflowApprovalEntry) => Promise<ActionResult>
}

export function useWorkflowApprovals(): UseWorkflowApprovalsResult {
  const [attempt, setAttempt] = useState(0)
  const [outcome, setOutcome] = useState<ApprovalsOutcome | null>(null)
  const retry = useCallback(() => setAttempt((n) => n + 1), [])
  const key = `workflow-approvals:${attempt}`

  useEffect(() => {
    let cancelled = false
    apiFetch(APPROVALS_URL)
      .then(async (response) => {
        if (!response.ok) throw new Error(`GET ${APPROVALS_URL} — ${response.status}`)
        return parseWorkflowApprovalListing(unwrapEnvelope<unknown>(await response.json()))
      })
      .then((listing) => {
        if (cancelled) return
        setOutcome({ key, listing })
      })
      .catch((cause: unknown) => {
        if (cancelled) return
        setOutcome({ key, error: thrownMessage(cause) })
      })
    return () => {
      cancelled = true
    }
  }, [key])

  const approve = useCallback(
    async (entry: WorkflowApprovalEntry): Promise<ActionResult> => {
      const result = await approveWorkflowVersion(entry)
      if (result.ok) retry()
      return result
    },
    [retry],
  )

  const revoke = useCallback(
    async (entry: WorkflowApprovalEntry): Promise<ActionResult> => {
      const result = await revokeWorkflowApproval(entry)
      if (result.ok) retry()
      return result
    },
    [retry],
  )

  const current = outcome?.key === key ? outcome : null
  return {
    mode: current?.listing?.mode ?? null,
    entries: current?.listing?.entries ?? [],
    loading: current === null,
    error: current?.error ?? null,
    retry,
    approve,
    revoke,
  }
}
