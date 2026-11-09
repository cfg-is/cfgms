// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Script approval, pending-change and library-mode hooks (Issue #5856, Epic #5421).
 *
 * Endpoints covered:
 *   GET    /api/v1/automation/approvals/scripts                              → versions + state
 *   GET    /api/v1/automation/approvals/scripts/pending                      → pending changes + diff
 *   POST   /api/v1/automation/approvals/scripts                              → approve (presence tap)
 *   DELETE /api/v1/automation/approvals/scripts/{id}/{version}/{approval_hash} → revoke
 *   GET    /api/v1/automation/libraries/{kind}/mode                          → useLibraryMode
 *   PUT    /api/v1/automation/libraries/{kind}/mode                          → setLibraryMode (presence tap)
 *
 * The presence tap is handled centrally by apiFetch / StepUpModal: a gated
 * request is retried once with the X-Presence-Token. A 401 that survives
 * apiFetch means the tap was cancelled or failed and nothing was changed.
 *
 * Hashes are taken verbatim from the server record and sent back unchanged; the
 * browser never computes a hash. Every string field (script ids, versions,
 * reasons, diff text) is untrusted-origin data: it is coerced through str() and
 * must be rendered as JSX text only, never as HTML.
 */
import { useCallback, useEffect, useState } from 'react'
import { apiFetch, unwrapEnvelope } from '../api/client.ts'

// ── Types ─────────────────────────────────────────────────────────────────────

/** The kinds of content library that share the mode route. */
export type LibraryKind = 'script' | 'workflow'

export type LibraryMode = 'signed' | 'approve' | 'comment'

export const LIBRARY_MODES: readonly LibraryMode[] = ['signed', 'approve', 'comment']

export type ApprovalState = 'approved' | 'pending' | 'denied' | 'unknown'

export interface ApprovalInfo {
  approved_by: string
  approved_at: string
  method: string
}

export interface ScriptApprovalEntry {
  script_id: string
  version: string
  content_hash: string
  approval_hash: string
  state: ApprovalState
  /** Why a version is denied; empty when the server gives none. */
  reason: string
  approval: ApprovalInfo | null
}

export interface PendingScriptChange {
  script_id: string
  version: string
  content_hash: string
  approval_hash: string
  previous_version: string
  previous_approval_hash: string
  first_seen: string
  /** Plain-text unified diff. Render as text only. */
  diff: string
  diff_unavailable: string
}

export type ActionResult = { ok: true } | { ok: false; error: string }

// ── Parse helpers ─────────────────────────────────────────────────────────────

function str(value: unknown): string {
  return typeof value === 'string' ? value : ''
}

function record(value: unknown): Record<string, unknown> | null {
  return typeof value === 'object' && value !== null ? (value as Record<string, unknown>) : null
}

export function parseLibraryMode(value: unknown): LibraryMode | null {
  return LIBRARY_MODES.find((m) => m === value) ?? null
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

function parseApprovalInfo(value: unknown): ApprovalInfo | null {
  const r = record(value)
  if (r === null) return null
  return { approved_by: str(r.approved_by), approved_at: str(r.approved_at), method: str(r.method) }
}

export function parseApprovalEntry(value: unknown): ScriptApprovalEntry | null {
  const r = record(value)
  if (r === null) return null
  const script_id = str(r.script_id)
  const version = str(r.version)
  if (!script_id || !version) return null
  return {
    script_id,
    version,
    content_hash: str(r.content_hash),
    approval_hash: str(r.approval_hash),
    state: parseState(r.state),
    reason: str(r.reason),
    approval: parseApprovalInfo(r.approval),
  }
}

export function parsePendingChange(value: unknown): PendingScriptChange | null {
  const r = record(value)
  if (r === null) return null
  const script_id = str(r.script_id)
  const version = str(r.version)
  if (!script_id || !version) return null
  return {
    script_id,
    version,
    content_hash: str(r.content_hash),
    approval_hash: str(r.approval_hash),
    previous_version: str(r.previous_version),
    previous_approval_hash: str(r.previous_approval_hash),
    first_seen: str(r.first_seen),
    diff: str(r.diff),
    diff_unavailable: str(r.diff_unavailable),
  }
}

function parseList<T>(data: unknown, parse: (v: unknown) => T | null): T[] {
  if (data === null || data === undefined) return []
  if (!Array.isArray(data)) throw new Error('unexpected response shape')
  const out: T[] = []
  for (const item of data) {
    const parsed = parse(item)
    if (parsed !== null) out.push(parsed)
  }
  return out
}

export interface ApprovalListing {
  mode: LibraryMode
  entries: ScriptApprovalEntry[]
}

export function parseApprovalListing(data: unknown): ApprovalListing {
  const r = record(data)
  if (r === null) throw new Error('unexpected response shape')
  // An unrecognised mode is never presented as one of the three.
  const mode = parseLibraryMode(r.mode)
  if (mode === null) throw new Error('unexpected response shape')
  return { mode, entries: parseList(r.scripts, parseApprovalEntry) }
}

export function parsePendingList(data: unknown): PendingScriptChange[] {
  const r = record(data)
  if (r === null) throw new Error('unexpected response shape')
  return parseList(r.changes, parsePendingChange)
}

// ── Request helpers ───────────────────────────────────────────────────────────

const APPROVALS_URL = '/api/v1/automation/approvals/scripts'

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
 * POST /api/v1/automation/approvals/scripts. approval_hash and content_hash are
 * the server record's own values; they are sent back unchanged so the controller
 * can refuse the approval if the version moved since the record was read.
 */
export async function approveScriptVersion(
  entry: Pick<ScriptApprovalEntry, 'script_id' | 'version' | 'approval_hash' | 'content_hash'>,
): Promise<ActionResult> {
  try {
    const response = await apiFetch(APPROVALS_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        script_id: entry.script_id,
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

/** DELETE /api/v1/automation/approvals/scripts/{id}/{version}/{approval_hash}. */
export async function revokeScriptApproval(
  entry: Pick<ScriptApprovalEntry, 'script_id' | 'version' | 'approval_hash'>,
): Promise<ActionResult> {
  const url = [entry.script_id, entry.version, entry.approval_hash].map(encodeURIComponent).join('/')
  try {
    const response = await apiFetch(`${APPROVALS_URL}/${url}`, { method: 'DELETE' })
    if (response.ok) return { ok: true }
    return { ok: false, error: await refusal(response, 'Revoke failed', 'nothing was revoked') }
  } catch (cause: unknown) {
    return { ok: false, error: thrownMessage(cause) }
  }
}

/** PUT /api/v1/automation/libraries/{kind}/mode (content-library:set-mode, presence tap). */
export async function setLibraryMode(kind: LibraryKind, mode: LibraryMode): Promise<ActionResult> {
  try {
    const response = await apiFetch(`/api/v1/automation/libraries/${encodeURIComponent(kind)}/mode`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode }),
    })
    if (response.ok) return { ok: true }
    return { ok: false, error: await refusal(response, 'Changing mode failed', 'the mode was not changed') }
  } catch (cause: unknown) {
    return { ok: false, error: thrownMessage(cause) }
  }
}

// ── useScriptApprovals ────────────────────────────────────────────────────────

interface ApprovalsOutcome {
  key: string
  listing?: ApprovalListing
  pending?: PendingScriptChange[]
  error?: string
}

export interface UseScriptApprovalsResult {
  /** The library mode as the server reports it with the list; null until loaded. */
  mode: LibraryMode | null
  entries: ScriptApprovalEntry[]
  pending: PendingScriptChange[]
  loading: boolean
  error: string | null
  /** Refetches the list and the pending changes. */
  retry: () => void
  approve: (entry: ScriptApprovalEntry | PendingScriptChange) => Promise<ActionResult>
  revoke: (entry: ScriptApprovalEntry) => Promise<ActionResult>
}

async function fetchJson(url: string): Promise<unknown> {
  const response = await apiFetch(url)
  if (!response.ok) throw new Error(`GET ${url} — ${response.status}`)
  return unwrapEnvelope<unknown>(await response.json())
}

export function useScriptApprovals(): UseScriptApprovalsResult {
  const [attempt, setAttempt] = useState(0)
  const [outcome, setOutcome] = useState<ApprovalsOutcome | null>(null)
  const retry = useCallback(() => setAttempt((n) => n + 1), [])
  const key = `script-approvals:${attempt}`

  useEffect(() => {
    let cancelled = false
    Promise.all([fetchJson(APPROVALS_URL), fetchJson(`${APPROVALS_URL}/pending`)])
      .then(([list, pending]) => {
        const listing = parseApprovalListing(list)
        const changes = parsePendingList(pending)
        if (cancelled) return
        setOutcome({ key, listing, pending: changes })
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
    async (entry: ScriptApprovalEntry | PendingScriptChange): Promise<ActionResult> => {
      const result = await approveScriptVersion(entry)
      if (result.ok) retry()
      return result
    },
    [retry],
  )

  const revoke = useCallback(
    async (entry: ScriptApprovalEntry): Promise<ActionResult> => {
      const result = await revokeScriptApproval(entry)
      if (result.ok) retry()
      return result
    },
    [retry],
  )

  const current = outcome?.key === key ? outcome : null
  return {
    mode: current?.listing?.mode ?? null,
    entries: current?.listing?.entries ?? [],
    pending: current?.pending ?? [],
    loading: current === null,
    error: current?.error ?? null,
    retry,
    approve,
    revoke,
  }
}

// ── useLibraryMode ────────────────────────────────────────────────────────────

interface ModeOutcome {
  key: string
  mode?: LibraryMode
  error?: string
}

export interface UseLibraryModeResult {
  mode: LibraryMode | null
  loading: boolean
  error: string | null
  retry: () => void
  /** Sets the mode through the presence flow, then refetches the mode. */
  change: (mode: LibraryMode) => Promise<ActionResult>
}

export function useLibraryMode(kind: LibraryKind): UseLibraryModeResult {
  const [attempt, setAttempt] = useState(0)
  const [outcome, setOutcome] = useState<ModeOutcome | null>(null)
  const retry = useCallback(() => setAttempt((n) => n + 1), [])
  const key = `library-mode:${kind}:${attempt}`

  useEffect(() => {
    let cancelled = false
    fetchJson(`/api/v1/automation/libraries/${encodeURIComponent(kind)}/mode`)
      .then((data) => {
        const mode = parseLibraryMode(record(data)?.mode)
        if (mode === null) throw new Error('unexpected response shape')
        if (cancelled) return
        setOutcome({ key, mode })
      })
      .catch((cause: unknown) => {
        if (cancelled) return
        setOutcome({ key, error: thrownMessage(cause) })
      })
    return () => {
      cancelled = true
    }
  }, [key, kind])

  const change = useCallback(
    async (mode: LibraryMode): Promise<ActionResult> => {
      const result = await setLibraryMode(kind, mode)
      if (result.ok) retry()
      return result
    },
    [kind, retry],
  )

  const current = outcome?.key === key ? outcome : null
  return {
    mode: current?.mode ?? null,
    loading: current === null,
    error: current?.error ?? null,
    retry,
    change,
  }
}
