// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Scripts, runs, and jobs fetch/mutation hooks (Issue #2988).
 *
 * Endpoints covered:
 *   GET  /api/v1/scripts                        → useScriptList
 *   GET  /api/v1/runs                           → useRunList
 *   GET  /api/v1/runs/{run_id}                  → useRunStatus (polls)
 *   GET  /api/v1/runs/{run_id}/jobs             → useRunJobs (polls while run is non-terminal)
 *   GET  /api/v1/jobs                           → useJobList
 *
 * Security A9.1: script names, params, run/job output, and status strings are
 * untrusted-origin data. Every string field is coerced via str(). Callers must
 * render them as JSX text nodes only, never dangerouslySetInnerHTML.
 *
 * Response envelope: all endpoints use writeSuccessResponse → { data: ..., timestamp: ... }.
 *
 * Polling: useRunStatus and useRunJobs use a fixed RUN_POLL_INTERVAL ticker
 * (same pattern as usePushStatus in useConfigs.ts) and stop when the run
 * reaches a terminal state ("completed", "failed", "cancelled").
 */
import { useCallback, useEffect, useState } from 'react'
import { apiFetch } from '../api/client.ts'

// ── Primitive coercers ────────────────────────────────────────────────────────

function str(value: unknown): string {
  return typeof value === 'string' ? value : ''
}

function num(value: unknown): number {
  return typeof value === 'number' ? value : 0
}

function bool(value: unknown): boolean {
  return typeof value === 'boolean' ? value : false
}

// ── Types ─────────────────────────────────────────────────────────────────────

export interface ScriptVersion {
  major: number
  minor: number
  patch: number
  prerelease: string
  build_meta: string
}

export interface ScriptParameter {
  name: string
  description: string
  type: string
  required: boolean
  default?: unknown
  allowed_values?: string[]
  dna_path?: string
}

export interface ScriptMetadata {
  id: string
  name: string
  description: string
  version: ScriptVersion | null
  author: string
  tags: string[]
  category: string
  platform: string[]
  shell: string
  parameters: ScriptParameter[]
  created_at: string
  updated_at: string
  idempotent: boolean
}

export interface RunRecord {
  run_id: string
  tenant_id: string
  created_by: string
  created_at: string
  status: string
  script_ref: string
  shell: string
  job_count: number
  completed_jobs: number
  failed_jobs: number
}

export interface JobRecord {
  job_id: string
  run_id: string
  device_id: string
  execution_id: string
  status: string
  created_at: string
  completed_at: string
  output: string
  stderr: string
  exit_code: number
}

export interface BatchJob {
  id: string
  tenant_id: string
  selector: string
  status: string
  targets: string[]
  created_at: string
  updated_at: string
  initiated_by: string
}

// ── Parse helpers ─────────────────────────────────────────────────────────────

function parseScriptVersion(value: unknown): ScriptVersion | null {
  if (typeof value !== 'object' || value === null) return null
  const r = value as Record<string, unknown>
  return {
    major: num(r.major),
    minor: num(r.minor),
    patch: num(r.patch),
    prerelease: str(r.prerelease),
    build_meta: str(r.build_meta),
  }
}

function parseScriptParameter(value: unknown): ScriptParameter | null {
  if (typeof value !== 'object' || value === null) return null
  const r = value as Record<string, unknown>
  const name = str(r.name)
  if (!name) return null
  return {
    name,
    description: str(r.description),
    type: str(r.type),
    required: bool(r.required),
    default: r.default !== undefined ? r.default : undefined,
    allowed_values: Array.isArray(r.allowed_values)
      ? r.allowed_values.filter((v): v is string => typeof v === 'string')
      : undefined,
    dna_path: r.dna_path !== undefined ? str(r.dna_path) : undefined,
  }
}

export function parseScriptMetadata(value: unknown): ScriptMetadata | null {
  if (typeof value !== 'object' || value === null) return null
  const r = value as Record<string, unknown>
  const id = str(r.id)
  if (!id) return null
  return {
    id,
    name: str(r.name),
    description: str(r.description),
    version: parseScriptVersion(r.version),
    author: str(r.author),
    tags: Array.isArray(r.tags)
      ? r.tags.filter((t): t is string => typeof t === 'string')
      : [],
    category: str(r.category),
    platform: Array.isArray(r.platform)
      ? r.platform.filter((p): p is string => typeof p === 'string')
      : [],
    shell: str(r.shell),
    parameters: Array.isArray(r.parameters)
      ? r.parameters.flatMap((p) => {
          const parsed = parseScriptParameter(p)
          return parsed ? [parsed] : []
        })
      : [],
    created_at: str(r.created_at),
    updated_at: str(r.updated_at),
    idempotent: bool(r.idempotent),
  }
}

export function parseScriptList(data: unknown): ScriptMetadata[] {
  if (!Array.isArray(data)) throw new Error('unexpected response shape')
  const list: ScriptMetadata[] = []
  for (const item of data) {
    const s = parseScriptMetadata(item)
    if (s !== null) list.push(s)
  }
  return list
}

export function parseRunRecord(value: unknown): RunRecord | null {
  if (typeof value !== 'object' || value === null) return null
  const r = value as Record<string, unknown>
  const run_id = str(r.run_id)
  if (!run_id) return null
  return {
    run_id,
    tenant_id: str(r.tenant_id),
    created_by: str(r.created_by),
    created_at: str(r.created_at),
    status: str(r.status),
    script_ref: str(r.script_ref),
    shell: str(r.shell),
    job_count: num(r.job_count),
    completed_jobs: num(r.completed_jobs),
    failed_jobs: num(r.failed_jobs),
  }
}

export function parseRunList(data: unknown): RunRecord[] {
  if (!Array.isArray(data)) throw new Error('unexpected response shape')
  const list: RunRecord[] = []
  for (const item of data) {
    const r = parseRunRecord(item)
    if (r !== null) list.push(r)
  }
  return list
}

export function parseJobRecord(value: unknown): JobRecord | null {
  if (typeof value !== 'object' || value === null) return null
  const r = value as Record<string, unknown>
  const job_id = str(r.job_id)
  if (!job_id) return null
  return {
    job_id,
    run_id: str(r.run_id),
    device_id: str(r.device_id),
    execution_id: str(r.execution_id),
    status: str(r.status),
    created_at: str(r.created_at),
    completed_at: r.completed_at !== undefined ? str(r.completed_at) : '',
    output: str(r.output),
    stderr: str(r.stderr),
    exit_code: num(r.exit_code),
  }
}

export function parseJobList(data: unknown): JobRecord[] {
  if (!Array.isArray(data)) throw new Error('unexpected response shape')
  const list: JobRecord[] = []
  for (const item of data) {
    const j = parseJobRecord(item)
    if (j !== null) list.push(j)
  }
  return list
}

export function parseBatchJob(value: unknown): BatchJob | null {
  if (typeof value !== 'object' || value === null) return null
  const r = value as Record<string, unknown>
  const id = str(r.id)
  if (!id) return null
  return {
    id,
    tenant_id: str(r.tenant_id),
    selector: str(r.selector),
    status: str(r.status),
    targets: Array.isArray(r.targets)
      ? r.targets.filter((t): t is string => typeof t === 'string')
      : [],
    created_at: str(r.created_at),
    updated_at: str(r.updated_at),
    initiated_by: str(r.initiated_by),
  }
}

export function parseBatchJobList(data: unknown): BatchJob[] {
  if (!Array.isArray(data)) throw new Error('unexpected response shape')
  const list: BatchJob[] = []
  for (const item of data) {
    const j = parseBatchJob(item)
    if (j !== null) list.push(j)
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

// ── useScriptList ─────────────────────────────────────────────────────────────

export interface UseScriptListResult {
  scripts: ScriptMetadata[]
  loading: boolean
  error: string | null
  fetchedAtMs: number
  retry: () => void
}

export function useScriptList(): UseScriptListResult {
  const [attempt, setAttempt] = useState(0)
  const [outcome, setOutcome] = useState<FetchOutcome<ScriptMetadata[]> | null>(null)
  const retry = useCallback(() => setAttempt((n) => n + 1), [])
  const key = `scripts:${attempt}`

  useEffect(() => {
    let cancelled = false
    apiFetch('/api/v1/scripts')
      .then(async (response) => {
        if (!response.ok) throw new Error(`GET /api/v1/scripts — ${response.status}`)
        const body: unknown = await response.json()
        const parsed = parseScriptList((body as Record<string, unknown> | null)?.data)
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
              : 'GET /api/v1/scripts — request failed',
          fetchedAtMs: Date.now(),
        })
      })
    return () => {
      cancelled = true
    }
  }, [key, attempt])

  const current = outcome?.key === key ? outcome : null
  return {
    scripts: current?.data ?? [],
    loading: current === null,
    error: current?.error ?? null,
    fetchedAtMs: current?.fetchedAtMs ?? 0,
    retry,
  }
}

// ── useRunList ────────────────────────────────────────────────────────────────

export interface UseRunListResult {
  runs: RunRecord[]
  loading: boolean
  error: string | null
  retry: () => void
}

export function useRunList(): UseRunListResult {
  const [attempt, setAttempt] = useState(0)
  const [outcome, setOutcome] = useState<FetchOutcome<RunRecord[]> | null>(null)
  const retry = useCallback(() => setAttempt((n) => n + 1), [])
  const key = `runs:${attempt}`

  useEffect(() => {
    let cancelled = false
    apiFetch('/api/v1/runs')
      .then(async (response) => {
        if (!response.ok) throw new Error(`GET /api/v1/runs — ${response.status}`)
        const body: unknown = await response.json()
        const parsed = parseRunList((body as Record<string, unknown> | null)?.data)
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
              : 'GET /api/v1/runs — request failed',
          fetchedAtMs: Date.now(),
        })
      })
    return () => {
      cancelled = true
    }
  }, [key, attempt])

  const current = outcome?.key === key ? outcome : null
  return {
    runs: current?.data ?? [],
    loading: current === null,
    error: current?.error ?? null,
    retry,
  }
}

// ── useRunStatus (polls until terminal) ───────────────────────────────────────

export const RUN_POLL_INTERVAL = 3000
export const RUN_TERMINAL = new Set(['completed', 'failed', 'cancelled'])

export interface UseRunStatusResult {
  run: RunRecord | null
  loading: boolean
  error: string | null
}

export function useRunStatus(runId: string | null): UseRunStatusResult {
  const [outcome, setOutcome] = useState<FetchOutcome<RunRecord> | null>(null)
  const [pollTick, setPollTick] = useState(0)
  const key = `run-status:${runId ?? ''}:${pollTick}`

  const current = outcome?.key === key ? outcome : null
  const isTerminal =
    current?.data !== undefined && RUN_TERMINAL.has(current.data.status)

  // Polling ticker — fires every RUN_POLL_INTERVAL while run is non-terminal
  useEffect(() => {
    if (!runId || isTerminal) return
    const timer = setInterval(() => setPollTick((n) => n + 1), RUN_POLL_INTERVAL)
    return () => clearInterval(timer)
  }, [runId, isTerminal])

  // Fetch on runId change or poll tick
  useEffect(() => {
    if (!runId) return
    let cancelled = false
    apiFetch(`/api/v1/runs/${encodeURIComponent(runId)}`)
      .then(async (response) => {
        if (!response.ok)
          throw new Error(`GET /api/v1/runs/${runId} — ${response.status}`)
        const body: unknown = await response.json()
        const parsed = parseRunRecord((body as Record<string, unknown> | null)?.data)
        if (cancelled) return
        if (parsed !== null) {
          setOutcome({ key, data: parsed, fetchedAtMs: Date.now() })
        }
      })
      .catch((cause: unknown) => {
        if (cancelled) return
        setOutcome({
          key,
          error:
            cause instanceof Error && cause.message
              ? cause.message
              : 'request failed',
          fetchedAtMs: Date.now(),
        })
      })
    return () => {
      cancelled = true
    }
  }, [key, runId, pollTick])

  return {
    run: runId ? (current?.data ?? null) : null,
    loading: runId !== null && current === null,
    error: runId ? (current?.error ?? null) : null,
  }
}

// ── useRunJobs (polls while run is non-terminal) ──────────────────────────────

export interface UseRunJobsResult {
  jobs: JobRecord[]
  loading: boolean
  error: string | null
}

export function useRunJobs(
  runId: string | null,
  isRunTerminal: boolean,
): UseRunJobsResult {
  const [outcome, setOutcome] = useState<FetchOutcome<JobRecord[]> | null>(null)
  const [pollTick, setPollTick] = useState(0)
  const key = `run-jobs:${runId ?? ''}:${pollTick}`

  // Polling ticker — fires every RUN_POLL_INTERVAL while run is non-terminal
  useEffect(() => {
    if (!runId || isRunTerminal) return
    const timer = setInterval(() => setPollTick((n) => n + 1), RUN_POLL_INTERVAL)
    return () => clearInterval(timer)
  }, [runId, isRunTerminal])

  // Fetch on runId change or poll tick
  useEffect(() => {
    if (!runId) return
    let cancelled = false
    apiFetch(`/api/v1/runs/${encodeURIComponent(runId)}/jobs`)
      .then(async (response) => {
        if (!response.ok)
          throw new Error(`GET /api/v1/runs/${runId}/jobs — ${response.status}`)
        const body: unknown = await response.json()
        const parsed = parseJobList((body as Record<string, unknown> | null)?.data)
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
              : 'request failed',
          fetchedAtMs: Date.now(),
        })
      })
    return () => {
      cancelled = true
    }
  }, [key, runId, pollTick])

  const current = outcome?.key === key ? outcome : null
  return {
    jobs: current?.data ?? [],
    loading: runId !== null && current === null,
    error: runId ? (current?.error ?? null) : null,
  }
}

// ── useJobList ────────────────────────────────────────────────────────────────

export interface UseJobListResult {
  jobs: BatchJob[]
  loading: boolean
  error: string | null
  retry: () => void
}

export function useJobList(): UseJobListResult {
  const [attempt, setAttempt] = useState(0)
  const [outcome, setOutcome] = useState<FetchOutcome<BatchJob[]> | null>(null)
  const retry = useCallback(() => setAttempt((n) => n + 1), [])
  const key = `jobs:${attempt}`

  useEffect(() => {
    let cancelled = false
    apiFetch('/api/v1/jobs')
      .then(async (response) => {
        if (!response.ok) throw new Error(`GET /api/v1/jobs — ${response.status}`)
        const body: unknown = await response.json()
        const parsed = parseBatchJobList((body as Record<string, unknown> | null)?.data)
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
              : 'GET /api/v1/jobs — request failed',
          fetchedAtMs: Date.now(),
        })
      })
    return () => {
      cancelled = true
    }
  }, [key, attempt])

  const current = outcome?.key === key ? outcome : null
  return {
    jobs: current?.data ?? [],
    loading: current === null,
    error: current?.error ?? null,
    retry,
  }
}
