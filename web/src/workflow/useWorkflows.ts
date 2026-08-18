// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Workflow fetch and mutation hooks (Story #2731).
 *
 * Endpoints covered:
 *   GET  /api/v1/workflows                                    → useWorkflowList
 *   GET  /api/v1/workflows/{name}/executions                 → useWorkflowExecutions
 *   GET  /api/v1/workflows/{name}/executions/{exec_id}       → useExecutionStatus (polls)
 *   GET  /api/v1/triggers                                     → useTriggerList
 *
 * Security A9.1: workflow name, description, step names, and trigger fields
 * originate from user-supplied content. Every string field is coerced via
 * str(). Callers must render them as text nodes only, never via
 * dangerouslySetInnerHTML.
 *
 * Response shape: workflow endpoints return direct JSON objects (no
 * { data: ... } envelope), matching sendJSON usage in handlers_workflows.go.
 *
 * Polling: handleGetExecution is plain request/response (no SSE). The
 * useExecutionStatus hook uses a fixed EXEC_POLL_INTERVAL ticker (same
 * pattern as usePushStatus in useConfigs.ts) and stops when status reaches
 * a terminal value ("completed", "failed", "cancelled").
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

export interface SwitchCase {
  label: string
  steps: WorkflowStep[]
}

export interface WorkflowStep {
  id: string
  name: string
  type: string
  config?: Record<string, unknown>
  // Nested block tree fields — used by WorkflowGraph renderer (Story #3037)
  steps?: WorkflowStep[]        // children of sequential/parallel/loop containers
  condition?: string            // expression string for conditional steps
  switch?: SwitchCase[]         // cases for switch steps
  loop?: boolean                // true for for/while/foreach container steps
  fan_out?: boolean
  fan_in?: boolean
  /*
   * Verbatim step JSON as the controller sent it. The typed fields above model
   * only what the renderers need; features/workflow/types.go Step also carries
   * timeout, on_failure, semaphore, lock, barrier, try, error_handling,
   * workflow_call and more. PUT /api/v1/workflows/{id} is a wholesale replace,
   * so any editor that writes a step back MUST start from `raw` and override
   * only the fields it owns — otherwise the save deletes everything unmodeled.
   * Always populated by parseStep; optional only so renderer-side fixtures may
   * omit it.
   */
  raw?: Record<string, unknown>
}

export interface SemanticVersion {
  major: number
  minor: number
  patch: number
  pre_release: string
  build_meta: string
}

export interface VersionedWorkflow {
  name: string
  description: string
  version: string
  steps: WorkflowStep[]
  variables?: Record<string, unknown>
  timeout?: number
  on_failure?: string
  semantic_version: SemanticVersion
  version_tags?: string[]
  deprecated?: boolean
  deprecation_note?: string
  /*
   * Verbatim workflow JSON as the controller sent it — same contract as
   * WorkflowStep.raw. Editors consult it to detect stored fields that
   * CreateWorkflowRequest cannot carry back (on_failure, error_workflows,
   * version_tags, deprecated, deprecation_note, changelog). Always populated
   * by parseVersionedWorkflow.
   */
  raw?: Record<string, unknown>
}

export interface WorkflowExecution {
  id: string
  workflow_name: string
  status: string
  start_time: string
  end_time?: string
  current_step?: string
  step_results?: Record<string, unknown>
  variables?: Record<string, unknown>
  error?: string
}

export interface TriggerItem {
  id: string
  name: string
  description?: string
  type: string
  status: string
  tenant_id?: string
  workflow_name?: string
  created_at?: string
  updated_at?: string
  schedule?: { cron_expression: string }
  webhook?: { path: string }
}

// ── Parse helpers ─────────────────────────────────────────────────────────────

function parseSwitchCase(value: unknown): SwitchCase | null {
  if (typeof value !== 'object' || value === null) return null
  const r = value as Record<string, unknown>
  return {
    label: str(r.label),
    steps: Array.isArray(r.steps)
      ? r.steps.flatMap((s) => { const p = parseStep(s); return p ? [p] : [] })
      : [],
  }
}

function parseStep(value: unknown): WorkflowStep | null {
  if (typeof value !== 'object' || value === null) return null
  const r = value as Record<string, unknown>
  const step: WorkflowStep = {
    id: str(r.id),
    name: str(r.name),
    type: str(r.type),
    config:
      typeof r.config === 'object' && r.config !== null
        ? (r.config as Record<string, unknown>)
        : {},
    raw: { ...r },
  }
  if (Array.isArray(r.steps)) {
    step.steps = r.steps.flatMap((s) => { const p = parseStep(s); return p ? [p] : [] })
  }
  if (r.condition !== undefined) step.condition = str(r.condition)
  if (Array.isArray(r.switch)) {
    step.switch = r.switch.flatMap((c) => { const p = parseSwitchCase(c); return p ? [p] : [] })
  }
  if (r.loop !== undefined) step.loop = bool(r.loop)
  if (r.fan_out !== undefined) step.fan_out = bool(r.fan_out)
  if (r.fan_in !== undefined) step.fan_in = bool(r.fan_in)
  return step
}

function parseSemanticVersion(value: unknown): SemanticVersion {
  if (typeof value !== 'object' || value === null) {
    return { major: 0, minor: 0, patch: 0, pre_release: '', build_meta: '' }
  }
  const r = value as Record<string, unknown>
  return {
    major: num(r.major),
    minor: num(r.minor),
    patch: num(r.patch),
    pre_release: str(r.pre_release),
    build_meta: str(r.build_meta),
  }
}

export function parseVersionedWorkflow(value: unknown): VersionedWorkflow | null {
  if (typeof value !== 'object' || value === null) return null
  const r = value as Record<string, unknown>
  const name = str(r.name)
  if (!name) return null
  return {
    name,
    description: str(r.description),
    version: str(r.version),
    steps: Array.isArray(r.steps)
      ? r.steps.flatMap((s) => {
          const p = parseStep(s)
          return p ? [p] : []
        })
      : [],
    variables:
      typeof r.variables === 'object' && r.variables !== null
        ? (r.variables as Record<string, unknown>)
        : undefined,
    timeout: typeof r.timeout === 'number' ? r.timeout : undefined,
    on_failure: r.on_failure !== undefined ? str(r.on_failure) : undefined,
    semantic_version: parseSemanticVersion(r.semantic_version),
    version_tags: Array.isArray(r.version_tags)
      ? r.version_tags.filter((t): t is string => typeof t === 'string')
      : undefined,
    deprecated: r.deprecated !== undefined ? bool(r.deprecated) : undefined,
    deprecation_note:
      r.deprecation_note !== undefined ? str(r.deprecation_note) : undefined,
    raw: { ...r },
  }
}

export function parseWorkflowList(data: unknown): VersionedWorkflow[] {
  if (!Array.isArray(data)) throw new Error('unexpected response shape')
  const list: VersionedWorkflow[] = []
  for (const item of data) {
    const w = parseVersionedWorkflow(item)
    if (w !== null) list.push(w)
  }
  return list
}

export function parseWorkflowExecution(value: unknown): WorkflowExecution | null {
  if (typeof value !== 'object' || value === null) return null
  const r = value as Record<string, unknown>
  const id = str(r.id)
  if (!id) return null
  return {
    id,
    workflow_name: str(r.workflow_name),
    status: str(r.status),
    start_time: str(r.start_time),
    end_time: r.end_time !== undefined ? str(r.end_time) : undefined,
    current_step:
      r.current_step !== undefined ? str(r.current_step) : undefined,
    step_results:
      typeof r.step_results === 'object' && r.step_results !== null
        ? (r.step_results as Record<string, unknown>)
        : undefined,
    variables:
      typeof r.variables === 'object' && r.variables !== null
        ? (r.variables as Record<string, unknown>)
        : undefined,
    error: r.error !== undefined ? str(r.error) : undefined,
  }
}

export function parseExecutionList(data: unknown): WorkflowExecution[] {
  if (!Array.isArray(data)) throw new Error('unexpected response shape')
  const list: WorkflowExecution[] = []
  for (const item of data) {
    const e = parseWorkflowExecution(item)
    if (e !== null) list.push(e)
  }
  return list
}

export function parseTriggerItem(value: unknown): TriggerItem | null {
  if (typeof value !== 'object' || value === null) return null
  const r = value as Record<string, unknown>
  const id = str(r.id)
  if (!id) return null
  return {
    id,
    name: str(r.name),
    description: r.description !== undefined ? str(r.description) : undefined,
    type: str(r.type),
    status: str(r.status),
    tenant_id:
      r.tenant_id !== undefined ? str(r.tenant_id) : undefined,
    workflow_name:
      r.workflow_name !== undefined ? str(r.workflow_name) : undefined,
    created_at:
      r.created_at !== undefined ? str(r.created_at) : undefined,
    updated_at:
      r.updated_at !== undefined ? str(r.updated_at) : undefined,
    schedule:
      typeof r.schedule === 'object' && r.schedule !== null
        ? { cron_expression: str((r.schedule as Record<string, unknown>).cron_expression) }
        : undefined,
    webhook:
      typeof r.webhook === 'object' && r.webhook !== null
        ? { path: str((r.webhook as Record<string, unknown>).path) }
        : undefined,
  }
}

export function parseTriggerList(data: unknown): TriggerItem[] {
  if (!Array.isArray(data)) throw new Error('unexpected response shape')
  const list: TriggerItem[] = []
  for (const item of data) {
    const t = parseTriggerItem(item)
    if (t !== null) list.push(t)
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

// ── useWorkflowList ───────────────────────────────────────────────────────────

export interface UseWorkflowListResult {
  workflows: VersionedWorkflow[]
  loading: boolean
  error: string | null
  fetchedAtMs: number
  retry: () => void
}

export function useWorkflowList(): UseWorkflowListResult {
  const [attempt, setAttempt] = useState(0)
  const [outcome, setOutcome] = useState<FetchOutcome<VersionedWorkflow[]> | null>(null)
  const retry = useCallback(() => setAttempt((n) => n + 1), [])
  const key = `workflows:${attempt}`

  useEffect(() => {
    let cancelled = false
    apiFetch('/api/v1/workflows')
      .then(async (response) => {
        if (!response.ok)
          throw new Error(`GET /api/v1/workflows — ${response.status}`)
        const body: unknown = await response.json()
        const parsed = parseWorkflowList(
          (body as Record<string, unknown> | null)?.workflows,
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
              : 'GET /api/v1/workflows — request failed',
          fetchedAtMs: Date.now(),
        })
      })
    return () => {
      cancelled = true
    }
  }, [key, attempt])

  const current = outcome?.key === key ? outcome : null
  return {
    workflows: current?.data ?? [],
    loading: current === null,
    error: current?.error ?? null,
    fetchedAtMs: current?.fetchedAtMs ?? 0,
    retry,
  }
}

// ── useWorkflowExecutions ─────────────────────────────────────────────────────

export interface UseWorkflowExecutionsResult {
  executions: WorkflowExecution[]
  loading: boolean
  error: string | null
  retry: () => void
}

export function useWorkflowExecutions(
  name: string | null,
): UseWorkflowExecutionsResult {
  const [attempt, setAttempt] = useState(0)
  const [outcome, setOutcome] = useState<FetchOutcome<WorkflowExecution[]> | null>(
    null,
  )
  const retry = useCallback(() => setAttempt((n) => n + 1), [])
  const key = `workflow-executions:${name ?? ''}:${attempt}`

  useEffect(() => {
    if (!name) return
    let cancelled = false
    apiFetch(`/api/v1/workflows/${encodeURIComponent(name)}/executions`)
      .then(async (response) => {
        if (!response.ok)
          throw new Error(
            `GET /api/v1/workflows/${name}/executions — ${response.status}`,
          )
        const body: unknown = await response.json()
        const parsed = parseExecutionList(
          (body as Record<string, unknown> | null)?.executions,
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
              : `GET /api/v1/workflows/${name}/executions — request failed`,
          fetchedAtMs: Date.now(),
        })
      })
    return () => {
      cancelled = true
    }
  }, [key, name, attempt])

  const current = outcome?.key === key ? outcome : null
  return {
    executions: current?.data ?? [],
    loading: name !== null && current === null,
    error: current?.error ?? null,
    retry,
  }
}

// ── useExecutionStatus (polls until terminal) ─────────────────────────────────

const EXEC_POLL_INTERVAL = 3000
const EXEC_TERMINAL = new Set(['completed', 'failed', 'cancelled'])

export interface UseExecutionStatusResult {
  execution: WorkflowExecution | null
  loading: boolean
  error: string | null
}

export function useExecutionStatus(
  name: string | null,
  execId: string | null,
): UseExecutionStatusResult {
  const [outcome, setOutcome] = useState<FetchOutcome<WorkflowExecution> | null>(
    null,
  )
  const [pollTick, setPollTick] = useState(0)
  const key = `exec-status:${name ?? ''}:${execId ?? ''}:${pollTick}`

  const current = outcome?.key === key ? outcome : null
  const isTerminal =
    current?.data !== undefined && EXEC_TERMINAL.has(current.data.status)

  // Polling ticker — fires every EXEC_POLL_INTERVAL while execution is non-terminal
  useEffect(() => {
    if (!name || !execId || isTerminal) return
    const timer = setInterval(
      () => setPollTick((n) => n + 1),
      EXEC_POLL_INTERVAL,
    )
    return () => clearInterval(timer)
  }, [name, execId, isTerminal])

  // Fetch on name/execId change or poll tick
  useEffect(() => {
    if (!name || !execId) return
    let cancelled = false
    apiFetch(
      `/api/v1/workflows/${encodeURIComponent(name)}/executions/${encodeURIComponent(execId)}`,
    )
      .then(async (response) => {
        if (!response.ok)
          throw new Error(
            `GET /api/v1/workflows/${name}/executions/${execId} — ${response.status}`,
          )
        const body: unknown = await response.json()
        const parsed = parseWorkflowExecution(body)
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
  }, [key, name, execId, pollTick])

  return {
    execution: name && execId ? (current?.data ?? null) : null,
    loading: name !== null && execId !== null && current === null,
    error: name && execId ? (current?.error ?? null) : null,
  }
}

// ── useTriggerList ────────────────────────────────────────────────────────────

export interface UseTriggerListResult {
  triggers: TriggerItem[]
  loading: boolean
  error: string | null
  retry: () => void
}

export function useTriggerList(): UseTriggerListResult {
  const [attempt, setAttempt] = useState(0)
  const [outcome, setOutcome] = useState<FetchOutcome<TriggerItem[]> | null>(null)
  const retry = useCallback(() => setAttempt((n) => n + 1), [])
  const key = `triggers:${attempt}`

  useEffect(() => {
    let cancelled = false
    apiFetch('/api/v1/triggers')
      .then(async (response) => {
        if (!response.ok)
          throw new Error(`GET /api/v1/triggers — ${response.status}`)
        const body: unknown = await response.json()
        const parsed = parseTriggerList(
          (body as Record<string, unknown> | null)?.triggers,
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
              : 'GET /api/v1/triggers — request failed',
          fetchedAtMs: Date.now(),
        })
      })
    return () => {
      cancelled = true
    }
  }, [key, attempt])

  const current = outcome?.key === key ? outcome : null
  return {
    triggers: current?.data ?? [],
    loading: current === null,
    error: current?.error ?? null,
    retry,
  }
}
