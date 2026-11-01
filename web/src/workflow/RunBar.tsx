// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * RunBar — live run-state bar for the workflow builder (Issue #4616).
 *
 * Presentational over a polled execution (useExecutionStatus, owned by the
 * builder so the canvas overlay and the bar read the same poll). Shows
 * "step N/M", the execution status and a Cancel run action. Cancel uses the
 * existing cancel endpoint, which is permission-gated server-side; a denial is
 * rendered, never swallowed. A start or poll failure (403/503) renders the
 * Error state rather than a blank bar.
 *
 * Security A9.1: execution id, status and error text are server/user content,
 * rendered as text nodes only.
 */
import { useState } from 'react'
import { apiFetch } from '../api/client.ts'
import type { WorkflowExecution } from './useWorkflows.ts'

const NON_TERMINAL = new Set(['pending', 'running', 'paused'])

function tone(status: string): string {
  switch (status) {
    case 'completed':
      return 'ok'
    case 'failed':
    case 'cancelled':
      return 'crit'
    case 'running':
    case 'pending':
      return 'warn'
    default:
      return 'neutral'
  }
}

export interface RunBarProps {
  workflowName: string
  executionId: string | null
  execution: WorkflowExecution | null
  /** Start or poll failure to render as the Error state. */
  error: string | null
  /** Top-level steps that have reached a terminal result. */
  completedSteps: number
  totalSteps: number
  onDismiss: () => void
}

export default function RunBar({
  workflowName,
  executionId,
  execution,
  error,
  completedSteps,
  totalSteps,
  onDismiss,
}: RunBarProps) {
  const [cancelling, setCancelling] = useState(false)
  const [cancelError, setCancelError] = useState<string | null>(null)

  async function handleCancel() {
    if (executionId === null) return
    setCancelling(true)
    setCancelError(null)
    try {
      const response = await apiFetch(
        `/api/v1/workflows/${encodeURIComponent(workflowName)}/executions/${encodeURIComponent(executionId)}/cancel`,
        { method: 'POST' },
      )
      if (!response.ok) {
        const errBody = (await response.json().catch(() => ({}))) as Record<string, unknown>
        throw new Error(
          typeof errBody.error === 'string' && errBody.error
            ? errBody.error
            : `Cancel failed — ${response.status}`,
        )
      }
    } catch (cause: unknown) {
      setCancelError(cause instanceof Error && cause.message ? cause.message : 'Cancel failed')
    } finally {
      setCancelling(false)
    }
  }

  if (error !== null) {
    return (
      <div className="bld-runbar error" role="alert" data-testid="run-bar-error">
        <span className="wf-form-error">{error}</span>
        <button type="button" className="icobtn" aria-label="Dismiss run bar" onClick={onDismiss}>✕</button>
      </div>
    )
  }

  if (execution === null) {
    return (
      <div className="bld-runbar" aria-busy="true" data-testid="run-bar-loading">
        <span className="mut">Starting run…</span>
      </div>
    )
  }

  const canCancel = NON_TERMINAL.has(execution.status)
  const shown = execution.status === 'completed' ? totalSteps : Math.min(completedSteps, totalSteps)
  return (
    <div className="bld-runbar" data-testid="run-bar">
      <span className={`pill ${tone(execution.status)}`} data-testid="run-bar-status">
        <span className="dot" />
        {execution.status}
      </span>
      <span className="mut" data-testid="run-bar-progress">step {shown}/{totalSteps}</span>
      {execution.error && <span className="wf-form-error" data-testid="run-bar-exec-error">{execution.error}</span>}
      {cancelError !== null && <span className="wf-form-error" data-testid="run-bar-cancel-error">{cancelError}</span>}
      <div className="bld-spacer" />
      {canCancel && (
        <button type="button" className="wf-btn-danger" onClick={handleCancel} disabled={cancelling} data-testid="run-bar-cancel">
          {cancelling ? 'Cancelling…' : 'Cancel run'}
        </button>
      )}
      {!canCancel && (
        <button type="button" className="icobtn" aria-label="Dismiss run bar" onClick={onDismiss}>✕</button>
      )}
    </div>
  )
}
