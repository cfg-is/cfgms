// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Workflow execution view (Story #2731) — execute, history, live status, cancel.
 *
 * Execute and cancel are consequential actions (runs against real infrastructure,
 * interrupts running execution) — both require an explicit confirm step before the
 * POST is sent.
 *
 * Status polling: handleGetExecution is plain request/response (no SSE). The
 * useExecutionStatus hook polls at EXEC_POLL_INTERVAL until status reaches a
 * terminal value ("completed", "failed", "cancelled").
 *
 * Security A9.1: execution id, workflow name, status, and error text originate
 * from the controller. Every value reaches the DOM as a JSX text node — never
 * dangerouslySetInnerHTML.
 */
import { apiFetch } from '../api/client.ts'
import {
  useWorkflowExecutions,
  useExecutionStatus,
  type WorkflowExecution,
} from './useWorkflows.ts'
import { useState } from 'react'

function execStatusTone(status: string): string {
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

const NON_TERMINAL = new Set(['pending', 'running', 'paused'])

function ExecRow({
  execution,
  onCancel,
}: {
  execution: WorkflowExecution
  onCancel: (id: string) => void
}) {
  const canCancel = NON_TERMINAL.has(execution.status)
  return (
    <tr data-testid="exec-row">
      <td>
        <span className="nm">{execution.id}</span>
      </td>
      <td>
        <span className="mono2">{execution.start_time}</span>
      </td>
      <td>
        <span className={`pill ${execStatusTone(execution.status)}`}>
          <span className="dot" />
          {execution.status}
        </span>
      </td>
      <td>
        <span className="mono2">{execution.current_step || '—'}</span>
      </td>
      <td>
        {canCancel && (
          <button
            type="button"
            className="wf-btn-sm-danger"
            onClick={() => onCancel(execution.id)}
            data-testid="cancel-exec-btn"
          >
            Cancel
          </button>
        )}
      </td>
      <td className="c-spacer" />
    </tr>
  )
}

interface WorkflowExecutionViewProps {
  workflowName: string
  onClose: () => void
}

export default function WorkflowExecutionView({
  workflowName,
  onClose,
}: WorkflowExecutionViewProps) {
  const {
    executions,
    loading: exLoading,
    error: exError,
    retry: refreshExecutions,
  } = useWorkflowExecutions(workflowName)

  const [activeExecId, setActiveExecId] = useState<string | null>(null)
  const { execution: activeExec } = useExecutionStatus(workflowName, activeExecId)

  const [confirmExecute, setConfirmExecute] = useState(false)
  const [confirmCancelId, setConfirmCancelId] = useState<string | null>(null)
  const [executing, setExecuting] = useState(false)
  const [executeError, setExecuteError] = useState<string | null>(null)
  const [cancelError, setCancelError] = useState<string | null>(null)

  async function handleConfirmExecute() {
    setConfirmExecute(false)
    setExecuting(true)
    setExecuteError(null)
    setActiveExecId(null)
    try {
      const response = await apiFetch(
        `/api/v1/workflows/${encodeURIComponent(workflowName)}/execute`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({}),
        },
      )
      if (!response.ok) {
        const errBody = (await response.json().catch(() => ({}))) as Record<
          string,
          unknown
        >
        throw new Error(
          (errBody?.error as string) || `Execute failed — ${response.status}`,
        )
      }
      const result = (await response.json()) as Record<string, unknown>
      const execId = (result?.execution_id as string) || null
      setActiveExecId(execId)
      refreshExecutions()
    } catch (cause: unknown) {
      setExecuteError(
        cause instanceof Error && cause.message ? cause.message : 'Execute failed',
      )
    } finally {
      setExecuting(false)
    }
  }

  async function handleConfirmCancel() {
    if (!confirmCancelId) return
    const execId = confirmCancelId
    setConfirmCancelId(null)
    setCancelError(null)
    try {
      const response = await apiFetch(
        `/api/v1/workflows/${encodeURIComponent(workflowName)}/executions/${encodeURIComponent(execId)}/cancel`,
        { method: 'POST' },
      )
      if (!response.ok) {
        const errBody = (await response.json().catch(() => ({}))) as Record<
          string,
          unknown
        >
        throw new Error(
          (errBody?.error as string) || `Cancel failed — ${response.status}`,
        )
      }
      refreshExecutions()
    } catch (cause: unknown) {
      setCancelError(
        cause instanceof Error && cause.message ? cause.message : 'Cancel failed',
      )
    }
  }

  const activeIsNonTerminal =
    activeExec !== null && NON_TERMINAL.has(activeExec.status)

  return (
    <div className="wf-exec-panel" data-testid="workflow-exec-panel">
      <div className="wf-exec-header">
        <h2>Executions: {workflowName}</h2>
        <button
          type="button"
          className="wf-exec-close"
          aria-label="Close execution view"
          onClick={onClose}
        >
          ✕
        </button>
      </div>

      {/* Execute toolbar */}
      <div className="wf-exec-toolbar">
        <button
          type="button"
          className="wf-btn"
          disabled={executing}
          onClick={() => setConfirmExecute(true)}
          data-testid="execute-btn"
        >
          {executing ? 'Executing…' : 'Execute'}
        </button>
        {executeError && (
          <span className="wf-form-error" data-testid="execute-error">
            {executeError}
          </span>
        )}
        {cancelError && (
          <span className="wf-form-error" data-testid="cancel-error">
            {cancelError}
          </span>
        )}
      </div>

      {/* Active execution status */}
      {activeExec !== null && (
        <div className="wf-exec-status" data-testid="exec-status">
          <span className={`pill ${execStatusTone(activeExec.status)}`}>
            <span className="dot" />
            {activeExec.status}
          </span>
          <span className="wf-exec-id">{activeExecId}</span>
          {activeExec.current_step && (
            <span className="mono2">step: {activeExec.current_step}</span>
          )}
          {activeExec.error && (
            <span className="wf-form-error">{activeExec.error}</span>
          )}
          {activeIsNonTerminal && (
            <button
              type="button"
              className="wf-btn-sm-danger"
              onClick={() => setConfirmCancelId(activeExecId)}
              data-testid="cancel-active-btn"
            >
              Cancel execution
            </button>
          )}
        </div>
      )}

      {/* Execution history */}
      {exLoading ? (
        <div data-testid="exec-history-loading" aria-label="Loading executions">
          {Array.from({ length: 3 }, (_, i) => (
            <div className="skrow" key={i}>
              <span className="skel" style={{ width: '60%' }} />
              <span className="skel" style={{ width: '50%' }} />
              <span className="skel" style={{ width: '35%' }} />
              <span className="skel" style={{ width: '40%' }} />
            </div>
          ))}
        </div>
      ) : exError !== null ? (
        <div className="notice err" role="alert">
          <div className="ic">!</div>
          <h3>Couldn&apos;t load executions</h3>
          <span className="mono2 detail">{exError}</span>
          <button type="button" className="btn" onClick={refreshExecutions}>
            Retry
          </button>
        </div>
      ) : executions.length === 0 ? (
        <div className="notice empty" data-testid="exec-empty">
          <div className="ic">◍</div>
          <h3>No executions yet</h3>
          <p>Click Execute to run this workflow.</p>
        </div>
      ) : (
        <table className="tbl" data-testid="exec-table">
          <thead>
            <tr>
              <th>Execution ID</th>
              <th>Started</th>
              <th>Status</th>
              <th>Current step</th>
              <th>Actions</th>
              <th className="c-spacer" aria-hidden="true" />
            </tr>
          </thead>
          <tbody>
            {executions.map((ex) => (
              <ExecRow
                key={ex.id}
                execution={ex}
                onCancel={(id) => {
                  setCancelError(null)
                  setConfirmCancelId(id)
                }}
              />
            ))}
          </tbody>
        </table>
      )}

      {/* Confirm execute dialog */}
      {confirmExecute && (
        <div
          className="wf-overlay"
          role="dialog"
          aria-modal="true"
          aria-labelledby="exec-confirm-title"
        >
          <div className="wf-modal">
            <h3 id="exec-confirm-title">Execute {workflowName}?</h3>
            <p>
              This workflow will execute against real infrastructure. Ensure the
              workflow steps are correct before proceeding.
            </p>
            <div className="wf-modal-actions">
              <button
                type="button"
                className="wf-btn-secondary"
                onClick={() => setConfirmExecute(false)}
              >
                Cancel
              </button>
              <button
                type="button"
                className="wf-btn"
                onClick={handleConfirmExecute}
                data-testid="exec-confirm-btn"
              >
                Execute
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Confirm cancel dialog */}
      {confirmCancelId !== null && (
        <div
          className="wf-overlay"
          role="dialog"
          aria-modal="true"
          aria-labelledby="cancel-confirm-title"
        >
          <div className="wf-modal">
            <h3 id="cancel-confirm-title">Cancel execution?</h3>
            <p>
              Cancelling will interrupt the running execution{' '}
              <b>{confirmCancelId}</b>. Steps already completed will not be
              rolled back.
            </p>
            <div className="wf-modal-actions">
              <button
                type="button"
                className="wf-btn-secondary"
                onClick={() => setConfirmCancelId(null)}
              >
                Keep running
              </button>
              <button
                type="button"
                className="wf-btn-danger"
                onClick={handleConfirmCancel}
                data-testid="cancel-confirm-btn"
              >
                Cancel execution
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
