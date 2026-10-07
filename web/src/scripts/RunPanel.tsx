// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Run panel (Issue #2988): selector-targeted script run with a confirm step
 * that shows the resolved steward count before committing.
 *
 * POST /api/v1/runs/script returns { data: { run_id } }; useRunStatus then
 * polls GET /api/v1/runs/{run_id} and GET /api/v1/runs/{run_id}/jobs until
 * the run reaches a terminal state.
 *
 * Security A9.1: script names, params, run/job output, and status strings are
 * untrusted-origin data — rendered as JSX text nodes only, never
 * dangerouslySetInnerHTML.
 *
 * Destructive-action confirm gate (AC): the Run button only fires after the
 * user sees the resolved steward count and explicitly clicks "Confirm run" —
 * matching the PushPanel pattern (cfg-overlay/cfg-modal).
 */
import { useState } from 'react'
import { apiFetch } from '../api/client.ts'
import SelectorInput from '../shell/SelectorInput.tsx'
import { useRunStatus, useRunJobs, type ScriptMetadata } from './useScripts.ts'

interface RunPanelProps {
  script: ScriptMetadata
  onClose: () => void
}

interface ConfirmState {
  targetCount: number
  selector: string
  params: Record<string, string>
}

function runStatusTone(status: string): string {
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

const RUN_TERMINAL_SET = new Set(['completed', 'failed', 'cancelled'])

export default function RunPanel({ script, onClose }: RunPanelProps) {
  const [selector, setSelector] = useState('')
  const [params, setParams] = useState<Record<string, string>>(() =>
    Object.fromEntries(script.parameters.map((p) => [p.name, '']))
  )

  const [resolving, setResolving] = useState(false)
  const [resolveError, setResolveError] = useState<string | null>(null)
  const [resolvedCount, setResolvedCount] = useState<number | null>(null)

  const [confirm, setConfirm] = useState<ConfirmState | null>(null)
  const [running, setRunning] = useState(false)
  const [runError, setRunError] = useState<string | null>(null)
  const [activeRunId, setActiveRunId] = useState<string | null>(null)

  const { run: runStatus } = useRunStatus(activeRunId)
  const isRunTerminal = runStatus !== null && RUN_TERMINAL_SET.has(runStatus.status)
  const { jobs: runJobs } = useRunJobs(activeRunId, isRunTerminal)

  async function handleResolve() {
    if (!selector.trim()) {
      setResolveError('Selector is required')
      return
    }
    setResolving(true)
    setResolveError(null)
    setResolvedCount(null)
    try {
      const qp = new URLSearchParams()
      qp.set('limit', '1')
      qp.set('q', selector.trim())
      const response = await apiFetch(`/api/v1/stewards?${qp.toString()}`)
      if (!response.ok) throw new Error(`Fleet query failed — ${response.status}`)
      const body = (await response.json()) as Record<string, unknown>
      const data = body?.data as Record<string, unknown> | undefined
      const total = typeof data?.total === 'number' ? data.total : 0
      setResolvedCount(total)
    } catch (cause: unknown) {
      setResolveError(
        cause instanceof Error && cause.message ? cause.message : 'Fleet query failed',
      )
    } finally {
      setResolving(false)
    }
  }

  function handleRequestRun() {
    if (!selector.trim()) {
      setRunError('Selector is required')
      return
    }
    if (resolvedCount === null) {
      setRunError('Resolve target count first')
      return
    }
    setRunError(null)
    const activeParams = Object.fromEntries(
      Object.entries(params).filter(([, v]) => v.trim()).map(([k, v]) => [k, v.trim()])
    )
    setConfirm({
      targetCount: resolvedCount,
      selector: selector.trim(),
      params: activeParams,
    })
  }

  async function handleConfirmRun() {
    if (!confirm) return
    setRunning(true)
    setRunError(null)
    setActiveRunId(null)
    setConfirm(null)
    try {
      const body = {
        target: confirm.selector,
        script_id: script.id,
        params: confirm.params,
      }
      const response = await apiFetch('/api/v1/runs/script', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      if (!response.ok) {
        const errBody = (await response.json().catch(() => ({}))) as Record<string, unknown>
        throw new Error(
          (errBody?.error as string) || `Run failed — ${response.status}`,
        )
      }
      const result = (await response.json()) as Record<string, unknown>
      const data = result?.data as Record<string, unknown> | undefined
      setActiveRunId((data?.run_id as string) || null)
    } catch (cause: unknown) {
      setRunError(
        cause instanceof Error && cause.message ? cause.message : 'Run failed',
      )
    } finally {
      setRunning(false)
    }
  }

  const canResolve = selector.trim().length > 0 && !resolving
  const canRequestRun =
    selector.trim().length > 0 &&
    resolvedCount !== null &&
    !running &&
    !activeRunId

  return (
    <div className="cfg-push-panel" data-testid="run-panel">
      <div className="cfg-push-form">
        <div className="cfg-push-row">
          <div className="cfg-push-field">
            <span className="cfg-push-label">Target selector</span>
            <SelectorInput
              value={selector}
              onChange={(next) => {
                setSelector(next)
                setResolvedCount(null)
              }}
              className="wide"
              ariaLabel="Target selector"
              placeholder="name:web* os:linux tag:prod"
              hintId="run-selector-hint"
              hintTestId="run-selector-syntax"
            />
          </div>
        </div>

        {script.parameters.length > 0 && (
          <div className="cfg-push-row">
            {script.parameters.map((p) => (
              <div key={p.name} className="cfg-push-field">
                <span className="cfg-push-label">
                  {p.name}{p.required ? ' *' : ''}
                </span>
                <input
                  type="text"
                  aria-label={p.name}
                  placeholder={p.description || p.name}
                  value={params[p.name] ?? ''}
                  onChange={(e) =>
                    setParams((prev) => ({ ...prev, [p.name]: e.target.value }))
                  }
                  data-testid={`param-input-${p.name}`}
                />
              </div>
            ))}
          </div>
        )}

        <div className="cfg-push-actions">
          <button
            type="button"
            className="cfg-btn-secondary"
            disabled={!canResolve}
            onClick={handleResolve}
            data-testid="resolve-btn"
          >
            {resolving ? 'Resolving…' : 'Resolve targets'}
          </button>

          {resolvedCount !== null && (
            <span className="cfg-push-count" data-testid="run-target-count">
              {resolvedCount} steward{resolvedCount !== 1 ? 's' : ''} match
            </span>
          )}

          {resolveError && (
            <span className="cfg-validation-err" data-testid="run-resolve-error">
              {resolveError}
            </span>
          )}

          <button
            type="button"
            className="cfg-btn"
            disabled={!canRequestRun}
            onClick={handleRequestRun}
            data-testid="run-btn"
          >
            Run script
          </button>

          <button
            type="button"
            className="cfg-btn-secondary"
            onClick={onClose}
          >
            Cancel
          </button>
        </div>

        {runError && (
          <div className="cfg-validation-err" data-testid="run-error">
            {runError}
          </div>
        )}

        {activeRunId !== null && runStatus !== null && (
          <div className="cfg-push-status" data-testid="run-status">
            <span className={`pill ${runStatusTone(runStatus.status)}`}>
              <span className="dot" />
              {runStatus.status}
            </span>
            <span className="mono2">
              Run ID: {activeRunId}
            </span>
            <span className="mono2">
              Jobs: {runStatus.completed_jobs}/{runStatus.job_count}
              {runStatus.failed_jobs > 0
                ? ` (${runStatus.failed_jobs} failed)`
                : ''}
            </span>
          </div>
        )}

        {runJobs.length > 0 && (
          <div className="cfg-deployment-breakdown" data-testid="run-jobs-table-container">
            <table className="tbl" data-testid="run-jobs-table">
              <thead>
                <tr>
                  <th>Steward</th>
                  <th>Status</th>
                  <th>Exit code</th>
                </tr>
              </thead>
              <tbody>
                {runJobs.map((j) => (
                  <tr key={j.job_id} data-testid="run-job-row">
                    <td><span className="mono2">{j.device_id}</span></td>
                    <td>
                      <span className={`pill ${runStatusTone(j.status)}`}>
                        <span className="dot" />
                        {j.status}
                      </span>
                    </td>
                    <td><span className="mono2">{j.exit_code}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {confirm !== null && (
        <div
          className="cfg-overlay"
          role="dialog"
          aria-modal="true"
          aria-labelledby="run-confirm-title"
        >
          <div className="cfg-modal">
            <h3 id="run-confirm-title">Confirm script run</h3>
            <p>
              This will run script <b>{script.name}</b> against stewards matching{' '}
              <code>{confirm.selector}</code>.
            </p>
            <div className="cfg-modal-count" data-testid="run-confirm-count">
              {confirm.targetCount} steward{confirm.targetCount !== 1 ? 's' : ''} will
              execute this script
            </div>
            <p>This action will run against active endpoints. Proceed?</p>
            <div className="cfg-modal-actions">
              <button
                type="button"
                className="cfg-btn-secondary"
                onClick={() => setConfirm(null)}
              >
                Cancel
              </button>
              <button
                type="button"
                className="cfg-btn-danger"
                onClick={handleConfirmRun}
                data-testid="run-confirm-btn"
              >
                Confirm run
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
