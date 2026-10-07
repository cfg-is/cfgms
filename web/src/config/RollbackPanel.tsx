// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Rollback panel (Story #2730): rollback points / preview / execute / history
 * for a single steward. Destructive-action confirm gate (AC): the execute path
 * shows a confirm dialog before POST /api/v1/rollback/execute fires.
 *
 * Routes used:
 *   GET  /api/v1/rollback/points?target_type=steward&target_id={id}
 *   POST /api/v1/rollback/preview
 *   POST /api/v1/rollback/execute
 *   GET  /api/v1/rollback/{id}/status
 *   GET  /api/v1/rollback/history?target_type=steward&target_id={id}
 */
import { useState } from 'react'
import { apiFetch } from '../api/client.ts'
import {
  useRollbackPoints,
  useRollbackHistory,
  parseRollbackPreview,
  type RollbackPoint,
  type RollbackOperation,
  type RollbackPreview,
  type ConfigurationChange,
} from './useConfigs.ts'

interface RollbackPanelProps {
  stewardId: string
}

type PanelView = 'points' | 'history'

function riskTone(level: string): string {
  switch (level) {
    case 'critical':
    case 'high':
      return 'crit'
    case 'medium':
      return 'warn'
    default:
      return 'neutral'
  }
}

function statusTone(status: string): string {
  switch (status) {
    case 'completed':
      return 'ok'
    case 'failed':
    case 'cancelled':
      return 'crit'
    case 'in_progress':
    case 'validating':
      return 'warn'
    default:
      return 'neutral'
  }
}

function DiffLine({ line }: { line: string }) {
  let cls = 'cfg-diff-line'
  if (line.startsWith('+')) cls += ' add'
  else if (line.startsWith('-')) cls += ' del'
  return <div className={cls}>{line}</div>
}

function ChangeRow({ change }: { change: ConfigurationChange }) {
  return (
    <div className="cfg-rb-change" data-testid="rb-change-row">
      <div className="cfg-rb-change-header">
        <span className="mono2 cfg-rb-change-path">{change.path}</span>
        {change.module && <span className="mut">{change.module}</span>}
        <span className={`pill ${riskTone(change.risk)}`}>
          <span className="dot" />
          {change.risk || 'unknown'}
        </span>
      </div>
      {change.diff && (
        <pre className="cfg-diff-block">
          {change.diff.split('\n').map((line, i) => (
            <DiffLine key={i} line={line} />
          ))}
        </pre>
      )}
    </div>
  )
}

function LoadingRows() {
  return (
    <div aria-label="Loading rollback data" data-testid="rb-loading">
      {Array.from({ length: 3 }, (_, i) => (
        <div className="skrow" key={i}>
          <span className="skel" style={{ width: '70%' }} />
          <span className="skel" style={{ width: '50%' }} />
          <span className="skel" style={{ width: '60%' }} />
          <span className="skel" style={{ width: '40%' }} />
          <span className="skel" style={{ width: '30%' }} />
        </div>
      ))}
    </div>
  )
}

function ErrorNotice({ detail, onRetry }: { detail: string; onRetry: () => void }) {
  return (
    <div className="notice err" role="alert">
      <div className="ic">!</div>
      <h3>Couldn&apos;t load rollback data</h3>
      <p>{detail}</p>
      <button type="button" className="btn" onClick={onRetry}>
        Retry
      </button>
    </div>
  )
}

function EmptyPoints() {
  return (
    <div className="notice empty" data-testid="rb-empty-points">
      <div className="ic">◍</div>
      <h3>No rollback points</h3>
      <p>No configuration history is available for this steward.</p>
    </div>
  )
}

function EmptyHistory() {
  return (
    <div className="notice empty" data-testid="rb-empty-history">
      <div className="ic">◍</div>
      <h3>No rollback history</h3>
      <p>No rollback operations have been performed on this steward.</p>
    </div>
  )
}

interface RollbackPointRowProps {
  point: RollbackPoint
  selected: boolean
  onSelect: () => void
  onPreview: () => void
  onExecute: () => void
}

function RollbackPointRow({ point, selected, onSelect, onPreview, onExecute }: RollbackPointRowProps) {
  const shortSha = point.commit_sha.slice(0, 8)
  return (
    <div
      className={`cfg-rb-point${selected ? ' selected' : ''}`}
      onClick={onSelect}
      data-testid="rb-point-row"
    >
      <div className="cfg-rb-point-meta">
        <div className="cfg-rb-point-sha">{shortSha}</div>
        <div className="cfg-rb-point-msg">{point.message || '(no message)'}</div>
        <div className="cfg-rb-point-detail">
          {point.author} · {point.timestamp}
          {point.configurations.length > 0 && (
            <> · {point.configurations.length} config{point.configurations.length !== 1 ? 's' : ''}</>
          )}
        </div>
      </div>
      <div className="cfg-rb-point-actions" onClick={(e) => e.stopPropagation()}>
        {point.risk_level && (
          <span className={`pill ${riskTone(point.risk_level)}`}>
            <span className="dot" />
            {point.risk_level}
          </span>
        )}
        <button
          type="button"
          className="cfg-btn-secondary"
          disabled={!point.can_rollback}
          onClick={onPreview}
          data-testid="rb-preview-btn"
        >
          Preview
        </button>
        <button
          type="button"
          className="cfg-btn-danger"
          disabled={!point.can_rollback}
          onClick={onExecute}
          data-testid="rb-execute-btn"
        >
          Execute
        </button>
      </div>
    </div>
  )
}

function HistoryRow({ op }: { op: RollbackOperation }) {
  return (
    <tr data-testid="rb-history-row">
      <td className="mono2">{op.id.slice(0, 12)}</td>
      <td className="mono2">{op.rollback_to.slice(0, 8)}</td>
      <td>
        <span className={`pill ${statusTone(op.status)}`}>
          <span className="dot" />
          {op.status}
        </span>
      </td>
      <td className="mono2">{op.created_at}</td>
      <td className="mut">{op.reason || '—'}</td>
      <td className="c-spacer" />
    </tr>
  )
}

export default function RollbackPanel({ stewardId }: RollbackPanelProps) {
  const [view, setView] = useState<PanelView>('points')
  const [selectedSha, setSelectedSha] = useState<string | null>(null)

  const [preview, setPreview] = useState<RollbackPreview | null>(null)
  const [previewing, setPreviewing] = useState(false)
  const [previewError, setPreviewError] = useState<string | null>(null)

  const [confirmPoint, setConfirmPoint] = useState<RollbackPoint | null>(null)
  const [executing, setExecuting] = useState(false)
  const [executeError, setExecuteError] = useState<string | null>(null)
  const [executeResult, setExecuteResult] = useState<Record<string, unknown> | null>(null)

  const { points, loading: pointsLoading, error: pointsError, retry: retryPoints } =
    useRollbackPoints(stewardId)
  const { operations, loading: historyLoading, error: historyError, retry: retryHistory } =
    useRollbackHistory(stewardId)

  async function handlePreview(point: RollbackPoint) {
    setSelectedSha(point.commit_sha)
    setPreviewing(true)
    setPreview(null)
    setPreviewError(null)
    try {
      const body = {
        target_type: 'steward',
        target_id: stewardId,
        rollback_type: 'full',
        rollback_to: point.commit_sha,
        reason: 'Preview via web UI',
        dry_run: true,
      }
      const response = await apiFetch('/api/v1/rollback/preview', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      if (!response.ok) throw new Error(`Preview failed — ${response.status}`)
      const result = (await response.json()) as Record<string, unknown>
      setPreview(parseRollbackPreview(result?.preview))
    } catch (cause: unknown) {
      setPreviewError(
        cause instanceof Error && cause.message ? cause.message : 'Preview failed',
      )
    } finally {
      setPreviewing(false)
    }
  }

  function handleRequestExecute(point: RollbackPoint) {
    setSelectedSha(point.commit_sha)
    setConfirmPoint(point)
    setExecuteError(null)
  }

  async function handleConfirmExecute() {
    if (!confirmPoint) return
    setExecuting(true)
    setExecuteError(null)
    const point = confirmPoint
    setConfirmPoint(null)
    try {
      const body = {
        target_type: 'steward',
        target_id: stewardId,
        rollback_type: 'full',
        rollback_to: point.commit_sha,
        reason: 'Executed via web UI',
      }
      const response = await apiFetch('/api/v1/rollback/execute', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      if (!response.ok) {
        const errBody = (await response.json().catch(() => ({}))) as Record<string, unknown>
        throw new Error(
          (errBody?.error as string) || `Execute failed — ${response.status}`,
        )
      }
      const result = (await response.json()) as Record<string, unknown>
      setExecuteResult(result?.rollback as Record<string, unknown> ?? {})
    } catch (cause: unknown) {
      setExecuteError(
        cause instanceof Error && cause.message ? cause.message : 'Execute failed',
      )
    } finally {
      setExecuting(false)
    }
  }

  return (
    <div data-testid="rollback-panel">
      <div className="cfg-rb-tabs">
        <button
          type="button"
          className={`cfg-rb-tab${view === 'points' ? ' active' : ''}`}
          onClick={() => setView('points')}
        >
          Rollback Points
        </button>
        <button
          type="button"
          className={`cfg-rb-tab${view === 'history' ? ' active' : ''}`}
          onClick={() => setView('history')}
          data-testid="rb-history-tab"
        >
          History
        </button>
      </div>

      <div className="cfg-rb-body">
        {view === 'points' && (
          <>
            {pointsLoading ? (
              <LoadingRows />
            ) : pointsError !== null ? (
              <ErrorNotice detail={pointsError} onRetry={retryPoints} />
            ) : points.length === 0 ? (
              <EmptyPoints />
            ) : (
              points.map((point) => (
                <RollbackPointRow
                  key={point.commit_sha}
                  point={point}
                  selected={selectedSha === point.commit_sha}
                  onSelect={() => setSelectedSha(point.commit_sha)}
                  onPreview={() => handlePreview(point)}
                  onExecute={() => handleRequestExecute(point)}
                />
              ))
            )}

            {preview !== null && (
              <div className="cfg-rb-preview" data-testid="rb-preview-result">
                <h4>Preview</h4>
                {preview.changes.length === 0 ? (
                  <p className="mut" data-testid="rb-preview-no-changes">
                    No configuration changes detected.
                  </p>
                ) : (
                  <div className="cfg-rb-changes">
                    {preview.changes.map((change, i) => (
                      <ChangeRow key={`${change.path}-${i}`} change={change} />
                    ))}
                  </div>
                )}
              </div>
            )}

            {previewing && (
              <div className="cfg-rb-preview" data-testid="rb-previewing">
                <span className="skel" style={{ width: '60%' }} />
              </div>
            )}

            {previewError && (
              <div className="cfg-validation-err" style={{ padding: '12px 14px' }} data-testid="rb-preview-error">
                {previewError}
              </div>
            )}

            {executeError && (
              <div className="cfg-validation-err" style={{ padding: '12px 14px' }} data-testid="rb-execute-error">
                {executeError}
              </div>
            )}

            {executeResult && (
              <div className="cfg-rb-preview" data-testid="rb-execute-result">
                <h4>Rollback initiated</h4>
                <p className="mut">
                  ID: {(executeResult.id as string) || '—'} · Status:{' '}
                  {(executeResult.status as string) || '—'}
                </p>
              </div>
            )}
          </>
        )}

        {view === 'history' && (
          <>
            {historyLoading ? (
              <LoadingRows />
            ) : historyError !== null ? (
              <ErrorNotice detail={historyError} onRetry={retryHistory} />
            ) : operations.length === 0 ? (
              <EmptyHistory />
            ) : (
              <table className="tbl" data-testid="rb-history-table">
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Target version</th>
                    <th>Status</th>
                    <th>Started</th>
                    <th>Reason</th>
                    <th className="c-spacer" aria-hidden="true" />
                  </tr>
                </thead>
                <tbody>
                  {operations.map((op) => (
                    <HistoryRow key={op.id} op={op} />
                  ))}
                </tbody>
              </table>
            )}
          </>
        )}
      </div>

      {confirmPoint !== null && (
        <div className="cfg-overlay" role="dialog" aria-modal="true" aria-labelledby="rb-confirm-title">
          <div className="cfg-modal">
            <h3 id="rb-confirm-title">Confirm rollback</h3>
            <p>
              Roll back <b>{stewardId}</b> to version{' '}
              <b>{confirmPoint.commit_sha.slice(0, 8)}</b>.
            </p>
            <div className="cfg-modal-count" data-testid="rb-confirm-point">
              {confirmPoint.message || confirmPoint.commit_sha.slice(0, 16)}
              {confirmPoint.configurations.length > 0 && (
                <span style={{ marginLeft: 8 }} className="mut">
                  · {confirmPoint.configurations.length} config
                  {confirmPoint.configurations.length !== 1 ? 's' : ''} affected
                </span>
              )}
            </div>
            <p>
              This will revert endpoint configurations. This action cannot be undone
              without another rollback.
            </p>
            {executing && <p className="mut">Executing…</p>}
            <div className="cfg-modal-actions">
              <button
                type="button"
                className="cfg-btn-secondary"
                disabled={executing}
                onClick={() => setConfirmPoint(null)}
              >
                Cancel
              </button>
              <button
                type="button"
                className="cfg-btn-danger"
                disabled={executing}
                onClick={handleConfirmExecute}
                data-testid="rb-confirm-execute-btn"
              >
                Confirm rollback
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
