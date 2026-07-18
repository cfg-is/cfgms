// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Push panel (Story #2730): selector-targeted config push with a confirm step
 * that shows the resolved steward count before committing. POST /api/v1/config/push
 * returns 202 + a push_id; usePushStatus polls GET /api/v1/config/push/{id}
 * until the operation reaches a terminal state.
 *
 * Destructive-action confirm gate (AC): the Push button only fires after the
 * user sees a count and explicitly clicks "Confirm push" — a modal confirms
 * the resolved target count before the fleet-wide action commits.
 */
import { useState } from 'react'
import { apiFetch } from '../api/client.ts'
import { usePushStatus } from './useConfigs.ts'

interface PushPanelProps {
  onClose: () => void
}

interface ConfirmState {
  targetCount: number
  configId: string
  version: string
  tenantId: string
  selector: string
}

function statusTone(status: string): string {
  switch (status) {
    case 'completed':
      return 'ok'
    case 'failed':
      return 'crit'
    case 'in_progress':
    case 'accepted':
      return 'warn'
    default:
      return 'neutral'
  }
}

export default function PushPanel({ onClose }: PushPanelProps) {
  const [selector, setSelector] = useState('')
  const [configId, setConfigId] = useState('')
  const [version, setVersion] = useState('')
  const [tenantId, setTenantId] = useState('')

  const [resolving, setResolving] = useState(false)
  const [resolveError, setResolveError] = useState<string | null>(null)
  const [resolvedCount, setResolvedCount] = useState<number | null>(null)

  const [confirm, setConfirm] = useState<ConfirmState | null>(null)
  const [pushing, setPushing] = useState(false)
  const [pushError, setPushError] = useState<string | null>(null)
  const [activePushId, setActivePushId] = useState<string | null>(null)

  const { status: pushStatus } = usePushStatus(activePushId)

  async function handleResolve() {
    if (!selector.trim()) {
      setResolveError('Selector is required')
      return
    }
    setResolving(true)
    setResolveError(null)
    setResolvedCount(null)
    try {
      const params = new URLSearchParams()
      params.set('limit', '1')
      params.set('q', selector.trim())
      const response = await apiFetch(`/api/v1/stewards?${params.toString()}`)
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

  function handleRequestPush() {
    if (!selector.trim() || !configId.trim() || !tenantId.trim()) {
      setPushError('Selector, Config ID, and Tenant ID are required')
      return
    }
    if (resolvedCount === null) {
      setPushError('Resolve target count first')
      return
    }
    setPushError(null)
    setConfirm({
      targetCount: resolvedCount,
      configId: configId.trim(),
      version: version.trim() || 'latest',
      tenantId: tenantId.trim(),
      selector: selector.trim(),
    })
  }

  async function handleConfirmPush() {
    if (!confirm) return
    setPushing(true)
    setPushError(null)
    setActivePushId(null)
    setConfirm(null)
    try {
      const body = {
        selector: confirm.selector,
        config_id: confirm.configId,
        version: confirm.version,
        tenant_id: confirm.tenantId,
        policies: {},
        modules: [],
        source: 'web-ui',
      }
      const response = await apiFetch('/api/v1/config/push', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      if (!response.ok) {
        const errBody = (await response.json().catch(() => ({}))) as Record<string, unknown>
        throw new Error(
          (errBody?.error as string) || `Push failed — ${response.status}`,
        )
      }
      const result = (await response.json()) as Record<string, unknown>
      setActivePushId((result?.push_id as string) || null)
    } catch (cause: unknown) {
      setPushError(
        cause instanceof Error && cause.message ? cause.message : 'Push failed',
      )
    } finally {
      setPushing(false)
    }
  }

  const canResolve = selector.trim().length > 0 && !resolving
  const canRequestPush =
    selector.trim().length > 0 &&
    configId.trim().length > 0 &&
    tenantId.trim().length > 0 &&
    resolvedCount !== null &&
    !pushing &&
    !activePushId

  return (
    <div className="cfg-push-panel" data-testid="push-panel">
      <div className="cfg-push-form">
        <div className="cfg-push-row">
          <div className="cfg-push-field">
            <span className="cfg-push-label">Selector</span>
            <input
              type="text"
              className="wide"
              aria-label="Selector"
              placeholder="name:web* os:linux tag:prod"
              value={selector}
              onChange={(e) => {
                setSelector(e.target.value)
                setResolvedCount(null)
              }}
            />
          </div>
          <div className="cfg-push-field">
            <span className="cfg-push-label">Config ID</span>
            <input
              type="text"
              aria-label="Config ID"
              placeholder="steward-id"
              value={configId}
              onChange={(e) => setConfigId(e.target.value)}
            />
          </div>
          <div className="cfg-push-field">
            <span className="cfg-push-label">Version</span>
            <input
              type="text"
              aria-label="Version"
              placeholder="latest"
              value={version}
              onChange={(e) => setVersion(e.target.value)}
            />
          </div>
          <div className="cfg-push-field">
            <span className="cfg-push-label">Tenant ID</span>
            <input
              type="text"
              aria-label="Tenant ID"
              placeholder="root"
              value={tenantId}
              onChange={(e) => setTenantId(e.target.value)}
            />
          </div>
        </div>

        <div className="cfg-push-actions">
          <button
            type="button"
            className="cfg-btn-secondary"
            disabled={!canResolve}
            onClick={handleResolve}
          >
            {resolving ? 'Resolving…' : 'Resolve targets'}
          </button>

          {resolvedCount !== null && (
            <span className="cfg-push-count" data-testid="push-target-count">
              {resolvedCount} steward{resolvedCount !== 1 ? 's' : ''} match
            </span>
          )}

          {resolveError && (
            <span className="cfg-validation-err" data-testid="push-resolve-error">
              {resolveError}
            </span>
          )}

          <button
            type="button"
            className="cfg-btn"
            disabled={!canRequestPush}
            onClick={handleRequestPush}
          >
            Push config
          </button>

          <button
            type="button"
            className="cfg-btn-secondary"
            onClick={onClose}
          >
            Cancel
          </button>
        </div>

        {pushError && (
          <div className="cfg-validation-err" data-testid="push-error">
            {pushError}
          </div>
        )}

        {activePushId && pushStatus && (
          <div className="cfg-push-status" data-testid="push-status">
            <span className={`pill ${statusTone(pushStatus.status)}`}>
              <span className="dot" />
              {pushStatus.status}
            </span>
            <span className="mono2">
              Push ID: {activePushId}
            </span>
          </div>
        )}
      </div>

      {confirm !== null && (
        <div className="cfg-overlay" role="dialog" aria-modal="true" aria-labelledby="push-confirm-title">
          <div className="cfg-modal">
            <h3 id="push-confirm-title">Confirm config push</h3>
            <p>
              This will push config <b>{confirm.configId}</b> (version{' '}
              <b>{confirm.version}</b>) to stewards matching{' '}
              <code>{confirm.selector}</code>.
            </p>
            <div className="cfg-modal-count" data-testid="push-confirm-count">
              {confirm.targetCount} steward{confirm.targetCount !== 1 ? 's' : ''} will
              receive this push
            </div>
            <p>This action will affect active endpoint configurations. Proceed?</p>
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
                onClick={handleConfirmPush}
                data-testid="push-confirm-btn"
              >
                Confirm push
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
