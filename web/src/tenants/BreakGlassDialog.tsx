// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Break-glass request dialog (Issue #4588, ADR-025 Decision 2(b)).
 *
 * Reuses the shipped step-up write pattern: the POST goes through apiFetch, so a
 * CFGMS-StepUp 401 runs the existing step-up modal and retries transparently.
 * The justification is held only in this form's state and sent once, as the
 * X-Justification header; it is never logged. The server's echo of it is kept
 * as the banner's `reason` in sessionStorage (useTenantCrossings.ts), as the
 * issue specifies, so the banner can survive a reload.
 */
import { useState } from 'react'
import {
  breakGlassWindowMinutes,
  justificationMaxLen,
  justificationMinLen,
  requestBreakGlass,
  type Crossing,
} from './useTenantCrossings.ts'

export default function BreakGlassDialog({
  tenantId: initialTenantId = '',
  onInvoked,
  onClose,
}: {
  /** Pre-fills the target (a boundary row's MSP); the field stays editable. */
  tenantId?: string
  onInvoked: (crossing: Crossing) => void
  onClose: () => void
}) {
  const [tenantId, setTenantId] = useState(initialTenantId)
  const [justification, setJustification] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function handleSubmit() {
    const target = tenantId.trim()
    const reason = justification.trim()
    if (!target) {
      setError('Target tenant ID is required')
      return
    }
    if (reason.length < justificationMinLen || reason.length > justificationMaxLen) {
      setError(`Justification must be ${justificationMinLen}-${justificationMaxLen} characters`)
      return
    }
    setSubmitting(true)
    setError(null)
    try {
      const crossing = await requestBreakGlass(target, reason)
      onInvoked(crossing)
    } catch (cause: unknown) {
      setError(cause instanceof Error && cause.message ? cause.message : 'Break-glass request failed')
      setSubmitting(false)
    }
  }

  return (
    <div className="wf-overlay" role="dialog" aria-modal="true" aria-labelledby="break-glass-title">
      <div className="wf-modal" data-testid="break-glass-dialog">
        <h3 id="break-glass-title">Request break-glass</h3>
        <p>
          Grants a root-scoped session access to one MSP tenant for a fixed{' '}
          <b data-testid="break-glass-window">{breakGlassWindowMinutes}-minute</b> window. The
          invocation is audited at critical severity and visible to the MSP.
        </p>
        <div className="wf-form">
          <div className="wf-form-field">
            <span className="wf-form-label">Target tenant ID *</span>
            <input
              type="text"
              aria-label="Target tenant ID"
              value={tenantId}
              onChange={(e) => setTenantId(e.target.value)}
              data-testid="break-glass-tenant-input"
            />
          </div>
          <div className="wf-form-field">
            <span className="wf-form-label">Justification *</span>
            <textarea
              aria-label="Justification"
              rows={4}
              maxLength={justificationMaxLen}
              value={justification}
              onChange={(e) => setJustification(e.target.value)}
              data-testid="break-glass-justification-input"
            />
            <span style={{ fontSize: '0.75rem', color: 'var(--color-muted)' }}>
              {justificationMinLen}-{justificationMaxLen} characters. Recorded in the audit log.
            </span>
          </div>
        </div>
        {error && (
          <div className="wf-form-error" role="alert" data-testid="break-glass-error">
            {error}
          </div>
        )}
        <div className="wf-modal-actions">
          <button
            type="button"
            className="wf-btn-secondary"
            onClick={onClose}
            data-testid="break-glass-cancel-btn"
          >
            Cancel
          </button>
          <button
            type="button"
            className="wf-btn-danger"
            disabled={submitting}
            onClick={() => void handleSubmit()}
            data-testid="break-glass-submit-btn"
          >
            {submitting ? 'Requesting…' : 'Request break-glass'}
          </button>
        </div>
      </div>
    </div>
  )
}
