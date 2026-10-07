// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * "Allow support access" dialog (Issue #4588, ADR-025 Decision 2(a)).
 *
 * An MSP admin names a root operator's principal ID and a duration. The POST goes
 * through apiFetch, so a CFGMS-StepUp 401 runs the existing step-up modal. A
 * rejection (400 MISSING_PRINCIPAL_ID or any other refusal) keeps the dialog open
 * with the entered values and shows the server's message inline.
 */
import { useState } from 'react'
import {
  createAccessGrant,
  errCodeMissingPrincipalID,
  grantMaxMinutes,
  grantMinMinutes,
  justificationMaxLen,
  justificationMinLen,
  type Crossing,
} from './useTenantCrossings.ts'
import { TenantApiError } from './useTenants.ts'

export default function SupportAccessDialog({
  tenantId,
  tenantName,
  onGranted,
  onClose,
}: {
  tenantId: string
  tenantName: string
  onGranted: (crossing: Crossing) => void
  onClose: () => void
}) {
  const [principalId, setPrincipalId] = useState('')
  const [duration, setDuration] = useState('60')
  const [justification, setJustification] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [principalError, setPrincipalError] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  async function handleSubmit() {
    setPrincipalError(null)
    setError(null)
    const principal = principalId.trim()
    if (!principal) {
      setPrincipalError('Operator principal ID is required')
      return
    }
    const minutes = Number(duration)
    if (!Number.isInteger(minutes) || minutes < grantMinMinutes || minutes > grantMaxMinutes) {
      setError(`Duration must be a whole number of minutes between ${grantMinMinutes} and ${grantMaxMinutes}`)
      return
    }
    const reason = justification.trim()
    if (reason !== '' && (reason.length < justificationMinLen || reason.length > justificationMaxLen)) {
      setError(`Justification must be ${justificationMinLen}-${justificationMaxLen} characters`)
      return
    }
    setSubmitting(true)
    try {
      const crossing = await createAccessGrant(tenantId, {
        principalId: principal,
        durationMinutes: minutes,
        justification: reason || undefined,
      })
      onGranted(crossing)
    } catch (cause: unknown) {
      const message = cause instanceof Error && cause.message ? cause.message : 'Grant support access failed'
      if (cause instanceof TenantApiError && (cause.code === errCodeMissingPrincipalID || cause.status === 400)) {
        setPrincipalError(message)
      } else {
        setError(message)
      }
      setSubmitting(false)
    }
  }

  return (
    <div className="wf-overlay" role="dialog" aria-modal="true" aria-labelledby="support-access-title">
      <div className="wf-modal" data-testid="support-access-dialog">
        <h3 id="support-access-title">Allow support access to {tenantName}</h3>
        <div className="wf-form">
          <div className="wf-form-field">
            <span className="wf-form-label">Operator principal ID *</span>
            <input
              type="text"
              aria-label="Operator principal ID"
              value={principalId}
              onChange={(e) => setPrincipalId(e.target.value)}
              aria-invalid={principalError !== null}
              data-testid="support-principal-input"
            />
            <span style={{ fontSize: '0.75rem', color: 'var(--color-muted)' }} data-testid="support-principal-help">
              Enter the root operator&apos;s principal ID — the support person you are granting
              access to, not your own.
            </span>
            {principalError && (
              <span className="wf-form-error" role="alert" data-testid="support-principal-error">
                {principalError}
              </span>
            )}
          </div>
          <div className="wf-form-field">
            <span className="wf-form-label">Duration (minutes) *</span>
            <input
              type="number"
              aria-label="Duration in minutes"
              min={grantMinMinutes}
              max={grantMaxMinutes}
              value={duration}
              onChange={(e) => setDuration(e.target.value)}
              data-testid="support-duration-input"
            />
          </div>
          <div className="wf-form-field">
            <span className="wf-form-label">Justification</span>
            <textarea
              aria-label="Justification"
              rows={3}
              maxLength={justificationMaxLen}
              value={justification}
              onChange={(e) => setJustification(e.target.value)}
              data-testid="support-justification-input"
            />
          </div>
        </div>
        {error && (
          <div className="wf-form-error" role="alert" data-testid="support-error">
            {error}
          </div>
        )}
        <div className="wf-modal-actions">
          <button type="button" className="wf-btn-secondary" onClick={onClose} data-testid="support-cancel-btn">
            Cancel
          </button>
          <button
            type="button"
            className="wf-btn"
            disabled={submitting}
            onClick={() => void handleSubmit()}
            data-testid="support-submit-btn"
          >
            {submitting ? 'Granting…' : 'Allow support access'}
          </button>
        </div>
      </div>
    </div>
  )
}
