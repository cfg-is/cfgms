// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Certificate lifecycle view (Issue #3135) — the /certificates route entry point.
 * Fetches GET /api/v1/certificates, renders a table with expiry/days-remaining
 * column, provision form, revoke action (confirm modal), and CA-rotation action
 * (distinct fleet-impact-worded confirm that requires typing ROTATE).
 *
 * Days-remaining thresholds (founder-approved 2026-07-30):
 *   > 30d  → normal (no highlight)
 *   8–30d  → amber/warn
 *   ≤ 7d   → red/crit
 *
 * Status pills:
 *   Revoked  → neutral  (is_valid=false, days>=0)
 *   Expired  → crit     (is_valid=false, days<0)
 *   Valid    → ok/warn/crit based on days_until_expiration
 *
 * Provision (POST /api/v1/certificates/provision) opens an inline form panel.
 * Revoke (POST /api/v1/certificates/{serial}/revoke) requires a confirm modal.
 * CA rotation (POST /api/v1/certificates/signing/rotate) requires a distinct
 * amber-bordered modal with explicit fleet-impact copy; the confirm button enables
 * only when the operator types ROTATE in the confirmation input.
 *
 * Security A9.1: serial_number, common_name, steward_id come from server-controlled
 * data. All values reach the DOM as JSX text nodes — never dangerouslySetInnerHTML.
 */
import { useState } from 'react'
import {
  useCertificateList,
  provisionCertificate,
  revokeCertificate,
  rotateSigningCA,
  type CertificateInfo,
} from './useCertificates.ts'

// ── Certificate status helpers ────────────────────────────────────────────────

type CertStatus = 'valid-ok' | 'valid-warn' | 'valid-crit' | 'expired' | 'revoked'

function certStatus(cert: CertificateInfo): CertStatus {
  if (!cert.is_valid) {
    return cert.days_until_expiration < 0 ? 'expired' : 'revoked'
  }
  if (cert.days_until_expiration <= 7) return 'valid-crit'
  if (cert.days_until_expiration <= 30) return 'valid-warn'
  return 'valid-ok'
}

// ── Status pill ───────────────────────────────────────────────────────────────

function StatusPill({ cert }: { cert: CertificateInfo }) {
  const status = certStatus(cert)
  if (status === 'revoked') {
    return (
      <span className="pill neutral" data-testid="cert-status-pill">
        <span className="dot" />
        Revoked
      </span>
    )
  }
  if (status === 'expired') {
    return (
      <span className="pill crit" data-testid="cert-status-pill">
        <span className="dot" />
        Expired
      </span>
    )
  }
  const pillClass =
    status === 'valid-crit' ? 'crit' : status === 'valid-warn' ? 'warn' : 'ok'
  return (
    <span className={`pill ${pillClass}`} data-testid="cert-status-pill">
      <span className="dot" />
      Valid
    </span>
  )
}

// ── Days remaining cell ───────────────────────────────────────────────────────

function DaysCell({ cert }: { cert: CertificateInfo }) {
  const status = certStatus(cert)
  // Revoked and expired certs show no days-remaining value (per mockup).
  if (status === 'revoked' || status === 'expired') return null
  const days = cert.days_until_expiration
  if (status === 'valid-crit') {
    return (
      <span className="days crit" data-testid="cert-days">
        {days}d left
      </span>
    )
  }
  if (status === 'valid-warn') {
    return (
      <span className="days warn" data-testid="cert-days">
        {days}d left
      </span>
    )
  }
  return (
    <span className="days" data-testid="cert-days">
      {days}d left
    </span>
  )
}

// ── Skeleton loading rows ─────────────────────────────────────────────────────

function LoadingRows() {
  return (
    <div data-testid="certs-loading" aria-label="Loading certificates">
      {Array.from({ length: 3 }, (_, i) => (
        <div className="skrow" key={i}>
          <span className="skel" style={{ width: '30%' }} />
          <span className="skel" style={{ width: '40%' }} />
          <span className="skel" style={{ width: '20%' }} />
          <span className="skel" style={{ width: '25%' }} />
        </div>
      ))}
    </div>
  )
}

// ── Error notice ──────────────────────────────────────────────────────────────

function ErrorNotice({ detail, onRetry }: { detail: string; onRetry: () => void }) {
  return (
    <div className="notice err" role="alert">
      <div className="ic">!</div>
      <h3>Couldn&apos;t load certificates</h3>
      <p>The certificate list request failed. Check your connection and try again.</p>
      <span className="mono2 detail">{detail}</span>
      <button type="button" className="btn" onClick={onRetry}>
        Retry
      </button>
    </div>
  )
}

// ── Empty state ───────────────────────────────────────────────────────────────

function CertEmpty() {
  return (
    <div className="notice empty" data-testid="certs-empty">
      <div className="ic">◍</div>
      <h3>No certificates found</h3>
      <p>No certificates have been provisioned yet. Use Provision certificate to get started.</p>
    </div>
  )
}

// ── Certificate table row ─────────────────────────────────────────────────────

function CertRow({
  cert,
  onRevoke,
}: {
  cert: CertificateInfo
  onRevoke: () => void
}) {
  const status = certStatus(cert)
  const canRevoke = status === 'valid-ok' || status === 'valid-warn' || status === 'valid-crit'
  const expiresDate = cert.expires_at
    ? new Date(cert.expires_at).toLocaleDateString()
    : '—'

  return (
    <tr data-testid="cert-row" className={status === 'revoked' ? 'revoked' : ''}>
      <td>
        <span className="mono2">{cert.serial_number}</span>
      </td>
      <td>
        <span className="nm">{cert.common_name || '—'}</span>
      </td>
      <td>
        <span className="mono2">{cert.steward_id || '—'}</span>
      </td>
      <td>
        <span className="mut">{expiresDate}</span>
        {' '}
        <DaysCell cert={cert} />
      </td>
      <td>
        <StatusPill cert={cert} />
      </td>
      <td>
        {canRevoke ? (
          <button
            type="button"
            className="wf-btn-sm-danger"
            onClick={onRevoke}
            data-testid="cert-revoke-btn"
          >
            Revoke
          </button>
        ) : (
          <button
            type="button"
            className="wf-btn-sm"
            disabled
            data-testid="cert-revoke-btn-disabled"
          >
            Revoke
          </button>
        )}
      </td>
    </tr>
  )
}

// ── Provision form panel ──────────────────────────────────────────────────────

interface ProvisionFormState {
  stewardId: string
  commonName: string
  validityDays: string
}

function defaultProvisionForm(): ProvisionFormState {
  return { stewardId: '', commonName: '', validityDays: '365' }
}

function ProvisionPanel({
  onSaved,
  onClose,
}: {
  onSaved: () => void
  onClose: () => void
}) {
  const [form, setForm] = useState<ProvisionFormState>(defaultProvisionForm)
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState<string | null>(null)

  function set<K extends keyof ProvisionFormState>(key: K, value: ProvisionFormState[K]) {
    setForm((prev) => ({ ...prev, [key]: value }))
  }

  async function handleSubmit() {
    if (!form.stewardId.trim()) {
      setSaveError('Steward ID is required')
      return
    }
    const validityDays = parseInt(form.validityDays, 10)
    setSaving(true)
    setSaveError(null)
    try {
      await provisionCertificate({
        stewardId: form.stewardId.trim(),
        commonName: form.commonName.trim() || undefined,
        validityDays: validityDays > 0 ? validityDays : undefined,
      })
      onSaved()
    } catch (cause: unknown) {
      setSaveError(
        cause instanceof Error && cause.message ? cause.message : 'Provision failed',
      )
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="wf-form-panel" data-testid="provision-panel">
      <div className="wf-form">
        <div className="wf-form-row">
          <div className="wf-form-field">
            <span className="wf-form-label">Steward ID *</span>
            <input
              type="text"
              aria-label="Steward ID"
              placeholder="new-host.acme-corp"
              value={form.stewardId}
              onChange={(e) => set('stewardId', e.target.value)}
              data-testid="provision-steward-input"
            />
          </div>
          <div className="wf-form-field">
            <span className="wf-form-label">Common Name (CN)</span>
            <input
              type="text"
              aria-label="Common Name"
              placeholder="new-host.acme-corp"
              value={form.commonName}
              onChange={(e) => set('commonName', e.target.value)}
              data-testid="provision-cn-input"
            />
          </div>
          <div className="wf-form-field">
            <span className="wf-form-label">Validity (days)</span>
            <input
              type="number"
              aria-label="Validity days"
              value={form.validityDays}
              min={1}
              onChange={(e) => set('validityDays', e.target.value)}
              data-testid="provision-validity-input"
            />
          </div>
        </div>
        <div className="wf-form-actions">
          <button
            type="button"
            className="wf-btn"
            disabled={saving}
            onClick={() => void handleSubmit()}
            data-testid="provision-save-btn"
          >
            {saving ? 'Provisioning…' : 'Provision certificate'}
          </button>
          <button type="button" className="wf-btn-secondary" onClick={onClose}>
            Cancel
          </button>
          {saveError && (
            <span className="wf-form-error" data-testid="provision-error">
              {saveError}
            </span>
          )}
        </div>
      </div>
    </div>
  )
}

// ── Main view ─────────────────────────────────────────────────────────────────

export default function CertificatesView() {
  const { certificates, loading, error, retry } = useCertificateList()
  const [showProvision, setShowProvision] = useState(false)
  const [revokingCert, setRevokingCert] = useState<CertificateInfo | null>(null)
  const [revoking, setRevoking] = useState(false)
  const [revokeError, setRevokeError] = useState<string | null>(null)
  const [showRotateModal, setShowRotateModal] = useState(false)
  const [rotateInput, setRotateInput] = useState('')
  const [rotating, setRotating] = useState(false)
  const [rotateError, setRotateError] = useState<string | null>(null)

  function openRotateModal() {
    setRotateInput('')
    setRotateError(null)
    setShowRotateModal(true)
  }

  function closeRotateModal() {
    setShowRotateModal(false)
    setRotateInput('')
    setRotateError(null)
  }

  async function handleConfirmRevoke() {
    if (!revokingCert) return
    const cert = revokingCert
    setRevoking(true)
    setRevokeError(null)
    setRevokingCert(null)
    try {
      await revokeCertificate(cert.serial_number)
      retry()
    } catch (cause: unknown) {
      setRevokeError(
        cause instanceof Error && cause.message ? cause.message : 'Revoke failed',
      )
    } finally {
      setRevoking(false)
    }
  }

  async function handleConfirmRotate() {
    if (rotateInput.trim() !== 'ROTATE') return
    setRotating(true)
    setRotateError(null)
    try {
      await rotateSigningCA(true)
      closeRotateModal()
    } catch (cause: unknown) {
      setRotateError(
        cause instanceof Error && cause.message ? cause.message : 'Rotation failed',
      )
    } finally {
      setRotating(false)
    }
  }

  return (
    <>
      <div className="htitle">
        <div>
          <h1>Certificates</h1>
          <p>Provision, monitor expiry, revoke, and rotate the signing CA for mTLS across the fleet.</p>
        </div>
        <button
          type="button"
          className="wf-btn-rotate"
          onClick={openRotateModal}
          data-testid="rotate-ca-btn"
        >
          Rotate signing CA
        </button>
      </div>

      <section className="panel">
        <div className="ptool">
          <button
            type="button"
            className={showProvision ? 'wf-btn' : 'wf-btn-secondary'}
            onClick={() => setShowProvision((v) => !v)}
            data-testid="toggle-provision-btn"
          >
            {showProvision ? 'Close' : '+ Provision certificate'}
          </button>
          {!loading && error === null && (
            <span className="cnt" data-testid="cert-count">
              {certificates.length} certificate{certificates.length !== 1 ? 's' : ''}
            </span>
          )}
        </div>

        {showProvision && (
          <ProvisionPanel
            onSaved={() => {
              setShowProvision(false)
              retry()
            }}
            onClose={() => setShowProvision(false)}
          />
        )}

        {revokeError && (
          <div className="wf-form-error" style={{ padding: '8px 14px' }} data-testid="revoke-error">
            {revokeError}
          </div>
        )}

        {loading ? (
          <LoadingRows />
        ) : error !== null ? (
          <ErrorNotice detail={error} onRetry={retry} />
        ) : certificates.length === 0 ? (
          <CertEmpty />
        ) : (
          <table className="tbl" data-testid="certs-table">
            <thead>
              <tr>
                <th>Serial</th>
                <th>Subject / CN</th>
                <th>Steward</th>
                <th>Expires</th>
                <th>Status</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {certificates.map((cert) => (
                <CertRow
                  key={cert.serial_number}
                  cert={cert}
                  onRevoke={() => {
                    setRevokeError(null)
                    setRevokingCert(cert)
                  }}
                />
              ))}
            </tbody>
          </table>
        )}
      </section>

      {/* Revoke confirm modal */}
      {revokingCert !== null && (
        <div
          className="wf-overlay"
          role="dialog"
          aria-modal="true"
          aria-labelledby="revoke-cert-title"
          data-testid="revoke-overlay"
        >
          <div className="wf-modal">
            <h3 id="revoke-cert-title">Revoke certificate?</h3>
            <p>
              This revokes the certificate for{' '}
              <b>{revokingCert.common_name}</b> (serial{' '}
              <b>{revokingCert.serial_number}</b>). Anything presenting it will
              be rejected on its next mTLS handshake.
            </p>
            <p>This action cannot be undone.</p>
            <div className="wf-modal-actions">
              <button
                type="button"
                className="wf-btn-secondary"
                disabled={revoking}
                onClick={() => setRevokingCert(null)}
              >
                Cancel
              </button>
              <button
                type="button"
                className="wf-btn-danger"
                disabled={revoking}
                onClick={() => void handleConfirmRevoke()}
                data-testid="revoke-confirm-btn"
              >
                {revoking ? 'Revoking…' : 'Revoke certificate'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* CA rotation modal — distinct amber/warn border + type-to-confirm */}
      {showRotateModal && (
        <div
          className="wf-overlay"
          role="dialog"
          aria-modal="true"
          aria-labelledby="rotate-ca-title"
          data-testid="rotate-overlay"
        >
          <div className="wf-modal rotate-modal">
            <h3 id="rotate-ca-title">Rotate the signing CA?</h3>
            <div className="rotate-warn" role="note">
              <span>
                <b>This affects every steward in the fleet.</b> A new CA is
                generated and every future certificate is issued under it.
                Existing steward certs keep working until they are renewed, but
                any out-of-band trust bundles referencing the current CA
                fingerprint must be updated.
              </span>
            </div>
            <p>
              Type <b>ROTATE</b> to confirm.
            </p>
            <div className="wf-form-field">
              <input
                type="text"
                aria-label="Type ROTATE to confirm"
                placeholder="ROTATE"
                value={rotateInput}
                onChange={(e) => setRotateInput(e.target.value)}
                data-testid="rotate-confirm-input"
                style={{ width: '100%' }}
              />
            </div>
            {rotateError && (
              <p className="wf-form-error" data-testid="rotate-error">
                {rotateError}
              </p>
            )}
            <div className="wf-modal-actions">
              <button
                type="button"
                className="wf-btn-secondary"
                disabled={rotating}
                onClick={closeRotateModal}
              >
                Cancel
              </button>
              <button
                type="button"
                className="wf-btn-danger"
                disabled={rotating || rotateInput.trim() !== 'ROTATE'}
                onClick={() => void handleConfirmRotate()}
                data-testid="rotate-confirm-btn"
              >
                {rotating ? 'Rotating…' : 'Rotate signing CA'}
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  )
}
