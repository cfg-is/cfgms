// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * "Certificates" section of the account expand panel (Issue #5448, Epic #5300).
 *
 * Lists the account's certificate bindings and binds, revokes and rotates them.
 * Revoke and rotate use the per-row inline confirm of support-access.html: the
 * button turns into Confirm / Cancel and nothing is sent until Confirm. Every
 * value from the wire (label included) renders as JSX text only.
 */
import { useState } from 'react'
import {
  bindCert,
  revokeCert,
  rotateCert,
  useCertBindings,
  type CertBinding,
} from './useCertBindings.ts'

type Pending = { kind: 'revoke' | 'rotate'; serial: string } | null

const rowStyle = {
  display: 'flex',
  flexWrap: 'wrap',
  alignItems: 'center',
  gap: 'var(--space-2)',
  padding: 'var(--space-2) 0',
  borderTop: '1px solid var(--border)',
  fontSize: 'var(--text-base)',
} as const

const monoStyle = { fontFamily: 'var(--font-mono)', fontSize: 'var(--text-sm)' } as const
const faintStyle = { color: 'var(--text-faint)', fontSize: 'var(--text-sm)' } as const
const errorStyle = { color: 'var(--state-crit)', fontSize: 'var(--text-sm)' } as const
const inputStyle = {
  background: 'var(--bg-surface)',
  color: 'var(--text-primary)',
  border: '1px solid var(--border)',
  padding: 'var(--space-1) var(--space-2)',
  fontFamily: 'var(--font-mono)',
  fontSize: 'var(--text-sm)',
} as const

function errorText(cause: unknown, fallback: string): string {
  return cause instanceof Error && cause.message ? cause.message : fallback
}

export default function CertBindingsSection({ username }: { username: string }) {
  const { bindings, loading, error, refetch } = useCertBindings(username)
  const [pending, setPending] = useState<Pending>(null)
  const [rotateSerial, setRotateSerial] = useState('')
  const [rotateFingerprint, setRotateFingerprint] = useState('')
  const [busy, setBusy] = useState(false)
  const [actionError, setActionError] = useState<string | null>(null)
  const [bindSerial, setBindSerial] = useState('')
  const [bindFingerprint, setBindFingerprint] = useState('')
  const [bindLabel, setBindLabel] = useState('')

  async function run(action: () => Promise<void>, fallback: string): Promise<boolean> {
    setBusy(true)
    setActionError(null)
    try {
      await action()
      refetch()
      return true
    } catch (cause: unknown) {
      setActionError(errorText(cause, fallback))
      return false
    } finally {
      setBusy(false)
    }
  }

  function cancel() {
    setPending(null)
    setRotateSerial('')
    setRotateFingerprint('')
  }

  async function handleBind() {
    if (bindSerial.trim() === '' || bindFingerprint.trim() === '') {
      setActionError('Serial and fingerprint are required')
      return
    }
    const ok = await run(
      () => bindCert(username, { serial: bindSerial.trim(), fingerprint: bindFingerprint.trim(), label: bindLabel.trim() }),
      'Bind failed',
    )
    if (ok) {
      setBindSerial('')
      setBindFingerprint('')
      setBindLabel('')
    }
  }

  async function handleConfirm(binding: CertBinding) {
    if (pending === null) return
    if (pending.kind === 'revoke') {
      if (await run(() => revokeCert(username, binding.serial), 'Revoke failed')) cancel()
      return
    }
    if (rotateSerial.trim() === '') {
      setActionError('The new certificate serial is required')
      return
    }
    const ok = await run(
      () => rotateCert(username, binding.serial, { serial: rotateSerial.trim(), fingerprint: rotateFingerprint.trim() }),
      'Rotate failed',
    )
    if (ok) cancel()
  }

  return (
    <div style={{ padding: 'var(--space-2) var(--space-3)' }} data-testid="cert-bindings-section">
      <span className="wf-form-label">Certificates</span>
      {loading ? (
        <span style={{ ...faintStyle, marginLeft: 'var(--space-2)' }}>Loading…</span>
      ) : error !== null ? (
        <span style={errorStyle} data-testid="cert-bindings-error" role="alert">{error}</span>
      ) : bindings.length === 0 ? (
        <span style={{ ...faintStyle, marginLeft: 'var(--space-2)' }} data-testid="cert-bindings-empty">
          No certificates bound
        </span>
      ) : (
        <div data-testid="cert-bindings-list">
          {bindings.map((b) => {
            const confirming = pending?.serial === b.serial ? pending : null
            return (
              <div key={b.serial} style={rowStyle} data-testid="cert-binding-row">
                <span style={monoStyle} data-testid="cert-serial">{b.serial}</span>
                <span style={{ ...monoStyle, color: 'var(--text-secondary)' }}>{b.fingerprint}</span>
                {b.label !== '' && <span data-testid="cert-label">{b.label}</span>}
                <span style={faintStyle}>bound {b.boundAt}</span>
                <span style={faintStyle}>{b.lastUsedAt !== null ? `last used ${b.lastUsedAt}` : 'never used'}</span>
                {b.humanApprovedAt !== null && <span style={faintStyle}>approved {b.humanApprovedAt}</span>}
                {confirming === null ? (
                  <span style={{ marginLeft: 'auto', display: 'flex', gap: 'var(--space-2)' }}>
                    <button
                      type="button"
                      className="wf-btn wf-btn-secondary wf-btn-sm"
                      disabled={busy}
                      data-testid="cert-rotate-btn"
                      onClick={() => {
                        setActionError(null)
                        setPending({ kind: 'rotate', serial: b.serial })
                      }}
                    >
                      Rotate
                    </button>
                    <button
                      type="button"
                      className="wf-btn wf-btn-danger wf-btn-sm"
                      disabled={busy}
                      data-testid="cert-revoke-btn"
                      onClick={() => {
                        setActionError(null)
                        setPending({ kind: 'revoke', serial: b.serial })
                      }}
                    >
                      Revoke
                    </button>
                  </span>
                ) : (
                  <span
                    style={{ flexBasis: '100%', display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 'var(--space-2)', background: 'var(--bg-sunk)', padding: 'var(--space-2) var(--space-3)' }}
                    data-testid="cert-confirm"
                  >
                    <b>{confirming.kind === 'revoke' ? 'Revoke this certificate?' : 'Rotate this certificate?'}</b>
                    {confirming.kind === 'rotate' && (
                      <>
                        <input
                          aria-label="New certificate serial"
                          style={inputStyle}
                          value={rotateSerial}
                          onChange={(e) => setRotateSerial(e.target.value)}
                          data-testid="cert-rotate-serial-input"
                        />
                        <input
                          aria-label="New certificate fingerprint (optional)"
                          style={inputStyle}
                          value={rotateFingerprint}
                          onChange={(e) => setRotateFingerprint(e.target.value)}
                          data-testid="cert-rotate-fingerprint-input"
                        />
                      </>
                    )}
                    <button type="button" className="wf-btn wf-btn-secondary wf-btn-sm" disabled={busy} onClick={cancel} data-testid="cert-cancel-btn">
                      Cancel
                    </button>
                    <button
                      type="button"
                      className={`wf-btn ${confirming.kind === 'revoke' ? 'wf-btn-danger ' : ''}wf-btn-sm`}
                      disabled={busy}
                      onClick={() => void handleConfirm(b)}
                      data-testid="cert-confirm-btn"
                    >
                      Confirm
                    </button>
                  </span>
                )}
              </div>
            )
          })}
        </div>
      )}

      <div style={{ ...rowStyle, borderTop: 'none' }} onClick={(e) => e.stopPropagation()}>
        <input aria-label="Certificate serial" placeholder="Serial" style={inputStyle} value={bindSerial} onChange={(e) => setBindSerial(e.target.value)} data-testid="cert-bind-serial-input" />
        <input aria-label="Certificate fingerprint" placeholder="Fingerprint" style={inputStyle} value={bindFingerprint} onChange={(e) => setBindFingerprint(e.target.value)} data-testid="cert-bind-fingerprint-input" />
        <input aria-label="Certificate label" placeholder="Label (optional)" style={inputStyle} value={bindLabel} onChange={(e) => setBindLabel(e.target.value)} data-testid="cert-bind-label-input" />
        <button type="button" className="wf-btn wf-btn-sm" disabled={busy} onClick={() => void handleBind()} data-testid="cert-bind-btn">
          Bind certificate
        </button>
      </div>
      {actionError !== null && (
        <div style={errorStyle} role="alert" data-testid="cert-action-error">{actionError}</div>
      )}
    </div>
  )
}
