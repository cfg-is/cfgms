// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * One-time password reveal dialog (Issue #5566). Opened for one pending record; the
 * admin presses Reveal, the apiFetch interceptor runs the passkey tap, and the value is
 * shown once, masked until Show is pressed.
 *
 * States: Ready / Loading / Error / Revealed / Already-revealed.
 *
 * Secret handling: the value lives in this component's state only. It is never written
 * to storage, the URL, history, the console or an error message. Unmounting the dialog
 * (Close, Escape, the page navigating away) discards it, and a result that arrives
 * after the dialog closed is dropped without ever entering state. While masked the value
 * is not in the DOM at all.
 */
import { useEffect, useRef, useState } from 'react'
import { revealCredential, type PendingCredential } from './credentialsApi.ts'

type View =
  | { kind: 'ready' }
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | { kind: 'revealed'; password: string }
  | { kind: 'gone' }

const mask = '••••••••••••'

export default function RevealDialog({
  credential,
  onClose,
  onRevealed,
}: {
  credential: PendingCredential
  onClose: () => void
  /** Called after the value was shown, so the caller can drop the record from its list. */
  onRevealed: () => void
}) {
  const [view, setView] = useState<View>({ kind: 'ready' })
  const [shown, setShown] = useState(false)
  const [copied, setCopied] = useState(false)
  const alive = useRef(true)
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => {
    alive.current = true
    return () => {
      alive.current = false
      if (timer.current !== null) clearTimeout(timer.current)
    }
  }, [])

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [onClose])

  async function handleReveal() {
    setView({ kind: 'loading' })
    try {
      const result = await revealCredential(credential.id)
      if (!alive.current) return
      if (result.status === 'gone') {
        setView({ kind: 'gone' })
        onRevealed()
        return
      }
      setShown(false)
      setView({ kind: 'revealed', password: result.password })
      onRevealed()
    } catch (cause: unknown) {
      if (!alive.current) return
      setView({
        kind: 'error',
        message: cause instanceof Error && cause.message ? cause.message : 'Reveal request failed',
      })
    }
  }

  function handleCopy(password: string) {
    navigator.clipboard
      .writeText(password)
      .then(() => {
        if (!alive.current) return
        setCopied(true)
        if (timer.current !== null) clearTimeout(timer.current)
        timer.current = setTimeout(() => setCopied(false), 2000)
      })
      .catch(() => {})
  }

  return (
    <div
      className="modal-overlay"
      role="dialog"
      aria-modal="true"
      aria-labelledby="reveal-dialog-title"
      data-testid="reveal-dialog"
    >
      <div className="modal-panel">
        <h2 id="reveal-dialog-title">Reveal initial password</h2>
        <p>
          Account <span className="mono2" data-testid="reveal-resource">{credential.resource_id || '—'}</span>
        </p>

        {view.kind === 'ready' && (
          <>
            <p className="notice-warn" data-testid="reveal-warning">
              The password is shown once. Confirm with your passkey, then copy it before closing.
            </p>
            <button type="button" className="wf-btn-primary" onClick={() => void handleReveal()} data-testid="reveal-btn">
              Reveal password
            </button>
          </>
        )}

        {view.kind === 'loading' && (
          <p role="status" data-testid="reveal-loading">
            Waiting for passkey confirmation…
          </p>
        )}

        {view.kind === 'error' && (
          <>
            <p className="wf-form-error" role="alert" data-testid="reveal-error">
              {view.message}
            </p>
            <button type="button" className="wf-btn-primary" onClick={() => void handleReveal()} data-testid="reveal-retry-btn">
              Try again
            </button>
          </>
        )}

        {view.kind === 'revealed' && (
          <>
            <p className="notice-warn" role="status" data-testid="reveal-once-warning">
              This password will not be shown again. Copy it before closing.
            </p>
            <div className="secret-row">
              <code className="mono2 secret-value" data-testid="reveal-value">
                {shown ? view.password : mask}
              </code>
              <button
                type="button"
                className="wf-btn-sm"
                aria-pressed={shown}
                onClick={() => setShown((s) => !s)}
                data-testid="reveal-toggle-btn"
              >
                {shown ? 'Hide' : 'Show'}
              </button>
              <button
                type="button"
                className="wf-btn-sm"
                onClick={() => handleCopy(view.password)}
                aria-label="Copy password to clipboard"
                data-testid="reveal-copy-btn"
              >
                {copied ? 'Copied!' : 'Copy'}
              </button>
            </div>
          </>
        )}

        {view.kind === 'gone' && (
          <div className="notice" role="status" data-testid="reveal-already">
            <h3>Already revealed</h3>
            <p>
              This password was already revealed or is no longer available. It cannot be shown again; if it was
              lost, delete the account and have it recreated.
            </p>
          </div>
        )}

        <button type="button" className="wf-btn-sm" onClick={onClose} data-testid="reveal-close-btn">
          Close
        </button>
      </div>
    </div>
  )
}
