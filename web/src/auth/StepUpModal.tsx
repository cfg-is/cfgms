// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * WebAuthn re-authentication modal (Story #2786, ADR-021 Decision 6).
 *
 * Renders as a focus-trapped overlay over the current view when apiFetch
 * detects a 401 + WWW-Authenticate: CFGMS-StepUp response. Performs the
 * WebAuthn presence ceremony:
 *
 *   1. POST /api/v1/webauthn/presence/begin  → server-side challenge
 *   2. navigator.credentials.get()           → authenticator gesture
 *   3. POST /api/v1/webauthn/presence/finish → presence token
 *   4. Retry original request with X-Presence-Token
 *
 * Security properties:
 *  - No click-outside-to-dismiss: the backdrop intercepts pointer events but
 *    does not call onCancel. Cancel requires the explicit button.
 *  - No Escape dismissal: intentionally not handled — this is a security gate.
 *  - Focus-trapped: Tab cycles only within the modal; focus is restored on unmount.
 *  - Ceremony calls use raw fetch (not apiFetch) to avoid re-triggering the
 *    step-up listener; CSRF is applied manually via the session cookie.
 *  - On cancel or failure: onSuccess is NOT called; the original mutation
 *    receives null (its 401) and the operator stays signed-in at their prior
 *    assurance level.
 *
 * Design: docs/design/mockups/login.html `mfa` state, rendered as a modal.
 */

import { useCallback, useEffect, useRef, useState } from 'react'
import type { StepUpRequest } from '../api/client.ts'
import './StepUpModal.css'

// ── CSRF cookie helper (session token only; pre-session is for login) ────────

function readSessionCsrf(): string | null {
  for (const pair of document.cookie.split(';')) {
    const eq = pair.indexOf('=')
    if (eq === -1) continue
    if (pair.slice(0, eq).trim() === 'cfgms_csrf') {
      return decodeURIComponent(pair.slice(eq + 1).trim())
    }
  }
  return null
}

// ── base64url helpers ────────────────────────────────────────────────────────

function b64uToBytes(b64u: string): Uint8Array<ArrayBuffer> {
  const padded = b64u + '='.repeat((4 - (b64u.length % 4)) % 4)
  const base64 = padded.replace(/-/g, '+').replace(/_/g, '/')
  return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0))
}

function bytesToB64u(buf: ArrayBuffer | ArrayBufferLike): string {
  const bytes = new Uint8Array(buf)
  let binary = ''
  for (const b of bytes) binary += String.fromCharCode(b)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}

// ── WebAuthn JSON ↔ browser type adapters ────────────────────────────────────
//
// go-webauthn/webauthn serialises challenge + credential IDs as raw base64url
// strings. The browser's PublicKeyCredential API requires ArrayBuffer. These
// adapters convert between the two representations without an external library.

interface PresenceOptions {
  publicKey: {
    challenge: string
    timeout?: number
    rpId?: string
    allowCredentials?: Array<{
      type: 'public-key'
      id: string
      transports?: string[]
    }>
    userVerification?: UserVerificationRequirement
  }
}

function toBrowserOptions(opts: PresenceOptions): PublicKeyCredentialRequestOptions {
  const pk = opts.publicKey
  return {
    challenge: b64uToBytes(pk.challenge),
    timeout: pk.timeout,
    rpId: pk.rpId,
    userVerification: pk.userVerification,
    allowCredentials: pk.allowCredentials?.map((c) => ({
      type: 'public-key' as const,
      id: b64uToBytes(c.id),
      transports: c.transports as AuthenticatorTransport[] | undefined,
    })),
  }
}

interface AssertionJSON {
  id: string
  rawId: string
  response: {
    authenticatorData: string
    clientDataJSON: string
    signature: string
    userHandle: string | null
  }
  type: 'public-key'
  clientExtensionResults: Record<string, unknown>
}

function toAssertionJSON(cred: PublicKeyCredential): AssertionJSON {
  const resp = cred.response as AuthenticatorAssertionResponse
  return {
    id: cred.id,
    rawId: bytesToB64u(cred.rawId),
    response: {
      authenticatorData: bytesToB64u(resp.authenticatorData),
      clientDataJSON: bytesToB64u(resp.clientDataJSON),
      signature: bytesToB64u(resp.signature),
      userHandle: resp.userHandle !== null ? bytesToB64u(resp.userHandle) : null,
    },
    type: 'public-key',
    clientExtensionResults: {},
  }
}

// ── Component ────────────────────────────────────────────────────────────────

export interface StepUpModalProps {
  request: StepUpRequest
  principalUsername: string | null
  onSuccess: (response: Response) => void
  onCancel: () => void
}

type Phase = 'loading' | 'waiting' | 'running' | 'error'

const UNSAFE = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])

export default function StepUpModal({
  request,
  principalUsername,
  onSuccess,
  onCancel,
}: StepUpModalProps) {
  const [phase, setPhase] = useState<Phase>('loading')
  const [errorMsg, setErrorMsg] = useState<string | null>(null)
  const optsRef = useRef<PresenceOptions | null>(null)
  const modalRef = useRef<HTMLDivElement>(null)
  // Incrementing this triggers the presence/begin effect to re-run on retry.
  const [beginKey, setBeginKey] = useState(0)

  // Focus trap: move focus into modal on mount; restore previous focus on unmount.
  useEffect(() => {
    const prevFocus = document.activeElement as HTMLElement | null

    function trapFocus(e: KeyboardEvent) {
      if (e.key !== 'Tab' || modalRef.current === null) return
      const btns = [
        ...modalRef.current.querySelectorAll<HTMLElement>('button:not([disabled])'),
      ]
      if (btns.length === 0) {
        e.preventDefault()
        return
      }
      const first = btns[0]!
      const last = btns[btns.length - 1]!
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault()
        last.focus()
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault()
        first.focus()
      }
    }

    document.addEventListener('keydown', trapFocus)

    // Defer focus so the browser has painted the modal buttons.
    const timer = setTimeout(() => {
      modalRef.current?.querySelector<HTMLElement>('button:not([disabled])')?.focus()
    }, 0)

    return () => {
      clearTimeout(timer)
      document.removeEventListener('keydown', trapFocus)
      prevFocus?.focus()
    }
  }, [])

  // Fetch a fresh challenge on mount and on each retry.
  // Routes to the elevation endpoint (Basic→Strong) when presenceRequired is false,
  // or the presence endpoint (per-action assertion) when presenceRequired is true.
  useEffect(() => {
    let aborted = false

    async function beginCeremony() {
      setPhase('loading')
      setErrorMsg(null)
      optsRef.current = null

      const beginUrl = request.presenceRequired
        ? '/api/v1/webauthn/presence/begin'
        : '/api/v1/webauthn/elevate/begin'

      try {
        const csrf = readSessionCsrf()
        const headers = new Headers()
        if (csrf !== null) headers.set('X-CSRF-Token', csrf)

        const resp = await fetch(beginUrl, {
          method: 'POST',
          headers,
          credentials: 'same-origin',
        })
        if (aborted) return

        if (!resp.ok) {
          setPhase('error')
          setErrorMsg(
            'Unable to start verification. Sign in again if the issue persists.',
          )
          return
        }

        const opts = (await resp.json()) as PresenceOptions
        if (aborted) return
        optsRef.current = opts
        setPhase('waiting')
      } catch {
        if (!aborted) {
          setPhase('error')
          setErrorMsg('Network error — check your connection and try again.')
        }
      }
    }

    void beginCeremony()
    return () => {
      aborted = true
    }
  }, [beginKey, request.presenceRequired])

  const handleVerify = useCallback(async () => {
    const opts = optsRef.current
    if (opts === null) return

    setPhase('running')

    try {
      const publicKey = toBrowserOptions(opts)
      const rawCred = await navigator.credentials.get({ publicKey })

      // navigator.credentials.get({ publicKey }) should always return a
      // PublicKeyCredential, but the return type is Credential | null.
      // Duck-type check avoids a hard instanceof dependency on the class
      // (which is unavailable in test environments that don't support WebAuthn).
      if (rawCred === null || rawCred.type !== 'public-key') {
        throw new DOMException('Expected a public-key credential', 'NotAllowedError')
      }
      const cred = rawCred as PublicKeyCredential

      // Send the assertion to the server. Route to the correct finish endpoint:
      //   - elevate/finish: upgrades the session to AssuranceStrong (Basic→Strong)
      //   - presence/finish: mints a short-lived presence token for the action gate
      const csrf = readSessionCsrf()
      const finishUrl = request.presenceRequired
        ? '/api/v1/webauthn/presence/finish'
        : '/api/v1/webauthn/elevate/finish'
      const finishHeaders = new Headers({ 'Content-Type': 'application/json' })
      if (csrf !== null) finishHeaders.set('X-CSRF-Token', csrf)

      const finishResp = await fetch(finishUrl, {
        method: 'POST',
        headers: finishHeaders,
        credentials: 'same-origin',
        body: JSON.stringify(toAssertionJSON(cred)),
      })

      if (!finishResp.ok) {
        setPhase('error')
        setErrorMsg('Verification failed — please try again.')
        return
      }

      // Build retry headers, then replay the original request using raw fetch
      // (not apiFetch) to avoid re-triggering the step-up listener.
      const method = (request.init.method ?? 'GET').toUpperCase()
      const retryHeaders = new Headers(request.init.headers)

      if (request.presenceRequired) {
        // Presence path: attach the single-use token minted by presence/finish.
        const presenceData = (await finishResp.json()) as { presence_token: string }
        retryHeaders.set('X-Presence-Token', presenceData.presence_token)
      } else {
        // Elevation path: the session cookie is now Strong — no extra header needed.
        // Consume the response body to avoid a connection leak.
        await finishResp.json()
      }

      // Re-attach the session CSRF token on unsafe-method retries (ADR-018 §3).
      if (UNSAFE.has(method) && csrf !== null) {
        retryHeaders.set('X-CSRF-Token', csrf)
      }

      const retryResp = await fetch(request.path, {
        ...request.init,
        headers: retryHeaders,
        credentials: 'same-origin',
      })

      onSuccess(retryResp)
    } catch (err) {
      const isCancelled =
        err instanceof DOMException && err.name === 'NotAllowedError'
      setPhase('error')
      setErrorMsg(
        isCancelled
          ? 'Verification cancelled — click Cancel to go back, or try again.'
          : 'An unexpected error occurred — please try again.',
      )
    }
  }, [request, onSuccess])

  function handleRetry() {
    setBeginKey((k) => k + 1)
  }

  const username = principalUsername ?? 'your account'

  return (
    <div className="step-up-overlay" data-testid="step-up-overlay">
      <div
        className="step-up-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="step-up-title"
        ref={modalRef}
      >
        <div className="step-up-titlebar">
          <span className="step-up-title">cfgms · secure session</span>
        </div>

        <div className="step-up-body">
          <div className="step-up-icon" aria-hidden="true">
            {/* Passkey / key icon (Lucide "key", ISC — a recognizable key). */}
            <svg
              width="26"
              height="26"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.9"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <circle cx="7.5" cy="15.5" r="5.5" />
              <path d="m21 2-9.6 9.6" />
              <path d="m15.5 7.5 3 3L22 7l-3-3" />
            </svg>
          </div>

          <h3 id="step-up-title" className="step-up-heading">
            Verify it&rsquo;s you
          </h3>

          <p className="step-up-desc">
            Action requires verification as{' '}
            <b className="step-up-title">{username}</b>. Use your passkey or
            security key to continue.
          </p>

          {phase === 'error' && errorMsg !== null && (
            <div
              className="step-up-error"
              role="alert"
              data-testid="step-up-error"
            >
              <span className="step-up-err-dot" aria-hidden="true" />
              {errorMsg}
            </div>
          )}

          <div className="step-up-actions">
            {(phase === 'loading') && (
              <button type="button" className="step-up-btn" disabled>
                <span className="step-up-spin" aria-hidden="true" />
                <span>Preparing…</span>
              </button>
            )}

            {phase === 'waiting' && (
              <button
                type="button"
                className="step-up-btn"
                onClick={() => void handleVerify()}
                data-testid="step-up-verify-btn"
              >
                <svg
                  width="16"
                  height="16"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  aria-hidden="true"
                >
                  <circle cx="7.5" cy="15.5" r="5.5" />
                  <path d="m21 2-9.6 9.6" />
                  <path d="m15.5 7.5 3 3L22 7l-3-3" />
                </svg>
                Verify with passkey
              </button>
            )}

            {phase === 'running' && (
              <button type="button" className="step-up-btn" disabled>
                <span className="step-up-spin" aria-hidden="true" />
                <span>Waiting for gesture…</span>
              </button>
            )}

            {phase === 'error' && (
              <button
                type="button"
                className="step-up-btn"
                onClick={handleRetry}
                data-testid="step-up-retry-btn"
              >
                Try again
              </button>
            )}
          </div>

          <button
            type="button"
            className="step-up-cancel"
            onClick={onCancel}
            disabled={phase === 'running'}
            data-testid="step-up-cancel-btn"
          >
            Cancel — action not completed
          </button>
        </div>
      </div>
    </div>
  )
}
