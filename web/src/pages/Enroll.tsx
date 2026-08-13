// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * First-passkey enrollment page (Story #2968, ADR-021 Amendment 1).
 *
 * Unauthenticated route at /enroll/:token. The token is a single-use
 * magic-link credential that identifies the zero-passkey account to enroll.
 * No session or login step is required before this page.
 *
 * Flow:
 *   1. Read token from URL params (never from session/storage).
 *   2. POST /api/v1/web/passkey/enroll/begin with X-Enrollment-Token to
 *      validate the token server-side and receive WebAuthn creation options.
 *   3. navigator.credentials.create({ publicKey }) — browser-native ceremony.
 *   4. POST /api/v1/web/passkey/enroll/finish (via apiFetch) with the
 *      attestation; a 201 fires onSessionConfirmed → AuthContext signedIn.
 *   5. navigate('/') → fleet view (session probe already resolved).
 *
 * Terminal error states (no retry): invalid/expired/revoked/already-enrolled
 * token. Cancelled ceremony returns to the ready state for a retry.
 */
import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router'
import {
  passkeyEnrollBeginRequest,
  passkeyEnrollFinishRequest,
  type PasskeyEnrollOptions,
  type AttestationJSON,
} from '../api/client.ts'
import './Enroll.css'

// ── base64url helpers (same pattern as AuthContext / StepUpModal) ─────────────

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

// ── WebAuthn JSON ↔ browser type adapters (registration ceremony) ─────────────

function toBrowserCreationOptions(opts: PasskeyEnrollOptions): PublicKeyCredentialCreationOptions {
  const pk = opts.publicKey
  return {
    challenge: b64uToBytes(pk.challenge),
    rp: pk.rp,
    user: {
      id: b64uToBytes(pk.user.id),
      name: pk.user.name,
      displayName: pk.user.displayName,
    },
    pubKeyCredParams: pk.pubKeyCredParams,
    timeout: pk.timeout,
    excludeCredentials: pk.excludeCredentials?.map((c) => ({
      type: 'public-key' as const,
      id: b64uToBytes(c.id),
      transports: c.transports as AuthenticatorTransport[] | undefined,
    })),
    authenticatorSelection: pk.authenticatorSelection as AuthenticatorSelectionCriteria | undefined,
    attestation: pk.attestation as AttestationConveyancePreference | undefined,
  }
}

function toAttestationJSON(cred: PublicKeyCredential): AttestationJSON {
  const resp = cred.response as AuthenticatorAttestationResponse
  return {
    id: cred.id,
    rawId: bytesToB64u(cred.rawId),
    response: {
      attestationObject: bytesToB64u(resp.attestationObject),
      clientDataJSON: bytesToB64u(resp.clientDataJSON),
    },
    type: 'public-key',
    clientExtensionResults: {},
  }
}

// ── Component ─────────────────────────────────────────────────────────────────

/**
 * validating — begin request in flight (server-side token check)
 * ready      — token valid, showing "Register passkey" button
 * running    — navigator.credentials.create() pending
 * error      — terminal: invalid/expired/revoked token, or already enrolled
 */
type Phase = 'validating' | 'ready' | 'running' | 'error'

export default function Enroll() {
  const { token } = useParams<{ token: string }>()
  const navigate = useNavigate()
  // Derive initial state directly: a missing token is already an error at
  // render time (useParams returned undefined), no async check needed.
  const [phase, setPhase] = useState<Phase>(() => (token ? 'validating' : 'error'))
  const [errorMsg, setErrorMsg] = useState<string | null>(() =>
    token ? null : 'Invalid enrollment link — no token in the URL.',
  )
  const [enrollOptions, setEnrollOptions] = useState<PasskeyEnrollOptions | null>(null)

  useEffect(() => {
    if (!token) return  // error state already set via lazy initializer above

    let aborted = false

    async function beginEnrollment() {
      const result = await passkeyEnrollBeginRequest(token)
      if (aborted) return

      if (!result.ok) {
        setPhase('error')
        setErrorMsg(
          result.status === 401 || result.status === 400
            ? 'This enrollment link is invalid or has already been used. Contact your administrator for a new one.'
            : 'Unable to validate the enrollment link. Please try again later.',
        )
        return
      }

      setEnrollOptions(result.options!)
      setPhase('ready')
    }

    void beginEnrollment()
    return () => {
      aborted = true
    }
  }, [token])

  async function handleRegister() {
    if (phase !== 'ready' || enrollOptions === null || token === undefined) return
    setPhase('running')

    let rawCred: Credential | null = null
    try {
      rawCred = await navigator.credentials.create({
        publicKey: toBrowserCreationOptions(enrollOptions),
      })
    } catch (err) {
      const isCancelled = err instanceof DOMException && err.name === 'NotAllowedError'
      setPhase('ready')
      if (!isCancelled) {
        setErrorMsg('An unexpected error occurred. Please try again.')
        setPhase('error')
      }
      return
    }

    if (rawCred === null || rawCred.type !== 'public-key') {
      setPhase('ready')
      return
    }

    const result = await passkeyEnrollFinishRequest(
      token,
      toAttestationJSON(rawCred as PublicKeyCredential),
    )

    if (!result.ok) {
      setPhase('error')
      if (result.status === 409) {
        setErrorMsg(
          'This account already has a passkey enrolled. Contact your administrator.',
        )
      } else if (result.status === 410) {
        setErrorMsg(
          'This enrollment link was revoked. Contact your administrator for a new one.',
        )
      } else {
        setErrorMsg(
          'Passkey registration failed. This link may have already been used.',
        )
      }
      return
    }

    // Successful 201: apiFetch fired onSessionConfirmed → AuthContext is now
    // signedIn. Navigate to the app root; the fleet view's own data call
    // confirms the session (existing probe architecture — no separate probe).
    void navigate('/', { replace: true })
  }

  if (phase === 'validating') {
    return (
      <div className="enroll-stage">
        <div className="enroll-win">
          <div className="enroll-titlebar">
            <span className="enroll-title mono">cfgms · first-time setup</span>
          </div>
          <div className="enroll-body">
            <div className="enroll-wordmark">
              <b>CFGMS</b>
              <span>config management</span>
            </div>
            <div className="enroll-waiting">
              <div className="enroll-waiting-icon" aria-hidden="true">
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
              <h3 className="enroll-waiting-heading">Validating your link…</h3>
              <p className="enroll-waiting-desc">
                Checking the enrollment link. This only takes a moment.
              </p>
            </div>
          </div>
        </div>
      </div>
    )
  }

  if (phase === 'running') {
    return (
      <div className="enroll-stage">
        <div className="enroll-win">
          <div className="enroll-titlebar">
            <span className="enroll-title mono">cfgms · first-time setup</span>
          </div>
          <div className="enroll-body">
            <div className="enroll-wordmark">
              <b>CFGMS</b>
              <span>config management</span>
            </div>
            <div className="enroll-waiting">
              <div className="enroll-waiting-icon" aria-hidden="true">
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
              <h3 className="enroll-waiting-heading">Waiting for your passkey</h3>
              <p className="enroll-waiting-desc">
                Confirm on your security key or device to register your passkey.
              </p>
            </div>
          </div>
        </div>
      </div>
    )
  }

  if (phase === 'error') {
    return (
      <div className="enroll-stage">
        <div className="enroll-win">
          <div className="enroll-titlebar">
            <span className="enroll-title mono">cfgms · first-time setup</span>
          </div>
          <div className="enroll-body">
            <div className="enroll-wordmark">
              <b>CFGMS</b>
              <span>config management</span>
            </div>
            <div className="enroll-err-block" role="alert">
              <span className="mono" aria-hidden="true">⚠</span>
              <div>
                <strong>Enrollment link unavailable</strong>
                <p className="enroll-err-detail">{errorMsg}</p>
              </div>
            </div>
            <p className="enroll-helper">
              Each enrollment link can only be used once and expires after a short
              time. If you believe this is an error, contact your administrator.
            </p>
            <div className="enroll-foot">
              <span className="mono">© 2026 cfg.is</span>
            </div>
          </div>
        </div>
      </div>
    )
  }

  // phase === 'ready'
  return (
    <div className="enroll-stage">
      <div className="enroll-win">
        <div className="enroll-titlebar">
          <span className="enroll-title mono">cfgms · first-time setup</span>
        </div>

        <div className="enroll-body">
          <div className="enroll-wordmark">
            <b>CFGMS</b>
            <span>config management</span>
          </div>
          <p className="enroll-lead">Register your passkey</p>

          <p className="enroll-desc">
            Your account has been provisioned. Register a passkey to finish
            setting up your secure access — no password needed.
          </p>

          <button
            className="enroll-register"
            type="button"
            onClick={() => void handleRegister()}
          >
            {/* Lucide "key" icon (ISC) */}
            <svg
              width="17"
              height="17"
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
            <span className="enroll-register-txt">Register a passkey</span>
          </button>

          <p className="enroll-helper">
            Your passkey never leaves your device. No password to phish.
          </p>

          <div className="enroll-foot">
            <a
              href="https://github.com/cfg-is/cfgms/blob/main/docs/README.md"
              rel="noreferrer"
              target="_blank"
            >
              Need help?
            </a>
            <span className="mono">© 2026 cfg.is</span>
          </div>
        </div>
      </div>
    </div>
  )
}
