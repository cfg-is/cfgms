// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * CLI presence-relay confirmation screen (Issue #4287, ADR-021 Amendment 4/6).
 *
 * Unauthenticated top-level route at /cli/presence?request_id=<id> — a sibling of the
 * RequireAuth-gated subtree, mirroring how /login/confirm (CliLogin.tsx, Issue #3722)
 * is registered in App.tsx. The ONLY value read from the URL is request_id, for the
 * same reason CliLogin.tsx reads only that one: any other parameter (a host, a
 * scheme, a callback URL) would be an exfiltration channel this page never needs and
 * never contacts.
 *
 * Flow:
 *   1. Read request_id from the URL.
 *   2. If not authenticated, render the shipped Login page's passkey ceremony inline
 *      (same guard condition RequireAuth uses), exactly like CliLogin.tsx.
 *   3. Once authenticated, GET the presence request — this is the only way to learn
 *      the bound action and the user code; the CLI never puts either in the
 *      confirmation URL, only the request ID.
 *   4. Show the bound action and the code, and require an explicit "Confirm — codes
 *      match" click before the WebAuthn ceremony trigger even appears. This closes
 *      the "refuses to run without a user code confirmation" requirement at the UI
 *      layer, mirroring CliLogin's own explicit Confirm/Deny gate.
 *
 *      What is shown is exactly what is enforced: permission, method, path and body
 *      digest — the four values the controller binds onto the minted token and then
 *      compares against the retried request (requirePermission's action-binding
 *      check). No free-form description is displayed, and none exists: the lodge API
 *      accepts no display text at all, because a caller that can bind one action and
 *      describe another substitutes a different action into this gesture, which is the
 *      very substitution ADR-021 Amendment 7 Decision 1's binding exists to stop.
 *   5. Once confirmed, a "Verify with security key" button (StepUpModal.tsx's own
 *      shape) drives POST presence/begin -> navigator.credentials.get() -> POST
 *      presence/finish?cli_presence_request_id=<id>. The finish call is the ONLY
 *      place the CLI's action binding is attached, and it is attached server-side —
 *      from the durable record the CLI itself lodged, never from anything this page
 *      sends — so this page cannot swap in a different pending action even if it
 *      were compromised (see handlers_cli_presence.go's package doc comment).
 *   6. On success, the waiting `cfg` command collects the token over its own
 *      already-authenticated connection (handlers_cli_presence.go's collect route) —
 *      this screen never sees it and never needs to.
 *
 * Design Source: reuses CliLogin.tsx's chrome and component pattern verbatim — same
 * titlebar/wordmark/code-display layout, same terminal-relay framing. Every value in
 * the companion CSS is a token var() (CliPresence.css header comment); no new colour,
 * spacing, or type value, and no free-hand styling.
 */
import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router'
import { useAuth } from '../auth/AuthContext.tsx'
import Login from './Login.tsx'
import { getCliPresenceRequest, type CliPresenceRequestState } from '../api/client.ts'
import './CliPresence.css'

// ── CSRF cookie helper (mirrors StepUpModal.tsx's readSessionCsrf) ───────────────

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

// ── base64url + WebAuthn JSON adapters (mirrors StepUpModal.tsx) ────────────────

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

// SHA-256 of an empty byte string — the digest every bodyless request binds to. Shown
// as plain words rather than 64 hex characters, so an admin can tell at a glance whether
// the action they are authorizing carries a payload.
const EMPTY_BODY_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'

/**
 * Renders the bound request-body digest for display. A bodyless request says so; any
 * other digest is shown truncated (the full value is on the element's title attribute),
 * since its purpose here is to show that a specific payload is bound, not to be
 * recomputed by hand.
 */
function describeBodyDigest(digest: string): string {
  if (digest === '') return 'unknown'
  if (digest === EMPTY_BODY_SHA256) return 'none (empty request body)'
  return `sha256:${digest.slice(0, 16)}…`
}

/**
 * loading    — GET in flight
 * waiting    — pending; description + code shown, awaiting explicit code confirmation
 * confirmed  — code confirmed; the "verify with security key" trigger is now shown
 * running    — begin/assert/finish ceremony in flight
 * done       — terminal: ceremony completed successfully
 * error      — terminal: ceremony failed (retryable) or the request could not be read
 * expired    — terminal: past its TTL, or no longer found (swept)
 */
type Phase = 'loading' | 'waiting' | 'confirmed' | 'running' | 'done' | 'error' | 'expired'

function phaseForStatus(status: CliPresenceRequestState['status']): Phase {
  switch (status) {
    case 'pending':
      return 'waiting'
    case 'approved':
    case 'collected':
      return 'done'
    default:
      return 'expired'
  }
}

export default function CliPresence() {
  const { status, probing } = useAuth()
  const [searchParams] = useSearchParams()
  // The ONLY value ever read from the URL — see the file doc comment.
  const requestId = searchParams.get('request_id')

  const [phase, setPhase] = useState<Phase>(() => (requestId ? 'loading' : 'error'))
  const [errorMsg, setErrorMsg] = useState<string | null>(() =>
    requestId ? null : 'Invalid presence link — no request in the URL.',
  )
  const [request, setRequest] = useState<CliPresenceRequestState | null>(null)

  // Mirrors CliLogin.tsx's own guard exactly, for the same reason: this route is a
  // top-level sibling outside the guarded subtree.
  const authenticated = status === 'signedIn' || (probing && status === 'signedOut')

  useEffect(() => {
    if (!requestId || !authenticated) return
    let aborted = false

    async function load() {
      const result = await getCliPresenceRequest(requestId!)
      if (aborted) return
      if (!result.ok || !result.request) {
        if (result.status === 404) {
          setPhase('expired')
        } else {
          setErrorMsg('Unable to load this presence request. Please try again.')
          setPhase('error')
        }
        return
      }
      setRequest(result.request)
      setPhase(phaseForStatus(result.request.status))
    }

    void load()
    return () => {
      aborted = true
    }
  }, [requestId, authenticated])

  function confirmCode() {
    if (phase !== 'waiting') return
    setPhase('confirmed')
  }

  async function runCeremony() {
    if (!requestId || phase !== 'confirmed') return
    setPhase('running')
    setErrorMsg(null)

    try {
      const csrf = readSessionCsrf()
      const beginHeaders = new Headers()
      if (csrf !== null) beginHeaders.set('X-CSRF-Token', csrf)

      const beginResp = await fetch('/api/v1/webauthn/presence/begin', {
        method: 'POST',
        headers: beginHeaders,
        credentials: 'same-origin',
      })
      if (!beginResp.ok) {
        setPhase('error')
        setErrorMsg('Unable to start verification. Sign in again if the issue persists.')
        return
      }
      const beginBody = (await beginResp.json()) as Record<string, unknown>
      const opts = (beginBody.data ?? beginBody) as PresenceOptions

      const publicKey = toBrowserOptions(opts)
      const rawCred = await navigator.credentials.get({ publicKey })
      if (rawCred === null || rawCred.type !== 'public-key') {
        throw new DOMException('Expected a public-key credential', 'NotAllowedError')
      }
      const cred = rawCred as PublicKeyCredential

      const finishHeaders = new Headers({ 'Content-Type': 'application/json' })
      if (csrf !== null) finishHeaders.set('X-CSRF-Token', csrf)

      const finishResp = await fetch(
        `/api/v1/webauthn/presence/finish?cli_presence_request_id=${encodeURIComponent(requestId)}`,
        {
          method: 'POST',
          headers: finishHeaders,
          credentials: 'same-origin',
          body: JSON.stringify(toAssertionJSON(cred)),
        },
      )
      if (!finishResp.ok) {
        setPhase('error')
        setErrorMsg('Verification failed — please try again.')
        return
      }
      // The token never appears here — the controller attached it directly to the
      // durable request record for the waiting CLI to collect (Issue #4287).
      await finishResp.json()

      setPhase('done')
    } catch (err) {
      const isCancelled = err instanceof DOMException && err.name === 'NotAllowedError'
      setPhase('error')
      setErrorMsg(
        isCancelled
          ? 'Verification cancelled — try again when ready.'
          : 'An unexpected error occurred — please try again.',
      )
    }
  }

  if (!authenticated) {
    return <Login />
  }

  return (
    <div className="cli-presence-stage">
      <div className="cli-presence-win">
        <div className="cli-presence-titlebar">
          <span className="cli-presence-title mono">cfgms · cli presence</span>
        </div>
        <div className="cli-presence-body">
          <div className="cli-presence-wordmark">
            <b>CFGMS</b>
            <span>config management</span>
          </div>

          {phase === 'loading' && (
            <div className="cli-presence-waiting">
              <h3 className="cli-presence-waiting-heading">Loading the pending action…</h3>
            </div>
          )}

          {(phase === 'waiting' || phase === 'confirmed' || phase === 'running') && request && (
            <>
              <p className="cli-presence-lead">Confirm this action</p>
              {/*
                Every row below is a value the controller enforces against the retried
                request; nothing here is caller-authored display text. See the file
                doc comment.
              */}
              <dl className="cli-presence-action" data-testid="cli-presence-action">
                <div className="cli-presence-action-row">
                  <dt>Permission</dt>
                  <dd className="mono" data-testid="cli-presence-permission">
                    {request.permission}
                  </dd>
                </div>
                <div className="cli-presence-action-row">
                  <dt>Request</dt>
                  <dd className="mono" data-testid="cli-presence-request">
                    {request.method} {request.path}
                  </dd>
                </div>
                <div className="cli-presence-action-row">
                  <dt>Body</dt>
                  <dd
                    className="mono"
                    title={request.bodySha256}
                    data-testid="cli-presence-body-digest"
                  >
                    {describeBodyDigest(request.bodySha256)}
                  </dd>
                </div>
              </dl>
              <p className="cli-presence-desc">
                Verifying below authorizes only this exact request. Check that the code matches what
                your terminal printed before continuing.
              </p>
              <div className="cli-presence-code" data-testid="cli-presence-code">
                {request.userCode}
              </div>

              {phase === 'waiting' && (
                <div className="cli-presence-actions">
                  <button
                    type="button"
                    className="cli-presence-confirm"
                    onClick={confirmCode}
                    data-testid="cli-presence-confirm-code-btn"
                  >
                    Confirm — codes match
                  </button>
                </div>
              )}

              {phase === 'confirmed' && (
                <div className="cli-presence-actions">
                  <button
                    type="button"
                    className="cli-presence-confirm"
                    onClick={() => void runCeremony()}
                    data-testid="cli-presence-verify-btn"
                  >
                    Verify with security key
                  </button>
                </div>
              )}

              {phase === 'running' && (
                <div className="cli-presence-actions">
                  <button type="button" className="cli-presence-confirm" disabled>
                    <span className="cli-presence-spin" aria-hidden="true" />
                    <span>Waiting for gesture…</span>
                  </button>
                </div>
              )}
            </>
          )}

          {phase === 'done' && (
            <div className="cli-presence-state cli-presence-state--ok" role="status">
              <strong>Verified</strong>
              <p>Return to your terminal — the command will continue automatically.</p>
            </div>
          )}

          {phase === 'expired' && (
            <div className="cli-presence-state cli-presence-state--warn" role="alert">
              <strong>Presence request expired</strong>
              <p>This request has expired or no longer exists. Run the command again.</p>
            </div>
          )}

          {phase === 'error' && (
            <div className="cli-presence-state cli-presence-state--crit" role="alert">
              <strong>Something went wrong</strong>
              <p>{errorMsg}</p>
              {request && (
                <button
                  type="button"
                  className="cli-presence-deny"
                  onClick={() => setPhase('confirmed')}
                  data-testid="cli-presence-retry-btn"
                >
                  Try again
                </button>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
