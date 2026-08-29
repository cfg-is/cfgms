// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * CLI login confirmation screen (Issue #3722, Epic #3711).
 *
 * Unauthenticated top-level route at /login/confirm?request_id=<id> — a sibling of
 * the RequireAuth-gated subtree, mirroring how /enroll/:token is registered in
 * App.tsx. The ONLY value read from the URL is request_id; every other query
 * parameter (a host, a scheme, a port, a callback URL) is ignored outright — a
 * parameter-supplied destination would be an exfiltration channel for a
 * strong-assurance session token, and this page never contacts the operator's
 * machine at all. The waiting `cfg login` command collects its own token directly
 * from the controller (handlers_cli_login.go); this screen never receives it.
 *
 * Flow:
 *   1. Read request_id from the URL.
 *   2. If not authenticated, render the shipped Login page's passkey ceremony
 *      inline (same guard condition RequireAuth uses) — an operator arriving
 *      without a session sees that first, before anything about the login
 *      request is shown.
 *   3. Once authenticated, GET the login request (doubles as this page's own
 *      session probe, mirroring the fleet view's data-call-as-probe pattern).
 *      This is the only way to learn the short user code — the CLI never puts
 *      it in the confirmation URL, only the request ID.
 *   4. Show the code and an explicit Confirm / Deny control. Approval only ever
 *      happens from a click on one of these — never on mount, never implicitly.
 *
 * Root-scope note (Amendment 2, superseding Amendment 1's withdrawn refusal
 * state): browser login now succeeds for a root-scope account (ADR-025
 * Amendment 4 gives the resulting session an explicit root-scope marker, so it
 * is confined rather than exempt) — this page needs no special case for that
 * account and renders the same states either way. What this page must never do,
 * for any account, is display or request a root-scope CERTIFICATE grant — that
 * capability is reachable only from a certificate-authenticated caller, which a
 * cookie-authenticated browser session run through this page is not. There is
 * no control here for it, and approveCliLoginRequest's own request/response
 * shape has no field that could carry one.
 */
import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router'
import { useAuth } from '../auth/AuthContext.tsx'
import Login from './Login.tsx'
import {
  approveCliLoginRequest,
  getCliLoginRequest,
  type CliLoginRequestState,
} from '../api/client.ts'
import './CliLogin.css'

/**
 * loading    — GET in flight
 * waiting    — pending; code shown, Confirm/Deny offered
 * submitting — approve/deny POST in flight
 * approved   — terminal: operator confirmed (or the request was already approved/collected)
 * denied     — terminal: this operator denied it (or it was already denied)
 * expired    — terminal: past its TTL, or no longer found (swept)
 * error      — terminal: no id in the URL, or an unexpected failure
 */
type Phase = 'loading' | 'waiting' | 'submitting' | 'approved' | 'denied' | 'expired' | 'error'

function phaseForStatus(status: CliLoginRequestState['status']): Phase {
  switch (status) {
    case 'pending':
      return 'waiting'
    case 'approved':
    case 'collected':
      return 'approved'
    case 'denied':
      return 'denied'
    default:
      return 'expired'
  }
}

export default function CliLogin() {
  const { status, probing } = useAuth()
  const [searchParams] = useSearchParams()
  // The ONLY value ever read from the URL. Every other parameter — a host, a
  // scheme, a port, a callback — is never inspected, let alone used.
  const requestId = searchParams.get('request_id')

  const [phase, setPhase] = useState<Phase>(() => (requestId ? 'loading' : 'error'))
  const [errorMsg, setErrorMsg] = useState<string | null>(() =>
    requestId ? null : 'Invalid login link — no request in the URL.',
  )
  const [request, setRequest] = useState<CliLoginRequestState | null>(null)

  // Mirrors RequireAuth's own guard exactly (AuthContext.tsx) without importing it:
  // this route is a top-level sibling outside the guarded subtree (Out of Scope: do
  // not change the router guard), so it re-derives the same condition locally.
  const authenticated = status === 'signedIn' || (probing && status === 'signedOut')

  useEffect(() => {
    if (!requestId || !authenticated) return
    let aborted = false

    async function load() {
      const result = await getCliLoginRequest(requestId!)
      if (aborted) return
      if (!result.ok || !result.request) {
        if (result.status === 404) {
          setPhase('expired')
        } else {
          setErrorMsg('Unable to load this login request. Please try again.')
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

  async function resolve(deny: boolean) {
    if (!requestId || !request || phase !== 'waiting') return
    setPhase('submitting')
    const result = await approveCliLoginRequest(requestId, request.userCode, deny)
    if (!result.ok) {
      if (result.status === 404) {
        setPhase('expired')
      } else {
        setErrorMsg('Unable to complete this action. Please try again.')
        setPhase('error')
      }
      return
    }
    setPhase(deny ? 'denied' : 'approved')
  }

  if (!authenticated) {
    return <Login />
  }

  return (
    <div className="cli-login-stage">
      <div className="cli-login-win">
        <div className="cli-login-titlebar">
          <span className="cli-login-title mono">cfgms · cli login</span>
        </div>
        <div className="cli-login-body">
          <div className="cli-login-wordmark">
            <b>CFGMS</b>
            <span>config management</span>
          </div>

          {phase === 'loading' && (
            <div className="cli-login-waiting">
              <h3 className="cli-login-waiting-heading">Loading your login request…</h3>
            </div>
          )}

          {(phase === 'waiting' || phase === 'submitting') && request && (
            <>
              <p className="cli-login-lead">Confirm this sign-in</p>
              <p className="cli-login-desc">
                Check that the code below matches what your terminal printed before
                confirming.
              </p>
              <div className="cli-login-code" data-testid="cli-login-code">
                {request.userCode}
              </div>
              <p className="cli-login-desc">
                If it does not match, deny this request — someone else may have sent you
                this link.
              </p>
              <div className="cli-login-actions">
                <button
                  type="button"
                  className="cli-login-confirm"
                  disabled={phase === 'submitting'}
                  onClick={() => void resolve(false)}
                >
                  Confirm — codes match
                </button>
                <button
                  type="button"
                  className="cli-login-deny"
                  disabled={phase === 'submitting'}
                  onClick={() => void resolve(true)}
                >
                  Deny
                </button>
              </div>
            </>
          )}

          {phase === 'approved' && (
            <div className="cli-login-state cli-login-state--ok" role="status">
              <strong>Login approved</strong>
              <p>Return to your terminal — the command will continue automatically.</p>
            </div>
          )}

          {phase === 'denied' && (
            <div className="cli-login-state cli-login-state--crit" role="status">
              <strong>Login denied</strong>
              <p>
                This login request was denied. If you did not expect this link, no
                further action is needed.
              </p>
            </div>
          )}

          {phase === 'expired' && (
            <div className="cli-login-state cli-login-state--warn" role="alert">
              <strong>Login request expired</strong>
              <p>This login request has expired or no longer exists. Run `cfg login` again.</p>
            </div>
          )}

          {phase === 'error' && (
            <div className="cli-login-state cli-login-state--crit" role="alert">
              <strong>Something went wrong</strong>
              <p>{errorMsg}</p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
