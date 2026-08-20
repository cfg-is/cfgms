// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * In-memory session state (Story #2495, security A7.2).
 *
 * The signed-in principal lives in React context ONLY — never in web
 * storage (enforced by a source-scan test), never in a cookie readable by
 * JS. Session presence is inferred from API responses; a page reload starts
 * signedOut and the first authenticated screen's data call re-establishes
 * or expires the session naturally.
 *
 * Step-up (Story #2786, ADR-021 Decision 6): when apiFetch receives a 401 +
 * WWW-Authenticate: CFGMS-StepUp, the onStepUpRequired listener fires and
 * the AuthProvider renders a StepUpModal over the current view. The operator's
 * AuthStatus stays 'signedIn' throughout — this is not a session expiry.
 * On successful assertion the original request is retried; on cancel/failure
 * the operator returns to the prior view still signed in.
 *
 * Passkey login (Story #2993, ADR-021 Amendment 1): the login() function
 * performs the full WebAuthn discoverable-credential ceremony internally
 * (begin → credentials.get → finish), establishing AssuranceStrong directly.
 */
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react'
import {
  passkeyLoginBeginRequest,
  passkeyLoginFinishRequest,
  logoutRequest,
  onSessionConfirmed,
  onSessionExpired,
  onStepUpRequired,
  type AssertionJSON,
  type PasskeyLoginOptions,
  type StepUpRequest,
} from '../api/client.ts'
import Login from '../pages/Login.tsx'
import StepUpModal from './StepUpModal.tsx'

// ── base64url helpers (same as StepUpModal.tsx — both need WebAuthn conversions) ──

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

function toBrowserOptions(opts: PasskeyLoginOptions): PublicKeyCredentialRequestOptions {
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

// ── Auth context types ────────────────────────────────────────────────────────

export interface Principal {
  username: string
  tenantId: string // Issue #2919: empty string means root scope; populated on login
  rootScope: boolean // Issue #3131: true only for principals explicitly marked root-scoped (ADR-025 A2.1)
}

/**
 * signedOut — fresh visit (mockup "signin" state)
 * invalid   — last login attempt was rejected (mockup "invalid"/"no passkey" state)
 * expired   — a plain 401 dropped the session (mockup "expired" state)
 * signedIn  — authenticated
 *
 * Step-up is NOT a new AuthStatus value: the operator remains 'signedIn'
 * while the step-up modal is visible, because their existing session is intact.
 */
export type AuthStatus = 'signedOut' | 'invalid' | 'expired' | 'signedIn'

export interface AuthValue {
  status: AuthStatus
  principal: Principal | null
  /**
   * True from initial mount until the first apiFetch response resolves
   * (success or 401). RequireAuth uses this to render children optimistically
   * on first load so the route's own data call can act as the session probe
   * (Story #2933, #2495 no-dedicated-probe constraint).
   */
  probing: boolean
  /**
   * Attempt passkey sign-in (Issue #2993, ADR-021 Amendment 1). Performs the
   * full WebAuthn discoverable-credential ceremony: begin → credentials.get →
   * finish. An optional username scopes to a specific account; omitting it
   * starts a usernameless (discoverable) ceremony. Resolves true on success.
   */
  login: (username?: string) => Promise<boolean>
  logout: () => Promise<void>
}

const AuthContext = createContext<AuthValue | null>(null)

interface StepUpState {
  request: StepUpRequest
  resolve: (response: Response | null) => void
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<AuthStatus>('signedOut')
  const [principal, setPrincipal] = useState<Principal | null>(null)
  const [stepUpState, setStepUpState] = useState<StepUpState | null>(null)
  // probingRef gates onSessionConfirmed (resolve the initial probe once).
  // sessionEstablishedRef tracks whether a real session has been confirmed
  // (explicit login OR probe success) — only then does a 401 mean 'expired'
  // rather than 'signedOut'. Both avoid stale-closure without mutating during
  // render (react-hooks/refs constraint).
  const probingRef = useRef(true)
  const sessionEstablishedRef = useRef(false)
  const [probing, setProbing] = useState(true)

  useEffect(() => {
    onSessionExpired(() => {
      setPrincipal(null)
      // A 401 only means a mid-session drop if a session was actually
      // established (login or probe confirmed). Probe-phase 401s — including
      // concurrent ones — leave status as signedOut (ADR-018 §4).
      if (sessionEstablishedRef.current) {
        setStatus('expired')
      }
      probingRef.current = false
      setProbing(false)
    })
    onSessionConfirmed(() => {
      // First non-401 response after mount: the session cookie is valid.
      if (probingRef.current) {
        probingRef.current = false
        setProbing(false)
        sessionEstablishedRef.current = true
        setStatus('signedIn')
      }
    })
    onStepUpRequired(
      (req) =>
        new Promise<Response | null>((resolve) => {
          setStepUpState({ request: req, resolve })
        }),
    )
    return () => {
      onSessionExpired(null)
      onSessionConfirmed(null)
      onStepUpRequired(null)
    }
  }, [])

  const login = useCallback(async (username?: string) => {
    // Explicit login commits us out of the probe phase regardless of outcome.
    probingRef.current = false
    setProbing(false)

    // Step 1: obtain the WebAuthn challenge (pre-session CSRF checked by server).
    const beginResult = await passkeyLoginBeginRequest(username)
    if (!beginResult.ok || beginResult.options === undefined) {
      setPrincipal(null)
      setStatus('invalid')
      return false
    }

    // Step 2: invoke the browser's WebAuthn assertion ceremony.
    let rawCred: Credential | null = null
    try {
      rawCred = await navigator.credentials.get({
        publicKey: toBrowserOptions(beginResult.options),
      })
    } catch {
      // NotAllowedError (user cancelled) or any other authenticator error.
      setPrincipal(null)
      setStatus('invalid')
      return false
    }

    // navigator.credentials.get({ publicKey }) should always return a
    // PublicKeyCredential, but the return type is Credential | null.
    if (rawCred === null || rawCred.type !== 'public-key') {
      setPrincipal(null)
      setStatus('invalid')
      return false
    }

    // Step 3: send the assertion to the server; server issues a session at
    // AssuranceStrong (ADR-021 Decision 3) and returns the resolved username.
    const result = await passkeyLoginFinishRequest(toAssertionJSON(rawCred as PublicKeyCredential))
    if (result.ok) {
      sessionEstablishedRef.current = true
      setPrincipal({ username: result.username, tenantId: result.tenantId, rootScope: result.rootScope })
      setStatus('signedIn')
      return true
    }
    setPrincipal(null)
    setStatus('invalid')
    return false
  }, [])

  const logout = useCallback(async () => {
    await logoutRequest()
    setPrincipal(null)
    setStatus('signedOut')
    // After an explicit logout the probe phase is over and the session is gone:
    // show the login screen immediately rather than rendering protected content.
    sessionEstablishedRef.current = false
    probingRef.current = false
    setProbing(false)
  }, [])

  const value = useMemo(
    () => ({ status, principal, probing, login, logout }),
    [status, principal, probing, login, logout],
  )

  function handleStepUpSuccess(response: Response) {
    const state = stepUpState
    setStepUpState(null)
    state?.resolve(response)
  }

  function handleStepUpCancel() {
    const state = stepUpState
    setStepUpState(null)
    state?.resolve(null)
  }

  return (
    <AuthContext.Provider value={value}>
      {children}
      {stepUpState !== null && (
        <StepUpModal
          request={stepUpState.request}
          principalUsername={principal?.username ?? null}
          onSuccess={handleStepUpSuccess}
          onCancel={handleStepUpCancel}
        />
      )}
    </AuthContext.Provider>
  )
}

export function useAuth(): AuthValue {
  const value = useContext(AuthContext)
  if (value === null) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return value
}

/**
 * Route guard: renders children when signed in, or during the initial probe
 * (probing=true, signedOut) so the route's first data call can act as the
 * session probe. Falls back to the login screen for invalid/expired or once
 * the probe resolves unauthenticated. (Story #2933)
 */
export function RequireAuth({ children }: { children: ReactNode }) {
  const { status, probing } = useAuth()
  if (status === 'signedIn' || (probing && status === 'signedOut')) {
    return <>{children}</>
  }
  return <Login />
}
