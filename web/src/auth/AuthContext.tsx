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
  loginRequest,
  logoutRequest,
  onSessionConfirmed,
  onSessionExpired,
  onStepUpRequired,
  type StepUpRequest,
} from '../api/client.ts'
import Login from '../pages/Login.tsx'
import StepUpModal from './StepUpModal.tsx'

export interface Principal {
  username: string
}

/**
 * signedOut — fresh visit (mockup "signin" state)
 * invalid   — last login attempt was rejected (mockup "invalid" state)
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
  /** Attempt sign-in; resolves true on success. */
  login: (username: string, password: string) => Promise<boolean>
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

  const login = useCallback(async (username: string, password: string) => {
    // Explicit login commits us out of the probe phase regardless of outcome.
    probingRef.current = false
    setProbing(false)
    const result = await loginRequest(username, password)
    if (result.ok) {
      sessionEstablishedRef.current = true
      setPrincipal({ username })
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
