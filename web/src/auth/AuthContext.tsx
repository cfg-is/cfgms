// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * In-memory session state (Story #2495, security A7.2).
 *
 * The signed-in principal lives in React context ONLY — never in web
 * storage (enforced by a source-scan test), never in a cookie readable by
 * JS. Session
 * presence is inferred from API responses; a page reload starts signedOut
 * and the first authenticated screen's data call re-establishes or expires
 * the session naturally.
 */
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react'
import { loginRequest, logoutRequest, onSessionExpired } from '../api/client.ts'
import Login from '../pages/Login.tsx'

export interface Principal {
  username: string
}

/**
 * signedOut — fresh visit (mockup "signin" state)
 * invalid   — last login attempt was rejected (mockup "invalid" state)
 * expired   — a 401 dropped the session (mockup "expired" state)
 * signedIn  — authenticated
 */
export type AuthStatus = 'signedOut' | 'invalid' | 'expired' | 'signedIn'

export interface AuthValue {
  status: AuthStatus
  principal: Principal | null
  /** Attempt sign-in; resolves true on success. */
  login: (username: string, password: string) => Promise<boolean>
  logout: () => Promise<void>
}

const AuthContext = createContext<AuthValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<AuthStatus>('signedOut')
  const [principal, setPrincipal] = useState<Principal | null>(null)

  useEffect(() => {
    onSessionExpired(() => {
      setPrincipal(null)
      setStatus('expired')
    })
    return () => onSessionExpired(null)
  }, [])

  const login = useCallback(async (username: string, password: string) => {
    const result = await loginRequest(username, password)
    if (result.ok) {
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
  }, [])

  const value = useMemo(
    () => ({ status, principal, login, logout }),
    [status, principal, login, logout],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthValue {
  const value = useContext(AuthContext)
  if (value === null) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return value
}

/**
 * Route guard: renders children only when signed in; otherwise the login
 * screen (which presents signin/invalid/expired per auth status).
 */
export function RequireAuth({ children }: { children: ReactNode }) {
  const { status } = useAuth()
  if (status !== 'signedIn') {
    return <Login />
  }
  return <>{children}</>
}
