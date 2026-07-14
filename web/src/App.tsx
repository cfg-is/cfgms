// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * App root (Story #2495): auth provider + route guard around a minimal
 * authenticated placeholder. The real app-shell chrome (nav, tenant
 * switcher, search, alerts, user menu) is Story #2496 and replaces
 * AuthedHome.
 */
import { useEffect } from 'react'
import { apiFetch } from './api/client.ts'
import { AuthProvider, RequireAuth, useAuth } from './auth/AuthContext.tsx'

function AuthedHome() {
  const { principal, logout } = useAuth()

  // Lightweight authenticated probe (story #2495 note): session presence is
  // inferred from API responses, never from reading cookies. A 401 here is
  // handled centrally — the app drops to the login screen ("session
  // expired"). The response body is irrelevant.
  useEffect(() => {
    void apiFetch('/api/v1/stewards?page_size=1').catch(() => {
      // Network errors are not session expiry; the next real data call
      // (app shell, #2496) owns user-visible error handling.
    })
  }, [])

  return (
    <main className="authed-home">
      <h1>CFGMS</h1>
      <p>
        Signed in as <code>{principal?.username}</code>. App shell lands in
        Story #2496.
      </p>
      <button type="button" onClick={() => void logout()}>
        Sign out
      </button>
    </main>
  )
}

function App() {
  return (
    <AuthProvider>
      <RequireAuth>
        <AuthedHome />
      </RequireAuth>
    </AuthProvider>
  )
}

export default App
