// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * App root: auth provider + route guard around the authenticated app
 * shell (Story #2496).
 */
import { useEffect } from 'react'
import { apiFetch } from './api/client.ts'
import { AuthProvider, RequireAuth } from './auth/AuthContext.tsx'
import AppShell from './shell/AppShell.tsx'

function AuthedApp() {
  // Lightweight authenticated probe (story #2495 note): session presence is
  // inferred from API responses, never from reading cookies. A 401 here is
  // handled centrally — the app drops to the login screen ("session
  // expired"). The response body is irrelevant.
  useEffect(() => {
    void apiFetch('/api/v1/stewards?page_size=1').catch(() => {
      // Network errors are not session expiry; the fleet view (#2497) owns
      // user-visible error handling for its own data call.
    })
  }, [])

  return <AppShell />
}

function App() {
  return (
    <AuthProvider>
      <RequireAuth>
        <AuthedApp />
      </RequireAuth>
    </AuthProvider>
  )
}

export default App
