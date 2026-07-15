// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * App root: auth provider + route guard around the authenticated app
 * shell (Story #2496).
 *
 * Session presence is inferred from API responses, never from reading
 * cookies (#2495). The fleet view's own data call (GET /api/v1/stewards,
 * #2497) doubles as the authenticated probe — a 401 on it is handled
 * centrally and drops the app to the login screen ("session expired"), so
 * the shell no longer fires a separate probe request.
 */
import { AuthProvider, RequireAuth } from './auth/AuthContext.tsx'
import AppShell from './shell/AppShell.tsx'

function App() {
  return (
    <AuthProvider>
      <RequireAuth>
        <AppShell />
      </RequireAuth>
    </AuthProvider>
  )
}

export default App
