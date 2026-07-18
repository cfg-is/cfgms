// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * App root: router + auth provider + route guard around the authenticated
 * app shell (Story #2496).
 *
 * Route table (Story #2723, #2727, #2730, #2731):
 *   /                → AppShell layout → FleetOverview
 *   /stewards/:id    → AppShell layout → StewardAssetPage
 *   /audit           → AppShell layout → AuditView
 *   /config          → AppShell layout → ConfigListView
 *   /workflows       → AppShell layout → WorkflowListView
 *
 * Session presence is inferred from API responses, never from reading
 * cookies (#2495). The fleet view's own data call (GET /api/v1/stewards,
 * #2497) doubles as the authenticated probe — a 401 on it is handled
 * centrally and drops the app to the login screen ("session expired"), so
 * the shell no longer fires a separate probe request.
 */
import { Routes, Route } from 'react-router-dom'
import { AuthProvider, RequireAuth } from './auth/AuthContext.tsx'
import AppShell from './shell/AppShell.tsx'
import FleetOverview from './fleet/FleetOverview.tsx'
import StewardAssetPage from './fleet/StewardAssetPage.tsx'
import AuditView from './audit/AuditView.tsx'
import ConfigListView from './config/ConfigListView.tsx'
import WorkflowListView from './workflow/WorkflowListView.tsx'

function App() {
  return (
    <AuthProvider>
      <RequireAuth>
        <Routes>
          <Route path="/" element={<AppShell />}>
            <Route index element={<FleetOverview />} />
            <Route path="stewards/:id" element={<StewardAssetPage />} />
            <Route path="audit" element={<AuditView />} />
            <Route path="config" element={<ConfigListView />} />
            <Route path="workflows" element={<WorkflowListView />} />
          </Route>
        </Routes>
      </RequireAuth>
    </AuthProvider>
  )
}

export default App
