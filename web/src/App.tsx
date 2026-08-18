// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * App root: router + auth provider + route guard around the authenticated
 * app shell (Story #2496).
 *
 * Route table (Story #2723, #2727, #2730, #2731, Issue #2732, #2733, #2941, #2968, #2992):
 *   /enroll/:token   → Enroll (unauthenticated — magic-link redemption)
 *   /                → AppShell layout → FleetOverview
 *   /stewards/:id    → AppShell layout → StewardAssetPage
 *   /audit           → AppShell layout → AuditView
 *   /config          → AppShell layout → ConfigListView
 *   /modules         → AppShell layout → ModuleReviewQueue
 *   /workflows       → AppShell layout → WorkflowListView
 *   /accounts        → AppShell layout → AccountsView
 *   /certificates    → AppShell layout → CertificatesView
 *   /registration    → AppShell layout → RegistrationConsolePage
 *   /refresh         → AppShell layout → RefreshQueuePage
 *   /passkeys        → AppShell layout → PasskeysView (self-service passkey management)
 *   /reports         → AppShell layout → ReportsDashboardView
 *
 * Session presence is inferred from API responses, never from reading
 * cookies (#2495). The fleet view's own data call (GET /api/v1/stewards,
 * #2497) doubles as the authenticated probe — a 401 on it is handled
 * centrally and drops the app to the login screen ("session expired"), so
 * the shell no longer fires a separate probe request.
 *
 * The /enroll/:token route is a top-level sibling of the RequireAuth-gated
 * subtree (Story #2968). It is genuinely unauthenticated — no session is
 * required before enrollment, and RequireAuth is not in its render path.
 * After a successful enrollment, apiFetch fires onSessionConfirmed and the
 * navigate('/') call transitions into the authenticated shell.
 */
import { Routes, Route } from 'react-router'
import { AuthProvider, RequireAuth } from './auth/AuthContext.tsx'
import AppShell from './shell/AppShell.tsx'
import FleetOverview from './fleet/FleetOverview.tsx'
import StewardAssetPage from './fleet/StewardAssetPage.tsx'
import AuditView from './audit/AuditView.tsx'
import ConfigListView from './config/ConfigListView.tsx'
import WorkflowListView from './workflow/WorkflowListView.tsx'
import AccountsView from './accounts/AccountsView.tsx'
import CertificatesView from './certificates/CertificatesView.tsx'
import ModuleReviewQueue from './modules/ModuleReviewQueue.tsx'
import ScriptsView from './scripts/ScriptsView.tsx'
import RegistrationConsolePage from './registration/RegistrationConsolePage.tsx'
import RefreshQueuePage from './refresh/RefreshQueuePage.tsx'
import PasskeysView from './passkeys/PasskeysView.tsx'
import Enroll from './pages/Enroll.tsx'
import ReportsDashboardView from './reports/ReportsDashboardView.tsx'

function App() {
  return (
    <AuthProvider>
      <Routes>
        {/* Unauthenticated: magic-link first-passkey enrollment (Story #2968) */}
        <Route path="/enroll/:token" element={<Enroll />} />

        {/* All other routes require an authenticated session */}
        <Route
          path="*"
          element={
            <RequireAuth>
              <Routes>
                <Route path="/" element={<AppShell />}>
                  <Route index element={<FleetOverview />} />
                  <Route path="stewards/:id" element={<StewardAssetPage />} />
                  <Route path="audit" element={<AuditView />} />
                  <Route path="config" element={<ConfigListView />} />
                  <Route path="modules" element={<ModuleReviewQueue />} />
                  <Route path="workflows" element={<WorkflowListView />} />
                  <Route path="accounts" element={<AccountsView />} />
                  <Route path="certificates" element={<CertificatesView />} />
                  <Route path="scripts" element={<ScriptsView />} />
                  <Route path="registration" element={<RegistrationConsolePage />} />
                  <Route path="refresh" element={<RefreshQueuePage />} />
                  <Route path="passkeys" element={<PasskeysView />} />
                  <Route path="reports" element={<ReportsDashboardView />} />
                </Route>
              </Routes>
            </RequireAuth>
          }
        />
      </Routes>
    </AuthProvider>
  )
}

export default App
