// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

// registerPrivateMarkerRoutes registers the deploy, rollback, rollout and chaos marker
// routes on the private metrics listener only. `monitoring` is that listener's
// authenticated /api/v1/monitoring subrouter (registerPrivateMetricsRoutes). Markers are
// platform signals (ADR-025 Decision 4), recorded and read under the system tenant, so
// no tenant crossing applies. The routes are absent from the public router and from the
// automation-grant allowlist, so a grant principal is refused by automationRouteGuard.
func registerPrivateMarkerRoutes(s *Server, monitoring *mux.Router) {
	monitoring.Handle("/markers", s.requirePermission("monitoring", "write-markers")(http.HandlerFunc(s.handleCreateMarker))).Methods("POST")
	monitoring.Handle("/markers", s.requirePermission("monitoring", "read-markers")(http.HandlerFunc(s.handleListMarkers))).Methods("GET")
}
