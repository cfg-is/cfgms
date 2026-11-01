// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerCockpitWatchRoutes) }

// registerCockpitWatchRoutes registers the GET /api/v1/cases/{id}/watch WebSocket
// endpoint (Issue #3613). The route is intentionally placed in a separate file so
// it can be reviewed alongside its handler without touching routes_cases.go.
func registerCockpitWatchRoutes(s *Server, api *mux.Router) {
	cases := api.PathPrefix("/cases").Subrouter()

	// GET /api/v1/cases/{id}/watch upgrades to a WebSocket and streams WatchEvents.
	// requirePermission("case", "read") is the same gate used by handleGetCase —
	// a caller who can read the case can subscribe to its live feed.
	cases.Handle("/{id}/watch",
		s.requirePermission("case", "read")(http.HandlerFunc(s.handleCockpitWatch)),
	).Methods("GET")
}
