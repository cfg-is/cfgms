// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerRolloutRoutes) }

func registerRolloutRoutes(s *Server, api *mux.Router) {
	// Rollout endpoints (Issue #2340). Always registered — handlers return 503 when
	// rolloutStore is nil (nil-safe by design).
	rollout := api.PathPrefix("/rollout").Subrouter()
	rollout.Handle("",
		s.requirePermission("installer", "dispatch:steward")(http.HandlerFunc(s.handleStartRollout))).Methods("POST")
	rollout.Handle("/{rollout_id}",
		s.requirePermission("installer", "read")(http.HandlerFunc(s.handleGetRollout))).Methods("GET")
	rollout.Handle("/{rollout_id}/halt",
		s.requirePermission("installer", "dispatch:steward")(http.HandlerFunc(s.handleHaltRollout))).Methods("POST")
}
