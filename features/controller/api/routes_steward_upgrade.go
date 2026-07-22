// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerStewardUpgradeRoutes) }

func registerStewardUpgradeRoutes(s *Server, api *mux.Router) {
	// Steward upgrade dispatch endpoints (Issue #1945).
	// Always registered — handlers return 503 when upgradeStore is nil (nil-safe by design).
	stewardUpgrade := api.PathPrefix("/stewards/upgrade").Subrouter()
	stewardUpgrade.Handle("",
		s.requirePermission("installer", "dispatch:steward")(http.HandlerFunc(s.handleDispatchUpgrade))).Methods("POST")
	stewardUpgrade.Handle("/{upgrade_id}",
		s.requirePermission("installer", "read")(http.HandlerFunc(s.handleUpgradeStatus))).Methods("GET")
	stewardUpgrade.Handle("/{upgrade_id}/rollback",
		s.requirePermission("installer", "dispatch:steward")(http.HandlerFunc(s.handleUpgradeRollback))).Methods("POST")
}
