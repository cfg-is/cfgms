// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerTenantCrossingRoutes) }

// registerTenantCrossingRoutes registers the cross-tenant crossing feed (Issue #4713).
func registerTenantCrossingRoutes(s *Server, api *mux.Router) {
	api.Handle("/tenant-crossings/active",
		s.requirePermission("tenant", "crossing-list")(http.HandlerFunc(s.handleListActiveTenantCrossings))).Methods("GET")
}
