// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerFleetRoutes) }

func registerFleetRoutes(s *Server, api *mux.Router) {
	// Fleet selector resolve endpoint (Issue #1640)
	fleetRouter := api.PathPrefix("/fleet").Subrouter()
	fleetRouter.Handle("/resolve", s.requirePermission("steward", "list")(http.HandlerFunc(s.handleResolveSelector))).Methods("POST")
	// Fleet health aggregate endpoint (Issue #2729)
	fleetRouter.Handle("/health", s.requirePermission("steward", "list")(http.HandlerFunc(s.handleFleetHealth))).Methods("GET")
}
