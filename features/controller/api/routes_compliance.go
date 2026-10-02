// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerComplianceRoutes) }

func registerComplianceRoutes(s *Server, api *mux.Router) {
	// System-wide compliance endpoints
	compliance := api.PathPrefix("/compliance").Subrouter()
	compliance.Handle("/summary", s.requirePermission("compliance", "read-summary")(http.HandlerFunc(s.handleGetComplianceSummary))).Methods("GET")
}
