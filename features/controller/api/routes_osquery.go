// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerOsqueryRoutes) }

func registerOsqueryRoutes(s *Server, api *mux.Router) {
	// POST /osquery/query — dispatch an ad-hoc catalog query to targeted stewards (Issue #3569).
	// Gated by osquery:execute (AssuranceStrong + RequireUserPresence) and HasLeadership().
	osquery := api.PathPrefix("/osquery").Subrouter()
	osquery.Handle("/query",
		s.requirePermission("osquery", "execute")(http.HandlerFunc(s.handleOsqueryQuery))).Methods("POST")
}
