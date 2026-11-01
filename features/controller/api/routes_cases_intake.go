// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerCasesIntakeRoutes) }

// registerCasesIntakeRoutes registers the /api/v1/cases/intake-assist route.
// Lives in a separate file from Story 4's case-CRUD routes so both register
// independently under the /cases prefix via their own init() (Issue #3604).
func registerCasesIntakeRoutes(s *Server, api *mux.Router) {
	cases := api.PathPrefix("/cases").Subrouter()

	cases.Handle("/intake-assist",
		s.requirePermission("case", "intake-assist")(http.HandlerFunc(s.handleCasesIntakeAssist)),
	).Methods("POST")
}
