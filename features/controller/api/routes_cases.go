// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerCaseRoutes) }

// registerCaseRoutes registers the /api/v1/cases CRUD routes (Issue #3605).
// Separate from routes_cases_intake.go (Story 3) — each file registers its own
// routes under /cases via its own init().
func registerCaseRoutes(s *Server, api *mux.Router) {
	cases := api.PathPrefix("/cases").Subrouter()

	cases.Handle("",
		s.requirePermission("case", "create")(http.HandlerFunc(s.handleCreateCase)),
	).Methods("POST")

	cases.Handle("",
		s.requirePermission("case", "list")(http.HandlerFunc(s.handleListCases)),
	).Methods("GET")

	cases.Handle("/{id}",
		s.requirePermission("case", "read")(http.HandlerFunc(s.handleGetCase)),
	).Methods("GET")

	cases.Handle("/{id}",
		s.requirePermission("case", "update")(http.HandlerFunc(s.handleUpdateCase)),
	).Methods("PUT")

	cases.Handle("/{id}/pins",
		s.requirePermission("case", "update")(http.HandlerFunc(s.handleAddPin)),
	).Methods("POST")

	cases.Handle("/{id}/pins/{pin_id}",
		s.requirePermission("case", "update")(http.HandlerFunc(s.handleRemovePin)),
	).Methods("DELETE")
}
