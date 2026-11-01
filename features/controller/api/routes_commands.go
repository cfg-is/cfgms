// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerCommandRoutes) }

// registerCommandRoutes wires the durable delivery/command-record read surface
// (Issue #3757, ADR-031 Decision 2). The steward-scoped pending-deliveries
// route lives in routes_stewards.go instead, on the existing /stewards
// subrouter — a second PathPrefix("/stewards").Subrouter() call here would
// register a duplicate wildcard route entry for the same prefix.
func registerCommandRoutes(s *Server, api *mux.Router) {
	commands := api.PathPrefix("/commands").Subrouter()
	commands.Handle("/{id}", s.requirePermission("config", "push")(http.HandlerFunc(s.handleGetCommandRecord))).Methods("GET")
}
