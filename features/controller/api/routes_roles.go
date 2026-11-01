// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerRoleRoutes) }

func registerRoleRoutes(s *Server, api *mux.Router) {
	// Role config endpoints (Issue #2543)
	roles := api.PathPrefix("/roles").Subrouter()
	roles.Handle("", s.requirePermission("role", "read")(http.HandlerFunc(s.handleListRoleConfigs))).Methods("GET")
	roles.Handle("", s.requirePermission("role", "write")(http.HandlerFunc(s.handleCreateRoleConfig))).Methods("POST")
	roles.Handle("/{name}", s.requirePermission("role", "read")(http.HandlerFunc(s.handleGetRoleConfig))).Methods("GET")
	roles.Handle("/{name}", s.requirePermission("role", "write")(http.HandlerFunc(s.handleDeleteRoleConfig))).Methods("DELETE")
}
