// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerAPIKeyRoutes) }

func registerAPIKeyRoutes(s *Server, api *mux.Router) {
	// API key management endpoints (for managing API keys themselves)
	apiKeys := api.PathPrefix("/api-keys").Subrouter()
	apiKeys.Handle("", s.requirePermission("api-key", "list")(http.HandlerFunc(s.handleListAPIKeys))).Methods("GET")
	apiKeys.Handle("", s.requirePermission("api-key", "create")(http.HandlerFunc(s.handleCreateAPIKey))).Methods("POST")
	apiKeys.Handle("/{id}", s.requirePermission("api-key", "read")(http.HandlerFunc(s.handleGetAPIKey))).Methods("GET")
	apiKeys.Handle("/{id}", s.requirePermission("api-key", "delete")(http.HandlerFunc(s.handleDeleteAPIKey))).Methods("DELETE")
}
