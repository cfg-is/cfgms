// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerScriptRoutes) }

func registerScriptRoutes(s *Server, api *mux.Router) {
	// Script library endpoints (Issue #1670)
	scripts := api.PathPrefix("/scripts").Subrouter()
	scripts.Handle("", s.requirePermission("script", "admin")(http.HandlerFunc(s.handleListScripts))).Methods("GET")
	scripts.Handle("/{id}", s.requirePermission("script", "admin")(http.HandlerFunc(s.handleGetScriptLibraryItem))).Methods("GET")
	scripts.Handle("/{id}/privilege", s.requirePermission("script", "admin")(http.HandlerFunc(s.handlePutScriptPrivilege))).Methods("PUT")
}
