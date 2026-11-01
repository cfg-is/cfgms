// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerConfigPushRoutes) }

func registerConfigPushRoutes(s *Server, api *mux.Router) {
	// Configuration push endpoint (Issue #1318) and push-status read (Issue #2366)
	cfgPush := api.PathPrefix("/config").Subrouter()
	cfgPush.Handle("/push", s.requirePermission("config", "push")(http.HandlerFunc(s.handleConfigPush))).Methods("POST")
	cfgPush.Handle("/push/{id}", s.requirePermission("config", "push")(http.HandlerFunc(s.handleGetConfigPush))).Methods("GET")
}
