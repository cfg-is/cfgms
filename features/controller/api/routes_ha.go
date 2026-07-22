// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerHARoutes) }

func registerHARoutes(s *Server, api *mux.Router) {
	// High Availability (HA) endpoints
	ha := api.PathPrefix("/ha").Subrouter()
	ha.Handle("/status", s.requirePermission("ha", "read-status")(http.HandlerFunc(s.handleHAStatus))).Methods("GET")
	ha.Handle("/cluster", s.requirePermission("ha", "read-cluster")(http.HandlerFunc(s.handleHACluster))).Methods("GET")
	ha.Handle("/leader", s.requirePermission("ha", "read-leader")(http.HandlerFunc(s.handleHALeader))).Methods("GET")
	ha.Handle("/nodes", s.requirePermission("ha", "read-nodes")(http.HandlerFunc(s.handleHANodes))).Methods("GET")
}
