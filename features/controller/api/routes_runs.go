// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerRunRoutes) }

func registerRunRoutes(s *Server, api *mux.Router) {
	// Ad-hoc run endpoints (Issue #1673). Always registered — returns 503 when
	// run manager is not wired (transport-disabled deployments).
	runs := api.PathPrefix("/runs").Subrouter()
	runs.Handle("/script", s.requirePermission("steward", "execute-scripts")(http.HandlerFunc(s.handlePostRunScript))).Methods("POST")
	runs.Handle("/command", s.requirePermission("steward", "execute-scripts")(http.HandlerFunc(s.handlePostRunCommand))).Methods("POST")
	runs.Handle("/{run_id}", s.requirePermission("steward", "read-scripts")(http.HandlerFunc(s.handleGetRun))).Methods("GET")
	runs.Handle("/{run_id}/jobs", s.requirePermission("steward", "read-scripts")(http.HandlerFunc(s.handleGetRunJobs))).Methods("GET")
	runs.Handle("/{run_id}", s.requirePermission("steward", "execute-scripts")(http.HandlerFunc(s.handleDeleteRun))).Methods("DELETE")
}
