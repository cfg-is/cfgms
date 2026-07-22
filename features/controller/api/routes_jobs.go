// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerJobRoutes) }

func registerJobRoutes(s *Server, api *mux.Router) {
	// Batch job endpoints (Issue #2296). Always registered — returns 503 when
	// batchJobStore is nil (nil-safe by design).
	jobs := api.PathPrefix("/jobs").Subrouter()
	jobs.Handle("", s.requirePermission("jobs", "write")(http.HandlerFunc(s.handleCreateJob))).Methods("POST")
	jobs.Handle("/{id}", s.requirePermission("jobs", "write")(http.HandlerFunc(s.handleGetJob))).Methods("GET")
}
